"""Análise de arquivos: hash SHA-256 (com cache), assinatura digital (Authenticode via
PowerShell), heurísticas de nome/local/tipo e análise estática de PE. Cada indicador vira
uma Evidence com peso; a classificação final é feita em Finding.finalize().

Princípios anti-falso-positivo: ausência de assinatura sozinha NUNCA classifica um arquivo
como malicioso; indicadores fracos só pesam quando combinados."""
from __future__ import annotations

import hashlib
import json
import math
import os
import re
from pathlib import Path

from . import config
from .logger import get_logger
from .models import Finding
from .platform_utils import IS_WINDOWS, PowerShellError, run_powershell_json
from .safety import norm

log = get_logger(__name__)

try:
    import pefile  # type: ignore
except ImportError:  # análise PE é opcional
    pefile = None

SCRIPT_PATTERNS = [
    (re.compile(rb"-enc(odedcommand)?\s", re.I), "PowerShell com comando codificado", 15),
    (re.compile(rb"frombase64string", re.I), "Decodificação Base64 em script", 8),
    (re.compile(rb"\b(iex|invoke-expression)\b", re.I), "Invoke-Expression (execução dinâmica)", 10),
    (re.compile(rb"downloadstring|downloadfile|invoke-webrequest|bitsadmin", re.I), "Download de conteúdo remoto", 10),
    (re.compile(rb"-windowstyle\s+hidden|-w\s+hidden", re.I), "Execução oculta", 8),
    (re.compile(rb"wscript\.shell", re.I), "WScript.Shell (execução de comandos)", 5),
]
MINER_STRONG = re.compile(rb"stratum\+(tcp|ssl)://|--donate-level|cryptonight|randomx", re.I)
MINER_WEAK = re.compile(rb"xmrig|minexmr|nanopool|nicehash|ethermine", re.I)
INJECTION_APIS = {"VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"}
HOOK_APIS = {"SetWindowsHookExA", "SetWindowsHookExW"}
KEYSTATE_APIS = {"GetAsyncKeyState", "GetKeyboardState"}

_PS_SIGNATURE = r"""
[Console]::OutputEncoding=[Text.Encoding]::UTF8
$p=[Console]::In.ReadToEnd() | ConvertFrom-Json
$r=foreach($x in @($p)){
  $s=Get-AuthenticodeSignature -LiteralPath $x -ErrorAction SilentlyContinue
  [pscustomobject]@{Path=$x;Status=[string]$s.Status;Subject=[string]$s.SignerCertificate.Subject}
}
ConvertTo-Json -InputObject @($r) -Compress
"""


def sha256_file(path, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while data := f.read(chunk):
            h.update(data)
    return h.hexdigest()


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in counts if c)


def load_known_hashes(directory: Path | None = None) -> set[str]:
    """Lê listas locais de hashes SHA-256 (arquivos .txt/.csv em data/signatures)."""
    hashes: set[str] = set()
    d = Path(directory or config.SIGNATURES_DIR)
    if d.exists():
        for f in list(d.glob("*.txt")) + list(d.glob("*.csv")):
            for line in f.read_text(encoding="utf-8", errors="ignore").splitlines():
                m = re.search(r"\b[0-9a-fA-F]{64}\b", line)
                if m and not line.lstrip().startswith("#"):
                    hashes.add(m.group(0).lower())
    return hashes


def _edit_distance_le1(a: str, b: str) -> bool:
    if a == b:
        return False
    if abs(len(a) - len(b)) > 1:
        return False
    if len(a) == len(b):
        return sum(x != y for x, y in zip(a, b)) == 1
    s, l = (a, b) if len(a) < len(b) else (b, a)
    i = 0
    while i < len(s) and s[i] == l[i]:
        i += 1
    return s[i:] == l[i + 1:]


def is_legit_system_location(path) -> bool:
    s = norm(path)
    win = norm(os.environ.get("SystemRoot", r"C:\Windows"))
    allowed = (win + "\\system32\\", win + "\\syswow64\\", win + "\\winsxs\\")
    if s.startswith(allowed):
        return True
    return Path(s.replace("\\", "/")).name == "explorer.exe" and s == win + "\\explorer.exe"


def in_temp_dir(path) -> bool:
    s = norm(path) + "\\"
    win = norm(os.environ.get("SystemRoot", r"C:\Windows"))
    return "\\appdata\\local\\temp\\" in s or s.startswith(win + "\\temp\\")


class FileAnalyzer:
    def __init__(self, db=None, known_hashes: set[str] | None = None):
        self.db = db
        self.known_hashes = known_hashes if known_hashes is not None else load_known_hashes()

    # --- hash com cache ---------------------------------------------------
    def hash_cached(self, path: Path, st: os.stat_result) -> str:
        if self.db:
            hit = self.db.get_cached(str(path), st.st_size, st.st_mtime_ns)
            if hit:
                return hit["sha256"]
        digest = sha256_file(path)
        if self.db:
            self.db.put_cached(str(path), st.st_size, st.st_mtime_ns, digest)
        return digest

    # --- assinatura digital -------------------------------------------------
    def get_signatures(self, paths: list[str]) -> dict[str, dict]:
        """Verifica assinaturas Authenticode em lote (uma chamada de PowerShell)."""
        if not IS_WINDOWS or not paths:
            return {p: {"status": "Unavailable", "subject": ""} for p in paths}
        try:
            data = run_powershell_json(_PS_SIGNATURE, json.dumps(paths, ensure_ascii=True), timeout=120)
            rows = [] if data is None else (data if isinstance(data, list) else [data])
            return {d["Path"]: {"status": d["Status"], "subject": d["Subject"]} for d in rows
                    if isinstance(d, dict) and "Path" in d}
        except (PowerShellError, OSError, KeyError, TypeError) as exc:
            log.warning("Falha ao verificar assinaturas: %s", exc)
            return {p: {"status": "Unavailable", "subject": ""} for p in paths}

    def apply_signature(self, f: Finding, sig: dict) -> None:
        status, subject = sig.get("status", "Unavailable"), sig.get("subject", "")
        f.signature = f"{status} {subject}".strip()
        if status == "Valid":
            if re.search(r"O=\"?Microsoft Corporation", subject):
                f.add("sig_ms", "Assinatura válida da Microsoft", -25)
            else:
                f.add("sig_valid", "Assinatura digital válida", -10)
        elif status == "HashMismatch":
            f.add("sig_tampered", "Arquivo alterado após ser assinado (hash não confere)", 40, "Arquivo adulterado")
        elif status == "NotSigned":
            # Ausência de assinatura não é evidência positiva (peso 0): fica registrada
            # para transparência, mas não pode, sozinha, classificar um arquivo.
            f.add("sig_none", "Sem assinatura digital (indicador fraco isolado)", 0)
        elif status == "NotTrusted":
            f.add("sig_untrusted", f"Assinatura não confiável ({status})", 5)
        # UnknownError/NotSupportedFileFormat/Unavailable são resultados INCONCLUSIVOS
        # (arquivo não-PE, falha do PowerShell, etc.) e não viram evidência.

    # --- heurística principal ---------------------------------------------------
    def analyze(self, path, check_signature: bool = True) -> Finding | None:
        p = Path(path)
        try:
            st = p.stat()
            with open(p, "rb") as fh:
                head = fh.read(4096)
        except OSError:
            return None  # inacessível / em uso: tratado pelo scanner como "ignorado"

        ext, name, s = p.suffix.lower(), p.name.lower(), norm(p)
        is_pe = head[:2] == b"MZ"
        is_script = ext in config.SCRIPT_EXT
        f = Finding(path=str(p), size=st.st_size)

        # Nome e tipo
        stem_ext = Path(p.stem).suffix.lower()
        if ext in (config.EXECUTABLE_EXT | config.SCRIPT_EXT) and stem_ext in config.DOCUMENT_EXT:
            f.add("double_ext", f"Extensão dupla ({stem_ext}{ext}) típica de disfarce", 25, "Executável disfarçado")
        if is_pe and ext in config.DOCUMENT_EXT:
            f.add("pe_as_doc", f"Executável (cabeçalho MZ) com extensão de documento ({ext})", 35, "Executável disfarçado")
        if name in config.SYSTEM_PROCESS_NAMES and ext == ".exe" and not is_legit_system_location(p):
            f.add("mimic_name", f"Nome de componente do Windows ({name}) fora de System32", 60, "Imitação de processo do Windows")
        elif ext == ".exe" and any(_edit_distance_le1(name, n) for n in config.SYSTEM_PROCESS_NAMES):
            f.add("lookalike", f"Nome muito parecido com componente do Windows ({name})", 30, "Imitação de processo do Windows")

        # Local
        if (is_pe or is_script) and in_temp_dir(p):
            f.add("in_temp", "Executável/script em diretório temporário", 15)
        attrs = getattr(st, "st_file_attributes", 0)
        if (is_pe or is_script) and attrs & 0x2 and "\\appdata\\" in s + "\\":
            f.add("hidden_exec", "Executável oculto em diretório de dados do usuário", 10)
        # "Criado recentemente em temp" seria redundante com in_temp e apenas somava
        # dois indicadores correlacionados (falso positivo). Mantido apenas in_temp.

        if is_pe or is_script:
            try:
                f.sha256 = self.hash_cached(p, st)
            except OSError:
                return None
            if f.sha256 in self.known_hashes:
                f.add("known_hash", "Hash SHA-256 consta na base local de ameaças conhecidas", 100, "Ameaça conhecida")
            if is_pe:
                self._analyze_pe(p, f)
            if is_script:
                self._analyze_script(p, f)

        # Assinatura só é consultada para PE que já tem algum indicador (custo/benefício).
        if check_signature and is_pe and any(e.weight > 0 for e in f.evidences):
            self.apply_signature(f, self.get_signatures([str(p)]).get(str(p), {}))

        f.finalize()
        return f if f.evidences and f.score > 0 else None

    # --- análise estática ---------------------------------------------------------
    def _analyze_script(self, p: Path, f: Finding) -> None:
        try:
            with open(p, "rb") as fh:
                data = fh.read(config.MAX_SCRIPT_SCAN_BYTES)
        except OSError:
            return
        hits = 0
        for rx, desc, w in SCRIPT_PATTERNS:
            if rx.search(data):
                f.add("script_" + desc[:12], desc, w, "Script suspeito")
                hits += 1
        if MINER_STRONG.search(data):
            f.add("miner_script", "Script com indicadores de mineração (stratum/pool)", 40, "Minerador")

    def _analyze_pe(self, p: Path, f: Finding) -> None:
        try:
            with open(p, "rb") as fh:
                data = fh.read(config.MAX_STRING_SCAN_BYTES)
        except OSError:
            return
        if MINER_STRONG.search(data):
            f.add("miner_strings", "Strings de protocolo/algoritmo de mineração no executável", 40, "Minerador")
        elif MINER_WEAK.search(data):
            f.add("miner_weak", "Referências a software/pools de mineração", 10, "Minerador (PUP)")
        if pefile is None:
            return
        try:
            pe = pefile.PE(data=data, fast_load=False)
        except Exception:
            f.add("bad_pe", "Cabeçalho PE malformado", 8)
            return
        try:
            for sec in pe.sections:
                if sec.SizeOfRawData > 10_000 and sec.get_entropy() > 7.2:
                    f.add("high_entropy", "Seção com alta entropia (possível empacotamento/ofuscação)", 10)
                    break
            names = {s.Name.rstrip(b"\x00").decode(errors="ignore").lower() for s in pe.sections}
            if names & {"upx0", "upx1", ".aspack", ".themida", ".vmp0"}:
                f.add("packer", "Empacotador conhecido detectado (comum em malware, mas também em software legítimo)", 8)
            imports: set[str] = set()
            for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
                imports |= {i.name.decode(errors="ignore") for i in entry.imports if i.name}
            if INJECTION_APIS <= imports:
                f.add("injection_apis", "Combinação de APIs de injeção de código em outros processos", 15, "Comportamento suspeito")
            if imports & HOOK_APIS and imports & KEYSTATE_APIS:
                f.add("keylog_apis", "APIs de hook + leitura de teclado (possível keylogger)", 15, "Possível keylogger")
            if not imports and len(data) > 50_000:
                f.add("no_imports", "Executável sem tabela de importação (possível packer)", 8)
        finally:
            pe.close()


# --------------------------------------------------------------------------------------
# Utilitários compartilhados pelos analisadores de processos, inicialização e registro
# --------------------------------------------------------------------------------------
_USER_WRITABLE = ("\\appdata\\", "\\users\\public\\", "\\programdata\\", "\\temp\\",
                  "\\downloads\\", "\\$recycle.bin\\")
_ENV_RE = re.compile(r"%([^%]+)%")


def in_user_writable_dir(path) -> bool:
    s = norm(path) + "\\"
    if "\\programdata\\microsoft\\" in s:
        return False
    return any(m in s for m in _USER_WRITABLE)


def under_windir(path) -> bool:
    win = norm(os.environ.get("SystemRoot", r"C:\Windows"))
    return norm(path).startswith(win + "\\")


def expand_env(text: str) -> str:
    """Expande %VAR% de forma independente de plataforma."""
    def rep(m):
        v = os.environ.get(m.group(1))
        if v is None:
            v = os.environ.get(m.group(1).upper())
        return v if v is not None else m.group(0)
    return _ENV_RE.sub(rep, text)


def normalize_nt(text: str) -> str:
    """Converte prefixos NT (\\??\\, \\SystemRoot\\) em caminhos Win32."""
    low = text.lower()
    win = os.environ.get("SystemRoot", r"C:\Windows")
    if low.startswith("\\??\\"):
        return text[4:]
    if low.startswith("\\systemroot\\"):
        return win + text[11:]
    if low.startswith("system32\\"):
        return win + "\\" + text
    return text


def read_company_name(path) -> str | None:
    """Fabricante (CompanyName) do recurso de versão do PE. '' = sem fabricante;
    None = não foi possível determinar (pefile ausente ou arquivo ilegível)."""
    if pefile is None:
        return None
    try:
        pe = pefile.PE(str(path), fast_load=True)
        try:
            pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]])
            for fi in getattr(pe, "FileInfo", None) or []:
                for entry in fi:
                    if getattr(entry, "Key", b"") == b"StringFileInfo":
                        for table in entry.StringTable:
                            val = table.entries.get(b"CompanyName")
                            if val:
                                return val.decode(errors="ignore").strip()
            return ""
        finally:
            pe.close()
    except Exception:
        return None
