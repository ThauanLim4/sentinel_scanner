"""Análise dos mecanismos de inicialização/persistência: chaves Run/RunOnce, pastas Startup,
serviços, tarefas agendadas e drivers. Cada entrada recebe um Finding com evidências e risco.

Desativar entradas é sempre reversível e exige confirmação:
- Run/Startup: usa StartupApproved (o mesmo mecanismo do Gerenciador de Tarefas), sem apagar nada.
- RunOnce/políticas: apaga o valor SOMENTE após backup .reg da chave.
- Serviços: muda o tipo de início para 'desativado' (nunca exclui). Serviços do Windows e drivers
  são recusados."""
from __future__ import annotations

import json
import ntpath
import os
import re
import struct
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

from . import config
from .file_analyzer import (FileAnalyzer, expand_env, in_temp_dir, in_user_writable_dir, is_legit_system_location,
                            normalize_nt, read_company_name, under_windir)
from .logger import get_logger
from .models import Finding, RiskLevel, merge_evidences
from .platform_utils import CREATE_NO_WINDOW, IS_WINDOWS, PowerShellError, run_powershell, run_powershell_json
from .registry_analyzer import HKCU, HKLM, RegistryAccess, RegistryError, backup_key
from .safety import norm

try:
    import psutil
except ImportError:
    psutil = None

log = get_logger(__name__)
CURRENT = r"SOFTWARE\Microsoft\Windows\CurrentVersion"
APPROVED = CURRENT + r"\Explorer\StartupApproved"
# (hive, chave, tipo, nome em StartupApproved ou None quando não suportado)
RUN_KEYS = [
    (HKLM, CURRENT + r"\Run", "run", "Run"),
    (HKLM, CURRENT + r"\RunOnce", "runonce", None),
    (HKLM, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", "run", "Run32"),
    (HKLM, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce", "runonce", None),
    (HKLM, CURRENT + r"\Policies\Explorer\Run", "run_policy", None),
    (HKCU, CURRENT + r"\Run", "run", "Run"),
    (HKCU, CURRENT + r"\RunOnce", "runonce", None),
    (HKCU, CURRENT + r"\Policies\Explorer\Run", "run_policy", None),
]
LOLBINS = {"cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe",
           "regsvr32.exe", "msiexec.exe"}
CMD_PATTERNS = [
    (re.compile(r"-enc(odedcommand)?\s", re.I), "PowerShell com comando codificado", 25, "st_ps_enc"),
    (re.compile(r"frombase64string|downloadstring|downloadfile|invoke-webrequest|\biwr\s|\biex\b|invoke-expression", re.I),
     "Download/execução dinâmica na linha de comando", 20, "st_download"),
    (re.compile(r"mshta(\.exe)?\s+(https?:|vbscript:|javascript:)", re.I), "mshta executando conteúdo remoto/script", 35, "st_mshta"),
    (re.compile(r"regsvr32.*(/i:https?:|scrobj\.dll)", re.I), "regsvr32 com scriptlet remoto", 35, "st_regsvr"),
    (re.compile(r"certutil.*-urlcache|bitsadmin.*/transfer", re.I), "Download via certutil/bitsadmin", 30, "st_certutil"),
    (re.compile(r"-w(indowstyle)?\s+hidden", re.I), "Execução com janela oculta", 8, "st_hidden"),
]
_TARGET = re.compile(r'([A-Za-z]:\\[^\s",;|<>]+?\.(?:exe|dll|vbs|vbe|js|jse|ps1|bat|cmd|hta|scr|wsf))', re.I)
_SPLIT = re.compile(r'^(.+?\.(?:exe|com|bat|cmd|scr|dll|sys|msi|ps1|vbs|js))(?:\s+|$)(.*)$', re.I | re.S)
CATEGORY = "Persistência suspeita"


def split_command(cmd: str) -> tuple[str, str]:
    cmd = cmd.strip()
    if cmd.startswith('"'):
        end = cmd.find('"', 1)
        return (cmd[1:end], cmd[end + 1:].strip()) if end > 0 else (cmd.strip('"'), "")
    m = _SPLIT.match(cmd)
    if m:
        return m.group(1), m.group(2).strip()
    parts = cmd.split(None, 1)
    return (parts[0], parts[1] if len(parts) > 1 else "") if parts else ("", "")


def extract_targets(args: str) -> list[str]:
    return _TARGET.findall(args)


@dataclass
class StartupEntry:
    kind: str                 # run | runonce | run_policy | startup_folder | service | task | driver
    name: str
    location: str
    command: str
    enabled: bool = True
    exe: str = ""
    target: str = ""
    company: str = ""
    signature: str = ""
    extra: dict = field(default_factory=dict)
    finding: Finding | None = None

    @property
    def risk(self) -> RiskLevel:
        return self.finding.risk if self.finding else RiskLevel.SEGURO

    def to_dict(self) -> dict:
        return {"kind": self.kind, "name": self.name, "location": self.location, "command": self.command,
                "enabled": self.enabled, "exe": self.exe, "target": self.target, "company": self.company,
                "signature": self.signature, "risk": self.risk.label,
                "justification": self.finding.justification if self.finding else ""}


_PS_SHORTCUTS = r"""
[Console]::OutputEncoding=[Text.Encoding]::UTF8
$sh=New-Object -ComObject WScript.Shell
$p=[Console]::In.ReadToEnd()|ConvertFrom-Json
$r=foreach($x in @($p)){$l=$sh.CreateShortcut($x);[pscustomobject]@{Path=$x;Target=[string]$l.TargetPath;Args=[string]$l.Arguments}}
ConvertTo-Json -InputObject @($r) -Compress
"""
_PS_TASKS = r"""
[Console]::OutputEncoding=[Text.Encoding]::UTF8
$r=foreach($t in Get-ScheduledTask -ErrorAction SilentlyContinue){foreach($a in @($t.Actions)){if($a.Execute){
[pscustomobject]@{Name=[string]$t.TaskName;Path=[string]$t.TaskPath;State=[string]$t.State;Execute=[string]$a.Execute;
Arguments=[string]$a.Arguments;Triggers=(@($t.Triggers|ForEach-Object{$_.CimClass.CimClassName -replace 'MSFT_Task',''}) -join ',')}}}}
ConvertTo-Json -InputObject @($r) -Compress
"""
_PS_DRIVERS = ("[Console]::OutputEncoding=[Text.Encoding]::UTF8;ConvertTo-Json -InputObject @(Get-CimInstance Win32_SystemDriver "
               "| Select-Object Name,DisplayName,PathName,StartMode,State) -Compress")


def _list(x):
    return [] if x is None else (x if isinstance(x, list) else [x])


def approved_disabled() -> bytes:
    return struct.pack("<I", 3) + struct.pack("<Q", int((time.time() + 11644473600) * 10_000_000))


def approved_enabled() -> bytes:
    return struct.pack("<I", 2) + b"\x00" * 8


class StartupAnalyzer:
    def __init__(self, file_analyzer: FileAnalyzer | None = None, access=None, db=None):
        self.fa = file_analyzer or FileAnalyzer(db)
        self.db = db
        self.access = access
        if self.access is None and IS_WINDOWS:
            try:
                self.access = RegistryAccess()
            except RegistryError:
                self.access = None

    # ------------------------------------------------------------------ coleta
    def collect(self, kinds=("registry", "folders", "services", "tasks", "drivers")) -> list[StartupEntry]:
        entries: list[StartupEntry] = []
        collectors = {"registry": self.collect_registry, "folders": self.collect_folders,
                      "services": self.collect_services, "tasks": self.collect_tasks, "drivers": self.collect_drivers}
        for kind in kinds:
            try:
                entries.extend(collectors[kind]())
            except Exception as exc:
                log.warning("Coleta '%s' falhou: %s", kind, exc)
        return entries

    @staticmethod
    def _is_disabled(blob) -> bool:
        return isinstance(blob, (bytes, bytearray)) and len(blob) > 0 and blob[0] % 2 == 1

    def collect_registry(self) -> list[StartupEntry]:
        if self.access is None:
            return []
        out: list[StartupEntry] = []
        for hive, key, kind, appr in RUN_KEYS:
            approved = self.access.values(hive, APPROVED + "\\" + appr) if appr else {}
            for name, (data, _t) in self.access.values(hive, key).items():
                if not isinstance(data, str) or not data.strip():
                    continue
                ap = approved.get(name)
                out.append(StartupEntry(kind, name or "(Padrão)", f"{hive}\\{key}", data,
                                        enabled=not (ap and self._is_disabled(ap[0])),
                                        extra={"hive": hive, "key": key, "value": name, "approved_key":
                                               (APPROVED + "\\" + appr) if appr else None, "approved_name": name}))
        legacy = r"Software\Microsoft\Windows NT\CurrentVersion\Windows"
        for val in ("Load", "Run"):
            data = self.access.get(HKCU, legacy, val)
            if isinstance(data, str) and data.strip():
                out.append(StartupEntry("run_policy", val, f"HKCU\\{legacy}", data,
                                        extra={"hive": HKCU, "key": legacy, "value": val, "approved_key": None}))
        return out

    def collect_folders(self) -> list[StartupEntry]:
        spec = [(os.environ.get("APPDATA"), HKCU), (os.environ.get("ProgramData"), HKLM)]
        files: list[tuple[Path, str]] = []
        for base, hive in spec:
            if not base:
                continue
            d = Path(base) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / ("Startup" if hive == HKCU else "StartUp")
            if d.is_dir():
                files += [(f, hive) for f in d.iterdir() if f.is_file() and f.name.lower() != "desktop.ini"]
        targets: dict[str, tuple[str, str]] = {}
        lnks = [str(f) for f, _ in files if f.suffix.lower() == ".lnk"]
        if lnks and IS_WINDOWS:
            try:
                rows = run_powershell_json(_PS_SHORTCUTS, json.dumps(lnks, ensure_ascii=True), timeout=60)
                for r in _list(rows):
                    if isinstance(r, dict) and "Path" in r:
                        targets[r["Path"]] = (r.get("Target", ""), r.get("Args", ""))
            except (PowerShellError, OSError, KeyError) as exc:
                log.warning("Não foi possível resolver atalhos: %s", exc)
        out = []
        for f, hive in files:
            tgt, args = targets.get(str(f), ("", ""))
            cmd = f'"{tgt}" {args}'.strip() if tgt else str(f)
            approved = self.access.values(hive, APPROVED + r"\StartupFolder") if self.access else {}
            ap = approved.get(f.name)
            out.append(StartupEntry("startup_folder", f.name, str(f.parent), cmd,
                                    enabled=not (ap and self._is_disabled(ap[0])),
                                    extra={"hive": hive, "approved_key": APPROVED + r"\StartupFolder",
                                           "approved_name": f.name, "file": str(f)}))
        return out

    def collect_services(self) -> list[StartupEntry]:
        if psutil is None or not hasattr(psutil, "win_service_iter"):
            return []
        out = []
        try:
            services = list(psutil.win_service_iter())
        except psutil.Error as exc:
            log.warning("Não foi possível listar serviços: %s", exc)
            return []
        for svc in services:
            try:
                d = svc.as_dict()
            except (psutil.Error, OSError) as exc:
                log.debug("Serviço inacessível ignorado: %s", exc)
                continue
            if d.get("start_type") == "disabled" or not d.get("name"):
                continue
            e = StartupEntry("service", d["name"], "Serviços do Windows", d.get("binpath") or "",
                             extra={"display": d.get("display_name"), "start_type": d.get("start_type"),
                                    "status": d.get("status"), "username": d.get("username"), "pid": d.get("pid")})
            if self.access is not None:
                dll = self.access.get(HKLM, rf"SYSTEM\CurrentControlSet\Services\{d['name']}\Parameters", "ServiceDll")
                if dll:
                    e.extra["service_dll"] = normalize_nt(expand_env(str(dll)))
            out.append(e)
        return out

    def collect_tasks(self) -> list[StartupEntry]:
        if not IS_WINDOWS:
            return []
        out = []
        for t in _list(run_powershell_json(_PS_TASKS, timeout=120)):
            if not isinstance(t, dict) or not t.get("Execute"):
                continue
            execute = str(t["Execute"])
            cmd = f'"{execute}" {t.get("Arguments", "")}'.strip() if " " in execute and not execute.startswith('"') \
                else f'{execute} {t.get("Arguments", "")}'.strip()
            out.append(StartupEntry("task", str(t.get("Name", "")), "Agendador de Tarefas " + str(t.get("Path", "")),
                                    cmd, enabled=str(t.get("State", "")).lower() != "disabled",
                                    extra={"task_name": str(t.get("Name", "")), "task_path": str(t.get("Path", "")),
                                           "state": t.get("State"), "triggers": t.get("Triggers")}))
        return out

    def collect_drivers(self) -> list[StartupEntry]:
        if not IS_WINDOWS:
            return []
        out = []
        for d in _list(run_powershell_json(_PS_DRIVERS, timeout=90)):
            if not isinstance(d, dict) or not d.get("PathName"):
                continue
            out.append(StartupEntry("driver", str(d.get("Name", "")), "Drivers do sistema", str(d["PathName"]),
                                    enabled=str(d.get("StartMode")).lower() != "disabled",
                                    extra={"display": d.get("DisplayName"), "start_mode": d.get("StartMode"),
                                           "state": d.get("State")}))
        return out

    # ------------------------------------------------------------------ avaliação
    def evaluate(self, e: StartupEntry, deep: bool = True) -> Finding:
        cmd = normalize_nt(expand_env(e.command))
        exe, args = split_command(cmd)
        base = ntpath.basename(exe).lower()
        targets = extract_targets(args) if base in LOLBINS else []
        e.exe, e.target = exe, (targets[0] if targets else exe)
        tgt = e.target
        f = Finding(path=tgt or e.command, category=CATEGORY)
        f.extra = {"kind": "startup", "entry_kind": e.kind, "entry_name": e.name, "location": e.location, "command": e.command}

        for rx, desc, weight, code in CMD_PATTERNS:
            if rx.search(cmd):
                f.add(code, desc, weight, CATEGORY)
        if base in LOLBINS:
            f.add("st_lolbin", f"Persistência executada via {base} (uso comum, mas também abusado por malware)", 4)
        exists = bool(tgt) and os.path.exists(tgt)
        if tgt and not exists and e.kind != "driver":
            f.add("st_missing", "Entrada aponta para arquivo inexistente (resíduo ou binário removido)", 5)
        if tgt and in_temp_dir(tgt):
            f.add("st_temp", "Persistência executando a partir de diretório temporário", 30, CATEGORY)
        if tgt and ntpath.basename(tgt).lower() in config.SYSTEM_PROCESS_NAMES and not is_legit_system_location(tgt):
            f.add("mimic_name", f"Nome de componente do Windows ({ntpath.basename(tgt)}) fora de System32", 60,
                  "Imitação de processo do Windows")
        dll = e.extra.get("service_dll")
        if dll and not under_windir(dll):
            f.add("st_service_dll", f"ServiceDll fora do diretório do Windows: {dll}", 30, CATEGORY)
            if in_temp_dir(dll):
                f.add("st_service_dll_temp", "ServiceDll em diretório temporário", 30, CATEGORY)
        if e.kind == "driver" and tgt and not under_windir(tgt):
            f.add("st_driver_path", "Driver carregado de fora do diretório do Windows", 10)

        if deep and exists and not under_windir(tgt) and os.path.isfile(tgt):
            ff = self.fa.analyze(tgt, check_signature=False)
            if ff:
                merge_evidences(f, ff)
            company = read_company_name(tgt)
            e.company = company or ""
            if company == "":
                f.add("no_company", "Executável sem fabricante identificado", 3)
        e.finding = f
        return f

    def analyze(self, entries: list[StartupEntry] | None = None, kinds=("registry", "folders", "services", "tasks", "drivers"),
                deep: bool = True) -> list[StartupEntry]:
        entries = entries if entries is not None else self.collect(kinds)
        for e in entries:
            self.evaluate(e, deep)
        # Assinaturas digitais em lote, só para binários fora do diretório do Windows
        paths = sorted({e.target for e in entries if e.target and os.path.isfile(e.target) and not under_windir(e.target)})
        sigs: dict = {}
        for i in range(0, len(paths), 40):
            sigs.update(self.fa.get_signatures(paths[i:i + 40]))
        for e in entries:
            sig = sigs.get(e.target)
            if sig and e.finding:
                self.fa.apply_signature(e.finding, sig)
                e.signature = e.finding.signature
                if sig["status"] == "NotSigned" and in_user_writable_dir(e.target):
                    e.finding.add("st_unsigned_user", "Persistência sem assinatura digital em diretório do usuário", 10, CATEGORY)
            if e.finding:
                e.finding.finalize()
        return entries


class StartupError(Exception):
    pass


class StartupManager:
    """Desativa/reativa entradas de forma reversível. Nunca exclui serviços, nunca toca em drivers."""

    def __init__(self, access=None, db=None, backup=None):
        self.access = access if access is not None else RegistryAccess()
        self.db, self.backup = db, backup or backup_key

    @staticmethod
    def is_critical(e: StartupEntry) -> bool:
        if e.kind == "driver":
            return True
        if e.kind in ("service", "task"):
            # Usa o alvo já avaliado ou reextrai do comando: uma entrada criada
            # manualmente (sem passar por evaluate) não pode burlar a proteção.
            exe = e.exe or split_command(normalize_nt(expand_env(e.command)))[0]
            if exe and under_windir(exe):
                return True
            if e.kind == "task" and e.extra.get("task_path", "").lower().startswith("\\microsoft\\windows\\"):
                return True
        return False

    def _backup_key(self, hive, key):
        if key and self.access.key_exists(hive, key):
            return self.backup(hive, key)
        return None

    def _log(self, action, e, detail, ok=True):
        if self.db:
            self.db.log_action(action, f"{e.kind}:{e.name}", detail, ok)

    def _check(self, e, confirmed, confirm_critical):
        if not confirmed:
            raise StartupError("A operação exige confirmação explícita do usuário.")
        if e.kind == "driver":
            raise StartupError("Drivers não podem ser desativados por esta ferramenta.")
        if self.is_critical(e) and not confirm_critical:
            raise StartupError("Item do Windows: é necessária uma confirmação adicional (confirm_critical).")

    def disable(self, e: StartupEntry, confirmed: bool, confirm_critical: bool = False) -> dict:
        self._check(e, confirmed, confirm_critical)
        info: dict = {"entry": e.name, "kind": e.kind}
        try:
            if e.kind in ("run", "startup_folder") and e.extra.get("approved_key"):
                info["backup"] = str(self._backup_key(e.extra["hive"], e.extra["approved_key"]) or "")
                self.access.set_value(e.extra["hive"], e.extra["approved_key"], e.extra["approved_name"],
                                      approved_disabled(), "REG_BINARY")
            elif e.kind in ("runonce", "run_policy") or (e.kind == "run"):
                info["backup"] = str(self._backup_key(e.extra["hive"], e.extra["key"]) or "")
                self.access.delete_value(e.extra["hive"], e.extra["key"], e.extra["value"])
            elif e.kind == "service":
                self._service_start_type(e, "disabled", info)
            elif e.kind == "task":
                self._task_state(e, False)
            else:
                raise StartupError("Tipo de entrada não suportado.")
        except (RegistryError, OSError) as exc:
            self._log("startup_disable", e, str(exc), False)
            raise StartupError(str(exc)) from exc
        e.enabled = False
        self._log("startup_disable", e, json.dumps(info))
        return info

    def enable(self, e: StartupEntry, confirmed: bool, confirm_critical: bool = False) -> None:
        self._check(e, confirmed, confirm_critical)
        if e.kind in ("run", "startup_folder") and e.extra.get("approved_key"):
            self.access.set_value(e.extra["hive"], e.extra["approved_key"], e.extra["approved_name"],
                                  approved_enabled(), "REG_BINARY")
        elif e.kind == "service":
            self._service_start_type(e, e.extra.get("previous_start") or "demand", {})
        elif e.kind == "task":
            self._task_state(e, True)
        else:
            raise StartupError("Esta entrada foi removida do Registro; restaure o backup .reg correspondente.")
        e.enabled = True
        self._log("startup_enable", e, "")

    def _service_start_type(self, e, mode, info):
        if not IS_WINDOWS:
            raise StartupError("Serviços só podem ser alterados no Windows.")
        if not re.fullmatch(r"[A-Za-z0-9_.\-$]+", e.name):
            raise StartupError("Nome de serviço inválido.")
        e.extra["previous_start"] = {"automatic": "auto", "manual": "demand"}.get(e.extra.get("start_type"), "demand")
        info["previous_start_type"] = e.extra["previous_start"]
        proc = subprocess.run(["sc.exe", "config", e.name, "start=", mode], capture_output=True, text=True,
                              errors="replace", timeout=30, creationflags=CREATE_NO_WINDOW)
        if proc.returncode != 0:
            raise StartupError(f"sc config falhou: {(proc.stdout or proc.stderr).strip()}")

    def _task_state(self, e, enable: bool):
        if not IS_WINDOWS:
            raise StartupError("Tarefas agendadas só podem ser alteradas no Windows.")
        cmd = ("Enable-ScheduledTask" if enable else "Disable-ScheduledTask") + \
              " -TaskName $env:SENTINEL_TASKNAME -TaskPath $env:SENTINEL_TASKPATH | Out-Null"
        env = dict(os.environ, SENTINEL_TASKNAME=e.extra["task_name"], SENTINEL_TASKPATH=e.extra["task_path"])
        proc = run_powershell(cmd, timeout=60, env=env)
        if proc.returncode != 0:
            raise StartupError(f"Falha ao alterar a tarefa: {(proc.stderr or '').strip()}")
