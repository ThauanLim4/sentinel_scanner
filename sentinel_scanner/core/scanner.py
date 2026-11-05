"""Motor de varredura de arquivos: percorre diretórios sem seguir links/junctions, analisa só o que
importa (executáveis, scripts e documentos em locais sensíveis), em paralelo controlado, com
limite de CPU, cancelamento, progresso em tempo real e varredura incremental (arquivos limpos e
inalterados são pulados nas próximas execuções)."""
from __future__ import annotations

import hashlib
import os
import platform
import queue
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from . import config
from .file_analyzer import FileAnalyzer
from .logger import get_logger
from .models import Finding, RiskLevel
from .safety import is_reparse_point, is_within, norm

try:
    import psutil
except ImportError:
    psutil = None

log = get_logger(__name__)
ATTR_CLOUD = 0x400000 | 0x40000 | 0x1000  # RECALL_ON_DATA_ACCESS | RECALL_ON_OPEN | OFFLINE
SENSITIVE_MARKERS = ("\\downloads\\", "\\temp\\", "\\appdata\\", "\\programdata\\", "\\startup\\", "\\desktop\\",
                     "\\users\\public\\")


@dataclass
class ScanProgress:
    phase: str
    files_seen: int = 0
    files_analyzed: int = 0
    files_cached: int = 0
    findings: int = 0
    inaccessible: int = 0
    current: str = ""
    elapsed: float = 0.0


@dataclass
class ScanResult:
    scan_id: int
    kind: str
    duration: float
    files_seen: int
    files_analyzed: int
    files_cached: int
    inaccessible: int
    cancelled: bool
    findings: list = field(default_factory=list)
    errors: list = field(default_factory=list)


def default_targets(kind: str) -> list[Path]:
    env = os.environ.get
    win, pd = env("SystemRoot", r"C:\Windows"), env("ProgramData")
    appdata, local, temp = env("APPDATA"), env("LOCALAPPDATA"), env("TEMP")
    home = Path.home()
    startup = lambda b, n: Path(b) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / n if b else None
    quick = [temp, str(Path(win) / "Temp"), startup(appdata, "Startup"), startup(pd, "StartUp"), home / "Downloads",
             home / "Desktop", Path(local) / "Temp" if local else None, appdata, pd, Path(env("PUBLIC", "C:\\Users\\Public"))]
    full = quick + [win, env("ProgramFiles"), env("ProgramFiles(x86)"), Path(env("SystemDrive", "C:") + "\\Users"), local]
    cands = [Path(p) for p in (full if kind == "full" else quick) if p]
    cands = [c for c in cands if c.exists()]
    # remove diretórios contidos em outros (evita varrer duas vezes)
    cands.sort(key=lambda p: len(str(p)))
    out: list[Path] = []
    for c in cands:
        if not any(is_within(c, o) for o in out):
            out.append(c)
    return out


class Scanner:
    def __init__(self, db, analyzer: FileAnalyzer | None = None, workers: int | None = None, cpu_limit: int = 60):
        self.db = db
        self.analyzer = analyzer or FileAnalyzer(db)
        self.workers = workers or max(1, min(4, (os.cpu_count() or 2) // 2))
        self.cpu_limit = cpu_limit
        self._cancel = threading.Event()
        self._lock = threading.Lock()
        known = "".join(sorted(self.analyzer.known_hashes))
        self.engine = f"{config.APP_VERSION}:{len(self.analyzer.known_hashes)}:{hashlib.sha1(known.encode()).hexdigest()[:8]}"
        self._own_dirs = [config.QUARANTINE_DIR]
        self._reset()

    def cancel(self) -> None:
        self._cancel.set()

    def _reset(self):
        self.seen = self.analyzed = self.cached = self.inaccessible = 0
        self.raw: list[Finding] = []
        self.errors: list[str] = []
        self.current = ""
        self._thr_t = 0.0

    # --------------------------------------------------------------------- varredura
    def run(self, kind: str = "quick", paths: list | None = None,
            progress: Callable[[ScanProgress], None] | None = None) -> ScanResult:
        if kind not in ("quick", "full", "custom"):
            raise ValueError("kind deve ser quick, full ou custom")
        targets = [Path(p) for p in (paths or [])] if kind == "custom" else default_targets(kind)
        if kind == "custom" and not targets:
            raise ValueError("Informe ao menos um caminho para a varredura personalizada.")
        self._cancel.clear()
        self._reset()
        scan_id = self.db.start_scan(kind, platform.platform())
        t0 = time.time()
        restore_prio = self._lower_priority()
        q: queue.Queue = queue.Queue(maxsize=2000)
        threads = [threading.Thread(target=self._worker, args=(q,), daemon=True) for _ in range(self.workers)]
        for t in threads:
            t.start()
        last = 0.0

        def emit(phase="verificando", force=False):
            nonlocal last
            now = time.time()
            if progress and (force or now - last >= 0.2):
                last = now
                progress(ScanProgress(phase, self.seen, self.analyzed, self.cached, len(self.raw), self.inaccessible,
                                      self.current, now - t0))
        try:
            for root in targets:
                explicit = kind == "custom"
                for path, size, mtime_ns in self._walk(root, explicit):
                    if self._cancel.is_set():
                        break
                    self.seen += 1
                    self.current = path
                    if self.seen % 200 == 0:
                        self._throttle()
                    emit()
                    if self.db.is_clean_cached(path, size, mtime_ns, self.engine):
                        self.cached += 1
                        continue
                    while not self._cancel.is_set():
                        try:
                            q.put((path, size, mtime_ns), timeout=0.2)
                            break
                        except queue.Full:
                            emit()
                if self._cancel.is_set():
                    break
            for _ in threads:
                q.put(None)
            while any(t.is_alive() for t in threads):
                for t in threads:
                    t.join(timeout=0.2)
                emit("analisando")
            findings = self._finish_findings(scan_id, emit)
        finally:
            restore_prio()
        cancelled = self._cancel.is_set()
        self.db.finish_scan(scan_id, self.seen, 0, "cancelled" if cancelled else "completed")
        emit("concluído", force=True)
        return ScanResult(scan_id, kind, time.time() - t0, self.seen, self.analyzed, self.cached, self.inaccessible,
                          cancelled, findings, list(self.errors))

    def start_async(self, *args, **kwargs) -> threading.Thread:
        """Executa em thread própria (a interface nunca trava). O resultado vai para `self.last_result`."""
        def target():
            try:
                self.last_result = self.run(*args, **kwargs)
            except Exception as exc:
                log.exception("Falha na varredura")
                self.last_error = exc
        self.last_result, self.last_error = None, None
        t = threading.Thread(target=target, daemon=True)
        t.start()
        return t

    # --------------------------------------------------------------------- internos
    def _is_own(self, path: str) -> bool:
        return any(is_within(path, d) for d in self._own_dirs)

    def _walk(self, root: Path, explicit: bool):
        """Gera (caminho, tamanho, mtime_ns) de candidatos. Não segue links/junctions e ignora
        placeholders de nuvem (ler um arquivo do OneDrive 'sob demanda' dispararia um download)."""
        if root.is_file():
            try:
                st = root.stat()
                yield str(root), st.st_size, st.st_mtime_ns
            except OSError:
                self.inaccessible += 1
            return
        stack = [str(root)]
        while stack and not self._cancel.is_set():
            d = stack.pop()
            try:
                with os.scandir(d) as it:
                    entries = list(it)
            except OSError:
                self.inaccessible += 1
                continue
            sensitive = explicit or any(m in norm(d) + "\\" for m in SENSITIVE_MARKERS)
            for e in entries:
                try:
                    if e.is_symlink():
                        continue
                    if e.is_dir(follow_symlinks=False):
                        if e.name.lower() in config.SCAN_EXCLUDED_DIR_NAMES or is_reparse_point(Path(e.path)) \
                                or self._is_own(e.path):
                            continue
                        stack.append(e.path)
                    elif e.is_file(follow_symlinks=False):
                        ext = os.path.splitext(e.name)[1].lower()
                        if not (ext in config.EXECUTABLE_EXT or ext in config.SCRIPT_EXT or
                                (sensitive and ext in config.DOCUMENT_EXT)):
                            continue
                        st = e.stat(follow_symlinks=False)
                        if getattr(st, "st_file_attributes", 0) & ATTR_CLOUD:
                            continue
                        yield e.path, st.st_size, st.st_mtime_ns
                except OSError:
                    self.inaccessible += 1

    def _worker(self, q: queue.Queue):
        clean: list[tuple] = []
        while True:
            item = q.get()
            if item is None:
                break
            if self._cancel.is_set():
                continue
            path, size, mtime_ns = item
            try:
                open(path, "rb").close()  # inacessível/em uso: não pode ser cacheado como "limpo"
            except OSError:
                with self._lock:
                    self.inaccessible += 1
                continue
            try:
                f = self.analyzer.analyze(path, check_signature=False)
            except Exception as exc:
                with self._lock:
                    self.errors.append(f"{path}: {exc}")
                continue
            with self._lock:
                self.analyzed += 1
                if f is not None:
                    self.raw.append(f)
            if f is None:
                clean.append((path, size, mtime_ns, self.engine))
                if len(clean) >= 200:
                    self.db.put_clean_many(clean)
                    clean = []
        if clean:
            self.db.put_clean_many(clean)

    def _finish_findings(self, scan_id: int, emit) -> list[Finding]:
        """Verifica assinaturas em lote (um PowerShell por 30 arquivos), reclassifica e persiste."""
        cand = [f for f in self.raw if f.sha256]
        for i in range(0, len(cand), 30):
            if self._cancel.is_set():
                break
            emit("verificando assinaturas", force=True)
            chunk = cand[i:i + 30]
            sigs = self.analyzer.get_signatures([f.path for f in chunk])
            for f in chunk:
                self.analyzer.apply_signature(f, sigs.get(f.path, {}))
        out = [f.finalize() for f in self.raw]
        out = sorted((f for f in out if f.risk >= RiskLevel.BAIXO), key=lambda f: -f.score)
        for f in out:
            self.db.add_finding(scan_id, f)
        return out

    def _throttle(self):
        if psutil is None or self.cpu_limit >= 100:
            return
        now = time.time()
        if now - self._thr_t < 1.0:
            return
        self._thr_t = now
        pct = psutil.Process().cpu_percent(None) / (psutil.cpu_count() or 1)
        if pct > self.cpu_limit:
            time.sleep(min(2.0, (pct - self.cpu_limit) / 50))

    def _lower_priority(self):
        if psutil is None or os.name != "nt":
            return lambda: None
        try:
            p = psutil.Process()
            old = p.nice()
            p.nice(psutil.BELOW_NORMAL_PRIORITY_CLASS)
            return lambda: p.nice(old)
        except psutil.Error:
            return lambda: None
