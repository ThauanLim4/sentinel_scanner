"""Análise de processos em execução (psutil). Alto consumo de CPU NUNCA é evidência isolada;
o risco vem de combinações verificáveis: nome imitando o Windows, local incomum, processo-pai
anômalo, binário removido do disco, hash conhecido, assinatura inválida.
Encerrar processos exige confirmação e recusa processos críticos, o próprio programa e
processos que hospedam serviços do Windows."""
from __future__ import annotations

import ntpath
import os
import time
from dataclasses import dataclass, field
from datetime import datetime

from . import config
from .file_analyzer import (FileAnalyzer, _edit_distance_le1, in_temp_dir, is_legit_system_location,
                            read_company_name, under_windir)
from .logger import get_logger
from .models import Finding, RiskLevel, merge_evidences
from .safety import norm

try:
    import psutil
except ImportError:
    psutil = None

log = get_logger(__name__)
EXPECTED_PARENT = {"svchost.exe": "services.exe", "services.exe": "wininit.exe", "lsass.exe": "wininit.exe",
                   "taskhostw.exe": "svchost.exe", "runtimebroker.exe": "svchost.exe", "sihost.exe": "svchost.exe"}
CRITICAL_NAMES = config.SYSTEM_PROCESS_NAMES | {"system", "registry", "memcompression", "lsaiso.exe", "dwm.exe",
                                                  "audiodg.exe", "wudfhost.exe", "system idle process"}


@dataclass
class ProcessInfo:
    pid: int
    name: str
    exe: str = ""
    username: str = ""
    cmdline: list = field(default_factory=list)
    cpu_percent: float = 0.0
    rss: int = 0
    create_time: float = 0.0
    ppid: int = 0
    parent_name: str = ""
    company: str = ""
    signature: str = ""
    connections: list = field(default_factory=list)
    finding: Finding | None = None

    @property
    def risk(self) -> RiskLevel:
        return self.finding.risk if self.finding else RiskLevel.SEGURO

    def to_dict(self) -> dict:
        return {"pid": self.pid, "name": self.name, "exe": self.exe, "user": self.username,
                "cpu": round(self.cpu_percent, 1), "ram_mb": round(self.rss / 1048576, 1),
                "started": datetime.fromtimestamp(self.create_time).isoformat(timespec="seconds") if self.create_time else "",
                "ppid": self.ppid, "parent": self.parent_name, "signature": self.signature, "company": self.company,
                "connections": len(self.connections), "risk": self.risk.label,
                "justification": self.finding.justification if self.finding else ""}


def _safe(fn, default=""):
    try:
        return fn()
    except Exception:  # AccessDenied, NoSuchProcess, ZombieProcess...
        return default


def is_critical_process(name: str, exe: str, pid: int) -> bool:
    if pid in (0, 4) or pid == os.getpid():
        return True
    n = name.lower()
    if n in CRITICAL_NAMES:
        return (not exe) or is_legit_system_location(exe)  # imitador fora de System32 não é "crítico"
    return False


class ProcessAnalyzer:
    def __init__(self, file_analyzer: FileAnalyzer | None = None, db=None):
        self.fa = file_analyzer or FileAnalyzer(db)
        self.db = db

    def snapshot(self, cpu_interval: float = 0.5, connections_by_pid: dict | None = None, deep: bool = True,
                 signatures: str = "suspicious") -> list[ProcessInfo]:
        """signatures: 'none' | 'suspicious' (só processos com indícios) | 'all'."""
        if psutil is None:
            raise RuntimeError("psutil não está instalado.")
        procs = list(psutil.process_iter())
        for p in procs:
            _safe(lambda p=p: p.cpu_percent(None))
        if cpu_interval > 0:
            time.sleep(cpu_interval)
        infos: list[ProcessInfo] = []
        for p in procs:
            try:
                with p.oneshot():
                    info = ProcessInfo(
                        pid=p.pid, name=_safe(p.name), exe=_safe(p.exe) or "", username=_safe(p.username) or "",
                        cmdline=_safe(p.cmdline, []) or [], cpu_percent=_safe(lambda: p.cpu_percent(None), 0.0),
                        rss=_safe(lambda: p.memory_info().rss, 0), create_time=_safe(p.create_time, 0.0),
                        ppid=_safe(p.ppid, 0))
            except psutil.Error:
                continue
            if connections_by_pid:
                info.connections = [c.to_dict() if hasattr(c, "to_dict") else c for c in connections_by_pid.get(p.pid, [])]
            infos.append(info)
        names = {i.pid: i.name for i in infos}
        for i in infos:
            i.parent_name = names.get(i.ppid, "")
            self.evaluate(i, deep)
        self._apply_signatures(infos, signatures)
        return sorted(infos, key=lambda i: (-int(i.risk), i.name.lower()))

    def evaluate(self, info: ProcessInfo, deep: bool = True) -> Finding:
        f = Finding(path=info.exe or f"[PID {info.pid}] {info.name}")
        f.extra = {"kind": "process", "pid": info.pid, "name": info.name, "create_time": info.create_time}
        name, exe = info.name.lower(), info.exe
        if exe:
            if name in config.SYSTEM_PROCESS_NAMES and not is_legit_system_location(exe):
                f.add("proc_mimic", f"Processo com nome de componente do Windows ({info.name}) executando fora de System32",
                      60, "Imitação de processo do Windows")
            elif name.endswith(".exe") and any(_edit_distance_le1(name, n) for n in config.SYSTEM_PROCESS_NAMES):
                f.add("proc_lookalike", f"Nome muito parecido com componente do Windows ({info.name})", 30,
                      "Imitação de processo do Windows")
            if in_temp_dir(exe):
                f.add("proc_temp", "Processo executando a partir de diretório temporário", 20)
            s = norm(exe) + "\\"
            if "\\$recycle.bin\\" in s:
                f.add("proc_recycle", "Processo executando a partir da Lixeira", 25)
            if "\\users\\public\\" in s:
                f.add("proc_public", "Processo executando a partir de Users\\Public", 8)
            if not os.path.exists(exe):
                f.add("proc_deleted", "O binário do processo não existe mais em disco", 20)
            if info.rss > 2 * 1024 ** 3 and "\\appdata\\" in s:
                f.add("proc_mem", "Consumo de memória elevado em processo de diretório do usuário", 3)
        expected = EXPECTED_PARENT.get(name)
        if expected and info.parent_name and info.parent_name.lower() != expected and (not exe or is_legit_system_location(exe)):
            f.add("proc_parent", f"Processo-pai anômalo: {info.parent_name} (esperado: {expected})", 30,
                  "Processo com origem anômala")
        if deep and exe and os.path.isfile(exe) and not under_windir(exe):
            ff = self.fa.analyze(exe, check_signature=False)
            if ff:
                merge_evidences(f, ff)
            company = read_company_name(exe)
            info.company = company or ""
            if company == "":
                f.add("no_company", "Executável sem fabricante identificado", 3)
        info.finding = f.finalize()
        return info.finding

    def _apply_signatures(self, infos, mode: str) -> None:
        if mode == "none":
            return
        todo = [i for i in infos if i.exe and os.path.isfile(i.exe) and not under_windir(i.exe)
                and (mode == "all" or (i.finding and i.finding.score > 0))]
        paths = sorted({i.exe for i in todo})
        sigs: dict = {}
        for k in range(0, len(paths), 40):
            sigs.update(self.fa.get_signatures(paths[k:k + 40]))
        for i in todo:
            sig = sigs.get(i.exe)
            if sig and i.finding:
                self.fa.apply_signature(i.finding, sig)
                i.signature = i.finding.signature
                i.finding.finalize()

    # ------------------------------------------------------------ encerramento seguro
    def terminate(self, pid: int, expected_create_time: float, confirmed: bool, kill_tree: bool = False,
                  timeout: float = 5.0) -> dict:
        """Encerra um processo NÃO crítico após confirmação. Valida create_time (evita reuso de PID),
        recusa processos críticos/próprio programa e processos que hospedam serviços do Windows."""
        if psutil is None:
            raise RuntimeError("psutil não está instalado.")
        if not confirmed:
            raise PermissionError("Encerrar um processo exige confirmação explícita.")
        try:
            p = psutil.Process(pid)
            name, exe = _safe(p.name), _safe(p.exe) or ""
            if abs(_safe(p.create_time, 0.0) - expected_create_time) > 1.0:
                raise PermissionError("O PID agora pertence a outro processo (reutilizado); operação cancelada.")
            if is_critical_process(name, exe, pid):
                raise PermissionError(f"'{name}' é um processo crítico do sistema e não será encerrado.")
            for svc in (psutil.win_service_iter() if hasattr(psutil, "win_service_iter") else []):
                if _safe(lambda s=svc: s.as_dict().get("pid"), None) == pid:
                    raise PermissionError(f"'{name}' hospeda o serviço '{svc.name()}'. Desative o serviço em vez de "
                                          "encerrar o processo.")
            children = _safe(lambda: p.children(recursive=True), [])
            victims = (children if kill_tree else []) + [p]
            for v in victims:
                _safe(v.terminate)
            gone, alive = psutil.wait_procs(victims, timeout=timeout)
            for v in alive:
                _safe(v.kill)
            info = {"pid": pid, "name": name, "exe": exe, "children_found": len(children),
                    "terminated": len(victims)}
        except psutil.NoSuchProcess as exc:
            raise ProcessLookupError("O processo não existe mais.") from exc
        except psutil.AccessDenied as exc:
            if self.db:
                self.db.log_action("process_terminate", str(pid), "acesso negado", False)
            raise PermissionError("Acesso negado: execute como administrador.") from exc
        if self.db:
            self.db.log_action("process_terminate", f"{pid}:{name}", f"exe={exe}", True)
        return info
