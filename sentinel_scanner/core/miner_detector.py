"""Detecção de mineradores de criptomoedas por COMBINAÇÃO de indicadores independentes
("famílias"): linha de comando, rede (pools), arquivo, disfarce/local, persistência e recursos
(CPU/GPU sustentados). CPU/GPU isolados nunca geram alerta; com uma única família o risco é
limitado (ALTO se a evidência for forte, senão MÉDIO)."""
from __future__ import annotations

import re
import statistics
import time
from typing import Callable

from . import config
from .logger import get_logger
from .models import Finding, RiskLevel
from .network_analyzer import MINING_PORTS, MiningPools
from .platform_utils import IS_WINDOWS, PowerShellError, run_powershell_json
from .safety import norm

try:
    import psutil
except ImportError:
    psutil = None

log = get_logger(__name__)
STRATUM = re.compile(r"stratum\+(tcp|ssl|tls)://", re.I)
MINER_FLAGS = re.compile(r"--donate-level|--coin[= ]\S+|\bxmrig\b|--cpu-priority|--randomx|-a\s+(rx/0|cn/r|ethash|kawpow)", re.I)
MONERO_ADDR = re.compile(r"\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b")
_PS_GPU = ("[Console]::OutputEncoding=[Text.Encoding]::UTF8;$c=(Get-Counter '\\GPU Engine(*)\\Utilization Percentage' "
           "-ErrorAction Stop).CounterSamples|Where-Object{$_.CookedValue -gt 0}|Select-Object InstanceName,CookedValue;"
           "ConvertTo-Json -InputObject @($c) -Compress")


class MinerDetector:
    def __init__(self, pools: MiningPools | None = None, cpu_threshold: float = 40.0, gpu_threshold: float = 50.0,
                 use_gpu: bool = True):
        self.pools = pools or MiningPools()
        self.cpu_threshold, self.gpu_threshold = cpu_threshold, gpu_threshold
        self.use_gpu = use_gpu and IS_WINDOWS
        self.stats: dict[tuple, dict] = {}

    def _gpu_usage(self) -> dict[int, float]:
        if not self.use_gpu:
            return {}
        try:
            rows = run_powershell_json(_PS_GPU, timeout=30) or []
        except PowerShellError:
            self.use_gpu = False  # contadores indisponíveis neste PC
            return {}
        out: dict[int, float] = {}
        for r in rows if isinstance(rows, list) else [rows]:
            m = re.search(r"pid_(\d+)_", r.get("InstanceName", ""))
            if m:
                out[int(m.group(1))] = out.get(int(m.group(1)), 0.0) + float(r.get("CookedValue", 0))
        return out

    def sample(self, duration: float = 20.0, interval: float = 2.0, cancel: Callable[[], bool] | None = None,
               progress: Callable[[float], None] | None = None) -> dict:
        """Mede CPU (e GPU) por processo durante `duration` segundos. Retorna e guarda as estatísticas."""
        if psutil is None:
            raise RuntimeError("psutil não está instalado.")
        n = psutil.cpu_count() or 1
        procs = {p.pid: p for p in psutil.process_iter()}
        for p in procs.values():
            try:
                p.cpu_percent(None)
            except psutil.Error:
                pass
        cpu: dict[tuple, list[float]] = {}
        gpu: dict[tuple, list[float]] = {}
        steps = max(1, int(duration / interval))
        keys: dict[int, tuple] = {}
        for i in range(steps):
            if cancel and cancel():
                break
            time.sleep(interval)
            g = self._gpu_usage()
            for pid, p in list(procs.items()):
                try:
                    key = keys.setdefault(pid, (pid, p.create_time()))
                    cpu.setdefault(key, []).append(p.cpu_percent(None) / n)
                    gpu.setdefault(key, []).append(g.get(pid, 0.0))
                except psutil.Error:
                    procs.pop(pid, None)
            if progress:
                progress((i + 1) / steps)
        self.stats = {}
        for key, vals in cpu.items():
            gv = gpu.get(key, [0.0])
            self.stats[key] = {
                "samples": len(vals), "cpu_avg": statistics.fmean(vals),
                "cpu_frac": sum(v >= self.cpu_threshold for v in vals) / len(vals),
                "gpu_avg": statistics.fmean(gv), "gpu_frac": sum(v >= self.gpu_threshold for v in gv) / len(gv)}
        return self.stats

    def detect(self, processes: list, connections: list, startup_paths: set[str] | None = None,
               file_findings: dict[str, Finding] | None = None) -> list[Finding]:
        """processes: ProcessInfo; connections: Connection; startup_paths: caminhos com persistência;
        file_findings: {caminho normalizado: Finding} de varreduras de arquivos."""
        if not self.pools.resolved and connections:
            self.pools.resolve()
        by_pid: dict[int, list] = {}
        for c in connections:
            by_pid.setdefault(c.pid, []).append(c)
        startup_paths = {norm(p) for p in (startup_paths or set())}
        file_findings = file_findings or {}
        results = []
        for info in processes:
            fam: set[str] = set()
            f = Finding(path=info.exe or f"[PID {info.pid}] {info.name}", category="Minerador")
            f.extra = {"kind": "miner", "pid": info.pid, "name": info.name}
            cmd = " ".join(info.cmdline)
            if STRATUM.search(cmd):
                f.add("miner_cmd_stratum", "Linha de comando contém URL de pool (stratum+tcp://)", 60, "Minerador"); fam.add("cmdline")
            elif MINER_FLAGS.search(cmd):
                f.add("miner_cmd_flags", "Parâmetros típicos de mineradores na linha de comando", 30, "Minerador"); fam.add("cmdline")
            if MONERO_ADDR.search(cmd):
                f.add("miner_wallet", "Endereço de carteira Monero na linha de comando", 40, "Minerador"); fam.add("cmdline")
            for c in by_pid.get(info.pid, []):
                host = c.host or self.pools.ip_to_host.get(c.raddr, "")
                if c.external and host:
                    f.add("miner_pool_conn", f"Conexão com pool de mineração conhecido ({host})", 60, "Minerador"); fam.add("network")
                elif c.external and c.rport in MINING_PORTS:
                    f.add("miner_port", f"Conexão externa em porta típica de mineração ({c.rport})", 10, "Minerador"); fam.add("network")
            ff = file_findings.get(norm(info.exe)) if info.exe else None
            if ff and any(e.code.startswith("miner") for e in ff.evidences):
                f.add("miner_file", "O executável contém strings/protocolos de mineração", 40, "Minerador"); fam.add("file")
            st = self.stats.get((info.pid, info.create_time))
            if st:
                if st["cpu_frac"] >= 0.8 and st["samples"] >= 3:
                    f.add("miner_cpu", f"CPU sustentada ({st['cpu_avg']:.0f}% do total) durante a amostragem", 10); fam.add("resource")
                if st["gpu_frac"] >= 0.8 and st["samples"] >= 3:
                    f.add("miner_gpu", f"GPU sustentada ({st['gpu_avg']:.0f}%) durante a amostragem", 8); fam.add("resource")
            pf = info.finding
            if pf and fam - {"resource"}:
                if any(e.code in ("proc_mimic", "proc_lookalike") for e in pf.evidences):
                    f.add("miner_disguise", "Processo disfarçado de componente do Windows", 15); fam.add("disguise")
                if any(e.code in ("proc_temp", "proc_deleted", "proc_recycle") for e in pf.evidences):
                    f.add("miner_hidden_loc", "Executando de local incomum/ocultando o binário", 10); fam.add("disguise")
                if info.exe and norm(info.exe) in startup_paths:
                    f.add("miner_persist", "Possui mecanismo de inicialização automática", 8); fam.add("persistence")
            if not fam or fam == {"resource"}:
                continue  # CPU/GPU alta isolada não é evidência
            f.extra["families"] = sorted(fam)
            f.finalize()
            if len(fam) < 2:
                strong = any(e.weight >= 60 for e in f.evidences)
                f.risk = min(f.risk, RiskLevel.ALTO if strong else RiskLevel.MEDIO)
            if f.risk >= RiskLevel.BAIXO:
                results.append(f)
        return sorted(results, key=lambda x: -x.score)
