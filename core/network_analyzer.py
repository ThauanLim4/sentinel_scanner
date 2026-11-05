"""Análise de conexões de rede ativas (psutil). Nenhuma conexão é bloqueada automaticamente.
Indicadores são fracos individualmente; servidores de pools de mineração conhecidos são resolvidos
por DNS no momento da análise (lista editável em data/signatures/mining_pools.txt)."""
from __future__ import annotations

import ipaddress
import socket
import time
from concurrent.futures import ThreadPoolExecutor, wait
from dataclasses import dataclass

from . import config
from .file_analyzer import in_user_writable_dir
from .logger import get_logger
from .models import Finding

try:
    import psutil
except ImportError:
    psutil = None

log = get_logger(__name__)
COMMON_PORTS = {20, 21, 22, 25, 53, 80, 110, 123, 143, 443, 465, 587, 853, 993, 995, 3478, 5222, 5228, 8080, 8443}
MINING_PORTS = {3333, 4444, 5555, 7777, 14433, 14444, 45560, 45700}
_CGNAT = ipaddress.ip_network("100.64.0.0/10")
DEFAULT_POOL_HOSTS = [
    "pool.supportxmr.com", "pool.minexmr.com", "xmr.nanopool.org", "xmr-eu1.nanopool.org", "xmr-us-east1.nanopool.org",
    "gulf.moneroocean.stream", "pool.hashvault.pro", "mine.c3pool.com", "xmrpool.eu", "monerohash.com",
    "stratum.slushpool.com", "eth.2miners.com", "xmr.2miners.com", "rx.unmineable.com",
]
CATEGORY = "Comunicação de rede suspeita"


@dataclass
class Connection:
    pid: int
    process: str
    exe: str
    proto: str
    laddr: str
    lport: int
    raddr: str
    rport: int
    status: str
    external: bool
    host: str = ""

    def to_dict(self) -> dict:
        return dict(self.__dict__)


def is_external(ip: str) -> bool:
    """True apenas para endereços roteáveis na Internet pública.

    Faixas privadas, loopback, link-local, multicast, reservadas, CGNAT
    (100.64.0.0/10) e documentação não geram tráfego externo real.
    """
    try:
        a = ipaddress.ip_address(ip.split("%")[0])
    except ValueError:
        return False
    if getattr(a, "ipv4_mapped", None):
        a = a.ipv4_mapped
    if isinstance(a, ipaddress.IPv4Address) and a in _CGNAT:
        return False
    # `is_global` sozinho considera multicast (224.0.0.0/4) global; essas faixas
    # nunca representam um destino roteável de Internet.
    if (a.is_multicast or a.is_reserved or a.is_link_local or a.is_loopback
            or a.is_private or a.is_unspecified):
        return False
    return bool(a.is_global)


class MiningPools:
    def __init__(self, hosts: list[str] | None = None):
        # `[]` explícito significa "nenhum pool"; só `None` usa a lista padrão.
        self.hosts = list(DEFAULT_POOL_HOSTS if hosts is None else hosts)
        extra = config.SIGNATURES_DIR / "mining_pools.txt"
        if extra.exists():
            self.hosts += [h.strip() for h in extra.read_text(encoding="utf-8", errors="ignore").splitlines()
                           if h.strip() and not h.startswith("#")]
        self.ip_to_host: dict[str, str] = {}
        self.resolved = False

    def resolve(self, timeout: float = 4.0) -> dict[str, str]:
        self.resolved = True
        def one(host):
            try:
                return host, {ai[4][0] for ai in socket.getaddrinfo(host, None)}
            except OSError:
                return host, set()
        ex = ThreadPoolExecutor(max_workers=8)
        done, _ = wait([ex.submit(one, h) for h in self.hosts], timeout=timeout)
        for fut in done:
            try:
                host, ips = fut.result()
            except (OSError, ValueError) as exc:  # DNS/execução do worker
                log.debug("Falha ao resolver pool: %s", exc)
                continue
            for ip in ips:
                self.ip_to_host[ip] = host
        ex.shutdown(wait=False, cancel_futures=True)
        return self.ip_to_host


class NetworkAnalyzer:
    def __init__(self, pools: MiningPools | None = None):
        self.pools = pools or MiningPools()
        self._first_seen: dict[tuple, float] = {}

    def snapshot(self) -> list[Connection]:
        if psutil is None:
            raise RuntimeError("psutil não está instalado.")
        try:
            raw = psutil.net_connections(kind="inet")
        except psutil.AccessDenied:
            log.warning("Sem permissão para listar conexões (execute como administrador).")
            return []
        except psutil.Error as exc:
            log.warning("Falha ao listar conexões: %s", exc)
            return []
        names: dict[int, tuple[str, str]] = {}
        out, now = [], time.time()
        for c in raw:
            if not c.pid:
                continue
            if c.pid not in names:
                try:
                    p = psutil.Process(c.pid)
                    names[c.pid] = (p.name(), p.exe())
                except psutil.Error:
                    names[c.pid] = ("", "")
            r_ip, r_port = (c.raddr.ip, c.raddr.port) if c.raddr else ("", 0)
            conn = Connection(c.pid, names[c.pid][0], names[c.pid][1], "TCP" if c.type == socket.SOCK_STREAM else "UDP",
                              c.laddr.ip if c.laddr else "", c.laddr.port if c.laddr else 0, r_ip, r_port,
                              c.status or "", bool(r_ip) and is_external(r_ip))
            out.append(conn)
            if conn.external:
                self._first_seen.setdefault((c.pid, r_ip, r_port), now)
        return out

    @staticmethod
    def by_pid(conns: list[Connection]) -> dict[int, list[Connection]]:
        out: dict[int, list[Connection]] = {}
        for c in conns:
            out.setdefault(c.pid, []).append(c)
        return out

    def analyze(self, conns: list[Connection], resolve_pools: bool = True, persistent_after: float = 300.0) -> list[Finding]:
        if resolve_pools and not self.pools.resolved:
            self.pools.resolve()
        groups: dict[str, list[Connection]] = {}
        for c in conns:
            groups.setdefault(c.exe or f"[PID {c.pid}] {c.process}", []).append(c)
        findings = []
        now = time.time()
        for key, group in groups.items():
            ext = [c for c in group if c.external]
            if not ext:
                continue
            for c in ext:
                c.host = self.pools.ip_to_host.get(c.raddr, "")
            f = Finding(path=key)
            f.extra = {"kind": "network", "pids": sorted({c.pid for c in group}),
                       "connections": [c.to_dict() for c in ext[:50]]}
            pool = [c for c in ext if c.host]
            if pool:
                f.add("net_pool", f"Conexão com servidor de pool de mineração conhecido ({pool[0].host}:{pool[0].rport})", 60, "Minerador")
            elif any(c.rport in MINING_PORTS for c in ext):
                f.add("net_miner_port", "Conexão externa em porta típica de mineração (indicador fraco)", 10, "Minerador")
            established = [c for c in ext if c.status == "ESTABLISHED"]
            uncommon = [c for c in established if c.rport not in COMMON_PORTS]
            if uncommon:
                f.add("net_uncommon", f"Conexão externa em porta incomum ({uncommon[0].rport})", 3)
                if in_user_writable_dir(key):
                    f.add("net_c2_pattern", "Programa em diretório do usuário com conexão externa direta (por IP) em porta incomum — "
                          "padrão compatível com C2, mas também com jogos/P2P", 12, CATEGORY)
            if any(now - self._first_seen.get((c.pid, c.raddr, c.rport), now) >= persistent_after for c in established):
                f.add("net_persistent", "Comunicação externa persistente com o mesmo destino", 5)
            f.extra["external_count"] = len(ext)
            findings.append(f.finalize())
        return findings
