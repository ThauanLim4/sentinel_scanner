"""Testes de classificação de rede: só endereços públicos roteáveis contam como
'externos', e falhas de DNS de pools não podem derrubar a análise."""
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

os.environ.setdefault("SENTINEL_HOME", tempfile.mkdtemp(prefix="sentinel_ntest_home_"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.network_analyzer import Connection, MiningPools, NetworkAnalyzer, is_external


class ExternalAddressTests(unittest.TestCase):
    def test_public_addresses_are_external(self):
        for ip in ("8.8.8.8", "1.1.1.1", "93.184.216.34", "2001:4860:4860::8888", "::ffff:8.8.8.8"):
            self.assertTrue(is_external(ip), ip)

    def test_private_reserved_and_invalid_are_not_external(self):
        for ip in ("127.0.0.1", "10.0.0.1", "172.16.5.4", "192.168.1.5", "169.254.1.1",
                   "100.64.0.1", "0.0.0.0", "224.0.0.1", "255.255.255.255",
                   "203.0.113.7", "198.51.100.7", "not-an-ip", ""):
            self.assertFalse(is_external(ip), ip)

    def test_zone_id_is_stripped(self):
        self.assertFalse(is_external("fe80::1%eth0"))


class MiningPoolResolveTests(unittest.TestCase):
    def test_dns_failure_in_one_worker_does_not_break_others(self):
        def fake_getaddrinfo(host, port):
            if host == "falha.invalid":
                raise OSError("DNS indisponível")
            return [(2, 1, 6, "", ("198.51.100.7", 0))]

        pools = MiningPools([])
        pools.hosts = ["ok.example", "falha.invalid"]
        with mock.patch("core.network_analyzer.socket.getaddrinfo", side_effect=fake_getaddrinfo):
            result = pools.resolve(timeout=2.0)
        self.assertTrue(pools.resolved)
        self.assertEqual(result.get("198.51.100.7"), "ok.example")

    def test_empty_host_list_resolves_cleanly(self):
        pools = MiningPools([])
        self.assertEqual(pools.resolve(timeout=1.0), {})
        self.assertTrue(pools.resolved)


class NetworkFindingTests(unittest.TestCase):
    def conn(self, **kw) -> Connection:
        opts = dict(pid=1, process="app.exe", exe=r"C:\Program Files\App\app.exe", proto="TCP",
                    laddr="10.0.0.2", lport=50000, raddr="198.51.100.7", rport=443,
                    status="ESTABLISHED", external=True)
        opts.update(kw)
        return Connection(**opts)

    def analyzer(self) -> NetworkAnalyzer:
        pools = MiningPools([])
        pools.resolved = True
        return NetworkAnalyzer(pools)

    def test_internal_traffic_generates_nothing(self):
        self.assertEqual(self.analyzer().analyze([self.conn(external=False, raddr="10.0.0.9")]), [])

    def test_common_https_from_program_files_is_quiet(self):
        out = self.analyzer().analyze([self.conn(rport=443)])
        self.assertTrue(all(f.risk <= 0 for f in out))

    def test_user_directory_with_direct_ip_uncommon_port_is_flagged(self):
        c = self.conn(exe=r"C:\Users\x\AppData\Local\app.exe", rport=4444)
        f = self.analyzer().analyze([c])[0]
        codes = {e.code for e in f.evidences}
        self.assertIn("net_c2_pattern", codes)
        self.assertGreaterEqual(f.risk, 2)  # MÉDIO

    def test_known_pool_is_strong(self):
        pools = MiningPools(["pool.example"])
        pools.resolved = True
        pools.ip_to_host["198.51.100.7"] = "pool.example"
        f = NetworkAnalyzer(pools).analyze([self.conn(rport=3333)])[0]
        self.assertIn("net_pool", {e.code for e in f.evidences})
        self.assertGreaterEqual(f.risk, 3)  # ALTO


if __name__ == "__main__":
    unittest.main()
