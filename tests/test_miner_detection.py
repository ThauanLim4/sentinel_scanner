"""Testes da detecção de mineradores: CPU/GPU nunca bastam sozinhos e cada
família de indicadores (linha de comando, rede, arquivo, disfarce, persistência)
é combinada de forma conservadora."""
import os
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("SENTINEL_HOME", tempfile.mkdtemp(prefix="sentinel_mtest_home_"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.miner_detector import MinerDetector, psutil
from core.models import Finding, RiskLevel
from core.network_analyzer import Connection, MiningPools
from core.process_analyzer import ProcessInfo
from core.safety import norm

EXE = r"C:\Program Files\App\app.exe"


def pools() -> MiningPools:
    p = MiningPools([])
    p.resolved = True
    return p


def info(**kw) -> ProcessInfo:
    opts = dict(pid=10, name="app.exe", exe=EXE, create_time=100.0)
    opts.update(kw)
    return ProcessInfo(**opts)


def stats(cpu=90.0, gpu=0.0, samples=10) -> dict:
    return {"samples": samples, "cpu_avg": cpu, "cpu_frac": 1.0 if cpu >= 1 else 0.0,
            "gpu_avg": gpu, "gpu_frac": 1.0 if gpu >= 1 else 0.0}


def conn(**kw) -> Connection:
    opts = dict(pid=10, process="app.exe", exe=EXE, proto="TCP", laddr="10.0.0.2", lport=50000,
                raddr="198.51.100.7", rport=3333, status="ESTABLISHED", external=True, host="")
    opts.update(kw)
    return Connection(**opts)


class MinerDetectionTests(unittest.TestCase):
    def setUp(self):
        self.md = MinerDetector(pools(), use_gpu=False)

    def test_high_cpu_and_gpu_alone_never_alert(self):
        p = info()
        self.md.stats[(p.pid, p.create_time)] = stats(cpu=99, gpu=99)
        self.assertEqual(self.md.detect([p], []), [])

    def test_resource_plus_persistence_is_still_not_an_alert(self):
        p = info()
        self.md.stats[(p.pid, p.create_time)] = stats(cpu=99, gpu=99)
        self.assertEqual(self.md.detect([p], [], {p.exe}), [])

    def test_persistence_alone_is_not_an_alert(self):
        p = info()
        self.assertEqual(self.md.detect([p], [], {p.exe}), [])

    def test_stratum_command_line_alone_is_high(self):
        p = info(exe="", cmdline=["app.exe", "stratum+tcp://pool.example:3333"])
        res = self.md.detect([p], [])
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0].risk, RiskLevel.ALTO)
        self.assertIn("cmdline", res[0].extra["families"])

    def test_miner_flags_alone_are_limited_to_medium(self):
        p = info(exe="", cmdline=["app.exe", "--donate-level=1"])
        res = self.md.detect([p], [])
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0].risk, RiskLevel.MEDIO)

    def test_cmdline_plus_persistence_plus_resource_reaches_high(self):
        p = info(cmdline=["app.exe", "stratum+tcp://pool.example:3333"])
        self.md.stats[(p.pid, p.create_time)] = stats(cpu=95)
        res = self.md.detect([p], [], {p.exe})
        self.assertEqual(len(res), 1)
        self.assertGreaterEqual(res[0].risk, RiskLevel.ALTO)
        self.assertTrue({"cmdline", "persistence", "resource"} <= set(res[0].extra["families"]))

    def test_known_pool_connection_is_high(self):
        p = info()
        c = conn(host="pool.example", raddr="198.51.100.7")
        res = self.md.detect([p], [c])
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0].risk, RiskLevel.ALTO)
        self.assertIn("network", res[0].extra["families"])

    def test_mining_port_without_known_pool_is_weak(self):
        p = info()
        res = self.md.detect([p], [conn(rport=3333)])
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0].risk, RiskLevel.BAIXO)
        self.assertNotIn("miner_pool_conn", {e.code for e in res[0].evidences})

    def test_internal_connection_is_ignored(self):
        p = info()
        self.assertEqual(self.md.detect([p], [conn(external=False, host="pool.example")]), [])

    def test_file_strings_indicator_is_a_family(self):
        p = info()
        ff = Finding(path=p.exe)
        ff.add("miner_strings", "stratum no binário", 40)
        res = self.md.detect([p], [], file_findings={norm(p.exe): ff})
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0].risk, RiskLevel.MEDIO)
        self.assertIn("file", res[0].extra["families"])

    def test_disguise_plus_persistence_is_detected_but_low(self):
        p = info()
        pf = Finding(path=p.exe)
        pf.add("proc_temp", "em temp", 20)
        p.finding = pf
        res = self.md.detect([p], [], {p.exe})
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0].risk, RiskLevel.BAIXO)
        self.assertTrue({"disguise", "persistence"} <= set(res[0].extra["families"]))

    def test_empty_process_list(self):
        self.assertEqual(self.md.detect([], []), [])

    def test_gpu_disabled_returns_empty(self):
        self.assertEqual(self.md._gpu_usage(), {})

    def test_sampler_rejects_invalid_arguments(self):
        for kwargs in ({"duration": 0}, {"duration": -1}, {"duration": 1, "interval": 0},
                       {"duration": 1, "interval": -2}):
            with self.assertRaises(ValueError):
                self.md.sample(**kwargs)

    @unittest.skipUnless(psutil is not None, "psutil não instalado")
    def test_cancelled_sample_clears_stale_stats(self):
        self.md.stats = {(1, 2.0): stats()}
        self.md.sample(duration=1.0, interval=0.1, cancel=lambda: True)
        self.assertEqual(self.md.stats, {})


if __name__ == "__main__":
    unittest.main()
