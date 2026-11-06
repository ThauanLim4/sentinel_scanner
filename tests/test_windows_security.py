"""Testes específicos do Windows e de falhas.

Regras:
- Nenhum teste altera o Registro real, serviços, tarefas agendadas ou o Defender.
- Registro/serviços/tarefas/Defender usam fakes e mocks.
- Arquivos, ACLs, junctions e atributos usam apenas diretórios temporários.
- Conteúdo é sempre sintético (nunca malware real).
"""
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

os.environ.setdefault("SENTINEL_HOME", tempfile.mkdtemp(prefix="sentinel_wintest_home_"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import miner_detector as md_module
from core import quarantine_crypto as qc
from core import win_security
from core.defender import DefenderClient, DefenderScan, DefenderUnavailable
from core.file_analyzer import FileAnalyzer
from core.miner_detector import MinerDetector
from core.models import Finding
from core.network_analyzer import MiningPools
from core.platform_utils import PowerShellError
from core.process_analyzer import ProcessAnalyzer, ProcessInfo, is_critical_process
from core.quarantine import Quarantine
from core.registry_analyzer import (FakeRegistry, HKCU, HKLM, WINLOGON, RegistryAnalyzer,
                                    RegistryError, RegistryFixer, backup_key)
from core.safety import has_reparse_in_chain, is_reparse_point
from core.startup_analyzer import StartupAnalyzer, StartupEntry, StartupError, StartupManager
from database.database import Database

IS_WINDOWS = sys.platform == "win32"


def make_test_root(prefix: str) -> Path:
    """Raiz fora de %TEMP% para não acionar heurísticas de 'arquivo em temp'."""
    if IS_WINDOWS:
        base = os.environ.get("LOCALAPPDATA") or tempfile.gettempdir()
        return Path(tempfile.mkdtemp(prefix=prefix, dir=base))
    return Path(tempfile.mkdtemp(prefix=prefix))


class Base(unittest.TestCase):
    def setUp(self):
        self.root = make_test_root("sw_")
        self.db = Database(self.root / "t.db")

    def tearDown(self):
        try:
            self.db.close()
        finally:
            shutil.rmtree(self.root, ignore_errors=True)


# --------------------------------------------------------------------------- ACL / atributos
@unittest.skipUnless(IS_WINDOWS, "ACLs NTFS só existem no Windows")
class WindowsAclTests(Base):
    def test_private_acl_is_applied_verified_and_restorable(self):
        f = self.root / "segredo.bin"
        f.write_bytes(b"conteudo sintetico")
        self.assertTrue(win_security.secure_private_file(f))
        self.assertTrue(win_security.verify_private_file(f))

        acl = win_security.capture_acl(f)
        self.assertIsNotNone(acl)
        self.assertTrue(acl.startswith("D:P"), acl)
        self.assertTrue(win_security.restore_acl(f, acl))
        self.assertTrue(win_security.verify_private_file(f))

    def test_readonly_attribute_can_be_applied_and_removed(self):
        f = self.root / "somente_leitura.txt"
        f.write_text("x", encoding="utf-8")
        self.assertTrue(win_security.apply_attributes(f, 0x1))
        self.assertTrue(f.stat().st_file_attributes & 0x1)
        self.assertTrue(win_security.apply_attributes(f, 0))
        self.assertFalse(f.stat().st_file_attributes & 0x1)

    def test_invalid_sddl_is_rejected(self):
        f = self.root / "x.txt"
        f.write_text("x", encoding="utf-8")
        self.assertFalse(win_security.restore_acl(f, "isto-nao-e-um-sddl"))

    def test_junction_is_detected_and_not_followed(self):
        target = self.root / "alvo"
        target.mkdir()
        (target / "arquivo.txt").write_text("nao deve ser lido pelo scanner", encoding="utf-8")
        link = self.root / "link"
        proc = subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(target)],
                              capture_output=True, text=True)
        if proc.returncode != 0 or not link.exists():
            self.skipTest("ambiente não permite criar junction")
        try:
            self.assertTrue(is_reparse_point(link))
            self.assertTrue(has_reparse_in_chain(link / "arquivo.txt", self.root))
        finally:
            # Remover a junction NÃO remove o conteúdo do alvo.
            try:
                os.rmdir(link)
            except OSError:
                pass

    def test_symlink_is_detected_when_supported(self):
        target = self.root / "alvo.txt"
        target.write_text("x", encoding="utf-8")
        link = self.root / "link.txt"
        try:
            link.symlink_to(target)
        except (OSError, NotImplementedError):
            self.skipTest("ambiente não permite criar symlink")
        self.assertTrue(is_reparse_point(link))


# --------------------------------------------------------------------------- DPAPI
@unittest.skipUnless(IS_WINDOWS, "DPAPI só existe no Windows")
class DpapiTests(Base):
    def test_dpapi_roundtrip_and_aad_binding(self):
        key = os.urandom(32)
        wrapped = qc.wrap_key(key, "item-dpapi-teste")
        self.assertTrue(wrapped.startswith("dpapi:"))
        self.assertNotIn(key.hex(), wrapped)
        self.assertEqual(qc.unwrap_key(wrapped, "item-dpapi-teste"), key)
        with self.assertRaises(qc.CryptoError):
            qc.unwrap_key(wrapped, "outro-item")  # AAD diferente deve falhar

    def test_corrupted_dpapi_blob_is_rejected(self):
        with self.assertRaises(qc.CryptoError):
            qc.unwrap_key("dpapi:" + "AAAA", "item")


# --------------------------------------------------------------------------- Defender
class DefenderTests(unittest.TestCase):
    def client(self):
        return DefenderClient()

    def test_empty_status_is_not_treated_as_clean(self):
        c = self.client()
        with mock.patch("core.defender.IS_WINDOWS", True), \
                mock.patch("core.defender.run_powershell_json", return_value=None):
            st = c.status()
        self.assertFalse(st["available"])
        self.assertIn("não retornou", st["message"])

    def test_realtime_off_is_reported(self):
        data = {"ServiceEnabled": True, "AntivirusEnabled": True, "RealTime": False,
                "SignatureAgeDays": 1}
        with mock.patch("core.defender.IS_WINDOWS", True), \
                mock.patch("core.defender.run_powershell_json",
                           side_effect=lambda script, *a, **k: [] if "AntivirusProduct" in script else data):
            st = self.client().status()
        self.assertTrue(st["available"])
        self.assertIn("tempo real", st["message"])

    def test_old_signatures_are_reported(self):
        data = {"ServiceEnabled": True, "AntivirusEnabled": True, "RealTime": True,
                "SignatureAgeDays": 30}
        with mock.patch("core.defender.IS_WINDOWS", True), \
                mock.patch("core.defender.run_powershell_json",
                           side_effect=lambda script, *a, **k: [] if "AntivirusProduct" in script else data):
            st = self.client().status()
        self.assertIn("desatualizadas", st["message"])

    def test_update_signatures_only_true_on_confirmation(self):
        with mock.patch("core.defender.run_powershell_json", return_value={"ok": True, "error": ""}):
            self.assertTrue(self.client().update_signatures())
        with mock.patch("core.defender.run_powershell_json", return_value={"ok": False, "error": "negado"}):
            self.assertFalse(self.client().update_signatures())
        with mock.patch("core.defender.run_powershell_json", side_effect=PowerShellError("x")):
            self.assertFalse(self.client().update_signatures())
        with mock.patch("core.defender.run_powershell_json", return_value=None):
            self.assertFalse(self.client().update_signatures())

    def test_exclusions_restricted_and_lists(self):
        payload = {"Paths": ["N/A: acesso negado"], "Processes": [], "Extensions": []}
        with mock.patch("core.defender.run_powershell_json", return_value=payload):
            ex = self.client().exclusions()
        self.assertTrue(ex["restricted"])
        self.assertEqual(ex["Paths"], [])

    def test_threats_and_history_empty_are_not_success_claims(self):
        with mock.patch("core.defender.run_powershell_json", return_value=None):
            self.assertEqual(self.client().threats(), [])
            self.assertEqual(self.client().history(), [])

    def test_quarantined_items_reports_mpcmdrun_failure(self):
        with mock.patch("core.defender.mpcmdrun_path", return_value=Path("MpCmdRun.exe")), \
                mock.patch("core.defender.subprocess.run",
                           return_value=SimpleNamespace(returncode=2, stdout="", stderr="falhou")):
            with self.assertRaises(DefenderUnavailable):
                self.client().quarantined_items()

    def test_scan_validation_and_cancel_without_process(self):
        c = self.client()
        with self.assertRaises(ValueError):
            c.start_scan("invalido")
        with self.assertRaises(ValueError):
            c.start_scan("custom", str(self.nonexistent()))
        scan = DefenderScan("quick", None)
        with mock.patch("core.defender.mpcmdrun_path", return_value=None):
            scan.cancel()  # sem processo e sem MpCmdRun não deve lançar

    def nonexistent(self):
        return Path(tempfile.gettempdir()) / "sentinel-path-que-nao-existe-12345"


# --------------------------------------------------------------------------- Registro (fake)
class RegistryFailureTests(Base):
    def bad_registry(self):
        return FakeRegistry({(HKLM, WINLOGON): {"Shell": "explorer.exe, evil.exe"}})

    def test_fixer_backup_failure_prevents_write(self):
        reg = self.bad_registry()
        finding = next(f for f in RegistryAnalyzer(reg).analyze() if f.extra.get("value") == "Shell")

        def backup_boom(hive, key):
            raise RegistryError("backup indisponível")

        fixer = RegistryFixer(reg, self.db, backup=backup_boom)
        with self.assertRaises(RegistryError):
            fixer.apply(finding, confirmed=True)
        self.assertEqual(reg.get(HKLM, WINLOGON, "Shell"), "explorer.exe, evil.exe")

    def test_fixer_write_failure_is_reported(self):
        reg = self.bad_registry()
        finding = next(f for f in RegistryAnalyzer(reg).analyze() if f.extra.get("value") == "Shell")

        class FailingRegistry(FakeRegistry):
            def set_value(self, hive, path, name, data, typ="REG_SZ"):
                raise RegistryError("Registro bloqueado")

        failing = FailingRegistry(reg.data)
        fixer = RegistryFixer(failing, self.db, backup=lambda h, k: Path("b.reg"))
        with self.assertRaises(RegistryError):
            fixer.apply(finding, confirmed=True)

    def test_invalid_hive_backup_is_refused(self):
        with self.assertRaises(RegistryError):
            backup_key("HKXX", r"Software\Teste", directory=self.root / "backups")

    def test_allowlist_rejects_arbitrary_registry_path(self):
        reg = self.bad_registry()
        fixer = RegistryFixer(reg, self.db, backup=lambda h, k: Path("b.reg"))
        forged = Finding(path="x", extra={"fix": {"action": "delete_value", "hive": HKLM,
                                                  "key": r"SYSTEM\CurrentControlSet\Services\Nada", "value": "x"}})
        with self.assertRaises(RegistryError):
            fixer.apply(forged, confirmed=True)


# --------------------------------------------------------------------------- inicialização
class StartupSafetyTests(Base):
    def manager(self):
        reg = FakeRegistry()
        return reg, StartupManager(reg, self.db, backup=lambda h, k: Path("b.reg"))

    def test_windows_run_entry_requires_extra_confirmation(self):
        e = StartupEntry("run", "Updater", r"HKCU\...\Run", r"C:\Windows\System32\cmd.exe /c whoami")
        self.assertTrue(StartupManager.is_critical(e))
        _, mgr = self.manager()
        with self.assertRaises(StartupError):
            mgr.disable(e, confirmed=True)  # falta confirm_critical

    def test_user_run_entry_is_reversible_without_deleting_value(self):
        base = r"SOFTWARE\Microsoft\Windows\CurrentVersion"
        reg = FakeRegistry({(HKCU, base + r"\Run"): {"App": r'"C:\Tools\app.exe"'}})
        sa_entry = StartupAnalyzer(
            FileAnalyzer(self.db, set()), access=reg, db=self.db).collect_registry()[0]
        mgr = StartupManager(reg, self.db, backup=lambda h, k: Path("b.reg"))
        mgr.disable(sa_entry, confirmed=True)
        self.assertIn("App", reg.values(HKCU, base + r"\Run"))
        mgr.enable(sa_entry, confirmed=True)
        self.assertTrue(reg.values(HKCU, base + r"\Run"))

    def test_service_disable_uses_sc_config_and_never_deletes(self):
        _, mgr = self.manager()
        e = StartupEntry("service", "TestSvc", "Serviços", r"C:\Tools\svc.exe",
                         extra={"start_type": "manual"})
        fake = SimpleNamespace(returncode=0, stdout="", stderr="")
        with mock.patch("core.startup_analyzer.subprocess.run", return_value=fake) as run:
            info = mgr.disable(e, confirmed=True)
        args = run.call_args.args[0]
        self.assertEqual(args[:4], ["sc.exe", "config", "TestSvc", "start="])
        self.assertEqual(args[4], "disabled")
        self.assertEqual(info["previous_start_type"], "demand")
        self.assertFalse(e.enabled)

    def test_invalid_service_name_is_refused_before_subprocess(self):
        _, mgr = self.manager()
        e = StartupEntry("service", "nome inválido; rm -rf", "Serviços", r"C:\Tools\svc.exe")
        with mock.patch("core.startup_analyzer.subprocess.run") as run:
            with self.assertRaises(StartupError):
                mgr.disable(e, confirmed=True)
        run.assert_not_called()

    def test_task_disable_passes_name_and_path_via_environment(self):
        _, mgr = self.manager()
        e = StartupEntry("task", "MinhaTarefa", r"Agendador\MinhaTarefa",
                         r"C:\Tools\task.exe", extra={"task_name": "MinhaTarefa",
                                                      "task_path": r"\MinhaTarefa"})
        fake = SimpleNamespace(returncode=0, stdout="", stderr="")
        with mock.patch("core.startup_analyzer.run_powershell", return_value=fake) as run:
            mgr.disable(e, confirmed=True)
        self.assertIn("Disable-ScheduledTask", run.call_args.args[0])
        env = run.call_args.kwargs["env"]
        self.assertEqual(env["SENTINEL_TASKNAME"], "MinhaTarefa")
        self.assertEqual(env["SENTINEL_TASKPATH"], r"\MinhaTarefa")

    def test_microsoft_task_requires_extra_confirmation(self):
        e = StartupEntry("task", "T", r"Agendador\T", r"C:\Tools\task.exe",
                         extra={"task_name": "T", "task_path": r"\Microsoft\Windows\T"})
        self.assertTrue(StartupManager.is_critical(e))
        _, mgr = self.manager()
        with mock.patch("core.startup_analyzer.run_powershell") as run:
            with self.assertRaises(StartupError):
                mgr.disable(e, confirmed=True)
        run.assert_not_called()

    def test_drivers_are_never_changed(self):
        _, mgr = self.manager()
        e = StartupEntry("driver", "drv", "Drivers", r"C:\Windows\System32\drivers\drv.sys")
        with self.assertRaises(StartupError):
            mgr.disable(e, confirmed=True, confirm_critical=True)


# --------------------------------------------------------------------------- processos
class ProcessSafetyTests(Base):
    def test_terminate_requires_confirmation_and_never_self(self):
        pa = ProcessAnalyzer(FileAnalyzer(self.db, set()), None)
        with self.assertRaises(PermissionError):
            pa.terminate(123456, 0.0, confirmed=False)
        with self.assertRaises(PermissionError):
            pa.terminate(os.getpid(), 0.0, confirmed=True)

    def test_kill_tree_skips_critical_children(self):
        class FakeError(Exception):
            pass

        class FakeNoSuchProcess(FakeError):
            pass

        class FakeAccessDenied(FakeError):
            pass

        class FakeProc:
            def __init__(self, pid, name, exe, ct):
                self.pid, self._name, self._exe, self._ct = pid, name, exe, ct
                self.kids = []
                self.terminated = self.killed = False

            def name(self):
                return self._name

            def exe(self):
                return self._exe

            def create_time(self):
                return self._ct

            def children(self, recursive=False):
                return self.kids

            def terminate(self):
                self.terminated = True

            def kill(self):
                self.killed = True

        parent = FakeProc(1234, "parent.exe", r"C:\Tools\parent.exe", 1.0)
        critical = FakeProc(1235, "lsass.exe", r"C:\Windows\System32\lsass.exe", 1.0)
        helper = FakeProc(1236, "helper.exe", r"C:\Tools\helper.exe", 1.0)
        parent.kids = [critical, helper]

        fake_psutil = SimpleNamespace(
            Error=FakeError, NoSuchProcess=FakeNoSuchProcess, AccessDenied=FakeAccessDenied,
            Process=lambda pid: {1234: parent, 1235: critical, 1236: helper}.get(pid),
            win_service_iter=lambda: [],
            wait_procs=lambda victims, timeout: (victims, []),
        )
        pa = ProcessAnalyzer(FileAnalyzer(self.db, set()), None)
        with mock.patch("core.process_analyzer.psutil", fake_psutil):
            info = pa.terminate(1234, 1.0, confirmed=True, kill_tree=True)
        self.assertTrue(parent.terminated)
        self.assertTrue(helper.terminated)
        self.assertFalse(critical.terminated)
        self.assertFalse(critical.killed)
        self.assertEqual(info["children_skipped"], 1)

    def test_critical_name_outside_system32_is_not_treated_as_critical(self):
        self.assertFalse(is_critical_process("lsass.exe", r"C:\Users\x\AppData\Local\Temp\lsass.exe", 77))
        self.assertTrue(is_critical_process("lsass.exe", r"C:\Windows\System32\lsass.exe", 77))


# --------------------------------------------------------------------------- mineradores
class MinerNormalizationTests(unittest.TestCase):
    def fake_psutil(self, procs, ncpu=4):
        class FakeError(Exception):
            pass

        return SimpleNamespace(Error=FakeError, process_iter=lambda: procs, cpu_count=lambda: ncpu)

    def test_cpu_is_normalized_by_logical_processors(self):
        clock = {"now": 0.0}

        class FakeProc:
            def __init__(self, pid, rate):
                self.pid, self.rate = pid, rate

            def cpu_times(self):
                return SimpleNamespace(user=self.rate * clock["now"], system=0.0)

            def create_time(self):
                return 1.0

        full = FakeProc(1, 4.0)      # 4s de CPU por segundo -> 100% do total em 4 CPUs
        single = FakeProc(2, 1.0)    # 1s de CPU por segundo -> 25% do total em 4 CPUs
        md = MinerDetector(MiningPools([]), cpu_threshold=40.0, use_gpu=False)
        with mock.patch("core.miner_detector.psutil", self.fake_psutil([full, single])), \
                mock.patch("core.miner_detector.time.monotonic", side_effect=lambda: clock["now"]), \
                mock.patch("core.miner_detector.time.sleep", side_effect=lambda s: clock.__setitem__("now", clock["now"] + s)):
            stats = md.sample(duration=2.0, interval=1.0)
        self.assertAlmostEqual(stats[(1, 1.0)]["cpu_avg"], 100.0, places=3)
        self.assertAlmostEqual(stats[(2, 1.0)]["cpu_avg"], 25.0, places=3)
        self.assertGreaterEqual(stats[(1, 1.0)]["cpu_frac"], 0.99)
        self.assertEqual(stats[(2, 1.0)]["cpu_frac"], 0.0)  # 25% < limiar de 40%

    def test_cpu_threshold_is_applied_only_with_another_family(self):
        md = MinerDetector(MiningPools([]), cpu_threshold=40.0, use_gpu=False)
        info = ProcessInfo(pid=7, name="x.exe", exe="", create_time=1.0,
                           cmdline=["x.exe", "--donate-level=1"])
        md.stats[(7, 1.0)] = {"samples": 5, "cpu_avg": 25.0, "cpu_frac": 1.0,
                              "gpu_avg": 0.0, "gpu_frac": 0.0}
        low = md.detect([info], [])
        self.assertTrue(low)
        self.assertNotIn("miner_cpu", {e.code for e in low[0].evidences})
        md.stats[(7, 1.0)]["cpu_avg"] = 100.0
        high = md.detect([info], [])
        self.assertIn("miner_cpu", {e.code for e in high[0].evidences})

    def test_gpu_instance_names_are_aggregated_by_pid(self):
        rows = [
            {"InstanceName": "pid_123_luid_0_phys_0_eng_0", "CookedValue": 30.0},
            {"InstanceName": "pid_123_luid_0_phys_0_eng_1", "CookedValue": 25.0},
            {"InstanceName": "pid_9_luid_0_phys_0_eng_0", "CookedValue": 5.0},
        ]
        with mock.patch.object(md_module, "IS_WINDOWS", True), \
                mock.patch.object(md_module, "run_powershell_json", return_value=rows):
            md = MinerDetector(MiningPools([]), use_gpu=True)
            self.assertEqual(md._gpu_usage(), {123: 55.0, 9: 5.0})

    def test_gpu_failure_disables_sampling_instead_of_faking_data(self):
        from core.platform_utils import PowerShellError
        with mock.patch.object(md_module, "IS_WINDOWS", True), \
                mock.patch.object(md_module, "run_powershell_json", side_effect=PowerShellError("sem contador")):
            md = MinerDetector(MiningPools([]), use_gpu=True)
            self.assertEqual(md._gpu_usage(), {})
            self.assertFalse(md.use_gpu)


# --------------------------------------------------------------------------- restauração Windows
@unittest.skipUnless(IS_WINDOWS, "atributos somente-leitura do Windows")
class RestoreWindowsTests(Base):
    def test_restore_overwrites_readonly_destination_only_when_confirmed(self):
        root = make_test_root("swr_")
        self.addCleanup(shutil.rmtree, root, True)
        db = Database(root / "r.db")
        self.addCleanup(db.close)
        f = root / "arquivo.bin"
        payload = os.urandom(4096)
        f.write_bytes(payload)
        q = Quarantine(db, root / "q")
        qid = q.quarantine_file(f, allowed_roots=[root])
        f.write_bytes(b"conteudo anterior")
        os.chmod(f, stat.S_IREAD)  # destino somente-leitura
        try:
            q.restore(qid, overwrite=True)
        finally:
            try:
                os.chmod(f, stat.S_IWRITE | stat.S_IREAD)
            except OSError:
                pass
        self.assertEqual(f.read_bytes(), payload)
        self.assertEqual(db.get_quarantine(qid)["status"], "restored")


if __name__ == "__main__":
    unittest.main()
