"""Testes da interface gráfica (Fase H da Etapa 3).

Nenhum recurso real é alterado: banco, quarentena, Defender, limpeza, processos,
inicialização e Registro são substituídos por dublês ou usam diretórios temporários.
O aplicativo é criado uma única vez com a plataforma ``offscreen``.
"""
import gc
import logging
import os
import tempfile
import threading
import time
import unittest
from dataclasses import dataclass
from pathlib import Path
from unittest import mock

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
_TEST_HOME = tempfile.mkdtemp(prefix="sentinel_gui_home_")
os.environ["SENTINEL_HOME"] = _TEST_HOME
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from PySide6.QtCore import QEventLoop, QTimer
from PySide6.QtWidgets import QApplication

from core.models import Finding, RiskLevel
from core.scanner import Scanner
from database.database import Database
from gui import app as app_module
from gui.context import AppContext
from gui.main_window import MainWindow
from gui.settings import Settings
from gui.styles.theme import stylesheet
from gui.views import build_views
from gui.views.placeholder_view import PlaceholderView
from gui.workers.base import TaskManager, Worker, check_cancelled
from gui.workers.cleanup_worker import ConfirmationRequired as CleanupConfirmationRequired
from gui.workers.cleanup_worker import make_clean_task
from gui.workers.defender_worker import (
    make_defender_query_task,
    make_defender_scan_task,
    make_defender_update_task,
)
from gui.workers.history_worker import make_history_task
from gui.workers.quarantine_worker import (
    ConfirmationRequired as QuarantineConfirmationRequired,
    make_delete_task,
    make_restore_task,
)
from gui.workers.scan_worker import make_scan_task
from gui.components.sidebar import NAV_ITEMS

APP = QApplication.instance() or QApplication([])
DARK_STYLE = stylesheet("dark")


def restore_style() -> None:
    """Evita reparsear QSS quando a janela já restaurou o tema padrão."""
    if APP.styleSheet() != DARK_STYLE:
        APP.setStyleSheet(DARK_STYLE)


def drain() -> None:
    """Processa os eventos Qt pendentes sem iniciar um loop de aplicativo real."""
    APP.processEvents()


def run_worker(task, *, cancel_before_start: bool = False, timeout: int = 3000) -> dict:
    """Executa uma tarefa em QThread e devolve os sinais recebidos na thread principal."""
    worker = Worker(task)
    state = {
        "worker": worker, "ok": False, "result": None, "error": (),
        "cancelled": False, "statuses": [], "progress": [], "finished": False,
    }
    loop = QEventLoop()

    def on_success(result):
        state["ok"] = True
        state["result"] = result

    def on_error(message, details):
        state["error"] = (message, details)

    def on_cancelled():
        state["cancelled"] = True

    def on_finished():
        state["finished"] = True
        loop.quit()

    worker.succeeded.connect(on_success)
    worker.failed.connect(lambda message, details: on_error(message, details))
    worker.cancelled.connect(on_cancelled)
    worker.status_changed.connect(state["statuses"].append)
    worker.progressed.connect(state["progress"].append)
    worker.finished.connect(on_finished)

    timer = QTimer()
    timer.setSingleShot(True)
    timer.timeout.connect(loop.quit)
    timer.start(timeout)
    if cancel_before_start:
        worker.cancel()
    worker.start()
    loop.exec()
    timer.stop()
    drain()
    return state


@dataclass
class FakeCategory:
    key: str
    name: str
    kind: str


class FakeQuarantine:
    def __init__(self):
        self.restore_calls = []
        self.delete_calls = []

    def restore(self, qid, destination=None, overwrite=False):
        self.restore_calls.append((qid, destination, overwrite))
        return {"id": qid, "restored": True}

    def delete_permanently(self, qid, confirmed=False):
        self.delete_calls.append((qid, confirmed))


class FakeScan:
    def __init__(self):
        self.started = False
        self.cancelled = False

    def start(self):
        self.started = True

    def running(self):
        return False

    def wait(self):
        return 0, "verificação concluída"

    def cancel(self):
        self.cancelled = True


class FakeDefender:
    """Dublê somente leitura; qualquer método de desativação falha o teste."""

    def __init__(self):
        self.calls = []
        self.scan = FakeScan()

    def status(self):
        self.calls.append("status")
        return {
            "available": True, "AntivirusEnabled": True, "RealTime": True,
            "TamperProtected": None, "SignatureVersion": "1.0",
            "SignatureUpdated": "", "SignatureAgeDays": 0,
            "QuickScanEnd": "", "FullScanEnd": "", "products": [], "message": "",
        }

    def threats(self):
        self.calls.append("threats")
        return {"items": []}

    def history(self):
        self.calls.append("history")
        return {"items": []}

    def exclusions(self):
        self.calls.append("exclusions")
        return {"restricted": True}

    def update_signatures(self):
        self.calls.append("update")
        return True

    def start_scan(self, kind):
        self.calls.append(f"scan:{kind}")
        return self.scan

    def set_real_time_protection(self, *_args, **_kwargs):
        raise AssertionError("A GUI não pode desativar proteção em tempo real")

    def add_exclusion(self, *_args, **_kwargs):
        raise AssertionError("A GUI não pode criar exclusões")

    def remove_exclusion(self, *_args, **_kwargs):
        raise AssertionError("A GUI não pode remover exclusões")


class FakeProcesses:
    def snapshot(self, **_kwargs):
        return []


class GuiTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="sentinel_gui_test_"))
        self.settings_path = self.tmp / "settings.json"
        self.db_path = self.tmp / "test.db"
        self.settings = Settings(self.settings_path)
        self.context = AppContext(
            settings=self.settings,
            db_path=self.db_path,
            quarantine_dir=self.tmp / "quarantine",
        )
        # Nenhuma tela deve consultar Defender ou processos reais durante os testes.
        self.context.set_override("defender", FakeDefender())
        self.context.set_override("processes", FakeProcesses())
        self.window = None
        self.addCleanup(self._cleanup)
        self.addCleanup(restore_style)
        self.addCleanup(lambda: logging.getLogger("sentinel").setLevel(logging.INFO))
        font = APP.font()
        self._original_font = font
        self.addCleanup(lambda: APP.setFont(self._original_font))

    def _cleanup(self):
        if self.window is not None:
            self.window.prepare_close(force=True)
            self.window.close()
            self.window.deleteLater()
            self.window = None
        else:
            self.context.close()
        drain()
        # Janelas acumuladas tornam setStyleSheet progressivamente mais lento.
        gc.collect()

    def make_window(self) -> MainWindow:
        """Janela sem carregamento automático: evita consultas ao abrir cada tela."""
        self.window = MainWindow(self.context, auto_load=False)
        drain()
        return self.window

    def _entrypoint_context(self, settings) -> AppContext:
        """Contexto do entrypoint com dublês: nunca consulta Defender/processos reais."""
        context = AppContext(settings=settings, db_path=self.tmp / "entry.db",
                             quarantine_dir=self.tmp / "entry_quarantine")
        context.set_override("defender", FakeDefender())
        context.set_override("processes", FakeProcesses())
        return context


class SettingsTests(GuiTestCase):
    def test_persistent_settings_are_normalized_and_written_atomically(self):
        settings = Settings(self.settings_path)
        settings.update({
            "theme": "verde", "log_level": "TRACE", "scan_workers": 99,
            "cpu_limit": 1, "scan_directories": [None, "", "C:\\scan"],
            "exclusions": "não-lista", "notifications": "false",
        })
        settings.save()

        loaded = Settings(self.settings_path).as_dict()
        self.assertEqual(loaded["theme"], "dark")
        self.assertEqual(loaded["log_level"], "INFO")
        self.assertEqual(loaded["scan_workers"], 8)
        self.assertEqual(loaded["cpu_limit"], 10)
        self.assertEqual(loaded["scan_directories"], ["C:\\scan"])
        self.assertEqual(loaded["exclusions"], [])
        self.assertIs(loaded["notifications"], False)
        self.assertFalse((self.tmp / "settings.json.tmp").exists())

    def test_settings_view_applies_theme_log_and_shares_paths_with_scanner(self):
        window = self.make_window()
        view = window.views["settings"]
        style_before = APP.styleSheet()
        folder = self.tmp / "scans"
        folder.mkdir()
        excluded = self.tmp / "excluded.bin"
        excluded.write_bytes(b"x")

        view.theme_combo.setCurrentIndex(1)  # claro
        view.notifications_check.setChecked(False)
        view.log_combo.setCurrentIndex(3)    # ERROR
        view.workers_spin.setValue(4)
        view.cpu_spin.setValue(75)
        view.folder_input.setText(str(folder))
        view.add_folder()
        view.exclusion_input.setText(str(excluded))
        view.add_exclusion()
        self.assertEqual(view.status_badge.text(), "Alterações pendentes")
        view.save()

        self.assertEqual(window._theme, "light")
        self.assertNotEqual(APP.styleSheet(), style_before)
        self.assertEqual(logging.getLogger("sentinel").level, logging.ERROR)
        persisted = Settings(self.settings_path)
        self.assertEqual(persisted.get("theme"), "light")
        self.assertEqual(persisted.get("log_level"), "ERROR")
        self.assertEqual(persisted.get("scan_workers"), 4)
        self.assertEqual(persisted.get("cpu_limit"), 75)
        self.assertEqual(persisted.get("scan_directories"), [str(folder)])
        self.assertEqual(persisted.get("exclusions"), [str(excluded)])

        # O Scanner consome as mesmas listas gravadas pela tela de Configurações.
        scanner_factory = self.context.make_scanner()
        self.assertEqual(scanner_factory.workers, 4)
        self.assertEqual(scanner_factory.cpu_limit, 75)
        window.navigate("scanner")
        scanner_view = window.views["scanner"]
        scanner_view.on_activate()
        self.assertEqual(scanner_view.path_list.count(), 1)
        self.assertIn("1", scanner_view.exclusions_label.text())

    def test_notification_preference_keeps_critical_messages(self):
        window = self.make_window()
        window.context.settings.set("notifications", False)
        before = len(window.notifications)

        window.notify("info", "Informativa")
        window.notify("success", "Sucesso")
        self.assertEqual(len(window.notifications), before)

        window.notify("danger", "Erro")
        window.notify("warning", "Aviso")
        self.assertEqual(len(window.notifications), before + 2)

    def test_real_changes_invalidate_dashboard_until_it_is_visible(self):
        window = self.make_window()
        dashboard = window.views["dashboard"]
        drain()
        self.assertFalse(dashboard._refresh_pending)

        window.views["scanner"].emit_data_changed()
        self.assertTrue(dashboard._refresh_pending)

        window.navigate("dashboard")
        dashboard.on_activate()
        self.assertFalse(dashboard._refresh_pending)
        self.assertTrue(dashboard._loaded)


class GuiViewsTests(GuiTestCase):
    def test_all_ten_real_views_navigate_at_required_resolutions_and_scales(self):
        window = self.make_window()
        self.assertEqual(len(window.views), 10)
        self.assertEqual(list(window.views), [key for key, _title, _icon in NAV_ITEMS])
        for view in window.views.values():
            self.assertNotIsInstance(view, PlaceholderView)

        base_font = APP.font()
        for width, height in ((1366, 768), (1280, 720), (1920, 1080)):
            window.resize(width, height)
            for scale in (1.0, 1.25, 1.5):
                font = APP.font()
                font.setPointSizeF(max(6.0, base_font.pointSizeF() * scale))
                APP.setFont(font)
                drain()
                for key, _title, _icon in NAV_ITEMS:
                    window.navigate(key)
                    drain()
                    view = window.views[key]
                    self.assertEqual(window.current_key, key)
                    self.assertEqual(window.header.title_label.text(), view.TITLE)
                    self.assertIs(window.stack.currentWidget(), view)
                    self.assertGreater(view.width(), 0)
                    self.assertGreater(view.height(), 0)

    def test_entrypoint_starts_the_window_without_a_real_event_loop(self):
        with mock.patch.object(QApplication, "exec", return_value=0) as exec_mock, \
                mock.patch.object(app_module, "Settings",
                                  side_effect=lambda: Settings(self.tmp / "entry_settings.json")), \
                mock.patch.object(
                    app_module, "AppContext",
                    side_effect=self._entrypoint_context):
            code = app_module.main([])

        self.assertEqual(code, 0)
        exec_mock.assert_called_once_with()
        self.assertTrue((self.tmp / "entry.db").exists())
        drain()
        gc.collect()


class WorkerTests(GuiTestCase):
    def test_worker_reports_status_progress_success_and_failure(self):
        def successful(worker):
            worker.set_status("Processando…")
            worker.emit_progress(1)
            worker.emit_progress(2)
            return {"ok": True}

        state = run_worker(successful)
        self.assertTrue(state["finished"])
        self.assertTrue(state["ok"])
        self.assertEqual(state["result"], {"ok": True})
        self.assertEqual(state["statuses"], ["Processando…"])
        self.assertEqual(state["progress"], [1, 2])

        def failing(_worker):
            raise RuntimeError("falha interna de teste")

        state = run_worker(failing)
        self.assertTrue(state["finished"])
        self.assertFalse(state["ok"])
        self.assertTrue(state["error"][0])
        self.assertIn("RuntimeError", state["error"][1])

    def test_cooperative_cancellation_does_not_report_failure(self):
        def task(worker):
            check_cancelled(worker)
            return "não deveria concluir"

        state = run_worker(task, cancel_before_start=True)
        self.assertTrue(state["finished"])
        self.assertTrue(state["cancelled"])
        self.assertFalse(state["ok"])
        self.assertEqual(state["error"], ())

    def test_task_manager_shutdown_cancels_and_joins_live_workers(self):
        started = threading.Event()
        manager = TaskManager()

        def task(worker):
            started.set()
            while not worker.is_cancelled():
                time.sleep(0.01)
            return "interrompida"

        worker = manager.start(task)
        self.assertTrue(started.wait(2))
        manager.shutdown(timeout_ms=1000)
        drain()
        self.assertFalse(worker.isRunning())
        self.assertEqual(manager.active_count(), 0)

    def test_scan_worker_forwards_real_exclusion_paths_to_core(self):
        root = self.tmp / "scan_root"
        excluded = root / "excluded"
        excluded.mkdir(parents=True)
        (root / "permitido.exe").write_bytes(b"x" * 16)
        (excluded / "ignorado.exe").write_bytes(b"y" * 16)
        scanner = Scanner(self.context.db, workers=1, cpu_limit=10)

        state = run_worker(make_scan_task(scanner, "custom", [root], [excluded]))
        self.assertTrue(state["ok"], state["error"])
        result = state["result"]
        self.assertEqual(result.files_seen, 1)
        self.assertFalse(result.cancelled)
        self.assertEqual(state["worker"].on_cancel, scanner.cancel)
        statuses = [row.get("path") for row in self.context.db.list_findings(limit=20)]
        self.assertNotIn(str(excluded / "ignorado.exe"), statuses)

    def test_defensive_operations_require_confirmation_and_forward_only_checked_paths(self):
        quarantine = FakeQuarantine()
        for factory in (lambda: make_restore_task(quarantine, "q1"),
                        lambda: make_delete_task(quarantine, "q1")):
            with self.assertRaises(QuarantineConfirmationRequired):
                factory()
        self.assertEqual(quarantine.restore_calls, [])
        self.assertEqual(quarantine.delete_calls, [])

        destination = self.tmp / "restored.exe"
        state = run_worker(make_restore_task(
            quarantine, "q1", destination=destination, overwrite=True, confirmed=True))
        self.assertTrue(state["ok"], state["error"])
        self.assertEqual(quarantine.restore_calls,
                         [("q1", str(destination), True)])
        state = run_worker(make_delete_task(quarantine, "q1", confirmed=True))
        self.assertTrue(state["ok"], state["error"])
        self.assertEqual(quarantine.delete_calls, [("q1", True)])

        categories = [FakeCategory("temp", "Temporários", "temp"),
                      FakeCategory("recycle", "Lixeira", "recycle")]
        with self.assertRaises(CleanupConfirmationRequired):
            make_clean_task(categories, self.context.db, confirmed=False)

        selected = [self.tmp / "arquivo.tmp"]
        cleaned = mock.Mock(freed=10, deleted=1, skipped=0, errors=[])
        with mock.patch("gui.workers.cleanup_worker.cleanup.clean", return_value=cleaned) as clean:
            state = run_worker(make_clean_task(
                categories, self.context.db, confirmed=True,
                only_paths={"temp": selected}, include_recycle=False))
            self.assertTrue(state["ok"], state["error"])
            clean.assert_called_once()
            self.assertEqual(clean.call_args.args[0].key, "temp")
            self.assertTrue(clean.call_args.kwargs["confirmed"])
            self.assertEqual(clean.call_args.kwargs["only_paths"], selected)
        self.assertEqual(state["result"]["results"][0]["freed"], 10)

    def test_defender_workers_only_query_or_log_confirmed_real_results(self):
        client = FakeDefender()
        db = self.context.db

        state = run_worker(make_defender_query_task(client, "exclusions"))
        self.assertTrue(state["ok"], state["error"])
        self.assertEqual(state["result"], {"restricted": True})
        self.assertEqual(db.list_actions(), [])  # consultas não são registradas

        state = run_worker(make_defender_update_task(client, db))
        self.assertTrue(state["ok"], state["error"])
        self.assertTrue(state["result"]["ok"])
        actions = db.list_actions()
        self.assertEqual(len(actions), 1)
        self.assertEqual(actions[0]["action"], "defender_update")
        self.assertEqual(actions[0]["success"], 1)

        state = run_worker(make_defender_scan_task(client, "quick", db))
        self.assertTrue(state["ok"], state["error"])
        self.assertTrue(client.scan.started)
        actions = db.list_actions()
        self.assertEqual(actions[0]["action"], "defender_scan_quick")
        self.assertEqual(actions[0]["success"], 1)
        for forbidden in ("set_real_time_protection", "add_exclusion", "remove_exclusion"):
            self.assertNotIn(forbidden, client.calls)


class HistoryTests(GuiTestCase):
    def test_history_uses_real_records_with_filters_and_incremental_pages(self):
        db = self.context.db
        scan_id = db.start_scan("quick")
        db.add_finding(scan_id, Finding(
            path=str(self.tmp / "detectado.exe"), sha256="abc", score=80,
            risk=RiskLevel.ALTO, category="Teste"))
        db.finish_scan(scan_id, 2, 0)
        db.add_quarantine({
            "id": "q-history", "original_path": str(self.tmp / "detectado.exe"),
            "stored_name": "q-history.qz", "sha256": "abc", "size": 16,
            "evidence": [], "meta": {},
        })
        db.log_action("defender_update", "Microsoft Defender", "ok", True)
        db.log_action("process_terminate", "42", "falha simulada", False)

        first = run_worker(make_history_task(
            db, category="all", period="all", search="", offset=0, limit=2))
        self.assertTrue(first["ok"], first["error"])
        page = first["result"]
        self.assertEqual(len(page["events"]), 2)
        self.assertGreater(page["total"], 2)
        self.assertTrue(page["has_more"])

        second = run_worker(make_history_task(
            db, category="all", period="all", search="", offset=2, limit=2))
        self.assertTrue(second["ok"], second["error"])
        self.assertLessEqual(second["result"]["events"][0]["ts"], page["events"][0]["ts"])
        self.assertNotEqual(second["result"]["events"][0]["title"], page["events"][0]["title"])

        filtered = run_worker(make_history_task(
            db, category="actions", period="24h", search="defender", offset=0, limit=10))
        self.assertTrue(filtered["ok"], filtered["error"])
        self.assertEqual(filtered["result"]["total"], 1)
        self.assertEqual(filtered["result"]["events"][0]["result"], "success")

        failed = run_worker(make_history_task(
            db, category="actions", period="all", search="falha simulada", offset=0, limit=10))
        self.assertTrue(failed["ok"], failed["error"])
        self.assertEqual(failed["result"]["events"][0]["result"], "failure")


if __name__ == "__main__":
    unittest.main()
