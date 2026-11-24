"""Janela principal: navegação, cabeçalho, notificações e ciclo de vida."""
from __future__ import annotations

from functools import partial

from PySide6.QtCore import QPoint, Qt
from PySide6.QtWidgets import (
    QApplication,
    QHBoxLayout,
    QMainWindow,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from core import config
from core.logger import get_logger, set_level
from .components.confirmation_dialog import confirm_action
from .components.header import Header
from .components.notification import NotificationCenter, NotificationPanel, Toast
from .components.sidebar import Sidebar
from .context import AppContext
from .styles.theme import stylesheet
from .views import build_views

log = get_logger("gui.main")


class MainWindow(QMainWindow):
    def __init__(self, context: AppContext, auto_load: bool = True, parent=None):
        super().__init__(parent)
        self.context = context
        self._auto_load = auto_load
        self._closing = False
        self._toast: Toast | None = None
        self.current_key = ""
        self.setWindowTitle(f"{config.APP_NAME} — Segurança e manutenção")
        self.resize(1360, 820)
        self.setMinimumSize(1080, 680)
        self.notifications = NotificationCenter(self)

        root = QWidget()
        root.setObjectName("AppRoot")
        self.setCentralWidget(root)
        outer = QHBoxLayout(root)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        self.sidebar = Sidebar()
        outer.addWidget(self.sidebar)

        right = QWidget()
        right.setObjectName("ContentRoot")
        right_layout = QVBoxLayout(right)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(0)
        self.header = Header()
        right_layout.addWidget(self.header)
        self.stack = QStackedWidget()
        right_layout.addWidget(self.stack, 1)
        outer.addWidget(right, 1)

        self.views = build_views(context)
        self._keys = list(self.views)
        for key in self._keys:
            view = self.views[key]
            view.system_status_changed.connect(self._on_system_status)
            view.data_changed.connect(partial(self._on_data_changed, key))
            view.settings_changed.connect(self._on_settings_changed)
            self.stack.addWidget(view)

        self.sidebar.navigate.connect(self.navigate)
        self.header.notifications_clicked.connect(self.toggle_notifications)
        self.notification_panel = NotificationPanel(self.notifications, self)
        self.notifications.added.connect(lambda _item: self._update_unread())
        self.notifications.cleared.connect(self._update_unread)

        self.statusBar().showMessage("Pronto")
        self.statusBar().setSizeGripEnabled(False)
        self.navigate("dashboard", load=auto_load)
        self.apply_theme(str(context.settings.get("theme", "dark")))

    # ------------------------------------------------------------------ navegação
    def navigate(self, key: str, load: bool = True) -> None:
        view = self.views.get(key)
        if view is None:
            return
        self.current_key = key
        self.stack.setCurrentWidget(view)
        self.sidebar.set_active(key)
        self.header.set_page(view.TITLE, view.SUBTITLE)
        self.statusBar().showMessage(f"Seção: {view.TITLE}", 4000)
        if load and self._auto_load:
            view.on_activate()

    def start_scan(self, kind: str = "quick") -> None:
        self.navigate("scanner")
        view = self.views.get("scanner")
        begin = getattr(view, "begin_scan", None)
        if callable(begin):
            begin(kind)
        else:
            self.notify("info", "Scanner", "A tela de varredura ainda não está disponível.")

    # ------------------------------------------------------------------ notificações
    def notify(self, level: str, title: str, message: str = "") -> None:
        enabled = bool(self.context.settings.get("notifications", True))
        # Apenas erros e avisos são críticos: continuam visíveis mesmo com as
        # notificações não críticas desligadas. Sucesso/info passam a ser apenas
        # registrados no log.
        important = level in ("danger", "warning")
        if not enabled and not important:
            log.info("%s: %s", title, message)
            return
        item = self.notifications.add(level, title, message)
        self._show_toast(item)
        self.statusBar().showMessage(f"{title}: {message}" if message else title, 8000)
        self._update_unread()

    def _show_toast(self, item) -> None:
        if self._toast is not None:
            try:
                self._toast.hide_animated()
            except RuntimeError:
                pass
        toast = Toast(self.centralWidget(), item)
        toast.closed.connect(self._toast_closed)
        self._toast = toast
        self._position_toast()
        toast.show_animated()
        toast.raise_()

    def _toast_closed(self, _toast) -> None:
        self._toast = None

    def _position_toast(self) -> None:
        if self._toast is None:
            return
        rect = self.centralWidget().rect()
        self._toast.adjustSize()
        x = max(12, rect.width() - self._toast.width() - 24)
        y = max(12, rect.height() - self._toast.height() - 24)
        self._toast.move(x, y)

    def _update_unread(self) -> None:
        self.header.set_unread(len(self.notifications))

    def toggle_notifications(self) -> None:
        if self.notification_panel.isVisible():
            self.notification_panel.hide()
            return
        position = self.header.bell_button.mapToGlobal(
            QPoint(self.header.bell_button.width() + 6, self.header.bell_button.height()))
        self.notification_panel.show_at(position)

    # ------------------------------------------------------------------ tema/estado
    def apply_theme(self, theme: str) -> None:
        app = QApplication.instance()
        if app is not None:
            app.setStyleSheet(stylesheet(theme))
        self.sidebar.refresh_icons(theme)
        self.header.refresh_icons(theme)
        for view in self.views.values():
            view.on_theme_changed(theme)
        self._theme = theme

    def _on_system_status(self, text: str, level: str) -> None:
        self.header.set_status(text, level)
        self.statusBar().showMessage(f"Proteção: {text}", 10000)

    def _on_data_changed(self, source_key: str) -> None:
        """Operações com efeito real invalidam os dados exibidos no Dashboard."""
        if source_key == "dashboard":
            return
        dashboard = self.views.get("dashboard")
        invalidate = getattr(dashboard, "invalidate", None)
        if callable(invalidate):
            invalidate()

    def _on_settings_changed(self, keys) -> None:
        changed = set(keys or [])
        if "theme" in changed:
            self.apply_theme(str(self.context.settings.get("theme", "dark")))
        if "log_level" in changed:
            applied = set_level(str(self.context.settings.get("log_level", "INFO")))
            self.statusBar().showMessage(f"Nível de log aplicado: {applied}", 5000)
        log.info("Preferências aplicadas: %s", ", ".join(sorted(changed)) or "nenhuma")

    def resizeEvent(self, event) -> None:  # noqa: N802 - API Qt
        super().resizeEvent(event)
        self._position_toast()

    # ------------------------------------------------------------------ encerramento
    def prepare_close(self, force: bool = False) -> bool:
        if self._closing:
            return True
        busy = sum(view.tasks.active_count() for view in self.views.values())
        if busy and not force and self.context.settings.get("confirm_close_during_scan", True):
            if not confirm_action(
                self,
                "Encerrar durante uma operação",
                "Há operações em andamento. Encerrar agora pode interromper uma varredura ou "
                "operação de manutenção.",
                "As operações serão canceladas. Resultados parciais podem não ser exibidos.",
                danger=True,
                confirm_text="Encerrar mesmo assim",
                require_ack=True,
            ):
                return False
        self._closing = True
        for view in self.views.values():
            try:
                view.shutdown()
            except Exception:
                log.exception("Falha ao encerrar a tela %s", view.KEY)
        self.context.close()
        return True

    def closeEvent(self, event) -> None:  # noqa: N802 - API Qt
        if self.prepare_close():
            event.accept()
        else:
            event.ignore()
