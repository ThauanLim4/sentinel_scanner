"""Classe-base das telas: contexto, trabalhadores assíncronos e notificações."""
from __future__ import annotations

from PySide6.QtCore import Signal
from PySide6.QtWidgets import QWidget

from core.logger import get_logger
from ..components.confirmation_dialog import confirm_action
from ..context import AppContext
from ..workers.base import TaskManager

log = get_logger("gui.views")


class BaseView(QWidget):
    # Sinais de integração: `data_changed` indica que o banco/estado real mudou
    # (o Dashboard precisa ser invalidado); `settings_changed` carrega as chaves
    # alteradas para a janela aplicar tema/nível de log em tempo real.
    system_status_changed = Signal(str, str)
    data_changed = Signal()
    settings_changed = Signal(object)

    KEY = ""
    TITLE = ""
    SUBTITLE = ""

    def __init__(self, context: AppContext, parent=None):
        super().__init__(parent)
        self.context = context
        self.tasks = TaskManager(self)
        self._activated = False
        self.setObjectName("ViewRoot")
        self._build_ui()

    # ------------------------------------------------------------------ contrato
    def _build_ui(self) -> None:  # pragma: no cover - implementado pelas telas
        raise NotImplementedError

    def on_activate(self) -> None:
        self._activated = True

    def on_theme_changed(self, theme: str) -> None:
        pass

    def shutdown(self) -> None:
        self.tasks.shutdown()
        self._activated = False

    # ------------------------------------------------------------------ utilidades
    def notify(self, level: str, title: str, message: str = "") -> None:
        log.log({"danger": 40, "warning": 30, "success": 20, "info": 20}.get(level, 20),
                "%s: %s", title, message)
        window = self.window()
        if window is not self and hasattr(window, "notify"):
            window.notify(level, title, message)

    def info(self, title: str, message: str = "") -> None:
        self.notify("info", title, message)

    def success(self, title: str, message: str = "") -> None:
        self.notify("success", title, message)

    def warn(self, title: str, message: str = "") -> None:
        self.notify("warning", title, message)

    def error(self, title: str, message: str = "") -> None:
        self.notify("danger", title, message)

    def confirm(self, title: str, message: str, details: str = "", *, danger: bool = False,
                confirm_text: str = "Confirmar", require_ack: bool = False,
                ack_text: str = "Entendo as consequências e desejo continuar.") -> bool:
        return confirm_action(self, title, message, details, danger=danger,
                              confirm_text=confirm_text, require_ack=require_ack,
                              ack_text=ack_text)

    def require_db(self):
        if self.context.db is None:
            self.error("Banco de dados indisponível",
                       str(self.context.db_error or "Não foi possível abrir o banco de dados."))
            return None
        return self.context.db

    def set_system_status(self, text: str, level: str) -> None:
        self.system_status_changed.emit(text, level)

    def emit_data_changed(self) -> None:
        self.data_changed.emit()

    def emit_settings_changed(self, keys) -> None:
        self.settings_changed.emit(list(keys))
