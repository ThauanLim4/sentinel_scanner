"""Diálogo de confirmação explícita para operações sensíveis."""
from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox,
    QDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from .common import make_button, set_class, set_role
from .icons import icon


class ConfirmationDialog(QDialog):
    def __init__(self, parent: QWidget | None, title: str, message: str,
                 details: str = "", confirm_text: str = "Confirmar",
                 cancel_text: str = "Cancelar", danger: bool = False,
                 require_ack: bool = False,
                 ack_text: str = "Entendo as consequências e desejo continuar."):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setModal(True)
        self.setMinimumWidth(520)
        self.setMaximumWidth(680)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 22, 24, 18)
        layout.setSpacing(14)

        heading = QHBoxLayout()
        heading.setSpacing(12)
        icon_label = QLabel()
        icon_label.setPixmap(icon("alert" if danger else "info",
                                  "#ef4444" if danger else "#8b5cf6", 28).pixmap(28, 28))
        heading.addWidget(icon_label, 0, Qt.AlignmentFlag.AlignTop)
        title_label = QLabel(title)
        set_role(title_label, "h2")
        title_label.setWordWrap(True)
        heading.addWidget(title_label, 1)
        layout.addLayout(heading)

        message_label = QLabel(message)
        message_label.setWordWrap(True)
        message_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        layout.addWidget(message_label)

        if details:
            detail_frame = QFrame()
            set_class(detail_frame, "cardSoft")
            detail_layout = QVBoxLayout(detail_frame)
            detail_layout.setContentsMargins(12, 10, 12, 10)
            detail_label = QLabel(details)
            detail_label.setWordWrap(True)
            detail_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            set_role(detail_label, "muted")
            detail_layout.addWidget(detail_label)
            layout.addWidget(detail_frame)

        self.ack_checkbox = QCheckBox(ack_text)
        self.ack_checkbox.setVisible(require_ack)
        layout.addWidget(self.ack_checkbox)

        buttons = QHBoxLayout()
        buttons.setSpacing(8)
        buttons.addStretch(1)
        cancel = QPushButton(cancel_text)
        set_class(cancel, "ghost")
        cancel.clicked.connect(self.reject)
        self.confirm_button = make_button(confirm_text, kind="danger" if danger else "primary",
                                          clicked=self.accept)
        self.confirm_button.setDefault(True)
        buttons.addWidget(cancel)
        buttons.addWidget(self.confirm_button)
        layout.addLayout(buttons)

        if require_ack:
            self.confirm_button.setEnabled(False)
            self.ack_checkbox.toggled.connect(self.confirm_button.setEnabled)

    @classmethod
    def ask(cls, parent, title: str, message: str, details: str = "", *,
            danger: bool = False, confirm_text: str = "Confirmar",
            require_ack: bool = False, ack_text: str = "Entendo as consequências e desejo continuar.") -> bool:
        dialog = cls(parent, title, message, details, confirm_text=confirm_text,
                     danger=danger, require_ack=require_ack, ack_text=ack_text)
        return dialog.exec() == QDialog.DialogCode.Accepted


def confirm_action(parent, title: str, message: str, details: str = "", *,
                   danger: bool = False, confirm_text: str = "Confirmar",
                   require_ack: bool = False,
                   ack_text: str = "Entendo as consequências e desejo continuar.") -> bool:
    return ConfirmationDialog.ask(parent, title, message, details, danger=danger,
                                 confirm_text=confirm_text, require_ack=require_ack,
                                 ack_text=ack_text)
