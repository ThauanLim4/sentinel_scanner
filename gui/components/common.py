"""Componentes visuais reutilizáveis (cartões, cabeçalhos, badges, estados vazios)."""
from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from ..styles.theme import color
from .icons import icon

MUTED = "#919bb0"


def repolish(widget: QWidget) -> None:
    """Reaplica o QSS depois de mudar uma propriedade dinâmica."""
    style = widget.style()
    style.unpolish(widget)
    style.polish(widget)
    widget.update()


def set_role(widget: QWidget, role: str) -> None:
    widget.setProperty("role", role)
    repolish(widget)


def set_class(widget: QWidget, value: str) -> None:
    widget.setProperty("class", value)
    repolish(widget)


def make_button(text: str, icon_name: str | None = None, kind: str | None = None,
                tooltip: str = "", clicked=None, parent=None) -> QPushButton:
    button = QPushButton(text, parent)
    if icon_name:
        icon_color = "#ffffff" if kind == "primary" else (color("dark", "@red") if kind == "danger" else MUTED)
        button.setIcon(icon(icon_name, icon_color, 16))
    if kind:
        set_class(button, kind)
        # O estilo é aplicado antes de o botão entrar no widget pai; reaplica ao mostrar.
        button.setProperty("_sentinel_kind", kind)
    if tooltip:
        button.setToolTip(tooltip)
    if clicked is not None:
        button.clicked.connect(clicked)
    return button


def elide(text: str, limit: int = 110) -> str:
    text = str(text or "")
    return text if len(text) <= limit else text[: max(0, limit - 1)] + "…"


class Card(QFrame):
    """Painel com borda e cantos arredondados."""

    def __init__(self, parent=None, *, soft: bool = False, padding: int = 18, spacing: int = 12):
        super().__init__(parent)
        set_class(self, "cardSoft" if soft else "card")
        self.body = QVBoxLayout(self)
        self.body.setContentsMargins(padding, padding, padding, padding)
        self.body.setSpacing(spacing)
        self.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Preferred)


class PageHeader(QWidget):
    def __init__(self, title: str, subtitle: str = "", actions: list[QWidget] | None = None, parent=None):
        super().__init__(parent)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(12)
        text_box = QVBoxLayout()
        text_box.setSpacing(3)
        self.title_label = QLabel(title)
        set_role(self.title_label, "h1")
        self.subtitle_label = QLabel(subtitle)
        set_role(self.subtitle_label, "muted")
        self.subtitle_label.setWordWrap(True)
        text_box.addWidget(self.title_label)
        text_box.addWidget(self.subtitle_label)
        layout.addLayout(text_box, 1)
        self.actions_layout = QHBoxLayout()
        self.actions_layout.setSpacing(8)
        layout.addLayout(self.actions_layout)
        for action in actions or []:
            self.actions_layout.addWidget(action)

    def set_title(self, title: str, subtitle: str | None = None) -> None:
        self.title_label.setText(title)
        if subtitle is not None:
            self.subtitle_label.setText(subtitle)


class SectionHeader(QWidget):
    def __init__(self, title: str, trailing: QWidget | None = None, parent=None):
        super().__init__(parent)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)
        self.title_label = QLabel(title)
        set_role(self.title_label, "h3")
        layout.addWidget(self.title_label)
        layout.addStretch(1)
        if trailing is not None:
            layout.addWidget(trailing)


class Badge(QLabel):
    _ROLES = {
        "safe": "badgeGreen",
        "warning": "badgeYellow",
        "danger": "badgeRed",
        "accent": "badgeAccent",
        "gray": "badgeGray",
    }

    def __init__(self, text: str = "", level: str = "gray", parent=None):
        super().__init__(text, parent)
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.set_level(level)

    def set_level(self, level: str) -> None:
        set_role(self, self._ROLES.get(level, "badgeGray"))


class Separator(QFrame):
    def __init__(self, parent=None):
        super().__init__(parent)
        set_class(self, "separator")
        self.setFixedHeight(1)


class InfoBanner(QFrame):
    """Faixa de erro/aviso/sucesso/informação, oculta enquanto vazia."""

    _CLASS = {"info": "notice", "warning": "warning", "danger": "danger", "success": "success"}
    _ICON = {"info": ("info", "#8b5cf6"), "warning": ("alert", "#f59e0b"),
             "danger": ("alert", "#ef4444"), "success": ("check", "#22c55e")}

    def __init__(self, parent=None):
        super().__init__(parent)
        set_class(self, "notice")
        layout = QHBoxLayout(self)
        layout.setContentsMargins(14, 11, 14, 11)
        layout.setSpacing(10)
        self.icon_label = QLabel()
        self.icon_label.setFixedSize(20, 20)
        layout.addWidget(self.icon_label, 0, Qt.AlignmentFlag.AlignTop)
        text_box = QVBoxLayout()
        text_box.setSpacing(2)
        self.title_label = QLabel()
        set_role(self.title_label, "h3")
        self.message_label = QLabel()
        set_role(self.message_label, "muted")
        self.message_label.setWordWrap(True)
        self.message_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        text_box.addWidget(self.title_label)
        text_box.addWidget(self.message_label)
        layout.addLayout(text_box, 1)
        self.hide()

    def set_message(self, level: str, title: str, message: str = "") -> None:
        set_class(self, self._CLASS.get(level, "notice"))
        icon_name, icon_color = self._ICON.get(level, self._ICON["info"])
        self.icon_label.setPixmap(icon(icon_name, icon_color, 18).pixmap(18, 18))
        self.title_label.setText(title)
        self.message_label.setText(message)
        self.message_label.setVisible(bool(message))
        self.show()

    def clear(self) -> None:
        self.hide()


class EmptyState(QWidget):
    def __init__(self, icon_name: str = "info", title: str = "Nada por aqui",
                 description: str = "", parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 34, 24, 34)
        layout.setSpacing(8)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.icon_label = QLabel()
        self.icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.title_label = QLabel(title)
        set_role(self.title_label, "h3")
        self.title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.text_label = QLabel(description)
        set_role(self.text_label, "muted")
        self.text_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.text_label.setWordWrap(True)
        layout.addWidget(self.icon_label)
        layout.addWidget(self.title_label)
        layout.addWidget(self.text_label)
        self.set_state(icon_name, title, description)

    def set_state(self, icon_name: str, title: str, description: str = "") -> None:
        self.icon_label.setPixmap(icon(icon_name, MUTED, 34).pixmap(34, 34))
        self.title_label.setText(title)
        self.text_label.setText(description)
        self.text_label.setVisible(bool(description))


class FieldRow(QWidget):
    def __init__(self, label: str, value: str = "—", parent=None):
        super().__init__(parent)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)
        self.name_label = QLabel(label)
        set_role(self.name_label, "muted2")
        self.name_label.setMinimumWidth(110)
        self.value_label = QLabel(value)
        self.value_label.setWordWrap(True)
        self.value_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        layout.addWidget(self.name_label, 0, Qt.AlignmentFlag.AlignTop)
        layout.addWidget(self.value_label, 1)

    def set_value(self, value: str) -> None:
        self.value_label.setText(str(value))


class MiniStat(QWidget):
    def __init__(self, label: str, value: str = "—", parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(3)
        self.value_label = QLabel(value)
        set_role(self.value_label, "h3")
        self.value_label.setWordWrap(True)
        self.name_label = QLabel(label)
        set_role(self.name_label, "muted2")
        layout.addWidget(self.value_label)
        layout.addWidget(self.name_label)

    def set_value(self, value: str) -> None:
        self.value_label.setText(str(value))


def make_scroll(content: QWidget, parent=None) -> QScrollArea:
    area = QScrollArea(parent)
    area.setWidgetResizable(True)
    area.setFrameShape(QFrame.Shape.NoFrame)
    area.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
    area.setWidget(content)
    return area


def card_grid(cards: list[QWidget], columns: int = 4, spacing: int = 14) -> QWidget:
    holder = QWidget()
    grid = QGridLayout(holder)
    grid.setContentsMargins(0, 0, 0, 0)
    grid.setSpacing(spacing)
    for index, card in enumerate(cards):
        grid.addWidget(card, index // columns, index % columns)
    for column in range(columns):
        grid.setColumnStretch(column, 1)
    return holder
