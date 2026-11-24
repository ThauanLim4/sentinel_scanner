"""Cartão de métrica do dashboard."""
from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QFrame, QHBoxLayout, QLabel, QVBoxLayout, QWidget

from ..styles.theme import color
from .common import Card, set_role
from .icons import icon


class MetricCard(Card):
    def __init__(self, title: str, value: str = "—", hint: str = "",
                 icon_name: str = "info", accent: str = "@accent", parent=None):
        super().__init__(parent, padding=16, spacing=6)
        top = QHBoxLayout()
        top.setSpacing(8)
        self.title_label = QLabel(title)
        set_role(self.title_label, "cardTitle")
        top.addWidget(self.title_label, 1)
        self.icon_label = QLabel()
        self.icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        top.addWidget(self.icon_label)
        self.body.addLayout(top)
        self.value_label = QLabel(value)
        set_role(self.value_label, "cardValue")
        self.body.addWidget(self.value_label)
        self.hint_label = QLabel(hint)
        set_role(self.hint_label, "muted2")
        self.hint_label.setWordWrap(True)
        self.body.addWidget(self.hint_label)
        self.setProperty("metricIcon", icon_name)
        self.set_accent(accent)

    def set_accent(self, accent: str) -> None:
        hex_color = accent if str(accent).startswith("#") else color("dark", accent)
        self._accent = hex_color
        name = self.property("metricIcon") or "info"
        if isinstance(name, str):
            self.icon_label.setPixmap(icon(name, hex_color, 20).pixmap(20, 20))

    def set_icon(self, name: str, accent: str | None = None) -> None:
        self.setProperty("metricIcon", name)
        self.set_accent(accent or self._accent)

    def set_value(self, value: str) -> None:
        self.value_label.setText(str(value))

    def set_hint(self, hint: str) -> None:
        self.hint_label.setText(hint)


def metric_card(title: str, value: str = "—", hint: str = "", icon_name: str = "info",
                accent: str = "@accent") -> MetricCard:
    return MetricCard(title, value, hint, icon_name, accent)
