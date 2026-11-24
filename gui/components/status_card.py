"""Cartão principal de estado da proteção do dashboard."""
from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QGridLayout, QHBoxLayout, QLabel, QVBoxLayout, QWidget

from ..styles.theme import color
from .common import Badge, Card, MiniStat, SectionHeader, Separator, set_role, set_class
from .icons import icon


class ProtectionCard(Card):
    _LEVEL_ICON = {
        "safe": ("shield", "@green"),
        "warning": ("alert", "@yellow"),
        "danger": ("alert", "@red"),
        "muted": ("info", "@muted"),
        "accent": ("shield", "@accent"),
    }

    def __init__(self, parent=None):
        super().__init__(parent, padding=20, spacing=14)
        top = QHBoxLayout()
        top.setSpacing(14)
        self.icon_label = QLabel()
        self.icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.icon_label.setFixedSize(44, 44)
        top.addWidget(self.icon_label, 0, Qt.AlignmentFlag.AlignTop)
        title_box = QVBoxLayout()
        title_box.setSpacing(3)
        heading = QHBoxLayout()
        heading.setSpacing(10)
        self.title_label = QLabel("Estado da proteção")
        set_role(self.title_label, "h2")
        self.badge = Badge("Verificando", "gray")
        heading.addWidget(self.title_label)
        heading.addWidget(self.badge)
        heading.addStretch(1)
        self.description_label = QLabel("Aguardando informações dos módulos do núcleo.")
        set_role(self.description_label, "muted")
        self.description_label.setWordWrap(True)
        title_box.addLayout(heading)
        title_box.addWidget(self.description_label)
        top.addLayout(title_box, 1)
        self.body.addLayout(top)
        self.body.addWidget(Separator())
        self.stats_holder = QWidget()
        self.stats_grid = QGridLayout(self.stats_holder)
        self.stats_grid.setContentsMargins(0, 0, 0, 0)
        self.stats_grid.setHorizontalSpacing(24)
        self.stats_grid.setVerticalSpacing(10)
        self.body.addWidget(self.stats_holder)
        self.actions_layout = QHBoxLayout()
        self.actions_layout.setSpacing(8)
        self.body.addLayout(self.actions_layout)
        self.set_state("muted", "Verificando", "Aguardando informações dos módulos do núcleo.", "Verificando")
        self.set_stats([
            ("Última varredura", "—"),
            ("Ameaças na última varredura", "—"),
            ("Itens em quarentena", "—"),
            ("Windows Defender", "—"),
        ])

    def set_state(self, level: str, title: str, description: str, badge_text: str) -> None:
        self.badge.setText(badge_text)
        self.badge.set_level(level)
        self.title_label.setText(title)
        self.description_label.setText(description)
        icon_name, token = self._LEVEL_ICON.get(level, self._LEVEL_ICON["muted"])
        self.icon_label.setPixmap(icon(icon_name, color("dark", token), 40).pixmap(40, 40))

    def set_stats(self, stats: list[tuple[str, str]]) -> None:
        while self.stats_grid.count():
            item = self.stats_grid.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()
        for index, (label, value) in enumerate(stats):
            widget = MiniStat(label, value)
            self.stats_grid.addWidget(widget, index // 4, index % 4)
        for column in range(4):
            self.stats_grid.setColumnStretch(column, 1)

    def add_action(self, widget: QWidget) -> None:
        self.actions_layout.addWidget(widget)

    def clear_actions(self) -> None:
        while self.actions_layout.count():
            item = self.actions_layout.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()
