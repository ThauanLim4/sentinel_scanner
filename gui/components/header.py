"""Cabeçalho da aplicação: página atual, estado do sistema e notificações."""
from __future__ import annotations

from PySide6.QtCore import QSize, Qt, Signal
from PySide6.QtWidgets import QFrame, QHBoxLayout, QLabel, QPushButton, QVBoxLayout

from core import config
from ..styles.theme import color
from .common import Badge, set_class, set_role
from .icons import icon


class Header(QFrame):
    notifications_clicked = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("Header")
        self.setFixedHeight(74)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(26, 12, 22, 12)
        layout.setSpacing(14)
        text_box = QVBoxLayout()
        text_box.setSpacing(2)
        self.title_label = QLabel("Dashboard")
        set_role(self.title_label, "h2")
        self.subtitle_label = QLabel("Visão geral da proteção")
        set_role(self.subtitle_label, "muted")
        text_box.addWidget(self.title_label)
        text_box.addWidget(self.subtitle_label)
        layout.addLayout(text_box, 1)

        self.status_badge = Badge("Verificando estado…", "gray")
        layout.addWidget(self.status_badge, 0, Qt.AlignmentFlag.AlignVCenter)

        self.bell_button = QPushButton()
        set_class(self.bell_button, "icon")
        self.bell_button.setFixedSize(34, 34)
        self.bell_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.bell_button.setToolTip("Notificações")
        self.bell_button.clicked.connect(self.notifications_clicked)
        layout.addWidget(self.bell_button)

        self.alert_count = QLabel("")
        set_role(self.alert_count, "badgeAccent")
        self.alert_count.setVisible(False)
        layout.addWidget(self.alert_count)

        version = QLabel(f"v{config.APP_VERSION}")
        set_role(version, "muted2")
        layout.addWidget(version)
        self.refresh_icons("dark")

    def set_page(self, title: str, subtitle: str = "") -> None:
        self.title_label.setText(title)
        self.subtitle_label.setText(subtitle)

    def set_status(self, text: str, level: str = "gray") -> None:
        self.status_badge.setText(text)
        self.status_badge.set_level(level)

    def set_unread(self, count: int) -> None:
        self.alert_count.setText(str(count) if count < 100 else "99+")
        self.alert_count.setVisible(count > 0)
        self.bell_button.setToolTip(f"Notificações ({count})" if count else "Notificações")

    def refresh_icons(self, theme: str = "dark") -> None:
        self.bell_button.setIcon(icon("bell", color(theme, "@muted"), 18))
        self.bell_button.setIconSize(QSize(18, 18))
