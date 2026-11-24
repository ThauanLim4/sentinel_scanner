"""Barra lateral de navegação."""
from __future__ import annotations

from PySide6.QtCore import QSize, Qt, Signal
from PySide6.QtWidgets import (
    QButtonGroup,
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from ..styles.theme import color
from .common import Separator, set_role
from .icons import icon

NAV_ITEMS = [
    ("dashboard", "Dashboard", "dashboard"),
    ("scanner", "Scanner", "scanner"),
    ("processes", "Processos", "process"),
    ("network", "Rede", "network"),
    ("startup", "Inicialização", "startup"),
    ("quarantine", "Quarentena", "quarantine"),
    ("cleanup", "Limpeza", "cleanup"),
    ("defender", "Windows Defender", "defender"),
    ("history", "Histórico", "history"),
    ("settings", "Configurações", "settings"),
]

_SECTIONS = [
    ("VISÃO GERAL", ("dashboard", "scanner")),
    ("MONITORAMENTO", ("processes", "network", "startup")),
    ("MANUTENÇÃO", ("quarantine", "cleanup", "defender")),
    ("SISTEMA", ("history", "settings")),
]


class Sidebar(QFrame):
    navigate = Signal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("Sidebar")
        self.setFixedWidth(234)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 18, 14, 14)
        layout.setSpacing(6)

        brand = QHBoxLayout()
        brand.setSpacing(10)
        self.logo_label = QLabel()
        self.logo_label.setFixedSize(34, 34)
        self.logo_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        brand.addWidget(self.logo_label)
        brand_text = QVBoxLayout()
        brand_text.setSpacing(0)
        name = QLabel("Sentinel")
        set_role(name, "suite")
        kind = QLabel("Scanner")
        set_role(kind, "muted2")
        brand_text.addWidget(name)
        brand_text.addWidget(kind)
        brand.addLayout(brand_text, 1)
        layout.addLayout(brand)
        layout.addSpacing(8)
        layout.addWidget(Separator())
        layout.addSpacing(6)

        self.buttons: dict[str, QPushButton] = {}
        self.group = QButtonGroup(self)
        self.group.setExclusive(True)
        for section, keys in _SECTIONS:
            label = QLabel(section)
            set_role(label, "muted2")
            label.setContentsMargins(8, 8, 0, 2)
            layout.addWidget(label)
            for key, title, icon_name in NAV_ITEMS:
                if key not in keys:
                    continue
                button = QPushButton(title)
                button.setObjectName("NavButton")
                button.setCheckable(True)
                button.setCursor(Qt.CursorShape.PointingHandCursor)
                button.setIconSize(QSize(18, 18))
                button.clicked.connect(lambda _checked=False, k=key: self.navigate.emit(k))
                self.group.addButton(button)
                self.buttons[key] = button
                self._icon_names = getattr(self, "_icon_names", {})
                self._icon_names[key] = icon_name
                layout.addWidget(button)
        layout.addStretch(1)
        layout.addWidget(Separator())
        footer = QVBoxLayout()
        footer.setSpacing(2)
        self.mode_label = QLabel("●  Modo local")
        set_role(self.mode_label, "safeText")
        footer.addWidget(self.mode_label)
        version = QLabel("Sentinel Scanner • 0.1.0")
        set_role(version, "muted2")
        footer.addWidget(version)
        layout.addLayout(footer)
        self.refresh_icons("dark")

    def set_active(self, key: str) -> None:
        button = self.buttons.get(key)
        if button is not None and not button.isChecked():
            button.setChecked(True)

    def refresh_icons(self, theme: str = "dark") -> None:
        self.logo_label.setPixmap(icon("logo", color(theme, "@accent"), 32).pixmap(32, 32))
        self.logo_label.setStyleSheet(
            f"background: {color(theme, '@accent_soft')}; border: 1px solid {color(theme, '@accent')};"
            "border-radius: 9px;")
        muted = color(theme, "@muted")
        for key, button in self.buttons.items():
            name = getattr(self, "_icon_names", {}).get(key, "info")
            button.setIcon(icon(name, muted, 18))
