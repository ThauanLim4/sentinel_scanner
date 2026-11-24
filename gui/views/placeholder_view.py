"""Tela temporária usada apenas enquanto as telas reais são implementadas por fase."""
from __future__ import annotations

from PySide6.QtWidgets import QVBoxLayout

from ..components.common import Card, PageHeader, make_scroll
from ..context import AppContext
from .base_view import BaseView


class PlaceholderView(BaseView):
    def __init__(self, context: AppContext, key: str, title: str, subtitle: str, parent=None):
        self.KEY = key
        self.TITLE = title
        self.SUBTITLE = subtitle
        super().__init__(context, parent)

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(26, 22, 26, 22)
        root.setSpacing(16)
        root.addWidget(PageHeader(self.TITLE, self.SUBTITLE))
        card = Card()
        card.body.addWidget(PageHeader("Em desenvolvimento", "Esta tela será implementada na próxima fase."))
        root.addWidget(card)
        root.addStretch(1)
