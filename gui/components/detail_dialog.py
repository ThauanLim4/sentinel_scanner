"""Diálogo genérico de detalhes (somente leitura)."""
from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QApplication,
    QDialog,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from .common import Card, FieldRow, Separator, make_button, make_scroll, set_class, set_role


class DetailDialog(QDialog):
    def __init__(self, parent: QWidget | None, title: str, subtitle: str = "",
                 fields: list[tuple[str, str]] | None = None,
                 sections: list[tuple[str, list[str] | str]] | None = None,
                 note: str = ""):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setModal(True)
        self.resize(680, 560)
        self.setMinimumSize(460, 340)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 18, 20, 16)
        layout.setSpacing(12)

        heading = QLabel(title)
        set_role(heading, "h2")
        heading.setWordWrap(True)
        layout.addWidget(heading)
        if subtitle:
            sub = QLabel(subtitle)
            set_role(sub, "muted")
            sub.setWordWrap(True)
            layout.addWidget(sub)

        content = QWidget()
        content.setObjectName("ViewRoot")
        body = QVBoxLayout(content)
        body.setContentsMargins(0, 0, 0, 0)
        body.setSpacing(14)

        if fields:
            card = Card(content, padding=14, spacing=8)
            for label, value in fields:
                card.body.addWidget(FieldRow(label, str(value if value not in (None, "") else "—")))
            body.addWidget(card)

        for section_title, items in sections or []:
            header = QLabel(section_title)
            set_role(header, "h3")
            body.addWidget(header)
            card = Card(content, padding=14, spacing=6)
            if isinstance(items, str):
                text = QLabel(items)
                text.setWordWrap(True)
                text.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
                set_role(text, "muted")
                card.body.addWidget(text)
            else:
                if not items:
                    empty = QLabel("Nenhum item.")
                    set_role(empty, "muted")
                    card.body.addWidget(empty)
                for item in items:
                    label = QLabel(f"•  {item}")
                    label.setWordWrap(True)
                    label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
                    set_role(label, "muted")
                    card.body.addWidget(label)
            body.addWidget(card)

        if note:
            note_label = QLabel(note)
            note_label.setWordWrap(True)
            note_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            set_role(note_label, "muted2")
            body.addWidget(note_label)

        body.addStretch(1)
        area = make_scroll(content)
        layout.addWidget(area, 1)

        buttons = QHBoxLayout()
        buttons.addStretch(1)
        copy = QPushButton("Copiar detalhes")
        set_class(copy, "ghost")
        copy.clicked.connect(lambda: self._copy(title, subtitle, fields, sections, note))
        close = make_button("Fechar", clicked=self.accept)
        buttons.addWidget(copy)
        buttons.addWidget(close)
        layout.addLayout(buttons)

        self._copy_text = self._compose(title, subtitle, fields, sections, note)

    @staticmethod
    def _compose(title, subtitle, fields, sections, note) -> str:
        lines = [title]
        if subtitle:
            lines += ["", subtitle]
        if fields:
            lines.append("")
            for label, value in fields:
                lines.append(f"{label}: {value if value not in (None, '') else '—'}")
        for section_title, items in sections or []:
            lines += ["", section_title]
            if isinstance(items, str):
                lines.append(items)
            else:
                lines.extend(f"- {item}" for item in (items or []))
        if note:
            lines += ["", note]
        return "\n".join(lines)

    def _copy(self, title, subtitle, fields, sections, note) -> None:
        QApplication.clipboard().setText(self._copy_text)


def show_details(parent, title: str, subtitle: str = "", fields=None, sections=None, note: str = "") -> None:
    DetailDialog(parent, title, subtitle, fields, sections, note).exec()
