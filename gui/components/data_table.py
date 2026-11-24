"""Tabela reutilizável: ordenação numérica, seleção por linha, estado vazio e checkbox."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QAbstractItemView,
    QHeaderView,
    QStackedWidget,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from .common import EmptyState


@dataclass
class Cell:
    text: str = ""
    sort_key: Any = None
    color: str | None = None
    tooltip: str = ""
    bold: bool = False
    checkable: bool = False
    checked: bool = False


class _CellItem(QTableWidgetItem):
    def __init__(self, cell: Cell):
        super().__init__(cell.text)
        self._sort_key = cell.sort_key if cell.sort_key is not None else cell.text
        flags = Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable
        if cell.checkable:
            flags |= Qt.ItemFlag.ItemIsUserCheckable
        self.setFlags(flags)
        if cell.checkable:
            self.setCheckState(Qt.CheckState.Checked if cell.checked else Qt.CheckState.Unchecked)
        if cell.color:
            self.setForeground(QColor(cell.color))
        if cell.tooltip:
            self.setToolTip(cell.tooltip)
        if cell.bold:
            font = self.font()
            font.setBold(True)
            self.setFont(font)

    def __lt__(self, other) -> bool:  # type: ignore[override]
        left = self._sort_key
        right = getattr(other, "_sort_key", other.text() if hasattr(other, "text") else "")
        try:
            return left < right
        except TypeError:
            return str(left).casefold() < str(right).casefold()


def _as_cell(value) -> Cell:
    if isinstance(value, Cell):
        return value
    return Cell(str(value if value is not None else ""))


class DataTable(QWidget):
    row_activated = Signal(object)
    selection_changed = Signal()
    item_changed = Signal(object, int, bool)

    def __init__(self, columns: list[str], parent=None, *,
                 empty_icon: str = "info",
                 empty_title: str = "Nenhum registro",
                 empty_text: str = "",
                 sortable: bool = True,
                 row_height: int = 32):
        super().__init__(parent)
        self.columns = list(columns)
        self._sortable = sortable
        self.table = QTableWidget(0, len(self.columns))
        self.table.setHorizontalHeaderLabels(self.columns)
        self.table.verticalHeader().setVisible(False)
        self.table.verticalHeader().setDefaultSectionSize(row_height)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        self.table.setShowGrid(False)
        self.table.setWordWrap(False)
        self.table.setTextElideMode(Qt.TextElideMode.ElideRight)
        self.table.setSortingEnabled(False)
        header = self.table.horizontalHeader()
        header.setHighlightSections(False)
        header.setDefaultAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        header.setDefaultSectionSize(150)
        header.setStretchLastSection(True)
        self.table.itemDoubleClicked.connect(self._activate)
        self.table.itemSelectionChanged.connect(self.selection_changed)
        self.table.itemChanged.connect(self._changed)
        self.empty = EmptyState(empty_icon, empty_title, empty_text)
        self.stack = QStackedWidget()
        self.stack.addWidget(self.table)
        self.stack.addWidget(self.empty)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self.stack)
        self.stack.setCurrentWidget(self.empty)

    # ------------------------------------------------------------------ dados
    def set_empty(self, icon_name: str, title: str, text: str = "") -> None:
        self.empty.set_state(icon_name, title, text)

    def set_rows(self, rows: list[list], payloads: list | None = None) -> None:
        self.table.setSortingEnabled(False)
        self.table.blockSignals(True)
        try:
            self.table.clearContents()
            self.table.setRowCount(len(rows))
            for row_index, row in enumerate(rows):
                payload = payloads[row_index] if payloads is not None and row_index < len(payloads) else None
                for column in range(len(self.columns)):
                    value = row[column] if column < len(row) else ""
                    item = _CellItem(_as_cell(value))
                    item.setData(Qt.ItemDataRole.UserRole, payload)
                    self.table.setItem(row_index, column, item)
        finally:
            self.table.blockSignals(False)
            self.table.setSortingEnabled(self._sortable)
        self.stack.setCurrentWidget(self.table if rows else self.empty)

    def clear(self) -> None:
        self.set_rows([])

    def row_count(self) -> int:
        return self.table.rowCount()

    def is_empty(self) -> bool:
        return self.table.rowCount() == 0

    def checked_payloads(self, column: int = 0) -> list:
        out = []
        for row in range(self.table.rowCount()):
            item = self.table.item(row, column)
            if item is not None and item.flags() & Qt.ItemFlag.ItemIsUserCheckable:
                if item.checkState() == Qt.CheckState.Checked:
                    first = self.table.item(row, 0)
                    if first is not None:
                        out.append(first.data(Qt.ItemDataRole.UserRole))
        return out

    def selected_payload(self):
        row = self.table.currentRow()
        if row < 0:
            return None
        item = self.table.item(row, 0)
        return item.data(Qt.ItemDataRole.UserRole) if item is not None else None

    def selected_row(self) -> int:
        return self.table.currentRow()

    def set_column_widths(self, widths: list[int]) -> None:
        for index, width in enumerate(widths):
            if index < self.table.columnCount() and width > 0:
                self.table.setColumnWidth(index, width)

    # ------------------------------------------------------------------ eventos
    def _activate(self, item: QTableWidgetItem) -> None:
        if item is None:
            return
        first = self.table.item(item.row(), 0)
        payload = first.data(Qt.ItemDataRole.UserRole) if first is not None else None
        self.row_activated.emit(payload)

    def _changed(self, item: QTableWidgetItem) -> None:
        if item is None or not (item.flags() & Qt.ItemFlag.ItemIsUserCheckable):
            return
        first = self.table.item(item.row(), 0)
        payload = first.data(Qt.ItemDataRole.UserRole) if first is not None else None
        self.item_changed.emit(payload, item.column(), item.checkState() == Qt.CheckState.Checked)
