"""Notificações internas: histórico no cabeçalho e avisos temporários."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from PySide6.QtCore import QEasingCurve, QObject, QPoint, QPropertyAnimation, Qt, QTimer, Signal
from PySide6.QtGui import QGuiApplication
from PySide6.QtWidgets import (
    QFrame,
    QGraphicsOpacityEffect,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from ..formatting import relative_time
from .common import Separator, make_button, set_class, set_role
from .icons import icon

LEVEL_COLORS = {
    "safe": "#22c55e",
    "success": "#22c55e",
    "warning": "#f59e0b",
    "danger": "#ef4444",
    "info": "#38bdf8",
    "accent": "#8b5cf6",
}
LEVEL_ICONS = {
    "safe": "check",
    "success": "check",
    "warning": "alert",
    "danger": "alert",
    "info": "info",
    "accent": "info",
}


@dataclass
class Notification:
    level: str
    title: str
    message: str
    created: datetime


class NotificationCenter(QObject):
    added = Signal(object)
    cleared = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.items: list[Notification] = []

    def add(self, level: str, title: str, message: str = "") -> Notification:
        item = Notification(level, title, message, datetime.now())
        self.items.insert(0, item)
        del self.items[50:]
        self.added.emit(item)
        return item

    def clear(self) -> None:
        self.items.clear()
        self.cleared.emit()

    def __len__(self) -> int:
        return len(self.items)


class Toast(QFrame):
    closed = Signal(object)

    def __init__(self, parent: QWidget, item: Notification, timeout_ms: int = 6000):
        super().__init__(parent)
        self.item = item
        set_class(self, "toast")
        self.setFixedWidth(370)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(14, 12, 10, 12)
        layout.setSpacing(10)
        icon_label = QLabel()
        icon_label.setPixmap(icon(LEVEL_ICONS.get(item.level, "info"),
                                  LEVEL_COLORS.get(item.level, "#38bdf8"), 18).pixmap(18, 18))
        icon_label.setFixedSize(20, 20)
        layout.addWidget(icon_label, 0, Qt.AlignmentFlag.AlignTop)
        text_box = QVBoxLayout()
        text_box.setSpacing(2)
        title = QLabel(item.title)
        set_role(title, "toastTitle")
        title.setWordWrap(True)
        message = QLabel(item.message)
        set_role(message, "toastText")
        message.setWordWrap(True)
        message.setVisible(bool(item.message))
        text_box.addWidget(title)
        text_box.addWidget(message)
        layout.addLayout(text_box, 1)
        close = QPushButton("✕")
        set_class(close, "link")
        close.setToolTip("Fechar aviso")
        close.setFixedWidth(24)
        close.clicked.connect(self.hide_animated)
        layout.addWidget(close, 0, Qt.AlignmentFlag.AlignTop)
        self._effect = QGraphicsOpacityEffect(self)
        self._effect.setOpacity(0.0)
        self.setGraphicsEffect(self._effect)
        self._fade = QPropertyAnimation(self._effect, b"opacity", self)
        self._fade.setDuration(160)
        self._fade.setEasingCurve(QEasingCurve.Type.OutCubic)
        self._timer = QTimer(self)
        self._timer.setSingleShot(True)
        self._timer.timeout.connect(self.hide_animated)
        self._timer.start(max(1500, timeout_ms))
        self._closed = False

    def show_animated(self) -> None:
        self.show()
        self.raise_()
        self._fade.stop()
        self._fade.setStartValue(0.0)
        self._fade.setEndValue(1.0)
        self._fade.start()

    def hide_animated(self) -> None:
        if not self.isVisible() or self._closed:
            self._finish()
            return
        self._timer.stop()
        self._fade.stop()
        self._fade.setStartValue(self._effect.opacity())
        self._fade.setEndValue(0.0)
        self._fade.finished.connect(self._finish)
        self._fade.start()

    def _finish(self) -> None:
        if self._closed:
            return
        self._closed = True
        self.closed.emit(self)
        self.hide()
        self.deleteLater()


class NotificationPanel(QFrame):
    """Painel popup com o histórico de notificações."""

    def __init__(self, center: NotificationCenter, parent=None):
        super().__init__(parent, Qt.WindowType.Popup)
        self.center = center
        self.setObjectName("NotificationPanel")
        self.setFixedWidth(360)
        self.setMaximumHeight(440)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(14, 12, 14, 12)
        outer.setSpacing(8)
        header = QHBoxLayout()
        title = QLabel("Notificações")
        set_role(title, "h3")
        header.addWidget(title)
        header.addStretch(1)
        clear = QPushButton("Limpar")
        set_class(clear, "link")
        clear.clicked.connect(self._clear)
        header.addWidget(clear)
        outer.addLayout(header)
        outer.addWidget(Separator())
        self.scroll = QScrollArea()
        self.scroll.setWidgetResizable(True)
        self.scroll.setFrameShape(QFrame.Shape.NoFrame)
        self.scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.content = QWidget()
        self.content.setObjectName("ViewRoot")
        self.body = QVBoxLayout(self.content)
        self.body.setContentsMargins(0, 0, 0, 0)
        self.body.setSpacing(6)
        self.scroll.setWidget(self.content)
        outer.addWidget(self.scroll, 1)
        center.added.connect(self._on_changed)
        center.cleared.connect(self.refresh)
        self.refresh()

    def _on_changed(self, _item=None) -> None:
        if self.isVisible():
            self.refresh()

    def _clear(self) -> None:
        self.center.clear()

    def refresh(self) -> None:
        while self.body.count():
            item = self.body.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()
        if not self.center.items:
            empty = QLabel("Nenhuma notificação.")
            set_role(empty, "muted")
            empty.setAlignment(Qt.AlignmentFlag.AlignCenter)
            empty.setContentsMargins(0, 28, 0, 28)
            self.body.addWidget(empty)
        else:
            for notification in self.center.items[:30]:
                frame = QFrame()
                set_class(frame, "cardSoft")
                row = QHBoxLayout(frame)
                row.setContentsMargins(10, 8, 10, 8)
                row.setSpacing(8)
                dot = QLabel("●")
                set_role(dot, "dot")
                dot.setStyleSheet(f"color: {LEVEL_COLORS.get(notification.level, '#38bdf8')};")
                row.addWidget(dot, 0, Qt.AlignmentFlag.AlignTop)
                text_box = QVBoxLayout()
                text_box.setSpacing(2)
                line = QHBoxLayout()
                title = QLabel(notification.title)
                set_role(title, "h3")
                title.setWordWrap(True)
                when = QLabel(relative_time(notification.created))
                set_role(when, "muted2")
                when.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
                line.addWidget(title, 1)
                line.addWidget(when, 0)
                text_box.addLayout(line)
                if notification.message:
                    message = QLabel(notification.message)
                    set_role(message, "muted")
                    message.setWordWrap(True)
                    text_box.addWidget(message)
                row.addLayout(text_box, 1)
                self.body.addWidget(frame)
        self.body.addStretch(1)

    def show_at(self, position: QPoint) -> None:
        self.refresh()
        self.adjustSize()
        screen = QGuiApplication.screenAt(position) or QGuiApplication.primaryScreen()
        if screen is not None:
            rect = screen.availableGeometry()
            x = min(max(position.x(), rect.left() + 8), rect.right() - self.width() - 8)
            y = min(max(position.y(), rect.top() + 8), rect.bottom() - self.height() - 8)
            position = QPoint(x, y)
        self.move(position)
        self.show()
        self.raise_()
