"""Ícones vetoriais próprios (SVG), sem dependência de pacotes externos."""
from __future__ import annotations

from functools import lru_cache

from PySide6.QtCore import QByteArray, Qt
from PySide6.QtGui import QIcon, QPainter, QPixmap
from PySide6.QtSvg import QSvgRenderer

_HEAD = ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" '
         'stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">')

_SVG = {
    "logo": _HEAD + '<path d="M12 2.5 20 6v6.1c0 4.8-3.4 8.1-8 9.4-4.6-1.3-8-4.6-8-9.4V6l8-3.5Z"/>'
                    '<path d="M8.2 12.1c1.2-1.2 2.4-1.8 3.8-1.8 1.7 0 2.8.9 2.8 2.2 0 1.4-1.2 2-3 2.3-1.8.3-3 .9-3 2.3'
                    ' 0 1.4 1.2 2.3 3 2.3 1.4 0 2.6-.6 3.8-1.8" transform="translate(0 -1.2) scale(.86)"/>'
                    '</svg>',
    "dashboard": _HEAD + '<rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/>'
                         '<rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/></svg>',
    "scanner": _HEAD + '<circle cx="11" cy="11" r="7"/><path d="m16.5 16.5 4 4"/><path d="M11 7.5v3.7l2.7 1.6"/></svg>',
    "process": _HEAD + '<rect x="7" y="7" width="10" height="10" rx="2"/><rect x="10" y="10" width="4" height="4" rx="1"/>'
                       '<path d="M9 2v3M12 2v3M15 2v3M9 19v3M12 19v3M15 19v3M2 9h3M2 12h3M2 15h3M19 9h3M19 12h3M19 15h3"/></svg>',
    "network": _HEAD + '<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c2.5 2.4 3.8 5.4 3.8 9S14.5 18.6 12 21c-2.5-2.4-3.8-5.4-3.8-9S9.5 5.4 12 3Z"/></svg>',
    "startup": _HEAD + '<path d="M14.5 4.5c2.6-.7 4.6-.4 5-.4.1.4.3 2.4-.4 5-.4 1.5-1.3 2.8-2.5 3.7l-1.2.9-4.2-4.2.9-1.2c.9-1.2 2.2-2.1 3.7-2.5Z"/>'
                       '<path d="m11.2 9.5-3.4.7-3 3 3.6 1.1M14.5 12.8l-.7 3.4-3 3-1.1-3.6"/><circle cx="16.8" cy="7.2" r="1.2"/></svg>',
    "quarantine": _HEAD + '<rect x="4" y="10" width="16" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/><path d="M12 14v3"/></svg>',
    "cleanup": _HEAD + '<path d="m4 20 9.5-9.5M12.5 8.5l3 3"/><path d="m13 6 5 5 2-2-5-5-2 2Z"/><path d="m8 15 1 1"/><path d="M5 19h6"/></svg>',
    "defender": _HEAD + '<path d="M12 2.5 20 6v6.1c0 4.8-3.4 8.1-8 9.4-4.6-1.3-8-4.6-8-9.4V6l8-3.5Z"/><path d="m8.5 12 2.3 2.3 4.7-4.7"/></svg>',
    "history": _HEAD + '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3.2 2M3.5 8.5 6 4l3 1.5"/></svg>',
    "settings": _HEAD + '<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.9l.1.1-2.8 2.8-.1-.1a1.7 1.7 0 0 0-1.9-.3 1.7 1.7 0 0 0-1 1.6v.2h-4V21a1.7 1.7 0 0 0-1-1.6 1.7 1.7 0 0 0-1.9.3l-.1.1L4.2 17l.1-.1a1.7 1.7 0 0 0 .3-1.9A1.7 1.7 0 0 0 3 14H2.8v-4H3a1.7 1.7 0 0 0 1.6-1 1.7 1.7 0 0 0-.3-1.9L4.2 7 7 4.2l.1.1a1.7 1.7 0 0 0 1.9.3A1.7 1.7 0 0 0 10 3V2.8h4V3a1.7 1.7 0 0 0 1 1.6 1.7 1.7 0 0 0 1.9-.3l.1-.1L19.8 7l-.1.1a1.7 1.7 0 0 0-.3 1.9 1.7 1.7 0 0 0 1.6 1h.2v4H21a1.7 1.7 0 0 0-1.6 1Z"/></svg>',
    "search": _HEAD + '<circle cx="10.5" cy="10.5" r="6.5"/><path d="m15.3 15.3 4.7 4.7"/></svg>',
    "refresh": _HEAD + '<path d="M20 11a8 8 0 1 0-2.3 6.7"/><path d="M20 4v7h-7"/></svg>',
    "play": _HEAD + '<path d="m8 5 11 7-11 7V5Z"/></svg>',
    "stop": _HEAD + '<rect x="6" y="6" width="12" height="12" rx="2"/></svg>',
    "folder": _HEAD + '<path d="M3 7a2 2 0 0 1 2-2h5l2 2h7a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V7Z"/></svg>',
    "trash": _HEAD + '<path d="M4 7h16M9 7V4h6v3M6 7l1 14h10l1-14M10 11v6M14 11v6"/></svg>',
    "restore": _HEAD + '<path d="M4 10a8 8 0 1 1 2.3 8"/><path d="M4 4v6h6"/></svg>',
    "bell": _HEAD + '<path d="M18 9a6 6 0 0 0-12 0c0 7-3 7-3 9h18c0-2-3-2-3-9"/><path d="M10 21h4"/></svg>',
    "info": _HEAD + '<circle cx="12" cy="12" r="9"/><path d="M12 11v5M12 8h.01"/></svg>',
    "check": _HEAD + '<path d="m5 12.5 4.5 4.5L19 7"/></svg>',
    "alert": _HEAD + '<path d="M12 3 2.8 20h18.4L12 3Z"/><path d="M12 9v5M12 17h.01"/></svg>',
    "x": _HEAD + '<path d="m6 6 12 12M18 6 6 18"/></svg>',
    "chevron": _HEAD + '<path d="m9 18 6-6-6-6"/></svg>',
    "external": _HEAD + '<path d="M14 4h6v6M20 4l-9 9"/><path d="M18 14v5a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1h5"/></svg>',
    "eye": _HEAD + '<path d="M2.5 12S6 5.5 12 5.5 21.5 12 21.5 12 18 18.5 12 18.5 2.5 12 2.5 12Z"/><circle cx="12" cy="12" r="3"/></svg>',
    "file": _HEAD + '<path d="M6 2.5h7l5 5V21a1 1 0 0 1-1 1H6a1 1 0 0 1-1-1V3.5a1 1 0 0 1 1-1Z"/><path d="M13 2.5v5h5"/></svg>',
    "monitor": _HEAD + '<rect x="3" y="4" width="18" height="12" rx="2"/><path d="M8 20h8M12 16v4"/></svg>',
    "shield": _HEAD + '<path d="M12 2.5 20 6v6.1c0 4.8-3.4 8.1-8 9.4-4.6-1.3-8-4.6-8-9.4V6l8-3.5Z"/></svg>',
    "users": _HEAD + '<circle cx="9" cy="8" r="3"/><path d="M3.5 20c.4-3.3 2.3-5 5.5-5s5.1 1.7 5.5 5"/><path d="M16 5.5a3 3 0 0 1 0 5.7M17 15c2.1.3 3.3 1.9 3.5 5"/></svg>',
    "power": _HEAD + '<path d="M12 2.5v9"/><path d="M6.3 5.8a8 8 0 1 0 11.4 0"/></svg>',
    "clock": _HEAD + '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></svg>',
}


def _render(name: str, color: str, size: int):
    renderer = QSvgRenderer(QByteArray(_SVG[name].replace("currentColor", color).encode("utf-8")))
    ratio = 2
    pix = QPixmap(size * ratio, size * ratio)
    pix.fill(Qt.GlobalColor.transparent)
    painter = QPainter(pix)
    renderer.render(painter)
    painter.end()
    pix.setDevicePixelRatio(ratio)
    return pix


@lru_cache(maxsize=256)
def icon(name: str = "shield", color: str = "#e7eaf2", size: int = 20) -> QIcon:
    if name not in _SVG:
        name = "info"
    return QIcon(_render(name, color, size))


def logo_icon(size: int = 32, color: str = "#8b5cf6") -> QIcon:
    return icon("logo", color, size)
