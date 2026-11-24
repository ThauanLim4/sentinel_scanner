"""Tema visual do Sentinel Scanner.

Um único arquivo QSS é parametrizado por paleta. Isso mantém os componentes
consistentes e permite alternar entre o tema escuro (padrão) e o claro sem
duplicar regras de estilo.
"""
from __future__ import annotations

from pathlib import Path

PALETTES = {
    "dark": {
        "@bg": "#0d1017",
        "@bg2": "#11151e",
        "@panel": "#171c27",
        "@panel2": "#1d2331",
        "@panel3": "#232a3a",
        "@border": "#2a3142",
        "@border_strong": "#3a4358",
        "@text": "#e7eaf2",
        "@muted": "#919bb0",
        "@muted2": "#6e7890",
        "@accent": "#8b5cf6",
        "@accent_hover": "#a78bfa",
        "@accent_pressed": "#7c3aed",
        "@accent_soft": "#2a2145",
        "@green": "#22c55e",
        "@green_soft": "#12301f",
        "@yellow": "#f59e0b",
        "@yellow_soft": "#33260c",
        "@red": "#ef4444",
        "@red_soft": "#3a1717",
        "@blue": "#38bdf8",
        "@blue_soft": "#102b38",
        "@input": "#0f131c",
        "@selection": "#2b2340",
        "@sidebar": "#0a0d13",
        "@shadow": "rgba(0,0,0,90)",
    },
    "light": {
        "@bg": "#f2f4f8",
        "@bg2": "#ffffff",
        "@panel": "#ffffff",
        "@panel2": "#f7f8fb",
        "@panel3": "#eef1f7",
        "@border": "#d8dde8",
        "@border_strong": "#bcc5d6",
        "@text": "#1b2130",
        "@muted": "#5d687c",
        "@muted2": "#7c879b",
        "@accent": "#6d28d9",
        "@accent_hover": "#7c3aed",
        "@accent_pressed": "#5b21b6",
        "@accent_soft": "#ede9fe",
        "@green": "#15803d",
        "@green_soft": "#dcfce7",
        "@yellow": "#b45309",
        "@yellow_soft": "#fef3c7",
        "@red": "#b91c1c",
        "@red_soft": "#fee2e2",
        "@blue": "#0369a1",
        "@blue_soft": "#e0f2fe",
        "@input": "#fbfcfe",
        "@selection": "#e9e3ff",
        "@sidebar": "#ffffff",
        "@shadow": "rgba(20,25,40,28)",
    },
}

_QSS_PATH = Path(__file__).with_name("styles.qss")
_cache: dict[str, str] = {}


def stylesheet(theme: str = "dark") -> str:
    theme = theme if theme in PALETTES else "dark"
    if theme not in _cache:
        text = _QSS_PATH.read_text(encoding="utf-8")
        # Tokens maiores primeiro: "@accent_hover" não pode ser corrompido por "@accent".
        for token in sorted(PALETTES[theme], key=len, reverse=True):
            text = text.replace(token, PALETTES[theme][token])
        _cache[theme] = text
    return _cache[theme]


def color(theme: str, token: str) -> str:
    return PALETTES.get(theme, PALETTES["dark"]).get(token, "#8b5cf6")


def accent(theme: str = "dark") -> str:
    return color(theme, "@accent")
