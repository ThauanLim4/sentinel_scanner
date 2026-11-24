"""Preferências persistentes da interface (JSON, sem tocar no Registro)."""
from __future__ import annotations

import json
import os
from pathlib import Path

from core import config
DEFAULTS = {
    "theme": "dark",
    "language": "pt-BR",
    "scan_directories": [],
    "exclusions": [],
    "log_level": "INFO",
    "notifications": True,
    "scan_workers": 2,
    "cpu_limit": 60,
    "confirm_close_during_scan": True,
}


def _clip_int(value, low: int, high: int, default: int) -> int:
    try:
        return max(low, min(high, int(value)))
    except (TypeError, ValueError):
        return default


def _clip_bool(value, default: bool) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        text = value.strip().casefold()
        if text in ("1", "true", "sim", "yes", "on"):
            return True
        if text in ("0", "false", "nao", "não", "no", "off"):
            return False
        return default
    return bool(value)


class Settings:
    """Configurações simples com gravação atômica.

    A interface nunca altera proteções do núcleo: estes valores controlam apenas
    apresentação, desempenho da varredura e filtros de caminhos.
    """

    def __init__(self, path: Path | None = None):
        self.path = Path(path or config.DATA_DIR / "gui_settings.json")
        self._data = dict(DEFAULTS)
        self.load()

    def load(self) -> dict:
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            raw = {}
        if isinstance(raw, dict):
            for key in DEFAULTS:
                if key in raw:
                    self._data[key] = raw[key]
        self._normalize()
        return dict(self._data)

    def _normalize(self) -> None:
        if self._data.get("theme") not in ("dark", "light"):
            self._data["theme"] = "dark"
        if self._data.get("log_level") not in ("DEBUG", "INFO", "WARNING", "ERROR"):
            self._data["log_level"] = "INFO"
        self._data["scan_workers"] = _clip_int(self._data.get("scan_workers"), 1, 8, 2)
        self._data["cpu_limit"] = _clip_int(self._data.get("cpu_limit"), 10, 100, 60)
        for key in ("scan_directories", "exclusions"):
            value = self._data.get(key)
            if not isinstance(value, list):
                value = []
            paths = []
            for item in value:
                if item is None:
                    continue
                text = str(item).strip()
                if text:
                    paths.append(text)
            self._data[key] = paths
        self._data["notifications"] = _clip_bool(self._data.get("notifications", True), True)
        self._data["confirm_close_during_scan"] = _clip_bool(
            self._data.get("confirm_close_during_scan", True), True)

    def get(self, key: str, default=None):
        return self._data.get(key, default)

    def set(self, key: str, value) -> None:
        self._data[key] = value
        self._normalize()

    def update(self, values: dict) -> None:
        for key, value in values.items():
            if key in DEFAULTS:
                self._data[key] = value
        self._normalize()

    def save(self) -> None:
        self._normalize()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_name(self.path.name + ".tmp")
        tmp.write_text(json.dumps(self._data, indent=2, ensure_ascii=False), encoding="utf-8")
        os.replace(tmp, self.path)

    def as_dict(self) -> dict:
        return dict(self._data)

    def reset(self) -> None:
        self._data = dict(DEFAULTS)
        self._normalize()
        self.save()
