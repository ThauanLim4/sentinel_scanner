"""Logging em arquivo rotativo + console."""
from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler

from . import config

_configured = False


def setup_logging(level: int = logging.INFO) -> None:
    global _configured
    if _configured:
        return
    config.ensure_dirs()
    root = logging.getLogger("sentinel")
    root.setLevel(level)
    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    fh = RotatingFileHandler(config.LOG_DIR / "sentinel.log", maxBytes=5_000_000,
                             backupCount=5, encoding="utf-8")
    fh.setFormatter(fmt)
    root.addHandler(fh)
    sh = logging.StreamHandler()
    sh.setFormatter(fmt)
    root.addHandler(sh)
    _configured = True


def set_level(level: str | int) -> str:
    """Ajusta o nível do logger raiz em tempo real e devolve o nome aplicado.

    Usado pela interface quando o usuário altera `log_level`: nenhuma reinicialização
    é necessária e um valor inválido cai para INFO (o mesmo critério de `Settings`).
    """
    if isinstance(level, str):
        value = getattr(logging, level.strip().upper(), None)
        if not isinstance(value, int):
            value = logging.INFO
    else:
        value = int(level)
    logging.getLogger("sentinel").setLevel(value)
    return logging.getLevelName(value)


def get_logger(name: str) -> logging.Logger:
    setup_logging()
    return logging.getLogger("sentinel." + name.split(".")[-1])
