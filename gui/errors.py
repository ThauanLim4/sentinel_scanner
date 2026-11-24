"""Tradução de exceções do núcleo em mensagens compreensíveis para o usuário."""
from __future__ import annotations

import sqlite3

from core.cleanup import CleanupError
from core.defender import DefenderUnavailable
from core.platform_utils import PowerShellError
from core.quarantine import QuarantineError
from core.registry_analyzer import RegistryError
from core.startup_analyzer import StartupError


def friendly_error(exc: BaseException | str) -> str:
    if isinstance(exc, str):
        return exc
    if isinstance(exc, PermissionError):
        return "Permissão insuficiente. Feche o arquivo ou execute o Sentinel como administrador."
    if isinstance(exc, FileNotFoundError):
        return "O arquivo ou diretório não existe mais."
    if isinstance(exc, ProcessLookupError):
        return "O processo não existe mais."
    if isinstance(exc, (QuarantineError, CleanupError, StartupError, RegistryError)):
        return str(exc) or "Operação recusada por segurança."
    if isinstance(exc, DefenderUnavailable):
        return f"Windows Defender indisponível: {exc}"
    if isinstance(exc, PowerShellError):
        return f"Falha na integração com o Windows: {exc}"
    if isinstance(exc, sqlite3.Error):
        return f"Banco de dados indisponível: {exc}"
    if isinstance(exc, ValueError):
        return str(exc) or "Valor inválido."
    if isinstance(exc, OSError):
        return f"Falha de leitura/gravação: {exc}"
    return f"Ocorreu um erro inesperado: {exc}"
