"""Proteções do próprio sistema: validação de caminhos, links simbólicos/junctions,
diretórios críticos e verificação de privilégios. Toda operação destrutiva passa por aqui."""
from __future__ import annotations

import os
import sys
from pathlib import Path

FILE_ATTRIBUTE_REPARSE_POINT = 0x400


class UnsafePathError(Exception):
    """Operação recusada por segurança."""


def norm(p) -> str:
    return str(p).replace("/", "\\").lower().rstrip("\\")


def is_admin() -> bool:
    if sys.platform != "win32":
        return hasattr(os, "geteuid") and os.geteuid() == 0
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def is_reparse_point(p: Path) -> bool:
    """True para symlinks e junctions. Em caso de erro, assume True (conservador)."""
    try:
        if Path(p).is_symlink():
            return True
        attrs = getattr(os.lstat(p), "st_file_attributes", 0)
        return bool(attrs & FILE_ATTRIBUTE_REPARSE_POINT)
    except OSError:
        return True


def has_reparse_in_chain(path: Path, stop: Path) -> bool:
    """Verifica se algum componente entre `stop` (exclusive) e `path` é link/junction."""
    path, stop = Path(path), Path(stop)
    cur = path
    while True:
        if os.path.normcase(str(cur)) == os.path.normcase(str(stop)):
            return False
        if is_reparse_point(cur):
            return True
        if cur.parent == cur:
            return False
        cur = cur.parent


def is_within(path, root) -> bool:
    try:
        a = os.path.normcase(os.path.realpath(path))
        b = os.path.normcase(os.path.realpath(root))
        return os.path.commonpath([a, b]) == b
    except ValueError:
        return False


def _env(name: str, default: str) -> str:
    return os.environ.get(name, default)


def protected_roots() -> list[str]:
    windir = _env("SystemRoot", r"C:\Windows")
    return [norm(x) for x in (
        windir,
        _env("ProgramData", r"C:\ProgramData") + r"\Microsoft",
        _env("SystemDrive", "C:") + r"\System Volume Information",
        _env("SystemDrive", "C:") + r"\Recovery",
    )]


def is_protected(path) -> bool:
    s = norm(path)
    return any(s == r or s.startswith(r + "\\") for r in protected_roots())


def sensitive_roots() -> list[str]:
    """Program Files: malware de terceiros pode estar aqui, então a quarentena é permitida,
    mas só com confirmação explícita do usuário."""
    return [norm(x) for x in (_env("ProgramFiles", r"C:\Program Files"),
                              _env("ProgramFiles(x86)", r"C:\Program Files (x86)"))]


def is_sensitive(path) -> bool:
    s = norm(path)
    return any(s == r or s.startswith(r + "\\") for r in sensitive_roots())


def is_dangerous_target(path) -> bool:
    """Raízes de drive, pasta Users e perfis inteiros nunca podem ser alvo direto."""
    s = norm(path)
    if len(s.strip("\\")) <= 3:
        return True
    home = norm(Path.home()) if Path.home() else ""
    drive = _env("SystemDrive", "C:").lower()
    return s in {home, drive + "\\users", drive + "\\windows", drive + "\\program files",
                 drive + "\\programdata"}


def validate_target(path, allowed_roots: list, *, allow_protected: bool = False,
                    allow_sensitive: bool = False, must_be_file: bool = True) -> Path:
    """Valida um alvo de exclusão/quarentena. Levanta UnsafePathError se qualquer
    regra de segurança for violada. Retorna o caminho resolvido."""
    p = Path(path)
    if not p.exists():
        raise UnsafePathError(f"Caminho inexistente: {p}")
    if is_dangerous_target(p):
        raise UnsafePathError(f"Alvo perigoso recusado: {p}")
    if must_be_file and not p.is_file():
        raise UnsafePathError(f"Não é um arquivo regular: {p}")
    if is_reparse_point(p):
        raise UnsafePathError(f"Link simbólico/junction recusado: {p}")
    if not allow_protected and is_protected(p):
        raise UnsafePathError(f"Caminho protegido do Windows: {p}")
    if not allow_sensitive and is_sensitive(p):
        raise UnsafePathError(f"Arquivo em Program Files: requer confirmação explícita do usuário: {p}")
    for root in allowed_roots:
        if is_within(p, root):
            if has_reparse_in_chain(p, Path(root)):
                raise UnsafePathError(f"Componente do caminho é link/junction: {p}")
            return Path(os.path.realpath(p))
    raise UnsafePathError(f"Fora dos diretórios autorizados: {p}")
