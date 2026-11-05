"""Limpeza segura de arquivos temporários. Só remove ARQUIVOS (nunca rmtree), ignora
links/junctions, respeita idade mínima (evita arquivos em uso) e registra cada exclusão."""
from __future__ import annotations

import fnmatch
import os
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from .logger import get_logger
from .safety import is_reparse_point, is_within, is_protected, norm

log = get_logger(__name__)
IS_WINDOWS = sys.platform == "win32"


@dataclass
class Category:
    key: str
    name: str
    description: str
    roots: list = field(default_factory=list)
    patterns: list | None = None      # None = todos os arquivos
    recursive: bool = True
    min_age_days: float = 1.0
    needs_admin: bool = False
    default_selected: bool = True
    kind: str = "dir"                  # "dir" | "recycle"


@dataclass
class CleanupResult:
    freed: int = 0
    deleted: int = 0
    skipped: int = 0
    errors: list = field(default_factory=list)


def _p(env: str, *parts: str) -> Path | None:
    v = os.environ.get(env)
    return Path(v, *parts) if v else None


def build_categories() -> list[Category]:
    local, prog, win = "LOCALAPPDATA", "ProgramData", "SystemRoot"
    cats = [
        Category("user_temp", "Temporários do usuário", "Arquivos em %TEMP% com mais de 24h",
                 [x for x in (_p("TEMP"),) if x], min_age_days=1),
        Category("win_temp", "Temporários do Windows", "C:\\Windows\\Temp (requer administrador)",
                 [x for x in (_p(win, "Temp"),) if x], needs_admin=True, min_age_days=1),
        Category("thumbs", "Cache de miniaturas/ícones", "thumbcache_*.db e iconcache_*.db",
                 [x for x in (_p(local, "Microsoft", "Windows", "Explorer"),) if x],
                 patterns=["thumbcache_*.db", "iconcache_*.db"], recursive=False, min_age_days=0),
        Category("wer", "Relatórios de erro do Windows", "Relatórios WER arquivados",
                 [x for x in (_p(prog, "Microsoft", "Windows", "WER", "ReportArchive"),
                               _p(prog, "Microsoft", "Windows", "WER", "ReportQueue"),
                               _p(local, "Microsoft", "Windows", "WER")) if x],
                 needs_admin=False, min_age_days=7),
        Category("crashdumps", "Despejos de falhas de aplicativos", "%LOCALAPPDATA%\\CrashDumps",
                 [x for x in (_p(local, "CrashDumps"),) if x], min_age_days=7, default_selected=False),
        Category("wu_download", "Download do Windows Update (antigo)", "SoftwareDistribution\\Download com mais de 14 dias",
                 [x for x in (_p(win, "SoftwareDistribution", "Download"),) if x],
                 needs_admin=True, min_age_days=14, default_selected=False),
        Category("old_logs", "Logs antigos do CBS", "Logs do Windows com mais de 30 dias",
                 [x for x in (_p(win, "Logs", "CBS"),) if x], patterns=["*.log", "*.cab"],
                 needs_admin=True, min_age_days=30),
        Category("recycle", "Lixeira", "Esvazia a Lixeira de todas as unidades", kind="recycle",
                 min_age_days=0, default_selected=False),
    ]
    return cats


def _iter_files(cat: Category):
    cutoff = time.time() - cat.min_age_days * 86400
    for root in cat.roots:
        root = Path(root)
        if not root.is_dir() or is_reparse_point(root):
            continue
        stack = [root]
        while stack:
            d = stack.pop()
            try:
                with os.scandir(d) as it:
                    for e in it:
                        try:
                            ep = Path(e.path)
                            if e.is_symlink() or is_reparse_point(ep):
                                continue  # nunca segue links/junctions
                            if e.is_dir(follow_symlinks=False):
                                if cat.recursive:
                                    stack.append(ep)
                            elif e.is_file(follow_symlinks=False):
                                if cat.patterns and not any(fnmatch.fnmatch(e.name.lower(), pt) for pt in cat.patterns):
                                    continue
                                st = e.stat(follow_symlinks=False)
                                # No Windows st_ctime = data de criação (conservador: arquivo recém-copiado é poupado);
                                # em POSIX st_ctime muda a cada alteração de metadados, então só usamos mtime.
                                ref = max(st.st_mtime, st.st_ctime) if (IS_WINDOWS and cat.min_age_days) else st.st_mtime
                                if ref > cutoff:
                                    continue
                                yield ep, st.st_size, root
                        except OSError:
                            continue
            except OSError:
                continue


def _recycle_info() -> tuple[int, int]:
    if not IS_WINDOWS:
        return 0, 0
    import ctypes
    from ctypes import wintypes

    class SHQUERYRBINFO(ctypes.Structure):
        _pack_ = 1
        _fields_ = [("cbSize", wintypes.DWORD), ("i64Size", ctypes.c_longlong), ("i64NumItems", ctypes.c_longlong)]

    info = SHQUERYRBINFO()
    info.cbSize = ctypes.sizeof(SHQUERYRBINFO)
    if ctypes.windll.shell32.SHQueryRecycleBinW(None, ctypes.byref(info)) != 0:
        return 0, 0
    return int(info.i64Size), int(info.i64NumItems)


def estimate(cat: Category) -> tuple[int, int]:
    """Retorna (bytes, quantidade de arquivos) que seriam liberados. Não altera nada."""
    if cat.kind == "recycle":
        return _recycle_info()
    total = count = 0
    for _, size, _ in _iter_files(cat):
        total += size
        count += 1
    return total, count


def clean(cat: Category, db=None, cancel: Callable[[], bool] | None = None,
          progress: Callable[[str], None] | None = None) -> CleanupResult:
    res = CleanupResult()
    if cat.kind == "recycle":
        size, n = _recycle_info()
        if IS_WINDOWS:
            import ctypes
            # flags: SHERB_NOCONFIRMATION | NOPROGRESSUI | NOSOUND
            rc = ctypes.windll.shell32.SHEmptyRecycleBinW(None, None, 0x1 | 0x2 | 0x4)
            if rc in (0, -2147418113):  # S_OK / E_UNEXPECTED (lixeira já vazia)
                res.freed, res.deleted = size, n
                if db:
                    db.log_action("cleanup_recycle", "Lixeira", f"{n} itens, {size} bytes", True)
            else:
                res.errors.append(f"SHEmptyRecycleBin retornou {rc}")
        return res

    for path, size, root in list(_iter_files(cat)):
        if cancel and cancel():
            break
        # Revalida imediatamente antes de excluir (TOCTOU / junction criada no meio)
        if not is_within(path, root) or is_reparse_point(path) or (is_protected(path) and not _allowed_protected(cat, path)):
            res.skipped += 1
            continue
        try:
            os.remove(path)
            res.freed += size
            res.deleted += 1
            if progress:
                progress(str(path))
            if db:
                db.log_action("cleanup_delete", str(path), f"{cat.key}; {size} bytes", True)
        except PermissionError:
            res.skipped += 1  # em uso ou sem permissão
        except OSError as exc:
            res.errors.append(f"{path}: {exc}")
    _prune_empty_dirs(cat)
    log.info("Limpeza %s: %d arquivos, %d bytes, %d ignorados", cat.key, res.deleted, res.freed, res.skipped)
    return res


def _allowed_protected(cat: Category, path: Path) -> bool:
    """Categorias de manutenção do Windows têm raízes dentro de áreas protegidas por definição;
    a exclusão só é permitida dentro dessas raízes explícitas."""
    return any(is_within(path, r) for r in cat.roots)


def _prune_empty_dirs(cat: Category) -> None:
    if not cat.recursive:
        return
    for root in cat.roots:
        root = Path(root)
        if not root.is_dir() or is_reparse_point(root):
            continue
        for dirpath, dirnames, _ in os.walk(root, topdown=False, followlinks=False):
            d = Path(dirpath)
            if d == root or is_reparse_point(d):
                continue
            try:
                os.rmdir(d)  # só remove se estiver vazio
            except OSError:
                pass
