"""Preservação de ACL e atributos de arquivo no Windows (ctypes, sem dependências externas).

- ``capture_acl`` exporta a DACL do arquivo em SDDL.
- ``restore_acl`` reaplica a DACL salva após a restauração.
- ``apply_attributes`` reaplica atributos (oculto, somente leitura etc.).

Todas as funções são "best effort": em caso de falta de privilégio ou plataforma
não suportada retornam ``None``/``False`` sem interromper a operação principal.
"""
from __future__ import annotations

import ctypes
import os
import stat
import sys
from pathlib import Path

from .logger import get_logger

log = get_logger(__name__)
IS_WINDOWS = sys.platform == "win32"

if IS_WINDOWS:  # pragma: no branch - constante de plataforma
    _SE_FILE_OBJECT = 1
    _DACL_SECURITY_INFORMATION = 0x00000004
    _SDDL_REVISION_1 = 1
    _FILE_ATTRIBUTE_DIRECTORY = 0x10
    _FILE_ATTRIBUTE_REPARSE_POINT = 0x400

    _advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    _advapi32.GetNamedSecurityInfoW.argtypes = [
        ctypes.c_wchar_p, ctypes.c_int, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_void_p),
    ]
    _advapi32.GetNamedSecurityInfoW.restype = ctypes.c_uint32
    _advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW.argtypes = [
        ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_wchar_p), ctypes.POINTER(ctypes.c_uint32),
    ]
    _advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW.restype = ctypes.c_int
    _advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        ctypes.c_wchar_p, ctypes.c_uint32, ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_uint32),
    ]
    _advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = ctypes.c_int
    _advapi32.SetFileSecurityW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_void_p]
    _advapi32.SetFileSecurityW.restype = ctypes.c_int
    _kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    _kernel32.LocalFree.restype = ctypes.c_void_p
    _kernel32.SetFileAttributesW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32]
    _kernel32.SetFileAttributesW.restype = ctypes.c_int


def capture_acl(path) -> str | None:
    """Retorna a DACL do arquivo em SDDL ou ``None`` se não for possível."""
    if not IS_WINDOWS:
        return None
    sd = ctypes.c_void_p()
    dacl = ctypes.c_void_p()
    try:
        rc = _advapi32.GetNamedSecurityInfoW(
            str(path), _SE_FILE_OBJECT, _DACL_SECURITY_INFORMATION, None, None,
            ctypes.byref(dacl), None, ctypes.byref(sd))
        if rc != 0 or not sd:
            log.debug("GetNamedSecurityInfo falhou para %s (código %s)", path, rc)
            return None
        text = ctypes.c_wchar_p()
        size = ctypes.c_uint32()
        ok = _advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW(
            sd, _SDDL_REVISION_1, _DACL_SECURITY_INFORMATION, ctypes.byref(text), ctypes.byref(size))
        if not ok or not text.value:
            return None
        return text.value
    except (OSError, ValueError) as exc:  # ctypes/biblioteca do sistema
        log.debug("Falha ao capturar ACL de %s: %s", path, exc)
        return None
    finally:
        if sd.value:
            _kernel32.LocalFree(sd)


def restore_acl(path, sddl: str | None) -> bool:
    """Reaplica a DACL salva. Retorna False se o Windows recusar (ex.: sem WRITE_DAC)."""
    if not IS_WINDOWS or not sddl:
        return False
    sd = ctypes.c_void_p()
    try:
        ok = _advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl, _SDDL_REVISION_1, ctypes.byref(sd), None)
        if not ok or not sd:
            log.debug("SDDL inválido ao restaurar ACL de %s", path)
            return False
        ok = _advapi32.SetFileSecurityW(str(path), _DACL_SECURITY_INFORMATION, sd)
        if not ok:
            log.warning("Não foi possível restaurar a ACL de %s: %s", path, ctypes.WinError(ctypes.get_last_error()))
        return bool(ok)
    except (OSError, ValueError) as exc:
        log.warning("Falha ao restaurar ACL de %s: %s", path, exc)
        return False
    finally:
        if sd.value:
            _kernel32.LocalFree(sd)


def apply_attributes(path, attributes: int | None) -> bool:
    """Reaplica atributos do Windows (ignora bits de diretório/reparse)."""
    if attributes is None:
        return False
    if IS_WINDOWS:
        attrs = int(attributes) & ~(_FILE_ATTRIBUTE_DIRECTORY | _FILE_ATTRIBUTE_REPARSE_POINT)
        try:
            return bool(_kernel32.SetFileAttributesW(str(path), attrs))
        except (OSError, ValueError) as exc:
            log.debug("Falha ao aplicar atributos em %s: %s", path, exc)
            return False
    return False


def apply_mode(path, mode: int | None) -> bool:
    """Reaplica permissões POSIX (usado apenas fora do Windows)."""
    if IS_WINDOWS or mode is None:
        return False
    try:
        os.chmod(Path(path), stat.S_IMODE(int(mode)))
        return True
    except OSError as exc:
        log.debug("Falha ao aplicar modo em %s: %s", path, exc)
        return False
