"""Preservação de ACL e atributos de arquivo no Windows (ctypes, sem dependências externas).

- ``capture_acl`` exporta a DACL do arquivo em SDDL.
- ``restore_acl`` reaplica a DACL salva após a restauração.
- ``apply_attributes`` reaplica atributos (oculto, somente leitura etc.).
- ``secure_private_file``/``verify_private_file`` restringem/verificam a DACL de
  arquivos sensíveis (ex.: chave mestra e temporários de restauração).

``capture_acl``/``restore_acl``/``apply_attributes`` são "best effort": em caso de
falta de privilégio ou plataforma não suportada retornam ``None``/``False`` sem
interromper a operação principal. ``secure_private_file``/``verify_private_file``
são usadas onde a falha precisa ser tratada como erro (fail-secure).
"""
from __future__ import annotations

import ctypes
import os
import re
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
    _TOKEN_QUERY = 0x0008
    _TOKEN_USER = 1
    _ERROR_INSUFFICIENT_BUFFER = 122
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
    _advapi32.OpenProcessToken.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.POINTER(ctypes.c_void_p)]
    _advapi32.OpenProcessToken.restype = ctypes.c_int
    _advapi32.GetTokenInformation.argtypes = [
        ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32),
    ]
    _advapi32.GetTokenInformation.restype = ctypes.c_int
    _advapi32.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_wchar_p)]
    _advapi32.ConvertSidToStringSidW.restype = ctypes.c_int
    _kernel32.GetCurrentProcess.restype = ctypes.c_void_p
    _kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    _kernel32.CloseHandle.restype = ctypes.c_int
    _kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    _kernel32.LocalFree.restype = ctypes.c_void_p
    _kernel32.SetFileAttributesW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32]
    _kernel32.SetFileAttributesW.restype = ctypes.c_int

    _PRIVATE_SID_ALIASES = {
        "SY", "BA", "OW", "S-1-5-18", "S-1-5-32-544", "S-1-3-4",
    }
    _ACE_RE = re.compile(r"\((?:A|OA|XA);([^)]*)\)", re.I)


def _read_dacl_sddl(path) -> str | None:
    """Lê a DACL em SDDL, liberando TODOS os buffers alocados pelo Windows."""
    if not IS_WINDOWS:
        return None
    sd = ctypes.c_void_p()
    text = ctypes.c_wchar_p()
    try:
        rc = _advapi32.GetNamedSecurityInfoW(
            str(path), _SE_FILE_OBJECT, _DACL_SECURITY_INFORMATION, None, None,
            None, None, ctypes.byref(sd))
        if rc != 0 or not sd:
            log.debug("GetNamedSecurityInfo falhou para %s (código %s)", path, rc)
            return None
        size = ctypes.c_uint32()
        ok = _advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW(
            sd, _SDDL_REVISION_1, _DACL_SECURITY_INFORMATION, ctypes.byref(text), ctypes.byref(size))
        if not ok or not text.value:
            return None
        return text.value
    except (OSError, ValueError) as exc:  # ctypes/biblioteca do sistema
        log.debug("Falha ao ler a DACL de %s: %s", path, exc)
        return None
    finally:
        # Ambos os buffers são alocados com LocalAlloc pelo Windows.
        if text.value:
            _kernel32.LocalFree(text)
        if sd.value:
            _kernel32.LocalFree(sd)


def _current_user_sid() -> str | None:
    """SID do usuário atual, ou ``None`` se não for possível consultar."""
    if not IS_WINDOWS:
        return None
    token = ctypes.c_void_p()
    try:
        if not _advapi32.OpenProcessToken(_kernel32.GetCurrentProcess(), _TOKEN_QUERY, ctypes.byref(token)):
            return None
        size = ctypes.c_uint32(0)
        _advapi32.GetTokenInformation(token, _TOKEN_USER, None, 0, ctypes.byref(size))
        if ctypes.get_last_error() != _ERROR_INSUFFICIENT_BUFFER or not size.value:
            return None
        buf = ctypes.create_string_buffer(size.value)

        class _SID_AND_ATTRIBUTES(ctypes.Structure):
            _fields_ = [("Sid", ctypes.c_void_p), ("Attributes", ctypes.c_uint32)]

        class _TOKEN_USER_STRUCT(ctypes.Structure):
            _fields_ = [("User", _SID_AND_ATTRIBUTES)]

        if not _advapi32.GetTokenInformation(token, _TOKEN_USER, buf, size, ctypes.byref(size)):
            return None
        user = ctypes.cast(buf, ctypes.POINTER(_TOKEN_USER_STRUCT)).contents
        text = ctypes.c_wchar_p()
        if not _advapi32.ConvertSidToStringSidW(user.User.Sid, ctypes.byref(text)):
            return None
        try:
            return text.value
        finally:
            if text.value:
                _kernel32.LocalFree(text)
    except (OSError, ValueError) as exc:
        log.debug("Falha ao obter o SID do usuário atual: %s", exc)
        return None
    finally:
        if token.value:
            _kernel32.CloseHandle(token)


def _dacl_is_private(sddl: str, user_sid: str | None) -> bool:
    """DACL protegida (sem herança) e com Allow somente para o usuário/SYSTEM/Admins."""
    if not sddl or not sddl.startswith("D:P"):
        return False
    allowed = set(_PRIVATE_SID_ALIASES)
    if user_sid:
        allowed.add(user_sid)
    for body in _ACE_RE.findall(sddl):
        parts = body.split(";")
        if len(parts) < 5:
            return False
        sid = parts[-1].strip()
        if sid and sid not in allowed:
            return False
    return True


def verify_private_file(path) -> bool:
    """True se o arquivo só é acessível pelo usuário atual, SYSTEM e Administradores."""
    if not IS_WINDOWS:
        try:
            return (stat.S_IMODE(os.stat(path).st_mode) & 0o077) == 0
        except OSError:
            return False
    return _dacl_is_private(_read_dacl_sddl(path) or "", _current_user_sid())


def secure_private_file(path) -> bool:
    """Aplica uma DACL restritiva (usuário atual/SYSTEM/Admins) e verifica o resultado.

    No Windows retorna ``False`` quando a ACL não pôde ser aplicada/verificada; o
    chamador deve tratar isso como falha de segurança (fail-secure).
    """
    if not IS_WINDOWS:
        try:
            os.chmod(path, 0o600)
            return verify_private_file(path)
        except OSError as exc:
            log.debug("Falha ao aplicar modo 0600 em %s: %s", path, exc)
            return False
    user_sid = _current_user_sid()
    if not user_sid:
        log.warning("Não foi possível obter o SID do usuário para restringir %s.", path)
        return False
    sddl = f"D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;{user_sid})"
    sd = ctypes.c_void_p()
    try:
        if not _advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl, _SDDL_REVISION_1, ctypes.byref(sd), None):
            log.warning("Não foi possível montar a DACL restritiva para %s.", path)
            return False
        if not _advapi32.SetFileSecurityW(str(path), _DACL_SECURITY_INFORMATION, sd):
            log.warning("Não foi possível aplicar a DACL restritiva em %s: %s",
                        path, ctypes.WinError(ctypes.get_last_error()))
            return False
    except (OSError, ValueError) as exc:
        log.warning("Falha ao aplicar a DACL restritiva em %s: %s", path, exc)
        return False
    finally:
        if sd.value:
            _kernel32.LocalFree(sd)
    return verify_private_file(path)


def capture_acl(path) -> str | None:
    """Retorna a DACL do arquivo em SDDL ou ``None`` se não for possível."""
    return _read_dacl_sddl(path)


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
