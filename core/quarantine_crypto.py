"""Criptografia autenticada e proteção de chaves da quarentena.

Formato de um arquivo ``.qz`` (versão 1)::

    MAGIC (5 bytes) | nonce (12 bytes) | ciphertext | tag GCM (16 bytes)

- Algoritmo: AES-256-GCM (biblioteca ``cryptography``, audited/confiável).
- Cada item usa uma chave aleatória de 32 bytes; a chave NUNCA é gravada em texto
  puro no SQLite.
- No Windows a chave é embrulhada com DPAPI (escopo do usuário atual). Em outros
  sistemas (ou se o DPAPI falhar) é usado um *key wrapping* AES-GCM com uma chave
  mestra local de 32 bytes, criada com permissões restritas.
- O ``item_id`` (UUID da quarentena) entra como AAD (*additional authenticated
  data*), ligando o conteúdo ao registro do banco: trocar o arquivo de lugar ou
  reaproveitar o registro de outro item faz a autenticação falhar.
"""
from __future__ import annotations

import base64
import ctypes
import hashlib
import os
import secrets
import stat
import sys
from pathlib import Path
from typing import Callable

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import config
from .logger import get_logger

log = get_logger(__name__)

IS_WINDOWS = sys.platform == "win32"

MAGIC = b"SNTQ\x01"
NONCE_LEN = 12
TAG_LEN = 16
KEY_LEN = 32
CHUNK = 1024 * 1024  # 1 MiB
_DPAPI_PREFIX = "dpapi:"
_MASTER_PREFIX = "mk1:"
_CRYPTPROTECT_UI_FORBIDDEN = 0x1


class CryptoError(Exception):
    """Falha criptográfica, de integridade ou de proteção de chave."""


class IntegrityError(CryptoError):
    """O hash/tag do conteúdo não corresponde ao esperado."""


def _aad(item_id: str) -> bytes:
    return b"sentinel-quarantine:" + item_id.encode("utf-8")


def _key_aad(item_id: str) -> bytes:
    return _aad(item_id) + b":key"


# ---------------------------------------------------------------------------
# AES-256-GCM em streaming
# ---------------------------------------------------------------------------
def encrypt_stream(src, dst, key: bytes, item_id: str) -> tuple[str, int]:
    """Criptografa ``src`` para ``dst`` e retorna ``(sha256_do_texto_claro, tamanho)``.

    O arquivo de destino é sincronizado em disco (``fsync``) antes do retorno.
    """
    if len(key) != KEY_LEN:
        raise CryptoError("Tamanho de chave inválido para AES-256.")
    nonce = secrets.token_bytes(NONCE_LEN)
    encryptor = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()
    encryptor.authenticate_additional_data(_aad(item_id))
    digest = hashlib.sha256()
    size = 0
    try:
        with open(src, "rb") as fin, open(dst, "wb") as fout:
            fout.write(MAGIC)
            fout.write(nonce)
            while chunk := fin.read(CHUNK):
                digest.update(chunk)
                size += len(chunk)
                fout.write(encryptor.update(chunk))
            fout.write(encryptor.finalize())
            fout.write(encryptor.tag)
            fout.flush()
            os.fsync(fout.fileno())
    except OSError as exc:
        raise CryptoError(f"Falha ao criptografar o arquivo: {exc}") from exc
    return digest.hexdigest(), size


def _decrypt_stream(src, key: bytes, item_id: str, sink: Callable[[bytes], None],
                    expected_sha: str | None = None) -> tuple[str, int]:
    if len(key) != KEY_LEN:
        raise CryptoError("Tamanho de chave inválido para AES-256.")
    digest = hashlib.sha256()
    size = 0
    try:
        with open(src, "rb") as fin:
            header = fin.read(len(MAGIC) + NONCE_LEN)
            if len(header) != len(MAGIC) + NONCE_LEN or not header.startswith(MAGIC):
                raise CryptoError("Arquivo de quarentena com cabeçalho inválido ou desconhecido.")
            nonce = header[-NONCE_LEN:]
            decryptor = Cipher(algorithms.AES(key), modes.GCM(nonce)).decryptor()
            decryptor.authenticate_additional_data(_aad(item_id))
            pending = b""
            while chunk := fin.read(CHUNK):
                data = pending + chunk
                if len(data) <= TAG_LEN:
                    pending = data
                    continue
                body, pending = data[:-TAG_LEN], data[-TAG_LEN:]
                plain = decryptor.update(body)
                digest.update(plain)
                size += len(plain)
                sink(plain)
            if len(pending) != TAG_LEN:
                raise IntegrityError("Arquivo de quarentena truncado (tag GCM ausente).")
            plain = decryptor.finalize_with_tag(pending)
            digest.update(plain)
            size += len(plain)
            sink(plain)
    except InvalidTag as exc:
        raise IntegrityError("Autenticação AES-GCM falhou: o conteúdo foi alterado ou a chave é inválida.") from exc
    except OSError as exc:
        raise CryptoError(f"Falha ao ler o arquivo de quarentena: {exc}") from exc
    result = digest.hexdigest()
    if expected_sha and result != expected_sha:
        raise IntegrityError("Hash SHA-256 do conteúdo restaurado difere do registrado.")
    return result, size


def decrypt_stream(src, dst, key: bytes, item_id: str,
                   expected_sha: str | None = None) -> tuple[str, int]:
    """Desautentica/descriptografa ``src`` para ``dst``, verificando o hash.

    O destino é sincronizado em disco. Se qualquer verificação falhar, uma
    ``CryptoError`` é levantada e o chamador deve descartar ``dst``.
    """
    try:
        with open(dst, "wb") as fout:
            result = _decrypt_stream(src, key, item_id, fout.write, expected_sha)
            fout.flush()
            os.fsync(fout.fileno())
            return result
    except OSError as exc:
        raise CryptoError(f"Falha ao escrever o arquivo restaurado: {exc}") from exc


def verify_stream(src, key: bytes, item_id: str,
                  expected_sha: str | None = None) -> tuple[str, int]:
    """Verifica autenticidade e integridade sem gravar o conteúdo em disco."""
    return _decrypt_stream(src, key, item_id, lambda _chunk: None, expected_sha)


# ---------------------------------------------------------------------------
# DPAPI (Windows)
# ---------------------------------------------------------------------------
class _DATA_BLOB(ctypes.Structure):
    _fields_ = [("cbData", ctypes.c_uint32), ("pbData", ctypes.POINTER(ctypes.c_ubyte))]


def _blob(data: bytes) -> tuple[_DATA_BLOB, ctypes.Array]:
    buf = (ctypes.c_ubyte * len(data)).from_buffer_copy(data)
    return _DATA_BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_ubyte))), buf


def _dpapi_call(protect: bool, data: bytes, entropy: bytes) -> bytes:
    if not IS_WINDOWS:
        raise CryptoError("DPAPI só está disponível no Windows.")
    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    in_blob, _in_buf = _blob(data)
    entropy_blob, _entropy_buf = _blob(entropy)
    out = _DATA_BLOB()
    if protect:
        fn = crypt32.CryptProtectData
        fn.argtypes = [ctypes.POINTER(_DATA_BLOB), ctypes.c_wchar_p, ctypes.POINTER(_DATA_BLOB),
                       ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32, ctypes.POINTER(_DATA_BLOB)]
        ok = fn(ctypes.byref(in_blob), "Sentinel Scanner quarantine key", ctypes.byref(entropy_blob),
                None, None, _CRYPTPROTECT_UI_FORBIDDEN, ctypes.byref(out))
    else:
        fn = crypt32.CryptUnprotectData
        fn.argtypes = [ctypes.POINTER(_DATA_BLOB), ctypes.c_void_p, ctypes.POINTER(_DATA_BLOB),
                       ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32, ctypes.POINTER(_DATA_BLOB)]
        ok = fn(ctypes.byref(in_blob), None, ctypes.byref(entropy_blob),
                None, None, _CRYPTPROTECT_UI_FORBIDDEN, ctypes.byref(out))
    if not ok:
        raise CryptoError(f"DPAPI falhou: {ctypes.WinError(ctypes.get_last_error())}")
    try:
        return ctypes.string_at(out.pbData, out.cbData)
    finally:
        kernel32.LocalFree(out.pbData)


# ---------------------------------------------------------------------------
# Chave mestra local (fallback fora do Windows / se DPAPI falhar)
# ---------------------------------------------------------------------------
def _master_key_path() -> Path:
    return Path(config.DATA_DIR) / "keys" / "master.key"


def _load_master_key() -> bytes:
    path = _master_key_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        data = path.read_bytes()
        if len(data) != KEY_LEN:
            raise CryptoError(f"Chave mestra corrompida: {path}")
        return data
    key = secrets.token_bytes(KEY_LEN)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    # 0o600 é aplicado em POSIX; no Windows a ACL do perfil do usuário já restringe.
    fd = os.open(path, flags, stat.S_IRUSR | stat.S_IWUSR)
    try:
        os.write(fd, key)
        os.fsync(fd)
    finally:
        os.close(fd)
    return key


def _master_wrap(key: bytes, aad: bytes) -> str:
    nonce = secrets.token_bytes(12)
    blob = AESGCM(_load_master_key()).encrypt(nonce, key, aad)
    return _MASTER_PREFIX + base64.b64encode(nonce + blob).decode("ascii")


def _master_unwrap(token: str, aad: bytes) -> bytes:
    raw = base64.b64decode(token[len(_MASTER_PREFIX):], validate=True)
    if len(raw) < 12 + 16:
        raise CryptoError("Chave protegida inválida (truncada).")
    try:
        return AESGCM(_load_master_key()).decrypt(raw[:12], raw[12:], aad)
    except InvalidTag as exc:
        raise CryptoError("Não foi possível desembrulhar a chave (chave mestra incorreta).") from exc


def wrap_key(key: bytes, item_id: str) -> str:
    """Embrulha a chave do item. Prefere DPAPI no Windows; nunca retorna texto puro."""
    if len(key) != KEY_LEN:
        raise CryptoError("Tamanho de chave inválido.")
    aad = _key_aad(item_id)
    if IS_WINDOWS:
        try:
            blob = _dpapi_call(True, key, aad)
            return _DPAPI_PREFIX + base64.b64encode(blob).decode("ascii")
        except (CryptoError, OSError) as exc:
            log.warning("DPAPI indisponível (%s); usando chave mestra local como fallback.", exc)
    return _master_wrap(key, aad)


def unwrap_key(token: str, item_id: str) -> bytes:
    """Recupera a chave do item a partir do token protegido."""
    if not isinstance(token, str):
        raise CryptoError("Token de chave inválido.")
    aad = _key_aad(item_id)
    if token.startswith(_DPAPI_PREFIX):
        try:
            raw = base64.b64decode(token[len(_DPAPI_PREFIX):], validate=True)
            key = _dpapi_call(False, raw, aad)
        except (CryptoError, OSError) as exc:
            raise CryptoError(f"Não foi possível desproteger a chave com DPAPI: {exc}") from exc
    elif token.startswith(_MASTER_PREFIX):
        key = _master_unwrap(token, aad)
    else:
        raise CryptoError("Formato de chave protegida desconhecido.")
    if len(key) != KEY_LEN:
        raise CryptoError("Chave recuperada com tamanho inválido.")
    return key


# ---------------------------------------------------------------------------
# Migração de itens legados (XOR + chave em texto puro no banco)
# ---------------------------------------------------------------------------
def legacy_xor(data: bytes, key: bytes) -> bytes:
    """Descriptografia de compatibilidade do formato antigo (somente leitura).

    A implementação antiga processava o arquivo em blocos de 64 KiB; como 64 KiB é
    múltiplo de 32, o keystream se mantém alinhado. Nunca use isto para gravar.
    """
    if not key:
        raise CryptoError("Chave legada ausente.")
    keystream = (key * (len(data) // len(key) + 1))[: len(data)]
    return (int.from_bytes(data, "big") ^ int.from_bytes(keystream, "big")).to_bytes(len(data), "big")
