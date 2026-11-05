"""Quarentena segura de arquivos.

Garantias principais:

- O conteúdo é cifrado com AES-256-GCM (autenticado) e a chave nunca é gravada
  em texto puro no banco: no Windows ela é protegida com DPAPI; fora dele (ou se
  o DPAPI falhar) usa-se *key wrapping* AES-GCM com uma chave mestra local.
- O registro é criado ANTES da cópia (write-ahead). O original só é removido
  depois de a cópia ser gravada, sincronizada e verificada por descriptografia +
  SHA-256.
- Quedas de energia/interrupções são reconciliadas por :meth:`Quarantine.recover`
  na inicialização: cópias incompletas são descartadas e o original permanece;
  cópias válidas cujo original sumiu são promovidas a ``quarantined``.
- Metadados (timestamps, atributos, permissões POSIX) e, no Windows, a DACL
  original (SDDL) são preservados quando tecnicamente possível.
- Toda operação (sucesso ou falha) é registrada na tabela ``actions``.
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import sqlite3
import stat
import uuid
from pathlib import Path

from . import config
from .logger import get_logger
from .quarantine_crypto import (CHUNK as CRYPTO_CHUNK, CryptoError, IntegrityError, decrypt_stream,
                                encrypt_stream, legacy_xor, unwrap_key, verify_stream, wrap_key)
from .safety import (UnsafePathError, is_dangerous_target, is_protected, is_reparse_point, is_within,
                     validate_target)
from .win_security import apply_attributes, apply_mode, capture_acl, restore_acl

log = get_logger(__name__)

LEGACY_CHUNK = 64 * 1024  # tamanho usado pela implementação antiga (múltiplo de 32)
KEY_LEN = 32
RECOVERABLE = ("pending", "ready")


class QuarantineError(Exception):
    """Operação de quarentena recusada ou que falhou de forma segura."""


def _sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        while chunk := fh.read(CRYPTO_CHUNK):
            digest.update(chunk)
    return digest.hexdigest()


def _remove_source(src: Path, meta: dict) -> None:
    """Remove o original, tratando o atributo somente-leitura do Windows.

    O bit de leitura é limpo apenas DEPOIS de a cópia cifrada ter sido verificada
    (o chamador garante isso). Se a remoção ainda falhar, os atributos originais
    são reaplicados para não deixar o arquivo alterado.
    """
    try:
        os.remove(src)
        return
    except PermissionError:
        if os.name != "nt":
            raise
    try:
        os.chmod(src, stat.S_IWRITE | stat.S_IREAD)
    except OSError:
        raise
    try:
        os.remove(src)
    except OSError:
        apply_attributes(src, meta.get("attributes"))
        raise


def _reparse_in_existing_ancestors(path) -> bool:
    """True se o próprio caminho ou um ancestral existente for link/junction."""
    cur = Path(path)
    while True:
        if cur.exists() and is_reparse_point(cur):
            return True
        if cur.parent == cur:
            return False
        cur = cur.parent


class Quarantine:
    def __init__(self, db, directory: Path | None = None):
        self.db = db
        self.dir = Path(directory or config.QUARANTINE_DIR)
        self.dir.mkdir(parents=True, exist_ok=True)
        if is_reparse_point(self.dir):
            raise QuarantineError("O diretório de quarentena não pode ser um link/junction.")
        try:
            self.recover()
        except Exception:  # recuperação nunca deve impedir o programa de abrir
            log.exception("Falha ao reconciliar operações de quarentena pendentes")

    # ------------------------------------------------------------------ utilidades
    def _meta(self, rec: dict) -> dict:
        try:
            meta = json.loads(rec.get("meta_json") or "{}")
            return meta if isinstance(meta, dict) else {}
        except (TypeError, ValueError) as exc:
            raise QuarantineError(f"Metadados da quarentena inválidos para {rec.get('id')}: {exc}") from exc

    def _stored_path(self, rec: dict) -> Path:
        name = rec.get("stored_name") or f"{rec.get('id')}.qz"
        if Path(name).name != name or not name.endswith(".qz"):
            raise QuarantineError("Nome de arquivo de quarentena inválido no banco.")
        root = self.dir.resolve()
        path = (self.dir / name).resolve()
        if os.path.normcase(str(path.parent)) != os.path.normcase(str(root)):
            raise QuarantineError("Tentativa de acesso fora do diretório de quarentena recusada.")
        return path

    @staticmethod
    def _key_from_meta(meta: dict, qid: str) -> bytes:
        token = meta.get("wrapped_key")
        if not token:
            raise QuarantineError("Registro sem chave protegida; item não pode ser restaurado.")
        return unwrap_key(token, qid)

    def _apply_metadata(self, path: Path, meta: dict) -> None:
        try:
            atime = int(meta.get("atime_ns", 0))
            mtime = int(meta.get("mtime_ns", 0))
            if atime and mtime:
                os.utime(path, ns=(atime, mtime))
        except (OSError, TypeError, ValueError) as exc:
            log.warning("Não foi possível restaurar timestamps de %s: %s", path, exc)
        if not apply_mode(path, meta.get("mode")):
            apply_attributes(path, meta.get("attributes"))

    # ------------------------------------------------------------------ recuperação
    def recover(self) -> list[str]:
        """Reconcilia registros ``pending``/``ready`` e migra itens legados (XOR).

        Retorna os IDs cujo estado foi alterado. Nunca remove o original.
        """
        changed: list[str] = []
        for rec in self.db.list_quarantine(status=None):
            try:
                meta = self._meta(rec)
            except QuarantineError as exc:
                log.error("Registro de quarentena corrompido (%s): %s", rec.get("id"), exc)
                continue

            if "key" in meta and "wrapped_key" not in meta:
                try:
                    if self._migrate_legacy(rec, meta):
                        changed.append(rec["id"])
                except (QuarantineError, CryptoError, OSError) as exc:
                    log.error("Falha ao migrar item legado %s (mantido para inspeção): %s", rec["id"], exc)
                continue

            if rec.get("status") not in RECOVERABLE:
                continue
            try:
                if self._recover_record(rec, meta):
                    changed.append(rec["id"])
            except (QuarantineError, CryptoError, OSError) as exc:
                log.error("Falha ao recuperar item %s: %s", rec["id"], exc)
                self.db.update_quarantine(rec["id"], status="failed")
                self.db.log_action("quarantine_recover", rec.get("original_path", ""),
                                   f"id={rec['id']}: {exc}", False)
        return changed

    def _recover_record(self, rec: dict, meta: dict) -> bool:
        qid = rec["id"]
        stored = self._stored_path(rec)
        part = stored.with_name(stored.name + ".part")
        original = Path(rec.get("original_path") or "")
        expected = rec.get("sha256") or meta.get("sha256") or ""

        if not stored.exists():
            part.unlink(missing_ok=True)
            if original.exists():
                self.db.update_quarantine(qid, status="failed")
                self.db.log_action("quarantine_recover", str(original),
                                   f"id={qid}: cópia ausente; original intacto", True)
                return True
            self.db.update_quarantine(qid, status="failed")
            self.db.log_action("quarantine_recover", str(original),
                               f"id={qid}: cópia e original ausentes", False)
            return True

        key = self._key_from_meta(meta, qid)
        digest, size = verify_stream(stored, key, qid, expected or None)

        # Se o original ainda existe e é idêntico, a operação não chegou a concluir:
        # desfazemos a cópia para voltar ao estado inicial (sem perda de dados).
        if original.is_file():
            try:
                original_sha = _sha256_path(original)
            except OSError:
                original_sha = ""
            if not expected or original_sha == expected:
                part.unlink(missing_ok=True)
                stored.unlink(missing_ok=True)
                self.db.update_quarantine(qid, status="failed")
                self.db.log_action("quarantine_recover", str(original),
                                   f"id={qid}: operação interrompida; cópia descartada, original preservado", True)
                return True

        part.unlink(missing_ok=True)
        meta["sha256"] = digest
        meta["size"] = size
        self.db.update_quarantine(qid, status="quarantined", sha256=digest, size=size, meta=meta)
        self.db.log_action("quarantine_recover", str(original),
                           f"id={qid}: cópia válida promovida a quarentena", True)
        return True

    def _migrate_legacy(self, rec: dict, meta: dict) -> bool:
        """Re-cifra um item do formato antigo (XOR/chave no banco) para AES-GCM."""
        qid = rec["id"]
        stored = self._stored_path(rec)
        if not stored.exists():
            return False
        legacy_key = bytes.fromhex(str(meta.get("key", "")))
        plain_tmp = stored.with_name(stored.name + ".legacy.plain")
        new_tmp = stored.with_name(stored.name + ".legacy.new")
        try:
            digest = hashlib.sha256()
            size = 0
            with open(stored, "rb") as fin, open(plain_tmp, "wb") as fout:
                while chunk := fin.read(LEGACY_CHUNK):
                    plain = legacy_xor(chunk, legacy_key)
                    digest.update(plain)
                    size += len(plain)
                    fout.write(plain)
                fout.flush()
                os.fsync(fout.fileno())
            if rec.get("sha256") and digest.hexdigest() != rec["sha256"]:
                raise QuarantineError("Hash do item legado não confere; migração abortada.")
            new_key = secrets.token_bytes(KEY_LEN)
            wrapped = wrap_key(new_key, qid)
            new_digest, new_size = encrypt_stream(plain_tmp, new_tmp, new_key, qid)
            if new_digest != digest.hexdigest() or new_size != size:
                raise QuarantineError("Falha ao re-cifrar o item legado.")
            verify_stream(new_tmp, new_key, qid, new_digest)
            os.replace(new_tmp, stored)
            meta.pop("key", None)
            meta.update({"wrapped_key": wrapped, "key_protection": wrapped.split(":", 1)[0],
                         "version": 2, "sha256": new_digest})
            self.db.update_quarantine(qid, meta=meta, sha256=new_digest, size=new_size)
            self.db.log_action("quarantine_migrate_legacy", rec.get("original_path", ""),
                               f"id={qid}: XOR -> AES-256-GCM", True)
            log.info("Item legado %s migrado para AES-GCM", qid)
            return True
        finally:
            plain_tmp.unlink(missing_ok=True)
            new_tmp.unlink(missing_ok=True)

    # ------------------------------------------------------------------ quarentena
    def quarantine_file(self, path, evidences: list[dict] | None = None, allowed_roots: list | None = None,
                        confirmed: bool = False) -> str:
        """Move ``path`` para a quarentena com segurança e retorna o ID.

        Recusa caminhos protegidos do Windows (arquivos de sistema suspeitos devem
        ser tratados com sfc/DISM/Defender, não removidos à força).
        """
        src = Path(path)
        roots = allowed_roots or [src.anchor or "/"]
        try:
            src = validate_target(src, roots, allow_protected=False, allow_sensitive=confirmed)
            st = src.stat()
        except (UnsafePathError, OSError) as exc:
            self.db.log_action("quarantine_refused", str(path), str(exc), False)
            raise QuarantineError(str(exc)) from exc

        qid = uuid.uuid4().hex
        key = secrets.token_bytes(KEY_LEN)
        stored_name = f"{qid}.qz"
        final = self.dir / stored_name
        part = final.with_name(final.name + ".part")
        acl = capture_acl(src)
        meta = {
            "version": 2,
            "mtime_ns": st.st_mtime_ns,
            "atime_ns": st.st_atime_ns,
            "attributes": int(getattr(st, "st_file_attributes", 0)),
            "mode": st.st_mode,
            "acl": acl,
            "wrapped_key": wrap_key(key, qid),
        }
        meta["key_protection"] = meta["wrapped_key"].split(":", 1)[0]
        original_removed = False
        try:
            # Write-ahead: o registro existe antes de qualquer cópia.
            self.db.add_quarantine({"id": qid, "original_path": str(src), "stored_name": stored_name,
                                    "sha256": "", "size": st.st_size, "evidence": evidences or [], "meta": meta},
                                   status="pending")
            digest, size = encrypt_stream(src, part, key, qid)
            if size != st.st_size:
                raise QuarantineError("Tamanho lido difere do tamanho do arquivo; operação abortada.")
            meta["sha256"] = digest
            meta["size"] = size
            self.db.update_quarantine(qid, sha256=digest, size=size, meta=meta)

            # Verifica autenticidade e hash da cópia antes de tocar no original.
            verified, verified_size = verify_stream(part, key, qid, digest)
            if verified != digest or verified_size != size:
                raise QuarantineError("Verificação da cópia em quarentena falhou; original preservado.")

            st2 = src.stat()
            if st2.st_size != st.st_size or st2.st_mtime_ns != st.st_mtime_ns:
                raise QuarantineError("O arquivo mudou durante a quarentena; operação abortada.")

            os.replace(part, final)
            self.db.update_quarantine(qid, status="ready")

            try:
                _remove_source(src, meta)
            except OSError as exc:
                final.unlink(missing_ok=True)
                self.db.update_quarantine(qid, status="failed")
                self.db.log_action("quarantine_failed", str(src),
                                   f"id={qid}: original não removido: {exc}", False)
                raise QuarantineError(f"Arquivo em uso ou protegido; nada foi alterado: {exc}") from exc
            original_removed = True

            self.db.update_quarantine(qid, status="quarantined")
            self.db.log_action("quarantine", str(src), f"id={qid} sha256={digest} aes-gcm", True)
            log.info("Quarentena: %s -> %s", src, qid)
            return qid
        except QuarantineError:
            self._rollback_failed(qid, src, final, part, original_removed)
            raise
        except (CryptoError, OSError, sqlite3.Error) as exc:
            self._rollback_failed(qid, src, final, part, original_removed)
            raise QuarantineError(f"Falha ao colocar o arquivo em quarentena: {exc}") from exc

    def _rollback_failed(self, qid: str, src: Path, final: Path, part: Path,
                         original_removed: bool) -> None:
        if original_removed:
            # O original já foi removido: a cópia é a única fonte de verdade.
            # Mantemos o registro em "ready" para a rotina de recuperação promover.
            log.error("Quarentena %s concluída, mas o estado no banco não pôde ser confirmado; "
                      "a recuperação na próxima inicialização corrigirá.", qid)
            return
        try:
            final.unlink(missing_ok=True)
            part.unlink(missing_ok=True)
        except OSError as exc:
            log.warning("Falha ao limpar restos da quarentena %s: %s", qid, exc)
        try:
            self.db.update_quarantine(qid, status="failed")
        except Exception:  # o erro original é mais importante
            log.exception("Não foi possível marcar a quarentena %s como falha", qid)
        self.db.log_action("quarantine_failed", str(src), f"id={qid}", False)

    # ------------------------------------------------------------------ restauração
    def restore(self, qid: str, destination=None, overwrite: bool = False,
                allowed_roots: list | None = None) -> Path:
        """Restaura um item, verificando autenticidade e SHA-256 antes de gravar o destino."""
        rec = self.db.get_quarantine(qid)
        if not rec or rec.get("status") != "quarantined":
            raise QuarantineError("Item inexistente ou já processado.")
        meta = self._meta(rec)

        if "wrapped_key" not in meta:
            if "key" in meta:  # item antigo ainda não migrado
                if not self._migrate_legacy(rec, meta):
                    raise QuarantineError("Item legado não pôde ser migrado para restauração.")
                rec = self.db.get_quarantine(qid)
                meta = self._meta(rec)
            else:
                raise QuarantineError("Registro sem chave protegida; restauração recusada.")

        dest = Path(destination or rec["original_path"])
        if is_dangerous_target(dest) or is_protected(dest):
            raise QuarantineError("Destino protegido do Windows; restauração recusada.")
        if allowed_roots and not any(is_within(dest, r) for r in allowed_roots):
            raise QuarantineError("Destino fora dos diretórios autorizados.")
        if _reparse_in_existing_ancestors(dest.parent):
            raise QuarantineError("Diretório de destino é link/junction.")
        if dest.exists() and not overwrite:
            raise QuarantineError(f"O destino já existe: {dest}")

        stored = self._stored_path(rec)
        if not stored.exists():
            raise QuarantineError("Arquivo de quarentena ausente.")

        dest.parent.mkdir(parents=True, exist_ok=True)
        if is_reparse_point(dest.parent):
            raise QuarantineError("Diretório de destino é link/junction.")

        key = self._key_from_meta(meta, qid)
        expected = rec.get("sha256") or meta.get("sha256") or ""
        tmp = dest.with_name(f".{dest.name}.restoring.{uuid.uuid4().hex[:8]}")
        try:
            digest, size = decrypt_stream(stored, tmp, key, qid, expected or None)
            expected_size = rec.get("size") or meta.get("size")
            if expected_size is not None and int(expected_size) != size:
                raise QuarantineError("Tamanho restaurado difere do registrado.")
            self._apply_metadata(tmp, meta)
            if dest.exists() and not overwrite:
                raise QuarantineError(f"O destino já existe: {dest}")
            if dest.exists():
                try:  # Windows: destino somente-leitura impede a substituição atômica
                    os.chmod(dest, 0o600)
                except OSError:
                    pass
            os.replace(tmp, dest)
            if not restore_acl(dest, meta.get("acl")):
                log.debug("ACL não restaurada para %s (sem privilégio ou plataforma não Windows).", dest)
            clean_meta = {k: v for k, v in meta.items() if k != "wrapped_key"}
            self.db.update_quarantine(qid, status="restored", meta=clean_meta)
            stored.unlink(missing_ok=True)
            self.db.log_action("restore", str(dest), f"id={qid} sha256={digest}", True)
            log.info("Restaurado: %s -> %s", qid, dest)
            return dest
        except (QuarantineError, CryptoError, OSError) as exc:
            tmp.unlink(missing_ok=True)
            self.db.log_action("restore_failed", str(dest), f"id={qid}: {exc}", False)
            if isinstance(exc, QuarantineError):
                raise
            raise QuarantineError(f"Falha ao restaurar o item: {exc}") from exc

    # ------------------------------------------------------------------ exclusão
    def delete_permanently(self, qid: str, confirmed: bool) -> None:
        if not confirmed:
            raise QuarantineError("Remoção definitiva exige confirmação explícita.")
        rec = self.db.get_quarantine(qid)
        if not rec or rec.get("status") != "quarantined":
            raise QuarantineError("Item inexistente ou já processado.")
        stored = self._stored_path(rec)
        try:
            stored.unlink(missing_ok=True)
        except OSError as exc:
            self.db.log_action("quarantine_delete", rec.get("original_path", ""),
                               f"id={qid}: {exc}", False)
            raise QuarantineError(f"Não foi possível apagar o item: {exc}") from exc
        try:
            meta = self._meta(rec)
        except QuarantineError:
            meta = {}
        meta.pop("wrapped_key", None)  # remove o material de chave do banco
        self.db.update_quarantine(qid, status="deleted", meta=meta)
        self.db.log_action("quarantine_delete", rec.get("original_path", ""), f"id={qid}", True)
        log.info("Item de quarentena removido definitivamente: %s", qid)

    def list_items(self):
        return self.db.list_quarantine()
