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
from .win_security import apply_attributes, apply_mode, capture_acl, restore_acl, secure_private_file

log = get_logger(__name__)

LEGACY_CHUNK = 64 * 1024  # tamanho usado pela implementação antiga (múltiplo de 32)
KEY_LEN = 32
RECOVERABLE = ("pending", "ready")
RESTORE_TMP_PREFIX = ".sentinel-restore-"
RESTORE_BACKUP_PREFIX = ".sentinel-restore-backup-"


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


def _strip_restore(meta: dict) -> dict:
    """Remove o journal transitório de restauração dos metadados persistidos."""
    return {k: v for k, v in meta.items() if k != "restore"}


def _valid_restore_artifact(path, dest: Path, prefix: str) -> bool:
    """Valida nomes/limites de temporários para não apagar arquivos arbitrários.

    O nome é gerado exclusivamente por nós e o arquivo precisa estar no mesmo
    diretório do destino, ser regular e não ser link/junction.
    """
    p = Path(path)
    try:
        return (p.name.startswith(prefix) and p.suffix == ".tmp"
                and os.path.normcase(str(p.parent)) == os.path.normcase(str(Path(dest).parent))
                and p.is_file() and not is_reparse_point(p))
    except OSError:
        return False


def _create_private_temp(dest: Path, qid: str) -> Path:
    """Cria um temporário de restauração com permissões restritivas.

    O arquivo contém dados em texto claro; se a ACL/modo não puder ser aplicado,
    a restauração é abortada (fail-secure) em vez de expor o conteúdo.
    """
    tmp = dest.with_name(f"{RESTORE_TMP_PREFIX}{qid}-{uuid.uuid4().hex[:8]}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    fd = os.open(tmp, flags, stat.S_IRUSR | stat.S_IWUSR)
    os.close(fd)
    if not secure_private_file(tmp):
        tmp.unlink(missing_ok=True)
        raise QuarantineError(
            "Não foi possível proteger o arquivo temporário de restauração; operação abortada.")
    return tmp


def _unlink_quietly(path: Path) -> None:
    try:
        Path(path).unlink(missing_ok=True)
    except OSError as exc:
        log.warning("Não foi possível remover resíduo %s: %s", path, exc)


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

            status = rec.get("status")
            try:
                if status == "restoring":
                    if self._recover_restore(rec, meta):
                        changed.append(rec["id"])
                    continue
                if status == "deleting":
                    if self._recover_delete(rec, meta):
                        changed.append(rec["id"])
                    continue
                if status == "quarantined":
                    if self._recover_quarantined(rec):
                        changed.append(rec["id"])
                    continue
                if status not in RECOVERABLE:
                    continue
                if self._recover_record(rec, meta):
                    changed.append(rec["id"])
            except (QuarantineError, CryptoError, OSError) as exc:
                log.error("Falha ao recuperar item %s: %s", rec["id"], exc)
                try:
                    self.db.update_quarantine(rec["id"], status="failed")
                    self.db.log_action("quarantine_recover", rec.get("original_path", ""),
                                       f"id={rec['id']}: {exc}", False)
                except sqlite3.Error:
                    log.exception("Banco indisponível ao registrar falha de recuperação de %s", rec["id"])
        return changed

    def _recover_quarantined(self, rec: dict) -> bool:
        """Item estável cuja cópia cifrada desapareceu: sinaliza em vez de mascarar."""
        qid = rec["id"]
        stored = self._stored_path(rec)
        if stored.exists():
            return False
        self.db.update_quarantine(qid, status="failed")
        self.db.log_action("quarantine_recover", rec.get("original_path", ""),
                           f"id={qid}: cópia de quarentena ausente", False)
        log.error("Cópia de quarentena ausente para o item %s", qid)
        return True

    def _recover_delete(self, rec: dict, meta: dict) -> bool:
        """Conclui/desfaz uma exclusão definitiva interrompida."""
        qid = rec["id"]
        stored = self._stored_path(rec)
        if stored.exists():
            self.db.update_quarantine(qid, status="quarantined", meta=_strip_restore(meta))
            self.db.log_action("quarantine_recover", rec.get("original_path", ""),
                               f"id={qid}: exclusão interrompida; item mantido", True)
            return True
        clean = _strip_restore(meta)
        clean.pop("wrapped_key", None)
        self.db.update_quarantine(qid, status="deleted", meta=clean)
        self.db.log_action("quarantine_recover", rec.get("original_path", ""),
                           f"id={qid}: exclusão definitiva concluída", True)
        return True

    def _recover_restore(self, rec: dict, meta: dict) -> bool:
        """Reconcilia uma restauração interrompida sem perder o arquivo original.

        Regras: o temporário em texto claro é sempre removido; se o destino já
        contém o conteúdo autenticado, o banco é finalizado; caso contrário o
        backup do destino anterior é recolocado e a cópia cifrada é preservada.
        """
        qid = rec["id"]
        journal = meta.get("restore") if isinstance(meta.get("restore"), dict) else {}
        dest = Path(journal.get("dest") or rec.get("original_path") or "")
        if not str(dest) or is_dangerous_target(dest) or is_protected(dest) \
                or _reparse_in_existing_ancestors(dest.parent):
            log.error("Journal de restauração inválido/perigoso para %s; item mantido.", qid)
            self.db.update_quarantine(qid, status="quarantined", meta=_strip_restore(meta))
            self.db.log_action("quarantine_recover", str(dest), f"id={qid}: destino inválido", False)
            return True

        tmp = Path(journal["tmp"]) if journal.get("tmp") else None
        backup = Path(journal["backup"]) if journal.get("backup") else None
        if tmp and _valid_restore_artifact(tmp, dest, RESTORE_TMP_PREFIX):
            _unlink_quietly(tmp)  # nunca deixar texto claro para trás

        expected = rec.get("sha256") or meta.get("sha256") or ""
        expected_size = rec.get("size") or meta.get("size")
        stored = self._stored_path(rec)
        dest_ok = False
        if dest.is_file() and not is_reparse_point(dest):
            try:
                dest_ok = (not expected or _sha256_path(dest) == expected) and \
                          (expected_size is None or int(expected_size) == dest.stat().st_size)
            except (OSError, TypeError, ValueError):
                dest_ok = False

        if dest_ok:
            clean = _strip_restore(meta)
            clean["restored_to"] = str(dest)
            clean.pop("wrapped_key", None)
            self.db.update_quarantine(qid, status="restored", meta=clean)
            if backup and _valid_restore_artifact(backup, dest, RESTORE_BACKUP_PREFIX):
                _unlink_quietly(backup)
            if stored.exists():
                _unlink_quietly(stored)
            self.db.log_action("restore_recover", str(dest), f"id={qid}: restauração concluída", True)
            log.info("Restauração interrompida concluída: %s -> %s", qid, dest)
            return True

        # Destino não contém o conteúdo autenticado: recoloca o backup, se houver.
        if backup and _valid_restore_artifact(backup, dest, RESTORE_BACKUP_PREFIX):
            try:
                os.replace(backup, dest)
                log.info("Backup do destino anterior recolocado para %s", dest)
            except OSError as exc:
                log.error("Falha ao recolocar o backup %s: %s", backup, exc)
                # Mantém o journal para nova tentativa na próxima inicialização.
                return False
        self.db.update_quarantine(qid, status="quarantined", meta=_strip_restore(meta))
        self.db.log_action("quarantine_recover", str(dest), f"id={qid}: restauração desfeita", True)
        return True

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
        try:
            wrapped_key = wrap_key(key, qid)
        except CryptoError as exc:
            self.db.log_action("quarantine_refused", str(src),
                               f"proteção da chave falhou: {exc}", False)
            raise QuarantineError(f"Não foi possível proteger a chave da quarentena: {exc}") from exc
        meta = {
            "version": 2,
            "mtime_ns": st.st_mtime_ns,
            "atime_ns": st.st_atime_ns,
            "attributes": int(getattr(st, "st_file_attributes", 0)),
            "mode": st.st_mode,
            "acl": acl,
            "wrapped_key": wrapped_key,
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
        """Restaura um item, verificando autenticidade e SHA-256 antes de gravar o destino.

        Grava primeiro em um temporário com ACL restritiva, valida tag GCM, SHA-256 e
        tamanho, preserva o destino anterior em backup (quando ``overwrite=True``) e
        só remove o arquivo cifrado depois de o banco confirmar o status ``restored``.
        """
        rec = self.db.get_quarantine(qid)
        if rec and rec.get("status") == "restoring":
            # Retoma uma restauração anterior interrompida antes de aceitar um novo pedido.
            self._recover_restore(rec, self._meta(rec))
            rec = self.db.get_quarantine(qid)
            if rec and rec.get("status") == "restored":
                return Path(self._meta(rec).get("restored_to") or rec.get("original_path"))
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

        try:
            key = self._key_from_meta(meta, qid)
        except CryptoError as exc:
            raise QuarantineError(f"Chave do item inválida ou inacessível: {exc}") from exc
        expected = rec.get("sha256") or meta.get("sha256") or ""
        expected_size = rec.get("size") or meta.get("size")
        try:
            expected_size = int(expected_size) if expected_size is not None else None
        except (TypeError, ValueError):
            expected_size = None

        # Journal write-ahead: se o processo cair, a recuperação saberá o que limpar.
        tmp = _create_private_temp(dest, qid)
        journal = {"dest": str(dest), "tmp": str(tmp), "backup": "", "phase": "decrypting"}
        meta["restore"] = journal
        try:
            self.db.update_quarantine(qid, status="restoring", meta=meta)
        except sqlite3.Error as exc:
            _unlink_quietly(tmp)
            raise QuarantineError(f"Não foi possível registrar o início da restauração: {exc}") from exc

        backup: Path | None = None
        moved_backup = False
        promoted = False
        dest_attrs = dest_mode = None
        try:
            digest, size = decrypt_stream(stored, tmp, key, qid, expected or None)
            if expected_size is not None and expected_size != size:
                raise QuarantineError("Tamanho restaurado difere do registrado.")
            self._apply_metadata(tmp, meta)

            # Revalida imediatamente antes da promoção (TOCTOU).
            if dest.exists() and not overwrite:
                raise QuarantineError(f"O destino já existe: {dest}")
            if _reparse_in_existing_ancestors(dest.parent):
                raise QuarantineError("Diretório de destino é link/junction.")

            if dest.exists():
                try:
                    st = dest.stat()
                    dest_attrs = int(getattr(st, "st_file_attributes", 0)) or None
                    dest_mode = stat.S_IMODE(st.st_mode)
                except OSError:
                    pass
                backup = dest.with_name(f"{RESTORE_BACKUP_PREFIX}{qid}-{uuid.uuid4().hex[:8]}.tmp")
                journal["backup"] = str(backup)
                journal["phase"] = "promoting"
                self.db.update_quarantine(qid, meta=meta)

                # O destino somente-leitura impede o rename no Windows.
                try:
                    os.chmod(dest, stat.S_IWRITE | stat.S_IREAD)
                except OSError:
                    pass
                try:
                    os.replace(dest, backup)
                    moved_backup = True
                except OSError as exc:
                    raise QuarantineError(
                        f"Não foi possível preservar o destino existente antes da substituição: {exc}") from exc

            try:
                os.replace(tmp, dest)
                promoted = True
            except OSError as exc:
                raise QuarantineError(f"Não foi possível promover o arquivo restaurado: {exc}") from exc

            # Primeiro confirma no banco; só depois remove o .qz e o backup.
            clean_meta = _strip_restore(meta)
            clean_meta["restored_to"] = str(dest)
            clean_meta.pop("wrapped_key", None)
            try:
                self.db.update_quarantine(qid, status="restored", meta=clean_meta)
            except sqlite3.Error as exc:
                # O arquivo já está no destino e o .qz continua intacto; a recuperação
                # (status "restoring" + journal) concluirá o registro depois.
                log.error("Restauração de %s promovida, mas o banco não confirmou: %s", qid, exc)
                raise QuarantineError(
                    "Arquivo restaurado, mas o registro no banco não pôde ser confirmado; "
                    "a recuperação na próxima inicialização concluirá.") from exc

            if moved_backup and backup:
                _unlink_quietly(backup)
            try:
                stored.unlink(missing_ok=True)
            except OSError as exc:
                log.warning("Item %s restaurado, mas a cópia cifrada não pôde ser removida: %s", qid, exc)
            if not restore_acl(dest, meta.get("acl")):
                log.debug("ACL não restaurada para %s (sem privilégio ou plataforma não Windows).", dest)
            self.db.log_action("restore", str(dest), f"id={qid} sha256={digest}", True)
            log.info("Restaurado: %s -> %s", qid, dest)
            return dest
        except (QuarantineError, CryptoError, OSError, sqlite3.Error) as exc:
            if not promoted:
                _unlink_quietly(tmp)
                journal_failed = False
                if moved_backup and backup and backup.exists():
                    try:
                        if dest.exists():
                            _unlink_quietly(dest)  # destino parcial; backup é a fonte de verdade
                        os.replace(backup, dest)
                        if dest_attrs is not None:
                            apply_attributes(dest, dest_attrs)
                        if dest_mode is not None:
                            apply_mode(dest, dest_mode)
                        moved_backup = False
                    except OSError as rb_exc:
                        journal_failed = True
                        log.error("Falha ao recolocar o backup de %s: %s", dest, rb_exc)
                if not journal_failed:
                    try:
                        self.db.update_quarantine(qid, status="quarantined", meta=_strip_restore(meta))
                    except sqlite3.Error:
                        log.exception("Banco indisponível ao desfazer a restauração de %s", qid)
                try:
                    self.db.log_action("restore_failed", str(dest), f"id={qid}: {exc}", False)
                except sqlite3.Error:
                    log.exception("Banco indisponível ao registrar falha de restauração de %s", qid)
            else:
                # Arquivo promovido: manter journal/status para a recuperação finalizar.
                try:
                    self.db.log_action("restore_pending", str(dest),
                                       f"id={qid}: arquivo promovido; banco pendente: {exc}", False)
                except sqlite3.Error:
                    log.exception("Banco indisponível ao registrar restauração pendente de %s", qid)
                log.error("Restauração de %s promovida, mas pendente de confirmação: %s", qid, exc)
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
            meta = self._meta(rec)
        except QuarantineError:
            meta = {}

        # Journal: se cair entre o unlink e o UPDATE, a recuperação conclui o estado.
        try:
            self.db.update_quarantine(qid, status="deleting")
        except sqlite3.Error as exc:
            raise QuarantineError(f"Não foi possível registrar a exclusão: {exc}") from exc
        try:
            stored.unlink(missing_ok=True)
            if stored.exists():
                raise OSError("o arquivo de quarentena ainda existe")
        except OSError as exc:
            try:
                self.db.update_quarantine(qid, status="quarantined")
            except sqlite3.Error:
                log.exception("Banco indisponível ao desfazer a exclusão de %s", qid)
            self.db.log_action("quarantine_delete", rec.get("original_path", ""),
                               f"id={qid}: {exc}", False)
            raise QuarantineError(f"Não foi possível apagar o item: {exc}") from exc
        meta.pop("wrapped_key", None)  # remove o material de chave do banco
        try:
            self.db.update_quarantine(qid, status="deleted", meta=_strip_restore(meta))
        except sqlite3.Error as exc:
            # O arquivo já foi removido; o status "deleting" permite à recuperação
            # concluir o registro na próxima inicialização.
            log.error("Exclusão de %s concluída, mas o banco não confirmou: %s", qid, exc)
            raise QuarantineError(
                "Arquivo removido, mas o registro não pôde ser confirmado; a recuperação "
                "na próxima inicialização concluirá.") from exc
        self.db.log_action("quarantine_delete", rec.get("original_path", ""), f"id={qid}", True)
        log.info("Item de quarentena removido definitivamente: %s", qid)

    def list_items(self):
        return self.db.list_quarantine()
