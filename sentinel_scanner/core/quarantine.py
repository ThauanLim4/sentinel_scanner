"""Quarentena: isola o arquivo (conteúdo codificado com XOR + extensão .qz, impossível de
executar acidentalmente), guarda caminho, hash, evidências e metadados para restauração."""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import uuid
from pathlib import Path

from . import config
from .logger import get_logger
from .safety import UnsafePathError, is_protected, is_reparse_point, validate_target

log = get_logger(__name__)
CHUNK = 64 * 1024  # múltiplo do tamanho da chave (32) -> alinhamento do keystream preservado
KEY_LEN = 32


class QuarantineError(Exception):
    pass


def _xor(data: bytes, key: bytes) -> bytes:
    keystream = (key * (len(data) // KEY_LEN + 1))[: len(data)]
    return (int.from_bytes(data, "big") ^ int.from_bytes(keystream, "big")).to_bytes(len(data), "big")


class Quarantine:
    def __init__(self, db, directory: Path | None = None):
        self.db = db
        self.dir = Path(directory or config.QUARANTINE_DIR)
        self.dir.mkdir(parents=True, exist_ok=True)

    def quarantine_file(self, path, evidences: list[dict] | None = None, allowed_roots: list | None = None,
                        confirmed: bool = False) -> str:
        """Move o arquivo para a quarentena. Retorna o ID. Recusa caminhos protegidos do Windows
        (arquivos de sistema suspeitos devem ser tratados com sfc/DISM/Defender, não removidos à força)."""
        src = Path(path)
        roots = allowed_roots or [src.anchor or "/"]
        try:
            src = validate_target(src, roots, allow_protected=False, allow_sensitive=confirmed)
        except UnsafePathError as exc:
            self.db.log_action("quarantine_refused", str(path), str(exc), False)
            raise QuarantineError(str(exc)) from exc

        st = src.stat()
        qid = uuid.uuid4().hex
        key = secrets.token_bytes(KEY_LEN)
        stored = self.dir / f"{qid}.qz"
        sha = hashlib.sha256()
        try:
            with open(src, "rb") as fin, open(stored, "wb") as fout:
                while chunk := fin.read(CHUNK):
                    sha.update(chunk)
                    fout.write(_xor(chunk, key))
        except OSError as exc:
            stored.unlink(missing_ok=True)
            self.db.log_action("quarantine_failed", str(src), str(exc), False)
            raise QuarantineError(f"Não foi possível ler o arquivo (em uso ou sem permissão): {exc}") from exc

        if stored.stat().st_size != st.st_size:
            stored.unlink(missing_ok=True)
            raise QuarantineError("Tamanho da cópia difere do original; operação abortada.")
        try:
            os.remove(src)
        except OSError as exc:  # em uso: desfaz a cópia, não deixa estado inconsistente
            stored.unlink(missing_ok=True)
            self.db.log_action("quarantine_failed", str(src), f"não removido: {exc}", False)
            raise QuarantineError(f"Arquivo em uso ou protegido; nada foi alterado: {exc}") from exc

        meta = {"key": key.hex(), "mtime_ns": st.st_mtime_ns, "atime_ns": st.st_atime_ns,
                "attributes": getattr(st, "st_file_attributes", 0), "mode": st.st_mode}
        self.db.add_quarantine({"id": qid, "original_path": str(src), "stored_name": stored.name,
                                "sha256": sha.hexdigest(), "size": st.st_size,
                                "evidence": evidences or [], "meta": meta})
        self.db.log_action("quarantine", str(src), f"id={qid} sha256={sha.hexdigest()}", True)
        log.info("Quarentena: %s -> %s", src, qid)
        return qid

    def restore(self, qid: str, destination=None, overwrite: bool = False) -> Path:
        rec = self.db.get_quarantine(qid)
        if not rec or rec["status"] != "quarantined":
            raise QuarantineError("Item inexistente ou já processado.")
        dest = Path(destination or rec["original_path"])
        if dest.exists() and not overwrite:
            raise QuarantineError(f"O destino já existe: {dest}")
        if is_protected(dest):
            raise QuarantineError("Restauração em diretório protegido do Windows não é permitida.")
        if is_reparse_point(dest.parent):
            raise QuarantineError("Diretório de destino é link/junction.")
        meta = json.loads(rec["meta_json"])
        key = bytes.fromhex(meta["key"])
        stored = self.dir / rec["stored_name"]
        if not stored.exists():
            raise QuarantineError("Arquivo de quarentena ausente.")
        dest.parent.mkdir(parents=True, exist_ok=True)
        tmp = dest.with_name(dest.name + ".restoring")
        sha = hashlib.sha256()
        try:
            with open(stored, "rb") as fin, open(tmp, "wb") as fout:
                while chunk := fin.read(CHUNK):
                    plain = _xor(chunk, key)
                    sha.update(plain)
                    fout.write(plain)
            if sha.hexdigest() != rec["sha256"]:
                raise QuarantineError("Falha de integridade: hash difere do registrado.")
            os.replace(tmp, dest)
        except Exception:
            tmp.unlink(missing_ok=True)
            raise
        try:
            os.utime(dest, ns=(meta["atime_ns"], meta["mtime_ns"]))
        except OSError:
            pass
        stored.unlink(missing_ok=True)
        self.db.set_quarantine_status(qid, "restored")
        self.db.log_action("restore", str(dest), f"id={qid}", True)
        return dest

    def delete_permanently(self, qid: str, confirmed: bool) -> None:
        if not confirmed:
            raise QuarantineError("Remoção definitiva exige confirmação explícita.")
        rec = self.db.get_quarantine(qid)
        if not rec or rec["status"] != "quarantined":
            raise QuarantineError("Item inexistente ou já processado.")
        (self.dir / rec["stored_name"]).unlink(missing_ok=True)
        self.db.set_quarantine_status(qid, "deleted")
        self.db.log_action("quarantine_delete", rec["original_path"], f"id={qid}", True)

    def list_items(self):
        return self.db.list_quarantine()
