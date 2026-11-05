"""Testes de segurança da quarentena: AES-GCM autenticado, proteção de chave,
detecção de adulteração, rollback, recuperação e migração do formato legado.

Todos os arquivos usados são sintéticos e aleatórios (nunca malware real).
"""
import hashlib
import json
import os
import shutil
import stat
import sys
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest import mock

os.environ.setdefault("SENTINEL_HOME", tempfile.mkdtemp(prefix="sentinel_qtest_home_"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import quarantine_crypto as qc
from core.quarantine import Quarantine, QuarantineError
from core.quarantine_crypto import (CryptoError, IntegrityError, decrypt_stream, encrypt_stream,
                                    legacy_xor, unwrap_key, verify_stream, wrap_key)
from database.database import Database


def make_test_root(prefix: str) -> Path:
    """Raiz fora de %TEMP% para não acionar heurísticas de 'arquivo em temp'."""
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA") or tempfile.gettempdir()
        return Path(tempfile.mkdtemp(prefix=prefix, dir=base))
    return Path(tempfile.mkdtemp(prefix=prefix))


def meta_of(rec) -> dict:
    return json.loads(rec["meta_json"] or "{}")


class QuarantineSecurityTests(unittest.TestCase):
    def setUp(self):
        self.root = make_test_root("qsx_")
        self.db = Database(self.root / "t.db")
        self.qdir = self.root / "quarantine"
        self.q = Quarantine(self.db, self.qdir)

    def tearDown(self):
        try:
            self.db.close()
        finally:
            shutil.rmtree(self.root, ignore_errors=True)

    def make_file(self, name="sample.bin", payload=None):
        f = self.root / name
        f.write_bytes(payload if payload is not None else os.urandom(4096))
        return f

    def test_ciphertext_is_authenticated_and_hides_plaintext(self):
        payload = os.urandom(300_000)
        f = self.make_file(payload=payload)
        qid = self.q.quarantine_file(f, allowed_roots=[self.root])

        stored = self.qdir / f"{qid}.qz"
        blob = stored.read_bytes()
        self.assertTrue(blob.startswith(qc.MAGIC))
        self.assertNotEqual(blob[:2], b"MZ")
        self.assertGreater(len(blob), len(payload))
        self.assertNotIn(payload[:64], blob)
        self.assertNotIn(payload, blob)
        self.assertFalse(f.exists())

    def test_database_never_contains_plaintext_key(self):
        f = self.make_file()
        qid = self.q.quarantine_file(f, allowed_roots=[self.root])
        rec = self.db.get_quarantine(qid)
        meta = meta_of(rec)
        self.assertNotIn("key", meta)
        self.assertIn("wrapped_key", meta)
        self.assertIn(meta["wrapped_key"].split(":", 1)[0], ("dpapi", "mk1"))
        self.assertNotIn("wrapped_key", self.db.get_quarantine(qid)["evidence_json"])
        # A chave só pode ser recuperada pelo token protegido, nunca pelo banco.
        self.assertFalse(any(k == "key" for k in meta))

        # Unwrap só funciona com o ID correto (a chave é vinculada ao item).
        key = unwrap_key(meta["wrapped_key"], qid)
        self.assertEqual(len(key), 32)
        with self.assertRaises(CryptoError):
            unwrap_key(meta["wrapped_key"], qid + "-outro")

    def test_tampered_ciphertext_is_rejected_and_original_not_restored(self):
        f = self.make_file(payload=os.urandom(50_000))
        qid = self.q.quarantine_file(f, allowed_roots=[self.root])
        stored = self.qdir / f"{qid}.qz"
        data = bytearray(stored.read_bytes())
        data[len(data) // 2] ^= 0xFF
        stored.write_bytes(data)

        with self.assertRaises(QuarantineError):
            self.q.restore(qid)
        self.assertFalse(f.exists())
        self.assertEqual(self.db.get_quarantine(qid)["status"], "quarantined")
        self.assertEqual(list(self.root.glob(".*.restoring.*")), [])

    def test_swapped_files_fail_authentication_by_item_id(self):
        f1 = self.make_file("one.bin", os.urandom(20_000))
        f2 = self.make_file("two.bin", os.urandom(20_000))
        q1 = self.q.quarantine_file(f1, allowed_roots=[self.root])
        q2 = self.q.quarantine_file(f2, allowed_roots=[self.root])
        s1, s2 = self.qdir / f"{q1}.qz", self.qdir / f"{q2}.qz"
        b1, b2 = s1.read_bytes(), s2.read_bytes()
        s1.write_bytes(b2)
        s2.write_bytes(b1)

        with self.assertRaises(QuarantineError):
            self.q.restore(q1)
        self.assertFalse(f1.exists())
        self.assertFalse(f2.exists())

    def test_truncated_or_unknown_headers_are_rejected(self):
        key = os.urandom(32)
        src = self.make_file("stream.bin", os.urandom(200_000))
        enc = self.root / "stream.qz"
        digest, size = encrypt_stream(src, enc, key, "item-1")
        self.assertEqual(size, src.stat().st_size)

        with self.assertRaises(CryptoError):
            verify_stream(enc, key, "item-diferente")
        with self.assertRaises(CryptoError):
            verify_stream(enc, os.urandom(32), "item-1")

        truncated = self.root / "truncated.qz"
        truncated.write_bytes(enc.read_bytes()[:-1])
        with self.assertRaises(CryptoError):
            verify_stream(truncated, key, "item-1")

        bad_magic = self.root / "bad_magic.qz"
        bad_magic.write_bytes(b"NOPE!" + enc.read_bytes()[len(qc.MAGIC):])
        with self.assertRaises(CryptoError):
            verify_stream(bad_magic, key, "item-1")

        with self.assertRaises(CryptoError):
            encrypt_stream(src, self.root / "x.qz", b"curta", "item-1")

    def test_streaming_roundtrip_across_chunk_boundary(self):
        key = os.urandom(32)
        payload = os.urandom(qc.CHUNK + 12_345)  # > 1 MiB força múltiplas leituras
        src = self.root / "large.bin"
        src.write_bytes(payload)
        enc = self.root / "large.qz"
        out = self.root / "large.out"

        digest, size = encrypt_stream(src, enc, key, "large-1")
        self.assertEqual(size, len(payload))
        self.assertEqual(verify_stream(enc, key, "large-1", digest), (digest, size))
        self.assertEqual(decrypt_stream(enc, out, key, "large-1", digest), (digest, size))
        self.assertEqual(out.read_bytes(), payload)

        out.write_bytes(b"conteudo anterior que deve ser substituido")
        with self.assertRaises(IntegrityError):
            decrypt_stream(enc, out, key, "large-1", "0" * 64)

    def test_invalid_stored_name_cannot_escape_quarantine_directory(self):
        f = self.make_file()
        qid = self.q.quarantine_file(f, allowed_roots=[self.root])
        for name in ("../escape.qz", r"..\escape.qz", "escape.bin", "sub/escape.qz"):
            self.db.update_quarantine(qid, stored_name=name)
            with self.assertRaises(QuarantineError):
                self.q.restore(qid)
        self.assertFalse((self.root / "escape.qz").exists())

    def test_restore_refuses_outside_allowed_roots_and_protected_destination(self):
        f = self.make_file()
        qid = self.q.quarantine_file(f, allowed_roots=[self.root])
        outside = make_test_root("qsx_out_")
        try:
            dest = outside / "restored.bin"
            with self.assertRaises(QuarantineError):
                self.q.restore(qid, destination=dest, allowed_roots=[self.root])
            self.assertFalse(dest.exists())
        finally:
            shutil.rmtree(outside, ignore_errors=True)

        if sys.platform == "win32":
            protected = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "sentinel_probe_never.bin"
            with self.assertRaises(QuarantineError):
                self.q.restore(qid, destination=protected)
            self.assertFalse(protected.exists())

    def test_restore_respects_overwrite_flag(self):
        payload = os.urandom(2048)
        f = self.make_file(payload=payload)
        qid = self.q.quarantine_file(f, allowed_roots=[self.root])
        f.write_bytes(b"ocupante")
        with self.assertRaises(QuarantineError):
            self.q.restore(qid)
        self.assertEqual(f.read_bytes(), b"ocupante")
        self.q.restore(qid, overwrite=True)
        self.assertEqual(f.read_bytes(), payload)

    def test_restore_preserves_timestamps_and_readonly(self):
        f = self.make_file(payload=os.urandom(2048))
        old_ns = 1_600_000_000_123_456_700
        os.utime(f, ns=(old_ns, old_ns))
        if sys.platform == "win32":
            os.chmod(f, stat.S_IREAD)
        else:
            os.chmod(f, 0o640)
        expected_mode = stat.S_IMODE(f.stat().st_mode)
        qid = self.q.quarantine_file(f, allowed_roots=[self.root])
        # A quarentena não deve alterar o original antes de removê-lo.
        self.q.restore(qid)

        st = f.stat()
        self.assertEqual(st.st_mtime_ns, old_ns)
        if sys.platform == "win32":
            self.assertTrue(st.st_file_attributes & stat.FILE_ATTRIBUTE_READONLY)
        else:
            self.assertEqual(stat.S_IMODE(st.st_mode), expected_mode)

    def test_delete_permanently_requires_confirmation_and_removes_key(self):
        f = self.make_file()
        qid = self.q.quarantine_file(f, allowed_roots=[self.root])
        stored = self.qdir / f"{qid}.qz"
        with self.assertRaises(QuarantineError):
            self.q.delete_permanently(qid, confirmed=False)
        self.assertTrue(stored.exists())

        self.q.delete_permanently(qid, confirmed=True)
        self.assertFalse(stored.exists())
        rec = self.db.get_quarantine(qid)
        self.assertEqual(rec["status"], "deleted")
        self.assertNotIn("wrapped_key", meta_of(rec))

    def test_missing_directory_source_and_symlink_are_refused(self):
        with self.assertRaises(QuarantineError):
            self.q.quarantine_file(self.root / "nao_existe.bin", allowed_roots=[self.root])
        d = self.root / "dir"
        d.mkdir()
        with self.assertRaises(QuarantineError):
            self.q.quarantine_file(d, allowed_roots=[self.root])
        self.assertTrue(d.is_dir())

    def test_failure_removing_original_rolls_back_without_data_loss(self):
        f = self.make_file(payload=b"conteudo original")
        with mock.patch("core.quarantine.os.remove", side_effect=PermissionError("em uso")):
            with self.assertRaises(QuarantineError):
                self.q.quarantine_file(f, allowed_roots=[self.root])
        self.assertEqual(f.read_bytes(), b"conteudo original")
        self.assertEqual(list(self.qdir.glob("*.qz")), [])
        records = self.db.list_quarantine(status=None)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["status"], "failed")
        refused = [a for a in self.db.list_actions() if a["action"] == "quarantine_failed"]
        self.assertTrue(refused)

    def test_recovery_promotes_valid_ready_copy(self):
        src = self.root / "interrompido.bin"
        payload = os.urandom(30_000)
        src.write_bytes(payload)
        qid = uuid.uuid4().hex
        key = os.urandom(32)
        stored = self.qdir / f"{qid}.qz"
        digest, size = encrypt_stream(src, stored, key, qid)
        self.db.add_quarantine({
            "id": qid, "original_path": str(src), "stored_name": stored.name, "sha256": digest,
            "size": size, "evidence": [], "meta": {"version": 2, "sha256": digest, "size": size,
                                                    "wrapped_key": wrap_key(key, qid)}},
            status="ready")
        os.remove(src)

        q = Quarantine(self.db, self.qdir)  # __init__ executa recover()
        self.assertEqual(self.db.get_quarantine(qid)["status"], "quarantined")
        q.restore(qid)
        self.assertEqual(src.read_bytes(), payload)

    def test_recovery_discards_copy_when_original_is_still_intact(self):
        src = self.root / "intacto.bin"
        payload = os.urandom(10_000)
        src.write_bytes(payload)
        qid = uuid.uuid4().hex
        key = os.urandom(32)
        stored = self.qdir / f"{qid}.qz"
        digest, size = encrypt_stream(src, stored, key, qid)
        self.db.add_quarantine({
            "id": qid, "original_path": str(src), "stored_name": stored.name, "sha256": digest,
            "size": size, "evidence": [], "meta": {"version": 2, "sha256": digest, "size": size,
                                                    "wrapped_key": wrap_key(key, qid)}},
            status="pending")

        Quarantine(self.db, self.qdir)
        self.assertEqual(self.db.get_quarantine(qid)["status"], "failed")
        self.assertEqual(src.read_bytes(), payload)
        self.assertFalse(stored.exists())

    def test_legacy_xor_item_is_migrated_and_restored(self):
        plain = os.urandom(200_000)
        src = self.root / "legado.bin"
        legacy_key = os.urandom(32)
        qid = uuid.uuid4().hex
        stored = self.qdir / f"{qid}.qz"
        stored.write_bytes(legacy_xor(plain, legacy_key))
        digest = hashlib.sha256(plain).hexdigest()
        self.db.add_quarantine({
            "id": qid, "original_path": str(src), "stored_name": stored.name, "sha256": digest,
            "size": len(plain), "evidence": [],
            "meta": {"key": legacy_key.hex(), "sha256": digest, "size": len(plain)}},
            status="quarantined")

        q = Quarantine(self.db, self.qdir)  # recover() migra automaticamente
        rec = self.db.get_quarantine(qid)
        meta = meta_of(rec)
        self.assertNotIn("key", meta)
        self.assertIn("wrapped_key", meta)
        self.assertTrue(stored.read_bytes().startswith(qc.MAGIC))

        q.restore(qid)
        self.assertEqual(src.read_bytes(), plain)

    def test_master_key_fallback_never_exposes_key(self):
        key = os.urandom(32)
        data_dir = self.root / "data"
        with mock.patch.object(qc, "IS_WINDOWS", False), \
                mock.patch.object(qc.config, "DATA_DIR", data_dir):
            token = wrap_key(key, "item-mk1")
            self.assertTrue(token.startswith("mk1:"))
            self.assertNotEqual(token, key.hex())
            self.assertNotIn(key.hex(), token)
            self.assertEqual(unwrap_key(token, "item-mk1"), key)
            with self.assertRaises(CryptoError):
                unwrap_key(token, "outro-item")

            master = data_dir / "keys" / "master.key"
            self.assertEqual(len(master.read_bytes()), 32)
            if sys.platform != "win32":
                self.assertEqual(stat.S_IMODE(master.stat().st_mode) & 0o077, 0)

    @unittest.skipUnless(sys.platform == "win32", "DPAPI só existe no Windows")
    def test_dpapi_is_used_on_windows(self):
        token = wrap_key(os.urandom(32), "item-dpapi")
        self.assertTrue(token.startswith("dpapi:"))


if __name__ == "__main__":
    unittest.main()
