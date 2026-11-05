"""Testes de segurança da limpeza de temporários.

Nenhum diretório real do sistema é limpo: todas as categorias usam raízes
temporárias sintéticas. A Lixeira real nunca é esvaziada nestes testes.
"""
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

os.environ.setdefault("SENTINEL_HOME", tempfile.mkdtemp(prefix="sentinel_ctest_home_"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import cleanup
from database.database import Database


def make_test_root(prefix: str) -> Path:
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA") or tempfile.gettempdir()
        return Path(tempfile.mkdtemp(prefix=prefix, dir=base))
    return Path(tempfile.mkdtemp(prefix=prefix))


def make_dir_link(target: Path, link: Path) -> bool:
    try:
        link.symlink_to(target, target_is_directory=True)
        return True
    except (OSError, NotImplementedError):
        pass
    if sys.platform == "win32":
        proc = subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(target)],
                              capture_output=True, text=True)
        return proc.returncode == 0 and link.exists()
    return False


class CleanupSecurityTests(unittest.TestCase):
    def setUp(self):
        self.root = make_test_root("cln_")
        self.db = Database(self.root / "t.db")
        self.tmp = self.root / "tmp"
        self.tmp.mkdir()

    def tearDown(self):
        try:
            self.db.close()
        finally:
            shutil.rmtree(self.root, ignore_errors=True)

    def put(self, name: str, data: bytes = b"x", age_days: float = 0.0) -> Path:
        p = self.tmp / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
        if age_days:
            t = time.time() - age_days * 86400
            os.utime(p, (t, t))
        return p

    def category(self, **kw) -> cleanup.Category:
        opts = dict(key="test", name="Teste", description="teste", roots=[self.tmp], min_age_days=0)
        opts.update(kw)
        return cleanup.Category(**opts)

    def test_recycle_requires_explicit_confirmation(self):
        cat = cleanup.Category("recycle", "Lixeira", "", kind="recycle", min_age_days=0)
        with self.assertRaises(cleanup.CleanupError):
            cleanup.clean(cat, self.db, confirmed=False)

    def test_estimate_does_not_change_anything_and_matches_clean(self):
        a = self.put("a.tmp", b"a" * 100)
        b = self.put("sub/b.log", b"b" * 200)
        cat = self.category()
        self.assertEqual(cleanup.estimate(cat), (300, 2))
        self.assertTrue(a.exists() and b.exists())  # estimar nunca apaga

        res = cleanup.clean(cat, self.db)
        self.assertEqual((res.deleted, res.freed, res.skipped), (2, 300, 0))
        self.assertFalse(a.exists())
        self.assertFalse(b.parent.exists())  # diretório esvaziado por esta rodada
        self.assertEqual(cleanup.estimate(cat), (0, 0))
        self.assertEqual(self.db.list_actions()[-1]["action"], "cleanup_delete")

    def test_personal_files_are_never_deleted(self):
        personal = ["nota.pdf", "script.py", "backup.zip", "video.mp4", "dados.json", "base.db", "foto.jpg"]
        junk = ["a.tmp", "b.log", "c.cache", "d~"]
        for name in personal:
            self.put(name, b"conteudo importante")
        for name in junk:
            self.put(name, b"lixo")
        keep = self.tmp / "meus_documentos" / "importante.pdf"
        keep.parent.mkdir()
        keep.write_bytes(b"nao apagar")

        res = cleanup.clean(self.category(), self.db)
        self.assertEqual(res.deleted, len(junk))
        for name in personal:
            self.assertTrue((self.tmp / name).exists(), name)
        self.assertTrue(keep.exists())

    def test_patterns_limit_deletion_to_known_cache_files(self):
        cache1 = self.put("thumbcache_123.db")
        cache2 = self.put("iconcache_9.db")
        other_db = self.put("meu_banco.db")
        other = self.put("arquivo.bin")
        cat = self.category(patterns=["thumbcache_*.db"], recursive=False)
        res = cleanup.clean(cat, self.db)
        self.assertEqual(res.deleted, 1)
        self.assertFalse(cache1.exists())
        for p in (cache2, other_db, other):
            self.assertTrue(p.exists(), p.name)

    def test_junction_is_not_followed(self):
        outside = self.root / "outside"
        outside.mkdir()
        victim = outside / "manter.txt"
        victim.write_bytes(b"nao apagar")
        link = self.tmp / "link"
        if not make_dir_link(outside, link):
            self.skipTest("ambiente não permite criar symlink/junction")

        cat = self.category()
        self.assertEqual(cleanup.estimate(cat), (0, 0))
        res = cleanup.clean(cat, self.db)
        self.assertEqual(res.deleted, 0)
        self.assertTrue(victim.exists())

    @unittest.skipUnless(sys.platform != "win32", "symlink de arquivo exige privilégio no Windows")
    def test_file_symlink_is_not_deleted(self):
        outside = self.root / "outside.txt"
        outside.write_bytes(b"original")
        link = self.tmp / "atalho.tmp"
        link.symlink_to(outside)
        res = cleanup.clean(self.category(), self.db)
        self.assertEqual(res.deleted, 0)
        self.assertTrue(outside.exists())

    def test_only_directories_touched_by_this_run_are_pruned(self):
        nested = self.put("sub/nested/a.tmp")
        untouched = self.tmp / "vazia_nao_tocada"
        untouched.mkdir()
        (untouched / "keep.txt").write_bytes(b"keep")
        res = cleanup.clean(self.category(), self.db)
        self.assertEqual(res.deleted, 1)
        self.assertFalse(nested.parent.exists())
        self.assertTrue(untouched.exists())

    def test_recent_files_are_skipped_by_age(self):
        recent = self.put("recente.tmp")
        res = cleanup.clean(self.category(min_age_days=1), self.db)
        self.assertEqual(res.deleted, 0)
        self.assertTrue(recent.exists())

    @unittest.skipUnless(sys.platform == "win32", "no Windows o ctime (criação) é conservador")
    def test_old_mtime_but_new_creation_is_conservative_on_windows(self):
        f = self.put("copiado_agora.tmp")
        old = time.time() - 3 * 86400
        os.utime(f, (old, old))
        res = cleanup.clean(self.category(min_age_days=1), self.db)
        self.assertEqual(res.deleted, 0)  # criado agora: não é lixo antigo
        self.assertTrue(f.exists())

    def test_cancel_stops_before_deleting(self):
        files = [self.put(f"{i}.tmp") for i in range(5)]
        res = cleanup.clean(self.category(), self.db, cancel=lambda: True)
        self.assertEqual(res.deleted, 0)
        self.assertTrue(all(f.exists() for f in files))

    def test_permission_error_is_counted_as_skipped(self):
        f = self.put("em_uso.tmp")
        with mock.patch("core.cleanup.os.remove", side_effect=PermissionError("em uso")):
            res = cleanup.clean(self.category(), self.db)
        self.assertEqual(res.deleted, 0)
        self.assertEqual(res.skipped, 1)
        self.assertTrue(f.exists())

    def test_missing_root_is_ignored(self):
        cat = cleanup.Category("x", "x", "x", roots=[self.root / "nao_existe"], min_age_days=0)
        self.assertEqual(cleanup.estimate(cat), (0, 0))
        self.assertEqual(cleanup.clean(cat, self.db).deleted, 0)

    @unittest.skipUnless(sys.platform == "win32", "lista de manutenção é específica do Windows")
    def test_protected_maintenance_allowlist_is_closed(self):
        win = Path(os.environ.get("SystemRoot", r"C:\Windows"))
        forged = cleanup.Category("forged", "x", "x", roots=[win / "System32"], min_age_days=0)
        self.assertFalse(cleanup._allowed_protected(forged, win / "System32" / "kernel32.dll"))
        self.assertFalse(cleanup._allowed_protected(forged, win / "System32" / "drivers" / "x.sys"))

        legit = cleanup.Category("win_temp", "x", "x", roots=[win / "Temp"], min_age_days=1)
        self.assertTrue(cleanup._allowed_protected(legit, win / "Temp" / "antigo.tmp"))

        # A raiz precisa estar declarada pela categoria E na lista fechada.
        wrong = cleanup.Category("x", "x", "x", roots=[self.tmp], min_age_days=0)
        self.assertFalse(cleanup._allowed_protected(wrong, win / "Temp" / "antigo.tmp"))

    def test_clean_never_deletes_directories_recursively(self):
        d = self.tmp / "sub" / "dir"
        d.mkdir(parents=True)
        keep = d / "keep.txt"  # arquivo pessoal, não pode ser removido
        keep.write_bytes(b"keep")
        (d / "junk.tmp").write_bytes(b"junk")
        res = cleanup.clean(self.category(), self.db)
        self.assertEqual(res.deleted, 1)
        self.assertTrue(keep.exists())
        self.assertTrue(d.exists())  # diretório contém arquivo pessoal: permanece


if __name__ == "__main__":
    unittest.main()
