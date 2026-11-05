import os, sys, tempfile, unittest
from pathlib import Path

_TMP = tempfile.mkdtemp(prefix="sentinel_test_")
os.environ["SENTINEL_HOME"] = _TMP
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import cleanup
from core.file_analyzer import FileAnalyzer, sha256_file
from core.models import RiskLevel
from core.quarantine import Quarantine, QuarantineError
from database.database import Database


class CoreTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="sx_"))
        self.db = Database(self.root / "t.db")

    def test_unsigned_alone_is_not_flagged(self):
        f = self.root / "tool.exe"
        f.write_bytes(b"MZ" + b"\x00" * 1000)
        r = FileAnalyzer(self.db, set()).analyze(f)
        self.assertTrue(r is None or r.risk < RiskLevel.BAIXO)  # indício fraco isolado nunca vira detecção

    def test_disguised_exe_in_temp(self):
        d = self.root / "AppData" / "Local" / "Temp"
        d.mkdir(parents=True)
        f = d / "fatura.pdf.exe"
        f.write_bytes(b"MZ" + b"\x00" * 1000)
        r = FileAnalyzer(self.db, set()).analyze(f)
        self.assertIsNotNone(r)
        self.assertGreaterEqual(r.risk, RiskLevel.MEDIO)

    def test_mimic_name_and_known_hash(self):
        d = self.root / "Temp"; d.mkdir()
        f = d / "svchost.exe"; f.write_bytes(b"MZ" + b"abc" * 100)
        r = FileAnalyzer(self.db, set()).analyze(f)
        self.assertGreaterEqual(r.risk, RiskLevel.ALTO)
        r2 = FileAnalyzer(self.db, {sha256_file(f)}).analyze(f)
        self.assertEqual(r2.risk, RiskLevel.CRITICO)

    def test_quarantine_roundtrip(self):
        f = self.root / "bad.exe"; payload = os.urandom(200_000); f.write_bytes(payload)
        q = Quarantine(self.db, self.root / "q")
        qid = q.quarantine_file(f, [{"x": 1}], allowed_roots=[self.root])
        self.assertFalse(f.exists())
        stored = (self.root / "q" / f"{qid}.qz").read_bytes()
        self.assertNotEqual(stored[:2], b"MZ"); self.assertNotEqual(stored, payload)
        q.restore(qid)
        self.assertEqual(f.read_bytes(), payload)

    def test_quarantine_outside_allowed_root_refused(self):
        f = self.root / "x.exe"; f.write_bytes(b"MZ")
        q = Quarantine(self.db, self.root / "q")
        with self.assertRaises(QuarantineError):
            q.quarantine_file(f, allowed_roots=[self.root / "other"])
        self.assertTrue(f.exists())

    @unittest.skipIf(sys.platform == "win32", "symlink test (posix)")
    def test_symlink_refused_and_cleanup_ignores_links(self):
        outside = self.root / "outside"; outside.mkdir(); (outside / "keep.txt").write_text("x")
        tmp = self.root / "tmp"; tmp.mkdir(); (tmp / "old.tmp").write_text("y")
        (tmp / "link").symlink_to(outside)
        old = 1_000_000_000
        os.utime(tmp / "old.tmp", (old, old))
        cat = cleanup.Category("t", "t", "t", [tmp], min_age_days=1)
        self.assertEqual(cleanup.estimate(cat), (1, 1))
        res = cleanup.clean(cat, self.db)
        self.assertEqual(res.deleted, 1)
        self.assertTrue((outside / "keep.txt").exists())


if __name__ == "__main__":
    unittest.main()
