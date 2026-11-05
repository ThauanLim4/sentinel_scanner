"""Persistência SQLite (thread-safe): varreduras, detecções, ações, cache de hashes e quarentena."""
from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime

from core import config

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans(
  id INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT, started TEXT, finished TEXT,
  files_scanned INTEGER DEFAULT 0, processes_scanned INTEGER DEFAULT 0,
  windows_version TEXT, app_version TEXT, status TEXT DEFAULT 'running');
CREATE TABLE IF NOT EXISTS findings(
  id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id INTEGER, path TEXT, sha256 TEXT,
  category TEXT, risk TEXT, score INTEGER, evidence_json TEXT, status TEXT DEFAULT 'open');
CREATE TABLE IF NOT EXISTS actions(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, action TEXT, target TEXT,
  detail TEXT, success INTEGER);
CREATE TABLE IF NOT EXISTS hash_cache(
  path TEXT PRIMARY KEY, size INTEGER, mtime_ns INTEGER, sha256 TEXT, signature TEXT);
CREATE TABLE IF NOT EXISTS verdict_cache(
  path TEXT PRIMARY KEY, size INTEGER, mtime_ns INTEGER, engine TEXT);
CREATE TABLE IF NOT EXISTS quarantine(
  id TEXT PRIMARY KEY, original_path TEXT, stored_name TEXT, sha256 TEXT, size INTEGER,
  ts TEXT, evidence_json TEXT, meta_json TEXT, status TEXT DEFAULT 'quarantined');
"""


def now() -> str:
    return datetime.now().isoformat(timespec="seconds")


class Database:
    def __init__(self, path=None):
        config.ensure_dirs()
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(str(path or config.DB_PATH), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=NORMAL")
            self._conn.executescript(SCHEMA)
            self._conn.commit()

    def _exec(self, sql, params=()):
        with self._lock:
            cur = self._conn.execute(sql, params)
            self._conn.commit()
            return cur

    def _query(self, sql, params=()):
        with self._lock:
            return [dict(r) for r in self._conn.execute(sql, params).fetchall()]

    def close(self):
        with self._lock:
            self._conn.close()

    # --- varreduras -----------------------------------------------------
    def start_scan(self, kind: str, windows_version: str = "") -> int:
        return self._exec("INSERT INTO scans(kind,started,windows_version,app_version) VALUES(?,?,?,?)",
                          (kind, now(), windows_version, config.APP_VERSION)).lastrowid

    def finish_scan(self, scan_id: int, files: int, processes: int, status: str = "completed"):
        self._exec("UPDATE scans SET finished=?,files_scanned=?,processes_scanned=?,status=? WHERE id=?",
                   (now(), files, processes, status, scan_id))

    def list_scans(self, limit: int = 100):
        return self._query("SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,))

    # --- detecções --------------------------------------------------------
    def add_finding(self, scan_id: int, f) -> int:
        return self._exec(
            "INSERT INTO findings(scan_id,path,sha256,category,risk,score,evidence_json) VALUES(?,?,?,?,?,?,?)",
            (scan_id, f.path, f.sha256, f.category, f.risk.label, f.score,
             json.dumps(f.to_dict(), ensure_ascii=False))).lastrowid

    def list_findings(self, scan_id: int | None = None, status: str | None = None):
        sql, p = "SELECT * FROM findings WHERE 1=1", []
        if scan_id is not None:
            sql += " AND scan_id=?"; p.append(scan_id)
        if status:
            sql += " AND status=?"; p.append(status)
        return self._query(sql + " ORDER BY score DESC", p)

    def set_finding_status(self, finding_id: int, status: str):
        self._exec("UPDATE findings SET status=? WHERE id=?", (status, finding_id))

    # --- ações (auditoria) ------------------------------------------------
    def log_action(self, action: str, target: str, detail: str = "", success: bool = True):
        self._exec("INSERT INTO actions(ts,action,target,detail,success) VALUES(?,?,?,?,?)",
                   (now(), action, target, detail, int(success)))

    def list_actions(self, limit: int = 500):
        return self._query("SELECT * FROM actions ORDER BY id DESC LIMIT ?", (limit,))

    # --- cache de hashes --------------------------------------------------
    def get_cached(self, path: str, size: int, mtime_ns: int):
        rows = self._query("SELECT sha256,signature FROM hash_cache WHERE path=? AND size=? AND mtime_ns=?",
                           (path, size, mtime_ns))
        return rows[0] if rows else None

    def put_cached(self, path: str, size: int, mtime_ns: int, sha256: str, signature: str = ""):
        self._exec("INSERT OR REPLACE INTO hash_cache VALUES(?,?,?,?,?)",
                   (path, size, mtime_ns, sha256, signature))

    # --- cache de veredictos (varredura incremental) ----------------------
    def is_clean_cached(self, path: str, size: int, mtime_ns: int, engine: str) -> bool:
        return bool(self._query("SELECT 1 FROM verdict_cache WHERE path=? AND size=? AND mtime_ns=? AND engine=?",
                                (path, size, mtime_ns, engine)))

    def put_clean_many(self, rows: list[tuple]):
        with self._lock:
            self._conn.executemany("INSERT OR REPLACE INTO verdict_cache VALUES(?,?,?,?)", rows)
            self._conn.commit()

    # --- quarentena -------------------------------------------------------
    def add_quarantine(self, rec: dict):
        self._exec("INSERT INTO quarantine(id,original_path,stored_name,sha256,size,ts,evidence_json,meta_json) "
                   "VALUES(?,?,?,?,?,?,?,?)",
                   (rec["id"], rec["original_path"], rec["stored_name"], rec["sha256"], rec["size"],
                    now(), json.dumps(rec.get("evidence", []), ensure_ascii=False),
                    json.dumps(rec.get("meta", {}))))

    def get_quarantine(self, qid: str):
        rows = self._query("SELECT * FROM quarantine WHERE id=?", (qid,))
        return rows[0] if rows else None

    def list_quarantine(self, status: str | None = "quarantined"):
        if status:
            return self._query("SELECT * FROM quarantine WHERE status=? ORDER BY ts DESC", (status,))
        return self._query("SELECT * FROM quarantine ORDER BY ts DESC")

    def set_quarantine_status(self, qid: str, status: str):
        self._exec("UPDATE quarantine SET status=? WHERE id=?", (status, qid))
