"""Persistent per-thread SQLite connections; no network database handshake."""
from datetime import datetime, timezone
from pathlib import Path
import json
import secrets
import sqlite3
import threading
import time
import uuid
from urllib.parse import urlsplit


def timestamp():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


class Store:
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._local = threading.local()
        self._connections = []
        self._lock = threading.Lock()
        self.closed = False
        connection = self.connection()
        connection.execute("PRAGMA journal_mode=WAL")
        connection.executescript("""
            CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY, owner TEXT NOT NULL,
                admin INTEGER NOT NULL DEFAULT 0, expires REAL NOT NULL
            );
            CREATE INDEX IF NOT EXISTS sessions_expiry ON sessions(expires);
            CREATE TABLE IF NOT EXISTS analyses (
                id TEXT PRIMARY KEY, share_id TEXT UNIQUE NOT NULL,
                owner TEXT NOT NULL, fingerprint TEXT NOT NULL,
                kind TEXT NOT NULL CHECK(kind IN ('url','news','screenshot')), label TEXT NOT NULL,
                input_text TEXT NOT NULL, result_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                UNIQUE(owner, fingerprint)
            );
            CREATE INDEX IF NOT EXISTS analyses_owner_time ON analyses(owner,created_at DESC);
            CREATE INDEX IF NOT EXISTS analyses_kind_label_time ON analyses(kind,label,created_at DESC);
            CREATE TABLE IF NOT EXISTS feedback (
                id TEXT PRIMARY KEY, analysis_id TEXT NOT NULL,
                owner TEXT NOT NULL, accurate INTEGER NOT NULL CHECK(accurate IN (0,1)),
                reason TEXT NOT NULL, other_text TEXT NOT NULL, created_at TEXT NOT NULL,
                FOREIGN KEY(analysis_id) REFERENCES analyses(id) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS feedback_analysis ON feedback(analysis_id);
            PRAGMA user_version=1;
        """)
        connection.commit()

    def connection(self):
        if self.closed:
            raise RuntimeError("Store is closed.")
        if not hasattr(self._local, "connection"):
            connection = sqlite3.connect(self.path, timeout=5, check_same_thread=False)
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA busy_timeout=5000")
            connection.execute("PRAGMA synchronous=NORMAL")
            self._local.connection = connection
            with self._lock:
                self._connections.append(connection)
        return self._local.connection

    def create_session(self, owner=None, admin=False, duration=30 * 86400):
        session = {"id": secrets.token_urlsafe(24), "owner": owner or secrets.token_urlsafe(18),
                   "admin": bool(admin), "expires": time.time() + duration}
        conn = self.connection()
        with conn:
            conn.execute("INSERT INTO sessions VALUES (?,?,?,?)",
                         (session["id"], session["owner"], int(admin), session["expires"]))
            conn.execute("DELETE FROM sessions WHERE expires < ?", (time.time(),))
        return session

    def get_session(self, session_id):
        row = self.connection().execute("SELECT * FROM sessions WHERE id=? AND expires>?",
                                        (session_id, time.time())).fetchone()
        return dict(row) if row else None

    def revoke_session(self, session_id):
        with self.connection() as conn:
            conn.execute("DELETE FROM sessions WHERE id=?", (session_id,))

    def save_analysis(self, owner, data):
        result = {key: value for key, value in data.items() if key not in ("private_input", "fingerprint")}
        fingerprint = data["fingerprint"]
        conn = self.connection()
        # Serializing saves prevents duplicate ownership rows without holding a worker lock.
        with self._lock, conn:
            row = conn.execute("SELECT id,share_id,created_at FROM analyses WHERE owner=? AND fingerprint=?",
                               (owner, fingerprint)).fetchone()
            if row:
                result.update(id=row["id"], share_id=row["share_id"], created_at=row["created_at"])
                conn.execute("UPDATE analyses SET result_json=?,label=? WHERE id=?",
                             (json.dumps(result, ensure_ascii=False, allow_nan=False), result["label"], row["id"]))
            else:
                result.update(id=str(uuid.uuid4()), share_id=secrets.token_urlsafe(18), created_at=timestamp())
                conn.execute("INSERT INTO analyses VALUES (?,?,?,?,?,?,?,?,?)", (
                    result["id"], result["share_id"], owner, fingerprint, result["kind"], result["label"],
                    data.get("private_input", ""), json.dumps(result, ensure_ascii=False, allow_nan=False), result["created_at"]))
        return result

    def history(self, owner, limit=30):
        rows = self.connection().execute("SELECT result_json FROM analyses WHERE owner=? ORDER BY created_at DESC LIMIT ?",
                                         (owner, min(max(limit, 1), 100))).fetchall()
        return [json.loads(row[0]) for row in rows]

    def shared(self, share_id):
        row = self.connection().execute("SELECT result_json FROM analyses WHERE share_id=?", (share_id,)).fetchone()
        if not row:
            return None
        result = json.loads(row[0])
        result.pop("extracted_text", None)
        return result

    def community(self):
        rows = self.connection().execute("SELECT result_json FROM analyses WHERE kind='url' AND label='high_risk' ORDER BY created_at DESC LIMIT 30").fetchall()
        results, seen = [], set()
        for row in rows:
            value = json.loads(row[0])
            domain = urlsplit(value["input_label"]).hostname or "Website"
            if value.get("label") == "high_risk" and domain not in seen:
                # Community cards expose domain-level signals, not private URL queries or share IDs.
                results.append({"kind": "url", "input_label": urlsplit(value["input_label"]).hostname or "Website",
                                "score": value["score"], "label": value["label"], "model": value["model"],
                                "model_version": value["model_version"], "created_at": value["created_at"],
                                "signals": ["A recent local check found a high domain-pattern signal."],
                                "limitations": value["limitations"], "cached": False, "elapsed_ms": 0})
                seen.add(domain)
            if len(results) == 3:
                break
        return results

    def add_feedback(self, owner, analysis_id, accurate, reason="", other_text=""):
        if type(accurate) is not bool:
            raise ValueError("Accuracy must be true or false.")
        conn = self.connection()
        if not conn.execute("SELECT 1 FROM analyses WHERE id=? AND owner=?", (analysis_id, owner)).fetchone():
            raise ValueError("This analysis is not in your history.")
        record = dict(id=str(uuid.uuid4()), analysis_id=analysis_id, owner=owner,
                      accurate=accurate, reason=reason[:120], other_text=other_text[:2000], created_at=timestamp())
        with conn:
            conn.execute("INSERT INTO feedback VALUES (?,?,?,?,?,?,?)", (
                record["id"], analysis_id, owner, int(accurate), record["reason"], record["other_text"], record["created_at"]))
        return record

    def overview(self):
        conn = self.connection()
        counts = conn.execute("SELECT kind,COUNT(*) FROM analyses GROUP BY kind").fetchall()
        analyses = [json.loads(row[0]) for row in conn.execute("SELECT result_json FROM analyses ORDER BY created_at DESC LIMIT 200")]
        by_label = dict(conn.execute("SELECT label,COUNT(*) FROM analyses GROUP BY label").fetchall())
        feedback = [dict(row) for row in conn.execute("SELECT f.*,a.kind FROM feedback f JOIN analyses a ON a.id=f.analysis_id ORDER BY f.created_at DESC LIMIT 200")]
        for item in feedback:
            item["accurate"] = bool(item["accurate"])
            item.pop("owner", None)
        return {"stats": {"total": sum(row[1] for row in counts), "by_kind": dict(counts), "by_label": by_label},
                "analyses": analyses, "feedback": feedback}

    def delete_analysis(self, record_id):
        with self.connection() as conn:
            return conn.execute("DELETE FROM analyses WHERE id=?", (record_id,)).rowcount > 0

    def delete_feedback(self, record_id):
        with self.connection() as conn:
            return conn.execute("DELETE FROM feedback WHERE id=?", (record_id,)).rowcount > 0

    def close(self):
        with self._lock:
            self.closed = True
            for connection in self._connections:
                connection.close()
            self._connections.clear()
