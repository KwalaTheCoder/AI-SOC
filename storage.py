"""
فاز ۱ — لایه ذخیره‌سازی پایدار (Persistent Storage Layer)
─────────────────────────────────────────────────────────
تحویلیِ سومِ فاز ۱ طبق سند: «لایه ذخیره‌سازی داده».
رویدادهای نرمال‌شده و غنی‌شده را در یک دیتابیس SQLite محلی ذخیره می‌کند
تا با ری‌استارت سرور از بین نروند و برای حسابرسی/جستجو در دسترس باشند.

کاملاً آفلاین — هیچ وابستگی بیرونی. فقط کتابخانه استاندارد پایتون.

استفاده در soc_server.py:

    from storage import init_db, store_events, get_stats, get_recent, get_by_ip

    init_db()                          # یک بار در استارتاپ
    enriched, fmt = parse_logs(content)
    store_events(enriched)             # ذخیره دائمی

ساختار ورودی: همان dict تختی که parse_logs() تولید می‌کند
(کلیدهایی مثل timestamp, severity, src_ip, dest_ip, action, signature, _ecs ...).
"""
from __future__ import annotations
import sqlite3
import json
import os
import threading
import hashlib
from datetime import datetime, timezone

DB_PATH = os.getenv("SOC_DB_PATH", os.path.join(os.path.dirname(__file__), "data", "events.db"))

_conn: sqlite3.Connection | None = None
_lock = threading.Lock()   # SQLite writes باید سریالی باشند (thread اسپلانک + Flask)


# ── راه‌اندازی ───────────────────────────────────────────
def init_db(path: str = None):
    """دیتابیس را باز/می‌سازد و جدول + ایندکس‌ها را ایجاد می‌کند."""
    global _conn, DB_PATH
    if path:
        DB_PATH = path
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    _conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    _conn.row_factory = sqlite3.Row
    _conn.execute("PRAGMA journal_mode=WAL;")     # همزمانی خواندن/نوشتن بهتر
    _conn.execute("PRAGMA synchronous=NORMAL;")
    _conn.executescript("""
    CREATE TABLE IF NOT EXISTS events (
        id                INTEGER PRIMARY KEY AUTOINCREMENT,
        event_id          TEXT UNIQUE,
        timestamp         TEXT,
        ingested_at       TEXT,
        severity          TEXT,
        event_type        TEXT,
        ecs_category      TEXT,
        ecs_kind          TEXT,
        action            TEXT,
        signature         TEXT,
        src_ip            TEXT,
        dest_ip           TEXT,
        dest_port         TEXT,
        proto             TEXT,
        host              TEXT,
        user              TEXT,
        asset_hostname    TEXT,
        asset_role        TEXT,
        asset_criticality TEXT,
        threat_label      TEXT,
        country           TEXT,
        raw_json          TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_ts       ON events(timestamp);
    CREATE INDEX IF NOT EXISTS idx_src      ON events(src_ip);
    CREATE INDEX IF NOT EXISTS idx_sev      ON events(severity);
    CREATE INDEX IF NOT EXISTS idx_ingested ON events(ingested_at);

    -- فاز ۳: Audit Log تمام تصمیمات AI و مداخلات تحلیلگر
    CREATE TABLE IF NOT EXISTS audit_log (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        logged_at    TEXT NOT NULL,
        event_type   TEXT NOT NULL,  -- ai_analysis | triage | feedback | qa
        incident_id  TEXT,
        ip           TEXT,
        actor        TEXT,           -- ai | analyst
        payload      TEXT NOT NULL,  -- JSON کامل رویداد
        score        REAL,
        triage_level TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_audit_type       ON audit_log(event_type);
    CREATE INDEX IF NOT EXISTS idx_audit_incident   ON audit_log(incident_id);
    CREATE INDEX IF NOT EXISTS idx_audit_ip         ON audit_log(ip);
    CREATE INDEX IF NOT EXISTS idx_audit_logged_at  ON audit_log(logged_at);

    -- فاز ۳: ذخیره مکالمات Q&A (multi-turn)
    CREATE TABLE IF NOT EXISTS qa_sessions (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id   TEXT NOT NULL,
        turn         INTEGER NOT NULL,
        logged_at    TEXT NOT NULL,
        ip_context   TEXT,
        question     TEXT NOT NULL,
        answer       TEXT NOT NULL,
        has_incident INTEGER DEFAULT 0
    );
    CREATE INDEX IF NOT EXISTS idx_qa_session ON qa_sessions(session_id);
    CREATE INDEX IF NOT EXISTS idx_qa_ip      ON qa_sessions(ip_context);
    """)

    _conn.commit()
    print(f"✅ Storage: دیتابیس آماده شد → {DB_PATH}")
    return _conn


def _ensure():
    if _conn is None:
        init_db()
    return _conn


# ── درج ─────────────────────────────────────────────────
def _event_id(e: dict) -> str:
    """اثر انگشت یکتا؛ اگر رویداد event_id از قبل نداشته باشد می‌سازیم."""
    if e.get("event_id"):
        return str(e["event_id"])
    basis = "|".join(str(e.get(k, "")) for k in
                     ("timestamp", "src_ip", "dest_ip", "dest_port", "action", "signature"))
    return hashlib.sha256(basis.encode()).hexdigest()[:24]


def store_events(events: list[dict]) -> int:
    """
    لیست رویدادهای نرمال‌شده را ذخیره می‌کند.
    رکوردهای با event_id تکراری نادیده گرفته می‌شوند (INSERT OR IGNORE).
    خروجی: تعداد رکوردهای واقعاً درج‌شده.
    """
    conn = _ensure()
    now = datetime.now(timezone.utc).isoformat()
    rows = []
    for e in events:
        rows.append((
            _event_id(e),
            e.get("timestamp", ""), now,
            e.get("severity", ""), e.get("event_type", ""),
            e.get("ecs_category", ""), e.get("ecs_kind", ""),
            e.get("action", ""), e.get("signature", ""),
            e.get("src_ip", ""), e.get("dest_ip", ""),
            str(e.get("dest_port", "")), e.get("proto", ""),
            e.get("host", ""), e.get("user", "") or e.get("username", ""),
            e.get("asset_hostname", ""), e.get("asset_role", ""),
            e.get("asset_criticality", ""), e.get("threat_label", ""),
            e.get("country", ""),
            json.dumps(e.get("_ecs", e), ensure_ascii=False, default=str),
        ))
    with _lock:
        cur = conn.executemany("""
            INSERT OR IGNORE INTO events (
              event_id, timestamp, ingested_at, severity, event_type,
              ecs_category, ecs_kind, action, signature, src_ip, dest_ip,
              dest_port, proto, host, user, asset_hostname, asset_role,
              asset_criticality, threat_label, country, raw_json
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, rows)
        conn.commit()
        inserted = cur.rowcount
    return inserted


# ── پرس‌وجو ─────────────────────────────────────────────
def get_recent(limit: int = 100) -> list[dict]:
    conn = _ensure()
    with _lock:
        cur = conn.execute("SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,))
        return [dict(r) for r in cur.fetchall()]


def get_by_ip(ip: str, limit: int = 500) -> list[dict]:
    conn = _ensure()
    with _lock:
        cur = conn.execute(
            "SELECT * FROM events WHERE src_ip=? OR dest_ip=? ORDER BY id DESC LIMIT ?",
            (ip, ip, limit))
        return [dict(r) for r in cur.fetchall()]


def get_stats() -> dict:
    """آمار خلاصه برای داشبورد."""
    conn = _ensure()
    with _lock:
        total = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        by_sev = {r[0] or "UNKNOWN": r[1] for r in
                  conn.execute("SELECT severity, COUNT(*) FROM events GROUP BY severity").fetchall()}
        uniq_src = conn.execute("SELECT COUNT(DISTINCT src_ip) FROM events WHERE src_ip!=''").fetchone()[0]
        threats = conn.execute("SELECT COUNT(*) FROM events WHERE threat_label!=''").fetchone()[0]
        span = conn.execute("SELECT MIN(timestamp), MAX(timestamp) FROM events").fetchone()
    return {
        "total_events": total,
        "by_severity": by_sev,
        "unique_source_ips": uniq_src,
        "threat_feed_hits": threats,
        "time_range": {"first": span[0], "last": span[1]},
        "db_path": DB_PATH,
    }


def purge_older_than(days: int) -> int:
    """پاک‌سازی رویدادهای قدیمی‌تر از N روز (بر اساس ingested_at)."""
    conn = _ensure()
    cutoff = datetime.now(timezone.utc).timestamp() - days * 86400
    cutoff_iso = datetime.fromtimestamp(cutoff, timezone.utc).isoformat()
    with _lock:
        cur = conn.execute("DELETE FROM events WHERE ingested_at < ?", (cutoff_iso,))
        conn.commit()
    return cur.rowcount


# ── فاز ۳: Audit Log ─────────────────────────────────────────

def log_audit(event_type: str, payload: dict, incident_id: str = "",
              ip: str = "", actor: str = "ai",
              score: float = None, triage_level: str = "") -> int:
    """
    ثبت هر تصمیم AI یا مداخله تحلیلگر در audit_log.
    event_type: ai_analysis | triage | feedback | qa | playbook
    """
    conn = _ensure()
    now  = datetime.now(timezone.utc).isoformat()
    with _lock:
        cur = conn.execute(
            """INSERT INTO audit_log
               (logged_at, event_type, incident_id, ip, actor, payload, score, triage_level)
               VALUES (?,?,?,?,?,?,?,?)""",
            (now, event_type, incident_id, ip, actor,
             json.dumps(payload, ensure_ascii=False, default=str),
             score, triage_level)
        )
        conn.commit()
    return cur.lastrowid


def get_audit_log(limit: int = 100, event_type: str = "",
                  ip: str = "") -> list[dict]:
    """بازیابی audit log با فیلتر اختیاری"""
    conn = _ensure()
    filters, params = [], []
    if event_type:
        filters.append("event_type=?"); params.append(event_type)
    if ip:
        filters.append("ip=?"); params.append(ip)
    where = ("WHERE " + " AND ".join(filters)) if filters else ""
    params.append(max(1, min(int(limit), 1000)))
    with _lock:
        cur = conn.execute(
            f"SELECT * FROM audit_log {where} ORDER BY id DESC LIMIT ?", params)
        return [dict(r) for r in cur.fetchall()]


# ── فاز ۳: Q&A Session Storage ───────────────────────────────

def save_qa_turn(session_id: str, turn: int, question: str, answer: str,
                 ip_context: str = "", has_incident: bool = False) -> int:
    """ذخیره یک turn از مکالمه Q&A"""
    conn = _ensure()
    now  = datetime.now(timezone.utc).isoformat()
    with _lock:
        cur = conn.execute(
            """INSERT INTO qa_sessions
               (session_id, turn, logged_at, ip_context, question, answer, has_incident)
               VALUES (?,?,?,?,?,?,?)""",
            (session_id, turn, now, ip_context, question, answer, int(has_incident))
        )
        conn.commit()
    return cur.lastrowid


def get_qa_history(session_id: str, limit: int = 10) -> list[dict]:
    """بازیابی تاریخچه مکالمه برای یک session"""
    conn = _ensure()
    with _lock:
        cur = conn.execute(
            """SELECT turn, question, answer, logged_at, ip_context
               FROM qa_sessions WHERE session_id=?
               ORDER BY turn ASC LIMIT ?""",
            (session_id, max(1, min(int(limit), 50)))
        )
        return [dict(r) for r in cur.fetchall()]


# ── تست مستقیم ──────────────────────────────────────────
if __name__ == "__main__":
    init_db(os.path.join(os.path.dirname(__file__), "data", "test_events.db"))
    sample = [
        {"timestamp": "2026-06-27T07:45:30", "severity": "CRITICAL", "event_type": "ssh",
         "action": "LOGIN_FAILED", "signature": "SSH brute force", "src_ip": "203.0.113.9",
         "dest_ip": "192.0.2.1", "dest_port": "22", "proto": "tcp", "host": "dc01",
         "asset_hostname": "dc01", "asset_criticality": "critical", "threat_label": "MALICIOUS",
         "ecs_category": "authentication", "ecs_kind": "alert", "_ecs": {"x": 1}},
    ]
    print("inserted:", store_events(sample))
    print("inserted again (dup):", store_events(sample))
    print("stats:", json.dumps(get_stats(), ensure_ascii=False, indent=2))
