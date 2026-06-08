from __future__ import annotations

import json
import os
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


@dataclass(frozen=True)
class DbPaths:
    data_dir: Path

    @property
    def db_path(self) -> Path:
        return self.data_dir / "minisiem.sqlite3"


def default_paths() -> DbPaths:
    base = Path(os.environ.get("LOCALAPPDATA", str(Path.home())))
    data_dir = base / "miniSIEM"
    return DbPaths(data_dir=data_dir)


def connect(db_path: Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(str(db_path))
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys = ON;")
    con.execute("PRAGMA journal_mode = WAL;")
    con.execute("PRAGMA synchronous = NORMAL;")
    return con


def migrate(con: sqlite3.Connection) -> None:
    con.executescript(
        """
        CREATE TABLE IF NOT EXISTS events (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            ts_utc          TEXT NOT NULL,
            channel         TEXT NOT NULL,
            provider        TEXT,
            event_id        INTEGER,
            level           INTEGER,
            computer        TEXT,
            record_id       INTEGER,
            message         TEXT,
            data_json       TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts_utc);
        CREATE INDEX IF NOT EXISTS idx_events_channel_ts ON events(channel, ts_utc);
        CREATE INDEX IF NOT EXISTS idx_events_eventid_ts ON events(event_id, ts_utc);

        CREATE TABLE IF NOT EXISTS alerts (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            ts_utc          TEXT NOT NULL,
            rule_id         TEXT NOT NULL,
            severity        TEXT NOT NULL,
            title           TEXT NOT NULL,
            details         TEXT,
            status          TEXT NOT NULL DEFAULT 'new'
        );

        CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts_utc);
        CREATE INDEX IF NOT EXISTS idx_alerts_status_ts ON alerts(status, ts_utc);

        CREATE TABLE IF NOT EXISTS actions (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            ts_utc          TEXT NOT NULL,
            alert_id        INTEGER,
            action_type     TEXT NOT NULL,
            target          TEXT,
            result          TEXT NOT NULL,
            details         TEXT,
            FOREIGN KEY(alert_id) REFERENCES alerts(id) ON DELETE SET NULL
        );

        CREATE INDEX IF NOT EXISTS idx_actions_ts ON actions(ts_utc);
        CREATE INDEX IF NOT EXISTS idx_actions_alert ON actions(alert_id);

        CREATE TABLE IF NOT EXISTS rules_state (
            rule_id     TEXT PRIMARY KEY,
            enabled     INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS settings (
            key     TEXT PRIMARY KEY,
            value   TEXT
        );

        CREATE TABLE IF NOT EXISTS rule_params (
            rule_id     TEXT NOT NULL,
            key         TEXT NOT NULL,
            value       TEXT,
            PRIMARY KEY(rule_id, key)
        );
        """
    )
    # Soft migration: add operator note/comment to existing DBs.
    # SQLite supports ADD COLUMN, but will fail if it already exists.
    try:
        con.execute("ALTER TABLE alerts ADD COLUMN comment TEXT;")
    except Exception:
        pass
    # Soft migration: parsed fields for Security logons (4624/4625)
    for col in ("parsed_account", "parsed_ip", "parsed_logon_type"):
        try:
            con.execute(f"ALTER TABLE events ADD COLUMN {col} TEXT;")
        except Exception:
            pass
    con.commit()


def _events_has_parsed_cols(con: sqlite3.Connection) -> bool:
    try:
        cur = con.execute("PRAGMA table_info(events)")
        cols = {str(r["name"]) for r in cur.fetchall()}
        return {"parsed_account", "parsed_ip", "parsed_logon_type"}.issubset(cols)
    except Exception:
        return False


def backfill_security_logon_parsed_fields(con: sqlite3.Connection, *, limit: int = 5000) -> int:
    """
    Populate parsed_account/parsed_ip/parsed_logon_type for existing rows.
    Only touches Security 4624/4625 rows where parsed_* is missing.
    Returns number of updated rows.
    """
    if not _events_has_parsed_cols(con):
        return 0

    cur = con.execute(
        """
        SELECT id, data_json
        FROM events
        WHERE channel = 'Security'
          AND event_id IN (4624, 4625)
          AND (parsed_account IS NULL OR parsed_ip IS NULL OR parsed_logon_type IS NULL)
        ORDER BY id DESC
        LIMIT ?
        """,
        (int(limit),),
    )
    rows = list(cur.fetchall())
    if not rows:
        return 0

    def _pick_ipv4(tokens: list[str]) -> str | None:
        for ss in tokens:
            s = (ss or "").strip()
            if s.count(".") != 3:
                continue
            parts = s.split(".")
            if len(parts) != 4:
                continue
            ok = True
            for p in parts:
                if not p.isdigit():
                    ok = False
                    break
                n = int(p)
                if n < 0 or n > 255:
                    ok = False
                    break
            if ok:
                return s
        return None

    def _pick_account(tokens: list[str]) -> str | None:
        for ss in tokens:
            s = (ss or "").strip()
            if "\\" in s and 1 < len(s) <= 128:
                return s
        return None

    def _pick_logon_type(tokens: list[str]) -> str | None:
        for ss in tokens:
            s = (ss or "").strip()
            if s.isdigit():
                n = int(s)
                if 2 <= n <= 13:
                    return str(n)
        return None

    upd: list[tuple[object, ...]] = []
    for r in rows:
        try:
            data = json.loads(r["data_json"] or "{}")
        except Exception:
            data = {}
        parsed = data.get("parsed") or {}
        inserts = data.get("StringInserts") or []
        tokens = [str(x) for x in inserts if x is not None]

        account = parsed.get("account") or _pick_account(tokens)
        ip = parsed.get("ip") or _pick_ipv4(tokens)
        logon_type = parsed.get("logon_type") or _pick_logon_type(tokens)

        upd.append((account, ip, logon_type, int(r["id"])))

    con.executemany(
        "UPDATE events SET parsed_account = ?, parsed_ip = ?, parsed_logon_type = ? WHERE id = ?",
        upd,
    )
    con.commit()
    return len(upd)

def _file_size_bytes(p: Path) -> int:
    try:
        return int(p.stat().st_size)
    except Exception:
        return 0


def get_db_file_stats(db_path: Path) -> dict[str, int]:
    """
    Return sizes on disk for main db and WAL/SHM sidecar files (bytes).
    Useful for UI/dashboard and operational checks.
    """
    return {
        "db": _file_size_bytes(db_path),
        "wal": _file_size_bytes(Path(str(db_path) + "-wal")),
        "shm": _file_size_bytes(Path(str(db_path) + "-shm")),
    }


def load_rules_state(con: sqlite3.Connection) -> dict[str, bool]:
    cur = con.execute("SELECT rule_id, enabled FROM rules_state")
    out: dict[str, bool] = {}
    for r in cur.fetchall():
        out[str(r["rule_id"])] = bool(int(r["enabled"]))
    return out


def set_rule_enabled(con: sqlite3.Connection, *, rule_id: str, enabled: bool) -> None:
    con.execute(
        """
        INSERT INTO rules_state(rule_id, enabled)
        VALUES(?, ?)
        ON CONFLICT(rule_id) DO UPDATE SET enabled = excluded.enabled
        """,
        (rule_id, 1 if enabled else 0),
    )
    con.commit()


def get_setting(con: sqlite3.Connection, key: str) -> str | None:
    cur = con.execute("SELECT value FROM settings WHERE key = ?", (key,))
    row = cur.fetchone()
    return None if row is None else (row["value"] if row["value"] is not None else None)


def set_setting(con: sqlite3.Connection, *, key: str, value: str | None) -> None:
    con.execute(
        """
        INSERT INTO settings(key, value)
        VALUES(?, ?)
        ON CONFLICT(key) DO UPDATE SET value = excluded.value
        """,
        (key, value),
    )
    con.commit()


def get_rule_param(con: sqlite3.Connection, *, rule_id: str, key: str) -> str | None:
    cur = con.execute("SELECT value FROM rule_params WHERE rule_id = ? AND key = ?", (rule_id, key))
    row = cur.fetchone()
    return None if row is None else (row["value"] if row["value"] is not None else None)


def set_rule_param(con: sqlite3.Connection, *, rule_id: str, key: str, value: str | None) -> None:
    con.execute(
        """
        INSERT INTO rule_params(rule_id, key, value)
        VALUES(?, ?, ?)
        ON CONFLICT(rule_id, key) DO UPDATE SET value = excluded.value
        """,
        (rule_id, key, value),
    )
    con.commit()


def now_utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def insert_event(
    con: sqlite3.Connection,
    *,
    ts_utc: str,
    channel: str,
    provider: str | None,
    event_id: int | None,
    level: int | None,
    computer: str | None,
    record_id: int | None,
    message: str | None,
    data: dict[str, Any] | None,
) -> int:
    parsed = (data or {}).get("parsed") or {}
    if _events_has_parsed_cols(con):
        cur = con.execute(
            """
            INSERT INTO events (
                ts_utc, channel, provider, event_id, level, computer, record_id, message, data_json,
                parsed_account, parsed_ip, parsed_logon_type
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                ts_utc,
                channel,
                provider,
                event_id,
                level,
                computer,
                record_id,
                message,
                json.dumps(data or {}, ensure_ascii=False),
                parsed.get("account"),
                parsed.get("ip"),
                parsed.get("logon_type"),
            ),
        )
    else:
        cur = con.execute(
            """
            INSERT INTO events (
                ts_utc, channel, provider, event_id, level, computer, record_id, message, data_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                ts_utc,
                channel,
                provider,
                event_id,
                level,
                computer,
                record_id,
                message,
                json.dumps(data or {}, ensure_ascii=False),
            ),
        )
    con.commit()
    return int(cur.lastrowid)


def insert_alert(
    con: sqlite3.Connection,
    *,
    rule_id: str,
    severity: str,
    title: str,
    details: str | None = None,
    ts_utc: str | None = None,
) -> int:
    cur = con.execute(
        """
        INSERT INTO alerts (ts_utc, rule_id, severity, title, details, status)
        VALUES (?, ?, ?, ?, ?, 'new')
        """,
        (ts_utc or now_utc_iso(), rule_id, severity, title, details),
    )
    con.commit()
    return int(cur.lastrowid)


def alert_exists_recently(
    con: sqlite3.Connection,
    *,
    rule_id: str,
    title: str,
    since_ts_utc: str,
) -> bool:
    cur = con.execute(
        """
        SELECT 1
        FROM alerts
        WHERE rule_id = ?
          AND title = ?
          AND ts_utc >= ?
        LIMIT 1
        """,
        (rule_id, title, since_ts_utc),
    )
    return cur.fetchone() is not None


def insert_action(
    con: sqlite3.Connection,
    *,
    action_type: str,
    result: str,
    target: str | None = None,
    details: str | None = None,
    alert_id: int | None = None,
    ts_utc: str | None = None,
) -> int:
    cur = con.execute(
        """
        INSERT INTO actions (ts_utc, alert_id, action_type, target, result, details)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (ts_utc or now_utc_iso(), alert_id, action_type, target, result, details),
    )
    con.commit()
    return int(cur.lastrowid)


def fetch_recent_events(con: sqlite3.Connection, limit: int = 200) -> list[sqlite3.Row]:
    cur = con.execute(
        "SELECT * FROM events ORDER BY ts_utc DESC, id DESC LIMIT ?",
        (int(limit),),
    )
    return list(cur.fetchall())


def search_events(
    con: sqlite3.Connection,
    *,
    ts_from_utc: str | None = None,
    ts_to_utc: str | None = None,
    channel: str | None = None,
    event_id: int | None = None,
    text: str | None = None,
    account: str | None = None,
    ip: str | None = None,
    logon_type: str | None = None,
    limit: int = 500,
) -> list[sqlite3.Row]:
    where = []
    params: list[object] = []
    if ts_from_utc:
        where.append("ts_utc >= ?")
        params.append(ts_from_utc)
    if ts_to_utc:
        where.append("ts_utc <= ?")
        params.append(ts_to_utc)
    if channel:
        where.append("channel = ?")
        params.append(channel)
    if event_id is not None:
        where.append("event_id = ?")
        params.append(int(event_id))
    if text:
        where.append("(provider LIKE ? OR computer LIKE ? OR data_json LIKE ?)")
        like = f"%{text}%"
        params.extend([like, like, like])
    if account:
        where.append("parsed_account LIKE ?")
        params.append(f"%{account}%")
    if ip:
        where.append("parsed_ip LIKE ?")
        params.append(f"%{ip}%")
    if logon_type:
        where.append("parsed_logon_type = ?")
        params.append(str(logon_type))

    sql = "SELECT * FROM events"
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY ts_utc DESC, id DESC LIMIT ?"
    params.append(int(limit))
    cur = con.execute(sql, tuple(params))
    return list(cur.fetchall())


def get_event_by_id(con: sqlite3.Connection, event_row_id: int) -> sqlite3.Row | None:
    cur = con.execute("SELECT * FROM events WHERE id = ?", (int(event_row_id),))
    return cur.fetchone()


def update_alert_status(con: sqlite3.Connection, alert_id: int, status: str) -> None:
    con.execute("UPDATE alerts SET status = ? WHERE id = ?", (status, int(alert_id)))
    con.commit()

def update_alert_comment(con: sqlite3.Connection, alert_id: int, comment: str | None) -> None:
    con.execute("UPDATE alerts SET comment = ? WHERE id = ?", (comment, int(alert_id)))
    con.commit()


def fetch_recent_alerts(con: sqlite3.Connection, limit: int = 200) -> list[sqlite3.Row]:
    cur = con.execute(
        "SELECT * FROM alerts ORDER BY ts_utc DESC, id DESC LIMIT ?",
        (int(limit),),
    )
    return list(cur.fetchall())


def fetch_recent_actions(con: sqlite3.Connection, limit: int = 200) -> list[sqlite3.Row]:
    cur = con.execute(
        "SELECT * FROM actions ORDER BY ts_utc DESC, id DESC LIMIT ?",
        (int(limit),),
    )
    return list(cur.fetchall())

def fetch_actions_for_alert(con: sqlite3.Connection, *, alert_id: int, limit: int = 200) -> list[sqlite3.Row]:
    cur = con.execute(
        """
        SELECT * FROM actions
        WHERE alert_id = ?
        ORDER BY ts_utc DESC, id DESC
        LIMIT ?
        """,
        (int(alert_id), int(limit)),
    )
    return list(cur.fetchall())


def bulk_insert_events(con: sqlite3.Connection, rows: Iterable[dict[str, Any]]) -> int:
    data_rows: list[tuple[object, ...]] = []
    has_parsed = _events_has_parsed_cols(con)
    for r in rows:
        data = r.get("data") or {}
        parsed = data.get("parsed") or {}
        if has_parsed:
            data_rows.append(
                (
                    r["ts_utc"],
                    r["channel"],
                    r.get("provider"),
                    r.get("event_id"),
                    r.get("level"),
                    r.get("computer"),
                    r.get("record_id"),
                    r.get("message"),
                    json.dumps(data, ensure_ascii=False),
                    parsed.get("account"),
                    parsed.get("ip"),
                    parsed.get("logon_type"),
                )
            )
        else:
            data_rows.append(
                (
                    r["ts_utc"],
                    r["channel"],
                    r.get("provider"),
                    r.get("event_id"),
                    r.get("level"),
                    r.get("computer"),
                    r.get("record_id"),
                    r.get("message"),
                    json.dumps(data, ensure_ascii=False),
                )
            )
    if not data_rows:
        return 0
    if has_parsed:
        con.executemany(
            """
            INSERT INTO events (
                ts_utc, channel, provider, event_id, level, computer, record_id, message, data_json,
                parsed_account, parsed_ip, parsed_logon_type
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            data_rows,
        )
    else:
        con.executemany(
            """
            INSERT INTO events (
                ts_utc, channel, provider, event_id, level, computer, record_id, message, data_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            data_rows,
        )
    con.commit()
    return len(data_rows)


def count_rows(con: sqlite3.Connection, table: str) -> int:
    if table not in {"events", "alerts", "actions"}:
        raise ValueError("invalid table")
    cur = con.execute(f"SELECT COUNT(*) AS n FROM {table}")
    row = cur.fetchone()
    return 0 if row is None else int(row["n"])


def count_events_since(con: sqlite3.Connection, since_ts_utc: str) -> int:
    cur = con.execute("SELECT COUNT(*) AS n FROM events WHERE ts_utc >= ?", (since_ts_utc,))
    row = cur.fetchone()
    return 0 if row is None else int(row["n"])


def count_alerts_by_status_since(con: sqlite3.Connection, since_ts_utc: str) -> dict[str, int]:
    cur = con.execute(
        """
        SELECT status, COUNT(*) AS n
        FROM alerts
        WHERE ts_utc >= ?
        GROUP BY status
        """,
        (since_ts_utc,),
    )
    out: dict[str, int] = {}
    for r in cur.fetchall():
        out[str(r["status"])] = int(r["n"])
    return out


def top_event_ids_since(con: sqlite3.Connection, since_ts_utc: str, limit: int = 10) -> list[tuple[int | None, int]]:
    cur = con.execute(
        """
        SELECT event_id, COUNT(*) AS n
        FROM events
        WHERE ts_utc >= ?
        GROUP BY event_id
        ORDER BY n DESC
        LIMIT ?
        """,
        (since_ts_utc, int(limit)),
    )
    out: list[tuple[int | None, int]] = []
    for r in cur.fetchall():
        out.append((r["event_id"], int(r["n"])))
    return out


def top_channels_since(con: sqlite3.Connection, since_ts_utc: str, limit: int = 10) -> list[tuple[str, int]]:
    cur = con.execute(
        """
        SELECT channel, COUNT(*) AS n
        FROM events
        WHERE ts_utc >= ?
        GROUP BY channel
        ORDER BY n DESC
        LIMIT ?
        """,
        (since_ts_utc, int(limit)),
    )
    out: list[tuple[str, int]] = []
    for r in cur.fetchall():
        out.append((str(r["channel"]), int(r["n"])))
    return out


def count_security_logons_since(con: sqlite3.Connection, since_ts_utc: str, *, event_id: int) -> int:
    """
    Count Security events for a given EventID since a timestamp (UTC ISO string).
    Intended for 4624/4625 dashboard metrics.
    """
    cur = con.execute(
        """
        SELECT COUNT(*) AS n
        FROM events
        WHERE ts_utc >= ?
          AND channel = 'Security'
          AND event_id = ?
        """,
        (since_ts_utc, int(event_id)),
    )
    row = cur.fetchone()
    return 0 if row is None else int(row["n"])


def _normalize_ip_value(v: str | None) -> str | None:
    if v is None:
        return None
    s = str(v).strip()
    if not s or s in ("-", "::1", "127.0.0.1", "0.0.0.0"):
        return None
    return s


def top_security_4625_by_ip_since(con: sqlite3.Connection, since_ts_utc: str, limit: int = 10) -> list[tuple[str, int]]:
    """
    Top source IPs for Security 4625 in a time window.
    Uses parsed_ip column; ignores empty/local placeholders.
    """
    cur = con.execute(
        """
        SELECT parsed_ip AS ip, COUNT(*) AS n
        FROM events
        WHERE ts_utc >= ?
          AND channel = 'Security'
          AND event_id = 4625
          AND parsed_ip IS NOT NULL
          AND parsed_ip NOT IN ('', '-', '::1', '127.0.0.1', '0.0.0.0')
        GROUP BY parsed_ip
        ORDER BY n DESC
        LIMIT ?
        """,
        (since_ts_utc, int(limit)),
    )
    out: list[tuple[str, int]] = []
    for r in cur.fetchall():
        ip = _normalize_ip_value(r["ip"])
        if not ip:
            continue
        out.append((ip, int(r["n"])))
    return out


def top_security_4625_by_account_since(con: sqlite3.Connection, since_ts_utc: str, limit: int = 10) -> list[tuple[str, int]]:
    """
    Top accounts for Security 4625 in a time window.
    Uses parsed_account column; ignores empty placeholders.
    """
    cur = con.execute(
        """
        SELECT parsed_account AS acc, COUNT(*) AS n
        FROM events
        WHERE ts_utc >= ?
          AND channel = 'Security'
          AND event_id = 4625
          AND parsed_account IS NOT NULL
          AND parsed_account NOT IN ('', '-')
        GROUP BY parsed_account
        ORDER BY n DESC
        LIMIT ?
        """,
        (since_ts_utc, int(limit)),
    )
    out: list[tuple[str, int]] = []
    for r in cur.fetchall():
        acc = str(r["acc"] or "").strip()
        if not acc or acc == "-":
            continue
        out.append((acc, int(r["n"])))
    return out


def top_security_4625_by_logon_type_since(con: sqlite3.Connection, since_ts_utc: str, limit: int = 10) -> list[tuple[str, int]]:
    """
    Top logon types for Security 4625 in a time window.
    Uses parsed_logon_type column; ignores empty placeholders.
    """
    cur = con.execute(
        """
        SELECT parsed_logon_type AS lt, COUNT(*) AS n
        FROM events
        WHERE ts_utc >= ?
          AND channel = 'Security'
          AND event_id = 4625
          AND parsed_logon_type IS NOT NULL
          AND parsed_logon_type NOT IN ('', '-')
        GROUP BY parsed_logon_type
        ORDER BY n DESC
        LIMIT ?
        """,
        (since_ts_utc, int(limit)),
    )
    out: list[tuple[str, int]] = []
    for r in cur.fetchall():
        lt = str(r["lt"] or "").strip()
        if not lt or lt == "-":
            continue
        out.append((lt, int(r["n"])))
    return out


def top_security_4625_rdp_by_ip_since(con: sqlite3.Connection, since_ts_utc: str, limit: int = 10) -> list[tuple[str, int]]:
    """
    Top source IPs for RDP failed logons: Security 4625 with logon_type=10.
    """
    cur = con.execute(
        """
        SELECT parsed_ip AS ip, COUNT(*) AS n
        FROM events
        WHERE ts_utc >= ?
          AND channel = 'Security'
          AND event_id = 4625
          AND parsed_logon_type = '10'
          AND parsed_ip IS NOT NULL
          AND parsed_ip NOT IN ('', '-', '::1', '127.0.0.1', '0.0.0.0')
        GROUP BY parsed_ip
        ORDER BY n DESC
        LIMIT ?
        """,
        (since_ts_utc, int(limit)),
    )
    out: list[tuple[str, int]] = []
    for r in cur.fetchall():
        ip = _normalize_ip_value(r["ip"])
        if not ip:
            continue
        out.append((ip, int(r["n"])))
    return out


def count_security_4625_by_logon_type_since(con: sqlite3.Connection, since_ts_utc: str, *, logon_type: str) -> int:
    """
    Count Security 4625 events for a given parsed_logon_type since timestamp.
    Useful for quick metrics (e.g. logon_type=10 for RDP).
    """
    cur = con.execute(
        """
        SELECT COUNT(*) AS n
        FROM events
        WHERE ts_utc >= ?
          AND channel = 'Security'
          AND event_id = 4625
          AND parsed_logon_type = ?
        """,
        (since_ts_utc, str(logon_type)),
    )
    row = cur.fetchone()
    return 0 if row is None else int(row["n"])


def normalize_legacy_event_ids(con: sqlite3.Connection, *, limit: int = 200_000) -> int:
    """
    Fix previously stored legacy-packed event_id values (very large or negative),
    rewriting them to the canonical low-16-bit Windows Event ID.

    Returns number of updated rows.
    """
    cur = con.execute(
        """
        UPDATE events
        SET event_id = (event_id & 65535)
        WHERE event_id IS NOT NULL
          AND (event_id < 0 OR event_id > 65535)
        LIMIT ?
        """,
        (int(limit),),
    )
    con.commit()
    return int(cur.rowcount or 0)


def prune_events_older_than(con: sqlite3.Connection, cutoff_ts_utc: str) -> int:
    cur = con.execute("DELETE FROM events WHERE ts_utc < ?", (cutoff_ts_utc,))
    con.commit()
    return int(cur.rowcount or 0)


def prune_actions_older_than(con: sqlite3.Connection, cutoff_ts_utc: str) -> int:
    cur = con.execute("DELETE FROM actions WHERE ts_utc < ?", (cutoff_ts_utc,))
    con.commit()
    return int(cur.rowcount or 0)


def prune_alerts_older_than(con: sqlite3.Connection, cutoff_ts_utc: str) -> int:
    cur = con.execute("DELETE FROM alerts WHERE ts_utc < ?", (cutoff_ts_utc,))
    con.commit()
    return int(cur.rowcount or 0)

def checkpoint_wal(con: sqlite3.Connection) -> None:
    """
    Best-effort WAL checkpoint to keep WAL size under control.
    Safe to call on a live DB; does nothing if journal_mode != WAL.
    """
    try:
        con.execute("PRAGMA wal_checkpoint(TRUNCATE);")
        con.commit()
    except Exception:
        # If PRAGMA isn't supported or DB is busy, ignore.
        pass


def vacuum(con: sqlite3.Connection) -> None:
    """
    Reclaim free pages on disk.
    Note: VACUUM can take time on large DBs.
    """
    con.execute("VACUUM;")
    con.commit()


def prune_all_older_than(con: sqlite3.Connection, cutoff_ts_utc: str) -> dict[str, int]:
    """
    Prune events/alerts/actions older than cutoff.
    Returns deleted counts.
    """
    de = prune_events_older_than(con, cutoff_ts_utc)
    da = prune_alerts_older_than(con, cutoff_ts_utc)
    dac = prune_actions_older_than(con, cutoff_ts_utc)
    return {"events": de, "alerts": da, "actions": dac}


def clear_table(con: sqlite3.Connection, table: str) -> None:
    if table not in {"events", "alerts", "actions"}:
        raise ValueError("invalid table")
    con.execute(f"DELETE FROM {table}")
    con.commit()


def delete_demo_data(con: sqlite3.Connection) -> dict[str, int]:
    """
    Delete synthetic demo rows created by the app (provider='DEMO', rule_id='DEMO', action_type='demo_*').
    Returns deleted counts.
    """
    cur_e = con.execute("DELETE FROM events WHERE provider = 'DEMO'")
    cur_a = con.execute("DELETE FROM actions WHERE action_type LIKE 'demo_%'")
    cur_al = con.execute("DELETE FROM alerts WHERE rule_id = 'DEMO'")
    con.commit()
    return {
        "events": int(cur_e.rowcount or 0),
        "actions": int(cur_a.rowcount or 0),
        "alerts": int(cur_al.rowcount or 0),
    }


def fetch_events_since(con: sqlite3.Connection, ts_utc: str, limit: int = 5000) -> list[sqlite3.Row]:
    cur = con.execute(
        """
        SELECT * FROM events
        WHERE ts_utc >= ?
        ORDER BY ts_utc ASC, id ASC
        LIMIT ?
        """,
        (ts_utc, int(limit)),
    )
    return list(cur.fetchall())


def fetch_events_between(
    con: sqlite3.Connection,
    *,
    ts_from_utc: str,
    ts_to_utc: str,
    limit: int = 1000,
) -> list[sqlite3.Row]:
    cur = con.execute(
        """
        SELECT * FROM events
        WHERE ts_utc >= ?
          AND ts_utc <= ?
        ORDER BY ts_utc ASC, id ASC
        LIMIT ?
        """,
        (ts_from_utc, ts_to_utc, int(limit)),
    )
    return list(cur.fetchall())

