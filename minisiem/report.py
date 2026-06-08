from __future__ import annotations

import json
import html
import sqlite3
from datetime import datetime, timedelta, timezone

from minisiem.winsec import logon_type_label


def build_html_report(con: sqlite3.Connection, *, title: str = "miniSIEM report") -> str:
    now_dt = datetime.now(timezone.utc)
    now = now_dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    events_cnt = con.execute("SELECT COUNT(1) AS c FROM events").fetchone()["c"]
    alerts_cnt = con.execute("SELECT COUNT(1) AS c FROM alerts").fetchone()["c"]
    actions_cnt = con.execute("SELECT COUNT(1) AS c FROM actions").fetchone()["c"]

    since_24h = (now_dt - timedelta(hours=24)).isoformat()
    ev_24h = con.execute("SELECT COUNT(1) AS c FROM events WHERE ts_utc >= ?", (since_24h,)).fetchone()["c"]
    al_24h = con.execute("SELECT COUNT(1) AS c FROM alerts WHERE ts_utc >= ?", (since_24h,)).fetchone()["c"]

    top_event_ids = con.execute(
        """
        SELECT event_id, COUNT(*) AS n
        FROM events
        WHERE ts_utc >= ?
        GROUP BY event_id
        ORDER BY n DESC
        LIMIT 10
        """,
        (since_24h,),
    ).fetchall()
    top_channels = con.execute(
        """
        SELECT channel, COUNT(*) AS n
        FROM events
        WHERE ts_utc >= ?
        GROUP BY channel
        ORDER BY n DESC
        LIMIT 10
        """,
        (since_24h,),
    ).fetchall()

    rules_state = con.execute("SELECT rule_id, enabled FROM rules_state ORDER BY rule_id ASC").fetchall()

    recent_alerts = con.execute(
        "SELECT ts_utc, severity, rule_id, title, status FROM alerts ORDER BY ts_utc DESC, id DESC LIMIT 50"
    ).fetchall()
    recent_actions = con.execute(
        "SELECT ts_utc, action_type, target, result, details FROM actions ORDER BY ts_utc DESC, id DESC LIMIT 50"
    ).fetchall()
    recent_events = con.execute(
        "SELECT ts_utc, channel, event_id, provider, computer, record_id FROM events ORDER BY ts_utc DESC, id DESC LIMIT 50"
    ).fetchall()

    def tr(cells: list[str]) -> str:
        return "<tr>" + "".join(f"<td>{html.escape(c)}</td>" for c in cells) + "</tr>"

    top_eid_rows = "\n".join(tr([str(r["event_id"]), str(r["n"])]) for r in top_event_ids)
    top_ch_rows = "\n".join(tr([str(r["channel"]), str(r["n"])]) for r in top_channels)
    rules_rows = "\n".join(tr([str(r["rule_id"]), "on" if int(r["enabled"]) else "off"]) for r in rules_state)

    alerts_rows = "\n".join(
        tr([str(r["ts_utc"]), str(r["severity"]), str(r["rule_id"]), str(r["title"]), str(r["status"])])
        for r in recent_alerts
    )
    actions_rows = "\n".join(
        tr(
            [
                str(r["ts_utc"]),
                str(r["action_type"]),
                str(r["target"] or ""),
                str(r["result"]),
                str(r["details"] or ""),
            ]
        )
        for r in recent_actions
    )
    events_rows = "\n".join(
        tr(
            [
                str(r["ts_utc"]),
                str(r["channel"]),
                str(r["event_id"]),
                str(r["provider"] or ""),
                str(r["computer"] or ""),
                str(r["record_id"] or ""),
            ]
        )
        for r in recent_events
    )

    return f"""<!doctype html>
<html lang="ru">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>{html.escape(title)}</title>
  <style>
    body {{ font-family: Segoe UI, Arial, sans-serif; margin: 24px; }}
    .cards {{ display: flex; gap: 12px; flex-wrap: wrap; }}
    .card {{ border: 1px solid #ddd; border-radius: 10px; padding: 12px 14px; min-width: 200px; }}
    h1 {{ margin: 0 0 4px 0; }}
    h2 {{ margin-top: 22px; }}
    table {{ border-collapse: collapse; width: 100%; }}
    th, td {{ border: 1px solid #ddd; padding: 8px; vertical-align: top; }}
    th {{ background: #f6f6f6; text-align: left; }}
    .muted {{ color: #666; }}
  </style>
</head>
<body>
  <h1>{html.escape(title)}</h1>
  <div class="muted">Сгенерировано: {html.escape(now)}</div>

  <div class="cards" style="margin-top: 12px;">
    <div class="card"><div class="muted">События</div><div style="font-size: 28px;">{events_cnt}</div></div>
    <div class="card"><div class="muted">Алерты</div><div style="font-size: 28px;">{alerts_cnt}</div></div>
    <div class="card"><div class="muted">Действия</div><div style="font-size: 28px;">{actions_cnt}</div></div>
    <div class="card"><div class="muted">За 24 часа</div><div>events: <b>{ev_24h}</b></div><div>alerts: <b>{al_24h}</b></div></div>
  </div>

  <h2>Топ EventID за 24 часа</h2>
  <table>
    <thead><tr><th>event_id</th><th>count</th></tr></thead>
    <tbody>{top_eid_rows}</tbody>
  </table>

  <h2>Топ channels за 24 часа</h2>
  <table>
    <thead><tr><th>channel</th><th>count</th></tr></thead>
    <tbody>{top_ch_rows}</tbody>
  </table>

  <h2>Состояние правил (SQLite)</h2>
  <table>
    <thead><tr><th>rule_id</th><th>enabled</th></tr></thead>
    <tbody>{rules_rows}</tbody>
  </table>

  <h2>Последние алерты (50)</h2>
  <table>
    <thead>
      <tr><th>ts_utc</th><th>severity</th><th>rule_id</th><th>title</th><th>status</th></tr>
    </thead>
    <tbody>
      {alerts_rows}
    </tbody>
  </table>

  <h2>Последние действия (50)</h2>
  <table>
    <thead>
      <tr><th>ts_utc</th><th>action_type</th><th>target</th><th>result</th><th>details</th></tr>
    </thead>
    <tbody>
      {actions_rows}
    </tbody>
  </table>

  <h2>Последние события (50)</h2>
  <table>
    <thead>
      <tr><th>ts_utc</th><th>channel</th><th>event_id</th><th>provider</th><th>computer</th><th>record_id</th></tr>
    </thead>
    <tbody>
      {events_rows}
    </tbody>
  </table>
</body>
</html>
"""


def build_alert_html_report(con: sqlite3.Connection, *, alert_id: int, title: str = "miniSIEM incident report") -> str:
    row = con.execute("SELECT * FROM alerts WHERE id = ?", (int(alert_id),)).fetchone()
    if row is None:
        return "<html><body><h1>Alert not found</h1></body></html>"

    now_dt = datetime.now(timezone.utc)
    now = now_dt.strftime("%Y-%m-%d %H:%M:%S UTC")

    # related events: +-10 minutes
    try:
        ts = str(row["ts_utc"])
        dt = datetime.fromisoformat(ts)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        dt = dt.astimezone(timezone.utc)
        ts_from = (dt - timedelta(minutes=10)).isoformat()
        ts_to = (dt + timedelta(minutes=10)).isoformat()
        rel_events = con.execute(
            """
            SELECT ts_utc, channel, event_id, parsed_account, parsed_ip, parsed_logon_type, provider, computer, record_id
            FROM events
            WHERE ts_utc >= ?
              AND ts_utc <= ?
            ORDER BY ts_utc ASC, id ASC
            LIMIT 500
            """,
            (ts_from, ts_to),
        ).fetchall()
    except Exception:
        rel_events = []

    rel_actions = con.execute(
        """
        SELECT ts_utc, action_type, target, result, details
        FROM actions
        WHERE alert_id = ?
        ORDER BY ts_utc ASC, id ASC
        LIMIT 500
        """,
        (int(alert_id),),
    ).fetchall()

    def tr(cells: list[str]) -> str:
        return "<tr>" + "".join(f"<td>{html.escape(c)}</td>" for c in cells) + "</tr>"

    events_rows = "\n".join(
        tr(
            [
                str(r["ts_utc"]),
                str(r["channel"]),
                str(r["event_id"]),
                str(r["parsed_account"] or ""),
                str(r["parsed_ip"] or ""),
                (
                    (
                        f"{r['parsed_logon_type']} ({logon_type_label(r['parsed_logon_type'])})"
                        if logon_type_label(r["parsed_logon_type"])
                        else str(r["parsed_logon_type"] or "")
                    )
                    if str(r["channel"]) == "Security" and int(r["event_id"] or 0) in (4624, 4625)
                    else ""
                ),
                str(r["provider"] or ""),
                str(r["computer"] or ""),
                str(r["record_id"] or ""),
            ]
        )
        for r in rel_events
    )
    actions_rows = "\n".join(
        tr(
            [
                str(r["ts_utc"]),
                str(r["action_type"]),
                str(r["target"] or ""),
                str(r["result"]),
                str(r["details"] or ""),
            ]
        )
        for r in rel_actions
    )

    comment = str(row["comment"] or "")
    details = str(row["details"] or "")

    return f"""<!doctype html>
<html lang="ru">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>{html.escape(title)}</title>
  <style>
    body {{ font-family: Segoe UI, Arial, sans-serif; margin: 24px; }}
    h1 {{ margin: 0 0 4px 0; }}
    h2 {{ margin-top: 22px; }}
    table {{ border-collapse: collapse; width: 100%; }}
    th, td {{ border: 1px solid #ddd; padding: 8px; vertical-align: top; }}
    th {{ background: #f6f6f6; text-align: left; }}
    .muted {{ color: #666; }}
    .box {{ border: 1px solid #ddd; border-radius: 10px; padding: 12px 14px; }}
    pre {{ white-space: pre-wrap; }}
  </style>
</head>
<body>
  <h1>{html.escape(title)}</h1>
  <div class="muted">Сгенерировано: {html.escape(now)}</div>

  <h2>Алерт</h2>
  <div class="box">
    <div><b>ID:</b> {html.escape(str(row["id"]))}</div>
    <div><b>ts_utc:</b> {html.escape(str(row["ts_utc"]))}</div>
    <div><b>severity:</b> {html.escape(str(row["severity"]))}</div>
    <div><b>rule_id:</b> {html.escape(str(row["rule_id"]))}</div>
    <div><b>title:</b> {html.escape(str(row["title"]))}</div>
    <div><b>status:</b> {html.escape(str(row["status"]))}</div>
  </div>

  <h2>Details</h2>
  <div class="box"><pre>{html.escape(details)}</pre></div>

  <h2>Комментарий аналитика</h2>
  <div class="box"><pre>{html.escape(comment)}</pre></div>

  <h2>Действия (Actions)</h2>
  <table>
    <thead><tr><th>ts_utc</th><th>action_type</th><th>target</th><th>result</th><th>details</th></tr></thead>
    <tbody>{actions_rows}</tbody>
  </table>

  <h2>События вокруг алерта (±10 минут)</h2>
  <table>
    <thead>
      <tr>
        <th>ts_utc</th><th>channel</th><th>event_id</th>
        <th>account</th><th>ip</th><th>logon_type</th>
        <th>provider</th><th>computer</th><th>record_id</th>
      </tr>
    </thead>
    <tbody>{events_rows}</tbody>
  </table>
</body>
</html>
"""


def build_alert_json_report(con: sqlite3.Connection, *, alert_id: int) -> str:
    """
    Export a single incident (alert) as JSON for offline analysis / appendix.
    Includes alert, actions and related events (±10 min) with parsed fields.
    Returns JSON string (pretty, UTF-8).
    """
    row = con.execute("SELECT * FROM alerts WHERE id = ?", (int(alert_id),)).fetchone()
    if row is None:
        return json.dumps({"error": "Alert not found", "alert_id": int(alert_id)}, ensure_ascii=False, indent=2)

    # related events: +-10 minutes
    try:
        ts = str(row["ts_utc"])
        dt = datetime.fromisoformat(ts)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        dt = dt.astimezone(timezone.utc)
        ts_from = (dt - timedelta(minutes=10)).isoformat()
        ts_to = (dt + timedelta(minutes=10)).isoformat()
        rel_events = con.execute(
            """
            SELECT id, ts_utc, channel, event_id, parsed_account, parsed_ip, parsed_logon_type, provider, computer, record_id, message, data_json
            FROM events
            WHERE ts_utc >= ?
              AND ts_utc <= ?
            ORDER BY ts_utc ASC, id ASC
            LIMIT 500
            """,
            (ts_from, ts_to),
        ).fetchall()
    except Exception:
        rel_events = []

    rel_actions = con.execute(
        """
        SELECT id, ts_utc, action_type, target, result, details
        FROM actions
        WHERE alert_id = ?
        ORDER BY ts_utc ASC, id ASC
        LIMIT 500
        """,
        (int(alert_id),),
    ).fetchall()

    alert_obj = {k: row[k] for k in row.keys()}

    actions_obj: list[dict[str, object]] = []
    for a in rel_actions:
        actions_obj.append({k: a[k] for k in a.keys()})

    events_obj: list[dict[str, object]] = []
    for e in rel_events:
        item = {k: e[k] for k in e.keys()}
        lt = item.get("parsed_logon_type")
        lbl = logon_type_label(lt)
        if lbl:
            item["parsed_logon_type_label"] = lbl
        # Try to decode data_json so JSON report is structured
        try:
            item["data"] = json.loads(str(item.get("data_json") or "{}"))
        except Exception:
            item["data"] = None
        events_obj.append(item)

    obj = {
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "alert": alert_obj,
        "actions": actions_obj,
        "events_window": {"from_utc": ts_from, "to_utc": ts_to},
        "events": events_obj,
    }
    return json.dumps(obj, ensure_ascii=False, indent=2)
