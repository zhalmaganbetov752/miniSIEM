from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from pathlib import Path

import yaml


DEFAULT_RULES_YAML = """\
rules:
  - id: WIN-SEC-4625-BURST
    title: "Brute-force: много неудачных входов"
    description: "Если за короткое окно много событий Security 4625 — создаётся алерт."
    mitre:
      - "T1110 Brute Force"
    severity: high
    detector: failed_logon_burst
    enabled_by_default: true
    params:
      threshold: 5
      window_minutes: 5

  - id: WIN-SEC-4625-BURST-BY-IP
    title: "Brute-force: burst по IP"
    description: "Security 4625: много ошибок входа с одного IP за окно времени (использует parsed.ip если есть)."
    mitre:
      - "T1110 Brute Force"
    severity: high
    detector: failed_logon_burst_by_ip
    enabled_by_default: true
    params:
      threshold: 8
      window_minutes: 5

  - id: WIN-SEC-4625-RDP-BURST-BY-IP
    title: "RDP brute-force: burst по IP"
    description: "Security 4625 с logon_type=10 (RDP): много ошибок входа с одного IP за окно времени."
    mitre:
      - "T1110 Brute Force"
      - "T1021.001 Remote Services: RDP"
    severity: critical
    detector: failed_logon_burst_rdp_by_ip
    enabled_by_default: true
    params:
      threshold: 6
      window_minutes: 5

  - id: WIN-SEC-4625-BURST-BY-ACCOUNT
    title: "Brute-force: burst по аккаунту"
    description: "Security 4625: много ошибок входа по одному аккаунту за окно времени (использует parsed.account если есть)."
    severity: high
    detector: failed_logon_burst_by_account
    enabled_by_default: true
    params:
      threshold: 8
      window_minutes: 10

  - id: WIN-SEC-1102-CLEARED
    title: "Очищен Security журнал"
    description: "Security 1102 часто означает попытку скрыть следы."
    mitre:
      - "T1070 Indicator Removal"
    severity: critical
    detector: security_log_cleared
    enabled_by_default: true

  - id: WIN-SYSMON-PS-ENC
    title: "PowerShell EncodedCommand (Sysmon)"
    description: "Sysmon 1: запуск PowerShell с -enc/-EncodedCommand."
    mitre:
      - "T1059.001 PowerShell"
    severity: high
    detector: powershell_encoded_sysmon
    enabled_by_default: true

  - id: WIN-SEC-4624-AFTER-FAIL
    title: "Успешный вход после серии ошибок"
    description: "Security 4624 после нескольких 4625 за окно времени (типичный признак brute-force)."
    severity: high
    detector: success_after_fail
    enabled_by_default: true
    params:
      threshold: 5
      window_minutes: 10

  - id: WIN-PROC-SUSPICIOUS
    title: "Подозрительный запуск cmd/powershell"
    description: "Сигнализирует по ключевым словам в строке (works best with Sysmon; fallback на Security 4688 если включено)."
    severity: medium
    detector: suspicious_cmdline
    enabled_by_default: true

  - id: WIN-CORR-BRUTE-LOGIN-PROC
    title: "Корреляция: brute-force → успешный вход → подозрительный процесс"
    description: "Цепочка в окне времени: 4625 burst, затем 4624, затем подозрительный запуск (Sysmon 1 или Security 4688)."
    severity: critical
    detector: corr_brute_login_proc
    enabled_by_default: true
    params:
      fail_threshold: 5
      fail_window_minutes: 10
      chain_window_minutes: 15
"""


@dataclass(frozen=True)
class Alert:
    rule_id: str
    severity: str
    title: str
    details: str | None = None


def _parse_ts(ts_utc: str) -> datetime:
    # ISO 8601 with timezone (we store UTC)
    dt = datetime.fromisoformat(ts_utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


@dataclass(frozen=True)
class RuleDef:
    rule_id: str
    title: str
    description: str
    severity: str
    detector: str
    enabled_by_default: bool = True
    params: dict[str, str] | None = None
    mitre: list[str] | None = None


def ensure_default_rules(rules_dir: Path) -> Path:
    """
    Ensure rules directory exists and contains default.yml (editable by user).
    Returns the rules_dir.
    """
    rules_dir.mkdir(parents=True, exist_ok=True)
    default_path = rules_dir / "default.yml"
    if not default_path.exists():
        default_path.write_text(DEFAULT_RULES_YAML, encoding="utf-8")
    return rules_dir


def load_rule_defs(rules_dir: Path) -> list[RuleDef]:
    """
    Load YAML rules from rules_dir/*.yml, merge into a list.
    """
    out: list[RuleDef] = []
    if not rules_dir.exists():
        return out
    for p in sorted(rules_dir.glob("*.yml")):
        try:
            doc = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        except Exception:
            continue
        items = doc.get("rules") or []
        if not isinstance(items, list):
            continue
        for r in items:
            if not isinstance(r, dict):
                continue
            rid = str(r.get("id") or "").strip()
            det = str(r.get("detector") or "").strip()
            if not rid or not det:
                continue
            params = r.get("params") or {}
            params_str: dict[str, str] = {}
            if isinstance(params, dict):
                for k, v in params.items():
                    params_str[str(k)] = str(v)
            mitre_raw = r.get("mitre")
            mitre: list[str] | None = None
            if isinstance(mitre_raw, list):
                mitre = [str(x).strip() for x in mitre_raw if str(x).strip()]
            elif isinstance(mitre_raw, str) and mitre_raw.strip():
                mitre = [mitre_raw.strip()]
            out.append(
                RuleDef(
                    rule_id=rid,
                    title=str(r.get("title") or rid),
                    description=str(r.get("description") or ""),
                    severity=str(r.get("severity") or "medium"),
                    detector=det,
                    enabled_by_default=bool(r.get("enabled_by_default", True)),
                    params=params_str or None,
                    mitre=mitre or None,
                )
            )
    # ensure stable unique by rule_id (first wins)
    seen: set[str] = set()
    uniq: list[RuleDef] = []
    for r in out:
        if r.rule_id in seen:
            continue
        seen.add(r.rule_id)
        uniq.append(r)
    return uniq


def run_detectors(events: list[dict[str, Any]], defs: list[RuleDef], enabled: dict[str, bool], params: dict[str, dict[str, str]]) -> list[Alert]:
    out: list[Alert] = []
    for d in defs:
        if not enabled.get(d.rule_id, d.enabled_by_default):
            continue
        p = {}
        p.update(d.params or {})
        p.update(params.get(d.rule_id, {}) or {})
        if d.detector == "failed_logon_burst":
            thr = int(p.get("threshold", "5") or 5)
            win = int(p.get("window_minutes", "5") or 5)
            out.extend(detect_failed_logon_burst(events, threshold=thr, window_minutes=win))
        elif d.detector == "failed_logon_burst_by_ip":
            thr = int(p.get("threshold", "8") or 8)
            win = int(p.get("window_minutes", "5") or 5)
            out.extend(detect_failed_logon_burst_by_key(events, key="ip", threshold=thr, window_minutes=win))
        elif d.detector == "failed_logon_burst_by_account":
            thr = int(p.get("threshold", "8") or 8)
            win = int(p.get("window_minutes", "10") or 10)
            out.extend(detect_failed_logon_burst_by_key(events, key="account", threshold=thr, window_minutes=win))
        elif d.detector == "failed_logon_burst_rdp_by_ip":
            thr = int(p.get("threshold", "6") or 6)
            win = int(p.get("window_minutes", "5") or 5)
            out.extend(detect_failed_logon_burst_by_key(events, key="ip", threshold=thr, window_minutes=win, logon_type="10"))
        elif d.detector == "security_log_cleared":
            out.extend(detect_security_log_cleared(events))
        elif d.detector == "powershell_encoded_sysmon":
            out.extend(detect_powershell_encoded_sysmon(events))
        elif d.detector == "success_after_fail":
            thr = int(p.get("threshold", "5") or 5)
            win = int(p.get("window_minutes", "10") or 10)
            out.extend(detect_success_after_fail(events, threshold=thr, window_minutes=win))
        elif d.detector == "suspicious_cmdline":
            out.extend(detect_suspicious_cmdline(events))
        elif d.detector == "corr_brute_login_proc":
            fail_thr = int(p.get("fail_threshold", "5") or 5)
            fail_win = int(p.get("fail_window_minutes", "10") or 10)
            chain_win = int(p.get("chain_window_minutes", "15") or 15)
            out.extend(
                detect_corr_bruteforce_login_suspicious_proc(
                    events,
                    fail_threshold=fail_thr,
                    fail_window_minutes=fail_win,
                    chain_window_minutes=chain_win,
                )
            )
    return out

def _strings(e: dict[str, Any]) -> list[str]:
    data = e.get("data") or {}
    inserts = data.get("StringInserts") or []
    out: list[str] = []
    for x in inserts:
        if x is None:
            continue
        out.append(str(x))
    return out


def detect_failed_logon_burst(
    events: list[dict[str, Any]],
    *,
    threshold: int = 5,
    window_minutes: int = 5,
) -> list[Alert]:
    """
    Very first detector: Security 4625 burst in a short window.
    Works on raw-normalized events dicts (as inserted to DB).
    """
    failed = [e for e in events if e.get("channel") == "Security" and int(e.get("event_id") or 0) == 4625]
    if not failed:
        return []

    failed.sort(key=lambda e: e.get("ts_utc", ""))
    window = timedelta(minutes=window_minutes)

    alerts: list[Alert] = []
    start = 0
    times = [_parse_ts(e["ts_utc"]) for e in failed if e.get("ts_utc")]
    for i in range(len(times)):
        while times[i] - times[start] > window:
            start += 1
        count = i - start + 1
        if count >= threshold:
            ts_from = times[start].isoformat()
            ts_to = times[i].isoformat()
            alerts.append(
                Alert(
                    rule_id="WIN-SEC-4625-BURST",
                    severity="high",
                    title=f"Подбор пароля: {count} неудачных входов за {window_minutes} мин",
                    details=f"Окно: {ts_from} → {ts_to}",
                )
            )
            # prevent spamming: advance window start
            start = i + 1
    return alerts


def _parsed(e: dict[str, Any]) -> dict[str, Any]:
    data = e.get("data") or {}
    parsed = data.get("parsed") or {}
    return parsed if isinstance(parsed, dict) else {}


def detect_failed_logon_burst_by_key(
    events: list[dict[str, Any]],
    *,
    key: str,
    threshold: int = 8,
    window_minutes: int = 5,
    logon_type: str | None = None,
) -> list[Alert]:
    """
    Security 4625 burst grouped by parsed[key], where key in {"ip","account"}.
    Uses best-effort parsed values from event data.
    """
    failed = [e for e in events if e.get("channel") == "Security" and int(e.get("event_id") or 0) == 4625]
    if not failed:
        return []

    # group by key
    groups: dict[str, list[dict[str, Any]]] = {}
    for e in failed:
        if logon_type is not None:
            lt = str(_parsed(e).get("logon_type") or "").strip()
            if lt != str(logon_type):
                continue
        v = str(_parsed(e).get(key) or "").strip()
        if not v:
            continue
        groups.setdefault(v, []).append(e)

    if not groups:
        return []

    window = timedelta(minutes=window_minutes)
    out: list[Alert] = []

    for gval, items in groups.items():
        items.sort(key=lambda e: e.get("ts_utc", ""))
        times = [_parse_ts(e["ts_utc"]) for e in items if e.get("ts_utc")]
        if not times:
            continue
        start = 0
        for i in range(len(times)):
            while times[i] - times[start] > window:
                start += 1
            count = i - start + 1
            if count >= threshold:
                ts_from = times[start].isoformat()
                ts_to = times[i].isoformat()
                if key == "ip":
                    if logon_type == "10":
                        title = f"RDP brute-force по IP: {count} ошибок входа за {window_minutes} мин"
                        details = f"ip={gval} | logon_type=10 (RDP) | окно: {ts_from} → {ts_to}"
                        rid = "WIN-SEC-4625-RDP-BURST-BY-IP"
                        sev = "critical"
                    else:
                        title = f"Brute-force по IP: {count} неудачных входов за {window_minutes} мин"
                        details = f"ip={gval} | окно: {ts_from} → {ts_to}"
                        rid = "WIN-SEC-4625-BURST-BY-IP"
                        sev = "high"
                else:
                    title = f"Brute-force по аккаунту: {count} неудачных входов за {window_minutes} мин"
                    details = f"account={gval} | окно: {ts_from} → {ts_to}"
                    rid = "WIN-SEC-4625-BURST-BY-ACCOUNT"
                    sev = "high"
                out.append(Alert(rule_id=rid, severity=sev, title=title, details=details))
                start = i + 1

    return out


def detect_security_log_cleared(events: list[dict[str, Any]]) -> list[Alert]:
    """
    Security log cleared:
    - classic Security EventID 1102
    """
    out: list[Alert] = []
    for e in events:
        if e.get("channel") != "Security":
            continue
        if int(e.get("event_id") or 0) != 1102:
            continue
        out.append(
            Alert(
                rule_id="WIN-SEC-1102-CLEARED",
                severity="critical",
                title="Очищен Security журнал (1102)",
                details=f"ts={e.get('ts_utc')} record_id={e.get('record_id')}",
            )
        )
    return out


def detect_powershell_encoded_sysmon(events: list[dict[str, Any]]) -> list[Alert]:
    """
    Sysmon ProcessCreate is EventID 1 in channel Microsoft-Windows-Sysmon/Operational.
    We don't parse XML here; we scan StringInserts for powershell + -enc/-encodedcommand.
    """
    out: list[Alert] = []
    for e in events:
        if e.get("channel") != "Microsoft-Windows-Sysmon/Operational":
            continue
        if int(e.get("event_id") or 0) != 1:
            continue
        s = " ".join(_strings(e)).lower()
        if "powershell" in s and ("-enc" in s or "-encodedcommand" in s):
            out.append(
                Alert(
                    rule_id="WIN-SYSMON-PS-ENC",
                    severity="high",
                    title="Подозрительный PowerShell: EncodedCommand (Sysmon 1)",
                    details=f"ts={e.get('ts_utc')} record_id={e.get('record_id')}",
                )
            )
    return out


def detect_success_after_fail(
    events: list[dict[str, Any]],
    *,
    threshold: int = 5,
    window_minutes: int = 10,
) -> list[Alert]:
    """
    Security: detect 4624 occurring after N failures (4625) within window.
    """
    sec = [e for e in events if e.get("channel") == "Security" and int(e.get("event_id") or 0) in (4624, 4625)]
    if not sec:
        return []
    sec.sort(key=lambda e: e.get("ts_utc", ""))
    win = timedelta(minutes=window_minutes)
    out: list[Alert] = []

    fail_times: list[datetime] = []
    for e in sec:
        ts = e.get("ts_utc")
        if not ts:
            continue
        t = _parse_ts(ts)
        eid = int(e.get("event_id") or 0)
        if eid == 4625:
            fail_times.append(t)
            continue
        if eid != 4624:
            continue
        # count failures within window prior to this success
        cutoff = t - win
        recent_fail = [ft for ft in fail_times if ft >= cutoff]
        if len(recent_fail) >= int(threshold):
            out.append(
                Alert(
                    rule_id="WIN-SEC-4624-AFTER-FAIL",
                    severity="high",
                    title=f"Успешный вход после {len(recent_fail)} неудачных (окно {window_minutes} мин)",
                    details=f"ts={ts} record_id={e.get('record_id')}",
                )
            )
            fail_times = []
    return out


def detect_suspicious_cmdline(events: list[dict[str, Any]]) -> list[Alert]:
    """
    Best-effort: scan StringInserts for suspicious process/flags.
    - Sysmon: channel Microsoft-Windows-Sysmon/Operational, EventID 1
    - Security: EventID 4688 (if auditing enabled)
    """
    suspicious = [
        " powershell",
        "pwsh",
        "cmd.exe",
        "rundll32",
        "regsvr32",
        "mshta",
        "wmic",
        "certutil",
        " -enc",
        "-encodedcommand",
        "iex(",
        "invoke-",
    ]
    out: list[Alert] = []
    for e in events:
        ch = str(e.get("channel") or "")
        eid = int(e.get("event_id") or 0)
        if ch == "Microsoft-Windows-Sysmon/Operational" and eid != 1:
            continue
        if ch == "Security" and eid != 4688:
            continue
        s = " " + " ".join(_strings(e)).lower()
        if any(tok in s for tok in suspicious):
            out.append(
                Alert(
                    rule_id="WIN-PROC-SUSPICIOUS",
                    severity="medium",
                    title="Подозрительный запуск процесса (cmd/powershell/LOLBin)",
                    details=f"channel={ch} event_id={eid} ts={e.get('ts_utc')} record_id={e.get('record_id')}",
                )
            )
    return out


def _is_suspicious_proc_event(e: dict[str, Any]) -> bool:
    ch = str(e.get("channel") or "")
    eid = int(e.get("event_id") or 0)
    if ch == "Microsoft-Windows-Sysmon/Operational" and eid != 1:
        return False
    if ch == "Security" and eid != 4688:
        return False
    if ch not in ("Microsoft-Windows-Sysmon/Operational", "Security"):
        return False
    suspicious = [
        " powershell",
        "pwsh",
        "cmd.exe",
        "rundll32",
        "regsvr32",
        "mshta",
        "wmic",
        "certutil",
        " -enc",
        "-encodedcommand",
        "iex(",
        "invoke-",
    ]
    s = " " + " ".join(_strings(e)).lower()
    return any(tok in s for tok in suspicious)


def detect_corr_bruteforce_login_suspicious_proc(
    events: list[dict[str, Any]],
    *,
    fail_threshold: int = 5,
    fail_window_minutes: int = 10,
    chain_window_minutes: int = 15,
) -> list[Alert]:
    """
    Correlation chain:
      - N failures (4625) within fail_window
      - then a success (4624)
      - then a suspicious process event (Sysmon 1 or Security 4688)
    all within chain_window (from the first failure in burst).
    """
    # Pre-filter and sort
    evs = [e for e in events if e.get("ts_utc")]
    evs.sort(key=lambda e: e.get("ts_utc", ""))

    fail_win = timedelta(minutes=int(fail_window_minutes))
    chain_win = timedelta(minutes=int(chain_window_minutes))

    # Collect failure timestamps
    fail_times: list[datetime] = []
    out: list[Alert] = []
    for e in evs:
        if e.get("channel") == "Security" and int(e.get("event_id") or 0) == 4625:
            fail_times.append(_parse_ts(e["ts_utc"]))

        # check chain anchor when we have enough fails recently
        if not fail_times:
            continue

        # shrink old fails (keep a rolling window ending at current event time)
        now_t = _parse_ts(e["ts_utc"])
        cutoff = now_t - fail_win
        fail_times = [t for t in fail_times if t >= cutoff]
        if len(fail_times) < int(fail_threshold):
            continue

        # chain start = oldest fail in current burst window
        chain_start = min(fail_times)
        chain_end = chain_start + chain_win
        if now_t > chain_end:
            continue

        # find a success and a suspicious proc within chain window
        # We only look forward from current index: simplest approach is to scan the whole list.
        # (Data sizes are small in our 10-min query windows in the app.)
        success_ts: datetime | None = None
        suspicious_ts: datetime | None = None
        for ee in evs:
            ts = ee.get("ts_utc")
            if not ts:
                continue
            t = _parse_ts(ts)
            if t < chain_start or t > chain_end:
                continue
            if success_ts is None and ee.get("channel") == "Security" and int(ee.get("event_id") or 0) == 4624:
                success_ts = t
            if _is_suspicious_proc_event(ee):
                suspicious_ts = t
            if success_ts is not None and suspicious_ts is not None and suspicious_ts >= success_ts:
                break

        if success_ts is not None and suspicious_ts is not None and suspicious_ts >= success_ts:
            out.append(
                Alert(
                    rule_id="WIN-CORR-BRUTE-LOGIN-PROC",
                    severity="critical",
                    title="Корреляция: brute-force → вход → подозрительный процесс",
                    details=(
                        f"fails>={fail_threshold} (win={fail_window_minutes}m) "
                        f"chain={chain_window_minutes}m | "
                        f"start={chain_start.isoformat()} success={success_ts.isoformat()} suspicious={suspicious_ts.isoformat()}"
                    ),
                )
            )
            # avoid spamming: reset burst after firing
            fail_times = []

    return out

