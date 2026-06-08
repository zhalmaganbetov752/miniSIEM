from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

import win32evtlog  # type: ignore
import xml.etree.ElementTree as ET


@dataclass(frozen=True)
class WinChannel:
    name: str


DEFAULT_CHANNELS = [
    WinChannel("Security"),
    WinChannel("System"),
    WinChannel("Application"),
    WinChannel("Microsoft-Windows-Sysmon/Operational"),
]


def _to_utc_iso(dt: datetime | None) -> str:
    if dt is None:
        return datetime.now(timezone.utc).isoformat()
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat()


def poll_channel(
    channel: str,
    *,
    server: str | None = None,
    flags: int | None = None,
    offset: int = 0,
    batch_size: int = 128,
) -> list[dict[str, Any]]:
    """
    Simple polling reader. Keeps state outside (the caller can store last_record_id).

    Returns events in "raw-normalized" dict form; write to SQLite as-is.
    """
    # Channels like "Microsoft-Windows-Sysmon/Operational" are not readable via legacy
    # OpenEventLog/ReadEventLog API. Use Windows Eventing (Evt*) API for them.
    if "/" in channel:
        return _poll_channel_evtapi(channel, offset=offset, batch_size=batch_size)

    # Classic event logs (Security/System/Application) are readable via legacy API.
    # SEEK_READ often breaks depending on OS/pywin32 build; use BACKWARDS+SEQUENTIAL
    # and filter by RecordNumber cursor (offset = next record id).
    flags = flags or (win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ)
    h = win32evtlog.OpenEventLog(server, channel)
    try:
        out: list[dict[str, Any]] = []
        while True:
            # Note: on many pywin32 builds ReadEventLog accepts only 3 args:
            # ReadEventLog(handle, flags, offset). We'll enforce batch_size ourselves.
            events = win32evtlog.ReadEventLog(h, flags, 0)
            if not events:
                break
            for e in events:
                rn = int(getattr(e, "RecordNumber", 0)) if getattr(e, "RecordNumber", None) is not None else None
                if rn is not None and rn < int(offset or 0):
                    # We are reading backwards from newest to oldest.
                    # Stop once we reached already-processed records.
                    events = []
                    break
                # Legacy Win32 Event Log API may return a 32-bit packed EventID that includes
                # severity/facility bits. The canonical Windows Event ID is the low 16 bits.
                raw_eid = int(getattr(e, "EventID", 0)) if getattr(e, "EventID", None) is not None else None
                event_id = (int(raw_eid) & 0xFFFF) if raw_eid is not None else None
                inserts = list(getattr(e, "StringInserts", []) or [])
                data: dict[str, Any] = {
                    "EventCategory": getattr(e, "EventCategory", None),
                    "Sid": str(getattr(e, "Sid", "")) if getattr(e, "Sid", None) else None,
                    "StringInserts": inserts,
                }
                if channel == "Security" and event_id in (4624, 4625):
                    # Best-effort parsing (indexes vary across versions/localization).
                    # We keep raw inserts and add a small parsed section when possible.
                    parsed: dict[str, Any] = {}
                    # Heuristic: pick first "domain\\user" like token
                    for s in inserts:
                        if not s:
                            continue
                        ss = str(s)
                        if "\\" in ss and len(ss) <= 128:
                            parsed.setdefault("account", ss)
                        if parsed.get("account"):
                            break
                    # Heuristic: pick first IPv4-ish token
                    for s in inserts:
                        if not s:
                            continue
                        ss = str(s)
                        if ss in ("-", "127.0.0.1", "0.0.0.0"):
                            continue
                        if ss.count(".") == 3 and all(p.isdigit() and 0 <= int(p) <= 255 for p in ss.split(".") if p):
                            parsed.setdefault("ip", ss)
                            break
                    # Heuristic: logon type is a small integer (2,3,10,11,...). Pick first plausible one.
                    for s in inserts:
                        if not s:
                            continue
                        ss = str(s).strip()
                        if ss.isdigit():
                            n = int(ss)
                            if 2 <= n <= 13:
                                parsed.setdefault("logon_type", str(n))
                                break
                    if parsed:
                        parsed["event_id"] = event_id
                        data["parsed"] = parsed
                out.append(
                    {
                        "ts_utc": _to_utc_iso(getattr(e, "TimeGenerated", None)),
                        "channel": channel,
                        "provider": getattr(e, "SourceName", None),
                        "event_id": event_id,
                        "level": int(getattr(e, "EventType", 0)) if getattr(e, "EventType", None) is not None else None,
                        "computer": getattr(e, "ComputerName", None),
                        "record_id": rn,
                        "message": None,  # message formatting is expensive; do later if needed
                        "data": data,
                    }
                )
                if len(out) >= int(batch_size):
                    break
            if not events:
                break
            if len(out) >= int(batch_size):
                break
        # We read newest→oldest; return oldest→newest for stable processing
        out.reverse()
        return out
    finally:
        win32evtlog.CloseEventLog(h)


def _poll_channel_evtapi(channel: str, *, offset: int = 0, batch_size: int = 128) -> list[dict[str, Any]]:
    """
    Read modern channels (Applications and Services Logs) via Windows Eventing API.

    Uses EventRecordID as cursor (offset).
    """
    # EventRecordID is monotonic within channel. We query forward.
    # Offset is "next record id to read".
    q = "*"
    if offset:
        q = f"*[System[(EventRecordID >= {int(offset)})]]"
    h = win32evtlog.EvtQuery(channel, win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryForwardDirection, q)
    handles = win32evtlog.EvtNext(h, batch_size)
    out: list[dict[str, Any]] = []
    for eh in handles:
        xml = win32evtlog.EvtRender(eh, win32evtlog.EvtRenderEventXml)
        parsed = _parse_evt_xml(xml)
        if parsed is None:
            continue
        parsed["channel"] = channel
        out.append(parsed)
    return out


def _parse_evt_xml(xml_text: str) -> dict[str, Any] | None:
    try:
        root = ET.fromstring(xml_text)
    except Exception:
        return None

    # Default namespace handling (Event schema uses a namespace)
    ns = ""
    if root.tag.startswith("{") and "}" in root.tag:
        ns = root.tag.split("}")[0][1:]

    def _find(path: str):
        if ns:
            parts = []
            for p in path.split("/"):
                if not p:
                    continue
                if p.startswith("@"):
                    parts.append(p)
                else:
                    parts.append(f"{{{ns}}}{p}")
            path = "/".join(parts)
        return root.find(path)

    system = _find("System")
    if system is None:
        return None

    def _text(elem) -> str | None:
        if elem is None or elem.text is None:
            return None
        return str(elem.text)

    provider = system.find(f"{{{ns}}}Provider") if ns else system.find("Provider")
    provider_name = provider.get("Name") if provider is not None else None

    event_id_el = system.find(f"{{{ns}}}EventID") if ns else system.find("EventID")
    event_id = int(event_id_el.text) if event_id_el is not None and (event_id_el.text or "").isdigit() else None

    level_el = system.find(f"{{{ns}}}Level") if ns else system.find("Level")
    level = int(level_el.text) if level_el is not None and (level_el.text or "").isdigit() else None

    comp_el = system.find(f"{{{ns}}}Computer") if ns else system.find("Computer")
    computer = _text(comp_el)

    rec_el = system.find(f"{{{ns}}}EventRecordID") if ns else system.find("EventRecordID")
    record_id = int(rec_el.text) if rec_el is not None and (rec_el.text or "").isdigit() else None

    time_el = system.find(f"{{{ns}}}TimeCreated") if ns else system.find("TimeCreated")
    ts_utc = None
    if time_el is not None:
        st = time_el.get("SystemTime")
        if st:
            # Convert Zulu/offset to ISO; keep raw as-is but normalize "Z" to "+00:00"
            ts_utc = st.replace("Z", "+00:00")
    if not ts_utc:
        ts_utc = datetime.now(timezone.utc).isoformat()

    data: dict[str, Any] = {"xml": xml_text}
    return {
        "ts_utc": ts_utc,
        "provider": provider_name,
        "event_id": event_id,
        "level": level,
        "computer": computer,
        "record_id": record_id,
        "message": None,
        "data": data,
    }


def max_record_number(channel: str, *, server: str | None = None) -> int | None:
    try:
        h = win32evtlog.OpenEventLog(server, channel)
    except Exception:
        return None
    try:
        oldest, total = win32evtlog.GetOldestEventLogRecord(h), win32evtlog.GetNumberOfEventLogRecords(h)
        return int(oldest + total - 1) if total else None
    finally:
        win32evtlog.CloseEventLog(h)

