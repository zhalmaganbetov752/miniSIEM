from __future__ import annotations

import subprocess
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class EvtxImportResult:
    imported: int
    errors: int


def import_evtx_file(path: Path, *, limit: int = 2000) -> list[dict[str, Any]]:
    """
    Offline import .evtx via wevtutil.

    Notes:
    - Requires Windows built-in `wevtutil`.
    - Reads up to `limit` newest events from the file.
    - Returns raw-normalized event dicts compatible with bulk_insert_events().
    """
    if not path.exists():
        raise FileNotFoundError(str(path))

    # Query events from log file (/lf:true) in XML format.
    # /c:N limits number of events. Output contains multiple <Event> blocks.
    cmd = [
        "wevtutil",
        "qe",
        str(path),
        "/lf:true",
        "/f:xml",
        f"/c:{int(limit)}",
    ]
    p = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
    if p.returncode != 0:
        msg = (p.stderr or p.stdout or "").strip()
        raise RuntimeError(msg or f"wevtutil failed: exit={p.returncode}")

    txt = (p.stdout or "").strip()
    if not txt:
        return []

    # Wrap into a root element so we can parse it.
    wrapped = "<Events>\n" + txt + "\n</Events>"
    root = ET.fromstring(wrapped)
    out: list[dict[str, Any]] = []
    for ev in root.findall(".//Event"):
        item = _parse_event_xml(ev)
        if item is None:
            continue
        item["data"]["source_file"] = str(path)
        item["provider"] = item.get("provider") or "EVTX_IMPORT"
        out.append(item)
    return out


def _parse_event_xml(ev: ET.Element) -> dict[str, Any] | None:
    # Namespace handling
    ns = ""
    if ev.tag.startswith("{") and "}" in ev.tag:
        ns = ev.tag.split("}")[0][1:]

    def _t(tag: str) -> str:
        return f"{{{ns}}}{tag}" if ns else tag

    system = ev.find(_t("System"))
    if system is None:
        return None

    channel_el = system.find(_t("Channel"))
    channel = channel_el.text if channel_el is not None and channel_el.text else "Unknown"

    provider_el = system.find(_t("Provider"))
    provider_name = provider_el.get("Name") if provider_el is not None else None

    event_id_el = system.find(_t("EventID"))
    event_id = None
    if event_id_el is not None and event_id_el.text:
        try:
            event_id = int(event_id_el.text.strip())
        except Exception:
            event_id = None

    level_el = system.find(_t("Level"))
    level = None
    if level_el is not None and level_el.text:
        try:
            level = int(level_el.text.strip())
        except Exception:
            level = None

    computer_el = system.find(_t("Computer"))
    computer = computer_el.text if computer_el is not None else None

    record_id_el = system.find(_t("EventRecordID"))
    record_id = None
    if record_id_el is not None and record_id_el.text:
        try:
            record_id = int(record_id_el.text.strip())
        except Exception:
            record_id = None

    time_el = system.find(_t("TimeCreated"))
    ts_utc = None
    if time_el is not None:
        st = time_el.get("SystemTime")
        if st:
            ts_utc = st.replace("Z", "+00:00")
    if not ts_utc:
        ts_utc = datetime.now(timezone.utc).isoformat()

    # Store full XML for later deep parsing if needed
    xml_text = ET.tostring(ev, encoding="unicode", method="xml")
    data: dict[str, Any] = {"xml": xml_text}

    # Best-effort structured extraction from EventData/UserData.
    # Useful for offline imports where StringInserts are not present.
    def _collect_kv(parent_tag: str) -> dict[str, str]:
        out: dict[str, str] = {}
        parent = ev.find(_t(parent_tag))
        if parent is None:
            return out
        # Common case: <EventData><Data Name="Foo">bar</Data></EventData>
        for d in list(parent.findall(_t("Data"))):
            name = d.get("Name") or d.get("name") or ""
            val = (d.text or "").strip()
            if name and val:
                out[str(name)] = str(val)
        return out

    event_data = _collect_kv("EventData")
    if event_data:
        data["EventData"] = event_data

    # Add parsed fields for Security logons (4624/4625) to power filters & rules.
    if channel == "Security" and event_id in (4624, 4625):
        parsed: dict[str, Any] = {"event_id": event_id}

        # Prefer named fields when present (language-independent).
        # References: TargetUserName/TargetDomainName, IpAddress, LogonType.
        user = event_data.get("TargetUserName") or event_data.get("SubjectUserName")
        domain = event_data.get("TargetDomainName") or event_data.get("SubjectDomainName")
        ip = event_data.get("IpAddress") or event_data.get("WorkstationName")
        logon_type = event_data.get("LogonType")

        if user and domain and user not in ("-", "ANONYMOUS LOGON"):
            parsed["account"] = f"{domain}\\{user}"
        elif user and user != "-":
            parsed["account"] = user

        if ip and ip not in ("-", "::1", "127.0.0.1", "0.0.0.0"):
            parsed["ip"] = ip

        if logon_type and str(logon_type).strip().isdigit():
            parsed["logon_type"] = str(int(logon_type))

        # Only attach if we extracted something useful besides event_id.
        if len(parsed) > 1:
            data["parsed"] = parsed

    return {
        "ts_utc": ts_utc,
        "channel": channel,
        "provider": provider_name,
        "event_id": event_id,
        "level": level,
        "computer": computer,
        "record_id": record_id,
        "message": None,
        "data": data,
    }

