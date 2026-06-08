from __future__ import annotations

from typing import Any


_LOGON_TYPE_LABELS: dict[int, str] = {
    2: "Interactive (local console)",
    3: "Network",
    4: "Batch",
    5: "Service",
    7: "Unlock",
    8: "NetworkCleartext",
    9: "NewCredentials",
    10: "RemoteInteractive (RDP)",
    11: "CachedInteractive",
    12: "CachedRemoteInteractive (RDP)",
    13: "CachedUnlock",
}


def logon_type_label(v: Any) -> str | None:
    """
    Convert Security LogonType value into a human-readable label.

    Returns None if value is missing/unknown.
    """
    if v is None:
        return None
    try:
        if isinstance(v, str):
            s = v.strip()
            if not s:
                return None
            n = int(s)
        else:
            n = int(v)
    except Exception:
        return None
    return _LOGON_TYPE_LABELS.get(n)

