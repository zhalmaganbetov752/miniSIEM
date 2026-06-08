"""
Отображение времени в часовом поясе пользователя (смещение от UTC).
В SQLite события и алерты хранятся в UTC; интерфейс показывает локальное смещение.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone

from minisiem.db import get_setting

# Диапазон разумных смещений (часы от UTC)
_MIN_OFF = -12
_MAX_OFF = 14
_DEFAULT_OFF = 5


def display_tz_offset_hours(con: sqlite3.Connection | None) -> int:
    if con is None:
        return _DEFAULT_OFF
    try:
        raw = get_setting(con, "display_tz_offset_hours")
        if raw is None or str(raw).strip() == "":
            return _DEFAULT_OFF
        h = int(str(raw).strip())
        return max(_MIN_OFF, min(_MAX_OFF, h))
    except Exception:
        return _DEFAULT_OFF


def user_display_tz(offset_hours: int) -> timezone:
    h = max(_MIN_OFF, min(_MAX_OFF, int(offset_hours)))
    return timezone(timedelta(hours=h), name=f"UTC{'+' if h >= 0 else ''}{h}")


def format_utc_iso_for_display(iso_str: object | None, *, offset_hours: int) -> str:
    if iso_str is None or iso_str == "":
        return ""
    s = str(iso_str).strip()
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
    except Exception:
        return s
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    off = max(_MIN_OFF, min(_MAX_OFF, int(offset_hours)))
    local = dt.astimezone(timezone(timedelta(hours=off)))
    return local.strftime("%Y-%m-%d %H:%M:%S") + f" (UTC{off:+d})"


def format_datetime_for_display(dt: datetime, *, offset_hours: int) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    off = max(_MIN_OFF, min(_MAX_OFF, int(offset_hours)))
    local = dt.astimezone(timezone(timedelta(hours=off)))
    return local.strftime("%Y-%m-%d %H:%M:%S") + f" (UTC{off:+d})"


def parse_user_time_to_utc_iso(s: str, *, display_offset_hours: int) -> str | None:
    """
    Разбор поля фильтра времени.
    - Пустая строка → None
    - Если в строке есть часовой пояс — используется он, затем перевод в UTC.
    - Если пояса нет — время считается в «вашем» смещении (display_offset_hours), затем в UTC.
    """
    txt = (s or "").strip()
    if not txt:
        return None
    txt = txt.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(txt)
    except Exception:
        try:
            dt = datetime.fromisoformat(txt.replace(" ", "T"))
        except Exception:
            return None
    off = max(_MIN_OFF, min(_MAX_OFF, int(display_offset_hours)))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone(timedelta(hours=off)))
    return dt.astimezone(timezone.utc).isoformat()
