from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class AutoStartResult:
    ok: bool
    details: str


RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
VALUE_NAME = "miniSIEM"


def set_autostart_enabled(exe_path: str, enabled: bool) -> AutoStartResult:
    """
    Enable/disable autostart for current user (HKCU\\...\\Run).
    Does not require admin rights.
    """
    try:
        import winreg

        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_SET_VALUE) as k:
            if enabled:
                winreg.SetValueEx(k, VALUE_NAME, 0, winreg.REG_SZ, f"\"{exe_path}\"")
                return AutoStartResult(ok=True, details="Автозапуск включен (HKCU Run)")
            try:
                winreg.DeleteValue(k, VALUE_NAME)
            except FileNotFoundError:
                pass
            return AutoStartResult(ok=True, details="Автозапуск выключен (HKCU Run)")
    except Exception as e:
        return AutoStartResult(ok=False, details=f"{type(e).__name__}: {e}")


def get_autostart_enabled() -> tuple[bool, str]:
    try:
        import winreg

        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_READ) as k:
            v, _t = winreg.QueryValueEx(k, VALUE_NAME)
            return True, str(v)
    except FileNotFoundError:
        return False, ""
    except Exception:
        return False, ""

