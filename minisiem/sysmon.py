from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import win32evtlog  # type: ignore


SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"


@dataclass(frozen=True)
class SysmonStatus:
    channel_available: bool
    details: str


def get_sysmon_status() -> SysmonStatus:
    """
    Best-effort check: if the Sysmon event channel exists and is readable.
    """
    try:
        h = win32evtlog.EvtQuery(SYSMON_CHANNEL, win32evtlog.EvtQueryChannelPath, "*")
        # If query handle created, channel exists (and is readable).
        _ = h
        return SysmonStatus(channel_available=True, details="Sysmon channel доступен")
    except Exception as e:
        msg = str(e)
        if "15007" in msg:
            return SysmonStatus(channel_available=False, details="Канал не найден (Sysmon не установлен)")
        return SysmonStatus(channel_available=False, details=f"{type(e).__name__}: {msg}")


SYSMON_CONFIG_XML = """\
<Sysmon schemaversion="4.90">
  <HashAlgorithms>*</HashAlgorithms>
  <EventFiltering>
    <!-- Minimal config for diploma demos: process + network + image load -->
    <ProcessCreate onmatch="include" />
    <NetworkConnect onmatch="include" />
    <ImageLoad onmatch="include" />

    <!-- Reduce noise a bit -->
    <ProcessCreate onmatch="exclude">
      <Image condition="end with">\\Windows\\System32\\svchost.exe</Image>
    </ProcessCreate>
  </EventFiltering>
</Sysmon>
"""


def ensure_sysmon_config(data_dir: Path) -> Path:
    """
    Write a minimal Sysmon config to user data directory.
    """
    data_dir.mkdir(parents=True, exist_ok=True)
    p = data_dir / "sysmon-config.xml"
    if not p.exists():
        p.write_text(SYSMON_CONFIG_XML, encoding="utf-8")
    return p


def build_install_command(*, sysmon_exe_path: str = r".\Sysmon64.exe", config_path: Path) -> str:
    """
    Returns a PowerShell snippet that installs Sysmon with the generated config.
    User must download Sysmon64.exe (Sysinternals) manually.
    """
    cfg = str(config_path)
    return (
        f"# 1) Скачай Sysmon64.exe (Sysinternals) в текущую папку\n"
        f"# 2) Запусти PowerShell от имени администратора\n"
        f"{sysmon_exe_path} -accepteula -i \"{cfg}\"\n"
    )

