from __future__ import annotations

from dataclasses import dataclass
import sqlite3
import json
import subprocess
import os
import sys
import zipfile
import tempfile

from minisiem import __version__
from minisiem.db import (
    connect,
    default_paths,
    get_db_file_stats,
    count_rows,
    count_events_since,
    count_security_logons_since,
    count_alerts_by_status_since,
    top_event_ids_since,
    top_channels_since,
    top_security_4625_by_ip_since,
    top_security_4625_by_account_since,
    top_security_4625_by_logon_type_since,
    count_security_4625_by_logon_type_since,
    top_security_4625_rdp_by_ip_since,
    prune_all_older_than,
    prune_events_older_than,
    prune_alerts_older_than,
    prune_actions_older_than,
    clear_table,
    delete_demo_data,
    checkpoint_wal,
    vacuum,
    backfill_security_logon_parsed_fields,
    normalize_legacy_event_ids,
    fetch_recent_actions,
    fetch_recent_alerts,
    fetch_recent_events,
    fetch_events_between,
    get_event_by_id,
    get_setting,
    insert_action,
    load_rules_state,
    migrate,
    search_events,
    set_rule_enabled,
    get_rule_param,
    set_rule_param,
    set_setting,
    update_alert_status,
)
from minisiem.report import build_alert_html_report, build_alert_json_report, build_html_report

from datetime import datetime, timedelta, timezone

from PySide6.QtCore import QAbstractTableModel, QModelIndex, QObject, QThread, QTimer, Qt, Signal
from PySide6.QtGui import QAction, QIcon, QShowEvent
from PySide6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QComboBox,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QProgressDialog,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QSplitter,
    QStatusBar,
    QTabWidget,
    QFileDialog,
    QVBoxLayout,
    QTextEdit,
    QToolBar,
    QWidget,
    QSystemTrayIcon,
)
from PySide6.QtPrintSupport import QPrinter

from pathlib import Path

from minisiem.collector_win import DEFAULT_CHANNELS, max_record_number, poll_channel
from minisiem.db import (
    alert_exists_recently,
    bulk_insert_events,
    fetch_actions_for_alert,
    fetch_events_since,
    insert_alert,
    update_alert_comment,
)
from minisiem.evtx_import import import_evtx_file
from minisiem.autostart import get_autostart_enabled, set_autostart_enabled
from minisiem.sysmon import build_install_command, ensure_sysmon_config, get_sysmon_status
from minisiem.rules import DEFAULT_RULES_YAML, ensure_default_rules, load_rule_defs, run_detectors
from minisiem.winsec import logon_type_label
from minisiem.theme import apply_muted_style, polish_table_view, size_table_columns
from minisiem.time_display import (
    display_tz_offset_hours,
    format_datetime_for_display,
    format_utc_iso_for_display,
    parse_user_time_to_utc_iso,
)


@dataclass(frozen=True)
class AppConfig:
    app_name: str = "miniSIEM"


class MiniSIEMApp:
    def __init__(self, config: AppConfig | None = None) -> None:
        self.config = config or AppConfig()
        self._db: sqlite3.Connection | None = None
        self._last_rule_check = datetime.now(timezone.utc) - timedelta(minutes=10)
        self._channel_offsets: dict[str, int] = {}
        self._dry_run = True
        self._real_lock_workstation = False
        self._collector_last_tick_utc: str | None = None
        self._collector_last_new_events: int = 0
        self._collector_channel_status: dict[str, str] = {}
        self._last_auto_prune_check: datetime = datetime.now(timezone.utc) - timedelta(days=1)
        # Rules live in user data dir so they are editable even for built .exe
        self._rule_defs = []
        self._rules_enabled: dict[str, bool] = {}
        self._rules_params: dict[str, dict[str, str]] = {}
        self._events_tab: _EventsTab | None = None
        self._alerts_tab: _AlertsTab | None = None
        self._actions_tab: _ActionsTab | None = None
        self._rules_tab: _RulesTab | None = None
        self._dashboard_tab: _DashboardTab | None = None
        self._rules_dir: Path | None = None
        self._tray: QSystemTrayIcon | None = None
        self._toast_enabled = True
        self._collector_enabled = True
        self._poll_interval_ms: int = 4000
        self._timer: QTimer | None = None
        self._tabs: QTabWidget | None = None

    def create_main_window(self) -> QMainWindow:
        paths = default_paths()
        con = connect(paths.db_path)
        migrate(con)
        self._db = con

        self._rules_dir = ensure_default_rules(paths.data_dir / "rules")
        self._reload_rules()

        # Load saved rule toggles (if present)
        saved = load_rules_state(con)
        for rid, enabled in saved.items():
            if rid in self._rules_enabled:
                self._rules_enabled[rid] = enabled

        # Load saved rule params (if present)
        for rid, defaults in self._rules_params.items():
            for k, v in list(defaults.items()):
                dbv = get_rule_param(con, rule_id=rid, key=k)
                if dbv is not None:
                    defaults[k] = dbv

        # Load saved settings
        s_dry = get_setting(con, "dry_run")
        if s_dry is not None:
            self._dry_run = (s_dry == "1")
        s_lock = get_setting(con, "lock_workstation")
        if s_lock is not None:
            self._real_lock_workstation = (s_lock == "1")
        s_toast = get_setting(con, "toast_enabled")
        if s_toast is not None:
            self._toast_enabled = (s_toast == "1")
        s_coll = get_setting(con, "collector_enabled")
        if s_coll is not None:
            self._collector_enabled = (s_coll == "1")
        s_interval = get_setting(con, "poll_interval_ms")
        if s_interval is not None:
            try:
                self._poll_interval_ms = max(1000, int(s_interval))
            except ValueError:
                pass

        # Retention defaults (auto maintenance)
        if get_setting(con, "retention_enabled") is None:
            set_setting(con, key="retention_enabled", value="1")
        if get_setting(con, "retention_days") is None:
            set_setting(con, key="retention_days", value="7")
        if get_setting(con, "retention_last_prune_utc") is None:
            set_setting(con, key="retention_last_prune_utc", value=None)

        if get_setting(con, "display_tz_offset_hours") is None:
            set_setting(con, key="display_tz_offset_hours", value="5")

        # Load per-channel offsets (collector cursor)
        for ch in DEFAULT_CHANNELS:
            v = get_setting(con, f"offset::{ch.name}")
            if v is not None:
                try:
                    self._channel_offsets[ch.name] = int(v)
                except ValueError:
                    pass

        win = QMainWindow()
        win.setWindowTitle(f"{self.config.app_name} v{__version__}")
        win.resize(1250, 800)
        win.setMinimumSize(1070, 640)

        tabs = QTabWidget()
        self._tabs = tabs
        self._dashboard_tab = _DashboardTab(con)
        tabs.addTab(self._dashboard_tab, "Dashboard")
        self._events_tab = _EventsTab(con)
        self._alerts_tab = _AlertsTab(con, on_open_event=self._open_event_in_events)
        self._actions_tab = _ActionsTab(con)
        tabs.addTab(self._events_tab, "Events")
        tabs.addTab(self._alerts_tab, "Alerts")
        tabs.addTab(self._actions_tab, "Actions")
        self._rules_tab = _RulesTab(
            con,
            self._rules_enabled,
            self._rules_params,
            rules_dir=self._rules_dir,
            get_rule_meta=self._get_rule_meta,
            on_test_rules=self._test_rules,
            on_reload_rules=self._reload_rules,
        )
        tabs.addTab(self._rules_tab, "Rules")
        tabs.addTab(
            _SettingsTab(
                con,
                initial_dry_run=self._dry_run,
                initial_lock_ws=self._real_lock_workstation,
                initial_toast=self._toast_enabled,
                initial_collector_enabled=self._collector_enabled,
                initial_poll_interval_ms=self._poll_interval_ms,
                on_change_dry_run=self._set_dry_run,
                on_change_lock_ws=self._set_lock_ws,
                on_change_toast=self._set_toast,
                on_change_collector_enabled=self._set_collector_enabled,
                on_change_poll_interval_ms=self._set_poll_interval_ms,
                on_maintenance=self._maintenance,
                on_sysmon_tools=self._sysmon_tools,
                on_admin_help=self._show_admin_help,
                on_copy_runas=self._copy_runas_command,
                on_demo_alert=self._demo_generate_alert,
                on_demo_seed=self._demo_seed_data,
                on_demo_clear=self._demo_clear_data,
                on_demo_bruteforce_ip=self._demo_bruteforce_ip,
                on_open_data_dir=self._open_data_dir,
                on_set_autostart=self._set_autostart,
                on_change_display_tz=self._refresh_display_tz,
            ),
            "Settings",
        )
        win.setCentralWidget(tabs)

        toolbar = QToolBar("Main")
        toolbar.setMovable(False)
        win.addToolBar(Qt.TopToolBarArea, toolbar)

        act_about = QAction("About", win)
        act_about.triggered.connect(lambda: _show_about(win))
        toolbar.addAction(act_about)

        status = QStatusBar()
        status.showMessage("Готово")
        win.setStatusBar(status)

        self._tray = QSystemTrayIcon(win)
        self._tray.setIcon(win.style().standardIcon(win.style().StandardPixmap.SP_ComputerIcon))
        self._tray.setToolTip("miniSIEM")
        self._tray.setVisible(True)

        # One-time DB hygiene: normalize legacy-packed EventID values (if any).
        if get_setting(con, "db_norm_eventid_done") != "1":
            try:
                n = normalize_legacy_event_ids(con, limit=500_000)
            except Exception:
                n = 0
            set_setting(con, key="db_norm_eventid_done", value="1")
            if n:
                insert_action(
                    con,
                    alert_id=None,
                    action_type="maintenance",
                    target="sqlite",
                    result="executed",
                    details=f"normalized legacy event_id values: rows={n}",
                )

        # Minimal online poll (prototype): poll channels every few seconds
        timer = QTimer(win)
        timer.setInterval(int(self._poll_interval_ms))
        self._timer = timer

        def _tick() -> None:
            if self._db is None:
                return
            if not self._collector_enabled:
                self._collector_last_tick_utc = datetime.now(timezone.utc).isoformat()
                self._collector_last_new_events = 0
                if self._dashboard_tab:
                    self._dashboard_tab.refresh(
                        last_tick_utc=self._collector_last_tick_utc,
                        last_new_events=self._collector_last_new_events,
                        channel_status={"collector": "paused"},
                    )
                return
            total = 0
            self._collector_channel_status = {}
            for ch in DEFAULT_CHANNELS:
                try:
                    if ch.name not in self._channel_offsets:
                        last = max_record_number(ch.name)
                        # start near the end to avoid loading entire history on first run
                        self._channel_offsets[ch.name] = (last - 200) if last and last > 200 else 0
                    offset = self._channel_offsets[ch.name]
                    rows = poll_channel(ch.name, offset=offset, batch_size=128)
                    if rows:
                        last_rn = max((r.get("record_id") or 0) for r in rows)
                        if last_rn:
                            self._channel_offsets[ch.name] = int(last_rn) + 1
                            set_setting(self._db, key=f"offset::{ch.name}", value=str(self._channel_offsets[ch.name]))
                    self._collector_channel_status[ch.name] = f"ok (+{len(rows)})"
                except Exception as e:
                    # Some channels may be missing or access denied; ignore in prototype
                    msg = str(e)
                    if len(msg) > 140:
                        msg = msg[:140] + "…"
                    hint = ""
                    if ch.name == "Security" and (
                        "Access is denied" in msg
                        or "Доступ запрещен" in msg
                        or "Access denied" in msg
                        or "5," in msg  # WinError 5 in tuple repr
                    ):
                        hint = " | запусти miniSIEM от администратора"
                    self._collector_channel_status[ch.name] = f"error: {type(e).__name__}: {msg}{hint}"
                    continue
                total += bulk_insert_events(self._db, rows)
            self._collector_last_tick_utc = datetime.now(timezone.utc).isoformat()
            self._collector_last_new_events = int(total)
            self._maybe_auto_prune()
            # Rule pass (prototype): run on recent window
            now = datetime.now(timezone.utc)
            since = (now - timedelta(minutes=10)).isoformat()
            recent = fetch_events_since(self._db, since, limit=5000)
            events = []
            for r in recent:
                try:
                    data = json.loads(r["data_json"] or "{}")
                except Exception:
                    data = {}
                events.append(
                    {
                        "ts_utc": r["ts_utc"],
                        "channel": r["channel"],
                        "provider": r["provider"],
                        "event_id": r["event_id"],
                        "level": r["level"],
                        "computer": r["computer"],
                        "record_id": r["record_id"],
                        "message": r["message"],
                        "data": data,
                    }
                )
            alerts = run_detectors(events, self._rule_defs, self._rules_enabled, self._rules_params)
            for a in alerts:
                # Simple per-rule dedupe windows
                dedupe_m = 5
                if a.rule_id == "WIN-SEC-4625-BURST":
                    dedupe_m = 2
                elif a.rule_id == "WIN-SEC-1102-CLEARED":
                    dedupe_m = 10
                dedupe_since = (now - timedelta(minutes=dedupe_m)).isoformat()
                if alert_exists_recently(self._db, rule_id=a.rule_id, title=a.title, since_ts_utc=dedupe_since):
                    continue
                details = a.details or ""
                # Enrich alert details with MITRE mapping (good for reporting/defense).
                for d in self._rule_defs:
                    if d.rule_id == a.rule_id and getattr(d, "mitre", None):
                        mitre = ", ".join([str(x) for x in (d.mitre or []) if str(x).strip()])
                        if mitre:
                            details = (f"MITRE ATT&CK: {mitre}\n" + details).strip()
                        break
                alert_id = insert_alert(self._db, rule_id=a.rule_id, severity=a.severity, title=a.title, details=details or None)
                insert_action(
                    self._db,
                    alert_id=alert_id,
                    action_type="notify",
                    target="ui",
                    result="dry-run" if self._dry_run else "skipped",
                    details=f"Оповестить: {a.rule_id}",
                )
                self._notify_alert(a.title, a.details or "")
                if self._real_lock_workstation and a.rule_id == "WIN-SEC-4625-BURST":
                    self._reaction_lock_workstation(alert_id)

            if total:
                win.statusBar().showMessage(f"Собрано событий: +{total} | правила проверены")
            if self._events_tab:
                self._events_tab.refresh()
            if self._alerts_tab:
                self._alerts_tab.refresh()
            if self._actions_tab:
                self._actions_tab.refresh()
            if self._rules_tab:
                self._rules_tab.sync_from_state()
            if self._dashboard_tab:
                self._dashboard_tab.refresh(
                    last_tick_utc=self._collector_last_tick_utc,
                    last_new_events=self._collector_last_new_events,
                    channel_status=self._collector_channel_status,
                )

        timer.timeout.connect(_tick)
        timer.start()

        return win

    def _open_event_in_events(self, event_row_id: int) -> None:
        if self._tabs is None or self._events_tab is None:
            return
        # Switch to Events tab and highlight the event.
        try:
            self._tabs.setCurrentWidget(self._events_tab)
        except Exception:
            pass
        try:
            self._events_tab.select_event_by_row_id(int(event_row_id))
        except Exception:
            pass

    def _reload_rules(self) -> None:
        if self._rules_dir is None:
            return
        defs = load_rule_defs(self._rules_dir)
        self._rule_defs = defs
        # Merge enabled/params with existing so we don't lose DB state
        new_enabled: dict[str, bool] = {}
        new_params: dict[str, dict[str, str]] = {}
        for d in defs:
            new_enabled[d.rule_id] = self._rules_enabled.get(d.rule_id, bool(d.enabled_by_default))
            base = dict(d.params or {})
            base.update(self._rules_params.get(d.rule_id, {}) or {})
            new_params[d.rule_id] = base
        self._rules_enabled = new_enabled
        self._rules_params = new_params
        if self._rules_tab:
            self._rules_tab.set_rules(self._rules_enabled, self._rules_params)

    def _maybe_auto_prune(self) -> None:
        """
        Best-effort auto maintenance:
        - prune old rows by retention_days
        - checkpoint WAL to keep size in check
        Runs at most once per ~6 hours.
        """
        if self._db is None:
            return
        now = datetime.now(timezone.utc)
        if now - self._last_auto_prune_check < timedelta(hours=6):
            return
        self._last_auto_prune_check = now

        enabled = (get_setting(self._db, "retention_enabled") or "1") == "1"
        try:
            days = int(get_setting(self._db, "retention_days") or "7")
        except ValueError:
            days = 7
        if days < 1:
            days = 1

        if enabled:
            cutoff = (now - timedelta(days=int(days))).isoformat()
            deleted = prune_all_older_than(self._db, cutoff)
            set_setting(self._db, key="retention_last_prune_utc", value=now.isoformat())
            insert_action(
                self._db,
                alert_id=None,
                action_type="maintenance_auto",
                target="sqlite",
                result="executed",
                details=f"auto_prune<{days}d: events={deleted['events']}, alerts={deleted['alerts']}, actions={deleted['actions']}",
            )

        checkpoint_wal(self._db)

    def _get_rule_meta(self, rule_id: str) -> tuple[str, str]:
        for d in self._rule_defs:
            if d.rule_id == rule_id:
                desc = d.description or ""
                if getattr(d, "mitre", None):
                    mitre = ", ".join([str(x) for x in (d.mitre or []) if str(x).strip()])
                    if mitre:
                        desc = (desc + "\n" if desc else "") + f"MITRE ATT&CK: {mitre}"
                return d.title, desc
        return rule_id, ""

    def _sysmon_tools(self, kind: str) -> None:
        paths = default_paths()
        if kind == "status":
            st = get_sysmon_status()
            QMessageBox.information(None, "Sysmon", st.details)
            return
        if kind == "write_config":
            p = ensure_sysmon_config(paths.data_dir)
            QMessageBox.information(None, "Sysmon", f"Конфиг создан/есть:\n{p}")
            return
        if kind == "copy_install_cmd":
            p = ensure_sysmon_config(paths.data_dir)
            cmd = build_install_command(config_path=p)
            QApplication.clipboard().setText(cmd)
            QMessageBox.information(None, "Sysmon", "Команда установки скопирована в буфер обмена.")
            return

    def _copy_runas_command(self) -> None:
        # Works for built exe. For python run, it's still a helpful hint.
        exe = sys.executable
        cmd = f'Start-Process -FilePath "{exe}" -Verb RunAs'
        QApplication.clipboard().setText(cmd)
        QMessageBox.information(None, "Админ-права", "Команда RunAs скопирована в буфер обмена (PowerShell).")

    def _open_data_dir(self) -> None:
        p = default_paths().data_dir
        try:
            os.startfile(str(p))  # type: ignore[attr-defined]
        except Exception as e:
            QMessageBox.critical(None, "Data dir", str(e))

    def _set_autostart(self, enabled: bool) -> None:
        exe = sys.executable
        res = set_autostart_enabled(exe, enabled)
        if self._db is not None:
            set_setting(self._db, key="autostart", value="1" if enabled else "0")
        QMessageBox.information(None, "Автозапуск", res.details)

    def _show_admin_help(self) -> None:
        exe = sys.executable
        text = (
            "Для чтения некоторых событий (особенно канал Security) могут требоваться права администратора.\n\n"
            "Как запустить:\n"
            "1) Закрой miniSIEM\n"
            "2) ПКМ по miniSIEM.exe → Запуск от имени администратора\n\n"
            "Или PowerShell:\n"
            f'Start-Process -FilePath "{exe}" -Verb RunAs\n'
        )
        QMessageBox.information(None, "Запуск от администратора", text)

    def _demo_generate_alert(self) -> None:
        if self._db is None:
            return
        ts = datetime.now(timezone.utc).isoformat()
        title = "DEMO: тестовый алерт (защита диплома)"
        details = f"ts={ts} | синтетическое событие (кнопка Demo)"
        alert_id = insert_alert(
            self._db,
            rule_id="DEMO",
            severity="info",
            title=title,
            details=details,
            ts_utc=ts,
        )
        insert_action(
            self._db,
            alert_id=alert_id,
            action_type="notify",
            target="tray",
            result="dry-run" if self._dry_run else "executed",
            details="Показать уведомление (demo)",
            ts_utc=ts,
        )
        self._notify_alert(title, details)
        if self._alerts_tab:
            self._alerts_tab.refresh()
        if self._actions_tab:
            self._actions_tab.refresh()
        if self._dashboard_tab:
            self._dashboard_tab.refresh(
                last_tick_utc=self._collector_last_tick_utc,
                last_new_events=self._collector_last_new_events,
                channel_status=self._collector_channel_status,
            )

    def _demo_seed_data(self, n_events: int = 300, n_alerts: int = 15) -> None:
        if self._db is None:
            return
        now = datetime.now(timezone.utc)

        # events
        rows = []
        demo_event_ids = [4624, 4625, 1102, 4688, 1, 3]
        demo_channels = [
            "Security",
            "System",
            "Application",
            "Microsoft-Windows-Sysmon/Operational",
        ]
        for i in range(int(n_events)):
            ts = (now - timedelta(minutes=(n_events - i) / 10)).isoformat()
            channel = demo_channels[i % len(demo_channels)]
            eid = demo_event_ids[i % len(demo_event_ids)]
            rows.append(
                {
                    "ts_utc": ts,
                    "channel": channel,
                    "provider": "DEMO",
                    "event_id": int(eid),
                    "level": 4,
                    "computer": "DEMO-PC",
                    "record_id": 10_000_000 + i,
                    "message": None,
                    "data": {"demo": True, "hint": "synthetic event for diploma demo"},
                }
            )
        bulk_insert_events(self._db, rows)

        # alerts + actions
        for i in range(int(n_alerts)):
            ts = (now - timedelta(minutes=i)).isoformat()
            title = f"DEMO alert #{i + 1}"
            alert_id = insert_alert(
                self._db,
                rule_id="DEMO",
                severity="info",
                title=title,
                details=f"ts={ts} | synthetic alert for demo",
                ts_utc=ts,
            )
            insert_action(
                self._db,
                alert_id=alert_id,
                action_type="demo_notify",
                target="ui",
                result="executed",
                details="synthetic action",
                ts_utc=ts,
            )

        self._notify_alert("DEMO: данные сгенерированы", f"events={n_events}, alerts={n_alerts}")
        if self._events_tab:
            self._events_tab.refresh()
        if self._alerts_tab:
            self._alerts_tab.refresh()
        if self._actions_tab:
            self._actions_tab.refresh()
        if self._dashboard_tab:
            self._dashboard_tab.refresh(
                last_tick_utc=self._collector_last_tick_utc,
                last_new_events=self._collector_last_new_events,
                channel_status=self._collector_channel_status,
            )

    def _demo_bruteforce_ip(
        self,
        ip: str = "10.10.10.10",
        account: str = "DEMO\\victim",
        n: int = 12,
        *,
        logon_type: str = "3",
    ) -> None:
        """
        Generate synthetic Security 4625 events with parsed.ip/account so that
        brute-force detectors can fire during defense/demo.
        """
        if self._db is None:
            return
        now = datetime.now(timezone.utc)
        rows = []
        base_rid = 20_000_000
        for i in range(int(n)):
            ts = (now - timedelta(seconds=(int(n) - i) * 10)).isoformat()
            rows.append(
                {
                    "ts_utc": ts,
                    "channel": "Security",
                    "provider": "DEMO",
                    "event_id": 4625,
                    "level": 4,
                    "computer": "DEMO-PC",
                    "record_id": base_rid + i,
                    "message": None,
                    "data": {
                        "demo": True,
                        "StringInserts": [account, str(logon_type), ip],
                        "parsed": {"account": account, "ip": ip, "logon_type": str(logon_type), "event_id": 4625},
                    },
                }
            )
        bulk_insert_events(self._db, rows)

        # run detectors immediately on this synthetic batch
        events = []
        for r in rows:
            events.append(
                {
                    "ts_utc": r["ts_utc"],
                    "channel": r["channel"],
                    "provider": r["provider"],
                    "event_id": r["event_id"],
                    "level": r["level"],
                    "computer": r["computer"],
                    "record_id": r["record_id"],
                    "message": r["message"],
                    "data": r["data"],
                }
            )
        alerts = run_detectors(events, self._rule_defs, self._rules_enabled, self._rules_params)
        created = 0
        for a in alerts:
            alert_id = insert_alert(self._db, rule_id=a.rule_id, severity=a.severity, title=a.title, details=a.details)
            insert_action(
                self._db,
                alert_id=alert_id,
                action_type="demo_notify",
                target="ui",
                result="executed",
                details=f"demo bruteforce ip={ip}",
                ts_utc=now.isoformat(),
            )
            created += 1
        if created == 0:
            # If user rules YAML wasn't updated yet, still create a visible demo incident.
            title = "DEMO: brute-force (4625 burst) по IP/аккаунту"
            details = (
                "Синтетические события сгенерированы, но правила могли быть не добавлены в YAML.\n"
                "Открой вкладку Rules → Append sample rules → Save, чтобы включить новые детекты.\n\n"
                f"ip={ip} account={account} events={n}"
            )
            alert_id = insert_alert(self._db, rule_id="DEMO", severity="info", title=title, details=details)
            insert_action(
                self._db,
                alert_id=alert_id,
                action_type="demo_notify",
                target="ui",
                result="executed",
                details=f"demo bruteforce fallback ip={ip}",
                ts_utc=now.isoformat(),
            )
            created = 1
        self._notify_alert("DEMO: brute-force сгенерирован", f"ip={ip} events={n} alerts={created}")
        if self._events_tab:
            self._events_tab.refresh()
        if self._alerts_tab:
            self._alerts_tab.refresh()
        if self._actions_tab:
            self._actions_tab.refresh()
        if self._dashboard_tab:
            self._dashboard_tab.refresh(
                last_tick_utc=self._collector_last_tick_utc,
                last_new_events=self._collector_last_new_events,
                channel_status=self._collector_channel_status,
            )

    def _demo_clear_data(self) -> None:
        if self._db is None:
            return
        deleted = delete_demo_data(self._db)
        self._notify_alert("DEMO: данные удалены", str(deleted))
        if self._events_tab:
            self._events_tab.refresh()
        if self._alerts_tab:
            self._alerts_tab.refresh()
        if self._actions_tab:
            self._actions_tab.refresh()
        if self._dashboard_tab:
            self._dashboard_tab.refresh(
                last_tick_utc=self._collector_last_tick_utc,
                last_new_events=self._collector_last_new_events,
                channel_status=self._collector_channel_status,
            )

    def _set_dry_run(self, enabled: bool) -> None:
        self._dry_run = enabled
        if self._db is not None:
            set_setting(self._db, key="dry_run", value="1" if enabled else "0")

    def _set_lock_ws(self, enabled: bool) -> None:
        self._real_lock_workstation = enabled
        if self._db is not None:
            set_setting(self._db, key="lock_workstation", value="1" if enabled else "0")

    def _set_toast(self, enabled: bool) -> None:
        self._toast_enabled = enabled
        if self._db is not None:
            set_setting(self._db, key="toast_enabled", value="1" if enabled else "0")

    def _set_collector_enabled(self, enabled: bool) -> None:
        self._collector_enabled = bool(enabled)
        if self._db is not None:
            set_setting(self._db, key="collector_enabled", value="1" if self._collector_enabled else "0")

    def _set_poll_interval_ms(self, ms: int) -> None:
        ms = int(ms)
        if ms < 1000:
            ms = 1000
        self._poll_interval_ms = int(ms)
        if self._db is not None:
            set_setting(self._db, key="poll_interval_ms", value=str(self._poll_interval_ms))
        if self._timer is not None:
            self._timer.setInterval(int(self._poll_interval_ms))

    def _refresh_display_tz(self) -> None:
        h = display_tz_offset_hours(self._db)
        if self._events_tab:
            self._events_tab.apply_display_tz(h)
        if self._alerts_tab:
            self._alerts_tab.apply_display_tz(h)
        if self._actions_tab:
            self._actions_tab.apply_display_tz(h)
        if self._dashboard_tab:
            self._dashboard_tab.refresh(
                last_tick_utc=self._collector_last_tick_utc,
                last_new_events=self._collector_last_new_events,
                channel_status=self._collector_channel_status,
            )

    def _notify_alert(self, title: str, details: str) -> None:
        if not self._toast_enabled:
            return
        if self._tray is None:
            return
        # Keep message short
        msg = details.strip().replace("\r", " ").replace("\n", " ")
        if len(msg) > 180:
            msg = msg[:180] + "…"
        try:
            self._tray.showMessage(title, msg, QSystemTrayIcon.MessageIcon.Warning, 7000)
        except Exception:
            pass

    def _reaction_lock_workstation(self, alert_id: int) -> None:
        if self._db is None:
            return
        if self._dry_run:
            insert_action(
                self._db,
                alert_id=alert_id,
                action_type="lock_workstation",
                target="local",
                result="dry-run",
                details="rundll32 user32.dll,LockWorkStation",
            )
            return
        try:
            subprocess.run(
                ["rundll32.exe", "user32.dll,LockWorkStation"],
                check=True,
                capture_output=True,
                text=True,
            )
            insert_action(
                self._db,
                alert_id=alert_id,
                action_type="lock_workstation",
                target="local",
                result="executed",
                details="LockWorkStation выполнен",
            )
        except Exception as e:
            insert_action(
                self._db,
                alert_id=alert_id,
                action_type="lock_workstation",
                target="local",
                result="error",
                details=str(e),
            )

    def _maintenance(self, kind: str) -> None:
        if self._db is None:
            return
        now = datetime.now(timezone.utc)
        if kind == "prune_7d":
            cutoff = (now - timedelta(days=7)).isoformat()
            de = prune_events_older_than(self._db, cutoff)
            da = prune_alerts_older_than(self._db, cutoff)
            dac = prune_actions_older_than(self._db, cutoff)
            insert_action(
                self._db,
                alert_id=None,
                action_type="maintenance",
                target="sqlite",
                result="executed",
                details=f"prune<7d: events={de}, alerts={da}, actions={dac}",
            )
        elif kind == "clear_events":
            clear_table(self._db, "events")
            insert_action(
                self._db,
                alert_id=None,
                action_type="maintenance",
                target="sqlite",
                result="executed",
                details="clear table events",
            )
        elif kind == "reset_offsets":
            for ch in list(self._channel_offsets.keys()):
                self._channel_offsets.pop(ch, None)
                set_setting(self._db, key=f"offset::{ch}", value=None)
            insert_action(
                self._db,
                alert_id=None,
                action_type="maintenance",
                target="collector",
                result="executed",
                details="reset channel offsets",
            )
        elif kind == "vacuum":
            vacuum(self._db)
            checkpoint_wal(self._db)
            insert_action(
                self._db,
                alert_id=None,
                action_type="maintenance",
                target="sqlite",
                result="executed",
                details="vacuum + wal_checkpoint",
            )
        elif kind == "backfill_parsed":
            n = backfill_security_logon_parsed_fields(self._db, limit=20_000)
            insert_action(
                self._db,
                alert_id=None,
                action_type="maintenance",
                target="sqlite",
                result="executed",
                details=f"backfill parsed fields (Security 4624/4625): rows={n}",
            )
        elif kind == "norm_eventid":
            n = normalize_legacy_event_ids(self._db, limit=2_000_000)
            insert_action(
                self._db,
                alert_id=None,
                action_type="maintenance",
                target="sqlite",
                result="executed",
                details=f"normalize legacy event_id values: rows={n}",
            )
        if self._events_tab:
            self._events_tab.refresh()
        if self._alerts_tab:
            self._alerts_tab.refresh()
        if self._actions_tab:
            self._actions_tab.refresh()
        if self._dashboard_tab:
            self._dashboard_tab.refresh(
                last_tick_utc=self._collector_last_tick_utc,
                last_new_events=self._collector_last_new_events,
                channel_status=self._collector_channel_status,
            )

    def _test_rules(self, minutes: int) -> None:
        if self._db is None:
            return
        now = datetime.now(timezone.utc)
        since = (now - timedelta(minutes=int(minutes))).isoformat()
        recent = fetch_events_since(self._db, since, limit=5000)
        events = []
        for r in recent:
            try:
                data = json.loads(r["data_json"] or "{}")
            except Exception:
                data = {}
            events.append(
                {
                    "ts_utc": r["ts_utc"],
                    "channel": r["channel"],
                    "provider": r["provider"],
                    "event_id": r["event_id"],
                    "level": r["level"],
                    "computer": r["computer"],
                    "record_id": r["record_id"],
                    "message": r["message"],
                    "data": data,
                }
            )
        alerts = run_detectors(events, self._rule_defs, self._rules_enabled, self._rules_params)
        by_rule: dict[str, int] = {}
        for a in alerts:
            by_rule[a.rule_id] = by_rule.get(a.rule_id, 0) + 1
        lines = [
            f"Тест правил за последние {minutes} мин",
            f"Событий: {len(events)}",
            f"Алертов: {len(alerts)}",
            "",
        ]
        for rid in sorted(by_rule.keys()):
            lines.append(f"{rid}: {by_rule[rid]}")
        QMessageBox.information(None, "Test rules", "\n".join(lines))


class _PlaceholderTab(QWidget):
    def __init__(self, title: str) -> None:
        super().__init__()
        self._log = QTextEdit()
        self._log.setReadOnly(True)
        self._log.setText(
            title
            + "\n\n"
            + "Дальше здесь появятся таблицы, фильтры и действия.\n"
            + "Сначала подключаю хранилище и сбор событий."
        )

        layout = QVBoxLayout()
        layout.addWidget(self._log)
        self.setLayout(layout)


def _show_about(parent: QWidget) -> None:
    QMessageBox.information(
        parent,
        "О программе",
        "miniSIEM — дипломный проект.\n"
        "Сбор: Windows Event Log / Sysmon, анализ правилами, алерты и реакции.",
    )


class _SqlTableModel(QAbstractTableModel):
    def __init__(self, columns: list[tuple[str, str]], *, display_tz_offset_hours: int = 5) -> None:
        super().__init__()
        self._columns = columns
        self._rows: list[sqlite3.Row] = []
        self._display_tz_offset_hours = int(display_tz_offset_hours)

    def set_display_tz_offset_hours(self, hours: int) -> None:
        nh = int(hours)
        if nh == self._display_tz_offset_hours:
            return
        self._display_tz_offset_hours = nh
        col_idx = next((i for i, (k, _) in enumerate(self._columns) if k == "ts_utc"), None)
        if col_idx is None or not self._rows:
            return
        top_left = self.index(0, col_idx)
        bottom_right = self.index(len(self._rows) - 1, col_idx)
        self.dataChanged.emit(top_left, bottom_right, [Qt.DisplayRole])

    def set_rows(self, rows: list[sqlite3.Row]) -> None:
        self.beginResetModel()
        self._rows = rows
        self.endResetModel()

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:  # noqa: N802
        return 0 if parent.isValid() else len(self._rows)

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:  # noqa: N802
        return 0 if parent.isValid() else len(self._columns)

    def headerData(self, section: int, orientation: Qt.Orientation, role: int = Qt.DisplayRole):  # noqa: N802
        if role != Qt.DisplayRole:
            return None
        if orientation == Qt.Horizontal:
            return self._columns[section][1]
        return str(section + 1)

    def data(self, index: QModelIndex, role: int = Qt.DisplayRole):  # noqa: N802
        row = self._rows[index.row()]
        key = self._columns[index.column()][0]
        if role == Qt.DisplayRole:
            v = row[key]
            if v is None:
                return ""
            if key == "ts_utc":
                return format_utc_iso_for_display(v, offset_hours=self._display_tz_offset_hours)
            # Human-friendly display for Security LogonType (if present as parsed column)
            if key == "parsed_logon_type":
                lbl = logon_type_label(v)
                return f"{v} ({lbl})" if lbl else str(v)
            return str(v)
        # Coloring for alerts table (if columns exist)
        if role in (Qt.BackgroundRole, Qt.ForegroundRole):
            if "severity" in row.keys():
                sev = str(row["severity"] or "").lower()
                if role == Qt.BackgroundRole:
                    from PySide6.QtGui import QColor

                    if sev in ("critical",):
                        return QColor("#ffebee")  # light red
                    if sev in ("high",):
                        return QColor("#fff3e0")  # light orange
                    if sev in ("medium",):
                        return QColor("#fffde7")  # light yellow
                    if sev in ("low", "info"):
                        return QColor("#e8f5e9")  # light green
        return None


class _EventsTab(QWidget):
    def __init__(self, con: sqlite3.Connection) -> None:
        super().__init__()
        self._con = con
        self._last_selected_event_row_id: int | None = None
        tz0 = display_tz_offset_hours(con)
        self._model = _SqlTableModel(
            [
                ("ts_utc", "время"),
                ("channel", "channel"),
                ("event_id", "event_id"),
                ("parsed_account", "account"),
                ("parsed_ip", "ip"),
                ("parsed_logon_type", "logon_type"),
                ("provider", "provider"),
                ("computer", "computer"),
                ("record_id", "record_id"),
            ],
            display_tz_offset_hours=tz0,
        )
        from PySide6.QtWidgets import QTableView

        self._table = QTableView()
        self._table.setModel(self._model)
        self._table.setSortingEnabled(False)
        self._table.setSelectionBehavior(QTableView.SelectionBehavior.SelectRows)
        self._table.setEditTriggers(QTableView.EditTrigger.NoEditTriggers)
        self._table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        polish_table_view(self._table)

        self._channel = QComboBox()
        self._channel.addItem("All", "")
        for ch in DEFAULT_CHANNELS:
            self._channel.addItem(ch.name, ch.name)
        self._event_id = QLineEdit()
        self._event_id.setPlaceholderText("EventID (например 4625)")
        self._account = QLineEdit()
        self._account.setPlaceholderText("account (domain\\user)")
        self._ip = QLineEdit()
        self._ip.setPlaceholderText("ip (например 192.168.1.10)")
        self._logon_type = QLineEdit()
        self._logon_type.setPlaceholderText("logon_type (2/3/10…)")
        self._text = QLineEdit()
        self._text.setPlaceholderText("поиск (provider/computer/data_json)")
        self._text.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self._text.setMinimumWidth(160)
        self._channel.setMinimumWidth(160)
        self._ts_from = QLineEdit()
        self._ts_from.setPlaceholderText(
            f"от (UTC{display_tz_offset_hours(con):+d}, YYYY-MM-DD HH:MM)"
        )
        self._ts_from.setMinimumWidth(175)
        self._ts_from.setMaximumWidth(260)
        self._ts_to = QLineEdit()
        self._ts_to.setPlaceholderText(
            f"до (UTC{display_tz_offset_hours(con):+d}, YYYY-MM-DD HH:MM)"
        )
        self._ts_to.setMinimumWidth(175)
        self._ts_to.setMaximumWidth(260)
        self._btn_apply = QPushButton("Применить")
        self._btn_clear = QPushButton("Сброс")
        self._btn_import_evtx = QPushButton("Import EVTX…")
        for b in (self._btn_apply, self._btn_clear, self._btn_import_evtx):
            b.setMinimumWidth(118)
            b.setSizePolicy(QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Fixed)

        self._details = QTextEdit()
        self._details.setReadOnly(True)

        self._btn_apply.clicked.connect(self.refresh)
        self._btn_clear.clicked.connect(self._clear_filters)
        self._btn_import_evtx.clicked.connect(self._import_evtx)
        self._table.selectionModel().selectionChanged.connect(lambda *_: self._render_details())

        filters_top = QHBoxLayout()
        filters_top.setSpacing(10)
        filters_top.addWidget(QLabel("Channel"))
        filters_top.addWidget(self._channel)
        filters_top.addWidget(QLabel("EventID"))
        filters_top.addWidget(self._event_id)
        filters_top.addWidget(QLabel("account"))
        filters_top.addWidget(self._account)
        filters_top.addWidget(QLabel("ip"))
        filters_top.addWidget(self._ip)
        filters_top.addWidget(QLabel("logon"))
        filters_top.addWidget(self._logon_type)
        filters_top.addStretch(1)

        filters_mid = QHBoxLayout()
        filters_mid.setSpacing(10)
        filters_mid.addWidget(QLabel("Поиск"))
        filters_mid.addWidget(self._text, stretch=1)
        filters_mid.addWidget(QLabel("from"))
        filters_mid.addWidget(self._ts_from)
        filters_mid.addWidget(QLabel("to"))
        filters_mid.addWidget(self._ts_to)
        filters_mid.addWidget(self._btn_apply)
        filters_mid.addWidget(self._btn_clear)
        filters_mid.addWidget(self._btn_import_evtx)

        # Keep details visible on the right (better for demo)
        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.addWidget(self._table)
        splitter.addWidget(self._details)
        splitter.setStretchFactor(0, 4)
        splitter.setStretchFactor(1, 3)

        layout = QVBoxLayout()
        layout.setSpacing(10)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addLayout(filters_top)
        layout.addLayout(filters_mid)
        layout.addWidget(splitter)
        self.setLayout(layout)
        self.refresh()

    def apply_display_tz(self, hours: int) -> None:
        h = int(hours)
        self._model.set_display_tz_offset_hours(h)
        self._ts_from.setPlaceholderText(f"от (UTC{h:+d}, YYYY-MM-DD HH:MM)")
        self._ts_to.setPlaceholderText(f"до (UTC{h:+d}, YYYY-MM-DD HH:MM)")
        self._render_details()

    def select_event_by_row_id(self, event_row_id: int) -> None:
        """
        Navigate to a specific event (SQLite row id) and ensure it is visible+selected.
        We load a small time window around the event so it is guaranteed to appear.
        """
        try:
            ev = get_event_by_id(self._con, int(event_row_id))
        except Exception:
            ev = None
        if ev is None:
            # Fallback to normal refresh
            self._last_selected_event_row_id = int(event_row_id)
            self.refresh()
            return

        # Clear filters that could hide the event
        try:
            self._channel.setCurrentIndex(0)
            self._event_id.setText("")
            self._account.setText("")
            self._ip.setText("")
            self._logon_type.setText("")
            self._text.setText("")
        except Exception:
            pass

        # Load a context window around the event timestamp (±10 min)
        try:
            ts = str(ev["ts_utc"])
            dt = datetime.fromisoformat(ts)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            dt = dt.astimezone(timezone.utc)
            ts_from = (dt - timedelta(minutes=10)).isoformat()
            ts_to = (dt + timedelta(minutes=10)).isoformat()
            rows = fetch_events_between(self._con, ts_from_utc=ts_from, ts_to_utc=ts_to, limit=2000)
        except Exception:
            rows = fetch_recent_events(self._con, limit=500)

        self._last_selected_event_row_id = int(event_row_id)
        self._model.set_rows(rows)
        self._restore_selection()
        self._render_details()
        size_table_columns(self._table)

    def _import_evtx(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Импорт EVTX",
            "",
            "EVTX (*.evtx);;All files (*.*)",
        )
        if not path:
            return
        from PySide6.QtWidgets import QInputDialog

        limit, ok = QInputDialog.getInt(self, "Импорт EVTX", "Сколько событий импортировать?", 2000, 1, 200_000, 100)
        if not ok:
            return

        dlg = QProgressDialog("Импорт EVTX…", "Отмена", 0, 0, self)
        dlg.setWindowTitle("Import EVTX")
        dlg.setWindowModality(Qt.WindowModality.WindowModal)
        dlg.setMinimumDuration(0)
        dlg.show()

        thread = QThread(self)
        worker = _EvtxImportWorker(self._con, Path(path), int(limit))
        worker.moveToThread(thread)

        def _cleanup() -> None:
            dlg.close()
            worker.deleteLater()
            thread.quit()
            thread.wait(2000)
            thread.deleteLater()

        dlg.canceled.connect(worker.cancel)
        worker.finished.connect(lambda n: (QMessageBox.information(self, "Import EVTX", f"Импортировано событий: {n}"), self.refresh(), _cleanup()))
        worker.failed.connect(lambda err: (QMessageBox.critical(self, "Import EVTX", err), _cleanup()))
        thread.started.connect(worker.run)
        thread.start()

    def _clear_filters(self) -> None:
        self._channel.setCurrentIndex(0)
        self._event_id.setText("")
        self._account.setText("")
        self._ip.setText("")
        self._logon_type.setText("")
        self._text.setText("")
        self._ts_from.setText("")
        self._ts_to.setText("")
        self.refresh()

    def refresh(self) -> None:
        # Preserve selection across auto-refreshes
        tz_h = display_tz_offset_hours(self._con)
        self._model.set_display_tz_offset_hours(tz_h)
        self._last_selected_event_row_id = self._get_selected_event_row_id()

        channel = str(self._channel.currentData() or "") or None
        event_id = None
        if self._event_id.text().strip():
            try:
                event_id = int(self._event_id.text().strip())
            except ValueError:
                event_id = None
        account = self._account.text().strip() or None
        ip = self._ip.text().strip() or None
        logon_type = self._logon_type.text().strip() or None
        text = self._text.text().strip() or None
        ts_from = parse_user_time_to_utc_iso(self._ts_from.text(), display_offset_hours=tz_h)
        ts_to = parse_user_time_to_utc_iso(self._ts_to.text(), display_offset_hours=tz_h)
        if channel or (event_id is not None) or text or account or ip or logon_type or ts_from or ts_to:
            rows = search_events(
                self._con,
                ts_from_utc=ts_from,
                ts_to_utc=ts_to,
                channel=channel,
                event_id=event_id,
                text=text,
                account=account,
                ip=ip,
                logon_type=logon_type,
                limit=500,
            )
        else:
            rows = fetch_recent_events(self._con, limit=500)
        self._model.set_rows(rows)
        self._restore_selection()
        self._render_details()
        size_table_columns(self._table)

    def _get_selected_event_row_id(self) -> int | None:
        try:
            sm = self._table.selectionModel()
            if sm is None:
                return None
            sel = sm.selectedRows()
            if sel:
                row_idx = sel[0].row()
            else:
                idx = self._table.currentIndex()
                if not idx.isValid():
                    return None
                row_idx = idx.row()
            row = self._model._rows[row_idx]
            return int(row["id"])
        except Exception:
            return None

    def _restore_selection(self) -> None:
        want = self._last_selected_event_row_id
        if want is None:
            return
        # Find the same DB row id in refreshed model and re-select it.
        for i, r in enumerate(self._model._rows):
            try:
                if int(r["id"]) == int(want):
                    self._table.selectRow(i)
                    # Ensure currentIndex is set so _render_details reads the right row.
                    self._table.setCurrentIndex(self._model.index(i, 0))
                    return
            except Exception:
                continue

    def _render_details(self) -> None:
        idx = self._table.currentIndex()
        if not idx.isValid():
            self._details.setText("")
            return
        row = self._model._rows[idx.row()]
        event_id = int(row["id"])
        full = get_event_by_id(self._con, event_id)
        if not full:
            self._details.setText("")
            return
        try:
            data = json.loads(full["data_json"] or "{}")
            data_pretty = json.dumps(data, ensure_ascii=False, indent=2)
        except Exception:
            data = {}
            data_pretty = str(full["data_json"] or "")

        # Human-friendly extracted fields (when present)
        parsed = {}
        if isinstance(data, dict):
            p = data.get("parsed") or {}
            if isinstance(p, dict):
                parsed = p
        event_data = {}
        if isinstance(data, dict):
            ed = data.get("EventData") or {}
            if isinstance(ed, dict):
                event_data = ed

        parsed_lines: list[str] = []
        if parsed:
            parsed_lines.append("parsed:")
            for k in ("account", "ip", "event_id"):
                if k in parsed and parsed.get(k) not in (None, "", "-"):
                    parsed_lines.append(f"  {k}: {parsed.get(k)}")
            if "logon_type" in parsed and parsed.get("logon_type") not in (None, "", "-"):
                lt = parsed.get("logon_type")
                lbl = logon_type_label(lt)
                if lbl:
                    parsed_lines.append(f"  logon_type: {lt} ({lbl})")
                else:
                    parsed_lines.append(f"  logon_type: {lt}")
        if event_data:
            # Keep it short (top few keys) to avoid flooding UI.
            parsed_lines.append("EventData:")
            keys = list(event_data.keys())
            for k in keys[:12]:
                v = event_data.get(k)
                if v is None or v == "":
                    continue
                sv = str(v)
                if len(sv) > 140:
                    sv = sv[:140] + "…"
                parsed_lines.append(f"  {k}: {sv}")
            if len(keys) > 12:
                parsed_lines.append(f"  … ({len(keys) - 12} more)")
        tz_h = display_tz_offset_hours(self._con)
        header = (
            f"id: {full['id']}\n"
            f"время: {format_utc_iso_for_display(full['ts_utc'], offset_hours=tz_h)}\n"
            f"(UTC в БД): {full['ts_utc']}\n"
            f"channel: {full['channel']}\n"
            f"provider: {full['provider']}\n"
            f"event_id: {full['event_id']}\n"
            f"computer: {full['computer']}\n"
            f"record_id: {full['record_id']}\n\n"
        )
        parsed_block = ("\n".join(parsed_lines) + "\n\n") if parsed_lines else ""
        self._details.setText(header + parsed_block + f"data_json:\n{data_pretty}")


class _EvtxImportWorker(QObject):
    finished = Signal(int)
    failed = Signal(str)

    def __init__(self, con: sqlite3.Connection, path: Path, limit: int) -> None:
        super().__init__()
        self._con = con
        self._path = path
        self._limit = int(limit)
        self._cancel = False

    def cancel(self) -> None:
        self._cancel = True

    def run(self) -> None:
        try:
            if self._cancel:
                self.finished.emit(0)
                return
            rows = import_evtx_file(self._path, limit=self._limit)
            if self._cancel:
                self.finished.emit(0)
                return
            n = bulk_insert_events(self._con, rows)
            self.finished.emit(int(n))
        except Exception as e:
            self.failed.emit(str(e))


class _AlertsTab(QWidget):
    def __init__(self, con: sqlite3.Connection, *, on_open_event) -> None:
        super().__init__()
        self._con = con
        self._on_open_event = on_open_event
        self._last_selected_alert_id: int | None = None
        tz0 = display_tz_offset_hours(con)
        self._status = QComboBox()
        self._status.addItem("All", "")
        self._status.addItem("new", "new")
        self._status.addItem("ack", "ack")
        self._status.addItem("closed", "closed")
        self._severity = QComboBox()
        self._severity.addItem("All", "")
        self._severity.addItem("critical", "critical")
        self._severity.addItem("high", "high")
        self._severity.addItem("medium", "medium")
        self._severity.addItem("low", "low")
        self._severity.addItem("info", "info")
        self._rule = QLineEdit()
        self._rule.setPlaceholderText("rule_id (например WIN-SEC-4625)")
        self._text = QLineEdit()
        self._text.setPlaceholderText("поиск (title/details/rule_id)")
        self._ts_from = QLineEdit()
        self._ts_from.setPlaceholderText(f"от (UTC{tz0:+d}, YYYY-MM-DD HH:MM)")
        self._ts_from.setMinimumWidth(175)
        self._ts_from.setMaximumWidth(260)
        self._ts_to = QLineEdit()
        self._ts_to.setPlaceholderText(f"до (UTC{tz0:+d}, YYYY-MM-DD HH:MM)")
        self._ts_to.setMinimumWidth(175)
        self._ts_to.setMaximumWidth(260)
        self._rule.setMinimumWidth(140)
        self._text.setMinimumWidth(160)
        self._rule.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self._text.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self._btn_apply = QPushButton("Применить")
        self._btn_clear = QPushButton("Сброс")

        self._model = _SqlTableModel(
            [
                ("ts_utc", "время"),
                ("severity", "severity"),
                ("rule_id", "rule_id"),
                ("title", "title"),
                ("status", "status"),
                ("comment", "comment"),
            ],
            display_tz_offset_hours=tz0,
        )
        from PySide6.QtWidgets import QTableView

        self._table = QTableView()
        self._table.setModel(self._model)
        self._table.setSelectionBehavior(QTableView.SelectionBehavior.SelectRows)
        self._table.setEditTriggers(QTableView.EditTrigger.NoEditTriggers)
        self._table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        polish_table_view(self._table)

        self._details = QTextEdit()
        self._details.setReadOnly(True)

        self._comment = QTextEdit()
        self._comment.setPlaceholderText("Заметка аналитика (комментарий к алерту)…")
        self._btn_save_note = QPushButton("Save note")
        self._btn_save_note.clicked.connect(self._save_comment)
        self._btn_export = QPushButton("Export incident (HTML)…")
        self._btn_export.clicked.connect(self._export_incident)
        self._btn_export_pdf = QPushButton("Export incident (PDF)…")
        self._btn_export_pdf.clicked.connect(self._export_incident_pdf)
        self._btn_export_json = QPushButton("Export incident (JSON)…")
        self._btn_export_json.clicked.connect(self._export_incident_json)
        self._btn_export_zip = QPushButton("Export incident (ZIP)…")
        self._btn_export_zip.clicked.connect(self._export_incident_zip)

        # Related events (incident context)
        from PySide6.QtWidgets import QTableView

        self._related_model = _SqlTableModel(
            [
                ("id", "id"),
                ("ts_utc", "время"),
                ("channel", "channel"),
                ("event_id", "event_id"),
                ("provider", "provider"),
                ("computer", "computer"),
                ("record_id", "record_id"),
            ],
            display_tz_offset_hours=tz0,
        )
        self._related = QTableView()
        self._related.setModel(self._related_model)
        self._related.setSelectionBehavior(QTableView.SelectionBehavior.SelectRows)
        self._related.setEditTriggers(QTableView.EditTrigger.NoEditTriggers)
        self._related.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self._related.setColumnHidden(0, True)
        self._related.doubleClicked.connect(self._open_related_event)
        polish_table_view(self._related)

        # Related actions for this alert
        self._actions_model = _SqlTableModel(
            [
                ("ts_utc", "время"),
                ("action_type", "action_type"),
                ("target", "target"),
                ("result", "result"),
                ("details", "details"),
            ],
            display_tz_offset_hours=tz0,
        )
        self._actions = QTableView()
        self._actions.setModel(self._actions_model)
        self._actions.setSelectionBehavior(QTableView.SelectionBehavior.SelectRows)
        self._actions.setEditTriggers(QTableView.EditTrigger.NoEditTriggers)
        self._actions.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        polish_table_view(self._actions)

        self._timeline = QTextEdit()
        self._timeline.setReadOnly(True)

        self._btn_ack = QPushButton("Ack")
        self._btn_close = QPushButton("Close")
        for b in (
            self._btn_apply,
            self._btn_clear,
            self._btn_ack,
            self._btn_close,
            self._btn_save_note,
            self._btn_export,
            self._btn_export_pdf,
            self._btn_export_json,
            self._btn_export_zip,
        ):
            b.setMinimumWidth(112)
            b.setSizePolicy(QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Fixed)
        self._btn_export.setMinimumWidth(168)
        self._btn_export_pdf.setMinimumWidth(188)
        self._btn_export_json.setMinimumWidth(188)
        self._btn_export_zip.setMinimumWidth(168)

        self._btn_ack.clicked.connect(lambda: self._set_status("ack"))
        self._btn_close.clicked.connect(lambda: self._set_status("closed"))
        self._btn_apply.clicked.connect(self.refresh)
        self._btn_clear.clicked.connect(self._clear_filters)
        self._table.selectionModel().selectionChanged.connect(lambda *_: self._render_details())

        filter_row = QHBoxLayout()
        filter_row.setSpacing(10)
        filter_row.addWidget(QLabel("status"))
        filter_row.addWidget(self._status)
        filter_row.addWidget(QLabel("severity"))
        filter_row.addWidget(self._severity)
        filter_row.addWidget(QLabel("rule_id"))
        filter_row.addWidget(self._rule, stretch=1)
        filter_row.addWidget(QLabel("поиск"))
        filter_row.addWidget(self._text, stretch=1)
        filter_row.addWidget(QLabel("from"))
        filter_row.addWidget(self._ts_from)
        filter_row.addWidget(QLabel("to"))
        filter_row.addWidget(self._ts_to)

        btn_row = QHBoxLayout()
        btn_row.setSpacing(10)
        for w in (
            self._btn_apply,
            self._btn_clear,
            self._btn_ack,
            self._btn_close,
            self._btn_export,
            self._btn_export_pdf,
            self._btn_export_json,
            self._btn_export_zip,
        ):
            btn_row.addWidget(w)
        btn_row.addStretch(1)

        actions = QVBoxLayout()
        actions.setSpacing(10)
        actions.addLayout(filter_row)
        actions.addLayout(btn_row)

        note_box = QWidget()
        note_lay = QVBoxLayout()
        note_lay.setContentsMargins(0, 0, 0, 0)
        note_lay.addWidget(QLabel("Комментарий"))
        note_lay.addWidget(self._comment)
        note_lay.addWidget(self._btn_save_note)
        note_box.setLayout(note_lay)

        right = QSplitter(Qt.Orientation.Vertical)
        right.addWidget(self._details)
        right.addWidget(note_box)
        right.addWidget(self._related)
        right.addWidget(self._actions)
        right.addWidget(self._timeline)
        right.setStretchFactor(0, 2)
        right.setStretchFactor(1, 2)
        right.setStretchFactor(2, 3)
        right.setStretchFactor(3, 2)
        right.setStretchFactor(4, 3)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.addWidget(self._table)
        splitter.addWidget(right)
        splitter.setStretchFactor(0, 2)
        splitter.setStretchFactor(1, 3)

        layout = QVBoxLayout()
        layout.setSpacing(10)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addLayout(actions)
        layout.addWidget(splitter)
        self.setLayout(layout)
        self.refresh()

    def apply_display_tz(self, hours: int) -> None:
        h = int(hours)
        self._model.set_display_tz_offset_hours(h)
        self._related_model.set_display_tz_offset_hours(h)
        self._actions_model.set_display_tz_offset_hours(h)
        self._ts_from.setPlaceholderText(f"от (UTC{h:+d}, YYYY-MM-DD HH:MM)")
        self._ts_to.setPlaceholderText(f"до (UTC{h:+d}, YYYY-MM-DD HH:MM)")
        self._render_details()

    def _clear_filters(self) -> None:
        self._status.setCurrentIndex(0)
        self._severity.setCurrentIndex(0)
        self._rule.setText("")
        self._text.setText("")
        self._ts_from.setText("")
        self._ts_to.setText("")
        self.refresh()

    def refresh(self) -> None:
        # Preserve selection across auto-refreshes
        tz_h = display_tz_offset_hours(self._con)
        self._model.set_display_tz_offset_hours(tz_h)
        self._related_model.set_display_tz_offset_hours(tz_h)
        self._actions_model.set_display_tz_offset_hours(tz_h)
        self._last_selected_alert_id = self._get_selected_alert_id()

        status = str(self._status.currentData() or "") or None
        severity = str(self._severity.currentData() or "") or None
        rule = self._rule.text().strip() or None
        text = self._text.text().strip() or None
        ts_from = parse_user_time_to_utc_iso(self._ts_from.text(), display_offset_hours=tz_h)
        ts_to = parse_user_time_to_utc_iso(self._ts_to.text(), display_offset_hours=tz_h)
        if status or severity or rule or text or ts_from or ts_to:
            where = []
            params: list[object] = []
            if ts_from:
                where.append("ts_utc >= ?")
                params.append(ts_from)
            if ts_to:
                where.append("ts_utc <= ?")
                params.append(ts_to)
            if status:
                where.append("status = ?")
                params.append(status)
            if severity:
                where.append("severity = ?")
                params.append(severity)
            if rule:
                where.append("rule_id LIKE ?")
                params.append(f"%{rule}%")
            if text:
                where.append("(title LIKE ? OR details LIKE ? OR rule_id LIKE ?)")
                like = f"%{text}%"
                params.extend([like, like, like])
            sql = "SELECT * FROM alerts"
            if where:
                sql += " WHERE " + " AND ".join(where)
            sql += " ORDER BY ts_utc DESC, id DESC LIMIT 500"
            cur = self._con.execute(sql, tuple(params))
            rows = list(cur.fetchall())
        else:
            rows = fetch_recent_alerts(self._con, limit=500)
        self._model.set_rows(rows)
        self._restore_selection()
        self._render_details()
        size_table_columns(self._table)

    def _get_selected_alert_id(self) -> int | None:
        try:
            sm = self._table.selectionModel()
            if sm is None:
                return None
            sel = sm.selectedRows()
            if sel:
                row_idx = sel[0].row()
            else:
                idx = self._table.currentIndex()
                if not idx.isValid():
                    return None
                row_idx = idx.row()
            row = self._model._rows[row_idx]
            return int(row["id"])
        except Exception:
            return None

    def _restore_selection(self) -> None:
        want = self._last_selected_alert_id
        if want is None:
            return
        for i, r in enumerate(self._model._rows):
            try:
                if int(r["id"]) == int(want):
                    self._table.selectRow(i)
                    self._table.setCurrentIndex(self._model.index(i, 0))
                    return
            except Exception:
                continue

    def _current_alert_row(self) -> sqlite3.Row | None:
        idx = self._table.currentIndex()
        if not idx.isValid():
            return None
        return self._model._rows[idx.row()]

    def _set_status(self, status: str) -> None:
        row = self._current_alert_row()
        if not row:
            return
        update_alert_status(self._con, int(row["id"]), status)
        self.refresh()

    def _render_details(self) -> None:
        row = self._current_alert_row()
        if not row:
            self._details.setText("")
            self._comment.setPlainText("")
            self._related_model.set_rows([])
            self._actions_model.set_rows([])
            self._timeline.setText("")
            size_table_columns(self._related)
            size_table_columns(self._actions)
            return
        tz_h = display_tz_offset_hours(self._con)
        self._related_model.set_display_tz_offset_hours(tz_h)
        self._actions_model.set_display_tz_offset_hours(tz_h)
        self._details.setText(
            f"id: {row['id']}\n"
            f"время: {format_utc_iso_for_display(row['ts_utc'], offset_hours=tz_h)}\n"
            f"(UTC в БД): {row['ts_utc']}\n"
            f"severity: {row['severity']}\n"
            f"rule_id: {row['rule_id']}\n"
            f"title: {row['title']}\n"
            f"status: {row['status']}\n\n"
            f"details:\n{row['details'] or ''}"
        )
        self._comment.setPlainText(str(row["comment"] or ""))

        # Related events: +-10 minutes around alert timestamp
        try:
            ts = str(row["ts_utc"])
            dt = datetime.fromisoformat(ts)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            dt = dt.astimezone(timezone.utc)
            ts_from = (dt - timedelta(minutes=10)).isoformat()
            ts_to = (dt + timedelta(minutes=10)).isoformat()
            rel = fetch_events_between(self._con, ts_from_utc=ts_from, ts_to_utc=ts_to, limit=500)
        except Exception:
            rel = []
        self._related_model.set_rows(rel)

        try:
            aid = int(row["id"])
            acts = fetch_actions_for_alert(self._con, alert_id=aid, limit=300)
        except Exception:
            acts = []
        self._actions_model.set_rows(acts)

        # Incident timeline (alert + actions + related events)
        try:
            entries: list[tuple[datetime, str]] = []
            ts_a = datetime.fromisoformat(str(row["ts_utc"]))
            if ts_a.tzinfo is None:
                ts_a = ts_a.replace(tzinfo=timezone.utc)
            ts_a = ts_a.astimezone(timezone.utc)
            entries.append(
                (
                    ts_a,
                    f"[ALERT] {row['severity']} {row['rule_id']} | {row['title']} | status={row['status']}",
                )
            )

            for a in acts:
                try:
                    dt = datetime.fromisoformat(str(a["ts_utc"]))
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=timezone.utc)
                    dt = dt.astimezone(timezone.utc)
                except Exception:
                    continue
                entries.append(
                    (
                        dt,
                        f"[ACTION] {a['action_type']} target={a['target'] or ''} result={a['result']} | {a['details'] or ''}",
                    )
                )

            for e in rel:
                try:
                    dt = datetime.fromisoformat(str(e["ts_utc"]))
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=timezone.utc)
                    dt = dt.astimezone(timezone.utc)
                except Exception:
                    continue
                extra = ""
                if str(e["channel"]) == "Security" and int(e["event_id"] or 0) in (4624, 4625):
                    acc = str(e["parsed_account"] or "")
                    ip = str(e["parsed_ip"] or "")
                    lt = str(e["parsed_logon_type"] or "")
                    parts = []
                    if acc:
                        parts.append(f"acc={acc}")
                    if ip:
                        parts.append(f"ip={ip}")
                    if lt:
                        parts.append(f"lt={lt}")
                    if parts:
                        extra = " | " + " ".join(parts)
                entries.append(
                    (
                        dt,
                        f"[EVENT] {e['channel']} {e['event_id']} provider={e['provider'] or ''} rid={e['record_id'] or ''}{extra}",
                    )
                )

            entries.sort(key=lambda x: x[0])
            lines = [
                f"{format_datetime_for_display(t, offset_hours=tz_h)} {msg}".rstrip() for t, msg in entries
            ]
            self._timeline.setText("\n".join(lines))
        except Exception:
            self._timeline.setText("")
        size_table_columns(self._related)
        size_table_columns(self._actions)

    def _open_related_event(self) -> None:
        try:
            idx = self._related.currentIndex()
            if not idx.isValid():
                return
            r = self._related_model._rows[idx.row()]
            ev_id = int(r["id"])
        except Exception:
            return
        try:
            self._on_open_event(int(ev_id))
        except Exception:
            return

    def _save_comment(self) -> None:
        row = self._current_alert_row()
        if not row:
            return
        aid = int(row["id"])
        txt = self._comment.toPlainText().strip()
        update_alert_comment(self._con, aid, txt or None)
        self.refresh()

    def _export_incident(self) -> None:
        row = self._current_alert_row()
        if not row:
            return
        aid = int(row["id"])
        suggested = f"minisiem-incident-alert-{aid}.html"
        path, _ = QFileDialog.getSaveFileName(self, "Экспорт инцидента (HTML)", suggested, "HTML (*.html);;All files (*.*)")
        if not path:
            return
        html_text = build_alert_html_report(self._con, alert_id=aid, title=f"miniSIEM — incident alert #{aid}")
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(html_text)
            QMessageBox.information(self, "Готово", f"Отчёт сохранён:\n{path}")
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", str(e))

    def _export_incident_pdf(self) -> None:
        row = self._current_alert_row()
        if not row:
            return
        aid = int(row["id"])
        suggested = f"minisiem-incident-alert-{aid}.pdf"
        path, _ = QFileDialog.getSaveFileName(self, "Экспорт инцидента (PDF)", suggested, "PDF (*.pdf);;All files (*.*)")
        if not path:
            return
        html_text = build_alert_html_report(self._con, alert_id=aid, title=f"miniSIEM — incident alert #{aid}")
        try:
            doc = QTextEdit()
            doc.setHtml(html_text)
            printer = QPrinter(QPrinter.PrinterMode.HighResolution)
            printer.setOutputFormat(QPrinter.OutputFormat.PdfFormat)
            printer.setOutputFileName(path)
            doc.document().print_(printer)
            QMessageBox.information(self, "Готово", f"PDF сохранён:\n{path}")
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", str(e))

    def _export_incident_json(self) -> None:
        row = self._current_alert_row()
        if not row:
            return
        aid = int(row["id"])
        suggested = f"minisiem-incident-alert-{aid}.json"
        path, _ = QFileDialog.getSaveFileName(self, "Экспорт инцидента (JSON)", suggested, "JSON (*.json);;All files (*.*)")
        if not path:
            return
        txt = build_alert_json_report(self._con, alert_id=aid)
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(txt)
            QMessageBox.information(self, "Готово", f"JSON сохранён:\n{path}")
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", str(e))

    def _export_incident_zip(self) -> None:
        row = self._current_alert_row()
        if not row:
            return
        aid = int(row["id"])
        suggested = f"minisiem-incident-alert-{aid}.zip"
        path, _ = QFileDialog.getSaveFileName(self, "Экспорт инцидента (ZIP)", suggested, "ZIP (*.zip);;All files (*.*)")
        if not path:
            return

        try:
            with tempfile.TemporaryDirectory(prefix="minisiem_incident_") as td:
                base = os.path.join(td, f"minisiem-incident-alert-{aid}")
                html_path = base + ".html"
                pdf_path = base + ".pdf"
                json_path = base + ".json"
                readme_path = base + ".txt"

                html_text = build_alert_html_report(self._con, alert_id=aid, title=f"miniSIEM — incident alert #{aid}")
                json_text = build_alert_json_report(self._con, alert_id=aid)

                with open(html_path, "w", encoding="utf-8") as f:
                    f.write(html_text)
                with open(json_path, "w", encoding="utf-8") as f:
                    f.write(json_text)
                with open(readme_path, "w", encoding="utf-8") as f:
                    f.write(
                        "miniSIEM incident export\n"
                        f"alert_id={aid}\n"
                        f"generated_utc={datetime.now(timezone.utc).isoformat()}\n\n"
                        "Files:\n"
                        f"- {os.path.basename(html_path)}\n"
                        f"- {os.path.basename(pdf_path)}\n"
                        f"- {os.path.basename(json_path)}\n"
                    )

                # Render PDF into temp file
                doc = QTextEdit()
                doc.setHtml(html_text)
                printer = QPrinter(QPrinter.PrinterMode.HighResolution)
                printer.setOutputFormat(QPrinter.OutputFormat.PdfFormat)
                printer.setOutputFileName(pdf_path)
                doc.document().print_(printer)

                # Zip all artifacts
                with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as z:
                    z.write(html_path, arcname=os.path.basename(html_path))
                    z.write(pdf_path, arcname=os.path.basename(pdf_path))
                    z.write(json_path, arcname=os.path.basename(json_path))
                    z.write(readme_path, arcname=os.path.basename(readme_path))

            QMessageBox.information(self, "Готово", f"ZIP сохранён:\n{path}")
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", str(e))


class _ActionsTab(QWidget):
    def __init__(self, con: sqlite3.Connection) -> None:
        super().__init__()
        self._con = con
        tz0 = display_tz_offset_hours(con)
        self._model = _SqlTableModel(
            [
                ("ts_utc", "время"),
                ("alert_id", "alert_id"),
                ("action_type", "action_type"),
                ("target", "target"),
                ("result", "result"),
            ],
            display_tz_offset_hours=tz0,
        )
        from PySide6.QtWidgets import QTableView

        self._table = QTableView()
        self._table.setModel(self._model)
        self._table.setSelectionBehavior(QTableView.SelectionBehavior.SelectRows)
        self._table.setEditTriggers(QTableView.EditTrigger.NoEditTriggers)
        polish_table_view(self._table)

        layout = QVBoxLayout()
        layout.addWidget(self._table)
        self.setLayout(layout)
        self.refresh()

    def apply_display_tz(self, hours: int) -> None:
        self._model.set_display_tz_offset_hours(int(hours))

    def refresh(self) -> None:
        tz_h = display_tz_offset_hours(self._con)
        self._model.set_display_tz_offset_hours(tz_h)
        rows = fetch_recent_actions(self._con, limit=500)
        self._model.set_rows(rows)
        size_table_columns(self._table)


class _SettingsTab(QWidget):
    def __init__(
        self,
        con: sqlite3.Connection,
        *,
        initial_dry_run: bool,
        initial_lock_ws: bool,
        initial_toast: bool,
        initial_collector_enabled: bool,
        initial_poll_interval_ms: int,
        on_change_dry_run,
        on_change_lock_ws,
        on_change_toast,
        on_change_collector_enabled,
        on_change_poll_interval_ms,
        on_maintenance,
        on_sysmon_tools,
        on_admin_help,
        on_copy_runas,
        on_demo_alert,
        on_demo_seed,
        on_demo_clear,
        on_demo_bruteforce_ip,
        on_open_data_dir,
        on_set_autostart,
        on_change_display_tz,
    ) -> None:
        super().__init__()
        self._con = con
        self._on_maintenance = on_maintenance
        self._on_toast = on_change_toast
        self._on_sysmon_tools = on_sysmon_tools
        self._on_admin_help = on_admin_help
        self._on_copy_runas = on_copy_runas
        self._on_demo_alert = on_demo_alert
        self._on_demo_seed = on_demo_seed
        self._on_demo_clear = on_demo_clear
        self._on_demo_bruteforce_ip = on_demo_bruteforce_ip
        self._on_open_data_dir = on_open_data_dir
        self._on_set_autostart = on_set_autostart
        self._on_display_tz = on_change_display_tz
        self._dry = QCheckBox("Dry-run реакции (ничего не менять в системе)")
        self._dry.setChecked(bool(initial_dry_run))
        self._dry.stateChanged.connect(lambda _: on_change_dry_run(bool(self._dry.isChecked())))

        self._lock = QCheckBox("Реакция: LockWorkStation при brute-force (4625 burst)")
        self._lock.setChecked(bool(initial_lock_ws))
        self._lock.stateChanged.connect(lambda _: on_change_lock_ws(bool(self._lock.isChecked())))

        self._toast = QCheckBox("Уведомления в трее при алертах")
        self._toast.setChecked(bool(initial_toast))
        self._toast.stateChanged.connect(lambda _: self._on_toast(bool(self._toast.isChecked())))

        self._collector_enabled = QCheckBox("Сбор событий включён (пауза/старт)")
        self._collector_enabled.setChecked(bool(initial_collector_enabled))
        self._collector_enabled.stateChanged.connect(
            lambda _: on_change_collector_enabled(bool(self._collector_enabled.isChecked()))
        )
        self._poll_interval = QLineEdit(str(max(1, int(initial_poll_interval_ms // 1000))))
        self._poll_interval.setMaximumWidth(60)
        self._poll_interval.setMinimumHeight(30)

        def _save_interval() -> None:
            txt = self._poll_interval.text().strip() or "4"
            try:
                sec = int(txt)
            except ValueError:
                sec = 4
            if sec < 1:
                sec = 1
            self._poll_interval.setText(str(sec))
            on_change_poll_interval_ms(int(sec) * 1000)

        self._poll_interval.editingFinished.connect(_save_interval)

        self._btn_report = QPushButton("Экспорт отчёта (HTML)…")
        self._btn_report.clicked.connect(self._export_report)
        self._btn_report_pdf = QPushButton("Экспорт отчёта (PDF)…")
        self._btn_report_pdf.clicked.connect(self._export_report_pdf)

        self._btn_sysmon_status = QPushButton("Sysmon: статус")
        self._btn_sysmon_status.clicked.connect(lambda: self._on_sysmon_tools("status"))
        self._btn_sysmon_cfg = QPushButton("Sysmon: создать конфиг")
        self._btn_sysmon_cfg.clicked.connect(lambda: self._on_sysmon_tools("write_config"))
        self._btn_sysmon_cmd = QPushButton("Sysmon: копировать команду установки")
        self._btn_sysmon_cmd.clicked.connect(lambda: self._on_sysmon_tools("copy_install_cmd"))

        self._btn_admin_help = QPushButton("Доступ к Security: как запустить от администратора")
        self._btn_admin_help.clicked.connect(lambda: self._on_admin_help())
        self._btn_copy_runas = QPushButton("Скопировать команду RunAs (PowerShell)")
        self._btn_copy_runas.clicked.connect(lambda: self._on_copy_runas())

        self._btn_demo_alert = QPushButton("Demo: сгенерировать тестовый алерт")
        self._btn_demo_alert.clicked.connect(lambda: self._on_demo_alert())
        self._btn_demo_seed = QPushButton("Demo: сгенерировать тестовые данные (events+alerts)")
        self._btn_demo_seed.clicked.connect(lambda: self._on_demo_seed(300, 15))
        self._btn_demo_clear = QPushButton("Demo: удалить демо-данные")
        self._btn_demo_clear.clicked.connect(lambda: self._on_demo_clear())
        self._btn_demo_bf = QPushButton("Demo: brute-force (4625 burst) по IP/аккаунту (logon_type=3)")
        self._btn_demo_bf.clicked.connect(lambda: self._on_demo_bruteforce_ip("10.10.10.10", "DEMO\\victim", 12, logon_type="3"))
        self._btn_demo_rdp_bf = QPushButton("Demo: RDP brute-force (4625, logon_type=10) по IP")
        self._btn_demo_rdp_bf.clicked.connect(
            lambda: self._on_demo_bruteforce_ip("10.10.10.10", "DEMO\\victim", 10, logon_type="10")
        )

        autostart_on, _ = get_autostart_enabled()
        self._autostart = QCheckBox("Автозапуск вместе с Windows (для текущего пользователя)")
        self._autostart.setChecked(bool(autostart_on))
        self._autostart.stateChanged.connect(lambda _: self._on_set_autostart(bool(self._autostart.isChecked())))
        self._btn_open_data = QPushButton("Открыть папку данных (SQLite/rules/конфиги)")
        self._btn_open_data.clicked.connect(lambda: self._on_open_data_dir())

        self._btn_prune = QPushButton("Обслуживание: удалить старше 7 дней")
        self._btn_prune.clicked.connect(lambda: self._on_maintenance("prune_7d"))
        self._btn_clear_events = QPushButton("Очистить события (events)")
        self._btn_clear_events.clicked.connect(lambda: self._on_maintenance("clear_events"))
        self._btn_reset_offsets = QPushButton("Сбросить offsets каналов")
        self._btn_reset_offsets.clicked.connect(lambda: self._on_maintenance("reset_offsets"))
        self._btn_vacuum = QPushButton("SQLite: VACUUM (оптимизация размера)")
        self._btn_vacuum.clicked.connect(lambda: self._on_maintenance("vacuum"))
        self._btn_backfill = QPushButton("Backfill: заполнить account/ip/logon_type (Security 4624/4625)")
        self._btn_backfill.clicked.connect(lambda: self._on_maintenance("backfill_parsed"))
        self._btn_norm_eid = QPushButton("Fix: нормализовать EventID (убрать большие/отрицательные значения)")
        self._btn_norm_eid.clicked.connect(lambda: self._on_maintenance("norm_eventid"))

        def _settings_fix_height(w: QWidget) -> None:
            w.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
            if isinstance(w, QPushButton):
                w.setMinimumHeight(36)

        row = QHBoxLayout()
        row.addWidget(self._dry)
        row.addWidget(self._lock)
        row.addWidget(self._toast)
        row.addStretch(1)

        self._ret_enabled = QCheckBox("Авто-ретеншн: удалять старые записи")
        self._ret_enabled.setChecked((get_setting(con, "retention_enabled") or "1") == "1")
        self._ret_enabled.stateChanged.connect(
            lambda _: set_setting(con, key="retention_enabled", value="1" if self._ret_enabled.isChecked() else "0")
        )
        self._ret_days = QLineEdit(get_setting(con, "retention_days") or "7")
        self._ret_days.setMaximumWidth(60)
        self._ret_days.setMinimumHeight(30)

        def _save_days() -> None:
            txt = self._ret_days.text().strip() or "7"
            try:
                d = int(txt)
            except ValueError:
                d = 7
            if d < 1:
                d = 1
            self._ret_days.setText(str(d))
            set_setting(con, key="retention_days", value=str(d))

        self._ret_days.editingFinished.connect(_save_days)
        ret_row = QHBoxLayout()
        ret_row.addWidget(self._ret_enabled)
        ret_row.addWidget(QLabel("дней:"))
        ret_row.addWidget(self._ret_days)
        ret_row.addStretch(1)

        coll_row = QHBoxLayout()
        coll_row.addWidget(self._collector_enabled)
        coll_row.addWidget(QLabel("интервал (сек):"))
        coll_row.addWidget(self._poll_interval)
        coll_row.addStretch(1)

        tz_row = QHBoxLayout()
        tz_row.addWidget(QLabel("Отображение времени (часы от UTC):"))
        self._disp_tz = QLineEdit(str(display_tz_offset_hours(con)))
        self._disp_tz.setMaximumWidth(56)
        self._disp_tz.setMinimumHeight(30)
        self._disp_tz.setToolTip(
            "Например 5 для UTC+5. В базе время в UTC; фильтры from/to без явного часового пояса "
            "интерпретируются в этом смещении."
        )

        def _save_disp_tz() -> None:
            txt = self._disp_tz.text().strip() or "5"
            try:
                h = int(txt)
            except ValueError:
                h = 5
            h = max(-12, min(14, h))
            self._disp_tz.setText(str(h))
            set_setting(con, key="display_tz_offset_hours", value=str(h))
            self._on_display_tz()

        self._disp_tz.editingFinished.connect(_save_disp_tz)
        tz_row.addWidget(self._disp_tz)
        tz_row.addStretch(1)

        layout = QVBoxLayout()
        layout.setSpacing(14)
        layout.setContentsMargins(12, 16, 12, 24)
        layout.addLayout(row)
        layout.addWidget(self._btn_report)
        layout.addWidget(self._btn_report_pdf)
        layout.addWidget(QLabel("Коллектор:"))
        layout.addLayout(coll_row)
        layout.addLayout(tz_row)
        layout.addWidget(QLabel("Ретеншн / размер БД:"))
        layout.addLayout(ret_row)
        layout.addWidget(QLabel("Удобство эксплуатации:"))
        layout.addWidget(self._autostart)
        layout.addWidget(self._btn_open_data)
        layout.addWidget(QLabel("Демо (для защиты):"))
        layout.addWidget(self._btn_demo_alert)
        layout.addWidget(self._btn_demo_seed)
        layout.addWidget(self._btn_demo_bf)
        layout.addWidget(self._btn_demo_rdp_bf)
        layout.addWidget(self._btn_demo_clear)
        layout.addWidget(QLabel("Права доступа:"))
        layout.addWidget(self._btn_admin_help)
        layout.addWidget(self._btn_copy_runas)
        layout.addWidget(QLabel("Sysmon (опционально):"))
        layout.addWidget(self._btn_sysmon_status)
        layout.addWidget(self._btn_sysmon_cfg)
        layout.addWidget(self._btn_sysmon_cmd)
        layout.addWidget(self._btn_prune)
        layout.addWidget(self._btn_clear_events)
        layout.addWidget(self._btn_reset_offsets)
        layout.addWidget(self._btn_vacuum)
        layout.addWidget(self._btn_backfill)
        layout.addWidget(self._btn_norm_eid)

        inner = QWidget()
        inner.setLayout(layout)
        inner.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum)

        for i in range(layout.count()):
            item = layout.itemAt(i)
            if item is None:
                continue
            w = item.widget()
            if w is not None:
                _settings_fix_height(w)
        for cb in (self._dry, self._lock, self._toast, self._collector_enabled, self._ret_enabled, self._autostart):
            cb.setMinimumHeight(28)
            cb.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        scroll.setWidget(inner)

        outer = QVBoxLayout()
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)
        outer.addWidget(scroll)
        self.setLayout(outer)

    def _export_report(self) -> None:
        path, _ = QFileDialog.getSaveFileName(
            self,
            "Сохранить отчёт",
            "minisiem-report.html",
            "HTML (*.html);;All files (*.*)",
        )
        if not path:
            return
        html_text = build_html_report(self._con, title="miniSIEM — отчёт")
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(html_text)
            QMessageBox.information(self, "Готово", f"Отчёт сохранён:\n{path}")
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", str(e))

    def _export_report_pdf(self) -> None:
        path, _ = QFileDialog.getSaveFileName(
            self,
            "Сохранить отчёт (PDF)",
            "minisiem-report.pdf",
            "PDF (*.pdf);;All files (*.*)",
        )
        if not path:
            return
        html_text = build_html_report(self._con, title="miniSIEM — отчёт")
        try:
            doc = QTextEdit()
            doc.setHtml(html_text)
            printer = QPrinter(QPrinter.PrinterMode.HighResolution)
            printer.setOutputFormat(QPrinter.OutputFormat.PdfFormat)
            printer.setOutputFileName(path)
            # PySide6 uses print_ to avoid clashing with Python keyword
            doc.document().print_(printer)
            QMessageBox.information(self, "Готово", f"PDF сохранён:\n{path}")
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", str(e))


class _RulesTab(QWidget):
    def __init__(
        self,
        con: sqlite3.Connection,
        state: dict[str, bool],
        params: dict[str, dict[str, str]],
        *,
        rules_dir: Path | None,
        get_rule_meta,
        on_test_rules,
        on_reload_rules,
    ) -> None:
        super().__init__()
        self._con = con
        self._state = state
        self._params = params
        self._get_rule_meta = get_rule_meta
        self._on_test_rules = on_test_rules
        self._on_reload_rules = on_reload_rules
        self._rules_dir = rules_dir
        self._checks: dict[str, QCheckBox] = {}
        self._desc_labels: dict[str, QLabel] = {}
        self._rules_split: QSplitter | None = None
        self._rules_split_initialized = False

        layout = QVBoxLayout()
        layout.setSpacing(12)
        layout.setContentsMargins(0, 0, 0, 0)
        intro = QLabel(
            "Правила из YAML (папка rules в данных пользователя). Включение/выключение сохраняется в SQLite."
        )
        intro.setWordWrap(True)
        layout.addWidget(intro)

        tools = QHBoxLayout()
        tools.setSpacing(10)
        tools.addWidget(QLabel("Test rules (last min):"))
        self._test_minutes = QLineEdit("10")
        self._test_minutes.setMaximumWidth(80)
        tools.addWidget(self._test_minutes)
        self._btn_test = QPushButton("Test")
        self._btn_test.clicked.connect(self._do_test)
        tools.addWidget(self._btn_test)
        self._btn_reload = QPushButton("Reload YAML")
        self._btn_reload.clicked.connect(lambda: self._on_reload_rules())
        tools.addWidget(self._btn_reload)

        self._btn_open_folder = QPushButton("Open rules folder")
        self._btn_open_folder.clicked.connect(self._open_rules_folder)
        tools.addWidget(self._btn_open_folder)
        tools.addStretch(1)
        layout.addLayout(tools)

        # YAML editor
        self._lbl_path = QLabel("")
        self._yaml_text = QTextEdit()
        self._yaml_text.setPlaceholderText("YAML rules…")
        self._yaml_msg = QLabel("")
        apply_muted_style(self._yaml_msg)

        editor_btns = QHBoxLayout()
        self._btn_load_yaml = QPushButton("Load default.yml")
        self._btn_load_yaml.clicked.connect(self._load_yaml)
        editor_btns.addWidget(self._btn_load_yaml)
        self._btn_append_samples = QPushButton("Append sample rules")
        self._btn_append_samples.clicked.connect(self._append_sample_rules)
        editor_btns.addWidget(self._btn_append_samples)
        self._btn_validate_yaml = QPushButton("Validate")
        self._btn_validate_yaml.clicked.connect(self._validate_yaml)
        editor_btns.addWidget(self._btn_validate_yaml)
        self._btn_save_yaml = QPushButton("Save")
        self._btn_save_yaml.clicked.connect(self._save_yaml)
        editor_btns.addWidget(self._btn_save_yaml)
        editor_btns.addStretch(1)

        for b in (
            self._btn_test,
            self._btn_reload,
            self._btn_open_folder,
            self._btn_load_yaml,
            self._btn_append_samples,
            self._btn_validate_yaml,
            self._btn_save_yaml,
        ):
            b.setMinimumHeight(34)
            b.setMinimumWidth(96)
            b.setSizePolicy(QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Fixed)

        self._rules_layout = QVBoxLayout()
        rules_scroll_inner = QWidget()
        rules_inner_lay = QVBoxLayout(rules_scroll_inner)
        rules_inner_lay.setContentsMargins(8, 8, 8, 12)
        rules_inner_lay.setSpacing(12)
        rules_inner_lay.addLayout(self._rules_layout)

        scroll_rules = QScrollArea()
        scroll_rules.setWidgetResizable(True)
        scroll_rules.setFrameShape(QFrame.Shape.NoFrame)
        scroll_rules.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll_rules.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        scroll_rules.setWidget(rules_scroll_inner)
        scroll_rules.setMinimumHeight(260)

        editor = QWidget()
        editor_layout = QVBoxLayout()
        editor_layout.setContentsMargins(0, 0, 0, 0)
        editor_layout.addWidget(QLabel("YAML editor (default.yml)"))
        editor_layout.addWidget(self._lbl_path)
        editor_layout.addLayout(editor_btns)
        editor_layout.addWidget(self._yaml_text, stretch=1)
        editor_layout.addWidget(self._yaml_msg)
        editor.setLayout(editor_layout)

        self._yaml_text.setMinimumHeight(120)
        self._yaml_text.setSizePolicy(
            QSizePolicy.Policy.Expanding,
            QSizePolicy.Policy.Preferred,
        )

        split = QSplitter(Qt.Orientation.Vertical)
        self._rules_split = split
        split.setChildrenCollapsible(False)
        split.addWidget(scroll_rules)
        split.addWidget(editor)
        split.setStretchFactor(0, 5)
        split.setStretchFactor(1, 2)
        layout.addWidget(split)

        self._build_rules_ui()
        self._load_yaml()

        self.setLayout(layout)

    def showEvent(self, event: QShowEvent) -> None:
        super().showEvent(event)
        if self._rules_split_initialized:
            return
        QTimer.singleShot(0, self._apply_initial_rules_split_sizes)

    def _apply_initial_rules_split_sizes(self) -> None:
        sp = self._rules_split
        if sp is None:
            return
        h = sp.height()
        if h < 120:
            QTimer.singleShot(50, self._apply_initial_rules_split_sizes)
            return
        self._rules_split_initialized = True
        gap = sp.handleWidth()
        # Больше места списку правил, редактор YAML ниже и компактнее
        top = max(300, int(h * 0.58))
        bot = max(220, h - top - gap)
        sp.setSizes([top, bot])

    def set_rules(self, state: dict[str, bool], params: dict[str, dict[str, str]]) -> None:
        self._state = state
        self._params = params
        self._build_rules_ui()

    def _build_rules_ui(self) -> None:
        # Clear previous widgets/layouts in rules area.
        # Important: do NOT just detach widgets (setParent(None)) because they become top-level windows.
        while self._rules_layout.count():
            item = self._rules_layout.takeAt(0)
            w = item.widget()
            if w is not None:
                w.deleteLater()
                continue
            lay = item.layout()
            if lay is not None:
                while lay.count():
                    sub = lay.takeAt(0)
                    sw = sub.widget()
                    if sw is not None:
                        sw.deleteLater()
                # layout object will be GC'ed
        self._checks = {}
        self._desc_labels = {}

        for rule_id in sorted(self._state.keys()):
            title, desc_text = self._get_rule_meta(rule_id)
            cb = QCheckBox(f"{rule_id} — {title}")
            cb.setChecked(bool(self._state[rule_id]))

            def _on_change(_: int, rid: str = rule_id, box: QCheckBox = cb) -> None:
                self._state[rid] = bool(box.isChecked())
                set_rule_enabled(self._con, rule_id=rid, enabled=self._state[rid])

            cb.stateChanged.connect(_on_change)
            self._checks[rule_id] = cb
            cb.setMinimumHeight(28)
            self._rules_layout.addWidget(cb)

            desc = QLabel(desc_text or "")
            desc.setWordWrap(True)
            apply_muted_style(desc)
            self._desc_labels[rule_id] = desc
            self._rules_layout.addWidget(desc)

            if rule_id in self._params and self._params[rule_id]:
                row = QHBoxLayout()
                for k in sorted(self._params[rule_id].keys()):
                    row.addWidget(QLabel(k))
                    inp = QLineEdit(self._params[rule_id].get(k, ""))
                    inp.setMaximumWidth(100)
                    row.addWidget(inp)

                    def _save_param(key: str = k, edit: QLineEdit = inp, rid: str = rule_id) -> None:
                        self._params[rid][key] = edit.text().strip()
                        set_rule_param(self._con, rule_id=rid, key=key, value=self._params[rid][key])

                    inp.editingFinished.connect(_save_param)
                    row.addSpacing(8)
                row.addStretch(1)
                self._rules_layout.addLayout(row)

            self._rules_layout.addWidget(QLabel(" "))

    def _do_test(self) -> None:
        try:
            m = int(self._test_minutes.text().strip() or "10")
        except ValueError:
            m = 10
        if m <= 0:
            m = 10
        self._on_test_rules(m)

    def _rules_file(self) -> Path | None:
        if self._rules_dir is None:
            return None
        return self._rules_dir / "default.yml"

    def _open_rules_folder(self) -> None:
        if self._rules_dir is None:
            QMessageBox.warning(self, "Rules", "rules_dir не задан")
            return
        try:
            os.startfile(str(self._rules_dir))  # type: ignore[attr-defined]
        except Exception as e:
            QMessageBox.critical(self, "Rules", str(e))

    def _load_yaml(self) -> None:
        p = self._rules_file()
        if p is None:
            self._lbl_path.setText("rules_dir не задан")
            return
        self._lbl_path.setText(str(p))
        try:
            txt = p.read_text(encoding="utf-8")
            self._yaml_text.setPlainText(txt)
            self._yaml_msg.setText("Загружено.")
        except Exception as e:
            self._yaml_msg.setText(f"Ошибка загрузки: {e}")

    def _validate_yaml(self) -> bool:
        try:
            import yaml  # local import for PyInstaller

            doc = yaml.safe_load(self._yaml_text.toPlainText())
        except Exception as e:
            self._yaml_msg.setText(f"YAML ошибка: {e}")
            return False
        if not isinstance(doc, dict) or "rules" not in doc:
            self._yaml_msg.setText("Ожидался документ вида: { rules: [ ... ] }")
            return False
        self._yaml_msg.setText("YAML валиден.")
        return True

    def _save_yaml(self) -> None:
        if not self._validate_yaml():
            return
        p = self._rules_file()
        if p is None:
            self._yaml_msg.setText("rules_dir не задан")
            return
        try:
            p.write_text(self._yaml_text.toPlainText(), encoding="utf-8")
            self._yaml_msg.setText("Сохранено. Перезагружаю правила…")
            self._on_reload_rules()
            self._build_rules_ui()
        except Exception as e:
            self._yaml_msg.setText(f"Ошибка сохранения: {e}")

    def _append_sample_rules(self) -> None:
        try:
            import yaml  # local import for PyInstaller

            cur_doc = yaml.safe_load(self._yaml_text.toPlainText() or "") or {}
            sample_doc = yaml.safe_load(DEFAULT_RULES_YAML) or {}
        except Exception as e:
            self._yaml_msg.setText(f"YAML ошибка: {e}")
            return

        if not isinstance(cur_doc, dict):
            cur_doc = {}
        if not isinstance(sample_doc, dict):
            self._yaml_msg.setText("Sample rules: invalid format")
            return

        cur_rules = cur_doc.get("rules") or []
        sample_rules = sample_doc.get("rules") or []
        if not isinstance(cur_rules, list):
            cur_rules = []
        if not isinstance(sample_rules, list):
            sample_rules = []

        existing_ids: set[str] = set()
        for r in cur_rules:
            if isinstance(r, dict) and r.get("id"):
                existing_ids.add(str(r.get("id")))

        added = 0
        for r in sample_rules:
            if not isinstance(r, dict):
                continue
            rid = str(r.get("id") or "").strip()
            if not rid or rid in existing_ids:
                continue
            cur_rules.append(r)
            existing_ids.add(rid)
            added += 1

        cur_doc["rules"] = cur_rules
        try:
            new_text = yaml.safe_dump(cur_doc, sort_keys=False, allow_unicode=True)
        except Exception:
            # fallback: keep current text if dumping fails
            self._yaml_msg.setText("Не удалось сериализовать YAML.")
            return

        self._yaml_text.setPlainText(new_text)
        self._yaml_msg.setText(f"Добавлено правил: {added}. Нажми Save для сохранения в default.yml.")

    def sync_from_state(self) -> None:
        for rid, cb in self._checks.items():
            want = bool(self._state.get(rid, True))
            if cb.isChecked() != want:
                cb.setChecked(want)


class _DashboardTab(QWidget):
    def __init__(self, con: sqlite3.Connection) -> None:
        super().__init__()
        self._con = con

        def _metric_card(title: str) -> tuple[QFrame, QLabel]:
            card = QFrame()
            card.setObjectName("metricCard")
            inner = QVBoxLayout(card)
            inner.setContentsMargins(14, 12, 14, 12)
            inner.setSpacing(4)
            tl = QLabel(title)
            tl.setObjectName("metricTitle")
            vl = QLabel("—")
            vl.setObjectName("metricValue")
            inner.addWidget(tl)
            inner.addWidget(vl)
            return card, vl

        title_main = QLabel("Сводка")
        title_main.setObjectName("sectionTitle")

        grid_cards = QGridLayout()
        grid_cards.setHorizontalSpacing(12)
        grid_cards.setVerticalSpacing(10)
        c1, self._mv_events = _metric_card("События (всего)")
        c2, self._mv_alerts = _metric_card("Алерты (всего)")
        c3, self._mv_actions = _metric_card("Действия (всего)")
        c4, self._mv_ev24 = _metric_card("События за 24 ч")
        c5, self._mv_al24 = _metric_card("Алерты за 24 ч")
        c6, self._mv_4625 = _metric_card("4625 неудача (10 мин)")
        grid_cards.addWidget(c1, 0, 0)
        grid_cards.addWidget(c2, 0, 1)
        grid_cards.addWidget(c3, 0, 2)
        grid_cards.addWidget(c4, 1, 0)
        grid_cards.addWidget(c5, 1, 1)
        grid_cards.addWidget(c6, 1, 2)

        sec_store = QLabel("Хранилище и сбор")
        sec_store.setObjectName("sectionTitle")
        self._lbl_db = QLabel("")
        self._lbl_collector = QLabel("")
        self._lbl_retention = QLabel("")
        apply_muted_style(self._lbl_db)
        apply_muted_style(self._lbl_collector)
        apply_muted_style(self._lbl_retention)

        sec_ch = QLabel("Каналы и аналитика")
        sec_ch.setObjectName("sectionTitle")
        self._txt_channels = QTextEdit()
        self._txt_channels.setReadOnly(True)

        layout = QVBoxLayout()
        layout.setSpacing(12)
        layout.addWidget(title_main)
        layout.addLayout(grid_cards)
        layout.addWidget(sec_store)
        layout.addWidget(self._lbl_db)
        layout.addWidget(self._lbl_collector)
        layout.addWidget(self._lbl_retention)
        layout.addWidget(sec_ch)
        layout.addWidget(self._txt_channels, stretch=1)
        self.setLayout(layout)
        self.refresh(last_tick_utc=None, last_new_events=0, channel_status={})

    def refresh(self, *, last_tick_utc: str | None, last_new_events: int, channel_status: dict[str, str]) -> None:
        now = datetime.now(timezone.utc)
        since_24h = (now - timedelta(hours=24)).isoformat()
        since_10m = (now - timedelta(minutes=10)).isoformat()
        paths = default_paths()
        st = get_db_file_stats(paths.db_path)
        total_events = count_rows(self._con, "events")
        total_alerts = count_rows(self._con, "alerts")
        total_actions = count_rows(self._con, "actions")
        ev_24h = count_events_since(self._con, since_24h)
        al_24h = count_alerts_by_status_since(self._con, since_24h)
        top_eid = top_event_ids_since(self._con, since_24h, limit=8)
        top_ch = top_channels_since(self._con, since_24h, limit=6)

        # Security logons (short window) – useful for brute-force demo
        sec_4625_10m = count_security_logons_since(self._con, since_10m, event_id=4625)
        sec_4624_10m = count_security_logons_since(self._con, since_10m, event_id=4624)
        top_ip_10m = top_security_4625_by_ip_since(self._con, since_10m, limit=6)
        top_acc_10m = top_security_4625_by_account_since(self._con, since_10m, limit=6)
        top_lt_10m = top_security_4625_by_logon_type_since(self._con, since_10m, limit=6)
        rdp_10m = count_security_4625_by_logon_type_since(self._con, since_10m, logon_type="10")
        top_rdp_ip_10m = top_security_4625_rdp_by_ip_since(self._con, since_10m, limit=6)

        al24_total = sum(int(v) for v in al_24h.values())

        self._mv_events.setText(f"{total_events:,}".replace(",", " "))
        self._mv_alerts.setText(f"{total_alerts:,}".replace(",", " "))
        self._mv_actions.setText(f"{total_actions:,}".replace(",", " "))
        self._mv_ev24.setText(f"{ev_24h:,}".replace(",", " "))
        self._mv_al24.setText(f"{al24_total:,}".replace(",", " "))
        self._mv_4625.setText(str(sec_4625_10m))

        def _fmt_mb(n: int) -> str:
            return f"{(float(n) / (1024 * 1024)):.1f}MB"

        off = display_tz_offset_hours(self._con)
        lt_disp = (
            format_utc_iso_for_display(last_tick_utc, offset_hours=off) if last_tick_utc else "-"
        )
        self._lbl_db.setText(
            "SQLite: "
            + f"events={total_events}, alerts={total_alerts}, actions={total_actions} | "
            + f"за 24ч events={ev_24h}, alerts_by_status={al_24h} | "
            + f"размер db={_fmt_mb(st['db'])} wal={_fmt_mb(st['wal'])} shm={_fmt_mb(st['shm'])}"
        )
        self._lbl_collector.setText(
            f"Collector: last_tick={lt_disp} | last_new_events=+{int(last_new_events)}"
        )

        ret_enabled = (get_setting(self._con, "retention_enabled") or "1") == "1"
        ret_days = get_setting(self._con, "retention_days") or "7"
        last_prune = get_setting(self._con, "retention_last_prune_utc") or "-"
        lp_disp = format_utc_iso_for_display(last_prune, offset_hours=off) if str(last_prune).strip() not in (
            "",
            "-",
        ) else str(last_prune)
        self._lbl_retention.setText(
            "Retention: "
            + f"enabled={'yes' if ret_enabled else 'no'}, days={ret_days}, last_prune={lp_disp}"
        )
        lines = []
        for ch in DEFAULT_CHANNELS:
            st = channel_status.get(ch.name, "—")
            if ch.name == "Microsoft-Windows-Sysmon/Operational" and "15007" in st:
                st = st + " (Sysmon не установлен)"
            lines.append(f"{ch.name}: {st}")

        lines.append("")
        lines.append("ТОП EventID (24ч):")
        for eid, n in top_eid:
            lines.append(f"  {eid}: {n}")
        lines.append("")
        lines.append("ТОП channels (24ч):")
        for cname, n in top_ch:
            lines.append(f"  {cname}: {n}")

        lines.append("")
        lines.append("Security (last 10 min):")
        lines.append(f"  4625 failed_logon: {sec_4625_10m}")
        lines.append(f"  4624 success_logon: {sec_4624_10m}")
        lines.append(f"  4625 by RDP (logon_type=10): {rdp_10m}")
        if top_rdp_ip_10m:
            lines.append("  TOP IP (RDP 4625, 10m):")
            for ip, n in top_rdp_ip_10m:
                lines.append(f"    {ip}: {n}")
        if sec_4625_10m >= 8:
            lines.append("  hint: possible brute-force (4625 burst)")
        if top_ip_10m:
            lines.append("  TOP IP (4625, 10m):")
            for ip, n in top_ip_10m:
                lines.append(f"    {ip}: {n}")
        if top_acc_10m:
            lines.append("  TOP account (4625, 10m):")
            for acc, n in top_acc_10m:
                lines.append(f"    {acc}: {n}")
        if top_lt_10m:
            lines.append("  TOP logon_type (4625, 10m):")
            for lt, n in top_lt_10m:
                lbl = logon_type_label(lt)
                if lbl:
                    lines.append(f"    {lt} ({lbl}): {n}")
                else:
                    lines.append(f"    {lt}: {n}")
        self._txt_channels.setText("\n".join(lines))

