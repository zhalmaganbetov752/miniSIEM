"""
Глобальная тёмная тема интерфейса (Qt Style Sheets).
"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QAbstractItemView, QApplication, QTableView, QWidget

# Единая палитра: тёмный фон + акцент cyan/blue (удобно для «security» UI)
APP_STYLESHEET = """
QWidget {
    background-color: #14141c;
    color: #e8e8f0;
    font-family: "Segoe UI", "Segoe UI Variable Display", Roboto, system-ui, sans-serif;
    font-size: 13px;
}

QMainWindow {
    background-color: #14141c;
}

/* Заголовки вкладок и панель */
QTabWidget::pane {
    border: 1px solid #2a2a38;
    border-radius: 10px;
    top: -2px;
    background-color: #181822;
    padding: 4px;
}

QTabBar::tab {
    background-color: #232330;
    color: #a8a8bc;
    padding: 10px 20px;
    margin-right: 4px;
    border-top-left-radius: 10px;
    border-top-right-radius: 10px;
    min-width: 72px;
}

QTabBar::tab:selected {
    background-color: #1c2533;
    color: #7dd3fc;
    font-weight: 600;
    border-bottom: 2px solid #38bdf8;
}

QTabBar::tab:hover:!selected {
    background-color: #2a2a3a;
    color: #d4d4e8;
}

/* Кнопки */
QPushButton {
    background-color: #243044;
    color: #eef2f8;
    border: 1px solid #3d4f68;
    border-radius: 8px;
    padding: 9px 18px;
    min-height: 28px;
}

QPushButton:hover {
    background-color: #2f3f56;
    border-color: #5a7a9e;
}

QPushButton:pressed {
    background-color: #1a2433;
}

QPushButton:disabled {
    background-color: #1e1e28;
    color: #6b6b7a;
    border-color: #2a2a38;
}

/* Поля ввода */
QLineEdit, QComboBox {
    background-color: #1a1a26;
    border: 1px solid #353548;
    border-radius: 8px;
    padding: 7px 12px;
    selection-background-color: #2563eb;
    selection-color: #ffffff;
}

QLineEdit:focus, QComboBox:focus {
    border-color: #38bdf8;
}

QComboBox::drop-down {
    border: none;
    width: 28px;
}

QComboBox QAbstractItemView {
    background-color: #232330;
    border: 1px solid #353548;
    selection-background-color: #1e4976;
    selection-color: #f8fafc;
    outline: none;
}

/* Таблицы */
QTableView {
    background-color: #12121a;
    alternate-background-color: #181822;
    color: #e8e8f0;
    gridline-color: transparent;
    border: 1px solid #2a2a38;
    border-radius: 10px;
    selection-background-color: #1e4a7a;
    selection-color: #f0f9ff;
}

/* Угол заголовков (иначе на Windows остаётся белым квадратом) */
QTableCornerButton::section {
    background-color: #1e2430;
    border: none;
    border-bottom: 2px solid #334155;
    border-right: 1px solid #2a3548;
}

QTableView::item {
    padding: 7px 10px;
    color: #e8e8f0;
    background-color: #12121a;
}

QTableView::item:alternate {
    background-color: #181822;
    color: #e8e8f0;
}

QTableView::item:selected {
    background-color: #1e4a7a;
    color: #f0f9ff;
}

QHeaderView::section {
    background-color: #1e2430;
    color: #c4c4dc;
    padding: 10px 10px;
    border: none;
    border-bottom: 2px solid #334155;
    font-weight: 600;
}

QHeaderView::section:vertical {
    background-color: #1e2430;
    color: #94a3b8;
    border: none;
    border-right: 1px solid #2a3548;
    padding: 4px 8px;
    min-height: 30px;
}

/* Текст / логи */
QTextEdit, QPlainTextEdit {
    background-color: #0e0e14;
    color: #d1e0f0;
    border: 1px solid #2a2a38;
    border-radius: 10px;
    padding: 10px;
    font-family: "Cascadia Code", "Consolas", "JetBrains Mono", ui-monospace, monospace;
    font-size: 12px;
    selection-background-color: #2563eb;
}

/* Чекбоксы */
QCheckBox {
    spacing: 10px;
}

QCheckBox::indicator {
    width: 18px;
    height: 18px;
    border-radius: 5px;
    border: 2px solid #4b5568;
    background-color: #1a1a26;
}

QCheckBox::indicator:checked {
    background-color: #2563eb;
    border-color: #60a5fa;
}

/* Прокручиваемые панели настроек */
QScrollArea {
    border: none;
    background-color: transparent;
}

/* Сплиттер */
QSplitter::handle {
    background-color: #2a2a38;
}

QSplitter::handle:horizontal {
    width: 3px;
}

QSplitter::handle:vertical {
    height: 3px;
}

/* Панели */
QToolBar {
    background-color: #181822;
    border: none;
    border-bottom: 1px solid #2a2a38;
    spacing: 10px;
    padding: 6px 8px;
}

QToolBar QToolButton {
    background-color: transparent;
    border-radius: 6px;
    padding: 6px 10px;
}

QToolBar QToolButton:hover {
    background-color: #2a2a38;
}

QStatusBar {
    background-color: #181822;
    color: #94a3b8;
    border-top: 1px solid #2a2a38;
}

/* Карточки метрик (Dashboard) */
QFrame#metricCard {
    background-color: #1a2030;
    border: 1px solid #2d3548;
    border-radius: 14px;
}

QLabel#metricTitle {
    color: #94a3b8;
    font-size: 11px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.06em;
}

QLabel#metricValue {
    color: #7dd3fc;
    font-size: 22px;
    font-weight: 700;
    font-family: "Segoe UI", sans-serif;
}

QLabel#sectionTitle {
    font-size: 16px;
    font-weight: 700;
    color: #f1f5f9;
    padding: 4px 0 8px 0;
}

/* Вторичный текст */
QLabel[muted="true"] {
    color: #94a3b8;
}

/* Прокрутка */
QScrollBar:vertical {
    background: #181822;
    width: 11px;
    margin: 0;
    border-radius: 5px;
}

QScrollBar::handle:vertical {
    background: #3f3f52;
    min-height: 28px;
    border-radius: 5px;
}

QScrollBar::handle:vertical:hover {
    background: #56566e;
}

QScrollBar:horizontal {
    background: #181822;
    height: 11px;
}

QScrollBar::handle:horizontal {
    background: #3f3f52;
    min-width: 28px;
    border-radius: 5px;
}

/* Диалоги */
QMessageBox {
    background-color: #181822;
}

QMessageBox QLabel {
    color: #e8e8f0;
}

QProgressDialog {
    background-color: #181822;
}
"""


def apply_application_theme(app: QApplication) -> None:
    # Fusion стабильнее сочетается с QSS, чем нативный Windows-стиль (нет «белых» строк таблицы).
    try:
        app.setStyle("Fusion")
    except Exception:
        pass
    app.setStyleSheet(APP_STYLESHEET)
    try:
        app.setHighDpiScaleFactorRoundingPolicy(Qt.HighDpiScaleFactorRoundingPolicy.PassThrough)
    except Exception:
        pass


def polish_table_view(tv: QAbstractItemView) -> None:
    tv.setAlternatingRowColors(True)
    tv.setShowGrid(False)
    try:
        tv.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
    except Exception:
        pass
    h = tv.horizontalHeader()
    if h is not None:
        h.setMinimumSectionSize(88)
        h.setStretchLastSection(True)
        h.setHighlightSections(False)
    v = tv.verticalHeader()
    if v is not None:
        v.setMinimumSectionSize(30)
        v.setDefaultSectionSize(30)


def size_table_columns(tv: QTableView, *, min_w: int = 80, max_w: int = 520) -> None:
    """Подогнать ширину колонок по содержимому (с ограничениями)."""
    model = tv.model()
    if model is None:
        return
    for c in range(model.columnCount()):
        if tv.isColumnHidden(c):
            continue
        tv.resizeColumnToContents(c)
        w = tv.columnWidth(c)
        tv.setColumnWidth(c, max(min_w, min(max_w, w)))


def apply_muted_style(widget: QWidget) -> None:
    """Применить вторичный цвет текста из темы (QLabel[muted=\"true\"])."""
    widget.setProperty("muted", True)
    style = widget.style()
    if style is not None:
        style.unpolish(widget)
        style.polish(widget)
