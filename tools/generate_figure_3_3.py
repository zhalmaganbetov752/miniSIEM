# -*- coding: utf-8 -*-
"""Рисунок 3.3 – понятная диаграмма последовательности (крупно, по-русски)."""
from __future__ import annotations

from pathlib import Path

import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch

ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = ROOT / "ПЗ" / "figures"
OUT_PNG = OUT_DIR / "Рисунок_3_3_Последовательность_обработки_события.png"
OUT_SVG = OUT_DIR / "Рисунок_3_3_Последовательность_обработки_события.svg"

W, H = 1400, 1050

# (x, короткое имя, пояснение под именем)
ACTORS = [
    (100, "Таймер", "QTimer"),
    (280, "Приложение", "app.py"),
    (480, "Сборщик", "collector_win"),
    (680, "Журнал Win", "Event Log"),
    (880, "База SQLite", "db.py"),
    (1080, "Детектор", "rules.py"),
    (1280, "Экран", "GUI"),
]

# (from, to, y, номер, текст, пунктир)
STEPS = [
    (0, 1, 130, "1", "Запуск цикла опроса", False),
    (1, 2, 200, "2", "Запросить события канала", False),
    (2, 3, 270, "3", "Прочитать журнал", False),
    (3, 2, 340, "4", "Записи журнала", True),
    (2, 1, 410, "5", "Нормализованные события", True),
    (1, 4, 500, "6", "Сохранить в базу", False),
    (4, 1, 570, "7", "Количество новых строк", True),
    (1, 4, 640, "8", "Взять события за 10 мин", False),
    (4, 1, 710, "9", "Выборка для анализа", True),
    (1, 5, 780, "10", "Проверить правила YAML", False),
    (5, 1, 850, "11", "Сформированные алерты", True),
    (1, 4, 930, "12", "Записать алерт (без дубля)", False),
    (1, 6, 1005, "13", "Показать на Dashboard / Alerts", False),
]

LOOP_Y = (185, 445)
OPT_Y = (905, 975)
LIFE_TOP, LIFE_BOT = 95, 940
HEADER_H = 52


def _header(ax, x, name, sub):
    w = 118
    box = FancyBboxPatch(
        (x - w / 2, 28), w, HEADER_H,
        boxstyle="round,pad=0.02,rounding_size=8",
        linewidth=2, edgecolor="#1D4ED8", facecolor="#EFF6FF",
    )
    ax.add_patch(box)
    ax.text(x, 48, name, ha="center", va="center", fontsize=13, fontweight="bold", color="#0F172A")
    ax.text(x, 68, sub, ha="center", va="center", fontsize=10, color="#475569")
    ax.plot([x, x], [LIFE_TOP, LIFE_BOT], color="#94A3B8", linewidth=1.5, linestyle=(0, (6, 4)))


def _step(ax, x1, x2, y, num, text, dashed):
    color = "#1E293B"
    lw = 2.0 if not dashed else 1.5
    ls = (0, (5, 4)) if dashed else "-"
    dx = 14 if x1 < x2 else -14
    ax.add_patch(FancyArrowPatch(
        (x1 + dx, y), (x2 - dx, y),
        arrowstyle="-|>", mutation_scale=14, linewidth=lw,
        color="#334155" if not dashed else "#64748B", linestyle=ls,
    ))
    mx = (x1 + x2) / 2
    # фон под текстом
    ax.text(mx, y - 14, text, ha="center", va="bottom", fontsize=11, color=color,
            bbox=dict(boxstyle="round,pad=0.35", facecolor="white", edgecolor="#E2E8F0", linewidth=0.8))
    # номер шага у левого участника
    lx = min(x1, x2) - 55
    circ = plt.Circle((lx, y), 14, facecolor="#1D4ED8", edgecolor="white", linewidth=1.5, zorder=5)
    ax.add_patch(circ)
    ax.text(lx, y, num, ha="center", va="center", fontsize=11, fontweight="bold", color="white", zorder=6)


def _activation(ax, x, y1, y2):
    ax.add_patch(mpatches.Rectangle(
        (x - 8, y1), 16, y2 - y1,
        linewidth=1.5, edgecolor="#2563EB", facecolor="#BFDBFE", alpha=0.9, zorder=2,
    ))


def _frame(ax, x1, x2, y1, y2, label, color):
    ax.add_patch(FancyBboxPatch(
        (x1, y1), x2 - x1, y2 - y1,
        boxstyle="round,pad=0.02,rounding_size=6",
        linewidth=2, edgecolor=color, facecolor=color, alpha=0.06,
    ))
    ax.text(x1 + 12, y1 + 14, label, fontsize=11, fontweight="bold", color=color, va="top")


def build() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    fig, ax = plt.subplots(figsize=(14, 10.5), dpi=200)
    ax.set_xlim(0, W)
    ax.set_ylim(H, 0)
    ax.axis("off")
    fig.patch.set_facecolor("white")

    xs = [a[0] for a in ACTORS]
    for x, name, sub in ACTORS:
        _header(ax, x, name, sub)

    _activation(ax, 280, 125, 995)
    _activation(ax, 880, 495, 935)

    _frame(ax, 230, 720, LOOP_Y[0], LOOP_Y[1],
           "Повтор для каждого канала: Security, System, Application, Sysmon", "#EA580C")
    _frame(ax, 250, 1150, OPT_Y[0], OPT_Y[1],
           "Если алерт новый — запись в alerts и actions (dry-run)", "#059669")

    for fi, ti, y, num, text, dashed in STEPS:
        if LOOP_Y[0] <= y <= LOOP_Y[1] and num not in ("1",):
            pass  # inside loop
        _step(ax, xs[fi], xs[ti], y, num, text, dashed)

    # Заголовок внутри схемы (не подпись рисунка)
    ax.text(W / 2, 12, "Онлайн-обработка события mini SIEM",
            ha="center", va="center", fontsize=15, fontweight="bold", color="#0F172A")

    ax.text(W / 2, 1020,
            "Сплошная стрелка — действие   |   Пунктир — ответ   |   Импорт EVTX: после шага 6 тот же путь к правилам",
            ha="center", fontsize=10, color="#64748B")

    fig.savefig(OUT_PNG, bbox_inches="tight", facecolor="white", pad_inches=0.1)
    fig.savefig(OUT_SVG, bbox_inches="tight", facecolor="white", pad_inches=0.1)
    plt.close(fig)
    print(f"PNG: {OUT_PNG}")
    print(f"SVG: {OUT_SVG}")


if __name__ == "__main__":
    build()
