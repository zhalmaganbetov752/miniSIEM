# -*- coding: utf-8 -*-
"""Генерация Рисунок 3.1 – Архитектура mini SIEM."""
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = ROOT / "ПЗ" / "figures"
OUT_SVG = OUT_DIR / "Рисунок_3_1_Архитектура_mini_SIEM.svg"
OUT_PNG = OUT_DIR / "Рисунок_3_1_Архитектура_mini_SIEM.png"

W, H = 920, 680

# (x, y, w, h, title, subtitle)
BOXES = [
    (310, 20, 300, 52, "Источники данных", "Windows Event Log · EVTX"),
    (310, 100, 300, 52, "Сбор и импорт", "collector_win.py · evtx_import.py"),
    (310, 180, 300, 44, "Нормализация", "EventID · parsed · data_json"),
    (310, 250, 300, 52, "Хранение", "db.py · SQLite (WAL)"),
    (120, 340, 240, 52, "Детектирование", "rules.py · default.yml"),
    (560, 340, 240, 52, "Представление", "app.py · PySide6 GUI"),
    (120, 440, 240, 44, "Алертинг", "alerts · rules_state"),
    (560, 440, 240, 44, "Отчётность", "report.py · HTML / JSON"),
    (340, 530, 240, 52, "Реакция", "actions · dry-run"),
]

# arrow: (x1, y1, x2, y2)
ARROWS = [
    (460, 72, 460, 100),
    (460, 152, 460, 180),
    (460, 224, 460, 250),
    (460, 302, 240, 340),
    (460, 302, 680, 340),
    (240, 392, 240, 440),
    (680, 392, 680, 440),
    (240, 484, 400, 530),
    (680, 484, 520, 530),
    (460, 484, 460, 530),
]


def _box_svg(x, y, w, h, title, subtitle, fill="#E8F0FE", stroke="#1A56DB"):
    lines = [
        f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="8" ry="8" '
        f'fill="{fill}" stroke="{stroke}" stroke-width="1.5"/>',
        f'<text x="{x + w/2}" y="{y + 22}" text-anchor="middle" '
        f'font-family="Segoe UI, Arial, sans-serif" font-size="13" font-weight="600" fill="#111827">{title}</text>',
        f'<text x="{x + w/2}" y="{y + 40}" text-anchor="middle" '
        f'font-family="Segoe UI, Arial, sans-serif" font-size="11" fill="#374151">{subtitle}</text>',
    ]
    return "\n".join(lines)


def _arrow_svg(x1, y1, x2, y2):
    return (
        f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" stroke="#374151" stroke-width="1.5" marker-end="url(#arrow)"/>'
    )


def build_svg() -> str:
    parts = [
        f'<?xml version="1.0" encoding="UTF-8"?>',
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}">',
        '<defs>',
        '<marker id="arrow" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto">',
        '<polygon points="0 0, 8 3, 0 6" fill="#374151"/>',
        '</marker>',
        '</defs>',
        f'<rect width="{W}" height="{H}" fill="white"/>',
    ]
    for x, y, w, h, t, s in BOXES:
        fill = "#FFF7ED" if "Источники" in t else "#E8F0FE"
        stroke = "#C2410C" if "Источники" in t else "#1A56DB"
        if t == "Хранение":
            fill, stroke = "#ECFDF5", "#047857"
        if t in ("Алертинг", "Реакция"):
            fill, stroke = "#FEF2F2", "#B91C1C"
        parts.append(_box_svg(x, y, w, h, t, s, fill, stroke))
    for a in ARROWS:
        parts.append(_arrow_svg(*a))
    parts.append(
        '<text x="460" y="660" text-anchor="middle" font-family="Segoe UI, Arial, sans-serif" '
        'font-size="10" fill="#6B7280">Конвейер: Collection → Normalization → Storage → Detection → Alerting → Presentation → Response</text>'
    )
    parts.append("</svg>")
    return "\n".join(parts)


def svg_to_png_matplotlib(png_path: Path) -> None:
    import matplotlib.pyplot as plt
    import matplotlib.patches as mpatches
    from matplotlib.patches import FancyArrowPatch

    fig, ax = plt.subplots(figsize=(9.2, 6.8), dpi=200)
    ax.set_xlim(0, W)
    ax.set_ylim(H, 0)
    ax.axis("off")
    fig.patch.set_facecolor("white")

    colors = {
        "Источники данных": ("#FFF7ED", "#C2410C"),
        "Сбор и импорт": ("#E8F0FE", "#1A56DB"),
        "Нормализация": ("#E8F0FE", "#1A56DB"),
        "Хранение": ("#ECFDF5", "#047857"),
        "Детектирование": ("#E8F0FE", "#1A56DB"),
        "Представление": ("#E8F0FE", "#1A56DB"),
        "Алертинг": ("#FEF2F2", "#B91C1C"),
        "Отчётность": ("#E8F0FE", "#1A56DB"),
        "Реакция": ("#FEF2F2", "#B91C1C"),
    }

    for x, y, w, h, title, subtitle in BOXES:
        fill, edge = colors.get(title, ("#E8F0FE", "#1A56DB"))
        box = mpatches.FancyBboxPatch(
            (x, y), w, h, boxstyle="round,pad=0.02,rounding_size=8",
            linewidth=1.5, edgecolor=edge, facecolor=fill,
        )
        ax.add_patch(box)
        ax.text(x + w / 2, y + 20, title, ha="center", va="center", fontsize=11, fontweight="bold")
        ax.text(x + w / 2, y + 38, subtitle, ha="center", va="center", fontsize=9)

    for x1, y1, x2, y2 in ARROWS:
        ax.add_patch(FancyArrowPatch(
            (x1, y1), (x2, y2), arrowstyle="-|>", mutation_scale=12,
            linewidth=1.2, color="#374151",
        ))

    ax.text(W / 2, H - 15,
            "Конвейер: Collection → Normalization → Storage → Detection → Alerting → Presentation → Response",
            ha="center", va="center", fontsize=8, color="#6B7280")

    fig.savefig(png_path, bbox_inches="tight", facecolor="white", pad_inches=0.05)
    plt.close(fig)


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    svg = build_svg()
    OUT_SVG.write_text(svg, encoding="utf-8")
    print(f"SVG: {OUT_SVG}")
    try:
        svg_to_png_matplotlib(OUT_PNG)
        print(f"PNG: {OUT_PNG}")
    except Exception as e:
        print(f"PNG error: {e}")


if __name__ == "__main__":
    main()
