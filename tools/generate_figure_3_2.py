# -*- coding: utf-8 -*-
"""Генерация Рисунок 3.2 – ER-диаграмма базы данных mini SIEM."""
from __future__ import annotations

from pathlib import Path

import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch

ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = ROOT / "ПЗ" / "figures"
OUT_PNG = OUT_DIR / "Рисунок_3_2_ER_диаграмма_mini_SIEM.png"
OUT_SVG = OUT_DIR / "Рисунок_3_2_ER_диаграмма_mini_SIEM.svg"

W, H = 1100, 780

# (x, y, width, height, title, attributes, header_color)
ENTITIES = [
    (
        40, 80, 300, 220, "events",
        [
            "id  PK",
            "ts_utc",
            "channel",
            "provider",
            "event_id",
            "level",
            "computer",
            "record_id",
            "message",
            "data_json",
            "parsed_account",
            "parsed_ip",
            "parsed_logon_type",
        ],
        "#ECFDF5", "#047857",
    ),
    (
        400, 80, 280, 200, "alerts",
        [
            "id  PK",
            "ts_utc",
            "rule_id  FK*",
            "severity",
            "title",
            "details",
            "status",
            "comment",
        ],
        "#FEF2F2", "#B91C1C",
    ),
    (
        760, 80, 280, 180, "rules_state",
        [
            "rule_id  PK",
            "enabled",
        ],
        "#EEF2FF", "#4338CA",
    ),
    (
        400, 360, 280, 170, "actions",
        [
            "id  PK",
            "ts_utc",
            "alert_id  FK",
            "action_type",
            "target",
            "result",
            "details",
        ],
        "#FFF7ED", "#C2410C",
    ),
    (
        760, 320, 280, 150, "rule_params",
        [
            "rule_id  PK, FK*",
            "key  PK",
            "value",
        ],
        "#EEF2FF", "#4338CA",
    ),
    (
        40, 380, 280, 120, "settings",
        [
            "key  PK",
            "value",
        ],
        "#F3F4F6", "#4B5563",
    ),
]

# (x1, y1, x2, y2, label, style)
RELATIONS = [
    (540, 280, 540, 360, "1 : N", "solid"),       # alerts -> actions
    (680, 170, 760, 130, "1 : N", "dashed"),      # rules_state -> alerts (rule_id)
    (820, 230, 820, 320, "1 : N", "dashed"),      # rules_state -> rule_params
    (340, 190, 400, 170, "источник\nсобытий", "dotted"),  # events ~ alerts (logical)
]


def _entity_box(ax, x, y, w, h, title, attrs, fill, edge):
    header_h = 32
    box = FancyBboxPatch(
        (x, y), w, h,
        boxstyle="round,pad=0.01,rounding_size=6",
        linewidth=1.6, edgecolor=edge, facecolor=fill,
    )
    ax.add_patch(box)
    header = mpatches.Rectangle((x, y), w, header_h, facecolor=edge, edgecolor=edge, linewidth=0)
    ax.add_patch(header)
    ax.text(x + w / 2, y + header_h / 2, title, ha="center", va="center",
            fontsize=12, fontweight="bold", color="white")
    line_y = y + header_h + 14
    for attr in attrs:
        weight = "bold" if "PK" in attr else "normal"
        ax.text(x + 12, line_y, attr, ha="left", va="center", fontsize=9, fontweight=weight, color="#111827")
        line_y += 16


def _relation_line(ax, x1, y1, x2, y2, label, style):
    ls = {"solid": "-", "dashed": (0, (5, 4)), "dotted": (0, (2, 3))}[style]
    color = "#374151" if style == "solid" else "#6B7280"
    ax.add_patch(FancyArrowPatch(
        (x1, y1), (x2, y2),
        arrowstyle="-|>" if style == "solid" else "-",
        mutation_scale=11, linewidth=1.4, color=color, linestyle=ls,
    ))
    mx, my = (x1 + x2) / 2, (y1 + y2) / 2
    ax.text(mx + 8, my, label, fontsize=8, color="#374151", va="center")


def build() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    fig, ax = plt.subplots(figsize=(11, 7.8), dpi=220)
    ax.set_xlim(0, W)
    ax.set_ylim(H, 0)
    ax.axis("off")
    fig.patch.set_facecolor("white")

    for x, y, w, h, title, attrs, fill, edge in ENTITIES:
        _entity_box(ax, x, y, w, h, title, attrs, fill, edge)

    for rel in RELATIONS:
        _relation_line(ax, *rel)

    ax.text(
        W / 2, 35,
        "PK — первичный ключ; FK — внешний ключ (actions.alert_id → alerts.id); FK* — логическая связь по rule_id",
        ha="center", va="center", fontsize=9, color="#6B7280",
    )

    fig.savefig(OUT_PNG, bbox_inches="tight", facecolor="white", pad_inches=0.08)
    fig.savefig(OUT_SVG, bbox_inches="tight", facecolor="white", pad_inches=0.08)
    plt.close(fig)
    print(f"PNG: {OUT_PNG}")
    print(f"SVG: {OUT_SVG}")


if __name__ == "__main__":
    build()
