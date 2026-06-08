# -*- coding: utf-8 -*-
"""Второй проход расширения (только EXTRA2) — не дублирует первый проход."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from expand_pz import ANCHORS, OUT, SRC, _find_anchor, _insert_before, _p_text  # noqa: E402
from pz_expansion_extra2 import EXPANSIONS_EXTRA2  # noqa: E402
from pz_expansion_extra3 import EXPANSIONS_EXTRA3  # noqa: E402

from docx import Document


def main() -> None:
    doc = Document(str(SRC))
    inserted = 0
    for key, next_prefix in ANCHORS:
        paragraphs = EXPANSIONS_EXTRA2.get(key, []) + EXPANSIONS_EXTRA3.get(key, [])
        if not paragraphs:
            continue
        anchor = _find_anchor(doc, next_prefix)
        if anchor is None:
            print(f"WARN: anchor not found for {key!r}")
            continue
        for text in paragraphs:
            _insert_before(doc, anchor, text)
            inserted += 1
    out_path = OUT
    try:
        doc.save(str(out_path))
    except PermissionError:
        out_path = ROOT / "ПЗ" / "ПЗ_расширено.docx"
        doc.save(str(out_path))
    chars = sum(len(_p_text(p)) for p in doc.paragraphs if _p_text(p))
    print(f"Pass2 inserted {inserted} paragraphs")
    print(f"Total chars: {chars} (~{chars // 2980} pages @2980, ~{chars // 1800} @1800)")
    print(f"Saved: {out_path}")


if __name__ == "__main__":
    main()
