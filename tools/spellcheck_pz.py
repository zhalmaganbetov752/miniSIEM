"""Scan PZ docx for orthographic issues excluding merge artifacts."""
from __future__ import annotations

import re
from pathlib import Path

from docx import Document

PZ = Path(__file__).resolve().parent.parent / "ПЗ" / "ПЗ Жалмаганбетов.docx"
MERGE = re.compile(r"соз(?:выполня|помога|обеспечива|гарантиру|берёт|берут)", re.I)


def is_code_para(t: str) -> bool:
    s = t.strip()
    if len(s) > 200 and ("CREATE TABLE" in s or s.startswith("def ")):
        return True
    if s.startswith("    ") and ("import " in s or "return " in s):
        return True
    return False


def main() -> None:
    d = Document(str(PZ))
    issues: list[tuple[int, str, str, str]] = []

    checks = [
        (r"\bOC Windows\b", "OC → ОС", "ОС Windows"),
        (r"\bOC Microsoft\b", "OC → ОС", "ОС Microsoft"),
        (r"\bТСР\b", "латиница/кириллица", "TCP"),
        (r"5ҮМ", "опечатка", "SYN"),
        (r"Ро\$", "опечатка", "DoS"),
        (r"\bЗОС\b", "опечатка", "SOC"),
        (r"\bСОТ\b", "опечатка", "SOC"),
        (r"епаро", "опечатка", "…"),
        (r"текуш", "опечатка", "текущ"),
        (r"последуюш", "опечатка", "последующ"),
        (r"ІР-", "укр. І", "IP-"),
        (r"ргодиспоп", "опечатка", "production"),
        (r"ПЫрсар", "опечатка", "PyShark"),
        (r"Мрсар", "опечатка", "Npcap"),
        (r"артеfact", "латиница", "артефакт"),
        (r"ретросpective", "латиница", "ретроспективного"),
        (r"measurable", "англ.", "измеримые"),
        (r"функциональности кейсы", "пропущено :", "функциональности: кейсы"),
        (r"\bне смотря\b", "орфография", "несмотря"),
        (r"\bв следствие\b", "орфография", "вследствие"),
        (r"\bиз за\b", "орфография", "из-за"),
        (r"\bпо этому\b", "орфография", "поэтому"),
        (r"\bв течении\b", "орфография", "в течение"),
        (r"\bв продолжении\b", "контекст", "в продолжение / в дальнейшем"),
        (r"\bввиду того что\b", "орфография", "ввиду того, что"),
        (r"\bв связи с тем что\b", "пунктуация", "в связи с тем, что"),
        (r"рисунке 7\b", "нумерация", "рисунке 4.4"),
        (r"\bмигрируют мигрируют\b", "дубль", "…"),
        (r"\bвыполняют выполняют\b", "дубль", "…"),
        (r"\bэто это\b", "дубль", "…"),
        (r"\bв итоге в итоге\b", "дубль", "…"),
        (r"Teh ", "опечатка", "The"),
        (r"–анализа", "тире", "-анализа"),
        (r"онлайн–", "тире", "онлайн-"),
    ]

    for i, p in enumerate(d.paragraphs):
        t = "".join(r.text for r in p.runs)
        if not t.strip() or is_code_para(t):
            continue
        if MERGE.search(t):
            continue

        for pat, kind, fix in checks:
            for m in re.finditer(pat, t, re.I):
                ctx = t[max(0, m.start() - 40) : m.end() + 40].replace("\n", " ")
                issues.append((i, f"{kind} → {fix}", m.group(), ctx))

        # Latin inside Cyrillic word
        for m in re.finditer(r"\b[а-яёА-ЯЁ]{2,}[a-zA-Z]{2,}[а-яёА-ЯЁ]*\b", t):
            w = m.group()
            if w.lower() not in ("windows",):
                issues.append((i, "смешение алфавитов", w, t[max(0, m.start() - 30) : m.end() + 30]))

    seen: set[tuple[int, str]] = set()
    print(f"File: {PZ.name}\nNon-merge issues: {len(issues)}\n")
    for i, note, word, ctx in issues:
        key = (i, word.lower())
        if key in seen:
            continue
        seen.add(key)
        print(f"  para {i}: [{word!r}] {note}")
        print(f"    ...{ctx}...")
        print()


if __name__ == "__main__":
    main()
