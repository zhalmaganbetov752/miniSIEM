# -*- coding: utf-8 -*-
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from expand_pz import ANCHORS, OUT, SRC, _find_anchor, _insert_before, _p_text
from docx import Document

EXTRA7 = {
    "1.1": [
        "Наблюдения практики в «ТрансТелеКом» (г. Астана) подтверждают: "
        "без централизованного сбора и корреляции выбор между технической "
        "неисправностью и атакой затруднён; mini SIEM отрабатывает "
        "корреляцию в учебном масштабе.",
    ],
    "1.3": [
        "Матрица FR/NFR трассируется к модулям collector_win, db, rules, "
        "app, report и тестам T-01–T-08; изменения требований отражаются "
        "в таблице 4 без пересмотра архитектуры.",
    ],
    "3.2": [
        "Поле data_json сериализуется с ensure_ascii=False для сохранения "
        "кириллицы в сообщениях Windows; parsed_* заполняются для "
        "4624/4625 при успешном разборе строковых вставок.",
    ],
    "3.4": [
        "Детектор detect_success_after_fail требует временной "
        "последовательности: серия 4625, затем 4624 с общим IP или "
        "account в chain_window_minutes.",
    ],
    "4.1": [
        "poll_channel возвращает список длиной до batch_size; пустой "
        "список означает отсутствие новых записей — штатная ситуация.",
    ],
    "4.4": [
        "_DashboardTab пересчитывает метрики при смене периода (1 ч, "
        "24 ч, 7 сут); запросы используют now_utc_iso() минус delta.",
    ],
    "5.3": [
        "WIN-SYSMON-PS-ENC при отсутствии Sysmon не срабатывает — "
        "документированное поведение опционального источника.",
    ],
    "5.5": [
        "Презентация и графические листы дополняют ПЗ; DVD включает "
        "отчёт антиплагиата и материалы защиты.",
    ],
    "2.3": [
        "rule_params хранит переопределения из GUI; при отсутствии "
        "записи используется значение из YAML params.",
    ],
    "Заключение": [
        "Цель — разработка mini SIEM для Windows — достигнута; "
        "прототип прошёл испытания и готов к защите дипломного проекта.",
    ],
}

doc = Document(str(SRC))
n = 0
for key, nxt in ANCHORS:
    paras = EXTRA7.get(key)
    if not paras:
        continue
    a = _find_anchor(doc, nxt)
    if not a:
        continue
    for t in paras:
        _insert_before(doc, a, t)
        n += 1
doc.save(str(OUT))
c = sum(len(_p_text(p)) for p in doc.paragraphs if _p_text(p))
print(f"pass7 {n} chars {c} pages@2980 {round(c/2980)}")
