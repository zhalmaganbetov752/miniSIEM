## miniSIEM (Windows workstation) — дипломный проект

Тема: **Разработка программного средства анализа журналов безопасности операционной системы на рабочей станции**.

Это мини‑SIEM для Windows:
- собирает события из **Windows Event Log** (Security/System/Application) и **Sysmon** (если установлен),
- сохраняет их в **SQLite**,
- применяет правила детекта,
- показывает события и алерты в GUI,
- поддерживает реакции в режиме **dry-run** (безопасный режим) и опционально реальные действия (потребуют админ‑прав).

## 1) Установка Python (нужно для сборки .exe)

Для разработки/сборки нужен Python **3.11 x64** (рекомендуется).

- Скачай Python с сайта Microsoft Store или python.org (вариант python.org предпочтительнее для dev).
- При установке поставь галочку **Add python.exe to PATH**.

Проверка:

```powershell
python --version
pip --version
```

## 2) Установка зависимостей

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## 3) Запуск

```powershell
.\.venv\Scripts\Activate.ps1
python -m minisiem
```

## 4) Сборка одного .exe (PyInstaller)

```powershell
.\.venv\Scripts\Activate.ps1
pyinstaller .\packaging\minisiem.spec --noconfirm
```

Результат будет в `dist\miniSIEM.exe` (один файл).

## 5) Sysmon (опционально)

Для части детектов нужен Sysmon канал `Microsoft-Windows-Sysmon/Operational`.
Установка Sysmon требует админ‑прав и отдельного дистрибутива Sysmon от Microsoft Sysinternals.

