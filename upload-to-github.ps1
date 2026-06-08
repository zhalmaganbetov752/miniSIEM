# Скрипт загрузки дипломного проекта mini SIEM на GitHub
# Запуск: powershell -ExecutionPolicy Bypass -File .\upload-to-github.ps1

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

$git = "C:\Program Files\Git\bin\git.exe"
$gh  = "C:\Program Files\GitHub CLI\gh.exe"

if (-not (Test-Path $git)) { throw "Git не найден. Установите: winget install Git.Git" }
if (-not (Test-Path $gh))  { throw "GitHub CLI не найден. Установите: winget install GitHub.cli" }

# gh auth status пишет в stderr — при $ErrorActionPreference=Stop PowerShell падает до проверки входа
$authCheck = cmd /c "`"$gh`" auth status 2>nul"
if ($LASTEXITCODE -ne 0) {
    Write-Host "Вы не вошли в GitHub. Откроется браузер для авторизации..." -ForegroundColor Yellow
    & $gh auth login -h github.com -p https -w
    if ($LASTEXITCODE -ne 0) { throw "Не удалось войти в GitHub. Запустите вручную: gh auth login" }
}

$repoName = "miniSIEM"

# Репозитория ещё нет — это нормально; gh repo view в таком случае пишет в stderr
cmd /c "`"$gh`" repo view $repoName 2>nul"
if ($LASTEXITCODE -ne 0) {
    Write-Host "Репозиторий $repoName не найден — создаю на GitHub..." -ForegroundColor Cyan
    & $gh repo create $repoName --public --source=. --remote=origin --description "Дипломный проект: mini SIEM — анализ журналов безопасности Windows"
    if ($LASTEXITCODE -ne 0) { throw "Не удалось создать репозиторий на GitHub." }
} else {
    $url = cmd /c "`"$gh`" repo view $repoName --json url -q .url"
    Write-Host "Репозиторий уже существует: $url" -ForegroundColor Green
    cmd /c "`"$git`" remote remove origin 2>nul"
    & $git remote add origin "$url.git"
}

& $git branch -M main
& $git push -u origin main

Write-Host ""
Write-Host "Готово! Репозиторий:" -ForegroundColor Green
& $gh repo view $repoName --json url -q .url
