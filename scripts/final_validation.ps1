# Phase 12 — fresh-environment validation (Windows).  Usage: .\scripts\final_validation.ps1 <git-url-or-local-path>
# NOT TESTED by the package author (no Windows in the build environment) — run it once and fix what breaks.
param([Parameter(Mandatory = $true)][string]$Source)
$ErrorActionPreference = "Stop"
$work = Join-Path $env:TEMP ("agentsentry_validation_" + [guid]::NewGuid().ToString("N").Substring(0, 8))
New-Item -ItemType Directory -Path $work | Out-Null
$repo = Join-Path $work "repo"
if (Test-Path $Source -PathType Container) {
    Copy-Item $Source $repo -Recurse
    foreach ($x in "venv", ".venv", "agentsentry.db", "models") { Remove-Item (Join-Path $repo $x) -Recurse -Force -ErrorAction SilentlyContinue }
} else { git clone --quiet $Source $repo }
Set-Location $repo
python -m venv .venv
& .\.venv\Scripts\python.exe -m pip install -q -r requirements.txt
if (Test-Path requirements-member2.txt) { & .\.venv\Scripts\python.exe -m pip install -q -r requirements-member2.txt }
& .\.venv\Scripts\python.exe -m pytest -q
if ($LASTEXITCODE -ne 0) { throw "pytest failed" }
& .\.venv\Scripts\python.exe agent/demo_agent.py --proxy | Out-Null
if ($LASTEXITCODE -ne 0) { throw "demo failed" }
Write-Host "VALIDATION PASSED (fresh env: $work)"
