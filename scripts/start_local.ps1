param(
    [int]$Port = 8501
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $PSScriptRoot
$Python = Join-Path $ProjectRoot ".venv\Scripts\python.exe"

if (-not (Test-Path -LiteralPath $Python)) {
    throw "Virtual environment not found. Run the setup steps in README.md first."
}

Write-Host "Starting CyberIntel Copilot at http://127.0.0.1:$Port"
& $Python -m streamlit run (Join-Path $ProjectRoot "app.py") --server.address 127.0.0.1 --server.port $Port --server.headless true
