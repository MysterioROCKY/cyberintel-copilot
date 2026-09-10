param(
    [int]$Port = 8501
)

$ErrorActionPreference = "Stop"
if (-not (Get-Command cloudflared -ErrorAction SilentlyContinue)) {
    throw "cloudflared is not installed. Install it first, then run this script again."
}

Write-Host "Creating a temporary public URL for http://127.0.0.1:$Port"
Write-Host "Do not upload private reports while the tunnel is public. Press Ctrl+C to close the public URL."
& cloudflared tunnel --url "http://127.0.0.1:$Port"
