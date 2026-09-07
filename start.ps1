# TraceVault Quick Launcher
# Run this script to start all TraceVault services

$dockerPath = "C:\Users\banka\AppData\Local\Programs\DockerDesktop\resources\bin"
if (Test-Path $dockerPath) {
    $env:PATH = "$env:PATH;$dockerPath"
}

Write-Host ""
Write-Host "  ████████╗██████╗  █████╗  ██████╗███████╗██╗   ██╗ █████╗ ██╗   ██╗██╗  ████████╗" -ForegroundColor Cyan
Write-Host "     ██╔══╝██╔══██╗██╔══██╗██╔════╝██╔════╝██║   ██║██╔══██╗██║   ██║██║  ╚══██╔══╝" -ForegroundColor Cyan
Write-Host "     ██║   ██████╔╝███████║██║     █████╗  ██║   ██║███████║██║   ██║██║     ██║   " -ForegroundColor Cyan
Write-Host "     ██║   ██╔══██╗██╔══██║██║     ██╔══╝  ╚██╗ ██╔╝██╔══██║██║   ██║██║     ██║   " -ForegroundColor Cyan
Write-Host "     ██║   ██║  ██║██║  ██║╚██████╗███████╗ ╚████╔╝ ██║  ██║╚██████╔╝███████╗██║   " -ForegroundColor Cyan
Write-Host "     ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚══════╝  ╚═══╝  ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝  " -ForegroundColor Cyan
Write-Host ""
Write-Host "  AI-Powered Email Threat Detection & Forensic Intelligence Platform" -ForegroundColor DarkCyan
Write-Host "  SIH 2024 — Problem Statement 26106 — AICTE Cyber Security Cell" -ForegroundColor DarkGray
Write-Host ""

# Check Docker is available
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Write-Host "  [ERROR] Docker not found. Make sure Docker Desktop is running." -ForegroundColor Red
    Write-Host "  Download: https://www.docker.com/products/docker-desktop/" -ForegroundColor Yellow
    Read-Host "  Press Enter to exit"
    exit 1
}

Write-Host "  [1/2] Starting TraceVault services..." -ForegroundColor Yellow
docker compose up -d

if ($LASTEXITCODE -ne 0) {
    Write-Host ""
    Write-Host "  [ERROR] Failed to start services. Check Docker Desktop is running." -ForegroundColor Red
    Read-Host "  Press Enter to exit"
    exit 1
}

Write-Host ""
Write-Host "  [2/2] Waiting for health checks..." -ForegroundColor Yellow
Start-Sleep -Seconds 5

Write-Host ""
docker compose ps
Write-Host ""
Write-Host "  ✅ TraceVault is LIVE!" -ForegroundColor Green
Write-Host ""
Write-Host "  🌐 Dashboard     → http://localhost:3000" -ForegroundColor White
Write-Host "  ⚡ API           → http://localhost:8000" -ForegroundColor White
Write-Host "  📚 API Docs      → http://localhost:8000/docs" -ForegroundColor White
Write-Host "  ❤️  Health Check  → http://localhost:8000/health" -ForegroundColor White
Write-Host ""

# Open browser
$openBrowser = Read-Host "  Open browser now? (Y/n)"
if ($openBrowser -ne 'n' -and $openBrowser -ne 'N') {
    Start-Process "http://localhost:3000"
}
