Write-Host "Starting HTTP server for TweetChat Frontend..." -ForegroundColor Cyan
Write-Host ""
Write-Host "Server will be accessible at:" -ForegroundColor Green
Write-Host "  - http://localhost:8000 (on this computer)" -ForegroundColor Yellow
Write-Host "  - http://10.1.33.159:8000 (from other devices on your network)" -ForegroundColor Yellow
Write-Host ""
Write-Host "Press Ctrl+C to stop the server." -ForegroundColor Cyan
Write-Host ""

# Try to use Python HTTP server first
$hasPython = Get-Command python -ErrorAction SilentlyContinue
if ($hasPython) {
    Write-Host "Using Python HTTP server..." -ForegroundColor Green
    python -m http.server 8000
}
else {
    Write-Host "Python not found. Please install Python or use:" -ForegroundColor Red
    Write-Host "npm install -g http-server" -ForegroundColor Yellow
    Write-Host "Then run: http-server -p 8000" -ForegroundColor Yellow
}

