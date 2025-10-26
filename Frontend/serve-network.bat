@echo off
echo Starting HTTP server for TweetChat Frontend...
echo.
echo Server will be accessible at:
echo   - http://localhost:8000 (on this computer)
echo   - http://10.1.33.159:8000 (from other devices on your network)
echo.
echo Press Ctrl+C to stop the server.
echo.
python -m http.server 8000

