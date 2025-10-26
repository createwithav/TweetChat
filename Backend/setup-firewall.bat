@echo off
echo Adding Windows Firewall rules for TweetChat...
echo.

netsh advfirewall firewall add rule name="TweetChat Backend" dir=in action=allow protocol=TCP localport=5000
netsh advfirewall firewall add rule name="TweetChat Frontend" dir=in action=allow protocol=TCP localport=8000

if %errorlevel% equ 0 (
    echo Firewall rules added successfully!
    echo.
    echo Your servers are now accessible at:
    echo   Backend:  http://localhost:5000 or http://10.1.33.159:5000
    echo   Frontend: http://localhost:8000 or http://10.1.33.159:8000
    echo.
    echo Access the frontend URL from your browser or other devices.
) else (
    echo Failed to add firewall rules. Please run this script as Administrator.
    pause
)

