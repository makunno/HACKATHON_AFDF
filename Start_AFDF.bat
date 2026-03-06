@echo off
title AFDF - Anti-Forensic Detection Framework
color 0A

echo ===================================================
echo     AFDF - Anti-Forensic Detection Framework
echo ===================================================
echo.
echo Starting Microservices (React, Node.js, Python)...
echo Please leave this window open while using the app.
echo.

:: Navigate to the directory where the batch file is located
cd /d "%~dp0"

:: Run the concurrently script
call npm run start:all

:: If it crashes or exits, keep the window open so the user can see the error
pause
