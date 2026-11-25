@echo off
title CHECKER - Fortinet/FortiGate Panel
cd /d "%~dp0"
echo ========================================
echo   CHECKER Panel - starting server...
echo   Panel will open at http://localhost:7000
echo   CHECKER - storona.shop - 1337or420 Team
echo ========================================
start "" http://localhost:7000
node server.js
pause
