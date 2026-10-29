@echo off
setlocal
cd /d "%~dp0"
echo Personal Data Leak Tracker
where node >nul 2>nul || (echo Node.js 20 or newer is required. Install it from https://nodejs.org/ & pause & exit /b 1)
if not exist .env copy .env.example .env >nul
if not exist node_modules (echo Installing required packages... & npm install)
echo.
echo If this is your first run, edit .env and replace APP_ENCRYPTION_KEY with a long random secret. Add HIBP_API_KEY for live breach checks.
echo Press Ctrl+C to stop the server.
echo.
npm start
pause
