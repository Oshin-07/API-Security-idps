@echo off
title AI-Driven API Security Scanner Launcher
echo ===================================================
echo Starting Vulnerable Test Target (Port 8888)...
echo ===================================================
start "Vulnerable Target API" cmd /k "cd /d %~dp0 && python test_vulnerable_api\mock_vulnerable_api.py"

timeout /t 2 /nobreak >nul

echo ===================================================
echo Starting FastAPI Backend (Port 8000)...
echo ===================================================
start "FastAPI Backend" cmd /k "cd /d %~dp0 && python backend\main.py"

timeout /t 2 /nobreak >nul

echo Opening browser to http://127.0.0.1:8000/ ...
start http://127.0.0.1:8000/

echo ===================================================
echo All servers are running!
echo ===================================================
pause
