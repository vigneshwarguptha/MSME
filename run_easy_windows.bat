@echo off
title MSME Pro Workforce Planner
cd /d "%~dp0"
echo Starting MSME Pro Workforce Planner...
echo.
where py >nul 2>nul
if %errorlevel%==0 (
  py easy_local.py
) else (
  python easy_local.py
)
echo.
echo Server stopped. Press any key to close.
pause >nul
