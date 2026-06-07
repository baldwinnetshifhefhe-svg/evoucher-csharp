@echo off
cd /d "%~dp0"
echo ==================================================
echo    e-PSS  (C# / .NET version)
echo ==================================================
echo  Starting... then open this in your browser:
echo      http://localhost:5005
echo  (the full system; the raw data is at /api/producers etc.)
echo  Press Ctrl+C in this window to stop.
echo.
"C:\Program Files\dotnet\dotnet.exe" run
pause
