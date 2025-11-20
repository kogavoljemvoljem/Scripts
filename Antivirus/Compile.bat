@echo off

:: Step 1: Elevate
>nul 2>&1 fsutil dirty query %systemdrive% || echo CreateObject^("Shell.Application"^).ShellExecute "%~0", "ELEVATED", "", "runas", 1 > "%temp%\uac.vbs" && "%temp%\uac.vbs" && exit /b
DEL /F /Q "%temp%\uac.vbs"

:: Step 2: Initialize environment
setlocal EnableExtensions EnableDelayedExpansion

:: Step 3: Move to the script directory
cd /d %~dp0

"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe" /win32manifest:app.manifest /target:winexe /win32icon:Autorun.ico /out:Antivirus.exe *.cs /reference:Newtonsoft.Json.dll;System.Windows.Forms.dll;System.Drawing.dll
echo Done! Antivirus.exe created.
pause