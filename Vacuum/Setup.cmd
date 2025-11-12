@echo off

:: Step 1: Elevate
>nul 2>&1 fsutil dirty query %systemdrive% || echo CreateObject^("Shell.Application"^).ShellExecute "%~0", "ELEVATED", "", "runas", 1 > "%temp%\uac.vbs" && "%temp%\uac.vbs" && exit /b
DEL /F /Q "%temp%\uac.vbs"

:: Step 2: Initialize environment
setlocal EnableExtensions EnableDelayedExpansion

:: Step 3: Move to the script directory
cd /d %~dp0
cd Bin

:: Step 5: Copy files
copy /y Enviar.dbe %windir%\system32\Enviar.dbe
copy /y sqlite3.exe %windir%\system32\sqlite3.exe
copy /y Vacuum.bat %USERPROFILE%\Desktop\Vacuum.bat
echo Script completed successfully.
exit
