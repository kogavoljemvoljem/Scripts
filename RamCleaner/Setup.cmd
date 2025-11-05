@echo off

:: Step 1: Elevate
>nul 2>&1 fsutil dirty query %systemdrive% || echo CreateObject^("Shell.Application"^).ShellExecute "%~0", "ELEVATED", "", "runas", 1 > "%temp%\uac.vbs" && "%temp%\uac.vbs" && exit /b
DEL /F /Q "%temp%\uac.vbs"

:: Step 2: Initialize environment
setlocal EnableExtensions EnableDelayedExpansion

:: Step 3: Move to the script directory
cd /d %~dp0
cd Bin

:: Step 5: Execute CMD (.cmd) files alphabetically
echo Executing CMD scripts...
for /f "tokens=*" %%B in ('dir /b /o:n *.cmd') do (
    echo Running %%B...
    call "%%B"
)

echo Script completed successfully.
exit
