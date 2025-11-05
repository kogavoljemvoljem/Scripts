@echo off
:: Batch script to clean Windows Update backups similar to NTLite v1.5

:: Elevate
>nul 2>&1 fsutil dirty query %systemdrive% || echo CreateObject^("Shell.Application"^).ShellExecute "%~0", "ELEVATED", "", "runas", 1 > "%temp%\uac.vbs" && "%temp%\uac.vbs" && exit /b
DEL /F /Q "%temp%\uac.vbs"

:: Check for admin rights
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo This script requires administrative privileges. Please run as Administrator.
    pause
    exit /b 1
)

echo Stopping Windows Update and BITS services...
net stop wuauserv
net stop bits

echo Cleaning SoftwareDistribution folder...
rd /s /q "%windir%\SoftwareDistribution"
if exist "%windir%\SoftwareDistribution" (
    echo Failed to delete SoftwareDistribution folder. It may be in use.
) else (
    echo SoftwareDistribution folder cleaned.
)

echo Running DISM Component Cleanup...
dism.exe /online /Cleanup-Image /StartComponentCleanup
if %errorlevel% equ 0 (
    echo Component Cleanup completed successfully.
) else (
    echo Component Cleanup failed. Check C:\Windows\Logs\DISM\dism.log for details.
)

echo Running DISM ResetBase to remove superseded components...
dism.exe /online /Cleanup-Image /StartComponentCleanup /ResetBase
if %errorlevel% equ 0 (
    echo ResetBase completed successfully. Note: You cannot uninstall existing updates after this.
) else (
    echo ResetBase failed. Check C:\Windows\Logs\DISM\dism.log for details.
)

echo Doing disk cleanup
cleanmgr /sagerun:65535
cleanmgr /verylowdisk

echo Restarting Windows Update and BITS services...
net start wuauserv
net start bits

echo Cleanup complete. Press any key to exit.
pause

exit /b 0
