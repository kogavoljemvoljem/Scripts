@echo off
Title Activator LTSC && Color 0b

:: Step 1: Elevate
>nul 2>&1 fsutil dirty query %systemdrive% || echo CreateObject^("Shell.Application"^).ShellExecute "%~0", "ELEVATED", "", "runas", 1 > "%temp%\uac.vbs" && "%temp%\uac.vbs" && exit /b
DEL /F /Q "%temp%\uac.vbs"

:: Step 2: Activate
slmgr //b /ipk M7XTQ-FN8P6-TTKYV-9D4CC-J462D
slmgr //b /skms kms.digiboy.ir
slmgr /ato
slmgr //b /cpky