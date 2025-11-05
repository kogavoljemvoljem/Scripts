@echo off
Title Activator Enterprise && Color 0b

:: Step 1: Elevate
>nul 2>&1 fsutil dirty query %systemdrive% || echo CreateObject^("Shell.Application"^).ShellExecute "%~0", "ELEVATED", "", "runas", 1 > "%temp%\uac.vbs" && "%temp%\uac.vbs" && exit /b
DEL /F /Q "%temp%\uac.vbs"

:: Step 2: Activate
slmgr //b /ipk NPPR9-FWDCX-D2C8J-H872K-2YT43
slmgr //b /skms kms.digiboy.ir
slmgr /ato
slmgr //b /cpky