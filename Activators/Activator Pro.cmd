@echo off
Title Activator Pro && Color 0b

:: Step 1: Elevate
>nul 2>&1 fsutil dirty query %systemdrive% || echo CreateObject^("Shell.Application"^).ShellExecute "%~0", "ELEVATED", "", "runas", 1 > "%temp%\uac.vbs" && "%temp%\uac.vbs" && exit /b
DEL /F /Q "%temp%\uac.vbs"

:: Step 2: Activate
slmgr //b /ipk W269N-WFGWX-YVC9B-4J6C9-T83GX
slmgr //b /skms kms.digiboy.ir
slmgr /ato
slmgr //b /cpky