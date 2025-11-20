@echo off
"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe" /win32manifest:app.manifest /target:winexe /win32icon:Autorun.ico /out:Antivirus.exe *.cs /reference:Newtonsoft.Json.dll;System.Windows.Forms.dll;System.Drawing.dll
echo Done! Antivirus.exe created.
pause