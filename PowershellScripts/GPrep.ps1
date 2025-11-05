$host.ui.RawUI.BackgroundColor = "Black"
$host.ui.RawUI.ForegroundColor = "White"
Clear-Host

# Function to check for administrative privileges
function Check-Admin {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Start-Process powershell -Verb runAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
        exit
    }
}
Check-Admin

# Install applications using Winget
$apps = @(
    "Guru3D.Afterburner",
    "TheBrowserCompany.Arc",
    "Audacity.Audacity",
    "BleachBit.BleachBit",
    "BlueStack.BlueStacks",
    "Brave.Brave",
    "Klocman.BulkCrapUninstaller",
    "Google.Chrome",
    "Discord.Discord",
    "ElectronicArts.EADesktop",
    "EpicGames.EpicGamesLauncher",
    "GIMP.GIMP",
    "Git.Git",
    "GOG.Galaxy",
    "Google.PlayGames.Beta",
    "CPUID.HWMonitor",
    "ItchIo.Itch",
    "CodecGuide.K-LiteCodecPack.Mega",
    "KDE.Krita",
    "Logitech.GHUB",
    "Microsoft.PCManager",
    "Mojang.MinecraftLauncher",
    "Mozilla.Firefox",
    "Notepad++.Notepad++",
    "Opera.OperaGX",
    "PicoTorrent.PicoTorrent",
    "Playnite.Playnite",
    "PrismLauncher.PrismLauncher",
    "Rainmeter.Rainmeter",
    "ShareX.ShareX",
    "Valve.Steam",
    "SteelSeries.GG",
    "Ubisoft.Connect",
    "Vivaldi.Vivaldi",
    "Microsoft.VisualStudio.2022.Community",
    "Microsoft.VisualStudioCode",
    "RamenSoftware.Windhawk",
    "MartiCliment.UniGetUI",
    "WinMerge.WinMerge",
    "Microsoft.XNARedist"
)

foreach ($app in $apps) {
    winget install -e --id $app --accept-package-agreements --accept-source-agreements --disable-interactivity --force -h
}

# Set DNS to Cloudflare
$networkAdapters = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' }
$ipv4Dns = "1.1.1.1", "1.0.0.1"
$ipv6Dns = "2606:4700:4700::1111", "2606:4700:4700::1001"

foreach ($adapter in $networkAdapters) {
    Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ServerAddresses $ipv4Dns
    Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ServerAddresses $ipv6Dns
}

# Disable memory compression
Disable-MMAgent -MemoryCompression

# Set system restore point creation frequency
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\SystemRestore" -Name "SystemRestorePointCreationFrequency" -Value 0
Checkpoint-Computer -Description "GPrep" -RestorePointType "MODIFY_SETTINGS"

# Clean up devices
function Cleanup-Devices {
    $devices = Get-PnpDevice -Status "Error" | Where-Object { $_.Present -eq $false }
    foreach ($device in $devices) {
        Remove-PnpDevice -InstanceId $device.InstanceId -Confirm:$false -ErrorAction SilentlyContinue
    }
}
Cleanup-Devices

# Disable USB power management
$power_device_enable = Get-WmiObject MSPower_DeviceEnable -Namespace root\wmi
$usb_devices = @("Win32_USBController", "Win32_USBControllerDevice", "Win32_USBHub")

foreach ($power_device in $power_device_enable) {
    $instance_name = $power_device.InstanceName.ToUpper()
    foreach ($device in $usb_devices) {
        foreach ($hub in Get-WmiObject $device) {
            $pnp_id = $hub.PNPDeviceID
            if ($instance_name -like "*$pnp_id*") {
                $power_device.enable = $False
                $power_device.psbase.put()
            }
        }
    }
}

# Apply BCD tweaks
function Apply-BCDTweaks {
    bcdedit /set tscsyncpolicy Enhanced
    bcdedit /timeout 0
    bcdedit /set bootux disabled
    bcdedit /set bootmenupolicy standard
    bcdedit /set quietboot yes
    bcdedit /set allowedinmemorysettings 0x0
    bcdedit /set vsmlaunchtype Off
    bcdedit /deletevalue nx
    bcdedit /set vm No
    bcdedit /set x2apicpolicy Enable
    bcdedit /set uselegacyapicmode No
    bcdedit /set configaccesspolicy Default
    bcdedit /set usephysicaldestination No
    bcdedit /set usefirmwarepcisettings No
    if ((Get-WmiObject Win32_Processor).Name -like '*Intel*') {
        bcdedit /set nx optout
    } else {
        bcdedit /set nx alwaysoff
    }
}
Apply-BCDTweaks

# Apply NTFS tweaks
function Apply-NTFSTweaks {
    fsutil behavior set memoryusage 2
    fsutil behavior set mftzone 4
    fsutil behavior set disablelastaccess 1
    fsutil behavior set disabledeletenotify 0
    fsutil behavior set encryptpagingfile 0
}
Apply-NTFSTweaks

# Set RAM management tweaks
function Set-RAMTweaks {
    $ramGB = [math]::Round((Get-WmiObject -Class Win32_ComputerSystem).TotalPhysicalMemory / 1GB)
    $ioPageLockLimit = $ramGB * 1024 * 1024 * 1024 / 512
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "IoPageLockLimit" /t REG_DWORD /d $ioPageLockLimit /f

    if ($ramGB -le 4) { $cacheUnmap = 0x00000100 }
    elseif ($ramGB -le 8) { $cacheUnmap = 0x00000200 }
    elseif ($ramGB -le 12) { $cacheUnmap = 0x00000300 }
    elseif ($ramGB -le 16) { $cacheUnmap = 0x00000400 }
    elseif ($ramGB -le 32) { $cacheUnmap = 0x00000800 }
    elseif ($ramGB -le 64) { $cacheUnmap = 0x00001600 }
    elseif ($ramGB -le 128) { $cacheUnmap = 0x00003200 }
    elseif ($ramGB -le 256) { $cacheUnmap = 0x00006400 }
    else { $cacheUnmap = 0x0000C800 }
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "CacheUnmapBehindLengthInMB" /t REG_DWORD /d $cacheUnmap /f

    if ($ramGB -le 4) { $modifiedWrite = 0x00000020 }
    elseif ($ramGB -le 8) { $modifiedWrite = 0x00000040 }
    elseif ($ramGB -le 12) { $modifiedWrite = 0x00000060 }
    elseif ($ramGB -le 16) { $modifiedWrite = 0x00000080 }
    elseif ($ramGB -le 32) { $modifiedWrite = 0x00000160 }
    elseif ($ramGB -le 64) { $modifiedWrite = 0x00000320 }
    elseif ($ramGB -le 128) { $modifiedWrite = 0x00000640 }
    elseif ($ramGB -le 256) { $modifiedWrite = 0x00000C80 }
    else { $modifiedWrite = 0x00001900 }
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "ModifiedWriteMaximum" /t REG_DWORD /d $modifiedWrite /f
}
Set-RAMTweaks

# Set services to recommended mode
function Set-ServicesRecommended {
    $services = @(
        "ALG", "BcastDVRUserService_48486de", "Browser", "BthAvctpSvc", "CaptureService_48486de",
        "cbdhsvc_48486de", "diagnosticshub.standardcollector.service", "DiagTrack", "dmwappushservice",
        "edgeupdate", "edgeupdatem", "Fax", "fhsvc", "FontCache", "gupdate", "gupdatem", "lfsvc",
        "lmhosts", "MapsBroker", "MicrosoftEdgeElevationService", "MSDTC", "NahimicService",
        "NetTcpPortSharing", "PcaSvc", "PerfHost", "PhoneSvc", "PrintNotify", "QWAVE", "RemoteAccess",
        "RemoteRegistry", "RetailDemo", "RtkBtManServ", "SCardSvr", "seclogon", "SEMgrSvc", "SharedAccess",
        "ssh-agent", "stisvc", "SysMain", "TrkWks", "WerSvc", "wisvc", "WMPNetworkSvc", "WpcMonSvc",
        "WPDBusEnum", "WpnService", "WSearch", "XblAuthManager", "XblGameSave", "XboxNetApiSvc",
        "XboxGipSvc", "HPAppHelperCap", "HPDiagsCap", "HPNetworkCap", "HPSysInfoCap",
        "HpTouchpointAnalyticsService", "HvHost", "vmicguestinterface", "vmicheartbeat", "vmickvpexchange",
        "vmicrdv", "vmicshutdown", "vmictimesync", "vmicvmsession"
    )
    foreach ($service in $services) {
        Get-Service -Name $service -ErrorAction SilentlyContinue | Set-Service -StartupType Manual -ErrorAction SilentlyContinue
    }
}
Set-ServicesRecommended

# Set DPI scaling to 100%
function Set-DPIScaling {
    Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "SmoothMouseXCurve" -Value ([byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xC0,0xCC,0x0C,0x00,0x00,0x00,0x00,0x00,0x80,0x99,0x19,0x00,0x00,0x00,0x00,0x00,0x40,0x66,0x26,0x00,0x00,0x00,0x00,0x00,0x00,0x33,0x33,0x00,0x00,0x00,0x00,0x00))
    Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "SmoothMouseYCurve" -Value ([byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x38,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xA8,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xE0,0x00,0x00,0x00,0x00,0x00))
}
Set-DPIScaling

# Set disk optimizations for SSD
function Set-DiskOptimizationsSSD {
    fsutil behavior set disableLastAccess 0
    fsutil behavior set disable8dot3 1
    cmd.exe /c "FOR /F ""eol=E"" %a in ('REG QUERY ""HKLM\SYSTEM\CurrentControlSet\Services"" /S /F ""IoLatencyCap""^| FINDSTR /V ""IoLatencyCap""') DO (REG ADD ""%a"" /F /V ""IoLatencyCap"" /T REG_DWORD /d 0 >NUL 2>&1)"
    cmd.exe /c "FOR /F ""eol=E"" %a in ('REG QUERY ""HKLM\SYSTEM\CurrentControlSet\Services"" /S /F ""EnableHIPM""^| FINDSTR /V ""EnableHIPM""') DO (REG ADD ""%a"" /F /V ""EnableHIPM"" /T REG_DWORD /d 0 >NUL 2>&1 & REG ADD ""%a"" /F /V ""EnableDIPM"" /T REG_DWORD /d 0 >NUL 2>&1 & REG ADD ""%a"" /F /V ""EnableHDDParking"" /T REG_DWORD /d 0 >NUL 2>&1)"
}
Set-DiskOptimizationsSSD

# Add Restart to BIOS context menu
function Add-RestartToBIOS {
    $regPath = "HKCU:\Software\Classes\DesktopBackground\Shell\RestartToBIOS"
    New-Item -Path $regPath -Force
    Set-ItemProperty -Path $regPath -Name "(Default)" -Value "Restart to BIOS"
    Set-ItemProperty -Path $regPath -Name "Icon" -Value "C:\Windows\System32\shell32.dll,24"
    New-Item -Path "$regPath\command" -Force
    $command = "powershell.exe -NoProfile -ExecutionPolicy Bypass -Command ""Start-Process shutdown.exe -ArgumentList '/r /fw /t 1' -Verb RunAs"""
    Set-ItemProperty -Path "$regPath\command" -Name "(Default)" -Value $command
}
Add-RestartToBIOS

# Download and install PowerToys
$downloadUrl = "https://github.com/microsoft/PowerToys/releases/download/v0.82.1/PowerToysSetup-0.82.1-x64.exe"
$outputPath = "$env:TEMP\PowerToysSetup.exe"
Invoke-WebRequest -Uri $downloadUrl -OutFile $outputPath
Start-Process -FilePath $outputPath -Wait

# Download and install FxSound
$downloadUrl = "https://github.com/fxsound2/fxsound-app/raw/latest/release/fxsound_setup.exe"
$outputPath = "$env:TEMP\fxsound_setup.exe"
Invoke-WebRequest -Uri $downloadUrl -OutFile $outputPath
Start-Process -FilePath $outputPath -Wait

# Install Chocolatey if not already installed
if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
    Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
}

# Install additional packages via Chocolatey
$chocoPackages = @(
    "autologon",
    "Everything",
    "goxlr-driver",
    "start11",
    "razer-synapse-2"
)

foreach ($package in $chocoPackages) {
    choco install $package -y --no-progress --force
}

# Install additional packages via Winget
$wingetPackages = @(
    "GoXLR-on-Linux.GoXLR-Utility",
    "RazerInc.RazerInstaller"
)

foreach ($package in $wingetPackages) {
    winget install -e --id $package --accept-package-agreements --accept-source-agreements --disable-interactivity --force -h
}

# Clean up temporary files
Remove-Item -Force "$env:TEMP\PowerToysSetup.exe"
Remove-Item -Force "$env:TEMP\fxsound_setup.exe"

# Final message
Write-Host "All configurations and installations have been applied successfully." -ForegroundColor Green