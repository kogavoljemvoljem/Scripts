# Antivirus - Final Clean & Working Version (November 2025)
# Author: Gorstak + Grok final fixes

# === CONFIGURATION ===
$taskName         = "SimpleAntivirusStartup"
$taskDescription  = "Runs the Simple Antivirus script at user logon with highest privileges."
$scriptDir        = "C:\Windows\Setup\Scripts\Bin"
$scriptPath       = "$scriptDir\Antivirus.ps1"
$quarantineFolder = "C:\Quarantine"
$logFile          = "$quarantineFolder\antivirus_log.txt"
$localDatabase    = "$quarantineFolder\scanned_files.txt"
$scannedFiles     = @{}

# Known-good Microsoft catalog-signed files (whitelist)
$knownGoodUnsigned = @(
    "c:\windows\system32\msctf.dll","c:\windows\system32\msutb.dll","c:\windows\system32\input.dll",
    "c:\windows\system32\coreuicomponents.dll","c:\windows\system32\dwrite.dll",
    "c:\windows\system32\windows.storage.dll","c:\windows\system32\win32u.dll",
    "c:\windows\syswow64\msctf.dll","c:\windows\syswow64\msutb.dll"
) | ForEach-Object { $_.ToLower() }

# Fully excluded folders (never scan or watch)
$excludeFolders = @(
    "d:\Steam\"
) | ForEach-Object { $_.ToLower() }

# === CORE FUNCTIONS ===
function Write-Log {
    param([string]$message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $entry = "[$timestamp] $message"
    Write-Host $entry
    if (-not (Test-Path $quarantineFolder)) { New-Item -Path $quarantineFolder -ItemType Directory -Force | Out-Null }
    if ((Test-Path $logFile) -and (Get-Item $logFile).Length -ge 10MB) {
        Rename-Item $logFile "$quarantineFolder\antivirus_log_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt" -Force
    }
    $entry | Out-File -FilePath $logFile -Append -Encoding UTF8
}

function Test-SkipFile {
    param([string]$fullPath)
    $p = $fullPath.ToLower()
    if ($knownGoodUnsigned -contains $p) { Write-Log "SKIP: Whitelisted file $fullPath"; return $true }
    foreach ($f in $excludeFolders) { if ($p.StartsWith($f)) { Write-Log "SKIP: Excluded folder $fullPath"; return $true } }
    return $false
}

function Calculate-FileHash {
    param([string]$filePath)
    try {
        $sig  = Get-AuthenticodeSignature -FilePath $filePath -ErrorAction Stop
        $hash = (Get-FileHash -Path $filePath -Algorithm SHA256 -ErrorAction Stop).Hash.ToLower()
        return [PSCustomObject]@{ Hash = $hash; Status = $sig.Status }
    } catch { Write-Log "Hash/sig error on $filePath : $_"; return $null }
}

function Set-FileOwnershipAndPermissions {
    param([string]$filePath)
    try { takeown /F $filePath /A >$null 2>&1; icacls $filePath /grant "Administrators:F" /T /C /Q >$null 2>&1; return $true }
    catch { Write-Log "Failed to take ownership of $filePath"; return $false }
}

function Stop-ProcessUsingDLL {
    param([string]$filePath)
    Get-Process | Where-Object { $_.Modules.FileName -contains $filePath } | ForEach-Object {
        Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
        Write-Log "Killed process $($_.Name) (PID $($_.Id)) using $filePath"
    }
}

function Quarantine-File {
    param([string]$filePath)
    try {
        $dest = Join-Path $quarantineFolder (Split-Path $filePath -Leaf)
        Move-Item -Path $filePath -Destination $dest -Force -ErrorAction Stop
        Write-Log "QUARANTINED → $dest"
    } catch { Write-Log "Quarantine failed $filePath : $_" }
}

# === FULL SYSTEM SCAN ===
function Remove-UnsignedDLLs {
    Write-Log "Starting full safe scan..."
    Get-CimInstance Win32_LogicalDisk | Where-Object DriveType -in 2,3,4 | ForEach-Object {
        $root = "$($_.DeviceID)\"
        Get-ChildItem -Path $root -Filter *.dll -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object {
            if (Test-SkipFile $_.FullName) { return }

            $info = Calculate-FileHash $_.FullName
            if (!$info) { return }

            if ($scannedFiles.ContainsKey($info.Hash)) {
                if (-not $scannedFiles[$info.Hash]) {
                    Set-FileOwnershipAndPermissions $_.FullName
                    Stop-ProcessUsingDLL $_.FullName
                    Quarantine-File $_.FullName
                }
                return
            }

            $valid = $info.Status -eq "Valid"
            $scannedFiles[$info.Hash] = $valid
            "$($info.Hash),$valid" | Out-File -FilePath $localDatabase -Append -Encoding utf8

            if (-not $valid) {
                Write-Log "SCAN QUARANTINE: $($_.FullName)"
                Set-FileOwnershipAndPermissions $_.FullName
                Stop-ProcessUsingDLL $_.FullName
                Quarantine-File $_.FullName
            }
        }
    }
    Write-Log "Full scan completed."
}

# === REAL-TIME FILESYSTEM WATCHER (fully working) ===
Get-CimInstance Win32_LogicalDisk | Where-Object DriveType -in 2,3,4 | ForEach-Object {
    $path = "$($_.DeviceID)\" 
    $watcher = New-Object IO.FileSystemWatcher $path, "*.dll"
    $watcher.IncludeSubdirectories = $true
    $watcher.NotifyFilter = [IO.NotifyFilters]::FileName -bor [IO.NotifyFilters]::LastWrite
    $watcher.EnableRaisingEvents = $true

    $action = {
        $fullPath = $Event.SourceEventArgs.FullPath
        $change   = $Event.SourceEventArgs.ChangeType
        if ($change -notin "Created","Changed") { return }
        if ($fullPath -like "*\C\Quarantine\*") { return }
        if (Test-SkipFile $fullPath) { return }

        Write-Log "WATCHER: Detected $change → $fullPath"

        $info = Calculate-FileHash $fullPath
        if (!$info) { return }

        # Reload database (can't modify in-memory hashtable from event)
        $db = @{}
        if (Test-Path $localDatabase) {
            Get-Content $localDatabase | Where-Object { $_ -match "^([0-9a-f]{64}),(true|false)$" } | ForEach-Object {
                $db[$matches[1]] = [bool]$matches[2]
            }
        }

        if ($db.ContainsKey($info.Hash) -and -not $db[$info.Hash]) {
            Set-FileOwnershipAndPermissions $fullPath
            Stop-ProcessUsingDLL $fullPath
            Quarantine-File $fullPath
            return
        }

        $valid = $info.Status -eq "Valid"
        "$($info.Hash),$valid" | Out-File -FilePath $localDatabase -Append -Encoding utf8

        if (-not $valid) {
            Write-Log "WATCHER QUARANTINE: $fullPath"
            Set-FileOwnershipAndPermissions $fullPath
            Stop-ProcessUsingDLL $fullPath
            Quarantine-File $fullPath
        }
    }

    Register-ObjectEvent $watcher Created  -Action $action >$null
    Register-ObjectEvent $watcher Changed -Action $action >$null
    Write-Log "Real-time watcher activated on $path"
}

# === PERSISTENCE & STARTUP ===
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole("Administrator")
Write-Log "Script started - Running as Administrator: $isAdmin"

# Copy itself for persistence
if (-not (Test-Path $scriptDir)) { New-Item -Path $scriptDir -ItemType Directory -Force | Out-Null }
if (-not (Test-Path $scriptPath) -or (Get-Item $scriptPath).LastWriteTime -lt (Get-Item $MyInvocation.MyCommand.Path).LastWriteTime) {
    Copy-Item -Path $MyInvocation.MyCommand.Path -Destination $scriptPath -Force
    Write-Log "Script copied/updated to persistent location"
}

# Register as SYSTEM task
if ($isAdmin -and -not (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue)) {
    $a = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$scriptPath`""
    $t = New-ScheduledTaskTrigger -AtLogOn
    $p = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName $taskName -Action $a -Trigger $t -Principal $p -Description $taskDescription -Force | Out-Null
    Write-Log "Scheduled task '$taskName' created (runs as SYSTEM)"
}

# Load database
if (Test-Path $localDatabase) {
    Get-Content $localDatabase | Where-Object { $_ -match "^([0-9a-f]{64}),(true|false)$" } | ForEach-Object {
        $scannedFiles[$matches[1]] = [bool]$matches[2]
    }
    Write-Log "Loaded $($scannedFiles.Count) cached file hashes"
}

# === START SCANNING & MONITORING ===
Remove-UnsignedDLLs
Write-Log "=== Simple Antivirus fully active - Real-time protection ON ==="
Write-Host "Antivirus is running in the background. Press Ctrl+C only if testing."

# Keep alive
try { while ($true) { Start-Sleep -Seconds 3600 } } catch { Write-Log "Script terminated" }