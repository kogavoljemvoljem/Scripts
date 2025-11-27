# DLL Injection Monitor
# High-security monitoring for DLL injection attacks
# Runs continuously by default, trusts nothing

# === CONFIGURATION ===
$quarantineFolder = "C:\Quarantine"
$logFile          = "$quarantineFolder\dll_monitor_log.txt"
$localDatabase    = "$quarantineFolder\dll_scanned.txt"
$scannedHashes    = @{}

# Specific ctfmon.exe whitelist (to prevent popups)
# Add DLL names here that ctfmon.exe legitimately uses
$ctfmonWhitelist = @(
    "msctf.dll",
    "msutb.dll",
    "ctfmon.exe"
) | ForEach-Object { $_.ToLower() }

# Specific explorer.exe whitelist to preserve context menus and shell functionality
$explorerWhitelist = @(
    "explorer.exe",
    "shell32.dll",
    "shlwapi.dll",
    "comctl32.dll",
    "propsys.dll",
    "explorerframe.dll",
    "windows.storage.dll",
    "twinui.dll",
    "twinui.pcshell.dll",
    "thumbcache.dll"
) | ForEach-Object { $_.ToLower() }

# Specific notepad.exe whitelist to preserve file menus and UI
$notepadWhitelist = @(
    "notepad.exe",
    "comctl32.dll",
    "shell32.dll",
    "shlwapi.dll",
    "comdlg32.dll",
    "uxtheme.dll",
    "dwmapi.dll"
) | ForEach-Object { $_.ToLower() }

# PowerShell whitelist to prevent the script from killing itself
$powershellWhitelist = @(
    "powershell.exe",
    "microsoft.powershell.consolehost.ni.dll",
    "system.management.automation.ni.dll",
    "system.management.automation.dll"
) | ForEach-Object { $_.ToLower() }

# === LOGGING ===
function Write-Log {
    param([string]$message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $entry = "[$timestamp] $message"
    Write-Host $entry -ForegroundColor Cyan
    if (-not (Test-Path $quarantineFolder)) { 
        New-Item -Path $quarantineFolder -ItemType Directory -Force | Out-Null 
    }
    if ((Test-Path $logFile) -and (Get-Item $logFile).Length -ge 10MB) {
        Rename-Item $logFile "$quarantineFolder\dll_monitor_log_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt" -Force
    }
    $entry | Out-File -FilePath $logFile -Append -Encoding UTF8
}

# === CTFMON EXCEPTION ===
function Test-IsCtfmonFile {
    param([string]$fullPath, [string]$processName)
    
    # If the process loading it is ctfmon, check whitelist
    if ($processName -eq "ctfmon") {
        $fileName = (Split-Path $fullPath -Leaf).ToLower()
        if ($ctfmonWhitelist -contains $fileName) {
            Write-Log "CTFMON EXCEPTION: Allowing $fullPath for ctfmon.exe"
            return $true
        }
    }
    return $false
}

# === EXPLORER EXCEPTION ===
function Test-IsExplorerFile {
    param([string]$fullPath, [string]$processName)
    
    # If the process loading it is explorer, check whitelist
    if ($processName -eq "explorer") {
        $fileName = (Split-Path $fullPath -Leaf).ToLower()
        if ($explorerWhitelist -contains $fileName) {
            Write-Log "EXPLORER EXCEPTION: Allowing $fullPath for explorer.exe"
            return $true
        }
    }
    return $false
}

# === POWERSHELL EXCEPTION ===
function Test-IsPowerShellFile {
    param([string]$fullPath, [string]$processName)
    
    # If the process loading it is powershell, check whitelist
    if ($processName -match "powershell") {
        $fileName = (Split-Path $fullPath -Leaf).ToLower()
        if ($powershellWhitelist -contains $fileName) {
            Write-Log "POWERSHELL EXCEPTION: Allowing $fullPath for PowerShell"
            return $true
        }
    }
    
    # Allow all .NET Native Images loaded by PowerShell
    $pathLower = $fullPath.ToLower()
    if ($pathLower -match "\.ni\.dll$") {
        Write-Log "POWERSHELL EXCEPTION: Allowing .NET Native Image $fullPath for PowerShell"
        return $true
    }
    
    # Allow PowerShell core files
    if ($pathLower -match "powershell|system\.management\.automation") {
        Write-Log "POWERSHELL EXCEPTION: Allowing core file $fullPath for PowerShell"
        return $true
    }
    
    return $false
}

# === NOTEPAD EXCEPTION ===
function Test-IsNotepadFile {
    param([string]$fullPath, [string]$processName)
    
    # If the process loading it is notepad, check whitelist
    if ($processName -eq "notepad") {
        $fileName = (Split-Path $fullPath -Leaf).ToLower()
        if ($notepadWhitelist -contains $fileName) {
            Write-Log "NOTEPAD EXCEPTION: Allowing $fullPath for notepad.exe"
            return $true
        }
    }
    return $false
}

# === FILE ANALYSIS ===
function Get-DLLThreatScore {
    param([string]$filePath)
    
    $score = 0
    $reasons = @()
    
    try {
        # Check signature
        $sig = Get-AuthenticodeSignature -FilePath $filePath -ErrorAction Stop
        if ($sig.Status -ne "Valid") {
            $score += 50
            $reasons += "Unsigned/Invalid signature"
        }
        
        # Check location (even System32 is suspicious now)
        $pathLower = $filePath.ToLower()
        if ($pathLower -match "\\temp\\|\\appdata\\|\\downloads\\|\\users\\.*\\desktop") {
            $score += 30
            $reasons += "Suspicious location"
        }
        
        # UWP/Windows Store apps are digitally signed by Microsoft
        if ($pathLower -match "\\windowsapps\\") {
            $score -= 40
            $reasons += "UWP/Windows Store app (Microsoft signed)"
        }
        
        # Even System32 files can be malicious - check hash against known good
        if ($pathLower -match "\\system32\\|\\syswow64\\") {
            # Don't auto-trust, but reduce score slightly
            $score -= 10
            $reasons += "System folder (still checking)"
        }
        
        # Check file metadata
        $file = Get-Item $filePath
        if ($file.CreationTime -gt (Get-Date).AddDays(-1)) {
            $score += 20
            $reasons += "Recently created (<24h)"
        }
        
        # Check if file is hidden or system
        if ($file.Attributes -match "Hidden") {
            $score += 25
            $reasons += "Hidden attribute"
        }
        
        return [PSCustomObject]@{
            Score = $score
            Reasons = ($reasons -join "; ")
            Hash = (Get-FileHash -Path $filePath -Algorithm SHA256).Hash.ToLower()
        }
    }
    catch {
        Write-Log "Error analyzing $filePath : $_"
        return $null
    }
}

# === QUARANTINE ===
function Set-FileOwnership {
    param([string]$filePath)
    try {
        takeown /F $filePath /A >$null 2>&1
        icacls $filePath /grant "Administrators:F" /T /C /Q >$null 2>&1
        return $true
    }
    catch {
        Write-Log "Failed to take ownership: $filePath"
        return $false
    }
}

function Stop-ProcessUsingFile {
    param([string]$filePath)
    
    Get-Process | ForEach-Object {
        $proc = $_
        try {
            if ($proc.Modules.FileName -contains $filePath) {
                Write-Log "Terminating process: $($proc.Name) (PID $($proc.Id))"
                Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
            }
        }
        catch {
            # Some processes can't be enumerated
        }
    }
}

function Quarantine-SuspiciousDLL {
    param([string]$filePath, [string]$reason, [int]$score)
    
    Write-Host ">>> THREAT DETECTED: $filePath (Score: $score)" -ForegroundColor Red
    Write-Host ">>> Reason: $reason" -ForegroundColor Yellow
    Write-Log "QUARANTINE: $filePath | Score: $score | $reason"
    
    try {
        $dest = Join-Path $quarantineFolder (Split-Path $filePath -Leaf)
        $counter = 1
        while (Test-Path $dest) {
            $dest = Join-Path $quarantineFolder "$counter-$(Split-Path $filePath -Leaf)"
            $counter++
        }
        
        Set-FileOwnership $filePath
        Stop-ProcessUsingFile $filePath
        Move-Item -Path $filePath -Destination $dest -Force -ErrorAction Stop
        Write-Log "Moved to quarantine: $dest"
    }
    catch {
        Write-Log "Quarantine failed: $_"
    }
}

# === PROCESS MONITORING ===
function Monitor-LoadedDLLs {
    Write-Log "Starting DLL injection monitoring (continuous mode)..."
    
    $lastScan = @{}
    
    while ($true) {
        Get-Process | ForEach-Object {
            $proc = $_
            $procName = $proc.Name.ToLower()
            
            try {
                $proc.Modules | Where-Object { $_.FileName -like "*.dll" } | ForEach-Object {
                    $dllPath = $_.FileName
                    $dllName = Split-Path $dllPath -Leaf
                    $key = "$($proc.Id)-$dllPath"
                    
                    # Skip if already scanned recently
                    if ($lastScan.ContainsKey($key)) {
                        return
                    }
                    
                    # Check PowerShell exception first (so script doesn't kill itself)
                    if (Test-IsPowerShellFile -fullPath $dllPath -processName $procName) {
                        $lastScan[$key] = $true
                        return
                    }
                    
                    # Check ctfmon exception first
                    if (Test-IsCtfmonFile -fullPath $dllPath -processName $procName) {
                        $lastScan[$key] = $true
                        return
                    }
                    
                    # Check notepad exception
                    if (Test-IsNotepadFile -fullPath $dllPath -processName $procName) {
                        $lastScan[$key] = $true
                        return
                    }
                    
                    if (Test-IsExplorerFile -fullPath $dllPath -processName $procName) {
                        $lastScan[$key] = $true
                        return
                    }
                    
                    # Analyze threat
                    $analysis = Get-DLLThreatScore -filePath $dllPath
                    if ($analysis -and $analysis.Score -ge 50) {
                        Quarantine-SuspiciousDLL -filePath $dllPath -reason $analysis.Reasons -score $analysis.Score
                    }
                    else {
                        # Mark as scanned
                        $lastScan[$key] = $true
                        if ($analysis) {
                            "$($analysis.Hash),$($analysis.Score)" | Out-File -FilePath $localDatabase -Append -Encoding utf8
                        }
                    }
                }
            }
            catch {
                # Some system processes can't be accessed
            }
        }
        
        # Clean up old scan cache every 100 iterations
        if ($lastScan.Count -gt 10000) {
            $lastScan.Clear()
            Write-Log "Cleared scan cache"
        }
        
        Start-Sleep -Seconds 5
    }
}

# === FILE SYSTEM WATCHER ===
function Watch-NewDLLs {
    Write-Log "Setting up filesystem watchers..."
    
    Get-CimInstance Win32_LogicalDisk | Where-Object DriveType -in 2,3,4 | ForEach-Object {
        $path = "$($_.DeviceID)\"
        
        $watcher = New-Object IO.FileSystemWatcher $path, "*.dll"
        $watcher.IncludeSubdirectories = $true
        $watcher.NotifyFilter = [IO.NotifyFilters]::FileName -bor [IO.NotifyFilters]::LastWrite
        $watcher.EnableRaisingEvents = $true
        
        $action = {
            $fullPath = $Event.SourceEventArgs.FullPath
            
            # Skip quarantine folder
            if ($fullPath -like "*\Quarantine\*") { return }
            
            Write-Log "NEW DLL DETECTED: $fullPath"
            
            # Allow all .NET Native Images loaded by PowerShell
            $pathLower = $fullPath.ToLower()
            if ($pathLower -match "\.ni\.dll$" -and $pathLower -match "\\windows\\assembly\\") {
                Write-Log "POWERSHELL EXCEPTION: Allowing .NET Native Image $fullPath"
                return
            }
            
            # Check PowerShell exception
            if (Test-IsPowerShellFile -fullPath $fullPath -processName "") {
                return
            }
            
            # Check ctfmon exception
            if (Test-IsCtfmonFile -fullPath $fullPath -processName "") {
                return
            }
            
            # Check notepad exception
            $fileName = (Split-Path $fullPath -Leaf).ToLower()
            if ($notepadWhitelist -contains $fileName) {
                Write-Log "NOTEPAD EXCEPTION: Allowing new file $fullPath"
                return
            }
            
            # Check explorer exception
            if ($explorerWhitelist -contains $fileName) {
                Write-Log "EXPLORER EXCEPTION: Allowing new file $fullPath"
                return
            }
            
            Start-Sleep -Milliseconds 500  # Let file finish writing
            
            $analysis = Get-DLLThreatScore -filePath $fullPath
            if ($analysis -and $analysis.Score -ge 50) {
                Quarantine-SuspiciousDLL -filePath $fullPath -reason $analysis.Reasons -score $analysis.Score
            }
        }
        
        Register-ObjectEvent $watcher Created -Action $action >$null
        Register-ObjectEvent $watcher Changed -Action $action >$null
        
        Write-Log "Watcher active on $path"
    }
}

# === MAIN EXECUTION ===
Write-Host "==================================================" -ForegroundColor Green
Write-Host "  DLL INJECTION MONITOR - CONTINUOUS MODE" -ForegroundColor Green
Write-Host "  Trust Level: ZERO (checks everything)" -ForegroundColor Yellow
Write-Host "  ctfmon.exe: Whitelisted to prevent popups" -ForegroundColor Cyan
Write-Host "  explorer.exe: Whitelisted for context menus" -ForegroundColor Cyan
Write-Host "  notepad.exe: Whitelisted for file menus" -ForegroundColor Cyan
Write-Host "  powershell.exe: Whitelisted (script protection)" -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Green

Write-Log "DLL Injection Monitor started"

# Load previous scan results
if (Test-Path $localDatabase) {
    $lines = Get-Content $localDatabase
    Write-Log "Loaded $($lines.Count) previous scan results"
}

# Start filesystem monitoring in background
Watch-NewDLLs

# Start process monitoring (runs in foreground)
Monitor-LoadedDLLs
