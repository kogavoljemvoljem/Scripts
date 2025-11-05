# GSecurity.ps1
# Author: Gorstak
$protectedProcesses = @("System", "svchost", "lsass", "services", "wininit", "winlogon", "explorer", "taskhostw", "dwm", "spoolsv", "ms-settings")

function Quarantine-Process {
    param ([string]$ExePath, [int]$Pid)
    $quarantineFolder = "C:\Quarantine"
    if (-not (Test-Path $quarantineFolder)) { New-Item -Path $quarantineFolder -ItemType Directory -Force | Out-Null }
    $quarantinePath = Join-Path $quarantineFolder (Split-Path $ExePath -Leaf)
    Move-Item -Path $ExePath -Destination $quarantinePath -Force -ErrorAction SilentlyContinue
    Stop-Process -Id $Pid -Force -ErrorAction SilentlyContinue
}

function Kill-Process {
    param ([int]$Pid)
    $proc = Get-Process -Id $Pid -ErrorAction SilentlyContinue
    if ($proc -and $protectedProcesses -notcontains $proc.ProcessName) {
        Stop-Process -Id $Pid -Force -ErrorAction SilentlyContinue
    }
}

function Kill-Process-And-Parent {
    param ([int]$Pid)
    $proc = Get-CimInstance Win32_Process -Filter "ProcessId=$Pid"
    if ($proc -and $protectedProcesses -notcontains $proc.Name) {
        Kill-Process -Pid $Pid
        if ($proc.ParentProcessId) {
            $parentProc = Get-Process -Id $proc.ParentProcessId -ErrorAction SilentlyContinue
            if ($parentProc -and $protectedProcesses -notcontains $parentProc.ProcessName) {
                if ($parentProc.ProcessName -eq "explorer") {
                    Stop-Process -Id $parentProc.Id -Force -ErrorAction SilentlyContinue
                    Start-Process "explorer.exe"
                } else {
                    Kill-Process -Pid $parentProc.Id
                }
            }
        }
    }
}

function Kill-Rootkits {
    $Procs = Get-NetTCPConnection | Where-Object { $_.RemoteAddress -like '192.168.*' -or $_.RemoteAddress -like '172.16.*' -or $_.RemoteAddress -like '10.*' -or $_.RemoteAddress -like '127.*' } | ForEach-Object { $Procs[$_.OwningProcess] = $true }
    foreach ($PID in $Procs.Keys) {
        $Proc = Get-Process -Id $PID -ErrorAction SilentlyContinue
        if ($Proc -and $protectedProcesses -notcontains $Proc.ProcessName) { Kill-Process -Pid $PID }
    }
}

function Start-ProcessKiller {
    $badNames = @("mimikatz", "procdump", "mimilib", "pypykatz")
    foreach ($name in $badNames) {
        Get-Process -Name $name -ErrorAction SilentlyContinue | Where-Object { $protectedProcesses -notcontains $_.ProcessName } | ForEach-Object { Kill-Process -Pid $_.Id }
    }
}

function Start-StealthKiller {
    while ($true) {
        Get-CimInstance Win32_Process | ForEach-Object {
            $exePath = $_.ExecutablePath
            if ($exePath -and (Test-Path $exePath)) {
                $isHidden = (Get-Item $exePath).Attributes -match "Hidden"
                $sigStatus = (Get-AuthenticodeSignature $exePath).Status
                if ($isHidden -or $sigStatus -ne 'Valid') {
                    $proc = Get-Process -Id $_.ProcessId -ErrorAction SilentlyContinue
                    if ($proc -and $protectedProcesses -notcontains $proc.ProcessName) {
                        Quarantine-Process -ExePath $exePath -Pid $_.ProcessId
                    }
                }
            }
        }

        $visible = tasklist /fo csv | ConvertFrom-Csv | Select-Object -ExpandProperty "PID"
        $all = Get-WmiObject Win32_Process | Select-Object -ExpandProperty ProcessId
        $hidden = Compare-Object -ReferenceObject $visible -DifferenceObject $all | Where-Object { $_.SideIndicator -eq "=>" }

        foreach ($pid in $hidden) {
            $proc = Get-Process -Id $pid.InputObject -ErrorAction SilentlyContinue
            if ($proc -and $protectedProcesses -notcontains $proc.ProcessName) {
                Quarantine-Process -ExePath $proc.Path -Pid $pid.InputObject
            }
        }

        Start-Sleep -Seconds 5
    }
}

function Monitor-XSS {
    Get-NetTCPConnection -State Established | ForEach-Object {
        $remoteIP = $_.RemoteAddress
        try {
            $hostEntry = [System.Net.Dns]::GetHostEntry($remoteIP)
            if ($hostEntry.HostName -match "xss") {
                Disable-NetAdapter -Name (Get-NetAdapter | Where-Object { $_.Status -eq "Up" }).Name -Confirm:$false -ErrorAction SilentlyContinue
                Start-Sleep -Seconds 3
                Enable-NetAdapter -Name (Get-NetAdapter | Where-Object { $_.Status -eq "Disabled" }).Name -Confirm:$false -ErrorAction SilentlyContinue
                New-NetFirewallRule -DisplayName "BlockXSS-$remoteIP" -Direction Outbound -RemoteAddress $remoteIP -Action Block -ErrorAction SilentlyContinue
            }
        } catch {}
    }
}

# Save the script to a fixed location for Task Scheduler
$scriptPath = "C:\ProgramData\GSecurity.ps1"
if (-not (Test-Path $scriptPath)) {
    Set-Content -Path $scriptPath -Value $PSCommandPath -Force
}

# Function to set up Task Scheduler for startup and persistence
function Register-GSecurityTask {
    $taskName = "GSecurity"
    $scriptPath = "C:\ProgramData\GSecurity.ps1"
    $action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$scriptPath`""
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 5)
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

    try {
        Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Force
        Write-Host "Antivirus scheduled task registered successfully. Will run at startup."
    }
    catch {
        Write-Host "Failed to register scheduled task: $_"
        exit
    }
}

Register-GSecurityTask

Start-Job -ScriptBlock {
    while ($true) {
        Kill-Rootkits
        Start-ProcessKiller
        Detect-And-Terminate-Keyloggers
        Detect-And-Terminate-Overlays
        Start-StealthKiller
        Monitor-XSS
    }
}