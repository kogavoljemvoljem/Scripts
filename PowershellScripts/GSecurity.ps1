function Register-SystemLogonScript {
    param ([string]$TaskName = "RunGSecurityAtLogon")
    
    $scriptSource = $MyInvocation.MyCommand.Path
    if (-not $scriptSource) { $scriptSource = $PSCommandPath }
    if (-not $scriptSource) {
        Write-Host "Error: Could not determine script path."
        return
    }

    $targetFolder = "C:\Windows\Setup\Scripts\Bin"
    $targetPath = Join-Path $targetFolder (Split-Path $scriptSource -Leaf)

    if (-not (Test-Path $targetFolder)) {
        New-Item -Path $targetFolder -ItemType Directory -Force | Out-Null
        Write-Host "Created folder: $targetFolder"
    }

    try {
        Copy-Item -Path $scriptSource -Destination $targetPath -Force -ErrorAction Stop
        Write-Host "Copied script to: $targetPath"
    } catch {
        Write-Host "Failed to copy script: $_"
        return
    }

    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -File `"$targetPath`""
    $trigger = New-ScheduledTaskTrigger -AtLogOn
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

    try {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
        Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal
        Write-Host "Scheduled task '$TaskName' created to run at user logon under SYSTEM."
    } catch {
        Write-Host "Failed to register task: $_"
    }
}

# Run the function
Register-SystemLogonScript

function Kill-Process-And-Parent {
    param ([int]$Pid)
    try {
        $proc = Get-CimInstance Win32_Process -Filter "ProcessId=$Pid"
        if ($proc) {
            Stop-Process -Id $Pid -Force -ErrorAction SilentlyContinue
            Write-Host "Killed process PID $Pid ($($proc.Name))" "Warning"
            if ($proc.ParentProcessId) {
                $parentProc = Get-Process -Id $proc.ParentProcessId -ErrorAction SilentlyContinue
                if ($parentProc) {
                    if ($parentProc.ProcessName -eq "explorer") {
                        Stop-Process -Id $parentProc.Id -Force -ErrorAction SilentlyContinue
                        Start-Process "explorer.exe"
                        Write-Host "Restarted Explorer after killing parent of suspicious process." "Warning"
                    } else {
                        Stop-Process -Id $parentProc.Id -Force -ErrorAction SilentlyContinue
                        Write-Host "Also killed parent process: $($parentProc.ProcessName) (PID $($parentProc.Id))" "Warning"
                    }
                }
            }
        }
    } catch {}
}

function Kill-Rootkits {
    $Safe = @("System","svchost","lsass","services","wininit","winlogon","explorer","taskhostw","dwm","spoolsv")
    $Procs = Get-NetTCPConnection | Where-Object { $_.RemoteAddress -like '192.168.*' -or $_.RemoteAddress -like '172.16.*' -or $_.RemoteAddress -like '10.*' -or $_.RemoteAddress -like '127.*' } | ForEach-Object { $Procs[$_.OwningProcess] = $true }
    foreach ($PID in $Procs.Keys) {
        $Proc = Get-Process -Id $PID -ErrorAction SilentlyContinue
        if ($Safe -notcontains $Proc.ProcessName) { Stop-Process -Id $PID -Force -ErrorAction SilentlyContinue; Write-Host "Killed $($Proc.ProcessName)" }
    }
}

function Start-ProcessKiller {
        $badNames = @("mimikatz", "", "procdump", "mimilib", "pypykatz")
        foreach ($name in $badNames) {
            Get-Process -Name $name -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
        }
    }

function Detect-And-Terminate-Keyloggers {
    $hooks = Get-WmiObject -Query "SELECT * FROM Win32_Process WHERE CommandLine LIKE '%hook%' OR CommandLine LIKE '%log%' OR CommandLine LIKE '%key%'"
    foreach ($hook in $hooks) {
        $process = Get-Process -Id $hook.ProcessId -ErrorAction SilentlyContinue
        if ($process -and -not ($protectedProcesses -contains $process.ProcessName)) {
            Write-Host "Keylogger activity detected: $($process.ProcessName) (PID: $($process.Id))"
            Stop-Process -Id $process.Id -Force
            Write-Host "Keylogger process terminated: $($process.ProcessName)"
        }
    }
}

function Detect-And-Terminate-Overlays {
    $overlayProcesses = Get-Process | Where-Object { 
        $_.MainWindowTitle -ne "" -and (-not $protectedProcesses -contains $_.ProcessName)
    }
    foreach ($process in $overlayProcesses) {
        Write-Host "Suspicious overlay detected: $($process.ProcessName) (PID: $($process.Id))"
        Stop-Process -Id $process.Id -Force
        Write-Host "Overlay process terminated: $($process.ProcessName)"
    }
}

function Start-StealthKiller {
    while ($true) {
        # Kill unsigned or hidden-attribute processes
        Get-CimInstance Win32_Process | ForEach-Object {
            $exePath = $_.ExecutablePath
            if ($exePath -and (Test-Path $exePath)) {
                $isHidden = (Get-Item $exePath).Attributes -match "Hidden"
                $sigStatus = (Get-AuthenticodeSignature $exePath).Status
                if ($isHidden -or $sigStatus -ne 'Valid') {
                    try {
                        Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
                        Write-Host "Killed unsigned/hidden-attribute process: $exePath" "Warning"
                    } catch {}
                }
            }
        }

        # Kill stealthy processes (present in WMI but not in tasklist)
        $visible = tasklist /fo csv | ConvertFrom-Csv | Select-Object -ExpandProperty "PID"
        $all = Get-WmiObject Win32_Process | Select-Object -ExpandProperty ProcessId
        $hidden = Compare-Object -ReferenceObject $visible -DifferenceObject $all | Where-Object { $_.SideIndicator -eq "=>" }

        foreach ($pid in $hidden) {
            try {
                $proc = Get-Process -Id $pid.InputObject -ErrorAction SilentlyContinue
                if ($proc) {
                    Stop-Process -Id $pid.InputObject -Force -ErrorAction SilentlyContinue
                    Write-Host "Killed stealthy (tasklist-hidden) process: $($proc.ProcessName) (PID $($pid.InputObject))" "Error"
                }
            } catch {}
        }

        Start-Sleep -Seconds 5
    }
}

function Monitor-XSS {
    try {
        Get-NetTCPConnection -State Established | ForEach-Object {
            $remoteIP = $_.RemoteAddress
            try {
                $hostEntry = [System.Net.Dns]::GetHostEntry($remoteIP)
                if ($hostEntry.HostName -match "xss") {
                    Disable-NetAdapter -Name (Get-NetAdapter | Where-Object { $_.Status -eq "Up" }).Name -Confirm:$false -ErrorAction SilentlyContinue
                    Start-Sleep -Seconds 3
                    Enable-NetAdapter -Name (Get-NetAdapter | Where-Object { $_.Status -eq "Disabled" }).Name -Confirm:$false -ErrorAction SilentlyContinue
                    New-NetFirewallRule -DisplayName "BlockXSS-$remoteIP" -Direction Outbound -RemoteAddress $remoteIP -Action Block -ErrorAction SilentlyContinue
                    Write-Host "XSS detected, blocked ${hostEntry.HostName}: $remoteIP and toggled network adapters." -Level Error
                }
            } catch {}
        }
    } catch {
        Write-Host "Error in XSS monitoring: $_" -Level Error
    }
}

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