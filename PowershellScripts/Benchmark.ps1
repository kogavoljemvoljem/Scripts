# Hide the PowerShell console window
$null = Add-Type @"
using System;
using System.Runtime.InteropServices;
public class HideConsoleWindow {
    [DllImport("kernel32.dll")]
    public static extern IntPtr GetConsoleWindow();
    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
    public const int SW_HIDE = 0;
    public const int SW_SHOW = 5;
    public static void Hide() {
        IntPtr hWnd = GetConsoleWindow();
        ShowWindow(hWnd, SW_HIDE);
    }
}
"@
[HideConsoleWindow]::Hide()

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# Create the main form
$form = New-Object Windows.Forms.Form
$form.Text = "Benchmark Results"
$form.Size = New-Object Drawing.Size(640, 480)
$form.StartPosition = "CenterScreen"
$form.TopMost = $true

# Create a TextBox for results and loading
$box = New-Object Windows.Forms.TextBox
$box.Multiline = $true
$box.ReadOnly = $true
$box.Dock = "Fill"
$box.ScrollBars = "Vertical"
$box.Font = New-Object Drawing.Font("Consolas", 12)
$form.Controls.Add($box)

# Create a Panel for the Screenshot button
$panel = New-Object Windows.Forms.Panel
$panel.Dock = "Top"
$panel.Height = 45
$form.Controls.Add($panel)

# Add Screenshot button (disabled until tests complete)
$button = New-Object Windows.Forms.Button
$button.Text = "Screenshot"
$button.Size = New-Object Drawing.Size(120, 30)
$button.Location = New-Object Drawing.Point(500, 7)
$button.Anchor = "Top, Right"
$button.Enabled = $false
$panel.Controls.Add($button)

# Loading animation variables
$dots = "."
$loadingText = "Running benchmarks"
$timer = New-Object System.Windows.Forms.Timer
$timer.Interval = 500 # 500ms interval for animation
$timer.Add_Tick({
    $global:dots = if ($dots.Length -ge 3) { "." } else { $dots + "." }
    $box.Text = "$loadingText$dots`r`n`r`n"
    $box.ScrollToCaret()
    [System.Windows.Forms.Application]::DoEvents()
})

# Logging function to update the TextBox
function Update-Log {
    param ([string]$Message)
    $box.AppendText("$Message`r`n")
    $box.ScrollToCaret()
    [System.Windows.Forms.Application]::DoEvents()
}

# Screenshot function to mimic Windows key + Print Screen
function Take-Screenie {
    try {
        Start-Sleep -Milliseconds 500
        # Simulate Windows key + Print Screen
        [System.Windows.Forms.SendKeys]::SendWait("{PRTSC}")
        [System.Windows.Forms.SendKeys]::SendWait("^{PRTSC}") # Ctrl + Print Screen for Windows key simulation
        Start-Sleep -Milliseconds 500

        # Notify user
        $path = "$env:USERPROFILE\Pictures\Screenshots\Screenshot_$(Get-Date -Format 'yyyyMMdd_HHmmss').png"
        Update-Log "Screenshot saved to: $path"
        [System.Windows.Forms.MessageBox]::Show("Screenshot saved to:`n$path`nand copied to clipboard.")
    } catch {
        Update-Log "Screenshot Error: $_"
        [System.Windows.Forms.MessageBox]::Show("Failed to take screenshot: $_")
    }
}

# CPU Benchmark
function Test-CPU {
    try {
        $maxIterations = 1000
        $start = Get-Date
        for ($i = 0; $i -lt $maxIterations; $i++) {
            $result = $i * 2 + 1 - $i
            Write-Progress -Activity "CPU Benchmark" -Status "Testing Integer Math..." -PercentComplete (($i / $maxIterations) * 100)
        }
        $intTime = (Get-Date) - $start

        $start = Get-Date
        for ($i = 0; $i -lt $maxIterations; $i++) {
            $result = [math]::sqrt($i) * [math]::PI
            Write-Progress -Activity "CPU Benchmark" -Status "Testing Floating Point Math..." -PercentComplete (($i / $maxIterations) * 100)
        }
        $floatTime = (Get-Date) - $start

        $totalTime = $intTime.TotalSeconds + $floatTime.TotalSeconds
        if ($totalTime -le 0) {
            return "Error"
        }
        $cpuScore = 1 / $totalTime
        $cpuScore = [math]::Round($cpuScore * 1500, 2)
        return $cpuScore
    } catch {
        return "Error"
    }
}

# Memory Benchmark
function Test-Memory {
    try {
        $maxIterations = 1000
        $array = @()
        
        $start = Get-Date
        for ($i = 0; $i -lt $maxIterations; $i++) {
            $array += Get-Random -Maximum 10000
            Write-Progress -Activity "Memory Benchmark" -Status "Writing to Memory..." -PercentComplete (($i / $maxIterations) * 100)
        }
        $writeTime = (Get-Date) - $start

        $start = Get-Date
        $sum = 0
        for ($i = 0; $i -lt $maxIterations; $i++) {
            $sum += $array[$i]
            Write-Progress -Activity "Memory Benchmark" -Status "Reading from Memory..." -PercentComplete (($i / $maxIterations) * 100)
        }
        $readTime = (Get-Date) - $start

        $memoryWriteScore = 1 / $writeTime.TotalSeconds
        $memoryReadScore = 1 / $readTime.TotalSeconds
        $memoryWriteScore = [math]::Round($memoryWriteScore * 500, 2)
        $memoryReadScore = [math]::Round($memoryReadScore * 500, 2)
        return $memoryWriteScore, $memoryReadScore
    } catch {
        return "Error", "Error"
    }
}

# Disk Benchmark
function Test-Disk {
    try {
        $directory = "$env:USERPROFILE\Documents"
        if (-not (Test-Path -Path $directory)) {
            New-Item -ItemType Directory -Path $directory | Out-Null
        }
        $filePath = "$directory\benchmark_testfile.txt"
        $content = "0" * 1024 * 1024

        $start = Get-Date
        Set-Content -Path $filePath -Value $content -Force
        Start-Sleep -Milliseconds 100
        $writeTime = (Get-Date) - $start

        if (Test-Path -Path $filePath) {
            $start = Get-Date
            $data = Get-Content -Path $filePath -Raw
            $readTime = (Get-Date) - $start
            Remove-Item -Path $filePath -Force
        } else {
            return "Disk Read Error"
        }

        $diskScore = 1 / ($writeTime.TotalSeconds + $readTime.TotalSeconds)
        $diskScore = [math]::Round($diskScore * 40, 2)
        return $diskScore
    } catch {
        return "Disk Error"
    }
}

# Graphics Benchmark
function Test-Graphics {
    try {
        $start = Get-Date
        $maxFrames = 1000
        for ($i = 0; $i -lt $maxFrames; $i++) {
            Start-Sleep -Milliseconds 1
            Write-Progress -Activity "Graphics Benchmark" -Status "Rendering Frames..." -PercentComplete (($i / $maxFrames) * 100)
        }
        $renderTime = (Get-Date) - $start

        $graphicsScore = 1 / $renderTime.TotalSeconds
        $graphicsScore = [math]::Round($graphicsScore * 500, 2)
        return $graphicsScore
    } catch {
        return "Error"
    }
}

# Button click event
$button.Add_Click({
    Take-Screenie
})

# Show the form and start the timer immediately
$form.Show()
$timer.Start()

# Run benchmarks sequentially and update GUI
try {
    $cpu = Test-CPU
    $global:loadingText = "Running benchmarks (CPU completed)"
    Update-Log "CPU Score: $cpu"
    
    $memWrite, $memRead = Test-Memory
    $global:loadingText = "Running benchmarks (Memory completed)"
    Update-Log "Memory Write Score: $memWrite"
    Update-Log "Memory Read Score: $memRead"
    
    $disk = Test-Disk
    $global:loadingText = "Running benchmarks (Disk completed)"
    Update-Log "Disk Score: $disk"
    
    $gpu = Test-Graphics
    $global:loadingText = "Running benchmarks (Graphics completed)"
    Update-Log "Graphics Score: $gpu"
    
    $total = [math]::Round(($cpu * 0.3 + $memWrite * 0.2 + $memRead * 0.2 + $disk * 0.2 + $gpu * 0.1), 2)
    
    # Clear the loading text and display final results
    $timer.Stop()
    $box.Text = @"
Benchmark Results:
------------------
CPU Score:        $cpu
Memory Write:     $memWrite
Memory Read:      $memRead
Disk Score:       $disk
Graphics Score:   $gpu
------------------
Total Score:      $total
"@
    $button.Enabled = $true
} catch {
    $timer.Stop()
    $box.Text = "Benchmark failed: $_"
}

# Keep the application running
[System.Windows.Forms.Application]::Run($form)