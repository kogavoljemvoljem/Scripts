# AutoPatch-FULLY-AUTO.ps1
# FULLY AUTOMATIC: No CSV export, no prompts, silent daily patching
# Uses Microsoft API + fallback to cached CSV

$ErrorActionPreference = "SilentlyContinue"
$Log = "C:\ProgramData\VulnPatcher\log.txt"
$Dir = "C:\ProgramData\VulnPatcher"
$Script = "$Dir\AutoPatch-FULLY-AUTO.ps1"
$Task = "VulnPatcher-FULLY-AUTO"
$CsvPath = "$Dir\ms-vulns.csv"

# === SILENT LOGGING ONLY (NO CONSOLE OUTPUT) ===
function L { param($m); "$((Get-Date).ToString('yyyy-MM-dd HH:mm:ss')) - $m" | Out-File $Log -Append -Encoding ASCII }

# === CREATE DIR & SELF-PERSIST ===
if (-not (Test-Path $Dir)) { New-Item -ItemType Directory -Path $Dir -Force | Out-Null }
if ($MyInvocation.MyCommand.Path -notlike "$Dir\*") {
    $Content = [IO.File]::ReadAllText($MyInvocation.MyCommand.Path)
    [IO.File]::WriteAllText($Script, $Content)
    Start-Process "powershell.exe" -ArgumentList "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$Script`"" -WindowStyle Hidden
    exit
}

L "=== FULLY AUTO PATCH CYCLE START ==="

# === 1. AUTO-DOWNLOAD MICROSOFT CSV (NO 999 ERROR) ===
$msApi = "https://api.msrc.microsoft.com/cvrf/2025-Oct?`$format=csv"
$tempCsv = "$env:TEMP\msrc-temp.csv"

try {
    $wc = New-Object Net.WebClient
    $wc.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
    $wc.Headers.Add("Accept", "text/csv")
    $wc.DownloadFile($msApi, $tempCsv)
    if ((Get-Item $tempCsv).Length -gt 1000) {
        Move-Item $tempCsv $CsvPath -Force
        L "Microsoft CSV auto-downloaded and cached"
    }
} catch {
    L "API download failed: $_"
    if (-not (Test-Path $CsvPath)) {
        L "No cached CSV. Cannot proceed without internet."
        goto END
    } else {
        L "Using cached CSV from previous run"
    }
}

# === 2. LOAD CSV ===
if (-not (Test-Path $CsvPath)) {
    L "FATAL: No CSV available. Need internet on first run."
    goto END
}

$vulns = Import-Csv $CsvPath
L "Loaded $($vulns.Count) vulnerabilities from Microsoft"

# === 3. GET INSTALLED KBs ===
$inst = Get-HotFix | Select-Object -ExpandProperty HotFixID -ErrorAction SilentlyContinue
if (-not $inst) { $inst = @() }

# === 4. FIND MISSING PATCHES ===
$toInstall = @()
foreach ($v in $vulns) {
    $cve = "CVE-" + $v.'CVE'
    $kbField = $v.'KB'
    if ($kbField -match 'KB\d{7}') {
        $kb = ($kbField -split ';')[0].Trim()
        if ($inst -notcontains $kb) {
            $toInstall += "$kb|$cve"
            L "[$cve] $kb - MISSING"
        }
    }
}

if ($toInstall.Count -eq 0) {
    L "ALL VULNS PATCHED"
    goto END
}

# === 5. WINDOWS UPDATE COM (SILENT) ===
try {
    $session = New-Object -ComObject Microsoft.Update.Session
    $searcher = $session.CreateUpdateSearcher()
    $result = $searcher.Search("IsInstalled=0")
    $installColl = New-Object -ComObject Microsoft.Update.UpdateColl

    foreach ($item in $toInstall) {
        $kb = ($item -split '\|')[0] -replace 'KB',''
        foreach ($u in $result.Updates) {
            if ($u.KBArticleIDs -contains $kb) {
                $installColl.Add($u) | Out-Null
                L "QUEUED KB$kb"
                break
            }
        }
    }

    if ($installColl.Count -gt 0) {
        $dl = $session.CreateUpdateDownloader()
        $dl.Updates = $installColl
        $dl.Download()
        $inst = $session.CreateUpdateInstaller()
        $inst.Updates = $installColl
        $res = $inst.Install()
        if ($res.ResultCode -eq 2) {
            L "INSTALLED $($installColl.Count) PATCHES"
            if ($res.RebootRequired) { L "REBOOT PENDING" }
        } else {
            L "INSTALL FAILED: $($res.ResultCode)"
        }
    }
} catch { L "WU ERROR: $_" }

:END

# === 6. SCHEDULE DAILY (SILENT) ===
$action = "powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$Script`""
schtasks /create /tn $Task /tr $action /sc daily /st 03:00 /ru SYSTEM /f /rl HIGHEST /delay 0000:30 | Out-Null
L "Daily silent task ensured"

L "=== CYCLE END ==="