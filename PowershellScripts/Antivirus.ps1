# Antivirus.ps1
# Author: Gorstak

# Ensure script runs as admin
$currentUser = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentUser.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Relaunching as Administrator..."
    Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

# Function to silently install Newtonsoft.Json
function Install-NewtonsoftJson {
    $libPath = "C:\ProgramData\AntivirusLibs"
    $dllPath = "$libPath\Newtonsoft.Json.dll"
    if (Test-Path $dllPath) {
        return $dllPath
    }

    try {
        Write-Host "Installing Newtonsoft.Json..."
        if (-not (Test-Path $libPath)) {
            New-Item -ItemType Directory -Path $libPath -Force | Out-Null
        }

        $nugetUrl = "https://www.nuget.org/api/v2/package/Newtonsoft.Json"
        $nupkgPath = "$libPath\Newtonsoft.Json.nupkg"
        $client = New-Object System.Net.WebClient
        $client.DownloadFile($nugetUrl, $nupkgPath)

        # Extract DLL from .nupkg (it's a ZIP)
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $zip = [System.IO.Compression.ZipFile]::OpenRead($nupkgPath)
        $entry = $zip.Entries | Where-Object { $_.FullName -like "lib/net45/Newtonsoft.Json.dll" }
        if ($entry) {
            [System.IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $dllPath, $true)
        }
        $zip.Dispose()
        Remove-Item $nupkgPath -Force

        if (Test-Path $dllPath) {
            Write-Host "Newtonsoft.Json installed successfully."
            return $dllPath
        }
        else {
            Write-Host "Failed to extract Newtonsoft.Json.dll."
            return $null
        }
    }
    catch {
        Write-Host "Failed to install Newtonsoft.Json: $_"
        return $null
    }
}

# Install Newtonsoft.Json
$jsonAssembly = Install-NewtonsoftJson
if (-not $jsonAssembly) {
    Write-Host "Error: Could not install Newtonsoft.Json. Script cannot proceed."
    exit
}

$sourceCode = @"
using System;
using System.IO;
using System.Security.Cryptography;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;
using System.Threading;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System.Diagnostics;
using System.Security.Principal;
using Microsoft.Win32;
using System.Security.AccessControl;

public class AntivirusScanner
{
    private static readonly string QuarantinePath = @"C:\Quarantine";
    private static readonly string LogPath = @"C:\ProgramData\AntivirusLog.txt";
    private static readonly HttpClient httpClient = new HttpClient();
    private static readonly string CirclBaseUrl = "https://hashlookup.circl.lu";
    private static readonly List<FileSystemWatcher> watchers = new List<FileSystemWatcher>();
    private static readonly SemaphoreSlim apiSemaphore = new SemaphoreSlim(1, 1);
    private static readonly TimeSpan BehaviorCheckInterval = TimeSpan.FromSeconds(30);

    public static async Task StartSystemMonitoring(bool silent = false)
    {
        try
        {
            // Ensure admin privileges
            if (!new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator))
            {
                Log("Error: This program requires administrative privileges.");
                return;
            }

            // Create quarantine directory
            if (!Directory.Exists(QuarantinePath))
                Directory.CreateDirectory(QuarantinePath);

            // Set up FileSystemWatchers for all fixed drives
            foreach (var drive in DriveInfo.GetDrives().Where(d => d.DriveType == DriveType.Fixed && d.IsReady))
            {
                try
                {
                    var watcher = new FileSystemWatcher
                    {
                        Path = drive.Name,
                        IncludeSubdirectories = true,
                        Filter = "*.*",
                        NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite
                    };
                    watcher.Changed += async (s, e) => await ScanFileAsync(e.FullPath);
                    watcher.Created += async (s, e) => await ScanFileAsync(e.FullPath);
                    watcher.EnableRaisingEvents = true;
                    watchers.Add(watcher);
                    Log(string.Format("Monitoring drive: {0}", drive.Name));
                }
                catch (Exception ex)
                {
                    Log(string.Format("Failed to monitor drive {0}: {1}", drive.Name, ex.Message));
                }
            }

            Log("Real-time system monitoring started with CIRCL Hashlookup. Press Ctrl+C to stop in non-silent mode.");

            // Initial scan of all drives
            Log("Performing initial drive scan...");
            foreach (var drive in DriveInfo.GetDrives().Where(d => d.DriveType == DriveType.Fixed && d.IsReady))
            {
                ScanDirectory(drive.Name);
            }

            // Start background tasks for process and persistence monitoring
            var processTask = Task.Run(() => MonitorProcessesAsync());
            var persistenceTask = Task.Run(() => MonitorPersistenceAsync());

            // Handle graceful shutdown
            if (!silent)
            {
                Console.CancelKeyPress += (s, e) =>
                {
                    Log("Stopping system monitoring...");
                    foreach (var watcher in watchers)
                    {
                        watcher.EnableRaisingEvents = false;
                        watcher.Dispose();
                    }
                    httpClient.Dispose();
                };
            }

            // Keep running
            await Task.WhenAll(processTask, persistenceTask);
        }
        catch (Exception ex)
        {
            Log(string.Format("Error in system monitoring: {0}", ex.Message));
        }
    }

    private static void ScanDirectory(string directoryPath)
    {
        try
        {
            var files = Directory.GetFiles(directoryPath, "*", SearchOption.AllDirectories)
                .Where(f => !f.StartsWith(QuarantinePath, StringComparison.OrdinalIgnoreCase));
            Parallel.ForEach(files, new ParallelOptions { MaxDegreeOfParallelism = 2 }, async file =>
            {
                await ScanFileAsync(file);
            });
            Log(string.Format("Initial scan completed for {0}.", directoryPath));
        }
        catch (Exception ex)
        {
            Log(string.Format("Error scanning directory {0}: {1}", directoryPath, ex.Message));
        }
    }

    private static async Task ScanFileAsync(string filePath)
    {
        await Task.Run(async () =>
        {
            try
            {
                if (filePath.StartsWith(QuarantinePath, StringComparison.OrdinalIgnoreCase))
                    return;

                string fileHash = ComputeSHA256(filePath);
                if (string.IsNullOrEmpty(fileHash))
                    return;

                var circlResult = await QueryCirclAsync(fileHash);
                if (circlResult.Trust < 30)
                {
                    string threatName = string.Format("CIRCL_LowTrust (Score: {0}/100, Sources: {1})", circlResult.Trust, string.Join(", ", circlResult.Sources));
                    Log(string.Format("Threat detected: {0} ({1})", filePath, threatName));
                    HandleMalware(filePath, threatName);
                }
                else if (circlResult.Trust == 50)
                {
                    Log(string.Format("Unknown file: {0} (CIRCL Score: {1})", filePath, circlResult.Trust));
                }
                else
                {
                    Log(string.Format("File clean: {0} (CIRCL Score: {1})", filePath, circlResult.Trust));
                }
            }
            catch (Exception ex)
            {
                Log(string.Format("Error scanning file {0}: {1}", filePath, ex.Message));
            }
        });
    }

    private static async Task MonitorProcessesAsync()
    {
        while (true)
        {
            try
            {
                foreach (var process in Process.GetProcesses())
                {
                    try
                    {
                        string exePath = process.MainModule != null ? process.MainModule.FileName : null;
                        if (string.IsNullOrEmpty(exePath) || exePath.StartsWith(QuarantinePath, StringComparison.OrdinalIgnoreCase))
                            continue;

                        string hash = ComputeSHA256(exePath);
                        if (string.IsNullOrEmpty(hash))
                            continue;

                        var circlResult = await QueryCirclAsync(hash);
                        if (circlResult.Trust < 30)
                        {
                            string threatName = string.Format("CIRCL_LowTrust (Score: {0}/100, Sources: {1})", circlResult.Trust, string.Join(", ", circlResult.Sources));
                            Log(string.Format("Malicious process detected: {0} (PID: {1}, Path: {2}, {3})", process.ProcessName, process.Id, exePath, threatName));
                            HandleMalware(exePath, threatName, process);
                        }

                        // Advanced: Check for suspicious behavior
                        if (IsSuspiciousProcess(process))
                        {
                            Log(string.Format("Suspicious behavior detected in process: {0} (PID: {1})", process.ProcessName, process.Id));
                            HandleMalware(exePath, "Suspicious_Behavior", process);
                        }
                    }
                    catch { }
                }
            }
            catch (Exception ex)
            {
                Log(string.Format("Error in process monitoring: {0}", ex.Message));
            }
            await Task.Delay(BehaviorCheckInterval);
        }
    }

    private static async Task MonitorPersistenceAsync()
    {
        while (true)
        {
            try
            {
                var runKey = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Run");
                if (runKey != null)
                {
                    foreach (var valueName in runKey.GetValueNames())
                    {
                        string path = runKey.GetValue(valueName) != null ? runKey.GetValue(valueName).ToString() : null;
                        if (!string.IsNullOrEmpty(path) && File.Exists(path) && !path.StartsWith(QuarantinePath, StringComparison.OrdinalIgnoreCase))
                        {
                            string hash = ComputeSHA256(path);
                            if (string.IsNullOrEmpty(hash))
                                continue;

                            var circlResult = await QueryCirclAsync(hash);
                            if (circlResult.Trust < 30)
                            {
                                string threatName = string.Format("CIRCL_LowTrust (Score: {0}/100, Sources: {1})", circlResult.Trust, string.Join(", ", circlResult.Sources));
                                Log(string.Format("Malicious persistence detected: {0} ({1})", path, threatName));
                                HandleMalware(path, threatName);
                                try
                                {
                                    runKey.DeleteValue(valueName);
                                    Log(string.Format("Removed malicious registry entry: {0}", valueName));
                                }
                                catch (Exception ex)
                                {
                                    Log(string.Format("Failed to remove registry entry {0}: {1}", valueName, ex.Message));
                                }
                            }
                        }
                    }
                    runKey.Close();
                }
            }
            catch (Exception ex)
            {
                Log(string.Format("Error in persistence monitoring: {0}", ex.Message));
            }
            await Task.Delay(BehaviorCheckInterval);
        }
    }

    private static bool IsSuspiciousProcess(Process process)
    {
        try
        {
            // Check CPU usage and memory
            if (process.TotalProcessorTime.TotalSeconds > 60 && process.WorkingSet64 > 500 * 1024 * 1024)
                return true;

            // Check for unsigned executable
            var fileInfo = FileVersionInfo.GetVersionInfo(process.MainModule != null ? process.MainModule.FileName : "");
            if (string.IsNullOrEmpty(fileInfo.CompanyName) || fileInfo.CompanyName == "Unknown")
                return true;

            return false;
        }
        catch
        {
            return false;
        }
    }

    private static void HandleMalware(string filePath, string threatName, Process process = null)
    {
        // Kill process if provided
        if (process != null)
        {
            try
            {
                if (!process.HasExited)
                {
                    process.Kill();
                    Log(string.Format("Terminated process: {0} (PID: {1})", process.ProcessName, process.Id));
                }
            }
            catch (Exception ex)
            {
                Log(string.Format("Failed to terminate process: {0} (PID: {1}): {2}", process.ProcessName, process.Id, ex.Message));
            }
        }

        // Quarantine file
        try
        {
            string fileName = Path.GetFileName(filePath);
            string quarantineFile = Path.Combine(QuarantinePath, string.Format("{0}_{1}_{2}", threatName, DateTime.Now.Ticks, fileName));
            File.Move(filePath, quarantineFile);
            Log(string.Format("Quarantined: {0} to {1}", filePath, quarantineFile));

            // Block file execution
            try
            {
                var acl = File.GetAccessControl(quarantineFile);
                acl.SetAccessRuleProtection(true, false);
                var denyRule = new FileSystemAccessRule(WindowsIdentity.GetCurrent().Name, FileSystemRights.ExecuteFile, AccessControlType.Deny);
                acl.AddAccessRule(denyRule);
                File.SetAccessControl(quarantineFile, acl);
                Log(string.Format("Blocked execution: {0}", quarantineFile));
            }
            catch (Exception ex)
            {
                Log(string.Format("Failed to block execution for {0}: {1}", quarantineFile, ex.Message));
            }
        }
        catch (Exception ex)
        {
            Log(string.Format("Failed to quarantine {0}: {1}", filePath, ex.Message));
        }
    }

    private static string ComputeSHA256(string filePath)
    {
        try
        {
            using (var sha256 = SHA256.Create())
            using (var stream = File.OpenRead(filePath))
            {
                byte[] hash = sha256.ComputeHash(stream);
                return BitConverter.ToString(hash).Replace("-", "").ToLower();
            }
        }
        catch
        {
            return string.Empty;
        }
    }

    private static async Task<CirclResult> QueryCirclAsync(string hash)
    {
        await apiSemaphore.WaitAsync();
        try
        {
            string url = string.Format("{0}/lookup/sha256/{1}", CirclBaseUrl, hash);
            var response = await httpClient.GetAsync(url);
            if (response.IsSuccessStatusCode)
            {
                string json = await response.Content.ReadAsStringAsync();
                var jObject = JObject.Parse(json);
                var trust = jObject["hashlookup:trust"] != null ? jObject["hashlookup:trust"].Value<int>() : 50;
                var sources = jObject["sources"] != null ? jObject["sources"].Values<string>().ToList() : new List<string>();
                return new CirclResult { Trust = trust, Sources = sources };
            }
        }
        catch (Exception ex)
        {
            Log(string.Format("CIRCL API error for {0}: {1}", hash, ex.Message));
        }
        finally
        {
            apiSemaphore.Release();
        }
        return new CirclResult { Trust = 50, Sources = new List<string>() };
    }

    private static void Log(string message)
    {
        string logMessage = string.Format("{0:yyyy-MM-dd HH:mm:ss} - {1}", DateTime.Now, message);
        try
        {
            File.AppendAllText(LogPath, logMessage + Environment.NewLine);
        }
        catch { }
    }

    private class CirclResult
    {
        public int Trust { get; set; }
        public List<string> Sources { get; set; }
        public CirclResult()
        {
            Sources = new List<string>();
        }
    }
}
"@

# Save the script to a fixed location for Task Scheduler
$scriptPath = "C:\ProgramData\SystemAntivirus.ps1"
if (-not (Test-Path $scriptPath)) {
    Set-Content -Path $scriptPath -Value $PSCommandPath -Force
}

# Function to set up Task Scheduler for startup and persistence
function Register-AntivirusTask {
    $taskName = "Antivirus"
    $scriptPath = "C:\ProgramData\Antivirus.ps1"
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

Register-AntivirusTask

# Compile the C# code
try {
    Add-Type -TypeDefinition $sourceCode -Language CSharp -ReferencedAssemblies "System.Net.Http", $jsonAssembly
}
catch {
    Write-Host "Compilation failed: $_"
    Write-Host "Ensure internet access for Newtonsoft.Json download."
    exit
}

# Start system-wide monitoring in silent mode

[AntivirusScanner]::StartSystemMonitoring($true)
