using System;
using System.IO;
using System.Security.Cryptography;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using System.Threading;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System.Diagnostics;
using System.Security.Principal;
using Microsoft.Win32;
using System.Security.AccessControl;
using System.Runtime.InteropServices;

public class AntivirusScanner
{
    [DllImport("kernel32.dll")]
    static extern IntPtr GetConsoleWindow();

    [DllImport("user32.dll")]
    static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

    private const int SW_HIDE = 0;

    private static readonly string QuarantinePath = @"C:\Quarantine";
    private static readonly string LogPath = @"C:\ProgramData\AntivirusLog.txt";
    private static readonly string CirclBaseUrl = "https://hashlookup.circl.lu";
    private static readonly List<FileSystemWatcher> watchers = new List<FileSystemWatcher>();
    private static readonly SemaphoreSlim apiSemaphore = new SemaphoreSlim(1, 1);
    private static readonly TimeSpan BehaviorCheckInterval = TimeSpan.FromSeconds(30);

    public static void Main(string[] args)
    {
        var handle = GetConsoleWindow();
        ShowWindow(handle, SW_HIDE);

        bool silent = args.Length > 0 && args[0].ToLower() == "silent";
        StartSystemMonitoring(silent).GetAwaiter().GetResult();
    }

    public static async Task StartSystemMonitoring(bool silent = false)
    {
        try
        {
            if (!new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator))
            {
                Log("Error: This program requires administrative privileges.");
                return;
            }

            AddToStartup();

            if (!Directory.Exists(QuarantinePath))
                Directory.CreateDirectory(QuarantinePath);

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

            Log("Performing initial drive scan...");
            foreach (var drive in DriveInfo.GetDrives().Where(d => d.DriveType == DriveType.Fixed && d.IsReady))
            {
                ScanDirectory(drive.Name);
            }

            var processTask = Task.Run(() => MonitorProcessesAsync());
            var persistenceTask = Task.Run(() => MonitorPersistenceAsync());

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
                };
            }

            await Task.WhenAll(processTask, persistenceTask);
        }
        catch (Exception ex)
        {
            Log(string.Format("Error in system monitoring: {0}", ex.Message));
        }
    }

    private static void AddToStartup()
    {
        try
        {
            string taskName = "AntivirusScannerStartup";
            string exePath = Process.GetCurrentProcess().MainModule.FileName;

            ProcessStartInfo deleteInfo = new ProcessStartInfo
            {
                FileName = "schtasks.exe",
                Arguments = string.Format("/delete /tn \"{0}\" /f", taskName),
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using (Process deleteProcess = Process.Start(deleteInfo))
            {
                deleteProcess.WaitForExit();
                if (deleteProcess.ExitCode == 0)
                {
                    Log(string.Format("Removed existing task: {0}", taskName));
                }
            }

            string xmlTask = string.Format(@"<?xml version=""1.0"" encoding=""UTF-16""?>
<Task version=""1.2"" xmlns=""http://schemas.microsoft.com/windows/2004/02/mit/task"">
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id=""Author"">
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>true</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>true</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>true</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context=""Author"">
    <Exec>
      <Command>""{0}""</Command>
      <Arguments>silent</Arguments>
    </Exec>
  </Actions>
</Task>", exePath);

            string tempXmlPath = Path.Combine(Path.GetTempPath(), "AntivirusTask.xml");
            File.WriteAllText(tempXmlPath, xmlTask);

            ProcessStartInfo createInfo = new ProcessStartInfo
            {
                FileName = "schtasks.exe",
                Arguments = string.Format("/create /tn \"{0}\" /xml \"{1}\"", taskName, tempXmlPath),
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using (Process createProcess = Process.Start(createInfo))
            {
                createProcess.WaitForExit();
                if (createProcess.ExitCode == 0)
                {
                    Log(string.Format("Added to Task Scheduler: {0}", taskName));
                }
                else
                {
                    string error = createProcess.StandardError.ReadToEnd();
                    Log(string.Format("Failed to add to Task Scheduler: {0}", error));
                }
            }

            File.Delete(tempXmlPath);
        }
        catch (Exception ex)
        {
            Log(string.Format("Failed to add to Task Scheduler: {0}", ex.Message));
        }
    }

    private static void ScanDirectory(string directoryPath)
    {
        try
        {
            var files = GetFilesSafely(directoryPath);
            Parallel.ForEach(files, new ParallelOptions { MaxDegreeOfParallelism = 2 }, async file =>
            {
                await ScanFileAsync(file);
            });
            Log(string.Format("Initial scan completed for {0}", directoryPath));
        }
        catch (Exception ex)
        {
            Log(string.Format("Error scanning directory {0}: {1}", directoryPath, ex.Message));
        }
    }

    private static IEnumerable<string> GetFilesSafely(string directoryPath)
    {
        var files = new List<string>();
        try
        {
            files.AddRange(Directory.GetFiles(directoryPath));
            foreach (var subDir in Directory.GetDirectories(directoryPath))
            {
                try
                {
                    files.AddRange(GetFilesSafely(subDir));
                }
                catch { } // Skip inaccessible subdirectories
            }
        }
        catch { } // Skip inaccessible root directory
        return files.Where(f => !f.StartsWith(QuarantinePath, StringComparison.OrdinalIgnoreCase));
    }

    private static async Task ScanFileAsync(string filePath)
    {
        if (filePath.Equals(LogPath, StringComparison.OrdinalIgnoreCase)) return; // Skip log file

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
            if (process.TotalProcessorTime.TotalSeconds > 60 && process.WorkingSet64 > 500 * 1024 * 1024)
                return true;

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

        try
        {
            string fileName = Path.GetFileName(filePath);
            string quarantineFile = Path.Combine(QuarantinePath, string.Format("{0}_{1}_{2}", threatName, DateTime.Now.Ticks, fileName));
            File.Move(filePath, quarantineFile);
            Log(string.Format("Quarantined: {0} to {1}", filePath, quarantineFile));

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
            using (var webClient = new WebClient())
            {
                string json = await webClient.DownloadStringTaskAsync(new Uri(url));
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