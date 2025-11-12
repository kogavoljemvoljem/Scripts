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
using System.Windows.Forms;

public class AntivirusScanner
{
    [DllImport("kernel32.dll")]
    static extern IntPtr GetConsoleWindow();

    [DllImport("user32.dll")]
    static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

    private const int SW_HIDE = 0;

    private static readonly string QuarantinePath = @"C:\Quarantine";
    private static readonly string LogPath = @"C:\ProgramData\AntivirusLog.txt";
    private static readonly string BackupPath = @"C:\ProgramData\Antivirus\Backup";
    private static readonly string ConfigPath = @"C:\ProgramData\AntivirusConfig.json";
    private static readonly string CirclBaseUrl = "https://hashlookup.circl.lu";
    private static readonly string VirusTotalApiKey = "YOURVIRUSTOTALAPIKEYHERE";
    private static readonly string VirusTotalUploadUrl = "https://www.virustotal.com/api/v3/files";
    private static readonly string VirusTotalAnalysisUrl = "https://www.virustotal.com/api/v3/files/{0}";
    private static readonly List<FileSystemWatcher> watchers = new List<FileSystemWatcher>();
    private static readonly SemaphoreSlim apiSemaphore = new SemaphoreSlim(4, 4);
    private static readonly TimeSpan BehaviorCheckInterval = TimeSpan.FromSeconds(30);
    private static readonly int MaxRetries = 3;
    private static readonly int RetryDelaySeconds = 15;
    private static readonly long MaxFileSizeBytes = 32 * 1024 * 1024;
    private static Dictionary<string, object> config;

    static AntivirusScanner()
    {
        config = new Dictionary<string, object>();
        config.Add("MaxLogSizeMB", 10);
        config.Add("ScanIntervalSeconds", 3600);
    }

    private static readonly string[] WhitelistPatterns = {
        @"*\Antivirus.exe",
        @"*\Quarantine*",
        @"*\Windows\System32*",
        @"*\Windows\SysWOW64*",
        @"*\Windows\WinSxS*",
        @"*\Program Files\Windows Defender*",
        @"*\Program Files\WindowsApps*"
    };

    public static void Main(string[] args)
    {
        var handle = GetConsoleWindow();
        ShowWindow(handle, SW_HIDE);

        bool silent = args.Length > 0 && args[0].ToLower() == "silent";
        StartSystemMonitoring(silent).GetAwaiter().GetResult();
    }

    private static void OnFileChanged(object sender, FileSystemEventArgs e)
    {
        ScanFileAsync(e.FullPath).GetAwaiter().GetResult();
    }

    private static void OnFileCreated(object sender, FileSystemEventArgs e)
    {
        ScanFileAsync(e.FullPath).GetAwaiter().GetResult();
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

            LoadConfig();
            if (!Directory.Exists(QuarantinePath)) Directory.CreateDirectory(QuarantinePath);
            if (!Directory.Exists(BackupPath)) Directory.CreateDirectory(BackupPath);

            AddToStartup();

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
                    watcher.Changed += OnFileChanged;
                    watcher.Created += OnFileCreated;
                    watcher.EnableRaisingEvents = true;
                    watchers.Add(watcher);
                    Log(string.Format("Monitoring drive: {0}", drive.Name));
                }
                catch (Exception ex)
                {
                    Log(string.Format("Failed to monitor drive {0}: {1}", drive.Name, ex.Message));
                }
            }

            Log("Real-time system monitoring started with VirusTotal and CIRCL. Press Ctrl+C to stop in non-silent mode.");

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

    private static void LoadConfig()
    {
        if (File.Exists(ConfigPath))
        {
            try
            {
                string json = File.ReadAllText(ConfigPath);
                config = JsonConvert.DeserializeObject<Dictionary<string, object>>(json);
            }
            catch (Exception ex)
            {
                Log(string.Format("Error loading config: {0}", ex.Message));
            }
        }
        else
        {
            try
            {
                File.WriteAllText(ConfigPath, JsonConvert.SerializeObject(config));
                Log("Created default config file at: " + ConfigPath);
            }
            catch (Exception ex)
            {
                Log(string.Format("Error creating config file: {0}", ex.Message));
            }
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
    <Principal id=""Gorstak"">
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
  <Actions Context=""Gorstak"">
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
            Parallel.ForEach(files, new ParallelOptions { MaxDegreeOfParallelism = 2 }, file =>
            {
                ScanFileAsync(file).GetAwaiter().GetResult();
            });
            Log(string.Format("Initial scan completed for {0}.", directoryPath));
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
                catch { }
            }
        }
        catch { }
        return files.Where(f => !f.StartsWith(QuarantinePath, StringComparison.OrdinalIgnoreCase));
    }

    private static async Task ScanFileAsync(string filePath)
    {
        if (filePath.Equals(LogPath, StringComparison.OrdinalIgnoreCase)) return;

        try
        {
            if (filePath.StartsWith(QuarantinePath, StringComparison.OrdinalIgnoreCase))
                return;

            if (IsWhitelisted(filePath))
            {
                Log(string.Format("Skipping whitelisted file: {0}", filePath));
                return;
            }

            string fileHash = ComputeSHA256(filePath);
            if (string.IsNullOrEmpty(fileHash))
                return;

            bool isMalicious = await ScanFileWithVirusTotal(fileHash, filePath);
            if (isMalicious)
            {
                string threatName = "VirusTotal_Malicious";
                Log(string.Format("Threat detected: {0} ({1})", filePath, threatName));
                HandleMalware(filePath, threatName);
                ShowNotification("Malicious file quarantined: " + filePath);
            }
            else if (Path.GetExtension(filePath).ToLower() == ".dll" && !IsSignedDLL(filePath))
            {
                string threatName = "Unsigned_DLL";
                Log(string.Format("Unsigned DLL detected: {0}", filePath));
                HandleMalware(filePath, threatName);
                ShowNotification("Unsigned DLL quarantined: " + filePath);
            }
            else
            {
                var circlResult = QueryCircl(filePath);
                if (circlResult.Trust < 30)
                {
                    string threatName = string.Format("CIRCL_LowTrust (Score: {0}/100, Sources: {1})", circlResult.Trust, string.Join(", ", circlResult.Sources));
                    Log(string.Format("Threat detected: {0} ({1})", filePath, threatName));
                    HandleMalware(filePath, threatName);
                    ShowNotification("Malicious file quarantined: " + filePath);
                }
                else
                {
                    Log(string.Format("File clean: {0} (CIRCL Score: {1})", filePath, circlResult.Trust));
                }
            }
        }
        catch (Exception ex)
        {
            Log(string.Format("Error scanning file {0}: {1}", filePath, ex.Message));
        }
    }

    private static async Task<bool> ScanFileWithVirusTotal(string hash, string filePath)
    {
        for (int i = 0; i < MaxRetries; i++)
        {
            bool semaphoreAcquired = false;
            bool success = false;
            string errorMessage = null;
            JObject result = null;

            try
            {
                semaphoreAcquired = apiSemaphore.Wait(30000);
                string url = string.Format(VirusTotalAnalysisUrl, hash);
                var request = WebRequest.Create(url);
                request.Headers.Add("x-apikey", VirusTotalApiKey);
                using (var response = request.GetResponse())
                {
                    using (var stream = response.GetResponseStream())
                    using (var reader = new StreamReader(stream))
                    {
                        string json = reader.ReadToEnd();
                        result = JObject.Parse(json);
                        success = true;
                    }
                }
            }
            catch (WebException ex)
            {
                errorMessage = ex.Message;
                if (ex.Response != null && ((HttpWebResponse)ex.Response).StatusCode == HttpStatusCode.NotFound)
                {
                    if (semaphoreAcquired) apiSemaphore.Release();
                    semaphoreAcquired = false;
                    return UploadFileToVirusTotal(filePath, hash);
                }
            }
            finally
            {
                if (semaphoreAcquired) apiSemaphore.Release();
            }

            if (success && result != null)
            {
                int malicious = result["data"]["attributes"]["last_analysis_stats"]["malicious"].Value<int>();
                Log(string.Format("VirusTotal result for {0}: {1} malicious detections.", hash, malicious));
                return malicious > 3;
            }

            if (errorMessage != null)
            {
                Log(string.Format("VirusTotal error for {0}: {1}", hash, errorMessage));
            }

            if (i < MaxRetries - 1)
            {
                await Task.Delay(RetryDelaySeconds * 1000);
            }
        }
        return false;
    }

    private static bool UploadFileToVirusTotal(string filePath, string hash)
    {
        if (new FileInfo(filePath).Length > MaxFileSizeBytes)
        {
            Log(string.Format("Cannot upload {0}: File size exceeds {1} MB.", filePath, MaxFileSizeBytes / (1024 * 1024)));
            return false;
        }

        bool semaphoreAcquired = false;
        bool success = false;
        string errorMessage = null;

        try
        {
            semaphoreAcquired = apiSemaphore.Wait(30000);
            var request = (HttpWebRequest)WebRequest.Create(VirusTotalUploadUrl);
            request.Method = "POST";
            request.Headers.Add("x-apikey", VirusTotalApiKey);
            var boundary = "----------" + DateTime.Now.Ticks.ToString("x");
            request.ContentType = "multipart/form-data; boundary=" + boundary;

            using (var requestStream = request.GetRequestStream())
            {
                string formDataTemplate = "\r\n--" + boundary + "\r\nContent-Disposition: form-data; name=\"{0}\"; filename=\"{1}\"\r\nContent-Type: application/octet-stream\r\n\r\n";
                string formItem = string.Format(formDataTemplate, "file", Path.GetFileName(filePath));
                byte[] formItemBytes = System.Text.Encoding.UTF8.GetBytes(formItem);
                requestStream.Write(formItemBytes, 0, formItemBytes.Length);

                byte[] buffer = new byte[4096];
                int bytesRead;
                using (FileStream fileStream = new FileStream(filePath, FileMode.Open, FileAccess.Read))
                {
                    while ((bytesRead = fileStream.Read(buffer, 0, buffer.Length)) != 0)
                    {
                        requestStream.Write(buffer, 0, bytesRead);
                    }
                }

                byte[] boundaryBytes = System.Text.Encoding.UTF8.GetBytes("\r\n--" + boundary + "--\r\n");
                requestStream.Write(boundaryBytes, 0, boundaryBytes.Length);
            }

            using (var response = request.GetResponse())
            {
                using (var stream = response.GetResponseStream())
                using (var reader = new StreamReader(stream))
                {
                    string json = reader.ReadToEnd();
                    JObject result = JObject.Parse(json);
                    string analysisId = result["data"]["id"].Value<string>();
                    Log(string.Format("Uploaded {0}. Analysis ID: {1}", filePath, analysisId));
                    success = true;

                    for (int i = 0; i < MaxRetries; i++)
                    {
                        bool isMalicious = CheckVirusTotalAnalysis(analysisId);
                        if (isMalicious) return true;
                        Thread.Sleep(RetryDelaySeconds * 1000);
                    }
                    return false;
                }
            }
        }
        catch (Exception ex)
        {
            errorMessage = ex.Message;
            Log(string.Format("Upload error for {0}: {1}", filePath, errorMessage));
            return false;
        }
        finally
        {
            if (semaphoreAcquired && success) apiSemaphore.Release();
        }
    }

    private static bool CheckVirusTotalAnalysis(string analysisId)
    {
        bool semaphoreAcquired = false;
        try
        {
            semaphoreAcquired = apiSemaphore.Wait(30000);
            string url = "https://www.virustotal.com/api/v3/analyses/" + analysisId;
            var request = WebRequest.Create(url);
            request.Headers.Add("x-apikey", VirusTotalApiKey);
            using (var response = request.GetResponse())
            {
                using (var stream = response.GetResponseStream())
                using (var reader = new StreamReader(stream))
                {
                    string json = reader.ReadToEnd();
                    JObject result = JObject.Parse(json);
                    if (result["data"]["attributes"]["status"].Value<string>() == "completed")
                    {
                        int malicious = result["data"]["attributes"]["stats"]["malicious"].Value<int>();
                        Log(string.Format("VirusTotal analysis for ID {0}: {1} malicious detections.", analysisId, malicious));
                        return malicious > 3;
                    }
                }
            }
        }
        catch (Exception ex)
        {
            Log(string.Format("Analysis check error for ID {0}: {1}", analysisId, ex.Message));
        }
        finally
        {
            if (semaphoreAcquired) apiSemaphore.Release();
        }
        return false;
    }

    private static bool IsSignedDLL(string filePath)
    {
        try
        {
            var sig = System.Security.Cryptography.X509Certificates.X509Certificate.CreateFromSignedFile(filePath);
            return sig != null;
        }
        catch
        {
            return false;
        }
    }

    private static bool IsWhitelisted(string filePath)
    {
        foreach (var pattern in WhitelistPatterns)
        {
            if (filePath.ToLower().Contains(pattern.ToLower().Replace("*", "")))
                return true;
        }
        return false;
    }

    private static void ShowNotification(string message)
    {
        try
        {
            NotifyIcon notify = new NotifyIcon();
            notify.Icon = System.Drawing.SystemIcons.Warning;
            notify.Visible = true;
            notify.ShowBalloonTip(5000, "Antivirus Alert", message, ToolTipIcon.Warning);
            Thread.Sleep(5000);
            notify.Visible = false;
            notify.Dispose();
        }
        catch (Exception ex)
        {
            Log(string.Format("Notification error: {0}", ex.Message));
        }
    }

    private static void Log(string message)
    {
        string logMessage = string.Format("{0:yyyy-MM-dd HH:mm:ss} - {1}", DateTime.Now, message);
        try
        {
            if (File.Exists(LogPath) && new FileInfo(LogPath).Length > (long)config["MaxLogSizeMB"] * 1024 * 1024)
            {
                string archiveName = string.Format("antivirus_log_{0}.txt", DateTime.Now.ToString("yyyyMMdd_HHmmss"));
                File.Move(LogPath, Path.Combine(Path.GetDirectoryName(LogPath), archiveName));
                Log("Rotated log file to " + archiveName);
            }
            File.AppendAllText(LogPath, logMessage + Environment.NewLine);
        }
        catch { }
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

                        if (IsWhitelisted(exePath))
                        {
                            Log(string.Format("Skipping whitelisted process: {0} (PID: {1})", process.ProcessName, process.Id));
                            continue;
                        }

                        string hash = ComputeSHA256(exePath);
                        if (string.IsNullOrEmpty(hash))
                            continue;

                        bool isMalicious = await ScanFileWithVirusTotal(hash, exePath);
                        if (isMalicious)
                        {
                            string threatName = "VirusTotal_Malicious";
                            Log(string.Format("Malicious process detected: {0} (PID: {1}, Path: {2}, {3})", process.ProcessName, process.Id, exePath, threatName));
                            HandleMalware(exePath, threatName, process);
                            ShowNotification("Malicious process quarantined: " + exePath);
                        }
                        else if (Path.GetExtension(exePath).ToLower() == ".dll" && !IsSignedDLL(exePath))
                        {
                            string threatName = "Unsigned_DLL";
                            Log(string.Format("Unsigned DLL process detected: {0} (PID: {1}, Path: {2})", process.ProcessName, process.Id, exePath));
                            HandleMalware(exePath, threatName, process);
                            ShowNotification("Unsigned DLL process quarantined: " + exePath);
                        }
                        else if (IsSuspiciousProcess(process))
                        {
                            string threatName = "Suspicious_Behavior";
                            Log(string.Format("Suspicious behavior detected in process: {0} (PID: {1})", process.ProcessName, process.Id));
                            HandleMalware(exePath, threatName, process);
                            ShowNotification("Suspicious process quarantined: " + exePath);
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
                            if (IsWhitelisted(path))
                            {
                                Log(string.Format("Skipping whitelisted registry entry: {0} ({1})", valueName, path));
                                continue;
                            }

                            string hash = ComputeSHA256(path);
                            if (string.IsNullOrEmpty(hash))
                                continue;

                            bool isMalicious = await ScanFileWithVirusTotal(hash, path);
                            if (isMalicious)
                            {
                                string threatName = "VirusTotal_Malicious";
                                Log(string.Format("Malicious persistence detected: {0} ({1})", path, threatName));
                                HandleMalware(path, threatName);
                                try
                                {
                                    runKey.Close();
                                    runKey = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", true);
                                    runKey.DeleteValue(valueName);
                                    Log(string.Format("Removed malicious registry entry: {0}", valueName));
                                }
                                catch (Exception ex)
                                {
                                    Log(string.Format("Failed to remove registry entry {0}: {1}", valueName, ex.Message));
                                }
                            }
                            else if (Path.GetExtension(path).ToLower() == ".dll" && !IsSignedDLL(path))
                            {
                                string threatName = "Unsigned_DLL";
                                Log(string.Format("Unsigned DLL in registry: {0} ({1})", path, threatName));
                                HandleMalware(path, threatName);
                                try
                                {
                                    runKey.Close();
                                    runKey = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", true);
                                    runKey.DeleteValue(valueName);
                                    Log(string.Format("Removed unsigned DLL registry entry: {0}", valueName));
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
                Log(string.Format("Failed to terminate process for {0}: {1}", filePath, ex.Message));
            }
        }

        try
        {
            if (!File.Exists(filePath))
            {
                Log(string.Format("File {0} no longer exists.", filePath));
                return;
            }

            try
            {
                using (File.Open(filePath, FileMode.Open, FileAccess.Read, FileShare.None)) { }
            }
            catch
            {
                Log(string.Format("File {0} is locked by another process.", filePath));
                return;
            }

            string backupPath = Path.Combine(BackupPath, string.Format("{0}_{1}", Path.GetFileName(filePath), DateTime.Now.ToString("yyyyMMdd_HHmmss")));
            File.Copy(filePath, backupPath, true);
            Log(string.Format("Backed up file: {0} to {1}", filePath, backupPath));

            string quarantineFile = Path.Combine(QuarantinePath, string.Format("{0}_{1}_{2}", threatName, DateTime.Now.Ticks, Path.GetFileName(filePath)));
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

    private static CirclResult QueryCircl(string filePath)
    {
        bool semaphoreAcquired = false;
        try
        {
            string hash = ComputeSHA256(filePath);
            if (string.IsNullOrEmpty(hash))
                return new CirclResult { Trust = 50, Sources = new List<string>() };

            semaphoreAcquired = apiSemaphore.Wait(30000);
            string url = string.Format("{0}/lookup/sha256/{1}", CirclBaseUrl, hash);
            using (var webClient = new WebClient())
            {
                string json = webClient.DownloadString(new Uri(url));
                var jObject = JObject.Parse(json);
                var trust = jObject["hashlookup:trust"] != null ? jObject["hashlookup:trust"].Value<int>() : 50;
                var sources = jObject["sources"] != null ? jObject["sources"].Values<string>().ToList() : new List<string>();
                return new CirclResult { Trust = trust, Sources = sources };
            }
        }
        catch (Exception ex)
        {
            Log(string.Format("CIRCL API error for {0}: {1}", filePath, ex.Message));
            return new CirclResult { Trust = 50, Sources = new List<string>() };
        }
        finally
        {
            if (semaphoreAcquired) apiSemaphore.Release();
        }
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
