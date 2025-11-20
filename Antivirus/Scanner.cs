using System;
using System.Diagnostics;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Windows.Forms;
using Newtonsoft.Json.Linq;

namespace GorstakCleanAV   // ← SAME namespace as Program.cs
{
    public class Scanner
    {
        public readonly string QuarantinePath = @"C:\Quarantine";
        public readonly string BackupPath = @"C:\ProgramData\GorstakAV\Backup";
        private readonly string LastMarker = @"C:\Quarantine\.last";

        private readonly WebClient web = new WebClient();
        private readonly List<FileSystemWatcher> watchers = new List<FileSystemWatcher>();
        private readonly SemaphoreSlim semaphore = new SemaphoreSlim(4, 4);
        private readonly string vtKey = ""; // ← your VT key here (or leave empty)

        private string lastOriginal, lastBackup, lastQuarantined;

        public void Start()
        {
            Directory.CreateDirectory(QuarantinePath);
            Directory.CreateDirectory(BackupPath);

            foreach (DriveInfo d in DriveInfo.GetDrives())
            {
                if (d.DriveType != DriveType.Fixed || !d.IsReady) continue;

                FileSystemWatcher w = new FileSystemWatcher(d.RootDirectory.FullName, "*.*");
                w.IncludeSubdirectories = true;
                w.NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite;
                w.Created += OnFile;
                w.Changed += OnFile;
                w.EnableRaisingEvents = true;
                watchers.Add(w);
            }

            Log("Gorstak Clean AV started – real-time protection (user approval mode)");
            Program.Tray.ShowBalloonTip(3000, "Gorstak Clean AV", "Protection active", ToolTipIcon.Info);
        }

        public void Stop()
        {
            foreach (var w in watchers) w.Dispose();
            Log("Stopped");
        }

        private void OnFile(object s, FileSystemEventArgs e)
        {
            if (!e.FullPath.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) &&
                !e.FullPath.EndsWith(".dll", StringComparison.OrdinalIgnoreCase))
                return;

            Thread.Sleep(1500);
            if (!File.Exists(e.FullPath)) return;

            ThreadPool.QueueUserWorkItem(state => ProcessFile(e.FullPath));
        }

        private void ProcessFile(string path)
        {
            try
            {
                FileInfo fi = new FileInfo(path);
                if (fi.Length > 64 * 1024 * 1024) return;

                string hash = ComputeSHA256(path);
                bool signed = IsSigned(path);

                int vt = 0;
                if (!string.IsNullOrEmpty(vtKey))
                    vt = QueryVT(hash);

                int circl = vt == 0 ? QueryCIRCL(hash) : 100;

                string verdict = signed ? "Signed" : "Unsigned";
                if (vt > 3) verdict = "VT flagged (" + vt + "+)";
                else if (circl < 40) verdict = "CIRCL low trust";

                if (vt <= 3 && circl >= 40 && signed) return;

                DialogResult dr = MessageBox.Show(
                    "Suspicious file detected!\n\n" +
                    path + "\n\n" +
                    "Signed: " + (signed ? "Yes" : "NO") + "\n" +
                    verdict + "\n" +
                    "SHA256: " + hash + "\n\n" +
                    "Quarantine it?",
                    "Gorstak Clean AV", MessageBoxButtons.YesNoCancel, MessageBoxIcon.Warning);

                if (dr == DialogResult.Yes)
                    Quarantine(path);
                else if (dr == DialogResult.No)
                    Log("User allowed: " + Path.GetFileName(path));
            }
            catch (Exception ex) { Log("Error: " + ex.Message); }
        }

        private void Quarantine(string original)
        {
            try
            {
                string name = Path.GetFileName(original);
                string backup = Path.Combine(BackupPath, name + "_" + DateTime.Now.ToString("yyyyMMdd_HHmmss") + "_bak");
                string dest   = Path.Combine(QuarantinePath, name + "_" + DateTime.Now.ToString("yyyyMMdd_HHmmss"));

                File.Copy(original, backup, true);
                if (File.Exists(dest)) File.Delete(dest);
                File.Move(original, dest);

                lastOriginal = original; lastBackup = backup; lastQuarantined = dest;
                File.WriteAllText(LastMarker, backup + "|" + dest);

                Log("QUARANTINED -> " + dest);
                Program.Tray.ShowBalloonTip(4000, "Quarantined", name, ToolTipIcon.Warning);
            }
            catch (Exception ex) { Log("Quarantine failed: " + ex.Message); }
        }

        public void UndoLastQuarantine()
        {
            if (!File.Exists(LastMarker)) return;

            try
            {
                string[] p = File.ReadAllText(LastMarker).Split('|');
                string quarantined = p[1];
                string original = lastOriginal ?? Path.Combine(Path.GetDirectoryName(quarantined), Path.GetFileName(quarantined));

                if (File.Exists(original)) File.Delete(original);
                File.Move(quarantined, original);
                File.Delete(LastMarker);

                Log("UNDO -> restored " + Path.GetFileName(original));
                Program.Tray.ShowBalloonTip(3000, "Undo", "File restored", ToolTipIcon.Info);
            }
            catch (Exception ex) { MessageBox.Show("Undo failed: " + ex.Message); }
        }

        private string ComputeSHA256(string path)
        {
            using (SHA256 sha = SHA256.Create())
            using (FileStream s = File.OpenRead(path))
            {
                byte[] h = sha.ComputeHash(s);
                StringBuilder sb = new StringBuilder();
                foreach (byte b in h) sb.Append(b.ToString("x2"));
                return sb.ToString();
            }
        }

        private bool IsSigned(string path)
        {
            try
            {
                X509Certificate.CreateFromSignedFile(path);
                return true;
            }
            catch { return false; }
        }

        private int QueryVT(string hash)
        {
            if (string.IsNullOrEmpty(vtKey)) return 0;
            semaphore.Wait();
            try
            {
                web.Headers.Clear();
                web.Headers.Add("x-apikey", vtKey);
                string json = web.DownloadString("https://www.virustotal.com/api/v3/files/" + hash);
                JObject o = JObject.Parse(json);
                return (int)(o["data"]["attributes"]["last_analysis_stats"]["malicious"] ?? 0);
            }
            catch { return 0; }
            finally { semaphore.Release(); }
        }

        private int QueryCIRCL(string hash)
        {
            try
            {
                string json = web.DownloadString("https://hashlookup.circl.lu/lookup/sha256/" + hash);
                JObject o = JObject.Parse(json);
                return (int)(o["hashlookup:trust"] ?? 100);
            }
            catch { return 100; }
        }

	public void ShowLog()
        {
            string log = Path.Combine(BackupPath, "GorstakAV_Log.txt");
            if (File.Exists(log))
                Process.Start("notepad.exe", log);   // now compiles!
            else
                MessageBox.Show("No log yet.");
        }

        public static void Log(string msg)
        {
            string line = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + " | " + msg + "\r\n";
            string file = Path.Combine(@"C:\ProgramData\GorstakAV\Backup", "GorstakAV_Log.txt");
            Directory.CreateDirectory(Path.GetDirectoryName(file));
            File.AppendAllText(file, line);
        }
    }
}