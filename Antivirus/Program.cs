using System;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Windows.Forms;

namespace GorstakCleanAV
{
    static class Program
    {
        public static NotifyIcon Tray;
        public static Scanner Scanner = new Scanner();

        [STAThread]
        static void Main()
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);

            if (Process.GetProcessesByName("Antivirus").Length > 1)
                return;

            Tray = new NotifyIcon();
            Tray.Icon = new Icon("Autorun.ico");
            Tray.Text = "Gorstak Clean AV";
            Tray.Visible = true;
            Tray.ContextMenuStrip = BuildMenu();
            Tray.DoubleClick += (s, e) => Scanner.ShowLog();

            Scanner.Start();

            Application.Run();
        }

        private static ContextMenuStrip BuildMenu()
        {
            ContextMenuStrip menu = new ContextMenuStrip();
            menu.Items.Add("Show Log", null, (s, e) => Scanner.ShowLog());
            menu.Items.Add("Open Quarantine", null, (s, e) => Process.Start("explorer.exe", Scanner.QuarantinePath));
            menu.Items.Add("Undo Last Quarantine", null, (s, e) => Scanner.UndoLastQuarantine());
            menu.Items.Add(new ToolStripSeparator());
            menu.Items.Add("Exit", null, (s, e) =>
            {
                Tray.Visible = false;
                Scanner.Stop();
                Application.Exit();
            });
            return menu;
        }
    }
}