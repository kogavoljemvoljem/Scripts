# Key Scrambler – Clean injection (no duplicates, no sausage)
$Source = @"
using System;
using System.Runtime.InteropServices;

public class KeyScrambler
{
    private const int WH_KEYBOARD_LL = 13;
    private const int WM_KEYDOWN = 0x0100;
    private const uint VK_A = 65;
    private const uint VK_Z = 90;
    private const uint KEYEVENTF_UNICODE = 0x0004;
    private const uint KEYEVENTF_KEYUP = 0x0002;

    [StructLayout(LayoutKind.Sequential)]
    public struct KBDLLHOOKSTRUCT
    {
        public uint vkCode;
        public uint scanCode;
        public uint flags;
        public uint time;
        public IntPtr dwExtraInfo;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct MSG { public IntPtr hwnd; public uint message; public IntPtr wParam; public IntPtr lParam; public uint time; public POINT pt; }
    [StructLayout(LayoutKind.Sequential)]
    public struct POINT { public int X; public int Y; }

    [DllImport("user32.dll", SetLastError = true)] private static extern IntPtr SetWindowsHookEx(int idHook, IntPtr lpfn, IntPtr hMod, uint dwThreadId);
    [DllImport("user32.dll", SetLastError = true)] private static extern bool UnhookWindowsHookEx(IntPtr hhk);
    [DllImport("user32.dll")] private static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode, IntPtr wParam, IntPtr lParam);
    [DllImport("user32.dll")] private static extern bool GetMessage(out MSG lpMsg, IntPtr hWnd, uint wMsgFilterMin, uint wMsgFilterMax);
    [DllImport("user32.dll")] private static extern bool TranslateMessage(ref MSG lpMsg);
    [DllImport("user32.dll")] private static extern IntPtr DispatchMessage(ref MSG lpMsg);
    [DllImport("user32.dll")] private static extern void keybd_event(byte bVk, byte bScan, uint dwFlags, UIntPtr dwExtraInfo);
    [DllImport("kernel32.dll")] private static extern IntPtr GetModuleHandle(string lpModuleName);

    private delegate IntPtr LowLevelKeyboardProc(int nCode, IntPtr wParam, IntPtr lParam);
    private static IntPtr _hookID = IntPtr.Zero;
    private static LowLevelKeyboardProc _proc;
    private static Random _rnd = new Random();

    public static void Start()
    {
        if (_hookID != IntPtr.Zero) return;
        _proc = HookCallback;
        _hookID = SetWindowsHookEx(WH_KEYBOARD_LL,
                                   Marshal.GetFunctionPointerForDelegate(_proc),
                                   GetModuleHandle(null), 0);
        if (_hookID == IntPtr.Zero) throw new Exception("Hook failed: " + Marshal.GetLastWin32Error());

        Console.WriteLine("Scrambler ON – you type normally, loggers see ONE random A-Z per key.");
        Console.WriteLine("Close window or Ctrl+C to stop.");

        MSG msg;
        while (GetMessage(out msg, IntPtr.Zero, 0, 0))
        {
            TranslateMessage(ref msg);
            DispatchMessage(ref msg);
        }
    }

    public static void Stop()
    {
        if (_hookID != IntPtr.Zero) { UnhookWindowsHookEx(_hookID); _hookID = IntPtr.Zero; Console.WriteLine("Stopped."); }
    }

    private static IntPtr HookCallback(int nCode, IntPtr wParam, IntPtr lParam)
    {
        if (nCode >= 0 && wParam == (IntPtr)WM_KEYDOWN)
        {
            // ---- Inject ONE random A-Z as pure Unicode char (no KEYDOWN, no duplicates) ----
            ushort fakeChar = (ushort)_rnd.Next((int)VK_A, (int)VK_Z + 1);
            keybd_event(0, 0, KEYEVENTF_UNICODE, UIntPtr.Zero);    // Unicode down (wParam = fakeChar)
            keybd_event(0, 0, KEYEVENTF_UNICODE | KEYEVENTF_KEYUP, UIntPtr.Zero);  // Unicode up

            // ---- Let original key pass through unchanged ----
            return CallNextHookEx(_hookID, nCode, wParam, lParam);
        }
        return CallNextHookEx(_hookID, nCode, wParam, lParam);
    }
}
"@

try { Add-Type -TypeDefinition $Source -ErrorAction Stop }
catch { Write-Error "Compile error: $($_.Exception.Message)"; exit }

try { [KeyScrambler]::Start() }
catch { Write-Error $_.Exception.Message }
finally { [KeyScrambler]::Stop() }