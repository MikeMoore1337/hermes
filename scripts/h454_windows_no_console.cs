using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

internal static class H454NoConsole
{
    [DllImport("kernel32.dll")]
    private static extern IntPtr GetConsoleWindow();

    private static int Main(string[] args)
    {
        try
        {
            if (GetConsoleWindow() != IntPtr.Zero || args.Length != 1 || args[0].Length > 16000)
                return 2;
            byte[] bytes = Convert.FromBase64String(args[0]);
            string arguments = new UTF8Encoding(false, true).GetString(bytes);
            if (arguments.Length > 10000)
                return 2;
            foreach (char c in arguments)
                if (char.IsControl(c)) return 2;
            string guard = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "h454_windows_guard_operator.ps1");
            string prefix = "-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File \"" + guard + "\" ";
            if (!arguments.StartsWith(prefix, StringComparison.Ordinal) ||
                !arguments.EndsWith(" -RestoreOriginal -AutoRecover -Apply -OwnerApproved", StringComparison.Ordinal))
                return 2;
            string powershell = Path.Combine(Environment.SystemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe");
            var start = new ProcessStartInfo(powershell, arguments);
            start.UseShellExecute = false;
            start.CreateNoWindow = true;
            using (Process child = Process.Start(start))
            {
                if (child == null) return 2;
                child.WaitForExit();
                return child.ExitCode;
            }
        }
        catch { return 2; }
    }
}
