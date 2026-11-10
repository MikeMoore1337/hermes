// CI-only Windows screenshot harness. NEVER included in the preview binary.
// This executable is built and run only on a disposable GitHub Windows runner.
// It cannot enroll devices, install services or touch original project roots.
using System;
using System.Drawing;
using System.Drawing.Imaging;
using System.IO;
using System.Windows.Forms;

namespace HermesCommander.NativePreview;

internal static class CiScreenshot
{
    [STAThread]
    private static int Main(string[] args)
    {
        if (args.Length != 2 || Program.SelfTest(args[0]) != 0)
            return 2;

        // The CI-only tool must write exactly one new PNG below the runner's
        // private temp directory, never to a caller-selected project path.
        string? runnerTemp = Environment.GetEnvironmentVariable("RUNNER_TEMP");
        if (string.IsNullOrWhiteSpace(runnerTemp) ||
            !Path.IsPathFullyQualified(runnerTemp))
            return 2;
        string expected = Path.Combine(Path.GetFullPath(runnerTemp),
            "h454-native-win32-preview.png");
        if (!Path.GetFullPath(args[1]).Equals(expected,
                StringComparison.OrdinalIgnoreCase))
            return 2;

        ApplicationConfiguration.Initialize();
        using var form = new Program.ScopePreviewForm(args[0])
        {
            ShowInTaskbar = false
        };
        form.Show();
        Application.DoEvents();
        form.Refresh();

        using var bitmap = new Bitmap(form.Width, form.Height);
        form.DrawToBitmap(bitmap,
            new Rectangle(0, 0, bitmap.Width, bitmap.Height));
        // CreateNew never overwrites an existing file in the runner temp.
        using (var file = new FileStream(expected, FileMode.CreateNew,
                   FileAccess.Write, FileShare.None))
            bitmap.Save(file, ImageFormat.Png);
        form.Close();
        return 0;
    }
}
