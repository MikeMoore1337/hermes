// Hermes #454 Stage 2A: offline Windows installation-scope PREVIEW ONLY.
// This deliberately contains NO installer, service controller, filesystem
// access, network client, token enrollment, UAC request, shell, or host effect.
// The unsigned build must never be presented as an installable native agent.
using System.Drawing;
using System.Reflection;
using System.Text.RegularExpressions;
using System.Windows.Forms;

namespace HermesCommander.NativePreview;

internal static class Program
{
    internal const string ServiceKey = "HermesCommanderNative";
    internal const string ServiceIdentity = @"NT SERVICE\HermesCommanderNative";
    internal const string InitialState = "DISABLED";
    internal const string AccessMode = "READ_ONLY";
    internal const string SignatureStatus = "NOT_SIGNED";
    internal const bool CanInstall = false;

    internal static readonly (string Project, string Root)[] ApprovedReadRoots =
    [
        ("Hermes", @"D:\Pet-projects\hermes"),
        ("Your Fitness Coach", @"D:\Pet-projects\your-fitness-coach"),
        ("AI Development Toolkit", @"D:\Pet-projects\ai-development-toolkit"),
        ("Financial Horizon", @"D:\Pet-projects\financial-horizon"),
        ("Second Brain (code only)", @"D:\Pet-projects\second-brain-workspace\second-brain"),
    ];

    private static string Revision()
    {
        string version = Assembly.GetExecutingAssembly()
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?
            .InformationalVersion ?? "";
        Match pinned = Regex.Match(version, @"\+([0-9a-f]{40})\z",
            RegexOptions.CultureInvariant);
        return pinned.Success ? pinned.Groups[1].Value : "NOT_PINNED";
    }

    private static int SelfTest(string expectedSourceSha)
    {
        // A smoke contract, not an OS isolation or graphical acceptance test.
        string sha = Revision();
        if (!Regex.IsMatch(expectedSourceSha, @"\A[0-9a-f]{40}\z", RegexOptions.CultureInvariant) ||
            sha != expectedSourceSha || CanInstall ||
            ServiceKey != "HermesCommanderNative" ||
            ServiceIdentity != @"NT SERVICE\HermesCommanderNative" ||
            InitialState != "DISABLED" || AccessMode != "READ_ONLY" ||
            SignatureStatus != "NOT_SIGNED" ||
            ApprovedReadRoots.Length != 5)
            return 1;
        var distinct = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var item in ApprovedReadRoots)
        {
            if (!distinct.Add(item.Root) ||
                !item.Root.StartsWith(@"D:\Pet-projects\", StringComparison.OrdinalIgnoreCase) ||
                item.Root.Contains("..", StringComparison.Ordinal) ||
                item.Root.Contains("vault", StringComparison.OrdinalIgnoreCase))
                return 1;
        }
        if (!ApprovedReadRoots.Any(x => x.Root.Equals(
            @"D:\Pet-projects\financial-horizon", StringComparison.Ordinal)))
            return 1;
        return 0;
    }

    [STAThread]
    private static int Main(string[] args)
    {
        if (args.Length == 2 && args[0] == "--self-test")
            return SelfTest(args[1]);
        if (args.Length != 0 || Revision() == "NOT_PINNED")
            return 2;

        ApplicationConfiguration.Initialize();
        Application.Run(new ScopePreviewForm(Revision()));
        return 0;
    }

    private sealed class ScopePreviewForm : Form
    {
        internal ScopePreviewForm(string sourceSha)
        {
            Text = "Hermes Commander Native - предварительный просмотр";
            StartPosition = FormStartPosition.CenterScreen;
            Size = new Size(800, 590);
            MinimumSize = new Size(720, 510);
            Font = new Font("Segoe UI", 10);
            FormBorderStyle = FormBorderStyle.Sizable;
            AutoScaleMode = AutoScaleMode.Dpi;

            var layout = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                AutoScroll = true,
                Padding = new Padding(24),
                ColumnCount = 1,
                RowCount = 5,
            };
            layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 64));
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 80));
            layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 82));
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 55));

            layout.Controls.Add(new Label
            {
                Text = "Только просмотр - установка недоступна",
                Font = new Font("Segoe UI", 16, FontStyle.Bold),
                Dock = DockStyle.Fill,
                TextAlign = ContentAlignment.MiddleLeft,
                AutoSize = false,
            }, 0, 0);

            layout.Controls.Add(new Label
            {
                Text = "Это НЕ установщик. Подпись издателя отсутствует. " +
                       "Служба, ключи, разрешения NTFS и соединения не создаются.",
                Dock = DockStyle.Fill,
                TextAlign = ContentAlignment.MiddleLeft,
                ForeColor = Color.Firebrick,
                AutoSize = false,
            }, 0, 1);

            string roots = string.Join(Environment.NewLine,
                ApprovedReadRoots.Select(x => x.Project + ": " + x.Root));
            layout.Controls.Add(new TextBox
            {
                Text = "Служба: " + ServiceKey + Environment.NewLine +
                       "Учётная запись: " + ServiceIdentity + Environment.NewLine +
                       "Начальное состояние: " + InitialState + Environment.NewLine +
                       "Права: " + AccessMode + Environment.NewLine +
                       "Исходный коммит: " + sourceSha + Environment.NewLine +
                       "Подпись: " + SignatureStatus + Environment.NewLine +
                       Environment.NewLine +
                       "Пять утверждённых корней только для чтения:" +
                       Environment.NewLine + roots,
                Multiline = true,
                ReadOnly = true,
                ScrollBars = ScrollBars.Vertical,
                Dock = DockStyle.Fill,
                WordWrap = false,
                TabStop = false,
            }, 0, 2);

            layout.Controls.Add(new Label
            {
                Text = "Для запуска потребуется отдельное разрешение на " +
                       "конкретный установочный файл, права ОС и сопряжение " +
                       "с существующим Hermes MCP. Доступ к private vault запрещён.",
                Dock = DockStyle.Fill,
                TextAlign = ContentAlignment.MiddleLeft,
                AutoSize = false,
            }, 0, 3);

            var close = new Button
            {
                Text = "Закрыть",
                Width = 120,
                Height = 36,
                Anchor = AnchorStyles.Right,
            };
            close.Click += (_, _) => Close();
            layout.Controls.Add(close, 0, 4);
            Controls.Add(layout);
            AcceptButton = close;
        }
    }
}
