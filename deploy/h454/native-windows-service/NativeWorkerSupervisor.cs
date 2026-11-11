// H454 Stage 2A: a tightly pinned Windows native READ worker subprocess.
// This runs only AFTER the SCM process token, owner-project kernel READ-only
// probes and protected ProgramData ACLs are validated by NativeHostAdmission.
// Exactly one trusted signed-release receipt pins both installed binaries;
// a matching file hash is *not* a substitute for the original signing audit.
// No arbitrary executable/path/credential/URL/command may be supplied by MCP.
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace HermesCommander.NativeService;

internal static class NativeWorkerSupervisor
{
    internal const string Worker = "HermesCommanderNativeWorker.exe";
    internal const string SignedReceipt = "signed-release.json";
    internal const string Ready = "H454_NATIVE_BRC_SESSION_READY=YES";
    private const int MaxReceiptBytes = 4096;
    private const long MaxWorkerBytes = 180L * 1024L * 1024L;
    private static readonly Regex Sha40 = new("^[0-9a-f]{40}$",
        RegexOptions.CultureInvariant);
    private static readonly Regex Sha64 = new("^[0-9a-f]{64}$",
        RegexOptions.CultureInvariant);
    private static readonly Regex Thumbprint = new("^[0-9A-Fa-f]{40}$",
        RegexOptions.CultureInvariant);

    internal static bool ReceiptMatches(
        byte[] data, string revision,
        string serviceHash, string workerHash)
    {
        try
        {
            if (data.Length is < 1 or > MaxReceiptBytes ||
                !Sha40.IsMatch(revision) || !Sha64.IsMatch(serviceHash) ||
                !Sha64.IsMatch(workerHash))
                return false;
            using JsonDocument json = JsonDocument.Parse(data);
            JsonElement root = json.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
                return false;
            HashSet<string> keys = new(StringComparer.Ordinal);
            foreach (JsonProperty item in root.EnumerateObject())
                if (!keys.Add(item.Name)) return false;
            if (!keys.SetEquals([
                "schema", "source_sha", "msi_sha256", "exe_sha256",
                "worker_sha256", "signer_thumbprint", "msi_valid",
                "exe_valid", "worker_valid", "installed_on_owner_host",
            ])) return false;
            return root.GetProperty("schema").GetString() ==
                       "h454-signed-msi-receipt-v1"
                && root.GetProperty("source_sha").GetString() == revision
                && root.GetProperty("exe_sha256").GetString() == serviceHash
                && root.GetProperty("worker_sha256").GetString() == workerHash
                && Sha64.IsMatch(root.GetProperty("msi_sha256").GetString() ?? "")
                && Thumbprint.IsMatch(
                    root.GetProperty("signer_thumbprint").GetString() ?? "")
                && root.GetProperty("msi_valid").GetBoolean()
                && root.GetProperty("exe_valid").GetBoolean()
                && root.GetProperty("worker_valid").GetBoolean()
                && !root.GetProperty("installed_on_owner_host").GetBoolean();
        }
        catch { return false; }
    }

    private static string HashPinnedFile(string fullPath)
    {
        // FileShare.Read prevents another writer from mutating the file
        // during hash computation; Program Files OS ACL prevents replacement
        // between verification and CreateProcess in normal unprivileged use.
        using FileStream input = new(fullPath, FileMode.Open, FileAccess.Read,
            FileShare.Read);
        return Convert.ToHexString(SHA256.HashData(input)).ToLowerInvariant();
    }

    internal static Process? TryLaunch(string revision)
    {
        Process? child = null;
        try
        {
            if (!OperatingSystem.IsWindows() ||
                !NativeHostAdmission.MatchesServiceUser() ||
                !NativeHostAdmission.PrivateStateIsConfined() ||
                !NativeHostAdmission.PrivateWorkerTempIsConfined() ||
                !NativeHostAdmission.OriginalRootsAreKernelReadOnly() ||
                !Sha40.IsMatch(revision))
                return null;

            // No caller-supplied path is accepted, even via environment vars.
            string dir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                "Hermes Commander Native");
            string servicePath = Path.Combine(dir, "HermesCommanderNativeService.exe");
            string workerPath = Path.Combine(dir, Worker);
            if (!string.Equals(Path.GetFullPath(servicePath),
                Path.GetFullPath(Environment.ProcessPath ?? ""),
                StringComparison.OrdinalIgnoreCase))
                return null;
            DirectoryInfo installDir = new(dir);
            FileInfo binary = new(workerPath);
            FileInfo ownBinary = new(servicePath);
            installDir.Refresh(); binary.Refresh(); ownBinary.Refresh();
            if (!installDir.Exists ||
                (installDir.Attributes & FileAttributes.ReparsePoint) != 0 ||
                !binary.Exists || !ownBinary.Exists ||
                (binary.Attributes & FileAttributes.ReparsePoint) != 0 ||
                (ownBinary.Attributes & FileAttributes.ReparsePoint) != 0 ||
                binary.Length is < 1 or > MaxWorkerBytes ||
                !NativeHostAdmission.InstallBinaryIsReadOnly(workerPath))
                return null;

            string state = Path.Combine(Environment.GetFolderPath(
                Environment.SpecialFolder.CommonApplicationData),
                "HermesCommanderNative", SignedReceipt);
            FileInfo receipt = new(state);
            if (!NativeHostAdmission.ProtectedStateFile(receipt))
                return null;
            byte[] bytes = File.ReadAllBytes(state);
            if (!ReceiptMatches(bytes, revision,
                HashPinnedFile(servicePath), HashPinnedFile(workerPath)))
                return null;

            ProcessStartInfo settings = new(workerPath)
            {
                UseShellExecute = false,
                WorkingDirectory = dir,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            };
            settings.ArgumentList.Add("--run-once");
            settings.ArgumentList.Add("--service-supervised");
            settings.ArgumentList.Add("--release-sha");
            settings.ArgumentList.Add(revision);
            // Explicit minimal environment, no inherited PYTHONPATH, token,
            // proxy override or user-selected library search path.
            settings.Environment.Clear();
            string root = Environment.GetEnvironmentVariable("SystemRoot") ?? "";
            if (string.IsNullOrEmpty(root) || !Path.IsPathFullyQualified(root))
                return null;
            settings.Environment["SystemRoot"] = root;
            settings.Environment["WINDIR"] = root;
            // PyInstaller must unpack ONLY under this owner-provisioned
            // service-specific directory with protected NTFS ACL; NEVER
            // fall back to shared %WINDIR%\Temp or the interactive user.
            string privateTemp = Path.Combine(Environment.GetFolderPath(
                Environment.SpecialFolder.CommonApplicationData),
                "HermesCommanderNative", "Temp");
            settings.Environment["TEMP"] = privateTemp;
            settings.Environment["TMP"] = privateTemp;
            settings.Environment["PYTHONNOUSERSITE"] = "1";
            settings.Environment["PYTHONDONTWRITEBYTECODE"] = "1";

            child = Process.Start(settings);
            if (child is not null)
                child.BeginErrorReadLine(); // discard private error messages
            return child;
        }
        catch
        {
            StopWorker(child);
            child?.Dispose();
            return null;
        }
    }

    internal static bool WaitForAuthenticatedWelcome(
        Process child, ManualResetEventSlim stop, TimeSpan budget)
    {
        try
        {
            if (!child.StartInfo.RedirectStandardOutput ||
                budget <= TimeSpan.Zero || budget > TimeSpan.FromSeconds(25))
                return false;
            Task<string?> output = child.StandardOutput.ReadLineAsync();
            DateTime end = DateTime.UtcNow + budget;
            while (!output.IsCompleted)
            {
                if (stop.IsSet || child.HasExited ||
                    DateTime.UtcNow >= end)
                    return false;
                stop.Wait(100);
            }
            return !stop.IsSet && !child.HasExited && output.IsCompletedSuccessfully
                && string.Equals(output.Result, Ready, StringComparison.Ordinal);
        }
        catch { return false; }
    }

    internal static void StopWorker(Process? child)
    {
        if (child is null) return;
        try
        {
            if (!child.HasExited)
                child.Kill(entireProcessTree: true);
            child.WaitForExit(5000);
        }
        catch { /* The SCM still reports a stopped service on failures. */ }
    }
}
