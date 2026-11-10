// H454: real Windows native-service SID, private-state DACL, and original-root
// read-only HANDLE preflight. This is an OS kernel gate, not a model allowlist.
// No credentials are decrypted, no original project file contents are read,
// no files are created, no process or network is started from this module.
// Future runtime must ALSO require owner-paired BRC+DPAPI and revocation.
using Microsoft.Win32.SafeHandles;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;

namespace HermesCommander.NativeService;

internal static class NativeHostAdmission
{
    internal const string ExpectedAccount = @"NT SERVICE\HermesCommanderNative";
    private static readonly string[] Roots =
    [
        @"D:\Pet-projects\hermes",
        @"D:\Pet-projects\your-fitness-coach",
        @"D:\Pet-projects\ai-development-toolkit",
        @"D:\Pet-projects\financial-horizon",
        @"D:\Pet-projects\second-brain-workspace\second-brain",
    ];
    private const uint FILE_READ_ATTRIBUTES = 0x00000080;
    private const uint FILE_ADD_FILE = 0x00000002;
    private const uint SHARE_READ_WRITE_DELETE = 0x00000007;
    private const uint OPEN_EXISTING = 3;
    private const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
    private const uint FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000;
    private const uint FLAGS = FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT;

    [DllImport("kernel32.dll", EntryPoint = "CreateFileW",
        CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle OpenRoot(
        string path, uint desiredAccess, uint shareMode, IntPtr sec,
        uint creation, uint flags, IntPtr template);

    private static SecurityIdentifier ExpectedSid()
    {
        return (SecurityIdentifier)new NTAccount(ExpectedAccount)
            .Translate(typeof(SecurityIdentifier));
    }

    internal static bool MatchesServiceUser()
    {
        try
        {
            if (!OperatingSystem.IsWindows()) return false;
            using WindowsIdentity user = WindowsIdentity.GetCurrent();
            SecurityIdentifier expected = ExpectedSid();
            return user.User is not null && user.User.Equals(expected)
                && !user.IsSystem && !user.IsGuest && !user.IsAnonymous;
        }
        catch { return false; }
    }

    private static bool RestrictedDacl(FileSystemSecurity sec)
    {
        try
        {
            if (!sec.AreAccessRulesProtected) return false;
            string service = ExpectedSid().Value;
            string system = new SecurityIdentifier(
                WellKnownSidType.LocalSystemSid, null).Value;
            string admins = new SecurityIdentifier(
                WellKnownSidType.BuiltinAdministratorsSid, null).Value;
            string owner = ((SecurityIdentifier)sec.GetOwner(
                typeof(SecurityIdentifier))).Value;
            if (owner != system && owner != admins) return false;
            bool serviceRead = false;
            foreach (FileSystemAccessRule rule in sec.GetAccessRules(
                true, true, typeof(SecurityIdentifier)))
            {
                string id = ((SecurityIdentifier)rule.IdentityReference).Value;
                if (rule.IsInherited || rule.AccessControlType != AccessControlType.Allow
                    || (id != system && id != admins && id != service))
                    return false;
                if (id == service &&
                    (rule.FileSystemRights & FileSystemRights.ReadData) != 0)
                    serviceRead = true;
            }
            return serviceRead;
        }
        catch { return false; }
    }

    private static bool IsOrdinaryFile(FileInfo file)
    {
        try
        {
            file.Refresh();
            if (!file.Exists ||
                (file.Attributes & FileAttributes.ReparsePoint) != 0 ||
                !file.Directory!.Exists || file.Length < 1 || file.Length > 8192)
                return false;
            FileSecurity sec = FileSystemAclExtensions.GetAccessControl(
                file, AccessControlSections.Access | AccessControlSections.Owner);
            return RestrictedDacl(sec);
        }
        catch { return false; }
    }

    internal static bool PrivateStateIsConfined()
    {
        try
        {
            if (!MatchesServiceUser()) return false;
            string programData = Environment.GetFolderPath(
                Environment.SpecialFolder.CommonApplicationData);
            if (string.IsNullOrWhiteSpace(programData)) return false;
            DirectoryInfo state = new(Path.Combine(programData, "HermesCommanderNative"));
            state.Refresh();
            if (!state.Exists || (state.Attributes & FileAttributes.ReparsePoint) != 0)
                return false;
            DirectorySecurity sec = FileSystemAclExtensions.GetAccessControl(
                state, AccessControlSections.Access | AccessControlSections.Owner);
            if (!RestrictedDacl(sec)) return false;
            return IsOrdinaryFile(new FileInfo(Path.Combine(state.FullName, "manifest.json")))
                && IsOrdinaryFile(new FileInfo(Path.Combine(state.FullName, "device.json")));
        }
        catch { return false; }
    }

    private static bool ReadWithoutWrite(string root)
    {
        try
        {
            DirectoryInfo directory = new(root);
            directory.Refresh();
            if (!directory.Exists || (directory.Attributes & FileAttributes.ReparsePoint) != 0)
                return false;
            using SafeFileHandle read = OpenRoot(root, FILE_READ_ATTRIBUTES,
                SHARE_READ_WRITE_DELETE, IntPtr.Zero, OPEN_EXISTING, FLAGS, IntPtr.Zero);
            if (read.IsInvalid) return false;
            // Merely request FILE_ADD_FILE on the existing directory handle;
            // never create, write or read project content.
            using SafeFileHandle forbiddenWrite = OpenRoot(root, FILE_ADD_FILE,
                SHARE_READ_WRITE_DELETE, IntPtr.Zero, OPEN_EXISTING, FLAGS, IntPtr.Zero);
            return forbiddenWrite.IsInvalid;
        }
        catch { return false; }
    }

    internal static bool OriginalRootsAreKernelReadOnly()
    {
        return MatchesServiceUser() && Roots.All(ReadWithoutWrite);
    }
}
