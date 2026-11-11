// H454: real Windows ACL API tests on disposable GitHub-hosted Windows.
// The test uses only an IN-MEMORY DirectorySecurity descriptor, never
// touches owner PC, filesystem ACLs, service accounts or production data.
using System;
using System.Security.AccessControl;
using System.Security.Principal;
using HermesCommander.NativeService;

internal static class NativeAclFixture
{
    private static DirectorySecurity SafeAcl(SecurityIdentifier service)
    {
        var acl = new DirectorySecurity();
        acl.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        acl.SetOwner(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null));
        acl.AddAccessRule(new FileSystemAccessRule(
            service, FileSystemRights.Read, AccessControlType.Allow));
        acl.AddAccessRule(new FileSystemAccessRule(
            new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
            FileSystemRights.FullControl, AccessControlType.Allow));
        return acl;
    }

    private static void Require(bool value, string code)
    {
        if (!value) throw new InvalidOperationException("H454_ACL_FIXTURE_" + code);
    }

    public static int Main()
    {
        if (!OperatingSystem.IsWindows()) return 2;
        try
        {
            using var user = WindowsIdentity.GetCurrent();
            SecurityIdentifier sid = user.User ??
                throw new InvalidOperationException("NO_TEST_SID");
            DirectorySecurity baseline = SafeAcl(sid);
            Require(NativeHostAdmission.RestrictedDaclForIdentity(
                baseline, sid), "SAFE_READ_REFUSED");
            foreach (FileSystemRights unsafeRight in new[]
            {
                FileSystemRights.FullControl,
                FileSystemRights.Modify,
                FileSystemRights.Write,
                FileSystemRights.WriteData,
                FileSystemRights.CreateDirectories,
                FileSystemRights.WriteAttributes,
                FileSystemRights.ChangePermissions,
                FileSystemRights.TakeOwnership,
                FileSystemRights.ExecuteFile,
                FileSystemRights.Delete,
            })
            {
                DirectorySecurity acl = SafeAcl(sid);
                acl.AddAccessRule(new FileSystemAccessRule(
                    sid, unsafeRight, AccessControlType.Allow));
                Require(!NativeHostAdmission.RestrictedDaclForIdentity(
                    acl, sid), "SERVICE_WRITE_ALLOWED_" + unsafeRight);
            }
            var otherUser = SafeAcl(sid);
            otherUser.AddAccessRule(new FileSystemAccessRule(
                new SecurityIdentifier(WellKnownSidType.WorldSid, null),
                FileSystemRights.Read, AccessControlType.Allow));
            Require(!NativeHostAdmission.RestrictedDaclForIdentity(
                otherUser, sid), "WORLD_READ_ALLOWED");
            var inherited = SafeAcl(sid);
            inherited.SetAccessRuleProtection(isProtected:false,
                                               preserveInheritance:false);
            Require(!NativeHostAdmission.RestrictedDaclForIdentity(
                inherited, sid), "INHERITED_DACL_ALLOWED");
            var foreignOwner = SafeAcl(sid);
            foreignOwner.SetOwner(sid);
            Require(!NativeHostAdmission.RestrictedDaclForIdentity(
                foreignOwner, sid), "FOREIGN_OWNER_ALLOWED");
            Console.WriteLine("H454_WIN32_PRIVATE_DACL_WRITE_DENIAL=PASS");
            Console.WriteLine("H454_OWNER_WINDOWS_HOST=NOT_RUN");
            return 0;
        }
        catch
        {
            Console.WriteLine("H454_WIN32_PRIVATE_DACL_WRITE_DENIAL=FAIL");
            return 2;
        }
    }
}
