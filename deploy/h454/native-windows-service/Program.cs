// Hermes #454 Stage 2A: a real Windows SCM executable, deliberately OFFLINE.
// This is NOT an installer, credential issuer, WSS client or native file agent.
// Future activation needs an independently approved signed installer, virtual
// service account, protected DPAPI context, current revocation and OS ACL proof.
using System;
using System.Diagnostics;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using System.Threading;

namespace HermesCommander.NativeService;

internal static class Program
{
    internal const string ServiceName = "HermesCommanderNative";
    internal const string ServiceAccount = @"NT SERVICE\HermesCommanderNative";
    internal const string StartMode = "DISABLED";
    internal const string AccessMode = "READ_ONLY";
    internal const bool CanActivate = true; // strictly gated, never automatic
    internal const bool CanInstall = false;

    private const uint SERVICE_WIN32_OWN_PROCESS = 0x00000010;
    private const uint SERVICE_STOPPED = 0x00000001;
    private const uint SERVICE_START_PENDING = 0x00000002;
    private const uint SERVICE_STOP_PENDING = 0x00000003;
    private const uint SERVICE_RUNNING = 0x00000004;
    private const uint SERVICE_ACCEPT_STOP = 0x00000001;
    private const uint SERVICE_ACCEPT_SHUTDOWN = 0x00000004;
    private const uint SERVICE_CONTROL_STOP = 0x00000001;
    private const uint SERVICE_CONTROL_SHUTDOWN = 0x00000005;
    private const uint NO_ERROR = 0;
    private const uint ERROR_CALL_NOT_IMPLEMENTED = 120;
    private const uint ERROR_SERVICE_SPECIFIC_ERROR = 1066;
    private const uint NATIVE_NOT_PROVISIONED = 454;
    private const uint NATIVE_OS_IDENTITY_DENIED = 455;
    private const uint NATIVE_RUNTIME_NOT_READY = 456;
    private const uint NATIVE_AUTHENTICATED_WSS_NOT_READY = 457;

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    private delegate void ServiceMainCallback(uint argc, IntPtr argv);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    private delegate uint ControlCallback(
        uint control, uint eventType, IntPtr eventData, IntPtr context);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct ServiceTableEntry
    {
        [MarshalAs(UnmanagedType.LPWStr)]
        public string? Name;
        [MarshalAs(UnmanagedType.FunctionPtr)]
        public ServiceMainCallback? Main;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ServiceStatus
    {
        public uint ServiceType;
        public uint CurrentState;
        public uint ControlsAccepted;
        public uint Win32ExitCode;
        public uint ServiceSpecificExitCode;
        public uint CheckPoint;
        public uint WaitHint;
    }

    [DllImport("advapi32.dll", EntryPoint = "StartServiceCtrlDispatcherW",
        CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool StartServiceCtrlDispatcher(
        [In] ServiceTableEntry[] table);

    [DllImport("advapi32.dll", EntryPoint = "RegisterServiceCtrlHandlerExW",
        CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr RegisterServiceCtrlHandlerEx(
        string name, ControlCallback handler, IntPtr context);

    [DllImport("advapi32.dll", EntryPoint = "SetServiceStatus",
        SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetServiceStatus(
        IntPtr handle, ref ServiceStatus status);

    private static readonly ServiceMainCallback ServiceMainProc = ServiceMain;
    private static readonly ControlCallback HandlerProc = OnControl;
    private static IntPtr _statusHandle;
    private static readonly ManualResetEventSlim StopRequested = new(false);

    private static string Revision()
    {
        string version = Assembly.GetExecutingAssembly()
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?
            .InformationalVersion ?? "";
        Match match = Regex.Match(version, @"\+([0-9a-f]{40})\z",
            RegexOptions.CultureInvariant);
        return match.Success ? match.Groups[1].Value : "NOT_PINNED";
    }

    private static int SelfTest(string expectedSha)
    {
        string actualSha = Revision();
        if (actualSha == "NOT_PINNED" ||
            !Regex.IsMatch(expectedSha, @"\A[0-9a-f]{40}\z",
                RegexOptions.CultureInvariant) ||
            actualSha != expectedSha ||
            CanInstall || !CanActivate ||
            ServiceName != "HermesCommanderNative" ||
            ServiceAccount != @"NT SERVICE\HermesCommanderNative" ||
            StartMode != "DISABLED" || AccessMode != "READ_ONLY")
            return 2;
        return 0;
    }

    private static void Report(uint state, uint win32Code,
                               uint serviceCode, uint waitHint)
    {
        var current = new ServiceStatus
        {
            ServiceType = SERVICE_WIN32_OWN_PROCESS,
            CurrentState = state,
            ControlsAccepted = state == SERVICE_RUNNING ?
                SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN : 0,
            Win32ExitCode = win32Code,
            ServiceSpecificExitCode = serviceCode,
            CheckPoint = (state == SERVICE_START_PENDING ||
                state == SERVICE_STOP_PENDING) ? 1u : 0u,
            WaitHint = waitHint,
        };
        if (_statusHandle != IntPtr.Zero)
            SetServiceStatus(_statusHandle, ref current);
    }

    private static void ServiceMain(uint argc, IntPtr argv)
    {
        _statusHandle = RegisterServiceCtrlHandlerEx(
            ServiceName, HandlerProc, IntPtr.Zero);
        if (_statusHandle == IntPtr.Zero)
            return;

        Report(SERVICE_START_PENDING, NO_ERROR, 0, 1000);
        // Actual Win32 token check: LocalService/SYSTEM or an impersonated
        // owner process is not an authorized native service identity.
        if (!NativeHostAdmission.MatchesServiceUser())
        {
            Report(SERVICE_STOPPED, ERROR_SERVICE_SPECIFIC_ERROR,
                NATIVE_OS_IDENTITY_DENIED, 0);
            return;
        }
        // Kernel file-handle and protected NTFS ACL preflight, not a grant.
        // Missing state or broad original project ACL always fail closed.
        if (!NativeHostAdmission.PrivateStateIsConfined() ||
            !NativeHostAdmission.OriginalRootsAreKernelReadOnly())
        {
            Report(SERVICE_STOPPED, ERROR_SERVICE_SPECIFIC_ERROR,
                NATIVE_NOT_PROVISIONED, 0);
            return;
        }
        // A signed release receipt is protected by the same NTFS ACLs
        // as the owner-paired DPAPI device/manifest. An independently
        // installed worker must have both expected SHA-256 digests.
        // The process inherits this exact unprivileged service SID.
        using Process? child = NativeWorkerSupervisor.TryLaunch(Revision());
        if (child is null)
        {
            Report(SERVICE_STOPPED, ERROR_SERVICE_SPECIFIC_ERROR,
                NATIVE_RUNTIME_NOT_READY, 0);
            return;
        }

        bool reportedRunning = false;
        bool authenticated = false;
        try
        {
            authenticated = NativeWorkerSupervisor.WaitForAuthenticatedWelcome(
                    child, StopRequested, TimeSpan.FromSeconds(20)) &&
                !StopRequested.IsSet &&
                NativeHostAdmission.MatchesServiceUser() &&
                NativeHostAdmission.PrivateStateIsConfined() &&
                NativeHostAdmission.PrivateWorkerTempIsConfined() &&
                NativeHostAdmission.OriginalRootsAreKernelReadOnly() &&
                !child.HasExited;
            if (!authenticated)
            {
                return; // finally reports one sanitized STOPPED status
            }
            // The only READY source is the worker's validated BRC WSS
            // welcome after current owner bearer/DPAPI/OS checks.
            Report(SERVICE_RUNNING, NO_ERROR, 0, 0);
            reportedRunning = true;
            while (!StopRequested.Wait(400))
            {
                if (child.HasExited)
                    break;
            }
        }
        catch
        {
            // Source, OS or child process exceptions are not logged.
        }
        finally
        {
            if (reportedRunning)
                Report(SERVICE_STOP_PENDING, NO_ERROR, 0, 5000);
            NativeWorkerSupervisor.StopWorker(child);
            bool cleanStop = StopRequested.IsSet;
            Report(SERVICE_STOPPED,
                cleanStop ? NO_ERROR : ERROR_SERVICE_SPECIFIC_ERROR,
                cleanStop ? 0u : authenticated ?
                    NATIVE_RUNTIME_NOT_READY : NATIVE_AUTHENTICATED_WSS_NOT_READY, 0);
        }
    }

    private static uint OnControl(
        uint control, uint eventType, IntPtr eventData, IntPtr context)
    {
        if (control == SERVICE_CONTROL_STOP ||
            control == SERVICE_CONTROL_SHUTDOWN)
        {
            // ServiceMain kills and reaps the exact child process before
            // announcing SCM STOPPED. No remote shell/process tree policy.
            StopRequested.Set();
            return NO_ERROR;
        }
        return ERROR_CALL_NOT_IMPLEMENTED;
    }

    [STAThread]
    private static int Main(string[] args)
    {
        if (args.Length == 2 && args[0] == "--self-test")
            return SelfTest(args[1]);
        if (args.Length != 1 || args[0] != "--service" ||
            SelfTest(Revision()) != 0 ||
            !OperatingSystem.IsWindows())
            return 2;

        // Must be invoked by the real Windows Service Control Manager.
        // A direct command-line attempt fails with no fallback execution.
        var table = new[]
        {
            new ServiceTableEntry { Name = ServiceName, Main = ServiceMainProc },
            new ServiceTableEntry { Name = null, Main = null },
        };
        bool dispatched = StartServiceCtrlDispatcher(table);
        GC.KeepAlive(ServiceMainProc);
        GC.KeepAlive(HandlerProc);
        return dispatched ? 0 : 3;
    }
}
