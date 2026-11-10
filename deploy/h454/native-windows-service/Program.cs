// Hermes #454 Stage 2A: a real Windows SCM executable, deliberately OFFLINE.
// This is NOT an installer, credential issuer, WSS client or native file agent.
// Future activation needs an independently approved signed installer, virtual
// service account, protected DPAPI context, current revocation and OS ACL proof.
using System;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;

namespace HermesCommander.NativeService;

internal static class Program
{
    internal const string ServiceName = "HermesCommanderNative";
    internal const string ServiceAccount = @"NT SERVICE\HermesCommanderNative";
    internal const string StartMode = "DISABLED";
    internal const string AccessMode = "READ_ONLY";
    internal const bool CanActivate = false;
    internal const bool CanInstall = false;

    private const uint SERVICE_WIN32_OWN_PROCESS = 0x00000010;
    private const uint SERVICE_STOPPED = 0x00000001;
    private const uint SERVICE_START_PENDING = 0x00000002;
    private const uint SERVICE_CONTROL_STOP = 0x00000001;
    private const uint SERVICE_CONTROL_SHUTDOWN = 0x00000005;
    private const uint NO_ERROR = 0;
    private const uint ERROR_CALL_NOT_IMPLEMENTED = 120;
    private const uint ERROR_SERVICE_SPECIFIC_ERROR = 1066;
    private const uint NATIVE_NOT_PROVISIONED = 454;

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
            CanInstall || CanActivate ||
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
            ControlsAccepted = 0,
            Win32ExitCode = win32Code,
            ServiceSpecificExitCode = serviceCode,
            CheckPoint = state == SERVICE_START_PENDING ? 1u : 0u,
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
        // There is intentionally no SERVICE_RUNNING branch. Installing this
        // candidate cannot grant filesystem, network or process capabilities.
        // On a future approved build replace only after verified Win32 SID,
        // private state, DPAPI, owner pairing, revocation and transport gates.
        Report(SERVICE_STOPPED, ERROR_SERVICE_SPECIFIC_ERROR,
            NATIVE_NOT_PROVISIONED, 0);
    }

    private static uint OnControl(
        uint control, uint eventType, IntPtr eventData, IntPtr context)
    {
        if (control == SERVICE_CONTROL_STOP ||
            control == SERVICE_CONTROL_SHUTDOWN)
        {
            Report(SERVICE_STOPPED, ERROR_SERVICE_SPECIFIC_ERROR,
                NATIVE_NOT_PROVISIONED, 0);
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
