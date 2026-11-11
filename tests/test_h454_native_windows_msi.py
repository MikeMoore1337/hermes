"""H454: WiX first-time Windows native service MSI, OFFLINE scope only."""
from __future__ import annotations
from pathlib import Path
import unittest
import xml.etree.ElementTree as ET

BASE = Path(__file__).resolve().parents[1]
WXS = BASE / "deploy/h454/native-windows-msi/Package.wxs"
WORKFLOW = BASE / ".github/workflows/h454-native-windows-msi.yml"
NS = "{http://wixtoolset.org/schemas/v4/wxs}"


class NativeWindowsMsiContracts(unittest.TestCase):
    def test_first_time_disabled_virtual_account_exact_binary(self):
        root = ET.parse(WXS).getroot()
        package = root.find(NS + "Package")
        self.assertEqual(package.attrib["Scope"], "perMachine")
        self.assertEqual(package.attrib["Id"],
                         "MikeMoore1337.HermesCommander.Native.Disabled")
        service = root.find(".//" + NS + "ServiceInstall")
        self.assertEqual(service.attrib["Name"], "HermesCommanderNative")
        self.assertEqual(service.attrib["Account"], r"NT SERVICE\HermesCommanderNative")
        self.assertEqual(service.attrib["Start"], "disabled")
        self.assertEqual(service.attrib["Type"], "ownProcess")
        self.assertEqual(service.attrib["Arguments"], "--service")
        self.assertEqual(service.attrib["Vital"], "yes")
        self.assertNotIn("Password", service.attrib)
        control = root.find(".//" + NS + "ServiceControl")
        self.assertEqual(control.attrib["Stop"], "uninstall")
        self.assertEqual(control.attrib["Remove"], "uninstall")
        self.assertNotIn("Start", control.attrib)
        file = root.find(".//" + NS + "File")
        self.assertEqual(file.attrib["Source"], "$(var.ServiceExe)")
        self.assertEqual(file.attrib["KeyPath"], "yes")
        all_files = root.findall(".//" + NS + "File")
        self.assertEqual({item.attrib["Id"] for item in all_files}, {
            "HermesCommanderNativeServiceExe", "HermesCommanderNativeWorkerExe"})
        self.assertEqual({item.attrib["Source"] for item in all_files}, {
            "$(var.ServiceExe)", "$(var.WorkerExe)"})
        self.assertEqual(len(root.findall(".//" + NS + "ServiceInstall")), 1)
        self.assertNotIn("LocalSystem", WXS.read_text(encoding="utf-8"))

    def test_unknown_existing_service_must_block_first_install(self):
        root = ET.parse(WXS).getroot()
        prop = root.find(".//" + NS + "Property")
        search = root.find(".//" + NS + "RegistrySearch")
        launch = root.find(".//" + NS + "Launch")
        self.assertEqual(prop.attrib["Id"], "H454_EXISTING_NATIVE_SERVICE")
        self.assertEqual(search.attrib["Root"], "HKLM")
        self.assertEqual(search.attrib["Name"], "ImagePath")
        self.assertEqual(search.attrib["Type"], "raw")
        self.assertIn(r"SYSTEM\CurrentControlSet\Services\HermesCommanderNative",
                      search.attrib["Key"])
        self.assertEqual(launch.attrib["Condition"],
                         "Installed OR NOT H454_EXISTING_NATIVE_SERVICE")
        self.assertNotIn("MajorUpgrade", WXS.read_text(encoding="utf-8"))
        self.assertNotIn("RemoveFile", WXS.read_text(encoding="utf-8"))

    def test_ci_requires_cleanup_and_never_distributes_unsigned_package(self):
        text = WORKFLOW.read_text(encoding="utf-8")
        for marker in (
            "runs-on: windows-2025", "contents: read",
            "persist-credentials: false", "--version 6.0.0",
            "Get-AuthenticodeSignature", "NotSigned",
            "msiexec.exe", "Get-CimInstance",
            "H454_WINDOWS_MSI_DISABLED=PASS",
            "H454_WIN32_WORKER_IN_MSI=PASS",
            "h454_package_win32_worker.ps1",
            "H454_WINDOWS_MSI_UNINSTALL=PASS",
            "H454_WINDOWS_MSI_VIRTUAL_SERVICE_FAIL_CLOSED=PASS",
            "H454_WINDOWS_MSI_EXISTING_SERVICE_DENIED=PASS",
            "H454_OWNER_WINDOWS_MSI_NOT_INSTALLED=YES",
        ):
            self.assertIn(marker, text)
        for forbidden in (
            "workflow_dispatch", "upload-artifact", "secrets.",
            "ssh ", "scp ", "docker ",
            "Start-Service", "Set-Service",
        ):
            self.assertNotIn(forbidden, text)


if __name__ == "__main__":
    unittest.main()
