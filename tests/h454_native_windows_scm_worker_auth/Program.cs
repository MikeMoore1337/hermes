// Synthetic policy-only CI. No UAC, live worker, host files, network, or SCM.
using System.Text.Json;

namespace HermesCommander.NativeService.Tests;

internal static class CiReceiptTests
{
    private static int Main()
    {
        const string sha = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        string service = new('b', 64);
        string worker = new('c', 64);
        var record = new Dictionary<string, object?>
        {
            ["schema"] = "h454-signed-msi-receipt-v1",
            ["source_sha"] = sha,
            ["msi_sha256"] = new string('d', 64),
            ["exe_sha256"] = service,
            ["worker_sha256"] = worker,
            ["signer_thumbprint"] = new string('E', 40),
            ["msi_valid"] = true,
            ["exe_valid"] = true,
            ["worker_valid"] = true,
            ["installed_on_owner_host"] = false,
        };
        byte[] raw = JsonSerializer.SerializeToUtf8Bytes(record);
        bool accepted = NativeWorkerSupervisor.ReceiptMatches(raw, sha,
            service, worker);
        if (!accepted) return 2;
        foreach (string bad in new [] {
            sha[..39] + "f", "NOT_A_SHA",
        })
            if (NativeWorkerSupervisor.ReceiptMatches(raw, bad, service, worker))
                return 3;
        if (NativeWorkerSupervisor.ReceiptMatches(
            raw, sha, new string('e',64), worker)) return 4;
        if (NativeWorkerSupervisor.ReceiptMatches(
            raw, sha, service, new string('f',64))) return 5;
        foreach (string field in new [] {
            "msi_valid","exe_valid","worker_valid",
        })
        {
            record[field] = false;
            if (NativeWorkerSupervisor.ReceiptMatches(
                JsonSerializer.SerializeToUtf8Bytes(record),sha,service,worker))
                return 6;
            record[field] = true;
        }
        record["unexpected_root"] = "C:\\";
        if (NativeWorkerSupervisor.ReceiptMatches(
            JsonSerializer.SerializeToUtf8Bytes(record),sha,service,worker))
            return 7;
        record.Remove("unexpected_root");
        string duplicate = JsonSerializer.Serialize(record);
        duplicate = duplicate.Replace("\"msi_valid\":true",
            "\"msi_valid\":false,\"msi_valid\":true");
        if (NativeWorkerSupervisor.ReceiptMatches(
            System.Text.Encoding.UTF8.GetBytes(duplicate),sha,service,worker))
            return 8;
        // Invalid fields never permit worker launch; no test executable
        // can ever invoke NativeWorkerSupervisor.TryLaunch.
        Console.WriteLine("H454_WIN32_SIGNED_RELEASE_RECEIPT=PASS");
        Console.WriteLine("H454_WINDOWS_NATIVE_AGENT_STARTED=NO");
        return 0;
    }
}
