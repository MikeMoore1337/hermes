#!/usr/bin/env node
// H-15 real OCI runtime surface probe. Runs FROM STDIN inside a disposable
// node:24-bookworm-slim image; never opens a network connection or runs shell.
// Presence is NOT proof that a vulnerable path is reachable/exploitable.
"use strict";
const fs = require("node:fs");

function statusValue(name) {
  const status = fs.readFileSync("/proc/self/status", "utf8");
  const line = status.split("\n").find((s) => s.startsWith(name + ":"));
  if (!line) throw new Error("required_kernel_status_absent");
  return line.split(":")[1].trim();
}

function binaryPresent(binary) {
  for (const dir of ["/usr/bin", "/bin", "/usr/sbin", "/sbin", "/usr/local/bin"]) {
    try {
      const path = dir + "/" + binary;
      if (fs.statSync(path).isFile()) return true;
    } catch (error) {
      if (error.code !== "ENOENT") throw new Error("binary_check_failed");
    }
  }
  return false;
}

const binaries = {};
for (const command of [
  "mount", "umount", "nsenter", "unshare", "fdisk", "sfdisk",
  "infocmp", "gzip", "perl", "setfacl", "getfacl",
]) {
  binaries[command] = binaryPresent(command);
}
const homed = ["/lib/systemd/systemd-homed", "/usr/lib/systemd/systemd-homed"];
const archiveTar = [
  "/usr/share/perl/5.36.0/Archive/Tar.pm",
  "/usr/share/perl5/Archive/Tar.pm",
];
const devices = fs.readdirSync("/dev", {withFileTypes: true});
const blockDevices = devices.filter((entry) => entry.isBlockDevice()).map((entry) => entry.name).sort();
let rootWriteDenied = false;
const testPath = "/.h15-disposable-write-probe";
try {
  // This must fail because of the readonly OCI root filesystem.
  const fd = fs.openSync(testPath, "wx", 0o600);
  fs.closeSync(fd);
  fs.unlinkSync(testPath);
} catch (error) {
  if (error.code === "EROFS" || error.code === "EACCES") rootWriteDenied = true;
  else throw new Error("unexpected_rootfs_write_error");
}
const data = {
  schema: "hermes-h15-oci-runtime-surface-v1",
  uid: process.getuid(),
  gid: process.getgid(),
  cap_eff_hex: statusValue("CapEff"),
  cap_bnd_hex: statusValue("CapBnd"),
  no_new_privs: Number(statusValue("NoNewPrivs")),
  seccomp_mode: Number(statusValue("Seccomp")),
  root_write_denied: rootWriteDenied,
  block_devices: blockDevices,
  observed_binaries: binaries,
  observed_systemd_homed_binary: homed.some((p) => fs.existsSync(p)),
  observed_perl_archive_tar_module: archiveTar.some((p) => fs.existsSync(p)),
  scope_limit: "BINARY_PRESENCE_ONLY_NOT_EXPLOITABILITY",
  release_approved: false,
};
if (data.uid !== 65534 || data.gid !== 65534 ||
    !/^0+$/.test(data.cap_eff_hex) || !/^0+$/.test(data.cap_bnd_hex) ||
    data.no_new_privs !== 1 || data.seccomp_mode !== 2 ||
    !data.root_write_denied || blockDevices.length > 0) {
  throw new Error("isolated_oci_runtime_boundary_failed");
}
process.stdout.write(JSON.stringify(data) + "\n");
