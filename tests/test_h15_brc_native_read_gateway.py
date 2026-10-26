"""Offline tests of pinned H-15 native READ gateway (#454); no live relay changes."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from scripts.h15_brc_native_read_gateway import (
    apply, MCP, IMPORT, LIST, CALL, NATIVE_IMPORT, NATIVE_CALL
)
from scripts.h15_remote_commander_candidate_audit import AuditError

class NativeReadGatewayTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.folder = self.root / MCP
        self.folder.mkdir(parents=True)
        self.server = self.folder / "server.ts"
        self.server.write_text(
            IMPORT + "\n" + LIST + "\n" + CALL + "\n", encoding="utf-8")
        for f in ("hermes-workspaces.ts","hermes-policy.ts",
                  "hermes-tool-catalog.ts","invoke.ts"):
            (self.folder / f).write_text("export {};\n", encoding="utf-8")
        p = patch("scripts.h15_brc_native_read_gateway.evaluate")
        p.start()
        self.addCleanup(p.stop)

    def test_exact_only_tools_injected_before_generic_invocation(self):
        result = apply(self.root)
        self.assertEqual(result["status"], "DISPOSABLE_NATIVE_READ_RELAY_PATCHED")
        self.assertFalse(result["production_activation"])
        actual = self.server.read_text()
        self.assertIn(NATIVE_IMPORT, actual)
        self.assertIn("...NATIVE_TOOLS", actual)
        self.assertEqual(actual.count(NATIVE_CALL), 1)
        self.assertLess(actual.index(NATIVE_CALL), actual.index(CALL))
        self.assertIn("invokeOwnerNativeRead", (self.folder / "hermes-native-read.ts").read_text())
        self.assertNotIn("deviceId: { type", (self.folder / "hermes-native-read.ts").read_text())

    def test_double_patch_denied_without_further_modifications(self):
        apply(self.root)
        before = self.server.read_bytes()
        target = (self.folder / "hermes-native-read.ts").read_bytes()
        with self.assertRaises(AuditError):
            apply(self.root)
        self.assertEqual(before, self.server.read_bytes())
        self.assertEqual(target, (self.folder / "hermes-native-read.ts").read_bytes())

    def test_source_drift_rejected_before_any_write(self):
        self.server.write_text(self.server.read_text().replace(CALL, "UNREVIEWED()"))
        original = self.server.read_bytes()
        with self.assertRaisesRegex(AuditError, "native_relay_marker_drift"):
            apply(self.root)
        self.assertFalse((self.folder / "hermes-native-read.ts").exists())
        self.assertEqual(self.server.read_bytes(), original)

    def test_missing_hardened_modules_denied(self):
        (self.folder / "hermes-policy.ts").unlink()
        with self.assertRaisesRegex(AuditError, "native_relay_source_not_ready"):
            apply(self.root)
        self.assertFalse((self.folder / "hermes-native-read.ts").exists())

    def test_wrong_upstream_ref_denied(self):
        with self.assertRaisesRegex(AuditError, "unreviewed_upstream_sha"):
            apply(self.root, sha="f"*40)

    def test_target_symlink_denied_without_writing_target(self):
        outside = self.root / "outside-secret.ts"
        outside.write_text("SECRET_SENTINEL")
        (self.folder / "hermes-native-read.ts").symlink_to(outside)
        with self.assertRaisesRegex(AuditError, "native_relay_source_symlink"):
            apply(self.root)
        self.assertEqual(outside.read_text(), "SECRET_SENTINEL")

    def test_typescript_native_route_runtime(self):
        if not shutil.which("tsc") or not shutil.which("node"):
            self.skipTest("Typescript compiler/node not available on this runner")
        apply(self.root)
        source_root = self.root / "packages/relay/src"
        (source_root / "store").mkdir(exist_ok=True)
        (source_root / "device-hub.ts").write_text(
            "export class DeviceHub {\n"
            " get(id: string): {ownerId:string;info:{deviceId:string;name:string;platform:string};tools:{name:string}[]} | undefined { return undefined; }\n"
            " call(id: string, t: string, a: any, o: any): Promise<any> { return Promise.reject(); }\n"
            "}\n")
        (source_root / "store/sqlite.ts").write_text(
            "export class SqliteStore {\n"
            " listDevices(id: string): any[] { return []; }\n"
            " audit(row: any): void {}\n"
            "}\n")
        (source_root / "mcp/invoke.ts").write_text(
            "export interface InvokeContext { userId: string; clientId: string }\n")
        (source_root / "ambient.d.ts").write_text(
            "declare module 'node:crypto' { export function createHash(s: string): any }\n"
            "declare const Buffer: { from(x: string, enc: string): any };\n")
        dest = self.root / "dist"
        proc = subprocess.run([
            "tsc", "--strict", "--target", "ES2022", "--module", "commonjs",
            "--skipLibCheck", "--outDir", str(dest),
            str(source_root / "ambient.d.ts"),
            str(self.folder / "hermes-native-read.ts")],
            capture_output=True, text=True, timeout=30)
        self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)
        module_path = dest / "mcp/hermes-native-read.js"
        program = r"""
const assert=require('node:assert/strict');
const crypto=require('node:crypto');
const {NATIVE_TOOLS,invokeOwnerNativeRead}=require(process.argv[1]);
const good={device_id:'h15-native-abcdefgh',name:'H15 Windows native read-only',
 platform:'win32',paused:0};
const agent={ownerId:'owner-A', info:{deviceId:good.device_id,name:good.name,platform:'win32'},
 tools:NATIVE_TOOLS.map(t=>({name:t.name}))};
const raw=Buffer.from('abc');
const verified={status:'ok',project:'hermes',relative:'README.md',action:'read',
 kind:'file',size_bytes:3,encoding:'base64',data:raw.toString('base64'),
 sha256:crypto.createHash('sha256').update(raw).digest('hex')};
let calls=0,logs=[];
let store={listDevices(owner){return owner==='owner-A'?[good]:[]},
 audit(e){logs.push(e)}};
let hub={get(id){return id===good.device_id?agent:undefined},
 async call(id,name,args){calls++;return {isError:false,content:[{type:'text',text:JSON.stringify(verified)}]}}};
const ctx={userId:'owner-A',clientId:'chatgpt'};
(async()=>{
 assert.deepEqual(NATIVE_TOOLS.map(t=>t.name),['native_file_stat','native_file_read','native_file_list']);
 const ok=await invokeOwnerNativeRead(hub,store,ctx,'native_file_read',{project:'hermes',relative:'README.md'});
 assert.equal(ok.isError,false);assert.equal(calls,1);assert.equal(logs.length,1);
 for(const args of [{project:'hermes',relative:'..\\README.md'},
 {project:'hermes',relative:'README.md',deviceId:good.device_id},
 {project:'hermes',relative:'D:\\Pet-projects\\hermes\\README.md'},
 {project:'hermes',relative:'private-vault\\a.md'},
 {project:'second-brain-workspace',relative:'README.md'}]){
  assert.equal((await invokeOwnerNativeRead(hub,store,ctx,'native_file_read',args)).isError,true);
 }
 assert.equal(calls,1);
 assert.equal((await invokeOwnerNativeRead(hub,store,{userId:'other',clientId:'codex'},'native_file_read',{project:'hermes',relative:'README.md'})).isError,true);
 assert.equal(calls,1);
 for(const altered of [
 {...agent,ownerId:'other'}, {...agent,tools:[...agent.tools,{name:'start_process'}]},
 {...agent,info:{...agent.info,platform:'linux'}}]){
  hub.get=()=>altered;
  assert.equal((await invokeOwnerNativeRead(hub,store,ctx,'native_file_read',{project:'hermes',relative:'README.md'})).isError,true);
 }
 assert.equal(calls,1);
 hub.get=()=>agent;
 hub.call=async()=>({isError:false,content:[{type:'text',text:JSON.stringify({...verified,data:'AAAA'})}]});
 assert.equal((await invokeOwnerNativeRead(hub,store,ctx,'native_file_read',{project:'hermes',relative:'README.md'})).isError,true);
 hub.call=async()=>({isError:false,content:[{type:'text',text:JSON.stringify({...verified,path:'C:\\private'})}]});
 assert.equal((await invokeOwnerNativeRead(hub,store,ctx,'native_file_read',{project:'hermes',relative:'README.md'})).isError,true);
 hub.call=async()=>({isError:false,content:[{type:'text',text:JSON.stringify(verified)}]});
 store.audit=()=>{throw Error('AUDIT_DB_OFFLINE_SECRET')};
 assert.equal((await invokeOwnerNativeRead(hub,store,ctx,'native_file_read',{project:'hermes',relative:'README.md'})).isError,true);
 console.log('H454_OWNER_NATIVE_RELAY_TS_RUNTIME=PASS');
})().catch(e=>{console.error(e);process.exitCode=1});
"""
        p = subprocess.run(["node", "-e", program, str(module_path)],
                           capture_output=True, text=True, timeout=15)
        self.assertEqual(p.returncode, 0, p.stderr + p.stdout)
        self.assertIn("H454_OWNER_NATIVE_RELAY_TS_RUNTIME=PASS", p.stdout)

    def test_unreviewed_generic_dispatch_never_modified(self):
        apply(self.root)
        self.assertEqual((self.folder / "invoke.ts").read_text(), "export {};\n")
        self.assertEqual((self.folder / "hermes-policy.ts").read_text(), "export {};\n")
        s = self.server.read_text()
        self.assertIn(CALL, s)
        self.assertIn(NATIVE_CALL, s)

if __name__ == "__main__":
    unittest.main()
