"""Windows stdio adapter contracts with a disposable local agent stub."""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from device_fabric.windows_personal_commander_pipe import PersonalCommanderPipe, PersonalPipeDenied

ROOT = Path(__file__).resolve().parents[1]
ADAPTER = ROOT / "scripts/h454_windows_personal_dispatcher.mjs"
TOOLS = ["read_file", "read_multiple_files", "write_file", "write_pdf", "edit_block", "create_directory",
         "list_directory", "move_file", "get_file_info", "start_process", "read_process_output",
         "interact_with_process", "force_terminate", "list_sessions", "start_search",
         "get_more_search_results", "stop_search", "list_searches"]


class PersonalDispatcherTests(unittest.TestCase):
    def test_pdf_rejects_unapproved_output_and_unavailable_image(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            project, outside = base / 'project', base / 'outside'
            project.mkdir()
            outside.mkdir()
            frames = [{'type': 'initialize', 'roots': [str(project)]},
                      {'type': 'call', 'id': 'foreign', 'name': 'write_pdf', 'args': {
                          'path': str(project / 'doc.pdf'), 'outputPath': str(outside / 'doc.pdf'),
                          'content': 'fixture'}},
                      {'type': 'call', 'id': 'image', 'name': 'write_pdf', 'args': {
                          'path': str(project / 'image.pdf'), 'content': '![image](image.png)'}}]
            result = self.run_adapter(base, frames)
            by_id = {item['id']: item['result'] for item in result[1:]}
            self.assertTrue(by_id['foreign']['isError'])
            self.assertTrue(by_id['image']['isError'])
            self.assertFalse((outside / 'doc.pdf').exists())
            self.assertFalse((project / 'image.pdf').exists())

    def make_bundle(self, base: Path):
        bundle = base / "bundle"
        core = bundle / "core"
        core.mkdir(parents=True)
        (bundle / "package.json").write_text('{"type":"module"}', encoding="utf-8")
        (bundle / "dispatcher.js").write_text(
            "import {writeFile} from 'node:fs/promises';\n"
            "export const listTools=()=>" + json.dumps([{"name": name} for name in TOOLS]) + ";\n"
            "export async function callTool(name,args){\n"
            " process.stdout.write('UNTRUSTED_LOG_MUST_NOT_ENTER_PROTOCOL\\n');\n"
            " if(name==='start_process'&&args.command==='synthetic_wait')"
            "await new Promise(r=>setTimeout(r,1300));\n"
            " if(name==='write_file')await writeFile(args.path,args.content);\n"
            " return {isError:false,content:[{type:'text',text:'handled:'+name}]};\n"
            "}\n", encoding="utf-8")
        (core / "config-manager.js").write_text(
            "export const configManager={async init(){},async setValue(){}};\n", encoding="utf-8")
        (core / "terminal-manager.js").write_text(
            "export const terminalManager={listActiveSessions(){return []},forceTerminate(){}};\n", encoding="utf-8")
        return bundle / "dispatcher.js"

    def run_adapter(self, base: Path, frames):
        entry = self.make_bundle(base)
        process = subprocess.run([shutil.which("node"), str(ADAPTER), str(entry)],
            input="".join(json.dumps(frame, separators=(",", ":")) + "\n" for frame in frames),
            capture_output=True, text=True, timeout=20, creationflags=subprocess.CREATE_NO_WINDOW)
        self.assertEqual(process.returncode, 0, process.stderr)
        return [json.loads(line) for line in process.stdout.splitlines()]

    def test_sixteenth_project_is_usable_and_seventeenth_is_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            roots = [base / f'project-{i:02}' for i in range(17)]
            for root in roots:
                root.mkdir()
            target = roots[15] / 'fixture.txt'
            frames = [{'type': 'initialize', 'roots': [str(p) for p in roots[:16]]},
                      {'type': 'call', 'id': 'write-last', 'name': 'write_file',
                       'args': {'path': str(target), 'content': 'synthetic'}}]
            result = self.run_adapter(base, frames)
            self.assertEqual(result[0]['type'], 'ready')
            self.assertFalse(result[1]['result']['isError'])
            self.assertEqual(target.read_text(), 'synthetic')
            entry = base / 'bundle' / 'dispatcher.js'
            rejected = subprocess.run([shutil.which('node'), str(ADAPTER), str(entry)],
                input=json.dumps({'type': 'initialize', 'roots': [str(p) for p in roots]}) + '\n',
                capture_output=True, text=True, timeout=20, creationflags=subprocess.CREATE_NO_WINDOW)
            self.assertEqual(rejected.returncode, 2)
            self.assertEqual(rejected.stdout, '')

    def test_write_is_confined_and_sensitive_paths_are_denied(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            project = base / "project"
            outside = base / "outside"
            project.mkdir()
            outside.mkdir()
            (project / "nested").mkdir()
            good = project / "source.txt"
            secret = project / ".env"
            foreign = outside / "foreign.txt"
            frames = [{"type": "initialize", "roots": [str(project)]}]
            for ident, target in (("good", good), ("secret", secret), ("outside", foreign)):
                frames.append({"type": "call", "id": ident, "name": "write_file",
                               "args": {"path": str(target), "content": "synthetic"}})
            frames.append({"type": "call", "id": "unavailable", "name": "set_config_value", "args": {}})
            frames.append({"type": "call", "id": "recursive", "name": "list_directory",
                           "args": {"path": str(project), "depth": 2}})
            frames.append({"type": "call", "id": "list", "name": "list_directory",
                           "args": {"path": str(project) + "\\", "depth": 1}})
            frames.append({"type": "call", "id": "move-directory", "name": "move_file",
                           "args": {"source": str(project / "nested"), "destination": str(project / "moved")}})
            result = self.run_adapter(base, frames)
            self.assertEqual(result[0]["type"], "ready")
            by_id = {item["id"]: item["result"] for item in result[1:]}
            self.assertFalse(by_id["good"]["isError"])
            self.assertFalse(by_id["list"]["isError"])
            for name in ("secret", "outside", "unavailable", "recursive", "move-directory"):
                self.assertTrue(by_id[name]["isError"], name)
            self.assertEqual(good.read_text(), "synthetic")
            self.assertFalse(secret.exists())
            self.assertFalse(foreign.exists())

    def test_persistent_pipe_dispatches_and_closes(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            project = base / "project"
            project.mkdir()
            entry = self.make_bundle(base)
            process = subprocess.Popen([shutil.which("node"), str(ADAPTER), str(entry)],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                creationflags=subprocess.CREATE_NO_WINDOW)
            bridge = PersonalCommanderPipe(process, [str(project)])
            try:
                self.assertEqual({tool["name"] for tool in bridge.tools}, set(TOOLS))
                target = project / "pipe.txt"
                self.assertFalse(bridge.dispatch("write_file", {"path": str(target), "content": "synthetic"})["isError"])
                self.assertTrue(bridge.dispatch("write_file", {"path": str(project / '.env'), "content": "bad"})["isError"])
                with self.assertRaises(PersonalPipeDenied):
                    bridge.dispatch("set_config_value", {})
                self.assertEqual(target.read_text(), "synthetic")
            finally:
                bridge.close()
            self.assertEqual(process.returncode, 0)

    def test_search_is_bounded_and_only_uses_approved_root(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            project, outside = base / "project", base / "outside"
            project.mkdir()
            outside.mkdir()
            frames = [{"type": "initialize", "roots": [str(project)]}]
            for ident, args in (
                ("good", {"path":str(project), "pattern":"sample", "searchType":"content"}),
                ("foreign", {"path":str(outside), "pattern":"sample"}),
                ("secret", {"path":str(project / '.env'), "pattern":"sample"}),
                ("unbounded", {"path":str(project), "pattern":"sample", "timeout_ms":999999}),
                ("office", {"path":str(project), "pattern":"sample", "searchType":"content", "filePattern":"*.xlsx"}),
            ):
                frames.append({"type":"call", "id":ident, "name":"start_search", "args":args})
            frames.append({"type":"call", "id":"bad-session", "name":"get_more_search_results",
                           "args":{"sessionId":"../foreign"}})
            result = self.run_adapter(base, frames)
            by_id = {item["id"]: item["result"] for item in result[1:]}
            self.assertFalse(by_id["good"]["isError"])
            for name in ("foreign", "secret", "unbounded", "office", "bad-session"):
                self.assertTrue(by_id[name]["isError"], name)

    def test_process_call_can_wait_longer_than_default_pipe_timeout(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            project = base / "project"
            project.mkdir()
            entry = self.make_bundle(base)
            process = subprocess.Popen([shutil.which("node"), str(ADAPTER), str(entry)],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                creationflags=subprocess.CREATE_NO_WINDOW)
            bridge = PersonalCommanderPipe(process, [str(project)], timeout=1)
            try:
                result = bridge.dispatch("start_process", {"command": "synthetic_wait", "timeout_ms": 2000})
                self.assertFalse(result["isError"])
            finally:
                bridge.close()

    def test_resolved_link_cannot_redirect_writes_to_an_unapproved_directory(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            project = base / "project"
            outside = base / "outside"
            project.mkdir()
            outside.mkdir()
            link = project / "linked"
            try:
                os.symlink(outside, link, target_is_directory=True)
            except OSError:
                created = subprocess.run([os.environ["COMSPEC"], "/d", "/c", "mklink", "/J",
                                          str(link), str(outside)], capture_output=True,
                                         timeout=10, creationflags=subprocess.CREATE_NO_WINDOW)
                if created.returncode != 0:
                    self.fail("directory link creation unavailable")
            target = link / "foreign.txt"
            frames = [{"type": "initialize", "roots": [str(project)]},
                      {"type": "call", "id": "link", "name": "write_file",
                       "args": {"path": str(target), "content": "synthetic"}}]
            result = self.run_adapter(base, frames)
            self.assertTrue(result[1]["result"]["isError"])
            self.assertFalse((outside / "foreign.txt").exists())


if os.name != "nt":
    del PersonalDispatcherTests

if __name__ == "__main__":
    unittest.main()
