import contextlib
import io
import json
import unittest
from scripts import audit_v0222_xml_ssh_surfaces as audit

def fake():
    data={name:b"# safe fixture\n" for name in audit.TARGETS}
    data["tools/read_extract.py"]=b"from xml.etree import ElementTree as ET\nET.fromstring(b'<a/>')\n"
    data["tools/environments/ssh.py"]=b"import subprocess\nsubprocess.Popen(['ssh','fictional-host'])\n"
    return data

class XMLSSHSurfaceTests(unittest.TestCase):
    def test_detects_stdlib_parser_and_ssh_backend(self):
        result=audit.inspect_bytes(fake())
        self.assertTrue(result["paths"]["tools/read_extract.py"]["xml_stdlib_etree_import"])
        self.assertEqual(result["paths"]["tools/read_extract.py"]["etree_parse_call_lines"],[2])
        self.assertEqual(result["paths"]["tools/environments/ssh.py"]["subprocess_call_lines"],[2])
        self.assertFalse(result["absence_of_libxml2_runtime_dependency_proven"])
        self.assertFalse(result["ssh_egress_denied_at_os_layer_proven"])
        self.assertFalse(result["resident_agent_allowed"])
    def test_nonstdlib_import_flagged(self):
        files=fake();files["tools/read_extract.py"]=b"from lxml import etree\n"
        self.assertTrue(audit.inspect_bytes(files)["paths"]["tools/read_extract.py"]["non_stdlib_xml_import_observed"])
    def test_modified_source_hash_changes(self):
        files=fake();first=audit.inspect_bytes(files)["paths"]["tools/read_extract.py"]["sha256"]
        files["tools/read_extract.py"]+=b"# changed\n"
        self.assertNotEqual(first,audit.inspect_bytes(files)["paths"]["tools/read_extract.py"]["sha256"])
    def test_missing_scope_denied(self):
        files=fake();files.pop("tools/read_extract.py")
        with self.assertRaisesRegex(audit.ScopeDenied,"exact_scope_required"):audit.inspect_bytes(files)
    def test_unknown_scope_denied(self):
        files=fake();files["secret_private.py"]=b""
        with self.assertRaises(audit.ScopeDenied):audit.inspect_bytes(files)
    def test_syntax_error_denied(self):
        files=fake();files["tools/read_extract.py"]=b"def broken(:\n"
        with self.assertRaises(audit.ScopeDenied):audit.inspect_bytes(files)
    def test_file_size_denied(self):
        files=fake();files["tools/read_extract.py"]=b"x"*(audit.MAX_SIZE+1)
        with self.assertRaises(audit.ScopeDenied):audit.inspect_bytes(files)
    def test_no_source_content_leaks(self):
        files=fake();files["tools/read_extract.py"]+=b"# SENSITIVE_MARKER\n"
        self.assertNotIn("SENSITIVE_MARKER",json.dumps(audit.inspect_bytes(files)))
    def test_no_implicit_execute(self):
        output=io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(audit.main([]),0)
        self.assertEqual(json.loads(output.getvalue())["status"],"NOT_EXECUTED")
    def test_missing_path_fails_closed(self):
        output=io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(audit.main(["--execute","--source-tree","/not-a-real-private-path"]),2)
        self.assertEqual(json.loads(output.getvalue())["status"],"INCONCLUSIVE")
        self.assertNotIn("private-path",output.getvalue())

if __name__=="__main__":unittest.main()
