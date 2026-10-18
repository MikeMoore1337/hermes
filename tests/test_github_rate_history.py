"""Read-only GH quota history: bounded, resource isolated, owner gated."""
from __future__ import annotations
from datetime import datetime, timedelta, timezone
from http.server import ThreadingHTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Thread
from urllib.error import HTTPError
from urllib.request import Request, urlopen
import json
import sqlite3
import unittest

from control_center.github_rate_history import append, read
from control_center.github_rate_limit import parse
from control_center.auth import AuthConfig, OAuthService, ORIGIN
from control_center.server import make_handler

NOW = datetime.now(timezone.utc)


class GitHubQuotaHistoryTests(unittest.TestCase):
    def evidence(self, observed, core, search):
        return parse(json.dumps({"resources":{
            "core":{"limit":100,"used":100-core,"remaining":core,
                "reset":int((observed+timedelta(hours=1)).timestamp())},
            "search":{"limit":20,"used":20-search,"remaining":search,
                "reset":int((observed+timedelta(hours=1)).timestamp())}
        }}).encode(),now=observed)

    def test_resource_separation_and_expiration(self):
        with TemporaryDirectory() as d:
            db=Path(d)/"history.sqlite3"
            append(self.evidence(NOW-timedelta(hours=2),80,10),db)
            append(self.evidence(NOW-timedelta(minutes=10),20,0),db)
            append(self.evidence(NOW-timedelta(minutes=10),20,0),db)
            core=read(db,resource="core",days=1,now=NOW)
            search=read(db,resource="search",days=1,now=NOW)
            self.assertEqual([x["remaining_percent"] for x in core["points"]],[80,20])
            self.assertEqual([x["remaining_percent"] for x in search["points"]],[50,0])
            self.assertEqual(len(core["points"]),2)
            self.assertEqual(read(db,resource="core",days=30,now=NOW)["resource"],"core")
            for bad_resource,days in (("private",7),("core",365),("core",True)):
                with self.subTest(value=bad_resource,days=days),self.assertRaises(ValueError):
                    read(db,resource=bad_resource,days=days,now=NOW)

    def test_symlink_and_corrupt_history_rejected(self):
        with TemporaryDirectory() as d:
            root=Path(d);broken=root/"db";broken.write_text("not-sqlite")
            with self.assertRaises(ValueError):
                read(broken,resource="core",now=NOW)
            link=root/"link";link.symlink_to(broken)
            self.assertEqual(read(link,resource="core",now=NOW)["points"],[])
            with self.assertRaises(ValueError):
                append(self.evidence(NOW,20,15),link)

    def test_owner_api_only_and_filters(self):
        with TemporaryDirectory() as d:
            root=Path(d);db=root/"gh.sqlite3"
            append(self.evidence(NOW,25,5),db)
            app=ThreadingHTTPServer(("127.0.0.1",0),make_handler(
                root/"overview.json",github_history_path=db,
                github_rate_limit_path=root/"gh.json",
                cloudflare_billing_path=root/"cf.json",
                codex_path=root/"codex.json",desktop_commander_path=root/"dc.json"))
            th=Thread(target=app.serve_forever,daemon=True);th.start()
            try:
                base=f"http://127.0.0.1:{app.server_port}"
                def get(query):
                    request=Request(base+"/api/providers/registry/history"+query,
                                    headers={"Host":"hermes.mikemoore.top"})
                    try: response=urlopen(request,timeout=3)
                    except HTTPError as e:response=e
                    with response: return response.status,response.read()
                ok,payload=get("?resource=core&days=1")
                self.assertEqual(ok,200)
                self.assertEqual(json.loads(payload)["resource"],"core")
                self.assertEqual(get("?resource=private&days=1")[0],400)
                self.assertEqual(get("?resource=core&days=1&auth=x")[0],400)
                self.assertEqual(get("")[0],400)
                # Broken SQLite is an unavailable provider, not user input 400.
                db.write_bytes(b"not-sqlite")
                self.assertEqual(get("?resource=core&days=1")[0],503)
            finally:
                app.shutdown();app.server_close();th.join(timeout=3)

    def test_protected_api_anonymous_401(self):
        with TemporaryDirectory() as d:
            root=Path(d)
            config=AuthConfig("github",ORIGIN,"Ov23abcdefghijk",
                  "test-client-secret-long-enough",42142321,
                  b"test signing secret longer than 32 characters")
            srv=ThreadingHTTPServer(("127.0.0.1",0),make_handler(
                root/"overview.json",auth_config=config,oauth_service=OAuthService(config),
                github_history_path=root/"history.sqlite3"))
            th=Thread(target=srv.serve_forever,daemon=True);th.start()
            try:
                req=Request(f"http://127.0.0.1:{srv.server_port}/api/providers/registry/history?resource=core&days=7",
                            headers={"Host":"hermes.mikemoore.top"})
                with self.assertRaises(HTTPError) as err:urlopen(req,timeout=3)
                self.assertEqual(err.exception.code,401)
            finally:srv.shutdown();srv.server_close();th.join(timeout=3)


if __name__=="__main__":
    unittest.main()
