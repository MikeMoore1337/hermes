"""Personal worker ordering and reconnect behavior with synthetic callbacks."""
import unittest
from unittest.mock import patch

from device_fabric.native_brc_enrollment import Paired
from device_fabric import windows_personal_commander_config as config
from device_fabric import windows_personal_commander_worker as worker
from device_fabric.windows_personal_commander_pipe import PersonalPipeDenied
from device_fabric.windows_personal_commander_transport import PersonalTransportDenied

SID = "S-1-5-21-1-2-3-1001"
DEVICE = "h454-win-personal-" + "a" * 32
TOKEN = "brc_dev_" + "b" * 64
CA = b"-----BEGIN CERTIFICATE-----\nSYNTHETIC\n-----END CERTIFICATE-----\n"
BUNDLE = "c" * 64


class Bridge:
    def __init__(self, *_args):
        self.tools = [{'name': 'force_terminate', 'inputSchema': {'type': 'object'}}]
        self.closed = False

    def dispatch(self, _name, _args):
        return {"content": []}

    def close(self):
        self.closed = True


class PersonalWorkerTests(unittest.TestCase):
    def setUp(self):
        self.raw = config.prepare_config(Paired("windows-personal", DEVICE, TOKEN,
            "wss://hermes.mikemoore.top/ws"), owner_sid=SID, release_sha="d" * 40,
            ca=CA, bundle_sha256=BUNDLE, now=1000, seal=lambda *_a, **_k: b"s" * 64)
        self.events = []
        self.bridge = Bridge()
        self.args = {"current_sid": lambda: SID, "ca": CA,
            "verify_bundle": lambda: self.events.append("verify") or BUNDLE,
            "isolation_verified": lambda: self.events.append("isolation") or True,
            "attach_job": lambda: self.events.append("job"),
            "start_dispatcher": lambda: self.events.append("start") or object(),
            "connector": lambda *_a, **_k: None,
            "status_factory": lambda _id, _token: lambda: True,
            "claim_call": lambda _id: True,
            "pause": lambda seconds: self.events.append(("pause", seconds)),
            "decrypt": lambda *_a, **_k: self.events.append("decrypt") or TOKEN}

    def test_checks_bundle_before_unseal_and_attaches_job_before_launch(self):
        with patch.object(worker, "PersonalCommanderPipe", return_value=self.bridge), \
             patch.object(worker, "run_session", side_effect=PersonalTransportDenied("synthetic")):
            outcome = worker.serve(self.raw, **self.args)
        self.assertEqual(outcome, "reconnect_exhausted")
        self.assertEqual(self.events[:5], ["isolation", "verify", "decrypt", "job", "start"])
        self.assertEqual(len([item for item in self.events if isinstance(item, tuple)]), worker.MAX_RECONNECTS)
        self.assertTrue(self.bridge.closed)

    def test_wrong_bundle_or_inactive_device_never_starts_a_process(self):
        self.args["verify_bundle"] = lambda: "e" * 64
        with self.assertRaises(worker.PersonalWorkerDenied):
            worker.serve(self.raw, **self.args)
        self.assertNotIn("decrypt", self.events)
        self.assertNotIn("job", self.events)
        self.args["verify_bundle"] = lambda: BUNDLE
        self.args["status_factory"] = lambda _id, _token: lambda: False
        with self.assertRaises(worker.PersonalWorkerDenied):
            worker.serve(self.raw, **self.args)
        self.assertNotIn("job", self.events)

    def test_initial_status_outage_requests_retry_without_starting_dispatcher(self):
        self.args["status_factory"] = lambda _id, _token: lambda: None
        self.assertEqual(worker.serve(self.raw, **self.args), "reconnect_exhausted")
        self.assertNotIn("job", self.events)
        self.assertNotIn("start", self.events)

    def test_missing_os_confinement_never_unseals_or_starts(self):
        self.args["isolation_verified"] = lambda: False
        with self.assertRaises(worker.PersonalWorkerDenied):
            worker.serve(self.raw, **self.args)
        self.assertNotIn("verify", self.events)
        self.assertNotIn("decrypt", self.events)
        self.assertNotIn("job", self.events)

    def test_failed_pipe_stops_worker_without_retrying_an_effect(self):
        def broken(*_args):
            raise PersonalPipeDenied("synthetic")
        self.bridge.dispatch = broken
        def session(**kwargs):
            try:
                kwargs["dispatch"]("write_file", {})
            except PersonalPipeDenied:
                raise PersonalTransportDenied("synthetic") from None
        with patch.object(worker, "PersonalCommanderPipe", return_value=self.bridge), \
             patch.object(worker, "run_session", side_effect=session) as run:
            self.assertEqual(worker.serve(self.raw, **self.args), "dispatcher_failed")
        self.assertEqual(run.call_count, 1)
        self.assertTrue(self.bridge.closed)

    def test_lost_os_confinement_stops_without_reconnect(self):
        states = iter((True, False))
        self.args["isolation_verified"] = lambda: next(states)
        with patch.object(worker, "PersonalCommanderPipe", return_value=self.bridge), \
             patch.object(worker, "run_session", side_effect=PersonalTransportDenied("synthetic")) as run:
            self.assertEqual(worker.serve(self.raw, **self.args), "isolation_lost")
        self.assertEqual(run.call_count, 1)
        self.assertTrue(self.bridge.closed)

    def test_idle_dispatcher_exit_requests_fresh_worker_without_replaying(self):
        class ExitedProcess:
            def poll(self):
                return 1
        states = iter((True, False))
        self.args["isolation_verified"] = lambda: next(states)
        self.args["start_dispatcher"] = lambda: ExitedProcess()
        with patch.object(worker, "PersonalCommanderPipe", return_value=self.bridge), \
             patch.object(worker, "run_session", side_effect=PersonalTransportDenied("synthetic")) as run:
            self.assertEqual(worker.serve(self.raw, **self.args), "dispatcher_failed")
        self.assertEqual(run.call_count, 1)
        self.assertTrue(self.bridge.closed)

    def test_import_call_is_advertised_and_dispatched_to_owned_broker(self):
        class Broker:
            closed = False
            calls = []
            def dispatch(self, args):
                self.calls.append(args)
                return {'content': [{'type': 'text', 'text': 'started'}], 'isError': False}
            def close(self):
                self.closed = True
        broker = Broker()
        self.args['import_broker'] = broker
        def session(**kwargs):
            self.assertIn('import_public_project', {tool['name'] for tool in kwargs['tools']})
            self.assertEqual(kwargs['dispatch']('import_public_project', {'action': 'status'})['content'][0]['text'], 'started')
            raise PersonalTransportDenied('synthetic')
        with patch.object(worker, 'PersonalCommanderPipe', return_value=self.bridge), \
             patch.object(worker, 'run_session', side_effect=session):
            self.assertEqual(worker.serve(self.raw, **self.args), 'reconnect_exhausted')
        self.assertEqual(len(broker.calls), worker.MAX_RECONNECTS)
        self.assertTrue(broker.closed)

    def test_vps_registration_is_advertised_only_with_owned_broker(self):
        class Broker:
            def __init__(self): self.calls, self.closed = [], False
            def dispatch(self, args):
                self.calls.append(args)
                return {'content': [{'type': 'text', 'text': 'plan_pass'}], 'isError': False}
            def close(self): self.closed = True
        broker = Broker()
        self.args['vps_broker'] = broker
        def session(**kwargs):
            self.assertIn('connect_original_vps_project', {tool['name'] for tool in kwargs['tools']})
            self.assertEqual(kwargs['dispatch']('connect_original_vps_project', {'mode': 'plan'})['content'][0]['text'], 'plan_pass')
            raise PersonalTransportDenied('synthetic')
        with patch.object(worker, 'PersonalCommanderPipe', return_value=self.bridge), \
             patch.object(worker, 'run_session', side_effect=session):
            self.assertEqual(worker.serve(self.raw, **self.args), 'reconnect_exhausted')
        self.assertEqual(len(broker.calls), worker.MAX_RECONNECTS)
        self.assertTrue(broker.closed)

    def test_committed_registration_reloads_after_lost_response_without_replay(self):
        class Broker:
            pending = False
            closed = False
            calls = 0
            def dispatch(self, args):
                self.calls += 1
                self.pending = True
                return {'content': [], 'isError': False}
            def reload_pending(self): return self.pending
            def close(self): self.closed = True
        broker = Broker()
        self.args['project_broker'] = broker
        def interrupted_session(**kwargs):
            self.assertIn('connect_original_windows_project', {tool['name'] for tool in kwargs['tools']})
            kwargs['dispatch']('connect_original_windows_project', {'path': 'synthetic', 'mode': 'execute'})
            raise PersonalTransportDenied('response lost')
        with patch.object(worker, 'PersonalCommanderPipe', return_value=self.bridge), \
             patch.object(worker, 'run_session', side_effect=interrupted_session) as session:
            self.assertEqual(worker.serve(self.raw, **self.args), 'reload_requested')
        self.assertEqual(session.call_count, 1)
        self.assertEqual(broker.calls, 1)
        self.assertTrue(broker.closed)

    def test_terminal_calls_use_only_the_owned_broker_and_close_it(self):
        class Broker:
            def __init__(self):
                self.calls = []
                self.closed = False
            def dispatch(self, name, args):
                self.calls.append((name, args))
                return {"content": [{"type": "text", "text": "broker"}], "isError": False}
            def close(self):
                self.closed = True
        broker = Broker()
        self.args["terminal_broker"] = broker
        states = iter((True, False))
        self.args["isolation_verified"] = lambda: next(states)
        observed = []
        def session(**kwargs):
            observed.append(kwargs["dispatch"]("start_process", {"command": "synthetic", "timeout_ms": 0}))
            self.assertIn('kill_process', {tool['name'] for tool in kwargs['tools']})
            observed.append(kwargs['dispatch']('kill_process', {'pid': 123}))
            observed.append(kwargs["dispatch"]("write_file", {}))
            raise PersonalTransportDenied("synthetic")
        with patch.object(worker, "PersonalCommanderPipe", return_value=self.bridge), \
             patch.object(worker, "run_session", side_effect=session):
            self.assertEqual(worker.serve(self.raw, **self.args), "isolation_lost")
        self.assertEqual(broker.calls, [("start_process", {"command": "synthetic", "timeout_ms": 0}),
                                        ('force_terminate', {'pid': 123})])
        self.assertEqual(observed[0]["content"][0]["text"], "broker")
        self.assertEqual(observed[1]["content"][0]["text"], "broker")
        self.assertEqual(observed[2], {"content": []})
        self.assertTrue(broker.closed)

    def test_terminal_without_broker_is_denied_without_fallback(self):
        states = iter((True, False))
        self.args["isolation_verified"] = lambda: next(states)
        observed = []
        def session(**kwargs):
            observed.append(kwargs["dispatch"]("start_process", {"command": "synthetic", "timeout_ms": 0}))
            raise PersonalTransportDenied("synthetic")
        with patch.object(worker, "PersonalCommanderPipe", return_value=self.bridge), \
             patch.object(worker, "run_session", side_effect=session):
            self.assertEqual(worker.serve(self.raw, **self.args), "isolation_lost")
        self.assertTrue(observed[0]["isError"])
        self.assertEqual(observed[0]["content"][0]["text"], "H454_PERSONAL_TERMINAL_UNAVAILABLE")

    def test_trusted_isolated_bridge_factory_is_used_and_closed(self):
        calls = []
        def factory(process, roots):
            calls.append((process, roots))
            return self.bridge
        self.args["bridge_factory"] = factory
        states = iter((True, False))
        self.args["isolation_verified"] = lambda: next(states)
        with patch.object(worker, "run_session", side_effect=PersonalTransportDenied("synthetic")):
            self.assertEqual(worker.serve(self.raw, **self.args), "isolation_lost")
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][1], list(config.PERSONAL_ROOTS.values()))
        self.assertTrue(self.bridge.closed)

    def test_yfc_profile_supplies_only_its_bound_root_to_the_bridge(self):
        self.raw = config.prepare_config(Paired("windows-personal", DEVICE, TOKEN,
            "wss://hermes.mikemoore.top/ws"), owner_sid=SID, release_sha="d" * 40,
            ca=CA, bundle_sha256=BUNDLE, now=1000, profile="yfc-dev", seal=lambda *_a, **_k: b"s" * 64)
        calls = []
        self.args["bridge_factory"] = lambda _process, roots: calls.append(roots) or self.bridge
        states = iter((True, False))
        self.args["isolation_verified"] = lambda: next(states)
        with patch.object(worker, "run_session", side_effect=PersonalTransportDenied("synthetic")):
            self.assertEqual(worker.serve(self.raw, **self.args), "isolation_lost")
        self.assertEqual(calls, [[r"D:\Pet-projects\yfc-dev"]])

    def test_owner_project_roots_reach_the_bridge_only_after_unseal(self):
        roots = (r'D:\Pet-projects\yfc-dev', r'D:\Pet-projects\hermes')
        self.raw = config.prepare_config(Paired('windows-personal', DEVICE, TOKEN,
            'wss://hermes.mikemoore.top/ws'), owner_sid=SID, release_sha='d' * 40,
            ca=CA, bundle_sha256=BUNDLE, now=1000, profile='owner-projects', roots=roots,
            seal=lambda *_args, **_kwargs: b's' * 64)
        calls = []
        self.args['bridge_factory'] = lambda _process, selected: calls.append(selected) or self.bridge
        states = iter((True, False))
        self.args['isolation_verified'] = lambda: next(states)
        with patch.object(worker, 'run_session', side_effect=PersonalTransportDenied('synthetic')):
            self.assertEqual(worker.serve(self.raw, **self.args), 'isolation_lost')
        self.assertEqual(calls, [list(roots)])

    def test_failed_bridge_construction_closes_owned_isolated_process(self):
        class OwnedProcess:
            closed = False
            def close(self):
                self.closed = True
        process = OwnedProcess()
        self.args["start_dispatcher"] = lambda: process
        self.args["bridge_factory"] = lambda *_args: (_ for _ in ()).throw(ValueError("synthetic"))
        with self.assertRaises(worker.PersonalWorkerDenied):
            worker.serve(self.raw, **self.args)
        self.assertTrue(process.closed)


if __name__ == "__main__":
    unittest.main()
