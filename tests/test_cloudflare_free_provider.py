"""Free-only Cloudflare Workers AI provider contract without real credentials."""

from __future__ import annotations

import importlib.util
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
PROVIDER = ROOT / "plugins/cloudflare-workers-ai-free/__init__.py"


def load_plugin() -> tuple[types.ModuleType, object]:
    """Model minimal Hermes extension API without importing network code."""
    registry: list[object] = []

    class StubProfile:
        def __init__(self, **kwargs: object) -> None:
            self.__dict__.update(kwargs)

    providers = types.ModuleType("providers")
    base = types.ModuleType("providers.base")
    providers.__path__ = []
    providers.register_provider = registry.append
    base.ProviderProfile = StubProfile
    spec = importlib.util.spec_from_file_location("_cloudflare_free_test_plugin", PROVIDER)
    assert spec and spec.loader
    plugin = importlib.util.module_from_spec(spec)
    with patch.dict(sys.modules, {"providers": providers, "providers.base": base}):
        spec.loader.exec_module(plugin)
    if len(registry) != 1:
        raise AssertionError("Provider must register once")
    return plugin, registry[0]


class CloudflareFreeProfileTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.plugin, cls.profile = load_plugin()

    def test_only_free_model_is_exposed(self) -> None:
        self.assertEqual(self.profile.fallback_models, ("@cf/openai/gpt-oss-20b",))
        self.assertEqual(
            set(self.profile.model_capabilities),
            {"@cf/openai/gpt-oss-20b"},
        )
        self.assertEqual(self.profile.default_aux_model, "@cf/openai/gpt-oss-20b")

    def test_paid_or_unknown_model_rejected_before_issuing_request(self) -> None:
        for model in ("@cf/moonshotai/kimi-k2.6", "@cf/deepseek-ai/deepseek-v4-pro-0813", "", None):
            with self.subTest(model=model):
                with self.assertRaises(ValueError):
                    self.profile.build_api_kwargs_extras(model=model, reasoning_config={"enabled": True, "effort": "low"})

    def test_hermes_reasoning_maps_to_model_supported_values(self) -> None:
        check = self.profile.build_api_kwargs_extras
        self.assertEqual(check(model=self.plugin.MODEL, reasoning_config={"enabled": False}), ({}, {"reasoning_effort": "low"}))
        self.assertEqual(check(model=self.plugin.MODEL, reasoning_config={"enabled": True, "effort": "medium"}), ({}, {"reasoning_effort": "medium"}))
        self.assertEqual(check(model=self.plugin.MODEL, reasoning_config={"enabled": True, "effort": "xhigh"}), ({}, {"reasoning_effort": "high"}))

    def test_free_quota_or_entitlement_refusal_never_auto_fallbacks(self) -> None:
        for status in (402, 403, 429):
            with self.subTest(status=status):
                verdict = self.profile.classify_api_error(None, status_code=status, message="Free plan quota exceeded")
                self.assertFalse(verdict["retryable"])
                self.assertFalse(verdict["should_fallback"])

    def test_no_broad_cloudflare_or_editorial_secret_variable(self) -> None:
        self.assertEqual(self.profile.env_vars, (
            "CLOUDFLARE_WORKERS_AI_API_TOKEN",
            "CLOUDFLARE_WORKERS_AI_BASE_URL",
        ))

    def test_no_network_or_untrusted_code_execution_in_provider(self) -> None:
        code = PROVIDER.read_text(encoding="utf-8")
        for forbidden in ("import subprocess", "import requests", "import socket", "exec(", "eval(", "Popen(", "os.system(", "httpx."):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, code)

    def test_provider_registers_with_expected_hermes_name(self) -> None:
        self.assertEqual(self.profile.name, "workers-ai")
        self.assertEqual(self.profile.get_model_context_length(self.plugin.MODEL), 128_000)
        self.assertIsNone(self.profile.get_model_context_length("@cf/moonshotai/kimi-k2.6"))


class InstallerSafetyTests(unittest.TestCase):
    def test_no_secret_or_service_changes_during_staging(self) -> None:
        code = (ROOT / "deploy/install-cloudflare-free.sh").read_text(encoding="utf-8")
        self.assertIn("config.yaml", code)
        self.assertIn("refusing to overwrite", code)
        self.assertIn("hermes-agent", code)
        for forbidden in ("systemctl enable", "systemctl restart", "docker run", "curl ", "CLOUDFLARE_WORKERS_AI_API_TOKEN=", "/etc/hermes/", "/var/lib/hermes/state.json"):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, code)


if __name__ == "__main__":
    unittest.main()
