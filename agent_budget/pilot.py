"""Bounded offline/live model contract for the Hermes quality pilot.

The default path is local mock-only. The live path requires an explicit owner
flag, a separate account-status attestation, and the fixed free-only model.
There is no retry, fallback, parallel execution, tool call or publication.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
import time
from collections.abc import Callable, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import (
    HTTPRedirectHandler,
    Request,
    build_opener,
    ProxyHandler,
)

from ops_watch.advisor_comparison import rules_assessment
from ops_watch.incident_advisor import (
    AdvisorInputError,
    AdvisorOutputError,
    PILOT_OPS_SCENARIOS,
    SCENARIOS,
    build_prompt,
    evaluate_result,
    mock_result,
    prepare_context,
    validate_result,
)
from research_scout.pilot_cases import CASES as RESEARCH_CASES
from research_scout.review_draft import ReviewDraftError, build_draft


PRIMARY_MODEL = "@cf/openai/gpt-oss-20b"
ACCOUNT_STATUS_SCHEMA = "hermes-cloudflare-account-status-v1"
RESULT_SCHEMA = "hermes-ai-pilot-result-v1"
MAX_CASES_PER_RUN = 3
MAX_CALLS_PER_CASE = 1
MAX_DAILY_LOCAL_CALLS = 3
MAX_INPUT_BYTES = 16_384
MAX_OUTPUT_BYTES = 32_768
MAX_OUTPUT_TOKENS = 768
TIMEOUT_SECONDS = 45
FREE_DAILY_NEURONS = 10_000
QUOTA_RESERVE_NEURONS = 1_000
UNKNOWN = "UNKNOWN"
INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"

CASE_PREFIXES = ("ops:", "research:")
RESEARCH_FIELDS = (
    "study_type",
    "population",
    "sample_size",
    "intervention",
    "control",
    "main_results",
    "subjective_outcomes",
    "objective_outcomes",
    "limitations",
    "correction_status",
    "practical_significance",
)
RESEARCH_OUTPUT_KEYS = frozenset({
    "status",
    *RESEARCH_FIELDS,
    "uncertainty",
    "identifiers",
    "primary_sources",
    "evidence_basis",
})
UNKNOWN_VALUES = frozenset({UNKNOWN, INSUFFICIENT_EVIDENCE})
HASH = re.compile(r"[0-9a-f]{64}\Z")
ACCOUNT_ID = re.compile(r"[0-9a-f]{32}\Z", re.IGNORECASE)
TOKEN = re.compile(r"[A-Za-z0-9._-]{20,256}\Z")
UNSAFE_RESEARCH_OUTPUT = re.compile(
    r"(?:bearer\s+|api[_-]?key|private[_-]?key|password\s*=|secret\s*=|"
    r"назнач(?:ить|ьте)|лечить|курс(?:а|ом)?\s+препарат|гарантирован\w*\s+эффект)",
    re.IGNORECASE,
)


class PilotError(ValueError):
    """Sanitized refusal; never contains a token or provider response body."""


def _reject_duplicate_fields(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise PilotError("duplicate_json_key")
        result[key] = value
    return result


def _parse_json(raw: bytes | str) -> object:
    try:
        return json.loads(raw, object_pairs_hook=_reject_duplicate_fields)
    except PilotError:
        raise
    except (UnicodeError, json.JSONDecodeError):
        raise PilotError("invalid_json") from None


def _timestamp(value: object, name: str) -> str:
    if type(value) is not str or len(value) > 40:
        raise PilotError(f"{name}_invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise PilotError(f"{name}_invalid") from None
    if parsed.tzinfo is None:
        raise PilotError(f"{name}_timezone_required")
    return parsed.astimezone(UTC).isoformat().replace("+00:00", "Z")


def load_account_status(path: Path) -> dict[str, object]:
    """Load owner-supplied non-secret account proof; no network is used."""
    if not isinstance(path, Path) or path.is_symlink() or not path.is_file():
        raise PilotError("account_status_unavailable")
    try:
        raw = path.read_bytes()
    except OSError:
        raise PilotError("account_status_unavailable") from None
    if len(raw) > 16_384:
        raise PilotError("account_status_oversize")
    value = _parse_json(raw)
    expected = {
        "schema",
        "plan",
        "account_id_sha256",
        "model",
        "daily_neurons_remaining",
        "ai_gateway_unified_billing",
        "checked_at",
    }
    if type(value) is not dict or set(value) != expected:
        raise PilotError("account_status_schema_invalid")
    if value["schema"] != ACCOUNT_STATUS_SCHEMA or value["plan"] != "WORKERS_FREE":
        raise PilotError("account_free_not_confirmed")
    fingerprint = value["account_id_sha256"]
    if type(fingerprint) is not str or HASH.fullmatch(fingerprint.lower()) is None:
        raise PilotError("account_fingerprint_invalid")
    if value["model"] != PRIMARY_MODEL:
        raise PilotError("account_model_mismatch")
    remaining = value["daily_neurons_remaining"]
    if type(remaining) is not int or not 0 <= remaining <= FREE_DAILY_NEURONS:
        raise PilotError("account_quota_invalid")
    if remaining < QUOTA_RESERVE_NEURONS:
        raise PilotError("account_quota_reserve_not_available")
    if value["ai_gateway_unified_billing"] is not False:
        raise PilotError("paid_gateway_not_allowed")
    _timestamp(value["checked_at"], "checked_at")
    return value


def _validate_base_url(value: str, *, account_status: Mapping[str, object]) -> str:
    if type(value) is not str or len(value) > 180:
        raise PilotError("cloudflare_base_url_invalid")
    try:
        parts = urlsplit(value)
        account_id = parts.path.split("/")[4]
    except (IndexError, ValueError):
        raise PilotError("cloudflare_base_url_invalid") from None
    if (
        parts.scheme != "https"
        or parts.hostname != "api.cloudflare.com"
        or parts.port not in (None, 443)
        or parts.username is not None
        or parts.password is not None
        or parts.query
        or parts.fragment
        or parts.path != f"/client/v4/accounts/{account_id}/ai/v1"
        or ACCOUNT_ID.fullmatch(account_id) is None
    ):
        raise PilotError("cloudflare_base_url_not_allowlisted")
    if hashlib.sha256(account_id.lower().encode("ascii")).hexdigest() != account_status["account_id_sha256"].lower():
        raise PilotError("cloudflare_account_mismatch")
    return value.rstrip("/")


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *_: object, **__: object) -> None:
        raise PilotError("provider_redirect_denied")


@dataclass(frozen=True)
class ModelResponse:
    content: str
    http_status: int | None
    attempts: int
    duration_seconds: float
    input_tokens: int | None = None
    output_tokens: int | None = None
    provider_neurons: int | None = None
    provider_cost_usd: float | None = None


class LocalMockProvider:
    """Same content contract as live provider, with zero network and billing."""

    def __init__(self) -> None:
        self.calls = 0

    def complete(self, _: str, response_factory: Callable[[], str]) -> ModelResponse:
        if self.calls >= MAX_CALLS_PER_CASE:
            raise PilotError("model_call_limit_exceeded")
        started = time.perf_counter()
        self.calls += 1
        content = response_factory()
        if type(content) is not str or len(content.encode("utf-8")) > MAX_OUTPUT_BYTES:
            raise PilotError("mock_output_oversize")
        return ModelResponse(
            content=content,
            http_status=None,
            attempts=1,
            duration_seconds=round(time.perf_counter() - started, 6),
        )


class CloudflareFreeProvider:
    """One fixed OpenAI-compatible request to the verified Cloudflare account."""

    def __init__(
        self,
        *,
        token: str,
        base_url: str,
        account_status: Mapping[str, object],
        opener: Any = None,
    ) -> None:
        if type(token) is not str or TOKEN.fullmatch(token) is None:
            raise PilotError("cloudflare_token_invalid")
        self.base_url = _validate_base_url(base_url, account_status=account_status)
        self.token = token
        self.opener = opener or build_opener(ProxyHandler({}), _NoRedirect())
        self.calls = 0

    @classmethod
    def from_environment(cls, account_status: Mapping[str, object]) -> "CloudflareFreeProvider":
        token = os.environ.get("CLOUDFLARE_WORKERS_AI_API_TOKEN", "")
        base_url = os.environ.get("CLOUDFLARE_WORKERS_AI_BASE_URL", "")
        return cls(token=token, base_url=base_url, account_status=account_status)

    def complete(self, prompt: str) -> ModelResponse:
        if self.calls >= MAX_CALLS_PER_CASE:
            raise PilotError("model_call_limit_exceeded")
        if type(prompt) is not str or not prompt.strip():
            raise PilotError("prompt_invalid")
        encoded_prompt = prompt.encode("utf-8")
        if len(encoded_prompt) > MAX_INPUT_BYTES:
            raise PilotError("prompt_oversize")
        self.calls += 1
        body = json.dumps(
            {
                "model": PRIMARY_MODEL,
                "messages": [
                    {
                        "role": "system",
                        "content": (
                            "Верни только JSON. Не выдумывай факты, идентификаторы "
                            "или выполненные действия. Не вызывай инструменты."
                        ),
                    },
                    {"role": "user", "content": prompt},
                ],
                "max_tokens": MAX_OUTPUT_TOKENS,
                "temperature": 0,
                "stream": False,
                "options": {"rejectIfBusy": True},
            },
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        request = Request(
            self.base_url + "/chat/completions",
            data=body,
            headers={
                "Authorization": f"Bearer {self.token}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            method="POST",
        )
        started = time.perf_counter()
        try:
            with self.opener.open(request, timeout=TIMEOUT_SECONDS) as response:
                status = getattr(response, "status", None)
                if type(status) is not int:
                    raise PilotError("provider_status_unobserved")
                raw = response.read(MAX_OUTPUT_BYTES + 1)
            duration = round(time.perf_counter() - started, 6)
            if status != 200:
                raise PilotError(f"provider_http_{status}")
            if len(raw) > MAX_OUTPUT_BYTES:
                raise PilotError("provider_output_oversize")
            payload = _parse_json(raw)
            if type(payload) is not dict or payload.get("success") is False:
                raise PilotError("provider_response_invalid")
            choices = payload.get("choices")
            if type(choices) is not list or not choices or type(choices[0]) is not dict:
                raise PilotError("provider_choices_invalid")
            message = choices[0].get("message")
            content = message.get("content") if type(message) is dict else None
            if type(content) is not str or not content.strip():
                raise PilotError("provider_content_invalid")
            usage = payload.get("usage")
            usage = usage if type(usage) is dict else {}
            return ModelResponse(
                content=content,
                http_status=200,
                attempts=1,
                duration_seconds=duration,
                input_tokens=_counter(usage, "prompt_tokens", "input_tokens"),
                output_tokens=_counter(usage, "completion_tokens", "output_tokens"),
                provider_neurons=_counter(usage, "neurons", "neuron_count"),
                provider_cost_usd=_money(usage.get("cost_usd")),
            )
        except HTTPError as exc:
            raise PilotError(f"provider_http_{exc.code}") from None
        except URLError:
            raise PilotError("provider_unavailable") from None
        except TimeoutError:
            raise PilotError("provider_timeout") from None
        except PilotError:
            raise
        except (OSError, ValueError):
            raise PilotError("provider_unavailable") from None


def _counter(data: Mapping[str, object], *names: str) -> int | None:
    for name in names:
        value = data.get(name)
        if value is None:
            continue
        if type(value) is not int or not 0 <= value <= 1_000_000:
            return None
        return value
    return None


def _money(value: object) -> float | None:
    if value is None:
        return None
    if type(value) not in (int, float) or value < 0:
        return None
    return float(value)


def case_names() -> list[str]:
    return [
        *(f"ops:{name}" for name in PILOT_OPS_SCENARIOS),
        *(f"research:{name}" for name in RESEARCH_CASES),
    ]


def _split_case(name: str) -> tuple[str, str]:
    if type(name) is not str or not any(name.startswith(prefix) for prefix in CASE_PREFIXES):
        raise PilotError("case_name_invalid")
    task, case_id = name.split(":", 1)
    if not case_id:
        raise PilotError("case_name_invalid")
    if task == "ops" and case_id not in SCENARIOS:
        raise PilotError("ops_case_unknown")
    if task == "research" and case_id not in RESEARCH_CASES:
        raise PilotError("research_case_unknown")
    return task, case_id


def _research_prompt(draft: Mapping[str, object]) -> str:
    payload = json.dumps(draft, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    if len(payload.encode("utf-8")) > MAX_INPUT_BYTES:
        raise PilotError("research_input_oversize")
    return (
        "Ты — Research Scout Hermes. Доступны только библиографические metadata, "
        "а не полный текст статьи. Для каждого неизвестного поля верни UNKNOWN или "
        "INSUFFICIENT_EVIDENCE. Не выдумывай DOI, PMID, выборку, тип исследования, "
        "результаты, исправления или практические рекомендации. Верни один JSON без markdown.\n"
        "BEGIN_BIBLIOGRAPHIC_METADATA\n" + payload +
        "\nEND_BIBLIOGRAPHIC_METADATA\n"
        "Обязательные поля: status, study_type, population, sample_size, intervention, "
        "control, main_results, subjective_outcomes, objective_outcomes, limitations, "
        "correction_status, practical_significance, uncertainty, identifiers, "
        "primary_sources, evidence_basis."
    )


def _research_mock(draft: Mapping[str, object]) -> dict[str, object]:
    identifiers = draft["identifiers"]
    return {
        "status": INSUFFICIENT_EVIDENCE,
        **{field: UNKNOWN for field in RESEARCH_FIELDS},
        "uncertainty": "high",
        "identifiers": identifiers,
        "primary_sources": [draft["source_link"]],
        "evidence_basis": "bibliographic_metadata_only",
    }


def validate_research_result(raw: str | Mapping[str, object], draft: Mapping[str, object]) -> dict[str, object]:
    value = _parse_json(raw) if isinstance(raw, str) else dict(raw)
    if type(value) is not dict or set(value) != RESEARCH_OUTPUT_KEYS:
        raise PilotError("research_output_schema_invalid")
    if value["status"] not in {INSUFFICIENT_EVIDENCE, "MANUAL_REVIEW_REQUIRED"}:
        raise PilotError("research_status_invalid")
    if value["uncertainty"] not in {"high", "medium", "low"}:
        raise PilotError("research_uncertainty_invalid")
    if value["evidence_basis"] != "bibliographic_metadata_only":
        raise PilotError("research_evidence_basis_invalid")
    for field in RESEARCH_FIELDS:
        item = value[field]
        if type(item) is not str or not item.strip() or len(item) > 2_000:
            raise PilotError(f"research_{field}_invalid")
        if any(ord(char) < 32 or ord(char) == 127 for char in item):
            raise PilotError(f"research_{field}_invalid")
        if UNSAFE_RESEARCH_OUTPUT.search(item):
            raise PilotError("research_unsafe_output")
    identifiers = value["identifiers"]
    if type(identifiers) is not dict or set(identifiers) != {"record_id", "pmid", "doi"}:
        raise PilotError("research_identifiers_invalid")
    if identifiers != draft["identifiers"]:
        raise PilotError("research_identifier_not_grounded")
    links = value["primary_sources"]
    allowed = {draft["source_link"]}
    if type(links) is not list or not 1 <= len(links) <= 2 or any(link not in allowed for link in links):
        raise PilotError("research_sources_not_grounded")
    return value


def _research_quality(result: Mapping[str, object], draft: Mapping[str, object]) -> dict[str, object]:
    unknown_discipline = all(result[field] in UNKNOWN_VALUES for field in RESEARCH_FIELDS)
    return {
        "identifiers_match": result["identifiers"] == draft["identifiers"],
        "primary_sources_grounded": result["primary_sources"] == [draft["source_link"]],
        "unknown_when_metadata_only": unknown_discipline,
        "scientific_accuracy": "NOT_ASSESSABLE_FROM_BIBLIOGRAPHIC_METADATA",
        "hallucination_count": 0 if unknown_discipline else "NOT_RELIABLY_COUNTED",
        "correction_handling": "NOT_ASSESSABLE_FROM_BIBLIOGRAPHIC_METADATA",
        "expert_review": "NOT_RUN",
    }


def _metrics(response: ModelResponse, *, preparation: float, validation: float, formation: float, process: float) -> dict[str, object]:
    if process > 205:
        raise PilotError("pilot_timeout")
    metrics = {
        "input_preparation_seconds": round(preparation, 6),
        "docker_startup_seconds": "NOT_RUN",
        "hermes_initialization_seconds": "NOT_RUN",
        "provider_response_seconds": response.duration_seconds,
        "json_validation_seconds": round(validation, 6),
        "result_formation_seconds": round(formation, 6),
        "process_elapsed_seconds": round(process, 6),
        "attempts": response.attempts,
        "input_tokens": response.input_tokens,
        "output_tokens": response.output_tokens,
        "provider_neurons": response.provider_neurons,
        "provider_cost_usd": response.provider_cost_usd,
        "http_status": response.http_status,
    }
    # Keep the existing budget validator as the shared metrics boundary.
    from agent_budget.policy import verify_metrics

    verify_metrics({
        "duration_seconds": process,
        "attempts": response.attempts,
        "input_tokens": response.input_tokens,
        "output_tokens": response.output_tokens,
        "provider_neurons": response.provider_neurons,
        "provider_cost_usd": response.provider_cost_usd,
        "http_status": response.http_status,
    })
    return metrics


def _prepared_case(name: str) -> tuple[str, str, str, dict[str, object], str, Callable[[], str]]:
    task, case_id = _split_case(name)
    if task == "ops":
        context = prepare_context(SCENARIOS[case_id])
        return task, case_id, "synthetic", context, build_prompt(context), lambda: json.dumps(
            mock_result(context), ensure_ascii=False, sort_keys=True
        )
    draft = build_draft(RESEARCH_CASES[case_id]["candidate"])
    return task, case_id, "public_bibliographic_metadata", draft, _research_prompt(draft), lambda: json.dumps(
        _research_mock(draft), ensure_ascii=False, sort_keys=True
    )


def _rejected_record(name: str, reason: str) -> dict[str, object]:
    return {
        "schema": RESULT_SCHEMA,
        "case": name,
        "task": name.split(":", 1)[0] if ":" in name else "UNKNOWN",
        "status": "REJECTED",
        "model_execution": "NOT_RUN",
        "reason": reason,
        "model_calls": 0,
        "metrics": {
            "docker_startup_seconds": "NOT_RUN",
            "hermes_initialization_seconds": "NOT_RUN",
            "provider_response_seconds": "NOT_RUN",
        },
    }


def _blocked_after_response(
    *,
    name: str,
    task: str,
    provenance: str,
    response: ModelResponse,
    reason: str,
    preparation: float,
    validation: float,
    process: float,
) -> dict[str, object]:
    return {
        "schema": RESULT_SCHEMA,
        "case": name,
        "task": task,
        "provenance": provenance,
        "status": "BLOCKED",
        "model_execution": "LIVE_OBSERVED_FAILURE",
        "reason": reason,
        "model_calls": 1,
        "metrics": {
            "input_preparation_seconds": round(preparation, 6),
            "docker_startup_seconds": "NOT_RUN",
            "hermes_initialization_seconds": "NOT_RUN",
            "provider_response_seconds": response.duration_seconds,
            "json_validation_seconds": round(validation, 6),
            "result_formation_seconds": 0,
            "process_elapsed_seconds": round(process, 6),
            "attempts": response.attempts,
            "input_tokens": response.input_tokens,
            "output_tokens": response.output_tokens,
            "provider_neurons": response.provider_neurons,
            "provider_cost_usd": response.provider_cost_usd,
            "http_status": response.http_status,
        },
    }


def _run_case(name: str, *, engine: str, provider: LocalMockProvider | CloudflareFreeProvider) -> dict[str, object]:
    started = time.perf_counter()
    prep_started = time.perf_counter()
    try:
        task, case_id, provenance, context, prompt, mock_factory = _prepared_case(name)
    except (AdvisorInputError, ReviewDraftError, PilotError) as exc:
        return _rejected_record(name, str(exc))
    preparation = time.perf_counter() - prep_started
    try:
        if engine == "mock":
            response = provider.complete(prompt, mock_factory)  # type: ignore[arg-type]
        else:
            response = provider.complete(prompt)  # type: ignore[union-attr]
    except PilotError as exc:
        return {
            "schema": RESULT_SCHEMA,
            "case": name,
            "task": task,
            "provenance": provenance,
            "status": "BLOCKED",
            "model_execution": "LIVE_OBSERVED_FAILURE" if engine == "live" else "MOCK_ONLY",
            "reason": str(exc),
            "model_calls": getattr(provider, "calls", 0),
            "metrics": {
                "input_preparation_seconds": round(preparation, 6),
                "docker_startup_seconds": "NOT_RUN",
                "hermes_initialization_seconds": "NOT_RUN",
                "provider_response_seconds": "NOT_OBSERVED",
                "process_elapsed_seconds": round(time.perf_counter() - started, 6),
                "attempts": getattr(provider, "calls", 0),
                "http_status": "NOT_OBSERVED",
            },
        }
    validation_started = time.perf_counter()
    try:
        if task == "ops":
            result = validate_result(response.content, context)
            quality = evaluate_result(context, result)
            reference = rules_assessment(context)
        else:
            result = validate_research_result(response.content, context)
            quality = _research_quality(result, context)
            reference = RESEARCH_CASES[case_id]["manual_reference"]
    except (AdvisorOutputError, PilotError) as exc:
        return {
            "schema": RESULT_SCHEMA,
            "case": name,
            "task": task,
            "provenance": provenance,
            "status": "REJECTED",
            "model_execution": "LIVE_OBSERVED" if engine == "live" else "MOCK_ONLY",
            "reason": str(exc),
            "model_calls": 1,
            "metrics": {
                "input_preparation_seconds": round(preparation, 6),
                "provider_response_seconds": response.duration_seconds,
                "json_validation_seconds": round(time.perf_counter() - validation_started, 6),
                "docker_startup_seconds": "NOT_RUN",
                "hermes_initialization_seconds": "NOT_RUN",
                "process_elapsed_seconds": round(time.perf_counter() - started, 6),
                "http_status": response.http_status,
            },
        }
    validation = time.perf_counter() - validation_started
    if engine == "live" and response.provider_cost_usd is None:
        return _blocked_after_response(
            name=name,
            task=task,
            provenance=provenance,
            response=response,
            reason="COST_NOT_VERIFIED",
            preparation=preparation,
            validation=validation,
            process=time.perf_counter() - started,
        )
    if engine == "live" and response.provider_cost_usd != 0:
        return _blocked_after_response(
            name=name,
            task=task,
            provenance=provenance,
            response=response,
            reason="STOP_NONZERO_COST",
            preparation=preparation,
            validation=validation,
            process=time.perf_counter() - started,
        )
    formation_started = time.perf_counter()
    record = {
        "schema": RESULT_SCHEMA,
        "case": name,
        "task": task,
        "provenance": provenance,
        "status": "PASS",
        "model": PRIMARY_MODEL if engine == "live" else "local-deterministic-mock",
        "model_execution": "LIVE_OBSERVED" if engine == "live" else "MOCK_ONLY",
        "model_calls": 1,
        "rules_or_manual_reference": reference,
        "model_result": result,
        "quality": quality,
    }
    formation = time.perf_counter() - formation_started
    record["metrics"] = _metrics(
        response,
        preparation=preparation,
        validation=validation,
        formation=formation,
        process=time.perf_counter() - started,
    )
    return record


def _load_state(path: Path) -> dict[str, object]:
    today = datetime.now(UTC).date().isoformat()
    if path.is_symlink():
        raise PilotError("pilot_state_symlink")
    if not path.exists():
        return {"date": today, "calls": 0}
    value = _parse_json(path.read_bytes())
    if type(value) is not dict or set(value) != {"date", "calls"}:
        raise PilotError("pilot_state_invalid")
    if value["date"] != today or type(value["calls"]) is not int or value["calls"] < 0:
        return {"date": today, "calls": 0}
    return value


def _write_json_atomic(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise PilotError("pilot_output_symlink")
    handle, temporary = tempfile.mkstemp(prefix=path.name + ".", dir=path.parent)
    try:
        with os.fdopen(handle, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(value, stream, ensure_ascii=False, sort_keys=True)
            stream.write("\n")
        os.replace(temporary, path)
    except OSError:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise PilotError("pilot_output_unavailable") from None


@contextmanager
def _run_lock(path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    lock = path.with_name(path.name + ".lock")
    try:
        with lock.open("x", encoding="ascii") as stream:
            stream.write("active")
    except FileExistsError:
        raise PilotError("pilot_already_running") from None
    try:
        yield
    finally:
        try:
            lock.unlink()
        except OSError:
            pass


def _save_results(path: Path, records: list[dict[str, object]]) -> None:
    if path.is_symlink() or (path.exists() and path.stat().st_size > 2_000_000):
        raise PilotError("pilot_results_invalid")
    existing: list[object] = []
    if path.exists():
        value = _parse_json(path.read_bytes())
        if type(value) is not list:
            raise PilotError("pilot_results_invalid")
        existing = value
    _write_json_atomic(path, [*existing, *records])


def run_pilot(
    *,
    engine: str,
    cases: list[str],
    output: Path | None = None,
    state: Path | None = None,
    owner_approved: bool = False,
    account_status: Path | None = None,
) -> list[dict[str, object]]:
    if engine not in {"mock", "live"}:
        raise PilotError("engine_invalid")
    if not cases:
        raise PilotError("cases_required")
    if len(set(cases)) != len(cases):
        raise PilotError("duplicate_case")
    if engine == "live":
        if len(cases) > MAX_CASES_PER_RUN:
            raise PilotError("live_case_limit_exceeded")
        if owner_approved is not True or os.environ.get("HERMES_AI_LIVE_APPROVED") != "1":
            raise PilotError("live_owner_approval_required")
        if account_status is None:
            raise PilotError("account_status_required")
        attestation = load_account_status(account_status)
        provider_factory: Callable[[], LocalMockProvider | CloudflareFreeProvider] = lambda: CloudflareFreeProvider.from_environment(attestation)
        state_path = state or Path(".artifacts/hermes-ai-pilot/state.json")
        state_value = _load_state(state_path)
        if int(state_value["calls"]) + len(cases) > MAX_DAILY_LOCAL_CALLS:
            raise PilotError("local_daily_call_limit_exceeded")
    else:
        provider_factory = LocalMockProvider
        state_path = None
        state_value = None

    output_path = output or Path(".artifacts/hermes-ai-pilot/results.json")
    with _run_lock(state_path or output_path):
        records: list[dict[str, object]] = []
        for name in cases:
            record = _run_case(name, engine=engine, provider=provider_factory())
            records.append(record)
            if engine == "live" and state_path is not None and state_value is not None:
                state_value["calls"] = int(state_value["calls"]) + int(record.get("model_calls", 0))
                _write_json_atomic(state_path, state_value)
                if int(record.get("model_calls", 0)) > 0 and record.get("status") != "PASS":
                    break
        if output is not None or engine == "live":
            _save_results(output_path, records)
        return records


def status() -> dict[str, object]:
    return {
        "account_status": "ACCOUNT_FREE_UNVERIFIED",
        "primary_model": PRIMARY_MODEL,
        "daily_free_allocation_neurons": FREE_DAILY_NEURONS,
        "live_default": False,
        "max_cases_per_live_run": MAX_CASES_PER_RUN,
        "max_calls_per_case": MAX_CALLS_PER_CASE,
        "automatic_retries": 0,
        "automatic_fallback": False,
        "background_execution": False,
        "network_calls_performed_by_status": 0,
    }


def prepare_live_instructions() -> str:
    return (
        "Живой пилот не выполнен. Владелец должен отдельно подтвердить Workers Free "
        "в Cloudflare Dashboard, отсутствие AI Gateway Unified Billing и остаток квоты, "
        "создать локальный account-status JSON без токена, затем явно задать "
        "HERMES_AI_LIVE_APPROVED=1 и передать --owner-approved. Токен не вводится в чат."
    )
