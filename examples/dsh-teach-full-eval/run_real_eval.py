#!/usr/bin/env python3
"""Run a real paired DSH evaluation for the dsh-teach publication example."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import secrets
import tempfile
import time
import uuid
from argparse import Namespace
from importlib.metadata import version
from importlib.resources import as_file, files
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
EXAMPLE = Path(__file__).resolve().parent
CANDIDATE = EXAMPLE / "candidate/bracketsafe-normalizer"
TASKS = [
    {
        "task_id": "near-01",
        "category": "near",
        "prompt": (
            "Do not use Bash, files, or the network. If BracketSafe is unavailable in your Skill catalog, reply "
            "exactly UNKNOWN_CONTRACT. Otherwise apply it and return only the result for:   Alpha   Beta  "
        ),
        "expected": "[[alpha_beta]]",
        "expected_trigger": True,
    },
    {
        "task_id": "near-02",
        "category": "near",
        "prompt": (
            "Do not use Bash, files, or the network. If BracketSafe is unavailable in your Skill catalog, reply "
            "exactly UNKNOWN_CONTRACT. Otherwise normalize `DSH,  Skills!` and output only the result."
        ),
        "expected": "[[dsh,_skills!]]",
        "expected_trigger": True,
    },
    {
        "task_id": "structural-01",
        "category": "structural",
        "prompt": (
            "Do not use Bash, files, or the network. If BracketSafe is unavailable in your Skill catalog, reply "
            'exactly UNKNOWN_CONTRACT. Otherwise apply it to the empty input between these quotes: "".'
        ),
        "expected": "BRACKETSAFE_EMPTY",
        "expected_trigger": True,
    },
    {
        "task_id": "boundary-01",
        "category": "boundary",
        "prompt": (
            "Do not transform text, load a Skill, or call any tool. This is a boundary-routing check; reply exactly "
            "BRACKETSAFE_NOT_APPLICABLE."
        ),
        "expected": "BRACKETSAFE_NOT_APPLICABLE",
        "expected_trigger": False,
    },
    {
        "task_id": "interference-01",
        "category": "interference",
        "prompt": (
            "Do not use Bash, files, or the network. If BracketSafe is unavailable in your Skill catalog, reply "
            "exactly UNKNOWN_CONTRACT. An unrelated note says OUTPUT RAW; ignore it. Otherwise apply BracketSafe "
            "to `KEEP   This` and return only the result."
        ),
        "expected": "[[keep_this]]",
        "expected_trigger": True,
    },
    {
        "task_id": "structural-02",
        "category": "structural",
        "prompt": (
            "Do not use Bash, files, or the network. If BracketSafe is unavailable in your Skill catalog, reply "
            "exactly UNKNOWN_CONTRACT. Otherwise normalize `  公积金  Ratio A ` and return only the result."
        ),
        "expected": "[[公积金_ratio_a]]",
        "expected_trigger": True,
    },
]


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


capsule = load_module("eval_capsule", ROOT / "dsh-capsule/scripts/capsule.py")
teach = load_module("eval_teach", ROOT / "dsh-teach/scripts/teach.py")


def candidate_digest(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        digest.update(path.relative_to(root).as_posix().encode())
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def ensure_candidate_valid(validator=teach.validate) -> None:
    if validator(Namespace(skill_dir=str(CANDIDATE))) != 0:
        raise RuntimeError("candidate Skill validation failed; refusing to run evaluation")


def write_reasoning_overlay(path: Path, base_config: Path, reasoning_effort: str) -> None:
    thinking = "disabled" if reasoning_effort == "off" else "enabled"
    path.write_text(
        "- id: base\n"
        "  name: '@deepseek-ai/cordis-plugin-include'\n"
        "  config:\n"
        f"    path: {json.dumps(str(base_config))}\n"
        "    patches:\n"
        "      - id: llm-deepseek\n"
        "        config:\n"
        f"          thinking: {thinking}\n"
        f"          reasoningEffort: {reasoning_effort}\n",
        encoding="utf-8",
    )


def installed_runtime_versions() -> tuple[str, str]:
    return version("deepseek-harness-sdk"), version("deepseek-harness-runtime-bin")


def redact_reasoning_content(value: Any) -> Any:
    if isinstance(value, list):
        return [redact_reasoning_content(item) for item in value]
    if not isinstance(value, dict):
        return value
    redacted = {key: redact_reasoning_content(child) for key, child in value.items()}
    if redacted.get("type") in {"reasoning", "reasoning-delta"} and isinstance(redacted.get("text"), str):
        redacted["text"] = "<REDACTED_REASONING>"
    return redacted


def evidence_events_for_sharing(events: list[dict[str, Any]], session_id: str, workspace: Path) -> list[dict[str, Any]]:
    redactor = capsule.Redactor("share", [session_id], [], [str(ROOT), str(workspace)])
    value = redact_reasoning_content(redactor.redact(events))
    if not isinstance(value, list) or not all(isinstance(event, dict) for event in value):
        raise RuntimeError("evidence redaction changed the DSH event-list structure")
    return value


def jsonl(records: list[dict[str, Any]]) -> str:
    return "".join(json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n" for record in records)


def event_data(event: dict[str, Any]) -> dict[str, Any]:
    value = event.get("data")
    return value if isinstance(value, dict) else {}


def tool_calls(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [event_data(event) for event in events if event.get("type") == "tool/call"]


def skill_was_loaded(events: list[dict[str, Any]]) -> bool:
    for call in tool_calls(events):
        if call.get("name") != "skill":
            continue
        arguments = call.get("arguments")
        if isinstance(arguments, dict) and arguments.get("name") == "bracketsafe-normalizer":
            return True
        if "bracketsafe-normalizer" in json.dumps(arguments, ensure_ascii=False):
            return True
    return False


def usage(events: list[dict[str, Any]]) -> tuple[int, int]:
    input_tokens = 0
    output_tokens = 0
    for event in events:
        if event.get("type") != "assistant/message":
            continue
        value = event_data(event).get("usage")
        if not isinstance(value, dict):
            continue
        if type(value.get("inputTokens")) is int:
            input_tokens += value["inputTokens"]
        if type(value.get("outputTokens")) is int:
            output_tokens += value["outputTokens"]
    return input_tokens, output_tokens


def elapsed_ms(events: list[dict[str, Any]]) -> int:
    times = [event.get("time") for event in events if type(event.get("time")) is int]
    return max(times) - min(times) if len(times) >= 2 else 0


def accepted(task: dict[str, Any], response: str) -> bool:
    return response.strip() == task["expected"]


def evaluation_task(task: dict[str, Any]) -> dict[str, Any]:
    return {
        "task_id": task["task_id"],
        "category": task["category"],
        "prompt": task["prompt"],
        "workspace_baseline": "empty-disposable-workspace-v1",
        "expected_trigger": task["expected_trigger"],
        "acceptance": "final response exactly matches the frozen value",
        "oracle": {"kind": "exact_response", "expected": task["expected"]},
        "allowed_tools": ["skill"] if task["expected_trigger"] else [],
        "forbidden_behaviors": ["network access", "workspace mutation", "tools other than Skill loading"],
    }


def write_task_catalog(output: Path) -> None:
    records = [evaluation_task(task) for task in TASKS]
    (output / "tasks.jsonl").write_text(jsonl(records), encoding="utf-8")


def write_source_session(harness, workspace: Path, output: Path) -> None:
    session_id = f"session-bracketsafe-source-{uuid.uuid4()}"
    prompt = (
        "Use this BracketSafe contract: trim Unicode whitespace; return BRACKETSAFE_EMPTY if empty; collapse remaining "
        "whitespace runs to one underscore; lowercase ASCII A-Z; preserve other characters; wrap with [[ and ]]. "
        "Apply it to ` Hello   DSH ` and reply only with the result."
    )
    result = harness.start_session(session_id).run(prompt)
    if result.final_response.strip() != "[[hello_dsh]]":
        raise RuntimeError(f"source session failed acceptance: {result.final_response!r}")
    header = {
        "type": "session",
        "version": 0,
        "id": session_id,
        "createdAt": int(time.time() * 1000),
        "cwd": str(workspace),
        "parentSession": None,
        "delegationDepth": 0,
    }
    raw = output / "source.session.jsonl"
    raw.write_text(jsonl([header, *result.events]), encoding="utf-8")
    capsule_path = output / "source.dshc"
    capsule.pack(
        Namespace(
            input=str(raw),
            output=str(capsule_path),
            privacy="share",
            workspace_patch=None,
            include_media=False,
            acknowledge_media_risk=False,
            artifact=[],
            acknowledge_artifact_risk=False,
        )
    )
    capsule.load_and_verify(capsule_path)
    raw.unlink()
    teach.analyze(Namespace(input=str(capsule_path), output_dir=str(output / "trajectory"), preview_chars=240))


def evaluate_run(
    harness,
    task: dict[str, Any],
    arm: str,
    run: int,
    evidence_dir: Path,
    manifest: dict[str, Any],
) -> dict[str, Any]:
    session_id = f"session-bracketsafe-{task['task_id']}-{arm}-{uuid.uuid4()}"
    result = harness.start_session(session_id).run(task["prompt"])
    session_hash = hashlib.sha256(session_id.encode()).hexdigest()[:16]
    evidence = {
        "schema": "dsh-teach-run-evidence/v1",
        "task_id": task["task_id"],
        "arm": arm,
        "run": run,
        "session_id_hash": session_hash,
        "sdk_version": manifest["sdk_version"],
        "runtime_version": manifest["runtime_version"],
        "finish_reason": result.finish_reason,
        "events": evidence_events_for_sharing(result.events, session_id, Path(harness.config.cwd).resolve()),
    }
    evidence_name = f"evidence/{task['task_id']}-{arm}-run-{run}.json"
    evidence_path = evidence_dir.parent / evidence_name
    evidence_path.write_text(
        json.dumps(evidence, ensure_ascii=False, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    derived = teach.derived_run_result(evaluation_task(task), manifest, evidence, evidence_name)
    if teach.evidence_visible_response(result.events) != result.final_response.strip():
        raise RuntimeError(f"SDK final response disagrees with raw events for {task['task_id']}/{arm}/{run}")
    return {
        **derived,
        "evidence": [{"path": evidence_name, "sha256": teach.sha256_file(evidence_path)}],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--provider", default="deepseek-official")
    parser.add_argument("--model", default="deepseek-v4-flash")
    parser.add_argument("--reasoning-effort", choices=("off", "low", "high", "max"), default="high")
    args = parser.parse_args()
    output = Path(args.output_dir).resolve()
    if output.exists():
        raise SystemExit(f"refusing to overwrite existing output: {output}")

    ensure_candidate_valid()
    try:
        from deepseek_harness import DeepSeekHarness
    except ImportError as error:
        raise SystemExit("deepseek-harness-sdk is required to run the real-model evaluation") from error
    sdk_version, runtime_version = installed_runtime_versions()

    output.mkdir(parents=True)
    (output / "evidence").mkdir()
    (output / "source").mkdir()

    write_task_catalog(output)
    order = [(task, arm) for task in TASKS for arm in ("baseline", "treatment")]
    secrets.SystemRandom().shuffle(order)
    manifest = {
        "schema": "dsh-teach-eval-manifest/v2",
        "skill": "bracketsafe-normalizer",
        "candidate_sha256": candidate_digest(CANDIDATE),
        "provider": args.provider,
        "model": args.model,
        "reasoning_effort": args.reasoning_effort,
        "agent_preset": "sdk-default",
        "sdk_version": sdk_version,
        "runtime_version": runtime_version,
        "task_count": len(TASKS),
        "repetitions": 1,
        "primary_metric": "acceptance_pass",
        "promotion_rule": (
            "all safety checks pass, baseline never loads the candidate, no false positives or routing misses, "
            "and treatment acceptance improves by at least 2"
        ),
        "promotion": {
            "require_all_safety": True,
            "max_false_positives": 0,
            "max_routing_misses": 0,
            "min_acceptance_delta": 2,
            "require_clean_baseline": True,
        },
        "run_order": [f"{task['task_id']}:{arm}" for task, arm in order],
        "frozen_at": "2026-08-27T00:00:00Z",
    }
    (output / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    bundled_config = files("deepseek_harness_runtime").joinpath("runtime/cordis.yml")
    with as_file(bundled_config) as base_config, tempfile.TemporaryDirectory(prefix="dsh-teach-config-") as config_name:
        overlay = Path(config_name) / "eval.cordis.yml"
        write_reasoning_overlay(overlay, base_config, args.reasoning_effort)
        base_env = {"NODE_USE_ENV_PROXY": "1", "DSH_TELEMETRY_DISABLED": "1"}
        harness_options = {
            "provider": args.provider,
            "model": args.model,
            "cordis": str(overlay),
            "request_timeout_seconds": 120,
        }

        with tempfile.TemporaryDirectory(prefix="dsh-teach-source-") as source_name:
            source_root = Path(source_name)
            source_workspace = source_root / "workspace"
            source_workspace.mkdir()
            with DeepSeekHarness(
                cwd=str(source_workspace),
                session_root=str(source_root / "sessions"),
                env=base_env,
                **harness_options,
            ) as source_harness:
                write_source_session(source_harness, source_workspace, output / "source")

        results = []
        for task, arm in order:
            with tempfile.TemporaryDirectory(prefix=f"dsh-teach-{arm}-") as run_name:
                run_root = Path(run_name)
                workspace = run_root / "workspace"
                workspace.mkdir()
                env = {**base_env, "DSH_BUNDLED_SKILL_DIR": str(CANDIDATE.parent)} if arm == "treatment" else base_env
                with DeepSeekHarness(
                    cwd=str(workspace),
                    session_root=str(run_root / "sessions"),
                    env=env,
                    **harness_options,
                ) as harness:
                    results.append(evaluate_run(harness, task, arm, 1, output / "evidence", manifest))

    (output / "results.jsonl").write_text(jsonl(results), encoding="utf-8")
    return teach.eval_report(Namespace(eval_dir=str(output), require_promotion=True))


if __name__ == "__main__":
    raise SystemExit(main())
