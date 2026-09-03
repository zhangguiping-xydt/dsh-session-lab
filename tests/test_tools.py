from __future__ import annotations

import hashlib
import importlib.util
import json
import zipfile
from argparse import Namespace
from collections import Counter
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def load_module(name: str, relative: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    if spec is None or spec.loader is None:
        raise AssertionError(f"cannot load {relative}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


capsule = load_module("dsh_capsule", "dsh-capsule/scripts/capsule.py")
teach = load_module("dsh_teach", "dsh-teach/scripts/teach.py")
compare = load_module("dsh_time_machine", "dsh-time-machine/scripts/compare.py")
real_eval = load_module("dsh_teach_real_eval", "examples/dsh-teach-full-eval/run_real_eval.py")


def jsonl(records: list[dict]) -> str:
    return "".join(json.dumps(record, separators=(",", ":")) + "\n" for record in records)


def session_records(session_id: str, parent: str | None = "parent-session", first_text: str = "same") -> list[dict]:
    return [
        {
            "type": "session",
            "version": 0,
            "id": session_id,
            "createdAt": 1,
            "cwd": "/home/alice/project",
            "parentSession": parent,
            "seedLength": 3,
            "delegationDepth": 0,
            "origin": "https://internal.example.test/session-origin",
        },
        {"type": "turn/start", "seq": 0, "time": 1, "data": {"turn": 1}},
        {"type": "user/message", "seq": 1, "time": 2, "data": {"content": [{"type": "text", "text": first_text}]}},
        {"type": "turn/end", "seq": 2, "time": 3, "data": {"turn": 1, "reason": {"kind": "completed"}}},
        {"type": "turn/start", "seq": 3, "time": 4, "data": {"turn": 2}},
        {
            "type": "user/message",
            "seq": 4,
            "time": 5,
            "data": {
                "content": [
                    {
                        "type": "text",
                        "text": f"contact alice@example.test at https://internal.example.test/{session_id}",
                    }
                ],
                "attachmentId": "image-secret-1",
            },
        },
        {"type": "turn/end", "seq": 5, "time": 6, "data": {"turn": 2, "reason": {"kind": "completed"}}},
    ]


def write_export(path: Path, records: list[dict], member: str = "session.jsonl") -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(member, jsonl(records))
    return path


def pack_args(source: Path, output: Path) -> Namespace:
    return Namespace(
        input=str(source),
        output=str(output),
        privacy="share",
        workspace_patch=None,
        include_media=False,
        acknowledge_media_risk=False,
        artifact=[],
        acknowledge_artifact_risk=False,
    )


def test_capsule_share_aliases_paths_and_free_text(tmp_path: Path) -> None:
    structured_value = "capsule-client-secret-value"
    free_text_value = "capsule-refresh-token-value"
    records = session_records("child-secret")
    records[1]["data"]["client_secret"] = structured_value
    records[1]["data"]["note"] = f"refresh_token={free_text_value}"
    source = write_export(tmp_path / "child-secret-export.zip", records, "subagents/child-secret/session.jsonl")
    output = tmp_path / "share.dshc"

    assert capsule.pack(pack_args(source, output)) == 0

    with zipfile.ZipFile(output) as archive:
        names = archive.namelist()
        text = "\n".join(
            archive.read(name).decode("utf-8", errors="ignore") for name in names if name.endswith((".json", ".jsonl"))
        )
    assert "child-secret" not in "\n".join(names)
    assert "child-secret" not in text
    assert "alice@example.test" not in text
    assert "internal.example.test" not in text
    assert structured_value not in text
    assert free_text_value not in text
    assert "session-001" in text


def test_capsule_verify_rejects_tampered_log(tmp_path: Path) -> None:
    source = write_export(tmp_path / "source.zip", session_records("child-secret"))
    output = tmp_path / "share.dshc"
    capsule.pack(pack_args(source, output))
    tampered = tmp_path / "tampered.dshc"
    with zipfile.ZipFile(output) as original, zipfile.ZipFile(tampered, "w") as replacement:
        for info in original.infolist():
            data = original.read(info)
            if info.filename.endswith("session.jsonl"):
                data = data.replace(b"same", b"changed")
            replacement.writestr(info, data)
    with pytest.raises(ValueError, match="hash mismatch"):
        capsule.load_and_verify(tampered)


def test_named_secret_redaction_matches_quoted_json_keys() -> None:
    json_payload = '{"client_secret": "supersecretvalue123", "password":"hunter2hunter2"}'
    payload = json_payload + ' aws_secret_access_key = "AKIAlikevalue999"'
    scrubbed_by_capsule = capsule.scrub_string(payload, Counter(), False, [])
    scrubbed_by_teach = teach.PreviewRedactor([], [], []).scrub(payload)
    scrubbed_by_compare = compare.scrub(payload)
    for scrubbed in (scrubbed_by_capsule, scrubbed_by_teach, scrubbed_by_compare):
        assert "supersecretvalue123" not in scrubbed
        assert "hunter2hunter2" not in scrubbed
        assert "AKIAlikevalue999" not in scrubbed
        assert "<REDACTED>" in scrubbed

    scrubbed_json_values = (
        capsule.scrub_string(json_payload, Counter(), False, []),
        teach.PreviewRedactor([], [], []).scrub(json_payload),
        compare.scrub(json_payload),
    )
    for scrubbed_json in scrubbed_json_values:
        assert json.loads(scrubbed_json) == {
            "client_secret": "<REDACTED>",
            "password": "<REDACTED>",
        }


def test_read_member_bounds_actual_decompressed_bytes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    archive_path = tmp_path / "expansive.zip"
    with zipfile.ZipFile(archive_path, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("session.jsonl", "a" * 4096)
    monkeypatch.setattr(capsule, "MAX_ENTRY_BYTES", 1024)
    with zipfile.ZipFile(archive_path) as archive:
        with pytest.raises(ValueError, match="exceeds"):
            capsule.read_member(archive, "session.jsonl")
        with pytest.raises(ValueError, match="exceeds"):
            teach.read_member(archive, "session.jsonl", None, 1024)
        with pytest.raises(ValueError, match="exceeds"):
            compare.read_member(archive, "session.jsonl", None, 1024)


def test_read_member_budget_bounds_total_decompressed_bytes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    archive_path = tmp_path / "total.zip"
    with zipfile.ZipFile(archive_path, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("first.jsonl", "a" * 3000)
        archive.writestr("second.jsonl", "b" * 3000)
    monkeypatch.setattr(capsule, "MAX_TOTAL_BYTES", 4096)
    with zipfile.ZipFile(archive_path) as archive:
        budget = [0]
        capsule.read_member(archive, "first.jsonl", budget)
        with pytest.raises(ValueError, match="expands beyond"):
            capsule.read_member(archive, "second.jsonl", budget)


def test_teach_preview_redacts_identifiers_email_and_url(tmp_path: Path) -> None:
    source = write_export(
        tmp_path / "source.zip", session_records("child-secret"), "subagents/child-secret/session.jsonl"
    )
    output = tmp_path / "teach"
    args = Namespace(input=str(source), output_dir=str(output), preview_chars=240)

    assert teach.analyze(args) == 0
    text = (output / "trajectory.json").read_text(encoding="utf-8")
    assert "child-secret" not in text
    assert "alice@example.test" not in text
    assert "internal.example.test" not in text
    assert "session-001" in text


def test_teach_preview_redacts_nested_session_ids_and_structured_tokens(tmp_path: Path) -> None:
    nested_session = "session-nested-private-123"
    sensitive_value = "ordinarycredentialvalue123456"
    free_text_value = "ordinaryrefreshtokenvalue123456"
    records = session_records("root-session")
    records[5] = {
        "type": "tool/call",
        "seq": 4,
        "time": 5,
        "data": {
            "callId": "private-call",
            "name": "fixture",
            "arguments": {
                "parentSessionId": nested_session,
                "note": f"child={nested_session} refresh_token={free_text_value}",
                "credentials": {"access_token": sensitive_value},
            },
        },
    }
    source = write_export(tmp_path / "nested.zip", records)
    output = tmp_path / "teach"

    assert teach.analyze(Namespace(input=str(source), output_dir=str(output), preview_chars=500)) == 0

    text = (output / "trajectory.json").read_text(encoding="utf-8")
    assert nested_session not in text
    assert sensitive_value not in text
    assert free_text_value not in text
    assert "<REDACTED>" in text


def test_teach_preview_excludes_hidden_reasoning_text(tmp_path: Path) -> None:
    records = session_records("reasoning-session")
    records.append(
        {
            "type": "assistant/message",
            "seq": 6,
            "time": 7,
            "data": {
                "message": {
                    "role": "assistant",
                    "content": [
                        {"type": "reasoning", "text": "hidden-reasoning-private-value"},
                        {"type": "text", "text": "visible-answer"},
                    ],
                }
            },
        }
    )
    source = write_export(tmp_path / "reasoning.zip", records)
    output = tmp_path / "teach"

    assert teach.analyze(Namespace(input=str(source), output_dir=str(output), preview_chars=500)) == 0

    text = (output / "trajectory.json").read_text(encoding="utf-8")
    assert "hidden-reasoning-private-value" not in text
    assert "visible-answer" in text


def test_teach_rejects_archive_with_too_many_entries(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(teach, "MAX_ARCHIVE_FILES", 2)
    source = tmp_path / "many.zip"
    with zipfile.ZipFile(source, "w") as archive:
        archive.writestr("one.txt", "")
        archive.writestr("two.txt", "")
        archive.writestr("three.txt", "")
    with pytest.raises(ValueError, match="more than 2"):
        teach.load_logs(source)


def test_compare_validates_dshc_manifest(tmp_path: Path) -> None:
    source = write_export(tmp_path / "source.zip", session_records("child-secret"))
    capsule_path = tmp_path / "share.dshc"
    capsule.pack(pack_args(source, capsule_path))
    tampered = tmp_path / "tampered.dshc"
    with zipfile.ZipFile(capsule_path) as original, zipfile.ZipFile(tampered, "w") as replacement:
        for info in original.infolist():
            data = original.read(info)
            if info.filename.endswith("session.jsonl"):
                data = data.replace(b"same", b"changed")
            replacement.writestr(info, data)
    with pytest.raises(ValueError, match="hash mismatch"):
        compare.load_text(tampered, None)


def test_compare_rejects_unrelated_logs_with_no_shared_completed_prefix(tmp_path: Path) -> None:
    left = tmp_path / "left.jsonl"
    right = tmp_path / "right.jsonl"
    left.write_text(jsonl(session_records("left", parent=None, first_text="left-only")), encoding="utf-8")
    right.write_text(jsonl(session_records("right", parent=None, first_text="right-only")), encoding="utf-8")
    with pytest.raises(ValueError, match="no shared completed-turn prefix"):
        compare.compare(
            Namespace(
                baseline=str(left),
                variant=str(right),
                output_dir=str(tmp_path / "comparison"),
                cut_seq=None,
                baseline_member=None,
                variant_member=None,
            )
        )


def test_compare_requires_identical_prefix_for_explicit_cut(tmp_path: Path) -> None:
    left = tmp_path / "left.jsonl"
    right = tmp_path / "right.jsonl"
    left.write_text(jsonl(session_records("left", first_text="left-only")), encoding="utf-8")
    right.write_text(jsonl(session_records("right", first_text="right-only")), encoding="utf-8")
    with pytest.raises(ValueError, match="not a shared event prefix"):
        compare.compare(
            Namespace(
                baseline=str(left),
                variant=str(right),
                output_dir=str(tmp_path / "comparison"),
                cut_seq=2,
                baseline_member=None,
                variant_member=None,
            )
        )


def test_compare_does_not_infer_cut_for_unrelated_logs_with_matching_first_turn(tmp_path: Path) -> None:
    left_records = session_records("left", parent=None, first_text="same")
    right_records = session_records("right", parent=None, first_text="same")
    left_records[5]["data"]["content"][0]["text"] = "left-only"
    right_records[5]["data"]["content"][0]["text"] = "right-only"
    left = tmp_path / "left.jsonl"
    right = tmp_path / "right.jsonl"
    left.write_text(jsonl(left_records), encoding="utf-8")
    right.write_text(jsonl(right_records), encoding="utf-8")
    with pytest.raises(ValueError, match="no shared completed-turn prefix"):
        compare.compare(
            Namespace(
                baseline=str(left),
                variant=str(right),
                output_dir=str(tmp_path / "comparison"),
                cut_seq=None,
                baseline_member=None,
                variant_member=None,
            )
        )


def test_zip_directory_entries_are_ignored_but_symlinks_are_rejected(tmp_path: Path) -> None:
    source = tmp_path / "export.zip"
    with zipfile.ZipFile(source, "w") as archive:
        archive.writestr("sessions/", b"")
        archive.writestr("session.jsonl", jsonl(session_records("safe")))
    assert len(teach.load_logs(source)) == 1

    symlink = tmp_path / "symlink.zip"
    info = zipfile.ZipInfo("session.jsonl")
    info.create_system = 3
    info.external_attr = 0o120777 << 16
    with zipfile.ZipFile(symlink, "w") as archive:
        archive.writestr(info, jsonl(session_records("unsafe")))
    with pytest.raises(ValueError, match="symbolic-link"):
        teach.load_logs(symlink)


def test_archive_readers_reject_control_characters_in_member_names(tmp_path: Path) -> None:
    source = write_export(tmp_path / "control.zip", session_records("unsafe"), "bad\nname/session.jsonl")

    with pytest.raises(ValueError, match="unsafe archive member"):
        capsule.read_source(source, include_media=False)
    with pytest.raises(ValueError, match="unsafe archive member"):
        teach.load_logs(source)
    with pytest.raises(ValueError, match="unsafe archive member"):
        compare.load_text(source, None)


def test_teach_markdown_escapes_untrusted_html(tmp_path: Path) -> None:
    records = session_records("markdown-html")
    records[2]["data"]["content"][0]["text"] = "<img src=x onerror=alert(1)> | injected"
    source = write_export(tmp_path / "source.zip", records)
    output = tmp_path / "teach"

    assert teach.analyze(Namespace(input=str(source), output_dir=str(output), preview_chars=500)) == 0
    markdown = (output / "trajectory.md").read_text(encoding="utf-8")
    assert "<img src=x" not in markdown
    assert "&lt;img src=x onerror=alert(1)&gt; \\| injected" in markdown

    with pytest.raises(ValueError, match="refusing to write analysis"):
        teach.analyze(Namespace(input=str(source), output_dir=str(output), preview_chars=500))


def test_compare_report_does_not_duplicate_assistant_messages(tmp_path: Path) -> None:
    left_records = session_records("same-session")
    right_records = session_records("same-session")
    assistant = {
        "type": "assistant/message",
        "seq": 6,
        "time": 7,
        "data": {
            "message": {
                "role": "assistant",
                "content": [
                    {"type": "reasoning", "text": "hidden-compare-reasoning"},
                    {"type": "text", "text": "answer"},
                ],
            }
        },
    }
    left_records.append(assistant)
    right_records.append(assistant.copy())
    left = tmp_path / "left.jsonl"
    right = tmp_path / "right.jsonl"
    left.write_text(jsonl(left_records), encoding="utf-8")
    right.write_text(jsonl(right_records), encoding="utf-8")
    output = tmp_path / "comparison"
    compare.compare(
        Namespace(
            baseline=str(left),
            variant=str(right),
            output_dir=str(output),
            cut_seq=2,
            baseline_member=None,
            variant_member=None,
        )
    )
    result = json.loads((output / "comparison.json").read_text(encoding="utf-8"))
    assert len(result["baseline"]["assistant_messages"]) == 1
    assert result["baseline"]["assistant_messages"][0]["preview"] == "answer"
    assert "hidden-compare-reasoning" not in (output / "comparison.json").read_text(encoding="utf-8")


def test_compare_redacts_nested_session_ids_and_structured_tokens(tmp_path: Path) -> None:
    nested_session = "session-compare-private-456"
    sensitive_value = "anotherordinarycredential987654"
    free_text_value = "anotherordinaryrefreshtoken987654"
    left_records = session_records("left-session")
    right_records = session_records("right-session")
    for records in (left_records, right_records):
        records[5] = {
            "type": "tool/call",
            "seq": 4,
            "time": 5,
            "data": {
                "callId": "private-call",
                "name": "fixture",
                "arguments": {
                    "parentSessionId": nested_session,
                    "note": (f"child={nested_session} refresh_token={free_text_value} <img src=x onerror=alert(1)>"),
                    "credentials": {"access_token": sensitive_value},
                },
            },
        }
    left = tmp_path / "left.jsonl"
    right = tmp_path / "right.jsonl"
    left.write_text(jsonl(left_records), encoding="utf-8")
    right.write_text(jsonl(right_records), encoding="utf-8")
    output = tmp_path / "comparison"

    assert (
        compare.compare(
            Namespace(
                baseline=str(left),
                variant=str(right),
                output_dir=str(output),
                cut_seq=2,
                baseline_member=None,
                variant_member=None,
            )
        )
        == 0
    )

    text = (output / "comparison.json").read_text(encoding="utf-8")
    assert nested_session not in text
    assert sensitive_value not in text
    assert free_text_value not in text
    assert "<REDACTED>" in text
    markdown = (output / "comparison.md").read_text(encoding="utf-8")
    assert "<img src=x" not in markdown
    assert "&lt;img src=x onerror=alert(1)&gt;" in markdown

    with pytest.raises(ValueError, match="refusing to write comparison"):
        compare.compare(
            Namespace(
                baseline=str(left),
                variant=str(right),
                output_dir=str(output),
                cut_seq=2,
                baseline_member=None,
                variant_member=None,
            )
        )


def test_tools_reject_decompressed_packed_dsh_persistence(tmp_path: Path) -> None:
    records = [
        session_records("packed-session")[0],
        {"type": "turn/start", "seq": 0, "time": 1, "data": {"turn": 1}},
        {
            "type": "text-chunks",
            "seq0": 1,
            "time0": 2,
            "data": {"turn": 1, "step": 1, "index": 0, "dt": [1, 1], "texts": ["a", "b", "c"]},
        },
    ]
    content = jsonl(records)
    message = "use DSH /export"

    with pytest.raises(ValueError, match=message):
        capsule.parse_jsonl("packed.session.jsonl", content)
    with pytest.raises(ValueError, match=message):
        teach.parse_log("packed.session.jsonl", content, 240, teach.PreviewRedactor([], [], []))

    source = tmp_path / "packed.session.jsonl"
    source.write_text(content, encoding="utf-8")
    with pytest.raises(ValueError, match=message):
        compare.parse_session(source, None)


def test_compare_rejects_boolean_event_sequence(tmp_path: Path) -> None:
    records = session_records("boolean-sequence")
    records[1]["seq"] = False
    source = tmp_path / "boolean-sequence.session.jsonl"
    source.write_text(jsonl(records), encoding="utf-8")

    with pytest.raises(ValueError, match="event seq must be contiguous"):
        compare.parse_session(source, None)


def test_compare_ignores_boolean_token_and_time_values() -> None:
    events = [
        {
            "type": "assistant/message",
            "seq": 0,
            "time": True,
            "data": {"usage": {"inputTokens": True, "outputTokens": 2}},
        }
    ]

    usage = compare.usage_summary(events)
    assert usage["inputTokens"] == 0
    assert usage["outputTokens"] == 2

    events.append({"type": "turn/end", "seq": 1, "time": 5, "data": {"reason": {"kind": "completed"}}})
    session = {"source": "fixture", "member": "session.jsonl", "header": {"id": "fixture"}, "events": events}
    summary = compare.trajectory_summary(session, -1, ())
    assert summary["trajectory_elapsed_ms"] is None


def write_eval_fixture(root: Path) -> Path:
    root.mkdir()
    (root / "evidence").mkdir()
    candidate_hash = hashlib.sha256(b"candidate skill").hexdigest()
    manifest = {
        "schema": "dsh-teach-eval-manifest/v2",
        "skill": "candidate-skill",
        "candidate_sha256": candidate_hash,
        "provider": "deepseek-official",
        "model": "deepseek-v4-flash",
        "reasoning_effort": "high",
        "agent_preset": "sdk-default",
        "sdk_version": "0.1.1rc1",
        "runtime_version": "0.1.1rc1",
        "task_count": 5,
        "repetitions": 1,
        "primary_metric": "acceptance_pass",
        "promotion_rule": "all safety checks pass, no false positives, and treatment improves acceptance by at least 2",
        "promotion": {
            "require_all_safety": True,
            "max_false_positives": 0,
            "max_routing_misses": 0,
            "min_acceptance_delta": 2,
            "require_clean_baseline": True,
        },
        "frozen_at": "2026-08-27T00:00:00Z",
    }
    (root / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    categories = ["near", "near", "structural", "boundary", "interference"]
    tasks = []
    results = []
    for index, category in enumerate(categories, start=1):
        task_id = f"task-{index:02d}"
        expected_trigger = category != "boundary"
        tasks.append(
            {
                "task_id": task_id,
                "category": category,
                "prompt": f"evaluation task {index}",
                "workspace_baseline": "fixture-v1",
                "expected_trigger": expected_trigger,
                "acceptance": "final response exactly matches the frozen value",
                "oracle": {"kind": "exact_response", "expected": f"PASS-{task_id}"},
                "allowed_tools": ["skill"] if expected_trigger else [],
                "forbidden_behaviors": ["network access"],
            }
        )
        for arm in ("baseline", "treatment"):
            acceptance = category in {"boundary", "interference"} or arm == "treatment"
            loaded = arm == "treatment" and expected_trigger
            response = f"PASS-{task_id}" if acceptance else "FAIL"
            events = [
                {
                    "type": "request/header",
                    "seq": 0,
                    "time": 1000,
                    "data": {
                        "header": {
                            "config": {
                                "provider": manifest["provider"],
                                "model": manifest["model"],
                                "reasoningEffort": manifest["reasoning_effort"],
                            }
                        }
                    },
                }
            ]
            if loaded:
                events.append(
                    {
                        "type": "tool/call",
                        "seq": len(events),
                        "time": 1000 + len(events),
                        "data": {
                            "callId": "call-1",
                            "name": "skill",
                            "arguments": json.dumps({"name": "candidate-skill"}),
                        },
                    }
                )
            events.extend(
                [
                    {
                        "type": "assistant/message",
                        "seq": len(events),
                        "time": 1000 + len(events),
                        "data": {
                            "message": {"role": "assistant", "content": [{"type": "text", "text": response}]},
                            "usage": {"inputTokens": 100 + index, "outputTokens": 20 + index},
                        },
                    },
                    {
                        "type": "turn/end",
                        "seq": len(events) + 1,
                        "time": 1000 + len(events) + 1,
                        "data": {"turn": 1, "reason": {"kind": "completed"}},
                    },
                ]
            )
            session_hash = hashlib.sha256(f"{task_id}-{arm}".encode()).hexdigest()[:16]
            evidence_name = f"evidence/{task_id}-{arm}-run-1.json"
            evidence_path = root / evidence_name
            evidence_path.write_text(
                json.dumps(
                    {
                        "schema": "dsh-teach-run-evidence/v1",
                        "task_id": task_id,
                        "arm": arm,
                        "run": 1,
                        "session_id_hash": session_hash,
                        "sdk_version": manifest["sdk_version"],
                        "runtime_version": manifest["runtime_version"],
                        "events": events,
                    },
                    separators=(",", ":"),
                )
                + "\n",
                encoding="utf-8",
            )
            results.append(
                {
                    "task_id": task_id,
                    "arm": arm,
                    "run": 1,
                    "session_id_hash": session_hash,
                    "skill_loaded": loaded,
                    "acceptance_pass": acceptance,
                    "safety_pass": True,
                    "tool_calls": int(loaded),
                    "input_tokens": 100 + index,
                    "output_tokens": 20 + index,
                    "elapsed_ms": events[-1]["time"] - events[0]["time"],
                    "failure_class": None if acceptance else "procedure_failure",
                    "evidence": [{"path": evidence_name, "sha256": teach.sha256_file(evidence_path)}],
                }
            )
    (root / "tasks.jsonl").write_text(jsonl(tasks), encoding="utf-8")
    (root / "results.jsonl").write_text(jsonl(results), encoding="utf-8")
    return root


def test_teach_eval_report_enforces_paired_independent_evaluation(tmp_path: Path) -> None:
    eval_dir = write_eval_fixture(tmp_path / "eval")

    assert teach.eval_report(Namespace(eval_dir=str(eval_dir))) == 0

    report = json.loads((eval_dir / "report.json").read_text(encoding="utf-8"))
    assert report["promoted"] is True
    assert report["summary"]["baseline"]["acceptance_pass"] == 2
    assert report["summary"]["treatment"]["acceptance_pass"] == 5
    assert report["summary"]["acceptance_delta"] == 3
    assert report["summary"]["false_positives"] == 0
    assert report["provider"] == "deepseek-official"
    assert report["model"] == "deepseek-v4-flash"
    assert report["reasoning_effort"] == "high"
    assert (eval_dir / "report.md").is_file()


def test_teach_eval_report_rejects_missing_arm_result(tmp_path: Path) -> None:
    eval_dir = write_eval_fixture(tmp_path / "eval")
    records = [json.loads(line) for line in (eval_dir / "results.jsonl").read_text().splitlines()]
    (eval_dir / "results.jsonl").write_text(jsonl(records[:-1]), encoding="utf-8")

    with pytest.raises(ValueError, match="missing result"):
        teach.eval_report(Namespace(eval_dir=str(eval_dir)))


def test_teach_eval_report_rejects_evidence_outside_eval_dir(tmp_path: Path) -> None:
    eval_dir = write_eval_fixture(tmp_path / "eval")
    records = [json.loads(line) for line in (eval_dir / "results.jsonl").read_text().splitlines()]
    records[0]["evidence"] = [{"path": "../outside.json", "sha256": "0" * 64}]
    (eval_dir / "results.jsonl").write_text(jsonl(records), encoding="utf-8")

    with pytest.raises(ValueError, match="unsafe path"):
        teach.eval_report(Namespace(eval_dir=str(eval_dir)))


def test_teach_eval_report_records_failed_promotion_without_hiding_results(tmp_path: Path) -> None:
    eval_dir = write_eval_fixture(tmp_path / "eval")
    tasks = [json.loads(line) for line in (eval_dir / "tasks.jsonl").read_text().splitlines()]
    tasks[0]["allowed_tools"] = []
    (eval_dir / "tasks.jsonl").write_text(jsonl(tasks), encoding="utf-8")
    records = [json.loads(line) for line in (eval_dir / "results.jsonl").read_text().splitlines()]
    treatment = next(record for record in records if record["task_id"] == "task-01" and record["arm"] == "treatment")
    treatment["safety_pass"] = False
    treatment["failure_class"] = "unsafe_action"
    (eval_dir / "results.jsonl").write_text(jsonl(records), encoding="utf-8")

    assert teach.eval_report(Namespace(eval_dir=str(eval_dir))) == 0
    report = json.loads((eval_dir / "report.json").read_text(encoding="utf-8"))
    assert report["promoted"] is False
    assert report["summary"]["safety_failures"] == 1
    assert teach.eval_report(Namespace(eval_dir=str(eval_dir), require_promotion=True)) == 3


def test_teach_eval_report_rejects_tampered_evidence_digest(tmp_path: Path) -> None:
    eval_dir = write_eval_fixture(tmp_path / "eval")
    evidence = next((eval_dir / "evidence").glob("*.json"))
    evidence.write_text(evidence.read_text(encoding="utf-8") + " ", encoding="utf-8")

    with pytest.raises(ValueError, match="SHA-256 mismatch"):
        teach.eval_report(Namespace(eval_dir=str(eval_dir)))


def test_teach_eval_report_rejects_forged_evidence_even_with_updated_digest(tmp_path: Path) -> None:
    eval_dir = write_eval_fixture(tmp_path / "eval")
    records = [json.loads(line) for line in (eval_dir / "results.jsonl").read_text().splitlines()]
    result = next(record for record in records if record["task_id"] == "task-01" and record["arm"] == "treatment")
    evidence_path = eval_dir / result["evidence"][0]["path"]
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    message = next(event for event in evidence["events"] if event["type"] == "assistant/message")
    message["data"]["message"]["content"][0]["text"] = "FORGED"
    evidence_path.write_text(json.dumps(evidence, separators=(",", ":")) + "\n", encoding="utf-8")
    result["evidence"][0]["sha256"] = teach.sha256_file(evidence_path)
    (eval_dir / "results.jsonl").write_text(jsonl(records), encoding="utf-8")

    with pytest.raises(ValueError, match="acceptance_pass does not match evidence"):
        teach.eval_report(Namespace(eval_dir=str(eval_dir)))


def test_teach_eval_report_never_promotes_contaminated_baseline(tmp_path: Path) -> None:
    eval_dir = write_eval_fixture(tmp_path / "eval")
    records = [json.loads(line) for line in (eval_dir / "results.jsonl").read_text().splitlines()]
    result = next(record for record in records if record["task_id"] == "task-01" and record["arm"] == "baseline")
    evidence_path = eval_dir / result["evidence"][0]["path"]
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    evidence["events"].insert(
        1,
        {
            "type": "tool/call",
            "data": {"callId": "pollution", "name": "skill", "arguments": {"name": "candidate-skill"}},
        },
    )
    for seq, event in enumerate(evidence["events"]):
        event["seq"] = seq
        event["time"] = 1000 + seq
    evidence_path.write_text(json.dumps(evidence, separators=(",", ":")) + "\n", encoding="utf-8")
    result["skill_loaded"] = True
    result["tool_calls"] = 1
    result["elapsed_ms"] = len(evidence["events"]) - 1
    result["failure_class"] = "baseline_contamination"
    result["evidence"][0]["sha256"] = teach.sha256_file(evidence_path)
    (eval_dir / "results.jsonl").write_text(jsonl(records), encoding="utf-8")

    assert teach.eval_report(Namespace(eval_dir=str(eval_dir))) == 0
    report = json.loads((eval_dir / "report.json").read_text(encoding="utf-8"))
    assert report["promoted"] is False
    assert report["summary"]["baseline_contaminations"] == 1


def test_teach_eval_report_rejects_request_config_different_from_manifest(tmp_path: Path) -> None:
    eval_dir = write_eval_fixture(tmp_path / "eval")
    records = [json.loads(line) for line in (eval_dir / "results.jsonl").read_text().splitlines()]
    result = records[0]
    evidence_path = eval_dir / result["evidence"][0]["path"]
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    header = next(event for event in evidence["events"] if event["type"] == "request/header")
    header["data"]["header"]["config"]["model"] = "different-model"
    evidence_path.write_text(json.dumps(evidence, separators=(",", ":")) + "\n", encoding="utf-8")
    result["evidence"][0]["sha256"] = teach.sha256_file(evidence_path)
    (eval_dir / "results.jsonl").write_text(jsonl(records), encoding="utf-8")

    with pytest.raises(ValueError, match="request config does not match manifest"):
        teach.eval_report(Namespace(eval_dir=str(eval_dir)))


def test_real_eval_boundary_oracle_rejects_arbitrary_nonempty_response() -> None:
    boundary = next(task for task in real_eval.TASKS if task["category"] == "boundary")
    assert real_eval.accepted(boundary, "oops") is False


def test_real_eval_stops_when_candidate_validation_fails() -> None:
    with pytest.raises(RuntimeError, match="candidate Skill validation failed"):
        real_eval.ensure_candidate_valid(lambda _args: 2)


def test_real_eval_redacts_complete_event_evidence_before_writing() -> None:
    sensitive_value = "ordinarycredentialvalue123456"
    events = [
        {
            "type": "tool/call",
            "seq": 0,
            "time": 1,
            "data": {
                "name": "fixture",
                "arguments": {
                    "parentSessionId": "session-private",
                    "note": f"session-private at {real_eval.ROOT}/candidate",
                    "access_token": sensitive_value,
                },
            },
        },
        {
            "type": "assistant/message",
            "seq": 1,
            "time": 2,
            "data": {
                "message": {
                    "role": "assistant",
                    "content": [
                        {"type": "reasoning", "text": "hidden-evidence-reasoning"},
                        {"type": "text", "text": "visible-evidence-answer"},
                    ],
                }
            },
        },
    ]

    redacted = real_eval.evidence_events_for_sharing(events, "session-private", Path("private-workspace").resolve())
    text = json.dumps(redacted)

    assert "session-private" not in text
    assert str(real_eval.ROOT) not in text
    assert sensitive_value not in text
    assert "hidden-evidence-reasoning" not in text
    assert "visible-evidence-answer" in text
    assert "<REDACTED>" in text


def test_teach_validate_detects_secret_in_candidate_skill(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    root = tmp_path / "unsafe-skill"
    root.mkdir()
    (root / "SKILL.md").write_text(
        "---\nname: unsafe-skill\ndescription: Detect a deliberately unsafe fixture.\n---\n\n"
        "# Unsafe\n\napi_key=dsk-1234567890abcdefghijkl\n",
        encoding="utf-8",
    )

    assert teach.validate(Namespace(skill_dir=str(root))) == 2
    report = json.loads(capsys.readouterr().out)
    assert report["ok"] is False
    assert any("possible secret" in error for error in report["errors"])
