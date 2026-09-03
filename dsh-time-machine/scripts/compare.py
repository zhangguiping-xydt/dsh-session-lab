#!/usr/bin/env python3
"""Compare two DSH session trajectories after a shared or declared cut."""

from __future__ import annotations

import argparse
import difflib
import hashlib
import html
import json
import re
import stat
import sys
import zipfile
from collections import Counter
from pathlib import Path, PurePosixPath
from typing import Any

MAX_LOG_BYTES = 128 * 1024 * 1024
MAX_TOTAL_BYTES = 512 * 1024 * 1024
MAX_ARCHIVE_BYTES = 256 * 1024 * 1024
MAX_ARCHIVE_FILES = 10_000
MAX_ENTRY_BYTES = 128 * 1024 * 1024
TOKEN_KEYS = ("inputTokens", "outputTokens", "cacheReadTokens", "cacheWriteTokens", "reasoningTokens")
SENSITIVE_FIELD_PATTERN = (
    r"(?:x[_-]?api[_-]?key|api[_-]?key|access[_-]?token|refresh[_-]?token|auth[_-]?token|"
    r"session[_-]?token|token|authorization|proxy[_-]?authorization|cookie|set[_-]?cookie|password|passwd|"
    r"secret|client[_-]?secret|private[_-]?key|aws[_-]?access[_-]?key[_-]?id|aws[_-]?secret[_-]?access[_-]?key|"
    r"credentials?)"
)
SECRET_PATTERNS = (
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), "<REDACTED_PRIVATE_KEY>"),
    (re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{12,}"), "Bearer <REDACTED>"),
    (re.compile(r"\b(?:sk|dsk)-[A-Za-z0-9_-]{16,}"), "<REDACTED_API_KEY>"),
    (re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"), "<REDACTED_AWS_ACCESS_KEY>"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,255}\b"), "<REDACTED_GITHUB_TOKEN>"),
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), "<REDACTED_SLACK_TOKEN>"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\b"), "<REDACTED_JWT>"),
    (
        re.compile(rf"(?i)\b({SENSITIVE_FIELD_PATTERN}['\"]?\s*[:=]\s*['\"]?)[^\s'\",;]{{8,}}"),
        r"\1<REDACTED>",
    ),
)
SECRET_KEYS = re.compile(rf"(?i)^{SENSITIVE_FIELD_PATTERN}$")
SESSION_KEYS = {"id", "sessionId", "parentSession", "parentSessionId", "childSessionId"}
HOME_PATTERNS = (
    re.compile(r"(?<![A-Za-z0-9_])/(?:home|Users)/[^/\s]+"),
    re.compile(r"(?i)\b[A-Z]:\\Users\\[^\\\s]+"),
)
EMAIL_PATTERN = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
URL_PATTERN = re.compile(r"\bhttps?://[^\s<>\"']+")
PACKED_STORAGE_TYPES = {"text-chunks", "reasoning-chunks", "tool-call-chunks"}


def safe_member(name: str) -> bool:
    path = PurePosixPath(name)
    return (
        bool(name)
        and not path.is_absolute()
        and all(part not in ("", ".", "..") for part in name.split("/"))
        and not any(ord(character) < 32 or ord(character) == 127 for character in name)
        and "\\" not in name
    )


def zip_is_symlink(info: zipfile.ZipInfo) -> bool:
    return stat.S_IFMT(info.external_attr >> 16) == stat.S_IFLNK


def digest_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def read_member(
    archive: zipfile.ZipFile,
    member: str | zipfile.ZipInfo,
    budget: list[int] | None = None,
    limit: int = MAX_ENTRY_BYTES,
) -> bytes:
    """Decompress one ZIP member in bounded chunks; declared header sizes are not trusted."""
    name = member if isinstance(member, str) else member.filename
    chunks: list[bytes] = []
    size = 0
    with archive.open(member) as handle:
        while chunk := handle.read(1024 * 1024):
            size += len(chunk)
            if size > limit:
                raise ValueError(f"capsule member exceeds {limit // (1024 * 1024)} MiB: {name}")
            if budget is not None:
                budget[0] += len(chunk)
                if budget[0] > MAX_TOTAL_BYTES:
                    raise ValueError("capsule expands beyond the 512 MiB comparison limit")
            chunks.append(chunk)
    return b"".join(chunks)


def validate_capsule_archive(archive: zipfile.ZipFile) -> list[str]:
    """Validate a .dshc manifest and return its declared session members."""
    infos = archive.infolist()
    if len(infos) > MAX_ARCHIVE_FILES:
        raise ValueError(f"capsule contains more than {MAX_ARCHIVE_FILES} entries")
    seen: set[str] = set()
    total = 0
    for info in infos:
        if info.is_dir():
            continue
        if not safe_member(info.filename):
            raise ValueError(f"unsafe capsule member: {info.filename!r}")
        if zip_is_symlink(info):
            raise ValueError(f"symbolic-link capsule member is not allowed: {info.filename}")
        if info.filename in seen:
            raise ValueError(f"duplicate capsule member: {info.filename}")
        if info.file_size > MAX_ENTRY_BYTES:
            raise ValueError(f"capsule member exceeds {MAX_ENTRY_BYTES // (1024 * 1024)} MiB: {info.filename}")
        total += info.file_size
        if total > MAX_TOTAL_BYTES:
            raise ValueError("capsule expands beyond the 512 MiB comparison limit")
        seen.add(info.filename)
    names = seen
    if "manifest.json" not in names:
        raise ValueError("capsule has no manifest.json")
    budget = [0]
    try:
        manifest = json.loads(read_member(archive, "manifest.json", budget))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("capsule manifest is not valid UTF-8 JSON") from error
    if not isinstance(manifest, dict) or manifest.get("format") != "dsh-capsule" or manifest.get("version") != 1:
        raise ValueError("unsupported capsule format or version")
    listed = manifest.get("files")
    if not isinstance(listed, list):
        raise ValueError("capsule manifest files must be an array")
    if len(listed) > MAX_ARCHIVE_FILES:
        raise ValueError(f"capsule manifest contains more than {MAX_ARCHIVE_FILES} files")
    expected: set[str] = set()
    session_members: list[str] = []
    for record in listed:
        if not isinstance(record, dict) or not isinstance(record.get("path"), str):
            raise ValueError("capsule manifest has an invalid file record")
        name = record["path"]
        if not safe_member(name) or name == "manifest.json" or name in expected:
            raise ValueError(f"invalid capsule manifest path: {name}")
        expected.add(name)
        if name not in names:
            raise ValueError(f"capsule manifest file is missing: {name}")
        data = read_member(archive, name, budget)
        declared_bytes = record.get("bytes")
        declared_hash = record.get("sha256")
        if (
            not isinstance(declared_bytes, int)
            or isinstance(declared_bytes, bool)
            or not isinstance(declared_hash, str)
            or declared_bytes != len(data)
            or declared_hash != digest_bytes(data)
        ):
            raise ValueError(f"capsule file hash mismatch: {name}")
        if name.endswith("session.jsonl"):
            session_members.append(name)
    if names != expected | {"manifest.json"}:
        raise ValueError("capsule manifest does not match ZIP members")
    return sorted(session_members)


def scrub(value: str, sensitive_values: tuple[str, ...] = ()) -> str:
    result = value
    for original in sensitive_values:
        result = result.replace(original, "<SESSION>")
    for pattern, replacement in SECRET_PATTERNS:
        result = pattern.sub(replacement, result)
    for pattern in HOME_PATTERNS:
        result = pattern.sub("<USER_HOME>", result)
    result = EMAIL_PATTERN.sub("<EMAIL>", result)
    result = URL_PATTERN.sub("<URL>", result)
    return result


def stable_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def digest(value: Any) -> str:
    return hashlib.sha256(stable_json(value).encode("utf-8")).hexdigest()[:16]


def markdown_inline(value: Any) -> str:
    """Render untrusted text without allowing Markdown/HTML structure changes."""
    return (
        html.escape(str(value), quote=False)
        .replace("`", "&#96;")
        .replace("|", "\\|")
        .replace("\r", " ")
        .replace("\n", " ")
    )


def preview(value: Any, limit: int = 240, sensitive_values: tuple[str, ...] = ()) -> str:
    strings: list[str] = []
    stack: list[Any] = [value]
    while stack and len(" ".join(strings)) < limit * 2:
        item = stack.pop()
        if isinstance(item, str):
            strings.append(item)
        elif isinstance(item, dict):
            values = ["<REDACTED>" if SECRET_KEYS.fullmatch(str(key)) else child for key, child in item.items()]
            stack.extend(reversed(values))
        elif isinstance(item, list):
            stack.extend(reversed(item))
    text = re.sub(r"\s+", " ", scrub(" ".join(strings), sensitive_values)).strip()
    return text if len(text) <= limit else text[: limit - 1] + "…"


def visible_message_text(message: Any) -> str:
    if isinstance(message, str):
        return message
    if not isinstance(message, dict):
        return ""
    content = message.get("content")
    if isinstance(content, str):
        return content
    if not isinstance(content, list):
        return ""
    return "".join(
        block["text"]
        for block in content
        if isinstance(block, dict) and block.get("type") == "text" and isinstance(block.get("text"), str)
    )


def collect_keyed_strings(value: Any, key_name: str) -> list[str]:
    found: list[str] = []
    stack: list[Any] = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, dict):
            for key, child in item.items():
                if key == key_name and isinstance(child, str) and child and child not in found:
                    found.append(child)
                else:
                    stack.append(child)
        elif isinstance(item, list):
            stack.extend(item)
    return found


def sensitive_session_values(*sessions: dict[str, Any]) -> tuple[str, ...]:
    found: list[str] = []
    for session in sessions:
        for key in SESSION_KEYS:
            for value in collect_keyed_strings({"header": session["header"], "events": session["events"]}, key):
                if value not in found:
                    found.append(value)
    return tuple(sorted(found, key=len, reverse=True))


def choose_member(names: list[str], requested: str | None) -> str:
    if requested:
        if requested not in names:
            raise ValueError(f"requested session member not found: {requested}; candidates={names}")
        return requested
    if not names:
        raise ValueError("archive contains no session.jsonl")
    preferred = ["session.jsonl", "sessions/root/session.jsonl"]
    for name in preferred:
        if name in names:
            return name
    root_like = [name for name in names if name.endswith("session.jsonl") and "subagents/" not in name]
    if len(root_like) == 1:
        return root_like[0]
    if len(names) == 1:
        return names[0]
    raise ValueError(f"multiple session logs found; select one explicitly: {names}")


def load_text(source: Path, requested: str | None) -> tuple[str, str]:
    if not source.is_file():
        raise ValueError(f"input does not exist: {source}")
    if source.stat().st_size > MAX_ARCHIVE_BYTES:
        raise ValueError(f"input archive exceeds {MAX_ARCHIVE_BYTES // (1024 * 1024)} MiB")
    if zipfile.is_zipfile(source):
        with zipfile.ZipFile(source) as archive:
            candidates: list[str] = []
            total = 0
            if source.suffix == ".dshc":
                candidates = validate_capsule_archive(archive)
            infos = archive.infolist()
            if len(infos) > MAX_ARCHIVE_FILES:
                raise ValueError(f"archive contains more than {MAX_ARCHIVE_FILES} entries")
            seen: set[str] = set()
            for info in infos:
                if info.is_dir():
                    continue
                if not safe_member(info.filename):
                    raise ValueError(f"unsafe archive member: {info.filename!r}")
                if zip_is_symlink(info):
                    raise ValueError(f"symbolic-link archive member is not allowed: {info.filename}")
                if info.filename in seen:
                    raise ValueError(f"duplicate archive member: {info.filename}")
                seen.add(info.filename)
                total += info.file_size
                if info.file_size > MAX_ENTRY_BYTES or total > MAX_TOTAL_BYTES:
                    raise ValueError("archive exceeds trajectory comparison limits")
                if info.filename.endswith("session.jsonl") and info.file_size > MAX_LOG_BYTES:
                    raise ValueError(f"session log exceeds {MAX_LOG_BYTES // (1024 * 1024)} MiB: {info.filename}")
                if info.filename.endswith("session.jsonl") and info.filename not in candidates:
                    candidates.append(info.filename)
            member = choose_member(sorted(candidates), requested)
            return member, read_member(archive, member, None, MAX_LOG_BYTES).decode("utf-8")
    if requested:
        raise ValueError("--*-member can only be used with ZIP or .dshc input")
    if source.stat().st_size > MAX_LOG_BYTES:
        raise ValueError("session JSONL exceeds 128 MiB")
    return source.name, source.read_text(encoding="utf-8")


def parse_session(source: Path, requested: str | None) -> dict[str, Any]:
    member, content = load_text(source, requested)
    records: list[dict[str, Any]] = []
    for line_number, line in enumerate(content.splitlines(), 1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as error:
            raise ValueError(f"{source}:{member}:{line_number}: invalid JSON: {error.msg}") from error
        if not isinstance(value, dict):
            raise ValueError(f"{source}:{member}:{line_number}: record is not an object")
        records.append(value)
    if not records or records[0].get("type") != "session":
        raise ValueError(f"{source}:{member}: first record is not a DSH session header")
    packed = next((event.get("type") for event in records[1:] if event.get("type") in PACKED_STORAGE_TYPES), None)
    if packed is not None:
        raise ValueError(
            f"{source}:{member}: contains packed DSH persistence record {packed!r}; use DSH /export instead of "
            "decompressing session.jsonl.zstd"
        )
    sequences = [event_seq(event) for event in records[1:]]
    expected_sequences = list(range(len(sequences)))
    if sequences != expected_sequences:
        raise ValueError(f"{source}:{member}: event seq must be contiguous from 0")
    header = records[0]
    session_id = header.get("id")
    display_member = scrub(member)
    display_source = scrub(source.name)
    if isinstance(session_id, str) and session_id:
        display_member = display_member.replace(session_id, "<SESSION>")
        display_source = display_source.replace(session_id, "<SESSION>")
    parent = header.get("parentSession")
    if isinstance(parent, str) and parent:
        display_member = display_member.replace(parent, "<PARENT_SESSION>")
        display_source = display_source.replace(parent, "<PARENT_SESSION>")
    return {"source": display_source, "member": display_member, "header": header, "events": records[1:]}


def comparable_event(event: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in event.items() if key != "time"}


def common_prefix_length(left: list[dict[str, Any]], right: list[dict[str, Any]]) -> int:
    length = 0
    for left_event, right_event in zip(left, right, strict=False):
        if comparable_event(left_event) != comparable_event(right_event):
            break
        length += 1
    return length


def same_prefix_through(left: list[dict[str, Any]], right: list[dict[str, Any]], cut_seq: int) -> bool:
    """Require both logs to contain identical events through the proposed cut."""
    left_by_seq = {event_seq(event): event for event in left if event_seq(event) is not None}
    right_by_seq = {event_seq(event): event for event in right if event_seq(event) is not None}
    for seq in range(cut_seq + 1):
        left_event = left_by_seq.get(seq)
        right_event = right_by_seq.get(seq)
        if left_event is None or right_event is None or comparable_event(left_event) != comparable_event(right_event):
            return False
    return True


def lineage_supports_seed_cut(baseline: dict[str, Any], variant: dict[str, Any]) -> bool:
    baseline_header = baseline["header"]
    variant_header = variant["header"]
    baseline_id = baseline_header.get("id")
    variant_id = variant_header.get("id")
    if isinstance(baseline_id, str) and baseline_id and baseline_id == variant_id:
        return True
    parent = baseline_header.get("parentSession")
    return isinstance(parent, str) and parent == variant_header.get("parentSession")


def event_seq(event: dict[str, Any]) -> int | None:
    value = event.get("seq")
    # ``bool`` is an ``int`` subclass in Python.  Treating ``True`` as sequence
    # zero would allow malformed exports to pass the contiguous-sequence check.
    return value if type(value) is int and value >= 0 else None


def resolve_cut(baseline: dict[str, Any], variant: dict[str, Any], requested: int | None) -> tuple[int, str]:
    baseline_events = baseline["events"]
    variant_events = variant["events"]
    if requested is not None:
        for label, events in (("baseline", baseline_events), ("variant", variant_events)):
            matches = [event for event in events if event_seq(event) == requested]
            if not matches:
                raise ValueError(f"cut seq {requested} is absent from {label}")
            if matches[0].get("type") != "turn/end":
                raise ValueError(f"cut seq {requested} is not turn/end in {label}")
        if not same_prefix_through(baseline_events, variant_events, requested):
            raise ValueError(f"cut seq {requested} is not a shared event prefix")
        return requested, "explicit"
    seed_lengths = [item["header"].get("seedLength") for item in (baseline, variant)]
    if (
        lineage_supports_seed_cut(baseline, variant)
        and seed_lengths[0] == seed_lengths[1]
        and all(type(value) is int and value > 0 for value in seed_lengths)
    ):
        candidate = min(seed_lengths) - 1
        baseline_at = next((event for event in baseline_events if event_seq(event) == candidate), None)
        variant_at = next((event for event in variant_events if event_seq(event) == candidate), None)
        if (
            baseline_at
            and variant_at
            and baseline_at.get("type") == variant_at.get("type") == "turn/end"
            and same_prefix_through(baseline_events, variant_events, candidate)
        ):
            return candidate, "seedLength"
    if lineage_supports_seed_cut(baseline, variant):
        common = common_prefix_length(baseline_events, variant_events)
        for index in range(common - 1, -1, -1):
            event = baseline_events[index]
            if event.get("type") == "turn/end" and event_seq(event) is not None:
                return int(event["seq"]), "common-prefix"
    raise ValueError("the two logs have no shared completed-turn prefix; provide matching fork exports")


def events_after(events: list[dict[str, Any]], cut_seq: int) -> list[dict[str, Any]]:
    return [event for event in events if event_seq(event) is not None and int(event["seq"]) > cut_seq]


def route_summary(events: list[dict[str, Any]], sensitive_values: tuple[str, ...]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for event in events:
        if event.get("type") != "request/header":
            continue
        data = event.get("data") if isinstance(event.get("data"), dict) else {}
        header = data.get("header") if isinstance(data.get("header"), dict) else {}
        config = header.get("config") if isinstance(header.get("config"), dict) else {}
        tools = header.get("tools") if isinstance(header.get("tools"), list) else []
        system = header.get("system")
        result.append(
            {
                "seq": event_seq(event),
                "reason": scrub(str(data.get("reason")), sensitive_values) if data.get("reason") is not None else None,
                "provider": scrub(str(config.get("provider")), sensitive_values)
                if config.get("provider") is not None
                else None,
                "model": scrub(str(config.get("model")), sensitive_values) if config.get("model") is not None else None,
                "reasoning_effort": scrub(str(config.get("reasoningEffort")), sensitive_values)
                if config.get("reasoningEffort") is not None
                else None,
                "system_digest": digest(system) if isinstance(system, str) else None,
                "tool_schema_digest": digest(tools),
                "tool_count": len(tools),
            }
        )
    return result


def tool_summary(events: list[dict[str, Any]], sensitive_values: tuple[str, ...]) -> list[dict[str, Any]]:
    calls: dict[str, dict[str, Any]] = {}
    order: list[str] = []
    for event in events:
        data = event.get("data") if isinstance(event.get("data"), dict) else {}
        if event.get("type") == "tool/call":
            call_id = str(data.get("callId", f"seq-{event_seq(event)}"))
            arguments = data.get("arguments")
            calls[call_id] = {
                "seq": event_seq(event),
                "name": scrub(str(data.get("name", "<unknown>")), sensitive_values),
                "arguments_digest": digest(arguments),
                "arguments_preview": preview(arguments, sensitive_values=sensitive_values),
                "result_seq": None,
                "result_digest": None,
                "result_preview": "",
            }
            order.append(call_id)
        elif event.get("type") == "tool/result":
            call_id = str(data.get("callId", ""))
            if call_id in calls:
                calls[call_id]["result_seq"] = event_seq(event)
                calls[call_id]["result_digest"] = digest(data)
                calls[call_id]["result_preview"] = preview(data, sensitive_values=sensitive_values)
    return [calls[item] for item in order]


def usage_summary(events: list[dict[str, Any]]) -> dict[str, int]:
    totals = {key: 0 for key in TOKEN_KEYS}
    for event in events:
        if event.get("type") != "assistant/message":
            continue
        data = event.get("data") if isinstance(event.get("data"), dict) else {}
        usage = data.get("usage") if isinstance(data.get("usage"), dict) else {}
        for key in TOKEN_KEYS:
            value = usage.get(key)
            if type(value) is int and value >= 0:
                totals[key] += value
    return totals


def event_signature(event: dict[str, Any], sensitive_values: tuple[str, ...]) -> str:
    kind = str(event.get("type", "<missing>"))
    data = event.get("data") if isinstance(event.get("data"), dict) else {}
    if kind == "tool/call":
        return f"tool/call:{scrub(str(data.get('name', '<unknown>')), sensitive_values)}"
    if kind == "turn/end":
        reason = data.get("reason") if isinstance(data.get("reason"), dict) else {}
        return f"turn/end:{reason.get('kind', '<unknown>')}"
    if kind == "request/header":
        header = data.get("header") if isinstance(data.get("header"), dict) else {}
        config = header.get("config") if isinstance(header.get("config"), dict) else {}
        return (
            f"request/header:{scrub(str(config.get('provider')), sensitive_values)}:"
            f"{scrub(str(config.get('model')), sensitive_values)}"
        )
    return kind


def trajectory_summary(session: dict[str, Any], cut_seq: int, sensitive_values: tuple[str, ...]) -> dict[str, Any]:
    events = events_after(session["events"], cut_seq)
    times = [event.get("time") for event in events if type(event.get("time")) is int]
    assistants = []
    turns = []
    for event in events:
        data = event.get("data") if isinstance(event.get("data"), dict) else {}
        if event.get("type") == "assistant/message":
            assistants.append(
                {
                    "seq": event_seq(event),
                    "digest": digest(data.get("message")),
                    "preview": preview(visible_message_text(data.get("message")), sensitive_values=sensitive_values),
                }
            )
        elif event.get("type") == "turn/end":
            reason = data.get("reason")
            turns.append(
                {
                    "seq": event_seq(event),
                    "turn": data.get("turn"),
                    "reason_kind": reason.get("kind") if isinstance(reason, dict) else None,
                    "reason_preview": preview(reason, sensitive_values=sensitive_values),
                }
            )
    return {
        "source": scrub(session["source"], sensitive_values),
        "member": scrub(session["member"], sensitive_values),
        "session_id_hash": hashlib.sha256(str(session["header"].get("id", "")).encode("utf-8")).hexdigest()[:16],
        "event_count": len(events),
        "event_types": dict(sorted(Counter(str(event.get("type", "<missing>")) for event in events).items())),
        "routes": route_summary(events, sensitive_values),
        "tools": tool_summary(events, sensitive_values),
        "assistant_messages": assistants,
        "turn_outcomes": turns,
        "tokens": usage_summary(events),
        "trajectory_elapsed_ms": (max(times) - min(times)) if len(times) >= 2 else None,
        "signatures": [event_signature(event, sensitive_values) for event in events],
    }


def sequence_delta(left: list[str], right: list[str]) -> list[dict[str, Any]]:
    matcher = difflib.SequenceMatcher(a=left, b=right, autojunk=False)
    result = []
    for tag, a0, a1, b0, b1 in matcher.get_opcodes():
        if tag == "equal":
            continue
        result.append(
            {
                "kind": tag,
                "baseline_range": [a0, a1],
                "variant_range": [b0, b1],
                "baseline": left[a0:a1],
                "variant": right[b0:b1],
            }
        )
    return result


def tool_delta(left: list[dict[str, Any]], right: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result = []
    for index in range(max(len(left), len(right))):
        baseline = left[index] if index < len(left) else None
        variant = right[index] if index < len(right) else None
        if baseline != variant:
            result.append({"index": index, "baseline": baseline, "variant": variant})
    return result


def render_markdown(result: dict[str, Any]) -> str:
    baseline = result["baseline"]
    variant = result["variant"]
    lines = [
        "# DSH 轨迹对比",
        "",
        f"- 切点：seq `{result['cut']['seq']}`（{result['cut']['source']}）",
        f"- baseline：`{baseline['session_id_hash']}`，切点后 {baseline['event_count']} 个事件",
        f"- variant：`{variant['session_id_hash']}`，切点后 {variant['event_count']} 个事件",
        "- 本报告描述轨迹差异，不判定任务正确性；胜负必须来自独立验收。",
        "",
        "## 请求路由",
        "",
        "```json",
        json.dumps({"baseline": baseline["routes"], "variant": variant["routes"]}, ensure_ascii=False, indent=2),
        "```",
        "",
        "## Token 与时长",
        "",
        "| 指标 | baseline | variant |",
        "|---|---:|---:|",
    ]
    for key in TOKEN_KEYS:
        lines.append(f"| {key} | {baseline['tokens'][key]} | {variant['tokens'][key]} |")
    lines.append(
        "| trajectory_elapsed_ms | "
        f"{baseline['trajectory_elapsed_ms'] or ''} | {variant['trajectory_elapsed_ms'] or ''} |"
    )
    lines.extend(["", "## 工具调用", "", "| # | baseline | variant |", "|---:|---|---|"])
    for index in range(max(len(baseline["tools"]), len(variant["tools"]))):
        left = baseline["tools"][index] if index < len(baseline["tools"]) else None
        right = variant["tools"][index] if index < len(variant["tools"]) else None
        left_text = (
            ""
            if left is None
            else f"{markdown_inline(left['name'])} {markdown_inline(left['arguments_preview'])} → "
            f"{markdown_inline(left['result_preview'])}"
        )
        right_text = (
            ""
            if right is None
            else f"{markdown_inline(right['name'])} {markdown_inline(right['arguments_preview'])} → "
            f"{markdown_inline(right['result_preview'])}"
        )
        lines.append(f"| {index + 1} | {left_text} | {right_text} |")
    if not baseline["tools"] and not variant["tools"]:
        lines.append("|  | 无 | 无 |")
    lines.extend(
        [
            "",
            "## 结构分叉",
            "",
            "```json",
            json.dumps(result["sequence_delta"], ensure_ascii=False, indent=2),
            "```",
            "",
            "## 轮次结局",
            "",
            "```json",
            json.dumps(
                {"baseline": baseline["turn_outcomes"], "variant": variant["turn_outcomes"]},
                ensure_ascii=False,
                indent=2,
            ),
            "```",
            "",
        ]
    )
    return "\n".join(lines)


def compare(args: argparse.Namespace) -> int:
    baseline_session = parse_session(Path(args.baseline).resolve(), args.baseline_member)
    variant_session = parse_session(Path(args.variant).resolve(), args.variant_member)
    cut_seq, cut_source = resolve_cut(baseline_session, variant_session, args.cut_seq)
    sensitive_values = sensitive_session_values(baseline_session, variant_session)
    baseline = trajectory_summary(baseline_session, cut_seq, sensitive_values)
    variant = trajectory_summary(variant_session, cut_seq, sensitive_values)
    result = {
        "schema": "dsh-time-machine-comparison/v1",
        "cut": {"seq": cut_seq, "source": cut_source},
        "baseline": baseline,
        "variant": variant,
        "sequence_delta": sequence_delta(baseline.pop("signatures"), variant.pop("signatures")),
        "tool_delta": tool_delta(baseline["tools"], variant["tools"]),
        "verdict": None,
        "verdict_note": (
            "Run an independent acceptance oracle; trajectory differences alone do not determine correctness."
        ),
    }
    output = Path(args.output_dir).resolve()
    if output.exists():
        raise ValueError(f"refusing to write comparison into existing path: {output}")
    output.mkdir(parents=True, exist_ok=False)
    (output / "comparison.json").write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (output / "comparison.md").write_text(render_markdown(result), encoding="utf-8")
    print(f"wrote {output / 'comparison.json'}")
    print(f"wrote {output / 'comparison.md'}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("baseline")
    parser.add_argument("variant")
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--cut-seq", type=int)
    parser.add_argument("--baseline-member")
    parser.add_argument("--variant-member")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if args.cut_seq is not None and args.cut_seq < 0:
        raise SystemExit("error: --cut-seq must be non-negative")
    try:
        return compare(args)
    except (OSError, UnicodeError, ValueError, RuntimeError, zipfile.BadZipFile) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
