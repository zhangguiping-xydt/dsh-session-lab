#!/usr/bin/env python3
"""Analyze DSH trajectories, validate Skills, and audit paired Skill evaluations."""

from __future__ import annotations

import argparse
import hashlib
import html
import json
import re
import stat
import statistics
import sys
import zipfile
from collections import Counter
from collections.abc import Iterable
from pathlib import Path, PurePosixPath
from typing import Any

MAX_LOG_BYTES = 128 * 1024 * 1024
# Keep the reader limits aligned with dsh-capsule and dsh-time-machine.  The
# compressed archive is capped separately; this is the expanded-size budget.
MAX_TOTAL_BYTES = 512 * 1024 * 1024
MAX_ARCHIVE_BYTES = 256 * 1024 * 1024
MAX_ARCHIVE_FILES = 10_000
MAX_ENTRY_BYTES = 128 * 1024 * 1024
MAX_EVIDENCE_BYTES = 128 * 1024 * 1024
MAX_EVIDENCE_FILES = 32
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
USER_PATH_PATTERNS = (
    re.compile(r"(?<![A-Za-z0-9_])/(?:home|Users)/[^/\s]+"),
    re.compile(r"(?i)\b[A-Z]:\\Users\\[^\\\s]+"),
)
EMAIL_PATTERN = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
URL_PATTERN = re.compile(r"\bhttps?://[^\s<>\"']+")
RESOURCE_REF = re.compile(r"(?<![A-Za-z0-9_.-])((?:scripts|references|assets)/[A-Za-z0-9_./-]+)")
KEBAB = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
PACKED_STORAGE_TYPES = {"text-chunks", "reasoning-chunks", "tool-call-chunks"}
EVAL_CATEGORIES = {"near", "structural", "boundary", "interference"}
EVAL_FAILURE_CLASSES = {
    "baseline_contamination",
    "routing_miss",
    "false_positive",
    "procedure_failure",
    "unsafe_action",
    "verification_failure",
    "environment_failure",
    "oracle_failure",
}
HEX_DIGEST = re.compile(r"^[0-9a-f]{64}$")
SESSION_HASH = re.compile(r"^[0-9a-f]{8,64}$")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def safe_member(name: str) -> bool:
    path = PurePosixPath(name)
    return (
        bool(name)
        and not path.is_absolute()
        and all(part not in ("", ".", "..") for part in name.split("/"))
        and not any(ord(character) < 32 or ord(character) == 127 for character in name)
        and "\\" not in name
    )


def digest_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def zip_is_symlink(info: zipfile.ZipInfo) -> bool:
    return stat.S_IFMT(info.external_attr >> 16) == stat.S_IFLNK


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
                    raise ValueError("capsule expands beyond the 512 MiB analysis limit")
            chunks.append(chunk)
    return b"".join(chunks)


def validate_capsule_archive(source: Path) -> None:
    """Validate a .dshc manifest before reading any session log from it."""
    with zipfile.ZipFile(source) as archive:
        infos = archive.infolist()
        if len(infos) > MAX_ARCHIVE_FILES:
            raise ValueError(f"capsule contains more than {MAX_ARCHIVE_FILES} entries")
        names: set[str] = set()
        total = 0
        for info in infos:
            if info.is_dir():
                continue
            if not safe_member(info.filename):
                raise ValueError(f"unsafe capsule member: {info.filename!r}")
            if zip_is_symlink(info):
                raise ValueError(f"symbolic-link capsule member is not allowed: {info.filename}")
            if info.filename in names:
                raise ValueError(f"duplicate capsule member: {info.filename}")
            if info.file_size > MAX_ENTRY_BYTES:
                raise ValueError(f"capsule member exceeds {MAX_ENTRY_BYTES // (1024 * 1024)} MiB: {info.filename}")
            total += info.file_size
            if total > MAX_TOTAL_BYTES:
                raise ValueError("capsule expands beyond the 512 MiB analysis limit")
            names.add(info.filename)
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
        if names != expected | {"manifest.json"}:
            raise ValueError("capsule manifest does not match ZIP members")


def load_logs(source: Path) -> list[tuple[str, str]]:
    if not source.exists():
        raise ValueError(f"input does not exist: {source}")
    if source.is_dir():
        found = sorted(item for item in source.rglob("session.jsonl") if not item.is_symlink())
        if not found:
            raise ValueError(f"no session.jsonl found under: {source}")
        if len(found) > MAX_ARCHIVE_FILES:
            raise ValueError(f"session directory contains more than {MAX_ARCHIVE_FILES} logs")
        total = sum(item.stat().st_size for item in found)
        if total > MAX_TOTAL_BYTES:
            raise ValueError("session logs exceed the 512 MiB analysis limit")
        return [(str(item.relative_to(source)), read_text_limited(item)) for item in found]
    if source.stat().st_size > MAX_ARCHIVE_BYTES:
        raise ValueError(f"input archive exceeds {MAX_ARCHIVE_BYTES // (1024 * 1024)} MiB")
    if source.suffix == ".dshc":
        if not zipfile.is_zipfile(source):
            raise ValueError(".dshc input is not a ZIP capsule")
        validate_capsule_archive(source)
    if zipfile.is_zipfile(source):
        logs: list[tuple[str, str]] = []
        total = 0
        budget = [0]
        with zipfile.ZipFile(source) as archive:
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
                if not info.filename.endswith("session.jsonl"):
                    continue
                if info.file_size > MAX_LOG_BYTES:
                    raise ValueError(f"session log exceeds 128 MiB: {info.filename}")
                total += info.file_size
                if total > MAX_TOTAL_BYTES:
                    raise ValueError("session logs exceed the 512 MiB analysis limit")
                logs.append((info.filename, read_member(archive, info, budget, MAX_LOG_BYTES).decode("utf-8")))
        if not logs:
            raise ValueError("archive contains no session.jsonl")
        return logs
    return [(source.name, read_text_limited(source))]


def read_text_limited(path: Path) -> str:
    size = path.stat().st_size
    if size > MAX_LOG_BYTES:
        raise ValueError(f"session log exceeds 128 MiB: {path}")
    return path.read_text(encoding="utf-8")


class PreviewRedactor:
    """Conservative preview scrubber; output remains non-public by default."""

    def __init__(self, session_ids: Iterable[str], attachment_ids: Iterable[str], workspaces: Iterable[str]) -> None:
        self.session_replacements = {value: f"session-{index:03d}" for index, value in enumerate(session_ids, 1)}
        self.attachment_replacements = {
            value: f"attachment-{index:03d}" for index, value in enumerate(attachment_ids, 1)
        }
        self.workspaces = sorted((value for value in workspaces if value), key=len, reverse=True)

    def scrub(self, value: str) -> str:
        result = value
        for original, alias in sorted(self.session_replacements.items(), key=lambda item: len(item[0]), reverse=True):
            result = result.replace(original, alias)
        for original, alias in sorted(
            self.attachment_replacements.items(), key=lambda item: len(item[0]), reverse=True
        ):
            result = result.replace(original, alias)
        for workspace in self.workspaces:
            result = result.replace(workspace, "<WORKSPACE>")
        for pattern, replacement in SECRET_PATTERNS:
            result = pattern.sub(replacement, result)
        for pattern in USER_PATH_PATTERNS:
            result = pattern.sub("<USER_HOME>", result)
        result = EMAIL_PATTERN.sub("<EMAIL>", result)
        result = URL_PATTERN.sub("<URL>", result)
        return result


def scrub_text(value: str, redactor: PreviewRedactor) -> str:
    return redactor.scrub(value)


def preview(value: Any, limit: int, redactor: PreviewRedactor) -> str:
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
    text = scrub_text(" ".join(strings), redactor)
    text = re.sub(r"\s+", " ", text).strip()
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


def event_preview_value(kind: str, data: dict[str, Any]) -> Any:
    if kind == "assistant/message":
        return visible_message_text(data.get("message"))
    if kind == "assistant/chunk":
        chunk = data.get("chunk")
        if isinstance(chunk, dict):
            if chunk.get("type") == "reasoning-delta":
                return "<REDACTED_REASONING>"
            block = chunk.get("block")
            if isinstance(block, dict) and block.get("type") == "reasoning":
                return "<REDACTED_REASONING>"
    return data


def parse_log(name: str, content: str, preview_chars: int, redactor: PreviewRedactor) -> dict[str, Any]:
    records: list[dict[str, Any]] = []
    for line_number, raw in enumerate(content.splitlines(), 1):
        if not raw.strip():
            continue
        try:
            value = json.loads(raw)
        except json.JSONDecodeError as error:
            raise ValueError(f"{name}:{line_number}: invalid JSON: {error.msg}") from error
        if not isinstance(value, dict):
            raise ValueError(f"{name}:{line_number}: JSONL record is not an object")
        records.append(value)
    if not records or records[0].get("type") != "session":
        raise ValueError(f"{name}: first record is not a DSH session header")
    for expected_seq, event in enumerate(records[1:]):
        if event.get("type") in PACKED_STORAGE_TYPES:
            raise ValueError(
                f"{name}: contains packed DSH persistence records; use DSH /export instead of decompressing "
                "session.jsonl.zstd"
            )
        seq = event.get("seq")
        if not isinstance(seq, int) or isinstance(seq, bool) or seq != expected_seq:
            raise ValueError(f"{name}: event seq must be contiguous from 0; expected {expected_seq}, got {seq!r}")

    header = records[0]
    events = records[1:]
    event_types = Counter(str(event.get("type", "<missing>")) for event in events)
    event_rows: list[dict[str, Any]] = []
    tools: dict[str, dict[str, Any]] = {}
    tool_order: list[str] = []
    call_aliases: dict[str, str] = {}
    user_messages: list[dict[str, Any]] = []
    turn_outcomes: list[dict[str, Any]] = []
    test_signal_count = 0

    for event in events:
        data = event.get("data") if isinstance(event.get("data"), dict) else {}
        kind = str(event.get("type", "<missing>"))
        row = {
            "seq": event.get("seq"),
            "type": kind,
            "turn": data.get("turn"),
            "step": data.get("step"),
            "preview": preview(event_preview_value(kind, data), preview_chars, redactor),
        }
        event_rows.append(row)
        if kind == "user/message":
            user_messages.append({"seq": event.get("seq"), "turn": data.get("turn"), "preview": row["preview"]})
        elif kind == "tool/call":
            raw_call_id = str(data.get("callId", f"seq-{event.get('seq')}"))
            call_id = call_aliases.setdefault(raw_call_id, f"call-{len(call_aliases) + 1:03d}")
            tools[call_id] = {
                "seq": event.get("seq"),
                "call_id": call_id,
                "name": scrub_text(str(data.get("name", "<unknown>")), redactor),
                "arguments_preview": preview(data.get("arguments", ""), preview_chars, redactor),
                "result_seq": None,
                "result_preview": "",
            }
            tool_order.append(call_id)
        elif kind == "tool/result":
            raw_call_id = str(data.get("callId", ""))
            call_id = call_aliases.setdefault(raw_call_id, f"call-{len(call_aliases) + 1:03d}") if raw_call_id else ""
            entry = tools.setdefault(
                call_id or f"orphan-{event.get('seq')}",
                {
                    "seq": None,
                    "call_id": call_id or "<orphan>",
                    "name": "<unknown>",
                    "arguments_preview": "",
                    "result_seq": None,
                    "result_preview": "",
                },
            )
            entry["result_seq"] = event.get("seq")
            entry["result_preview"] = row["preview"]
            if re.search(r"(?i)\b(?:tests? passed|passed all|0 failed|success)\b", row["preview"]):
                test_signal_count += 1
        elif kind == "turn/end":
            reason = data.get("reason")
            turn_outcomes.append(
                {
                    "seq": event.get("seq"),
                    "turn": data.get("turn"),
                    "reason": scrub_text(reason, redactor)
                    if isinstance(reason, str)
                    else reason
                    if isinstance(reason, (int, float, bool, type(None)))
                    else preview(reason, preview_chars, redactor),
                    "completed": isinstance(reason, dict) and reason.get("kind") == "completed",
                }
            )

    session_id = str(header.get("id", "<unknown>"))
    session_hash = hashlib.sha256(session_id.encode("utf-8")).hexdigest()[:16]
    header_summary = {
        "id_hash": session_hash,
        "version": header.get("version"),
        "created_at": header.get("createdAt"),
        "cwd": "<WORKSPACE>" if header.get("cwd") else None,
        "parent_present": header.get("parentSession") is not None,
        "seed_length": header.get("seedLength"),
        "origin": scrub_text(str(header.get("origin")), redactor) if header.get("origin") is not None else None,
        "delegation_depth": header.get("delegationDepth"),
        "agent_preset": scrub_text(str(header.get("agentPreset")), redactor) if header.get("agentPreset") else None,
    }
    return {
        "member": redactor.scrub(name),
        "header": header_summary,
        "event_count": len(events),
        "event_types": dict(sorted(event_types.items())),
        "turn_outcomes": turn_outcomes,
        "user_messages": user_messages,
        "tools": [tools[item] for item in tool_order]
        + [value for key, value in tools.items() if key not in tool_order],
        "heuristic_test_signal_count": test_signal_count,
        "events": event_rows,
    }


def collect_keyed_strings(value: Any, key_name: str) -> list[str]:
    found: list[str] = []
    stack: list[Any] = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, dict):
            for key, child in item.items():
                if key == key_name and isinstance(child, str) and child not in found:
                    found.append(child)
                else:
                    stack.append(child)
        elif isinstance(item, list):
            stack.extend(item)
    return found


def markdown_inline(value: Any) -> str:
    """Render untrusted text without allowing Markdown/HTML structure changes."""
    return (
        html.escape(str(value), quote=False)
        .replace("`", "&#96;")
        .replace("|", "\\|")
        .replace("\r", " ")
        .replace("\n", " ")
    )


def render_markdown(result: dict[str, Any]) -> str:
    lines = [
        "# DSH 轨迹清单",
        "",
        f"- 原始文件 SHA-256：`{result['source_sha256']}`",
        f"- Session 日志数：{len(result['sessions'])}",
        "- 注意：预览已做模式脱敏，但仍需人工保密审查；测试信号只是文本启发式，不是验收结论。",
        "",
    ]
    for session in result["sessions"]:
        header = session["header"]
        completed_turns = sum(1 for item in session["turn_outcomes"] if item["completed"])
        lines.extend(
            [
                f"## {markdown_inline(session['member'])}",
                "",
                f"- Session 哈希：`{header['id_hash']}`",
                f"- Agent Preset：`{markdown_inline(header['agent_preset'] or '未知')}`",
                f"- 事件数：{session['event_count']}；完成轮次：{completed_turns}",
                f"- 启发式测试成功信号：{session['heuristic_test_signal_count']}",
                "",
                "### 工具轨迹",
                "",
                "| seq | 工具 | 参数预览 | 结果 seq | 结果预览 |",
                "|---:|---|---|---:|---|",
            ]
        )
        for tool in session["tools"]:
            args = markdown_inline(tool["arguments_preview"])
            outcome = markdown_inline(tool["result_preview"])
            tool_name = markdown_inline(tool["name"])
            lines.append(f"| {tool['seq'] or ''} | `{tool_name}` | {args} | {tool['result_seq'] or ''} | {outcome} |")
        if not session["tools"]:
            lines.append("|  | 无 |  |  |  |")
        lines.extend(["", "### 用户消息候选", ""])
        for message in session["user_messages"]:
            lines.append(f"- seq {message['seq']}：{markdown_inline(message['preview'])}")
        if not session["user_messages"]:
            lines.append("- 无")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def analyze(args: argparse.Namespace) -> int:
    source = Path(args.input).resolve()
    output = Path(args.output_dir).resolve()
    if output.exists():
        raise ValueError(f"refusing to write analysis into existing path: {output}")
    logs = load_logs(source)
    output.mkdir(parents=True, exist_ok=False)
    session_ids: list[str] = []
    attachment_ids: list[str] = []
    workspaces: list[str] = []
    for name, content in logs:
        path_parts = PurePosixPath(name).parts
        for index, part in enumerate(path_parts[:-1]):
            if part in {"subagents", "sessions"} and index + 1 < len(path_parts) - 1:
                if path_parts[index + 1] not in session_ids:
                    session_ids.append(path_parts[index + 1])
        for line in content.splitlines():
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(record, dict):
                continue
            for key in ("id", "sessionId", "parentSession", "parentSessionId", "childSessionId"):
                for value in collect_keyed_strings(record, key):
                    if value not in session_ids:
                        session_ids.append(value)
            for value in collect_keyed_strings(record, "attachmentId"):
                if value not in attachment_ids:
                    attachment_ids.append(value)
            if record.get("type") == "session" and isinstance(record.get("cwd"), str):
                if record["cwd"] not in workspaces:
                    workspaces.append(record["cwd"])
    redactor = PreviewRedactor(session_ids, attachment_ids, workspaces)
    sessions = [parse_log(name, content, args.preview_chars, redactor) for name, content in logs]
    result = {
        "schema": "dsh-teach-trajectory/v1",
        "source_name": source.name,
        "source_sha256": sha256_file(source) if source.is_file() else None,
        "sessions": sessions,
    }
    (output / "trajectory.json").write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (output / "trajectory.md").write_text(render_markdown(result), encoding="utf-8")
    print(f"wrote {output / 'trajectory.json'}")
    print(f"wrote {output / 'trajectory.md'}")
    return 0


def read_frontmatter(path: Path) -> tuple[dict[str, str], str]:
    text = path.read_text(encoding="utf-8")
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        raise ValueError("SKILL.md must start with YAML frontmatter")
    try:
        end = next(index for index in range(1, len(lines)) if lines[index].strip() == "---")
    except StopIteration as error:
        raise ValueError("SKILL.md frontmatter is not closed") from error
    values: dict[str, str] = {}
    for raw in lines[1:end]:
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        match = re.match(r"^([A-Za-z0-9_-]+):\s*(.*?)\s*$", raw)
        if match:
            values[match.group(1)] = match.group(2).strip("'\"")
    return values, text


def text_files(root: Path) -> Iterable[Path]:
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            continue
        if path.is_file() and path.stat().st_size <= 2 * 1024 * 1024:
            try:
                path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue
            yield path


def validate(args: argparse.Namespace) -> int:
    root = Path(args.skill_dir).resolve()
    errors: list[str] = []
    warnings: list[str] = []
    if not root.is_dir():
        errors.append(f"skill directory does not exist or is not a directory: {root}")
    skill_file = root / "SKILL.md"
    if not skill_file.is_file():
        errors.append("missing SKILL.md")
    else:
        try:
            frontmatter, skill_text = read_frontmatter(skill_file)
            name = frontmatter.get("name", "")
            description = frontmatter.get("description", "")
            if not KEBAB.fullmatch(name):
                errors.append("frontmatter name must be kebab-case")
            if name and root.name != name:
                errors.append(f"directory name {root.name!r} does not match skill name {name!r}")
            if not description:
                errors.append("frontmatter description is required")
            elif len(description) > 500:
                warnings.append("description exceeds DSH's default 500-character catalog rendering limit")
            for reference in sorted(set(RESOURCE_REF.findall(skill_text))):
                target = (root / reference).resolve()
                try:
                    target.relative_to(root)
                except ValueError:
                    errors.append(f"resource reference escapes bundle: {reference}")
                    continue
                if not target.exists():
                    errors.append(f"referenced resource does not exist: {reference}")
        except (OSError, UnicodeError, ValueError) as error:
            errors.append(str(error))

    nested = [path for path in root.rglob("SKILL.md") if path != skill_file]
    if nested:
        errors.append(
            "nested SKILL.md files are not supported: " + ", ".join(str(path.relative_to(root)) for path in nested)
        )

    for path in text_files(root):
        text = path.read_text(encoding="utf-8")
        relative = path.relative_to(root)
        for pattern, _replacement in SECRET_PATTERNS:
            if pattern.search(text):
                errors.append(f"possible secret in {relative}: pattern {pattern.pattern!r}")
        for pattern in USER_PATH_PATTERNS:
            if pattern.search(text):
                errors.append(f"user-specific absolute path in {relative}")

    report = {
        "schema": "dsh-teach-validation/v1",
        "skill_dir": str(root),
        "ok": not errors,
        "errors": errors,
        "warnings": warnings,
    }
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if not errors else 2


def read_json_object(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as error:
        raise ValueError(f"missing evaluation file: {path.name}") from error
    except json.JSONDecodeError as error:
        raise ValueError(f"invalid JSON in {path.name}: {error}") from error
    if not isinstance(value, dict):
        raise ValueError(f"{path.name} must contain one JSON object")
    return value


def read_jsonl_objects(path: Path) -> list[dict[str, Any]]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError as error:
        raise ValueError(f"missing evaluation file: {path.name}") from error
    records: list[dict[str, Any]] = []
    for line_number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as error:
            raise ValueError(f"invalid JSON in {path.name}:{line_number}: {error}") from error
        if not isinstance(value, dict):
            raise ValueError(f"{path.name}:{line_number} must contain a JSON object")
        records.append(value)
    return records


def require_string(record: dict[str, Any], key: str, source: str) -> str:
    value = record.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{source}.{key} must be a non-empty string")
    return value


def require_nonnegative_int(record: dict[str, Any], key: str, source: str) -> int:
    value = record.get(key)
    if type(value) is not int or value < 0:
        raise ValueError(f"{source}.{key} must be a non-negative integer")
    return value


def load_run_evidence(eval_dir: Path, source: str, values: Any) -> dict[str, Any]:
    if not isinstance(values, list) or len(values) != 1:
        raise ValueError(f"{source}.evidence must contain exactly one hashed run-evidence descriptor")
    descriptor = values[0]
    if not isinstance(descriptor, dict):
        raise ValueError(f"{source}.evidence descriptor must be an object")
    path_value = descriptor.get("path")
    digest = descriptor.get("sha256")
    if not isinstance(path_value, str) or not safe_member(path_value):
        raise ValueError(f"{source}.evidence contains an unsafe path")
    if not isinstance(digest, str) or not HEX_DIGEST.fullmatch(digest):
        raise ValueError(f"{source}.evidence.sha256 must be a lowercase SHA-256 digest")
    target = (eval_dir / path_value).resolve()
    try:
        target.relative_to(eval_dir)
    except ValueError as error:
        raise ValueError(f"{source}.evidence escapes the evaluation directory: {path_value}") from error
    if not target.is_file():
        raise ValueError(f"{source}.evidence file does not exist: {path_value}")
    if target.stat().st_size > MAX_EVIDENCE_BYTES:
        raise ValueError(f"{source}.evidence exceeds {MAX_EVIDENCE_BYTES // (1024 * 1024)} MiB")
    if sha256_file(target) != digest:
        raise ValueError(f"{source}.evidence SHA-256 mismatch: {path_value}")
    evidence = read_json_object(target)
    if evidence.get("schema") != "dsh-teach-run-evidence/v1":
        raise ValueError(f"{source}.evidence has an unsupported schema")
    return evidence


def event_data(event: dict[str, Any]) -> dict[str, Any]:
    value = event.get("data")
    return value if isinstance(value, dict) else {}


def evidence_events(evidence: dict[str, Any], source: str) -> list[dict[str, Any]]:
    values = evidence.get("events")
    if not isinstance(values, list) or not values:
        raise ValueError(f"{source}.evidence.events must be a non-empty array")
    events: list[dict[str, Any]] = []
    for expected_seq, value in enumerate(values):
        if not isinstance(value, dict):
            raise ValueError(f"{source}.evidence.events[{expected_seq}] must be an object")
        seq = value.get("seq")
        if type(seq) is not int or seq != expected_seq:
            raise ValueError(f"{source}.evidence event seq must be contiguous from 0")
        events.append(value)
    return events


def evidence_tool_calls(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [event_data(event) for event in events if event.get("type") == "tool/call"]


def evidence_skill_loaded(events: list[dict[str, Any]], skill_name: str) -> bool:
    for call in evidence_tool_calls(events):
        if call.get("name") != "skill":
            continue
        arguments = call.get("arguments")
        if isinstance(arguments, str):
            try:
                arguments = json.loads(arguments)
            except json.JSONDecodeError:
                continue
        if isinstance(arguments, dict) and arguments.get("name") == skill_name:
            return True
    return False


def evidence_visible_response(events: list[dict[str, Any]]) -> str:
    for event in reversed(events):
        if event.get("type") != "assistant/message":
            continue
        return visible_message_text(event_data(event).get("message")).strip()
    return ""


def evidence_usage(events: list[dict[str, Any]]) -> tuple[int, int]:
    input_tokens = 0
    output_tokens = 0
    for event in events:
        if event.get("type") != "assistant/message":
            continue
        usage = event_data(event).get("usage")
        if not isinstance(usage, dict):
            continue
        if type(usage.get("inputTokens")) is int:
            input_tokens += usage["inputTokens"]
        if type(usage.get("outputTokens")) is int:
            output_tokens += usage["outputTokens"]
    return input_tokens, output_tokens


def evidence_elapsed_ms(events: list[dict[str, Any]]) -> int:
    times = [event.get("time") for event in events if type(event.get("time")) is int]
    return max(times) - min(times) if len(times) >= 2 else 0


def evidence_oracle_pass(task: dict[str, Any], evidence: dict[str, Any], events: list[dict[str, Any]]) -> bool:
    """Audit the recorded oracle result; a command_exit command is never re-executed here."""
    oracle = task["oracle"]
    if oracle["kind"] == "exact_response":
        return evidence_visible_response(events) == oracle["expected"]
    result = evidence.get("oracle_result")
    if not isinstance(result, dict) or result.get("kind") != "command_exit":
        raise ValueError("command_exit oracle requires evidence.oracle_result")
    if result.get("command") != oracle["command"]:
        raise ValueError("evidence oracle command does not match the frozen task")
    exit_code = result.get("exit_code")
    if type(exit_code) is not int:
        raise ValueError("evidence oracle exit_code must be an integer")
    for field in ("stdout", "stderr"):
        if not isinstance(result.get(field), str):
            raise ValueError(f"evidence oracle {field} must be a string")
    return exit_code in oracle["success_exit_codes"]


def validate_request_configs(events: list[dict[str, Any]], manifest: dict[str, Any], source: str) -> None:
    configs: list[dict[str, Any]] = []
    for event in events:
        if event.get("type") != "request/header":
            continue
        header = event_data(event).get("header")
        config = header.get("config") if isinstance(header, dict) else None
        if isinstance(config, dict):
            configs.append(config)
    if not configs:
        raise ValueError(f"{source}.evidence has no request/header config")
    expected = {
        "provider": manifest["provider"],
        "model": manifest["model"],
        "reasoningEffort": manifest["reasoning_effort"],
    }
    if any(any(config.get(key) != value for key, value in expected.items()) for config in configs):
        raise ValueError(f"{source}.evidence request config does not match manifest")


def failure_class_for(
    task: dict[str, Any], arm: str, skill_loaded: bool, acceptance_pass: bool, safety_pass: bool
) -> str | None:
    if arm == "baseline" and skill_loaded:
        return "baseline_contamination"
    if not safety_pass:
        return "unsafe_action"
    if arm == "treatment" and task["expected_trigger"] and not skill_loaded:
        return "routing_miss"
    if arm == "treatment" and not task["expected_trigger"] and skill_loaded:
        return "false_positive"
    if not acceptance_pass:
        return "procedure_failure"
    return None


def derived_run_result(
    task: dict[str, Any], manifest: dict[str, Any], evidence: dict[str, Any], source: str
) -> dict[str, Any]:
    for field in ("task_id", "arm", "session_id_hash", "sdk_version", "runtime_version"):
        require_string(evidence, field, f"{source}.evidence")
    run = require_nonnegative_int(evidence, "run", f"{source}.evidence")
    if evidence["sdk_version"] != manifest["sdk_version"] or evidence["runtime_version"] != manifest["runtime_version"]:
        raise ValueError(f"{source}.evidence runtime versions do not match manifest")
    events = evidence_events(evidence, source)
    validate_request_configs(events, manifest, source)
    calls = evidence_tool_calls(events)
    skill_loaded = evidence_skill_loaded(events, manifest["skill"])
    acceptance_pass = evidence_oracle_pass(task, evidence, events)
    allowed_tools = set(task["allowed_tools"])
    safety_pass = all(isinstance(call.get("name"), str) and call["name"] in allowed_tools for call in calls)
    input_tokens, output_tokens = evidence_usage(events)
    arm = evidence["arm"]
    return {
        "task_id": evidence["task_id"],
        "arm": arm,
        "run": run,
        "session_id_hash": evidence["session_id_hash"],
        "skill_loaded": skill_loaded,
        "acceptance_pass": acceptance_pass,
        "safety_pass": safety_pass,
        "tool_calls": len(calls),
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "elapsed_ms": evidence_elapsed_ms(events),
        "failure_class": failure_class_for(task, arm, skill_loaded, acceptance_pass, safety_pass),
    }


def render_eval_markdown(report: dict[str, Any], rows: list[dict[str, Any]]) -> str:
    summary = report["summary"]
    lines = [
        "# Skill 独立评测报告",
        "",
        f"- Skill：`{markdown_inline(report['skill'])}`",
        f"- 候选哈希：`{report['candidate_sha256']}`",
        f"- 请求配置：`{markdown_inline(report['provider'])}/{markdown_inline(report['model'])}`，"
        f"推理强度 `{markdown_inline(report['reasoning_effort'])}`",
        f"- SDK/Runtime：`{markdown_inline(report['sdk_version'])}` / `{markdown_inline(report['runtime_version'])}`",
        f"- Agent Preset：`{markdown_inline(report['agent_preset'])}`",
        f"- 推广结论：`{'PASS' if report['promoted'] else 'FAIL'}`",
        f"- baseline 通过：{summary['baseline']['acceptance_pass']}/{summary['baseline']['runs']}",
        f"- treatment 通过：{summary['treatment']['acceptance_pass']}/{summary['treatment']['runs']}",
        f"- 通过数增量：{summary['acceptance_delta']}",
        (
            f"- 安全失败：{summary['safety_failures']}；baseline 污染：{summary['baseline_contaminations']}；"
            f"误触发：{summary['false_positives']}；"
            f"漏触发：{summary['routing_misses']}"
        ),
        "",
        "## 任务明细",
        "",
        "| task | category | run | baseline | treatment | loaded | safety | failure |",
        "|---|---|---:|---:|---:|---:|---:|---|",
    ]
    for row in rows:
        lines.append(
            f"| {markdown_inline(row['task_id'])} | {markdown_inline(row['category'])} | {row['run']} | "
            f"{'PASS' if row['baseline_acceptance'] else 'FAIL'} | "
            f"{'PASS' if row['treatment_acceptance'] else 'FAIL'} | "
            f"{'yes' if row['treatment_skill_loaded'] else 'no'} | "
            f"{'PASS' if row['safety_pass'] else 'FAIL'} | {markdown_inline(row['failure_class'] or '')} |"
        )
    lines.extend(
        [
            "",
            "## 中位数",
            "",
            "| arm | tool calls | input tokens | output tokens | elapsed ms |",
            "|---|---:|---:|---:|---:|",
        ]
    )
    for arm in ("baseline", "treatment"):
        medians = summary[arm]["medians"]
        lines.append(
            f"| {arm} | {medians['tool_calls']} | {medians['input_tokens']} | "
            f"{medians['output_tokens']} | {medians['elapsed_ms']} |"
        )
    return "\n".join(lines).rstrip() + "\n"


def eval_report(args: argparse.Namespace) -> int:
    eval_dir = Path(args.eval_dir).resolve()
    if not eval_dir.is_dir():
        raise ValueError(f"evaluation directory does not exist: {eval_dir}")
    manifest = read_json_object(eval_dir / "manifest.json")
    tasks = read_jsonl_objects(eval_dir / "tasks.jsonl")
    results = read_jsonl_objects(eval_dir / "results.jsonl")

    if manifest.get("schema") != "dsh-teach-eval-manifest/v2":
        raise ValueError("manifest.schema must be dsh-teach-eval-manifest/v2")
    skill_name = require_string(manifest, "skill", "manifest")
    if not KEBAB.fullmatch(skill_name):
        raise ValueError("manifest.skill must be kebab-case")
    candidate_sha256 = require_string(manifest, "candidate_sha256", "manifest")
    if not HEX_DIGEST.fullmatch(candidate_sha256):
        raise ValueError("manifest.candidate_sha256 must be a lowercase SHA-256 digest")
    for key in (
        "provider",
        "model",
        "reasoning_effort",
        "agent_preset",
        "sdk_version",
        "runtime_version",
        "primary_metric",
        "promotion_rule",
        "frozen_at",
    ):
        require_string(manifest, key, "manifest")
    if manifest["primary_metric"] != "acceptance_pass":
        raise ValueError("manifest.primary_metric must be acceptance_pass")
    task_count = require_nonnegative_int(manifest, "task_count", "manifest")
    repetitions = require_nonnegative_int(manifest, "repetitions", "manifest")
    if task_count < 5 or len(tasks) < 5:
        raise ValueError("evaluation requires at least 5 tasks")
    if task_count != len(tasks):
        raise ValueError("manifest.task_count does not match tasks.jsonl")
    if repetitions < 1:
        raise ValueError("manifest.repetitions must be at least 1")
    promotion = manifest.get("promotion")
    if not isinstance(promotion, dict):
        raise ValueError("manifest.promotion must be an object")
    if type(promotion.get("require_all_safety")) is not bool:
        raise ValueError("manifest.promotion.require_all_safety must be a boolean")
    if type(promotion.get("require_clean_baseline")) is not bool:
        raise ValueError("manifest.promotion.require_clean_baseline must be a boolean")
    for key in ("max_false_positives", "max_routing_misses", "min_acceptance_delta"):
        require_nonnegative_int(promotion, key, "manifest.promotion")

    task_by_id: dict[str, dict[str, Any]] = {}
    categories: set[str] = set()
    for index, task in enumerate(tasks, start=1):
        source = f"tasks.jsonl:{index}"
        task_id = require_string(task, "task_id", source)
        if task_id in task_by_id:
            raise ValueError(f"duplicate task_id: {task_id}")
        category = require_string(task, "category", source)
        if category not in EVAL_CATEGORIES:
            raise ValueError(f"{source}.category is unsupported: {category}")
        for key in ("prompt", "workspace_baseline", "acceptance"):
            require_string(task, key, source)
        if type(task.get("expected_trigger")) is not bool:
            raise ValueError(f"{source}.expected_trigger must be a boolean")
        forbidden = task.get("forbidden_behaviors")
        if (
            not isinstance(forbidden, list)
            or not forbidden
            or not all(isinstance(value, str) and value for value in forbidden)
        ):
            raise ValueError(f"{source}.forbidden_behaviors must be a non-empty string array")
        allowed_tools = task.get("allowed_tools")
        if not isinstance(allowed_tools, list) or not all(isinstance(value, str) and value for value in allowed_tools):
            raise ValueError(f"{source}.allowed_tools must be a string array")
        oracle = task.get("oracle")
        if not isinstance(oracle, dict) or oracle.get("kind") not in {"exact_response", "command_exit"}:
            raise ValueError(f"{source}.oracle must use exact_response or command_exit")
        if oracle["kind"] == "exact_response":
            if not isinstance(oracle.get("expected"), str):
                raise ValueError(f"{source}.oracle.expected must be a string")
        else:
            require_string(oracle, "command", f"{source}.oracle")
            success_codes = oracle.get("success_exit_codes")
            if (
                not isinstance(success_codes, list)
                or not success_codes
                or not all(type(value) is int for value in success_codes)
            ):
                raise ValueError(f"{source}.oracle.success_exit_codes must be a non-empty integer array")
        task_by_id[task_id] = task
        categories.add(category)
    missing_categories = EVAL_CATEGORIES - categories
    if missing_categories:
        raise ValueError("evaluation is missing task categories: " + ", ".join(sorted(missing_categories)))

    keyed: dict[tuple[str, str, int], dict[str, Any]] = {}
    for index, result in enumerate(results, start=1):
        source = f"results.jsonl:{index}"
        task_id = require_string(result, "task_id", source)
        if task_id not in task_by_id:
            raise ValueError(f"{source} references unknown task_id: {task_id}")
        arm = require_string(result, "arm", source)
        if arm not in {"baseline", "treatment"}:
            raise ValueError(f"{source}.arm must be baseline or treatment")
        run = require_nonnegative_int(result, "run", source)
        if not 1 <= run <= repetitions:
            raise ValueError(f"{source}.run is outside 1..{repetitions}")
        key = (task_id, arm, run)
        if key in keyed:
            raise ValueError(f"duplicate result for {task_id}/{arm}/{run}")
        session_hash = require_string(result, "session_id_hash", source)
        if not SESSION_HASH.fullmatch(session_hash):
            raise ValueError(f"{source}.session_id_hash must be a lowercase hexadecimal hash")
        for field in ("skill_loaded", "acceptance_pass", "safety_pass"):
            if type(result.get(field)) is not bool:
                raise ValueError(f"{source}.{field} must be a boolean")
        for field in ("tool_calls", "input_tokens", "output_tokens", "elapsed_ms"):
            require_nonnegative_int(result, field, source)
        failure_class = result.get("failure_class")
        if failure_class is not None and failure_class not in EVAL_FAILURE_CLASSES:
            raise ValueError(f"{source}.failure_class is unsupported: {failure_class}")
        evidence = load_run_evidence(eval_dir, source, result.get("evidence"))
        derived = derived_run_result(task_by_id[task_id], manifest, evidence, source)
        for field in (
            "task_id",
            "arm",
            "run",
            "session_id_hash",
            "skill_loaded",
            "acceptance_pass",
            "safety_pass",
            "tool_calls",
            "input_tokens",
            "output_tokens",
            "elapsed_ms",
            "failure_class",
        ):
            if result.get(field) != derived[field]:
                raise ValueError(f"{source}.{field} does not match evidence")
        keyed[key] = result

    for task_id in task_by_id:
        for arm in ("baseline", "treatment"):
            for run in range(1, repetitions + 1):
                if (task_id, arm, run) not in keyed:
                    raise ValueError(f"missing result for {task_id}/{arm}/{run}")
    expected_results = task_count * repetitions * 2
    if len(keyed) != expected_results:
        raise ValueError(f"expected {expected_results} paired results, found {len(keyed)}")

    arm_results = {
        arm: [value for (_task, result_arm, _run), value in keyed.items() if result_arm == arm]
        for arm in ("baseline", "treatment")
    }
    summary: dict[str, Any] = {}
    for arm, values in arm_results.items():
        summary[arm] = {
            "runs": len(values),
            "acceptance_pass": sum(value["acceptance_pass"] for value in values),
            "safety_pass": sum(value["safety_pass"] for value in values),
            "medians": {
                field: statistics.median(value[field] for value in values)
                for field in ("tool_calls", "input_tokens", "output_tokens", "elapsed_ms")
            },
        }
    summary["acceptance_delta"] = summary["treatment"]["acceptance_pass"] - summary["baseline"]["acceptance_pass"]
    summary["safety_failures"] = sum(not value["safety_pass"] for value in results)
    summary["baseline_contaminations"] = sum(
        value["skill_loaded"] for (_task_id, arm, _run), value in keyed.items() if arm == "baseline"
    )
    summary["false_positives"] = sum(
        not task_by_id[task_id]["expected_trigger"] and value["skill_loaded"]
        for (task_id, arm, _run), value in keyed.items()
        if arm == "treatment"
    )
    summary["routing_misses"] = sum(
        task_by_id[task_id]["expected_trigger"] and not value["skill_loaded"]
        for (task_id, arm, _run), value in keyed.items()
        if arm == "treatment"
    )
    promoted = (
        (not promotion["require_all_safety"] or summary["safety_failures"] == 0)
        and (not promotion["require_clean_baseline"] or summary["baseline_contaminations"] == 0)
        and summary["false_positives"] <= promotion["max_false_positives"]
        and summary["routing_misses"] <= promotion["max_routing_misses"]
        and summary["acceptance_delta"] >= promotion["min_acceptance_delta"]
    )
    rows = []
    for task_id, task in task_by_id.items():
        for run in range(1, repetitions + 1):
            baseline = keyed[(task_id, "baseline", run)]
            treatment = keyed[(task_id, "treatment", run)]
            rows.append(
                {
                    "task_id": task_id,
                    "category": task["category"],
                    "run": run,
                    "baseline_acceptance": baseline["acceptance_pass"],
                    "treatment_acceptance": treatment["acceptance_pass"],
                    "treatment_skill_loaded": treatment["skill_loaded"],
                    "safety_pass": baseline["safety_pass"] and treatment["safety_pass"],
                    "failure_class": treatment["failure_class"] or baseline["failure_class"],
                }
            )
    report = {
        "schema": "dsh-teach-eval-report/v2",
        "skill": skill_name,
        "candidate_sha256": candidate_sha256,
        "provider": manifest["provider"],
        "model": manifest["model"],
        "reasoning_effort": manifest["reasoning_effort"],
        "agent_preset": manifest["agent_preset"],
        "sdk_version": manifest["sdk_version"],
        "runtime_version": manifest["runtime_version"],
        "promoted": promoted,
        "promotion": promotion,
        "summary": summary,
        "tasks": rows,
    }
    (eval_dir / "report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (eval_dir / "report.md").write_text(render_eval_markdown(report, rows), encoding="utf-8")
    print(json.dumps({"ok": True, "promoted": promoted, "report": str(eval_dir / "report.json")}, ensure_ascii=False))
    return 0 if promoted or not getattr(args, "require_promotion", False) else 3


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    analyze_parser = subparsers.add_parser("analyze", help="create a redacted trajectory inventory")
    analyze_parser.add_argument("input", help="DSH export ZIP, .dshc, session.jsonl, or directory")
    analyze_parser.add_argument("--output-dir", required=True)
    analyze_parser.add_argument("--preview-chars", type=int, default=240)
    analyze_parser.set_defaults(func=analyze)
    validate_parser = subparsers.add_parser("validate", help="validate a candidate Skill bundle")
    validate_parser.add_argument("skill_dir")
    validate_parser.set_defaults(func=validate)
    eval_parser = subparsers.add_parser("eval-report", help="validate paired evaluation evidence and write reports")
    eval_parser.add_argument("eval_dir")
    eval_parser.add_argument(
        "--require-promotion",
        action="store_true",
        help="return a non-zero status when the evidence is valid but the frozen promotion rule fails",
    )
    eval_parser.set_defaults(func=eval_report)
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    if hasattr(args, "preview_chars") and not 40 <= args.preview_chars <= 2000:
        parser.error("--preview-chars must be between 40 and 2000")
    try:
        return int(args.func(args))
    except (OSError, UnicodeError, ValueError, RuntimeError, zipfile.BadZipFile) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
