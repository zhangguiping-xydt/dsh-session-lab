#!/usr/bin/env python3
"""Pack, inspect, verify, and safely extract a DSH session capsule."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import stat
import sys
import zipfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any

FORMAT = "dsh-capsule"
VERSION = 1
MAX_FILES = 10_000
MAX_ARCHIVE_BYTES = 256 * 1024 * 1024
MAX_ENTRY_BYTES = 128 * 1024 * 1024
MAX_TOTAL_BYTES = 512 * 1024 * 1024
MAX_PATCH_BYTES = 32 * 1024 * 1024
SENSITIVE_FIELD_PATTERN = (
    r"(?:x[_-]?api[_-]?key|api[_-]?key|access[_-]?token|refresh[_-]?token|auth[_-]?token|"
    r"session[_-]?token|token|authorization|proxy[_-]?authorization|cookie|set[_-]?cookie|password|passwd|"
    r"secret|client[_-]?secret|private[_-]?key|aws[_-]?access[_-]?key[_-]?id|aws[_-]?secret[_-]?access[_-]?key|"
    r"credentials?)"
)
SECRET_KEYS = re.compile(rf"(?i)^{SENSITIVE_FIELD_PATTERN}$")
SESSION_KEYS = {"sessionId", "parentSession", "parentSessionId", "childSessionId"}
ATTACHMENT_KEYS = {"attachmentId"}
PACKED_STORAGE_TYPES = {"text-chunks", "reasoning-chunks", "tool-call-chunks"}
SECRET_PATTERNS = (
    ("private_key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), "<REDACTED_PRIVATE_KEY>"),
    ("bearer", re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{12,}"), "Bearer <REDACTED>"),
    ("api_key", re.compile(r"\b(?:sk|dsk)-[A-Za-z0-9_-]{16,}"), "<REDACTED_API_KEY>"),
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"), "<REDACTED_AWS_ACCESS_KEY>"),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,255}\b"), "<REDACTED_GITHUB_TOKEN>"),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), "<REDACTED_SLACK_TOKEN>"),
    (
        "jwt",
        re.compile(r"\beyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\b"),
        "<REDACTED_JWT>",
    ),
    (
        "named_secret",
        re.compile(rf"(?i)\b({SENSITIVE_FIELD_PATTERN}['\"]?\s*[:=]\s*['\"]?)[^\s'\",;]{{8,}}"),
        r"\1<REDACTED>",
    ),
)
HOME_PATTERNS = (
    re.compile(r"(?<![A-Za-z0-9_])/(?:home|Users)/[^/\s]+"),
    re.compile(r"(?i)\b[A-Z]:\\Users\\[^\\\s]+"),
)
EMAIL_PATTERN = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
URL_PATTERN = re.compile(r"\bhttps?://[^\s<>\"']+")


def digest_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digest_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate_member_name(name: str) -> None:
    if not name or any(ord(character) < 32 or ord(character) == 127 for character in name) or "\\" in name:
        raise ValueError(f"unsafe archive member name: {name!r}")
    path = PurePosixPath(name)
    if path.is_absolute() or any(part in ("", ".", "..") for part in name.split("/")):
        raise ValueError(f"unsafe archive member name: {name!r}")


def zip_is_symlink(info: zipfile.ZipInfo) -> bool:
    return stat.S_IFMT(info.external_attr >> 16) == stat.S_IFLNK


def read_member(archive: zipfile.ZipFile, member: str | zipfile.ZipInfo, budget: list[int] | None = None) -> bytes:
    """Decompress one ZIP member in bounded chunks; declared header sizes are not trusted."""
    name = member if isinstance(member, str) else member.filename
    chunks: list[bytes] = []
    size = 0
    with archive.open(member) as handle:
        while chunk := handle.read(1024 * 1024):
            size += len(chunk)
            if size > MAX_ENTRY_BYTES:
                raise ValueError(f"archive member exceeds 128 MiB: {name}")
            if budget is not None:
                budget[0] += len(chunk)
                if budget[0] > MAX_TOTAL_BYTES:
                    raise ValueError("archive expands beyond 512 MiB")
            chunks.append(chunk)
    return b"".join(chunks)


def checked_infos(archive: zipfile.ZipFile) -> list[zipfile.ZipInfo]:
    infos = [info for info in archive.infolist() if not info.is_dir()]
    if len(infos) > MAX_FILES:
        raise ValueError(f"archive contains more than {MAX_FILES} files")
    names: set[str] = set()
    total = 0
    for info in infos:
        validate_member_name(info.filename)
        if info.filename in names:
            raise ValueError(f"duplicate archive member: {info.filename}")
        names.add(info.filename)
        if zip_is_symlink(info):
            raise ValueError(f"symbolic-link archive member is not allowed: {info.filename}")
        if info.file_size > MAX_ENTRY_BYTES:
            raise ValueError(f"archive member exceeds 128 MiB: {info.filename}")
        total += info.file_size
        if total > MAX_TOTAL_BYTES:
            raise ValueError("archive expands beyond 512 MiB")
    return infos


def scrub_string(value: str, report: Counter[str], share: bool, workspaces: list[str]) -> str:
    result = value
    for name, pattern, replacement in SECRET_PATTERNS:
        result, count = pattern.subn(replacement, result)
        report[name] += count
    if share:
        for workspace in sorted((item for item in workspaces if item), key=len, reverse=True):
            if workspace in result:
                count = result.count(workspace)
                result = result.replace(workspace, "<WORKSPACE>")
                report["workspace_path"] += count
        for pattern in HOME_PATTERNS:
            result, count = pattern.subn("<USER_HOME>", result)
            report["user_home"] += count
        result, count = EMAIL_PATTERN.subn("<EMAIL>", result)
        report["email"] += count
        result, count = URL_PATTERN.subn("<URL>", result)
        report["url"] += count
    return result


class Redactor:
    def __init__(self, privacy: str, session_ids: list[str], attachment_ids: list[str], workspaces: list[str]) -> None:
        self.share = privacy == "share"
        self.report: Counter[str] = Counter()
        self.workspaces = workspaces
        self.session_map = {value: f"session-{index:03d}" for index, value in enumerate(session_ids, 1)}
        self.external_map: dict[str, str] = {}
        self.attachment_map = {value: f"attachment-{index:03d}" for index, value in enumerate(attachment_ids, 1)}
        self.external_attachment_map: dict[str, str] = {}

    def redact_free_text(self, value: str) -> str:
        """Replace known identifiers before applying pattern-based scrubbing."""
        result = value
        for original, alias in sorted(self.session_map.items(), key=lambda item: len(item[0]), reverse=True):
            if original in result:
                result = result.replace(original, alias)
                self.report["session_id"] += 1
        for original, alias in sorted(self.external_map.items(), key=lambda item: len(item[0]), reverse=True):
            if original in result:
                result = result.replace(original, alias)
                self.report["session_id"] += 1
        for original, alias in sorted(self.attachment_map.items(), key=lambda item: len(item[0]), reverse=True):
            if original in result:
                result = result.replace(original, alias)
                self.report["attachment_id"] += 1
        for original, alias in sorted(
            self.external_attachment_map.items(), key=lambda item: len(item[0]), reverse=True
        ):
            if original in result:
                result = result.replace(original, alias)
                self.report["attachment_id"] += 1
        return scrub_string(result, self.report, self.share, self.workspaces)

    def session_alias(self, value: str) -> str:
        if not self.share:
            return value
        if value in self.session_map:
            alias = self.session_map[value]
        else:
            alias = self.external_map.setdefault(value, f"external-session-{len(self.external_map) + 1:03d}")
        if alias != value:
            self.report["session_id"] += 1
        return alias

    def attachment_alias(self, value: str) -> str:
        if not self.share:
            return value
        if value in self.attachment_map:
            alias = self.attachment_map[value]
        else:
            alias = self.external_attachment_map.setdefault(
                value,
                f"external-attachment-{len(self.external_attachment_map) + 1:03d}",
            )
        if alias != value:
            self.report["attachment_id"] += 1
        return alias

    def redact(self, value: Any, key: str | None = None) -> Any:
        if key is not None and SECRET_KEYS.fullmatch(key):
            self.report["secret_field"] += 1
            return "<REDACTED>"
        if isinstance(value, str):
            if key in SESSION_KEYS:
                return self.session_alias(value)
            if key in ATTACHMENT_KEYS:
                return self.attachment_alias(value)
            if self.share and key == "cwd":
                self.report["workspace_path"] += 1
                return "<WORKSPACE>"
            return self.redact_free_text(value)
        if isinstance(value, list):
            return [self.redact(item) for item in value]
        if isinstance(value, dict):
            return {str(item_key): self.redact(item_value, str(item_key)) for item_key, item_value in value.items()}
        return value


def parse_jsonl(name: str, content: str) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for line_number, line in enumerate(content.splitlines(), 1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
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
    return records


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


def read_source(source: Path, include_media: bool) -> tuple[list[tuple[str, list[dict[str, Any]]]], dict[str, bytes]]:
    logs: list[tuple[str, list[dict[str, Any]]]] = []
    media: dict[str, bytes] = {}
    if source.stat().st_size > MAX_ARCHIVE_BYTES:
        raise ValueError(f"input archive exceeds {MAX_ARCHIVE_BYTES // (1024 * 1024)} MiB")
    if zipfile.is_zipfile(source):
        with zipfile.ZipFile(source) as archive:
            budget = [0]
            for info in checked_infos(archive):
                if info.filename.endswith("session.jsonl"):
                    logs.append(
                        (info.filename, parse_jsonl(info.filename, read_member(archive, info, budget).decode("utf-8")))
                    )
                elif include_media and (info.filename.startswith("media/") or "/media/" in info.filename):
                    media_name = "media/" + PurePosixPath(info.filename).name
                    if media_name in media:
                        raise ValueError(f"media filename collision: {media_name}")
                    media[media_name] = read_member(archive, info, budget)
    else:
        if source.stat().st_size > MAX_ENTRY_BYTES:
            raise ValueError("session JSONL exceeds 128 MiB")
        logs.append((source.name, parse_jsonl(source.name, source.read_text(encoding="utf-8"))))
    if not logs:
        raise ValueError("input contains no session.jsonl")
    return logs, media


def capsule_session_path(source_name: str, redactor: Redactor) -> str:
    path = PurePosixPath(source_name)
    if len(path.parts) == 1 or path.parts == ("sessions", "root", "session.jsonl"):
        return "sessions/root/session.jsonl"
    parts = list(path.parts)
    if parts[-1] != "session.jsonl":
        raise ValueError(f"session member must end with session.jsonl: {source_name}")
    if parts[:1] == ["subagents"]:
        parts.insert(0, "sessions")
    elif parts[:1] != ["sessions"]:
        safe_parent = re.sub(r"[^A-Za-z0-9._-]+", "-", path.parent.as_posix()).strip("-") or "additional"
        if redactor.share:
            safe_parent = (
                re.sub(
                    r"[^A-Za-z0-9._-]+",
                    "-",
                    redactor.redact_free_text(safe_parent),
                ).strip("-")
                or "additional"
            )
        return f"sessions/{safe_parent}/session.jsonl"
    if redactor.share:
        if len(parts) >= 4 and parts[1] == "subagents":
            parts[2] = redactor.session_alias(parts[2])
        elif len(parts) == 3 and parts[1] != "root":
            parts[1] = redactor.session_alias(parts[1])
    return PurePosixPath(*parts).as_posix()


def json_bytes(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")


def jsonl_bytes(records: list[dict[str, Any]]) -> bytes:
    return (
        "\n".join(json.dumps(record, ensure_ascii=False, separators=(",", ":")) for record in records) + "\n"
    ).encode("utf-8")


def add_entry(entries: dict[str, tuple[str, bytes]], name: str, role: str, data: bytes) -> None:
    validate_member_name(name)
    if len(data) > MAX_ENTRY_BYTES:
        raise ValueError(f"entry exceeds 128 MiB: {name}")
    if name in entries:
        raise ValueError(f"capsule path collision: {name}")
    entries[name] = (role, data)


def zip_write(archive: zipfile.ZipFile, name: str, data: bytes) -> None:
    info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = 0o100644 << 16
    archive.writestr(info, data)


def pack(args: argparse.Namespace) -> int:
    source = Path(args.input).resolve()
    output = Path(args.output).resolve()
    if not source.is_file():
        raise ValueError(f"input file does not exist: {source}")
    if output.exists():
        raise ValueError(f"refusing to overwrite existing output: {output}")
    if output.suffix != ".dshc":
        raise ValueError("output filename must end with .dshc")
    if args.include_media and not args.acknowledge_media_risk:
        raise ValueError("--include-media requires --acknowledge-media-risk")
    if args.artifact and not args.acknowledge_artifact_risk:
        raise ValueError("--artifact requires --acknowledge-artifact-risk")

    if source.suffix == ".dshc":
        load_and_verify(source)
    logs, media = read_source(source, args.include_media)
    session_ids: list[str] = []
    attachment_ids: list[str] = []
    workspaces: list[str] = []
    for _name, records in logs:
        header = records[0]
        if isinstance(header.get("id"), str) and header["id"] not in session_ids:
            session_ids.append(header["id"])
        if isinstance(header.get("cwd"), str) and header["cwd"] not in workspaces:
            workspaces.append(header["cwd"])
        for key in SESSION_KEYS:
            for session_id in collect_keyed_strings(records, key):
                if session_id not in session_ids:
                    session_ids.append(session_id)
        for attachment_id in collect_keyed_strings(records, "attachmentId"):
            if attachment_id not in attachment_ids:
                attachment_ids.append(attachment_id)
        path_parts = PurePosixPath(_name).parts
        if len(path_parts) >= 3 and path_parts[-1] == "session.jsonl":
            for index, part in enumerate(path_parts[:-1]):
                if part in {"subagents", "sessions"} and index + 1 < len(path_parts) - 1:
                    candidate = path_parts[index + 1]
                    if candidate not in session_ids:
                        session_ids.append(candidate)
    redactor = Redactor(args.privacy, session_ids, attachment_ids, workspaces)
    entries: dict[str, tuple[str, bytes]] = {}

    for source_name, records in logs:
        redacted = [redactor.redact(record) for record in records]
        if redactor.share and isinstance(records[0].get("id"), str):
            redacted[0]["id"] = redactor.session_alias(records[0]["id"])
        add_entry(entries, capsule_session_path(source_name, redactor), "session-log", jsonl_bytes(redacted))

    if args.workspace_patch:
        patch_path = Path(args.workspace_patch).resolve()
        if not patch_path.is_file():
            raise ValueError(f"workspace patch does not exist: {patch_path}")
        if patch_path.stat().st_size > MAX_PATCH_BYTES:
            raise ValueError("workspace patch exceeds 32 MiB")
        patch_text = patch_path.read_text(encoding="utf-8")
        redacted_patch = redactor.redact_free_text(patch_text)
        add_entry(entries, "workspace/change.patch", "workspace-patch", redacted_patch.encode("utf-8"))

    for name, data in sorted(media.items()):
        media_path = PurePosixPath(name)
        if redactor.share:
            suffix = media_path.suffix
            attachment_id = media_path.name[: -len(suffix)] if suffix else media_path.name
            name = f"media/{redactor.attachment_alias(attachment_id)}{suffix}"
        add_entry(entries, name, "media", data)

    for artifact_name in args.artifact or []:
        artifact = Path(artifact_name).resolve()
        if not artifact.is_file():
            raise ValueError(f"artifact does not exist: {artifact}")
        if artifact.stat().st_size > MAX_ENTRY_BYTES:
            raise ValueError(f"artifact exceeds 128 MiB: {artifact}")
        raw = artifact.read_bytes()
        try:
            artifact_text = raw.decode("utf-8")
        except UnicodeDecodeError:
            data = raw
            role = "artifact-binary"
        else:
            data = redactor.redact_free_text(artifact_text).encode("utf-8")
            role = "artifact-text"
        artifact_name = artifact.name
        if redactor.share:
            artifact_name = re.sub(r"[^A-Za-z0-9._-]+", "-", redactor.redact_free_text(artifact_name)).strip("-")
        artifact_name = artifact_name or "artifact"
        add_entry(entries, f"artifacts/{artifact_name}", role, data)

    redaction_report = {
        "schema": "dsh-capsule-redaction/v1",
        "privacy": args.privacy,
        "automatic_replacements": dict(sorted(redactor.report.items())),
        "warning": "Pattern redaction is incomplete; manually review all content before sharing.",
    }
    add_entry(entries, "redaction-report.json", "redaction-report", json_bytes(redaction_report))
    total = sum(len(data) for _role, data in entries.values())
    if len(entries) > MAX_FILES or total > MAX_TOTAL_BYTES:
        raise ValueError("capsule exceeds file-count or 512 MiB expanded-size limit")

    file_records = [
        {"path": name, "role": role, "bytes": len(data), "sha256": digest_bytes(data)}
        for name, (role, data) in sorted(entries.items())
    ]
    manifest = {
        "format": FORMAT,
        "version": VERSION,
        "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "privacy": args.privacy,
        "source": {
            "name": redactor.redact_free_text(source.name) if redactor.share else source.name,
            "sha256": digest_file(source),
        },
        "capabilities": {
            "integrity_verification": True,
            "offline_inspection": True,
            "dsh_import": False,
            "exact_model_replay": False,
        },
        "includes": {
            "session_logs": len(logs),
            "workspace_patch": bool(args.workspace_patch),
            "media_files": len(media),
            "artifact_files": len(args.artifact or []),
        },
        "files": file_records,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, "x") as archive:
        zip_write(archive, "manifest.json", json_bytes(manifest))
        for name, (_role, data) in sorted(entries.items()):
            zip_write(archive, name, data)
    print(
        json.dumps(
            {"output": str(output), "sha256": digest_file(output), "files": len(entries) + 1}, ensure_ascii=False
        )
    )
    return 0


def load_and_verify(capsule: Path) -> tuple[dict[str, Any], dict[str, bytes]]:
    if not capsule.is_file():
        raise ValueError(f"not a readable ZIP capsule: {capsule}")
    if capsule.stat().st_size > MAX_ARCHIVE_BYTES:
        raise ValueError(f"capsule exceeds {MAX_ARCHIVE_BYTES // (1024 * 1024)} MiB")
    if not zipfile.is_zipfile(capsule):
        raise ValueError(f"not a readable ZIP capsule: {capsule}")
    with zipfile.ZipFile(capsule) as archive:
        infos = checked_infos(archive)
        names = {info.filename for info in infos}
        if "manifest.json" not in names:
            raise ValueError("capsule has no manifest.json")
        budget = [0]
        manifest_data = read_member(archive, "manifest.json", budget)
        try:
            manifest = json.loads(manifest_data)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ValueError("manifest.json is not valid UTF-8 JSON") from error
        if not isinstance(manifest, dict) or manifest.get("format") != FORMAT or manifest.get("version") != VERSION:
            raise ValueError("unsupported capsule format or version")
        listed = manifest.get("files")
        if not isinstance(listed, list):
            raise ValueError("manifest files must be an array")
        if len(listed) > MAX_FILES:
            raise ValueError(f"manifest contains more than {MAX_FILES} files")
        expected_names: set[str] = set()
        contents: dict[str, bytes] = {}
        for record in listed:
            if not isinstance(record, dict):
                raise ValueError("manifest file record is not an object")
            name = record.get("path")
            if not isinstance(name, str):
                raise ValueError("manifest file path is missing")
            validate_member_name(name)
            if name == "manifest.json" or name in expected_names:
                raise ValueError(f"invalid or duplicate manifest file path: {name}")
            expected_names.add(name)
            if name not in names:
                raise ValueError(f"manifest file is missing from ZIP: {name}")
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
                raise ValueError(f"size or SHA-256 hash mismatch: {name}")
            contents[name] = data
        if names != expected_names | {"manifest.json"}:
            extra = sorted(names - expected_names - {"manifest.json"})
            missing = sorted(expected_names - names)
            raise ValueError(f"ZIP/manifest file-set mismatch; extra={extra}, missing={missing}")
        contents["manifest.json"] = manifest_data
        return manifest, contents


def inspect_capsule(args: argparse.Namespace) -> int:
    capsule = Path(args.capsule).resolve()
    manifest, _contents = load_and_verify(capsule)
    output = {"capsule": str(capsule), "sha256": digest_file(capsule), "manifest": manifest}
    print(json.dumps(output, ensure_ascii=False, indent=2))
    return 0


def verify(args: argparse.Namespace) -> int:
    capsule = Path(args.capsule).resolve()
    manifest, _contents = load_and_verify(capsule)
    print(
        json.dumps(
            {
                "ok": True,
                "capsule": str(capsule),
                "sha256": digest_file(capsule),
                "privacy": manifest.get("privacy"),
                "files": len(manifest.get("files", [])),
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


def extract(args: argparse.Namespace) -> int:
    capsule = Path(args.capsule).resolve()
    output = Path(args.output_dir).resolve()
    if output.exists():
        raise ValueError(f"refusing to extract into existing path: {output}")
    _manifest, contents = load_and_verify(capsule)
    output.mkdir(parents=True, exist_ok=False)
    for name, data in sorted(contents.items()):
        target = output.joinpath(*PurePosixPath(name).parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    print(json.dumps({"output_dir": str(output), "files": len(contents)}, ensure_ascii=False))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    pack_parser = subparsers.add_parser("pack")
    pack_parser.add_argument("input")
    pack_parser.add_argument("--output", required=True)
    pack_parser.add_argument("--privacy", choices=("share", "private"), default="share")
    pack_parser.add_argument("--workspace-patch")
    pack_parser.add_argument("--include-media", action="store_true")
    pack_parser.add_argument("--acknowledge-media-risk", action="store_true")
    pack_parser.add_argument("--artifact", action="append", default=[])
    pack_parser.add_argument("--acknowledge-artifact-risk", action="store_true")
    pack_parser.set_defaults(func=pack)
    inspect_parser = subparsers.add_parser("inspect")
    inspect_parser.add_argument("capsule")
    inspect_parser.set_defaults(func=inspect_capsule)
    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("capsule")
    verify_parser.set_defaults(func=verify)
    extract_parser = subparsers.add_parser("extract")
    extract_parser.add_argument("capsule")
    extract_parser.add_argument("--output-dir", required=True)
    extract_parser.set_defaults(func=extract)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        return int(args.func(args))
    except (OSError, UnicodeError, ValueError, RuntimeError, zipfile.BadZipFile) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
