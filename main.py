#!/usr/bin/env python3

from __future__ import annotations

import argparse
import csv
import datetime as dt
import fnmatch
import hashlib
import io
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable

APP = "rpm-drift"
VERSION = "2.0.0"
SCHEMA = 2
SUPPORTED_SCHEMAS = {1, 2}
FIELDS = ("name", "epoch", "version", "release", "arch", "install_time")
QUERY_FORMAT = r"%{NAME}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\t%{INSTALLTIME}\n"
VERIFY_CODES = {"S": "size", "M": "mode", "5": "digest", "D": "device", "L": "symlink", "U": "user", "G": "group", "T": "mtime", "P": "capabilities"}
MAX_SNAPSHOT_BYTES = 100 * 1024 * 1024


class DriftError(Exception):
    pass


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def run_command(command: list[str], timeout: int = 120) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(command, text=True, capture_output=True, timeout=timeout, check=False, errors="replace")
    except FileNotFoundError as exc:
        raise DriftError(f"required executable not found: {command[0]}") from exc
    except subprocess.TimeoutExpired as exc:
        raise DriftError(f"command timed out after {timeout} seconds: {command[0]}") from exc
    except OSError as exc:
        raise DriftError(f"unable to execute {command[0]}: {exc}") from exc


def require_rpm() -> None:
    if shutil.which("rpm") is None:
        raise DriftError("rpm executable is unavailable")


def normalize_epoch(value: Any) -> str:
    result = str(value).strip()
    if result in ("", "(none)", "None"):
        return "0"
    if not result.isdigit():
        raise DriftError(f"invalid RPM epoch: {result!r}")
    return str(int(result))


def validate_package(value: Any) -> dict[str, str]:
    if not isinstance(value, dict):
        raise DriftError("snapshot contains a non-object package")
    for field in FIELDS:
        if field not in value:
            raise DriftError(f"snapshot package missing {field}")
    result = {key: str(value[key]) for key in FIELDS}
    result["epoch"] = normalize_epoch(result["epoch"])
    if any(not result[key] for key in ("name", "version", "release", "arch")):
        raise DriftError("snapshot package contains an empty required field")
    if any(any(ord(char) < 32 or ord(char) == 127 for char in field) for field in result.values()):
        raise DriftError("snapshot package contains control characters")
    if not result["install_time"].isdigit():
        raise DriftError("snapshot package has an invalid install timestamp")
    return result


def package_key(package: dict[str, str]) -> str:
    return f"{package['name']}.{package['arch']}"


def package_identity(package: dict[str, str]) -> tuple[str, str, str, str, str]:
    return (package["name"], package["arch"], package["epoch"], package["version"], package["release"])


def nevra(package: dict[str, str]) -> str:
    epoch = package["epoch"]
    prefix = f"{epoch}:" if epoch != "0" else ""
    return f"{package['name']}-{prefix}{package['version']}-{package['release']}.{package['arch']}"


def sorted_packages(packages: Iterable[dict[str, str]]) -> list[dict[str, str]]:
    return sorted(packages, key=lambda item: (package_key(item), item["epoch"], item["version"], item["release"], item["install_time"]))


def parse_inventory(output: str) -> list[dict[str, str]]:
    packages = []
    for number, line in enumerate(output.splitlines(), 1):
        if not line.strip():
            continue
        parts = line.split("\t")
        if len(parts) != len(FIELDS):
            raise DriftError(f"malformed rpm query result on line {number}")
        packages.append(validate_package(dict(zip(FIELDS, parts))))
    return sorted_packages(packages)


def inventory(timeout: int) -> list[dict[str, str]]:
    require_rpm()
    result = run_command(["rpm", "-qa", "--qf", QUERY_FORMAT], timeout)
    if result.returncode != 0:
        raise DriftError(f"rpm query failed: {result.stderr.strip() or result.returncode}")
    return parse_inventory(result.stdout)


def os_release() -> dict[str, str]:
    result: dict[str, str] = {}
    try:
        for line in Path("/etc/os-release").read_text(encoding="utf-8").splitlines():
            if "=" not in line or line.startswith("#"):
                continue
            key, value = line.split("=", 1)
            value = value.strip()
            if value.startswith('"') and value.endswith('"'):
                value = value[1:-1].replace('\\"', '"')
            result[key] = value
    except (OSError, UnicodeError):
        pass
    return {key: result.get(key, "") for key in ("ID", "VERSION_ID", "PRETTY_NAME")}


def inventory_digest(packages: list[dict[str, str]]) -> str:
    identities = ["\t".join(package_identity(item)) for item in sorted_packages(packages)]
    return hashlib.sha256(("\n".join(identities) + "\n").encode("utf-8")).hexdigest()


def snapshot_document(packages: list[dict[str, str]]) -> dict[str, Any]:
    packages = sorted_packages(packages)
    return {
        "schema": SCHEMA,
        "generator": APP,
        "generator_version": VERSION,
        "created_at": utc_now(),
        "hostname": platform.node(),
        "machine": platform.machine(),
        "system": os_release(),
        "package_count": len(packages),
        "inventory_sha256": inventory_digest(packages),
        "packages": packages,
    }


def atomic_write(path: Path, content: str, overwrite: bool = False) -> None:
    path = path.expanduser()
    if path.is_symlink():
        raise DriftError(f"refusing to replace symbolic link: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and not overwrite:
        raise DriftError(f"output exists; use --force to replace: {path}")
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent, prefix=".rpm-drift-", delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        if path.is_symlink() or (path.exists() and not overwrite):
            raise DriftError(f"output changed during write: {path}")
        os.replace(temporary, path)
        temporary = None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def json_text(document: Any) -> str:
    return json.dumps(document, indent=2, ensure_ascii=False, sort_keys=True, allow_nan=False) + "\n"


def load_snapshot(path: Path) -> dict[str, Any]:
    path = path.expanduser()
    try:
        if path.stat().st_size > MAX_SNAPSHOT_BYTES:
            raise DriftError(f"snapshot exceeds size limit: {path}")
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise DriftError(f"cannot read snapshot {path}: {exc}") from exc
    if not isinstance(document, dict) or document.get("schema") not in SUPPORTED_SCHEMAS:
        raise DriftError(f"unsupported snapshot schema: {path}")
    if not isinstance(document.get("packages"), list):
        raise DriftError(f"snapshot has no package array: {path}")
    packages = sorted_packages(validate_package(item) for item in document["packages"])
    if document.get("package_count") != len(packages):
        raise DriftError(f"snapshot package count mismatch: {path}")
    if len(packages) != len({(package_identity(p), p["install_time"]) for p in packages}):
        raise DriftError(f"snapshot contains duplicate package records: {path}")
    if document["schema"] == 2 and document.get("inventory_sha256") != inventory_digest(packages):
        raise DriftError(f"snapshot inventory digest mismatch: {path}")
    document["packages"] = packages
    return document


def rpmvercmp(left: str, right: str) -> int:
    if left == right:
        return 0
    a = 0
    b = 0
    while True:
        while a < len(left) and not left[a].isalnum() and left[a] not in "~^":
            a += 1
        while b < len(right) and not right[b].isalnum() and right[b] not in "~^":
            b += 1
        if (a < len(left) and left[a] == "~") or (b < len(right) and right[b] == "~"):
            if a >= len(left) or left[a] != "~":
                return 1
            if b >= len(right) or right[b] != "~":
                return -1
            a += 1
            b += 1
            continue
        if (a < len(left) and left[a] == "^") or (b < len(right) and right[b] == "^"):
            if a >= len(left):
                return -1
            if b >= len(right):
                return 1
            if left[a] != "^":
                return 1
            if right[b] != "^":
                return -1
            a += 1
            b += 1
            continue
        if a == len(left) or b == len(right):
            return (a < len(left)) - (b < len(right))
        numeric = left[a].isdigit()
        start_a = a
        start_b = b
        while a < len(left) and (left[a].isdigit() if numeric else left[a].isalpha()):
            a += 1
        if numeric:
            while b < len(right) and right[b].isdigit():
                b += 1
        else:
            while b < len(right) and right[b].isalpha():
                b += 1
        if start_b == b:
            return 1 if numeric else -1
        x = left[start_a:a]
        y = right[start_b:b]
        if numeric:
            x = x.lstrip("0") or "0"
            y = y.lstrip("0") or "0"
            if len(x) != len(y):
                return (len(x) > len(y)) - (len(x) < len(y))
        if x != y:
            return (x > y) - (x < y)


def compare_evr(before: dict[str, str], after: dict[str, str]) -> int:
    left_epoch = int(before["epoch"])
    right_epoch = int(after["epoch"])
    if left_epoch != right_epoch:
        return (left_epoch > right_epoch) - (left_epoch < right_epoch)
    versions = rpmvercmp(before["version"], after["version"])
    if versions:
        return versions
    return rpmvercmp(before["release"], after["release"])


def version_change(before: dict[str, str], after: dict[str, str]) -> str:
    if package_identity(before) == package_identity(after):
        return "unchanged"
    result = compare_evr(before, after)
    if result < 0:
        if before["epoch"] == after["epoch"] and before["version"] == after["version"]:
            return "release_increased"
        return "upgraded"
    if result > 0:
        if before["epoch"] == after["epoch"] and before["version"] == after["version"]:
            return "release_decreased"
        return "downgraded"
    return "changed_equal_evr"


def selected(package: dict[str, str], include: list[str], exclude: list[str]) -> bool:
    candidates = (package["name"], package_key(package), nevra(package))
    if include and not any(fnmatch.fnmatchcase(candidate, pattern) for candidate in candidates for pattern in include):
        return False
    if any(fnmatch.fnmatchcase(candidate, pattern) for candidate in candidates for pattern in exclude):
        return False
    return True


def group_packages(packages: list[dict[str, str]], include: list[str], exclude: list[str]) -> dict[str, list[dict[str, str]]]:
    grouped: dict[str, list[dict[str, str]]] = defaultdict(list)
    for package in packages:
        if selected(package, include, exclude):
            grouped[package_key(package)].append(package)
    return {key: sorted_packages(value) for key, value in grouped.items()}


def change_record(key: str, kind: str, before: dict[str, str] | None, after: dict[str, str] | None) -> dict[str, Any]:
    return {
        "key": key,
        "change": kind,
        "before": nevra(before) if before else None,
        "after": nevra(after) if after else None,
        "before_install_time": before["install_time"] if before else None,
        "after_install_time": after["install_time"] if after else None,
    }


def compare_package_group(key: str, old: list[dict[str, str]], new: list[dict[str, str]]) -> list[dict[str, Any]]:
    remaining_old = list(old)
    remaining_new = list(new)
    matched_old: set[int] = set()
    matched_new: set[int] = set()
    for i, before in enumerate(remaining_old):
        for j, after in enumerate(remaining_new):
            if j not in matched_new and package_identity(before) == package_identity(after):
                matched_old.add(i)
                matched_new.add(j)
                break
    unmatched_old = [p for i, p in enumerate(remaining_old) if i not in matched_old]
    unmatched_new = [p for j, p in enumerate(remaining_new) if j not in matched_new]
    changes = []
    while unmatched_old and unmatched_new:
        before = unmatched_old.pop(0)
        after = unmatched_new.pop(0)
        changes.append(change_record(key, version_change(before, after), before, after))
    for before in unmatched_old:
        changes.append(change_record(key, "removed", before, None))
    for after in unmatched_new:
        changes.append(change_record(key, "added", None, after))
    return changes


def compare_snapshots(old: dict[str, Any], new: dict[str, Any], include: list[str], exclude: list[str]) -> dict[str, Any]:
    left = group_packages(old["packages"], include, exclude)
    right = group_packages(new["packages"], include, exclude)
    changes = []
    for key in sorted(left.keys() | right.keys()):
        changes.extend(compare_package_group(key, left.get(key, []), right.get(key, [])))
    changes.sort(key=lambda entry: (entry["key"], entry["change"], entry["before"] or "", entry["after"] or ""))
    counts = dict(sorted(Counter(change["change"] for change in changes).items()))
    warnings = []
    if old.get("hostname") != new.get("hostname"):
        warnings.append("snapshots originate from different hostnames")
    if old.get("machine") != new.get("machine"):
        warnings.append("snapshots originate from different architectures")
    if old.get("system", {}).get("ID") != new.get("system", {}).get("ID"):
        warnings.append("snapshots originate from different distributions")
    return {
        "app": APP,
        "version": VERSION,
        "generated_at": utc_now(),
        "baseline": {"created_at": old.get("created_at"), "hostname": old.get("hostname"), "packages": sum(map(len, left.values())), "digest": inventory_digest(old["packages"])},
        "current": {"created_at": new.get("created_at"), "hostname": new.get("hostname"), "packages": sum(map(len, right.values())), "digest": inventory_digest(new["packages"])},
        "summary": {"changes": len(changes), "categories": counts},
        "warnings": warnings,
        "filters": {"include": include, "exclude": exclude},
        "changes": changes,
    }


def parse_verify_line(line: str) -> dict[str, Any]:
    if len(line) < 13:
        return {"raw": line, "parsed": False}
    flags = line[:9]
    if any(char not in ".?" and char not in VERIFY_CODES for char in flags):
        return {"raw": line, "parsed": False}
    suffix = line[9:].lstrip()
    file_type = ""
    if len(suffix) > 2 and suffix[0] in "cgdrl" and suffix[1].isspace():
        file_type = suffix[0]
        suffix = suffix[2:].lstrip()
    return {
        "flags": flags,
        "file_type": file_type,
        "path": suffix,
        "differences": [description for code, description in VERIFY_CODES.items() if code in flags],
        "unreadable": "?" in flags,
        "missing": False,
        "parsed": True,
    }


def verify_installed(timeout: int, packages: list[str]) -> dict[str, Any]:
    require_rpm()
    if any(name.startswith("-") for name in packages):
        raise DriftError("package names cannot begin with a dash")
    command = ["rpm", "-V", "--"] + packages if packages else ["rpm", "-Va"]
    result = run_command(command, timeout)
    if result.returncode not in (0, 1):
        raise DriftError(f"rpm verification failed: {result.stderr.strip() or result.returncode}")
    records = []
    for line in result.stdout.splitlines():
        if line.startswith("missing "):
            records.append({"path": line[8:].strip(), "missing": True, "parsed": True, "differences": ["missing"]})
        else:
            records.append(parse_verify_line(line))
    return {
        "app": APP,
        "version": VERSION,
        "generated_at": utc_now(),
        "command": command,
        "verified_ok": result.returncode == 0 and not records,
        "changed_files": len(records),
        "difference_types": dict(sorted(Counter(kind for record in records for kind in record.get("differences", [])).items())),
        "files": records,
        "stderr": result.stderr.strip(),
    }


def render_comparison(report: dict[str, Any], limit: int) -> str:
    summary = report["summary"]
    lines = [
        f"{APP} {VERSION}",
        f"Baseline: {report['baseline']['hostname']}  {report['baseline']['created_at']}",
        f"Current:  {report['current']['hostname']}  {report['current']['created_at']}",
        f"Packages: {report['baseline']['packages']} -> {report['current']['packages']}",
        f"Changes:  {summary['changes']}",
    ]
    for category, count in summary["categories"].items():
        lines.append(f"  {category}: {count}")
    for warning in report["warnings"]:
        lines.append(f"Warning: {warning}")
    if summary["changes"]:
        lines.append("")
        for entry in report["changes"][:limit]:
            lines.append(f"{entry['change']:20} {entry['key']}")
            if entry["before"]:
                lines.append(f"  - {entry['before']}")
            if entry["after"]:
                lines.append(f"  + {entry['after']}")
        if len(report["changes"]) > limit:
            lines.append(f"... {len(report['changes']) - limit} additional changes")
    return "\n".join(lines)


def csv_report(report: dict[str, Any]) -> str:
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=("key", "change", "before", "after", "before_install_time", "after_install_time"))
    writer.writeheader()
    for entry in report["changes"]:
        writer.writerow({key: entry.get(key) for key in writer.fieldnames})
    return output.getvalue()


def inventory_summary(packages: list[dict[str, str]]) -> dict[str, Any]:
    names = {package["name"] for package in packages}
    return {
        "app": APP,
        "version": VERSION,
        "generated_at": utc_now(),
        "hostname": platform.node(),
        "system": os_release(),
        "installed_records": len(packages),
        "unique_names": len(names),
        "architectures": dict(sorted(Counter(item["arch"] for item in packages).items())),
        "inventory_sha256": inventory_digest(packages),
    }


def emit_report(report: dict[str, Any], args: argparse.Namespace, text: str) -> None:
    if getattr(args, "output", None):
        content = csv_report(report) if getattr(args, "format", "text") == "csv" else json_text(report)
        atomic_write(args.output, content, args.force)
        print(f"Report written: {args.output}", file=sys.stderr)
    if getattr(args, "format", "text") == "json":
        print(json_text(report), end="")
    elif getattr(args, "format", "text") == "csv":
        if "changes" not in report:
            raise DriftError("CSV is supported for comparison reports only")
        print(csv_report(report), end="")
    else:
        print(text)


def add_report_args(parser: argparse.ArgumentParser, csv_enabled: bool = False) -> None:
    formats = ("text", "json", "csv") if csv_enabled else ("text", "json")
    parser.add_argument("--format", choices=formats, default="text")
    parser.add_argument("--json", action="store_true", help="alias for --format json")
    parser.add_argument("--output", type=Path, help="save report as JSON or CSV")
    parser.add_argument("--force", action="store_true", help="replace existing output")


def add_compare_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--include", action="append", default=[], metavar="GLOB")
    parser.add_argument("--exclude", action="append", default=[], metavar="GLOB")
    parser.add_argument("--limit", type=int, default=100)
    parser.add_argument("--exit-on-drift", action="store_true")
    add_report_args(parser, csv_enabled=True)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog=APP, description="Read-only RPM inventory, drift analysis, and installed-file verification")
    parser.add_argument("--version", action="version", version=f"{APP} {VERSION}")
    sub = parser.add_subparsers(dest="command", required=True)

    capture = sub.add_parser("snapshot", help="capture an installed RPM inventory")
    capture.add_argument("path", type=Path)
    capture.add_argument("--timeout", type=int, default=120)
    capture.add_argument("--force", action="store_true")

    compare = sub.add_parser("compare", help="compare two saved snapshots")
    compare.add_argument("baseline", type=Path)
    compare.add_argument("current", type=Path)
    add_compare_args(compare)

    check = sub.add_parser("check", help="compare saved baseline with current installed packages")
    check.add_argument("baseline", type=Path)
    check.add_argument("--timeout", type=int, default=120)
    add_compare_args(check)

    verify = sub.add_parser("verify", help="verify installed files using rpm -V")
    verify.add_argument("packages", nargs="*")
    verify.add_argument("--timeout", type=int, default=300)
    verify.add_argument("--limit", type=int, default=100)
    add_report_args(verify)

    info = sub.add_parser("info", help="summarize installed RPM inventory")
    info.add_argument("--timeout", type=int, default=120)
    add_report_args(info)

    validate = sub.add_parser("validate", help="validate a snapshot and its inventory digest")
    validate.add_argument("path", type=Path)
    add_report_args(validate)

    return parser


def validate_args(args: argparse.Namespace) -> None:
    if hasattr(args, "timeout") and args.timeout <= 0:
        raise DriftError("timeout must be positive")
    if hasattr(args, "limit") and args.limit < 0:
        raise DriftError("limit must not be negative")
    if getattr(args, "json", False):
        if args.format not in ("text", "json"):
            raise DriftError("--json conflicts with --format csv")
        args.format = "json"


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    validate_args(args)

    if args.command == "snapshot":
        packages = inventory(args.timeout)
        document = snapshot_document(packages)
        atomic_write(args.path, json_text(document), args.force)
        print(f"Snapshot saved: {args.path} ({len(packages)} packages)")
        return 0

    if args.command == "validate":
        document = load_snapshot(args.path)
        report = {"valid": True, "schema": document["schema"], "packages": len(document["packages"]), "inventory_sha256": inventory_digest(document["packages"]), "path": str(args.path)}
        emit_report(report, args, f"Valid snapshot: {args.path} ({report['packages']} packages, schema {report['schema']})")
        return 0

    if args.command == "info":
        report = inventory_summary(inventory(args.timeout))
        lines = [f"Host: {report['hostname']}", f"OS: {report['system']['PRETTY_NAME']}", f"Installed RPM records: {report['installed_records']}", f"Unique package names: {report['unique_names']}"]
        lines.extend(f"  {arch}: {count}" for arch, count in report["architectures"].items())
        emit_report(report, args, "\n".join(lines))
        return 0

    if args.command in ("compare", "check"):
        baseline = load_snapshot(args.baseline)
        current = load_snapshot(args.current) if args.command == "compare" else snapshot_document(inventory(args.timeout))
        report = compare_snapshots(baseline, current, args.include, args.exclude)
        emit_report(report, args, render_comparison(report, args.limit))
        return 2 if args.exit_on_drift and report["summary"]["changes"] else 0

    if args.command == "verify":
        report = verify_installed(args.timeout, args.packages)
        lines = [f"RPM verification: {report['changed_files']} reported file differences"]
        for record in report["files"][:args.limit]:
            lines.append(f"{record.get('flags', ''):10} {record.get('file_type', ''):2} {record.get('path', record.get('raw', ''))}")
        if report["stderr"]:
            print(report["stderr"], file=sys.stderr)
        emit_report(report, args, "\n".join(lines))
        return 2 if report["changed_files"] else 0

    raise DriftError(f"unsupported command: {args.command}")


if __name__ == "__main__":
    try:
        sys.exit(main())
    except DriftError as exc:
        print(f"{APP}: {exc}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print(f"{APP}: interrupted", file=sys.stderr)
        sys.exit(130)
