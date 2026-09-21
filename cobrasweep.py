#!/usr/bin/env python3
"""CobraSweep - secure deletion and privacy sweep tool for PCs.

Two jobs:
  shred  — overwrite files with random data before deleting so recovery
           tools can't bring them back.
  sweep  — clean the privacy-cluttering corners of a PC (temp folders,
           caches, thumbnails, trash, recent-file lists).

Safety model: `sweep` is a dry run until --execute is passed, targets are
limited to well-known user-owned locations, and dangerous paths (/, the
home directory itself, system roots) are refused outright.

Pure standard library; Python 3.10+. Linux/ChromeOS and Windows aware.
"""

from __future__ import annotations

import argparse
import os
import secrets
import shutil
import stat
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

APP_NAME = "CobraSweep"
DEFAULT_PASSES = 3
CHUNK_SIZE = 1024 * 1024  # 1 MiB


class SweepError(Exception):
    """Base error for unsafe or failed operations."""


@dataclass
class SweepTarget:
    name: str
    description: str
    paths: list[Path]  # contents of these paths are cleared (not the path itself)


@dataclass
class SweepStats:
    files_removed: int = 0
    bytes_freed: int = 0
    errors: list[str] = field(default_factory=list)

    def merge(self, other: "SweepStats") -> None:
        self.files_removed += other.files_removed
        self.bytes_freed += other.bytes_freed
        self.errors.extend(other.errors)


def _forbidden_roots() -> set[Path]:
    roots = {Path("/").resolve(), Path.home().resolve()}
    if os.name == "nt":
        for drive_code in range(ord("A"), ord("Z") + 1):
            candidate = Path(f"{chr(drive_code)}:/")
            if candidate.exists():
                roots.add(candidate.resolve())
        roots.add(Path(os.environ.get("SystemRoot", r"C:\Windows")).resolve())
    else:
        roots.update({Path(p) for p in ("/etc", "/usr", "/bin", "/sbin", "/var", "/boot")})
    return roots


def guard_path(path: Path) -> Path:
    """Resolve and refuse dangerous targets. Returns the safe resolved path."""
    resolved = Path(path).resolve()
    forbidden = _forbidden_roots()
    if resolved in forbidden:
        raise SweepError(f"Refusing to touch protected path: {resolved}")
    if os.name != "nt" and Path.home().resolve() not in resolved.parents:
        # On POSIX, anything outside the user's own home needs explicit thought.
        tmp_root = Path(tempfile.gettempdir()).resolve()
        if tmp_root not in resolved.parents and resolved != tmp_root:
            raise SweepError(
                f"Refusing path outside home/temp: {resolved} (use your OS tools for system paths)"
            )
    return resolved


def shred_file(path: Path, passes: int = DEFAULT_PASSES) -> int:
    """Overwrite a file with random data `passes` times, then a zero pass,
    rename it to a random name, and unlink. Returns bytes destroyed."""
    resolved = guard_path(path)
    if resolved.is_dir():
        raise SweepError(f"{resolved} is a directory — pass files, or use sweep targets")
    if not resolved.exists():
        raise SweepError(f"Not found: {resolved}")
    if resolved.is_symlink():
        resolved.unlink()  # never follow symlinks into someone else's data
        return 0

    try:
        os.chmod(resolved, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass
    size = resolved.stat().st_size

    if size > 0:
        with resolved.open("r+b", buffering=0) as handle:
            for pass_index in range(passes + 1):  # +1: final all-zero pass
                handle.seek(0)
                remaining = size
                while remaining > 0:
                    chunk = min(CHUNK_SIZE, remaining)
                    block = b"\x00" * chunk if pass_index == passes else os.urandom(chunk)
                    handle.write(block)
                    remaining -= chunk
                handle.flush()
                os.fsync(handle.fileno())

    anonymous = resolved.with_name(f".sweep-{secrets.token_hex(8)}")
    resolved.rename(anonymous)
    anonymous.unlink()
    return size


def sweep_targets() -> list[SweepTarget]:
    """Well-known privacy-cluttering locations for this platform."""
    targets: list[SweepTarget] = []
    home = Path.home()

    targets.append(SweepTarget(
        name="system-temp",
        description="Temporary files from all apps",
        paths=[Path(tempfile.gettempdir())],
    ))
    if os.name == "nt":
        local = Path(os.environ.get("LOCALAPPDATA", home / "AppData" / "Local"))
        roaming = Path(os.environ.get("APPDATA", home / "AppData" / "Roaming"))
        targets.extend([
            SweepTarget("thumbnails", "Explorer thumbnail cache databases",
                        [local / "Microsoft" / "Windows" / "Explorer"]),
            SweepTarget("recent-files", "Recent Documents shortcuts",
                        [roaming / "Microsoft" / "Windows" / "Recent"]),
            SweepTarget("browser-cache", "Chrome/Edge/Brave disk caches", [
                local / "Google" / "Chrome" / "User Data" / "Default" / "Cache",
                local / "Microsoft" / "Edge" / "User Data" / "Default" / "Cache",
                local / "BraveSoftware" / "Brave-Browser" / "User Data" / "Default" / "Cache",
            ]),
            SweepTarget("crash-dumps", "Windows error-report dumps",
                        [local / "CrashDumps"]),
        ])
    else:
        targets.extend([
            SweepTarget("user-cache", "Application cache directory (~/.cache)",
                        [home / ".cache"]),
            SweepTarget("thumbnails", "Freedesktop thumbnail cache",
                        [home / ".cache" / "thumbnails", home / ".thumbnails"]),
            SweepTarget("trash", "Trash bin (files + metadata)", [
                home / ".local" / "share" / "Trash" / "files",
                home / ".local" / "share" / "Trash" / "info",
            ]),
            SweepTarget("recent-files", "Recently-used file list",
                        [home / ".local" / "share" / "recently-used.xbel"]),
            SweepTarget("browser-cache", "Chrome/Chromium/Firefox disk caches", [
                home / ".cache" / "google-chrome",
                home / ".cache" / "chromium",
                home / ".cache" / "mozilla",
                home / ".mozilla" / "firefox" / "cache2",
            ]),
        ])
    return targets


def _remove_entry(path: Path, stats: SweepStats, shred: bool, execute: bool) -> None:
    """Remove one file/dir inside a target. In dry-run mode only counts."""
    try:
        if path.is_symlink() or path.is_file():
            size = path.stat().st_size if not path.is_symlink() else 0
            stats.files_removed += 1
            stats.bytes_freed += size
            if execute:
                if shred and path.is_file() and not path.is_symlink():
                    shred_file(path)
                else:
                    path.unlink()
        elif path.is_dir():
            for child in path.iterdir():
                _remove_entry(child, stats, shred, execute)
            if execute:
                path.rmdir()
    except FileNotFoundError:
        pass
    except (PermissionError, OSError, SweepError) as exc:
        stats.errors.append(f"{path}: {exc}")


def sweep_target(target: SweepTarget, shred: bool, execute: bool) -> SweepStats:
    stats = SweepStats()
    for base in target.paths:
        if base.is_file():
            _remove_entry(base, stats, shred, execute)
        elif base.is_dir():
            for entry in base.iterdir():
                _remove_entry(entry, stats, shred, execute)
    return stats


def _format_bytes(count: int) -> str:
    value = float(count)
    for unit in ("B", "KiB", "MiB", "GiB"):
        if value < 1024 or unit == "GiB":
            return f"{value:.1f} {unit}" if unit != "B" else f"{int(value)} B"
        value /= 1024
    return f"{count} B"


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_shred(args: argparse.Namespace) -> int:
    paths = [Path(p) for p in args.files]
    if not args.yes:
        print(f"About to securely shred {len(paths)} file(s) with {args.passes} random "
              "passes + zero pass. This is IRREVERSIBLE.")
        answer = input("Type 'shred' to confirm: ").strip().lower()
        if answer != "shred":
            print("Aborted.")
            return 2

    stats = SweepStats()
    for path in paths:
        try:
            destroyed = shred_file(path, passes=args.passes)
            stats.files_removed += 1
            stats.bytes_freed += destroyed
            print(f"[SHREDDED] {path} ({_format_bytes(destroyed)})")
        except SweepError as exc:
            stats.errors.append(str(exc))
            print(f"[SKIP] {exc}", file=sys.stderr)

    print(f"\nShredded {stats.files_removed} file(s), "
          f"{_format_bytes(stats.bytes_freed)} destroyed, {len(stats.errors)} error(s).")
    return 0 if not stats.errors else 1


def cmd_sweep(args: argparse.Namespace) -> int:
    targets = sweep_targets()
    if args.targets:
        wanted = {name.strip() for name in args.targets.split(",") if name.strip()}
        unknown = wanted - {target.name for target in targets}
        if unknown:
            print(f"Unknown target(s): {', '.join(sorted(unknown))}", file=sys.stderr)
            print(f"Available: {', '.join(t.name for t in targets)}", file=sys.stderr)
            return 2
        targets = [target for target in targets if target.name in wanted]

    if not args.execute:
        print(f"=== DRY RUN === (re-run with --execute to actually clean; "
              f"add --shred for secure overwrite)\n")

    overall = SweepStats()
    for target in targets:
        existing = [p for p in target.paths if p.exists()]
        if not existing:
            print(f"-- {target.name}: nothing to clean")
            continue
        stats = sweep_target(target, shred=args.shred, execute=args.execute)
        overall.merge(stats)
        verb = "cleaned" if args.execute else "would clean"
        print(f"-- {target.name} ({target.description}): {verb} "
              f"{stats.files_removed} item(s), {_format_bytes(stats.bytes_freed)}")
        for error in stats.errors[:5]:
            print(f"     error: {error}")
        if len(stats.errors) > 5:
            print(f"     ... and {len(stats.errors) - 5} more error(s)")

    print(f"\nTotal: {overall.files_removed} item(s), "
          f"{_format_bytes(overall.bytes_freed)}, {len(overall.errors)} error(s).")
    return 0 if not overall.errors else 1


def cmd_list(args: argparse.Namespace) -> int:
    for target in sweep_targets():
        status = "exists" if any(p.exists() for p in target.paths) else "absent"
        print(f"  {target.name:<14} [{status}] {target.description}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=APP_NAME.lower(),
        description="Secure file shredding and privacy sweep. Sweep is a dry run "
                    "until --execute is passed.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    shred_parser = subparsers.add_parser("shred", help="Securely overwrite and delete files.")
    shred_parser.add_argument("files", nargs="+", help="File(s) to shred.")
    shred_parser.add_argument("--passes", type=int, default=DEFAULT_PASSES,
                              help=f"Random overwrite passes (default {DEFAULT_PASSES}).")
    shred_parser.add_argument("--yes", action="store_true", help="Skip the confirmation prompt.")
    shred_parser.set_defaults(handler=cmd_shred)

    sweep_parser = subparsers.add_parser("sweep", help="Clean temp/cache/trash locations.")
    sweep_parser.add_argument("--targets", help="Comma-separated target names (default: all).")
    sweep_parser.add_argument("--execute", action="store_true",
                              help="Actually delete (otherwise a dry run).")
    sweep_parser.add_argument("--shred", action="store_true",
                              help="Securely overwrite files instead of plain delete.")
    sweep_parser.set_defaults(handler=cmd_sweep)

    list_parser = subparsers.add_parser("list", help="List sweep targets for this platform.")
    list_parser.set_defaults(handler=cmd_list)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.handler(args))


if __name__ == "__main__":
    sys.exit(main())
