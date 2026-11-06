#!/usr/bin/env python3
"""ThreatPulse File Integrity Monitoring. Run it only inside the lab VM.

    python agent/fim/main.py baseline
    python agent/fim/main.py watch [--out <file>] [--poll-only]

FIM only reads what it watches. It writes only to its own folder and its log. Restoring
a change is an enforcement action, which belongs to policy/ in Phase 3.
"""

import argparse
import os
import sys
from pathlib import Path

LAB_MARKER = Path(r"C:\ThreatPulseLab\LAB_VM")
DEFAULT_FOLDER = Path(r"C:\ThreatPulseLab\fim")
DEFAULT_OUT = Path(r"C:\ThreatPulseLab\logs\fim.jsonl")
STOP_EVENT_NAME = r"Global\ThreatPulse-Fim-Stop"


def check_environment() -> str | None:
    """Why FIM can't run here, or None."""
    if not LAB_MARKER.exists():
        return f"{LAB_MARKER} was not found. FIM runs only inside the ThreatPulse lab VM."
    # 32-bit Python would see redirected System32 and registry paths.
    if sys.maxsize <= 2**32:
        return "FIM needs 64-bit Python."
    return None


def take_baseline(folder: Path) -> int:
    # Imported here, so --help and tests work without pywin32.
    import win32event
    from baseline import create_baseline
    from targets import REGISTRY_TARGETS, folder_targets
    from windows_watch import WindowsSource

    folders = folder_targets(os.environ)
    source = WindowsSource(REGISTRY_TARGETS, folders, win32event.CreateEvent(None, True, False, None), True)
    snapshot = source.scan()
    try:
        create_baseline(folder, snapshot)
    except FileExistsError as error:
        print(f"Refusing to replace the baseline: {error}", file=sys.stderr)
        return 1
    print(f"Baseline saved in {folder}, with {len(snapshot)} items.")
    return 0


def watch(folder: Path, out: Path, poll_only: bool) -> int:
    import win32api
    import win32event
    from baseline import load_baseline
    from events import EventWriter
    from monitor import FULL_COMPARE_SECONDS, Monitor, run
    from targets import REGISTRY_TARGETS, folder_targets
    from windows_watch import ERROR_ALREADY_EXISTS, WAIT_OBJECT_0, WindowsSource

    try:
        baseline = load_baseline(folder)
    except FileNotFoundError:
        print(f"No baseline in {folder}. Run: main.py baseline", file=sys.stderr)
        return 1

    # Named so that start_lab_sensors.ps1 can stop FIM cleanly from another console.
    stop_event = win32event.CreateEvent(None, True, False, STOP_EVENT_NAME)
    if win32api.GetLastError() == ERROR_ALREADY_EXISTS:
        print("Refusing to start: FIM is already running.", file=sys.stderr)
        return 1

    def on_console_event(_kind: int) -> bool:
        win32event.SetEvent(stop_event)
        return True

    win32api.SetConsoleCtrlHandler(on_console_event, True)

    writer = EventWriter(out)
    monitor = Monitor(baseline, writer.write)
    source = WindowsSource(REGISTRY_TARGETS, folder_targets(os.environ), stop_event, poll_only)

    mode = f"every {FULL_COMPARE_SECONDS} seconds only" if poll_only else "on notifications"
    print(f"ThreatPulse FIM running, comparing {mode}. Writing to {out}\nPress Ctrl+C to stop.")

    def should_stop() -> bool:
        return win32event.WaitForSingleObject(stop_event, 0) == WAIT_OBJECT_0

    try:
        run(monitor, source, should_stop)
    finally:
        writer.close()

    stats = monitor.stats
    print(
        f"\nChanges reported:             {stats.changes}"
        f"\nNotifications:                {stats.notifications}"
        f"\nNotifications with no change: {stats.notifications_no_change}"
        f"\nFull compares:                {stats.full_compares}"
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="ThreatPulse File Integrity Monitoring.")
    parser.add_argument("--dir", type=Path, default=DEFAULT_FOLDER, help="baseline folder")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("baseline", help="save the current state as the approved baseline")
    watch_parser = commands.add_parser("watch", help="watch for changes")
    watch_parser.add_argument("--out", type=Path, default=DEFAULT_OUT, help="output file")
    watch_parser.add_argument(
        "--poll-only", action="store_true", help="no notifications, to test the 60-second compare"
    )
    args = parser.parse_args()

    problem = check_environment()
    if problem:
        print(f"Refusing to start: {problem}", file=sys.stderr)
        return 2

    if args.command == "baseline":
        return take_baseline(args.dir)
    return watch(args.dir, args.out, args.poll_only)


if __name__ == "__main__":
    sys.exit(main())
