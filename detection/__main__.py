"""Scan files and print every layer's result as JSON: python -m detection <path> [<path> ...]

This reads files and changes nothing, so it's safe anywhere. It never runs what it scans.
"""

import argparse
import json

from detection.scanner import scan_details


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Scan files with the ThreatPulse static layers.")
    parser.add_argument("paths", nargs="+")
    args = parser.parse_args(argv)
    print(json.dumps([scan_details(path) for path in args.paths], indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
