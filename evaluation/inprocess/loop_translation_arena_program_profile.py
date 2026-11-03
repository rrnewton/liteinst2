#!/usr/bin/env python3
"""One bounded user-DWARF profile of a natural arena34 LS failure.

Requires the complete failed arena program receipt from this clean revision.
Uses the retained bridge and a reserved singleton CPU; no build or timing credit.
"""
import argparse
from pathlib import Path
from loop_ro_program_profile import execute


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--expect-revision', required=True)
    ap.add_argument('--diagnostic-receipt', type=Path, required=True)
    ap.add_argument('--diagnostic-sha256', required=True)
    ap.add_argument('--output', type=Path, required=True)
    ap.add_argument('--capacity128', action='store_true',
                    help='profile the distinct128-node failure under unchanged target and observer bounds')
    ap.add_argument('--snapshot', action='store_true',
                    help='take one parent-only stopped-state counter snapshot; no timing or completion credit')
    args = ap.parse_args()
    return execute(args, group_descriptor=True, arena=True, arena_capacity=args.capacity128, snapshot=args.snapshot)


if __name__ == '__main__':
    raise SystemExit(main())
