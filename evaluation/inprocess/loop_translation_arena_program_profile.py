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
    return execute(ap.parse_args(), group_descriptor=True, arena=True)


if __name__ == '__main__':
    raise SystemExit(main())
