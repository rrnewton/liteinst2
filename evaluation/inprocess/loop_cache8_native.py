#!/usr/bin/env python3
"""Additive ABC169 CACHE8 cohort; original49 and all qualification remain required."""
import argparse
from loop_resident_rx_native import execute


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('expect-revision','current-build','current-build-sha256','output'):
        p.add_argument('--'+name,required=True)
    return execute(p.parse_args(),cache8=True)


if __name__=='__main__':raise SystemExit(main())
