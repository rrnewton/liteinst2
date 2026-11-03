#!/usr/bin/env python3
"""Two complete real arena release programs through the original bounded collector."""
import argparse
from pathlib import Path
from loop_resident_rx_program import execute


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--expect-revision',required=True)
    ap.add_argument('--output',type=Path,required=True)
    ap.add_argument('--capacity128',action='store_true',help='separate128-node experiment; original subject bounds remain')
    args=ap.parse_args()
    return execute(args,cache8=True,group_descriptor=True,arena=True,arena_capacity=args.capacity128)


if __name__=='__main__':raise SystemExit(main())
