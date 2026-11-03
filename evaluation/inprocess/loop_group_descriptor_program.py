#!/usr/bin/env python3
"""Two complete real descriptor release programs through the shared bounded collector."""
import argparse
from pathlib import Path
from loop_resident_rx_program import execute

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--expect-revision',required=True)
    ap.add_argument('--output',type=Path,required=True)
    return execute(ap.parse_args(),cache8=True,group_descriptor=True)

if __name__=='__main__':raise SystemExit(main())
