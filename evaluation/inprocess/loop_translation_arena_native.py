#!/usr/bin/env python3
"""Ten-root791 native proof, fourteen arena activations and separate causal controls."""
import argparse
from loop_resident_rx_native import execute


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('expect-revision','current-build','current-build-sha256','output'):p.add_argument('--'+name,required=True)
    return execute(p.parse_args(),cache8=True,group_descriptor=True,arena=True)


if __name__=='__main__':raise SystemExit(main())
