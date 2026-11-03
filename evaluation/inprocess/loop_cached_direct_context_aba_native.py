#!/usr/bin/env python3
"""One actual live-proof ABA refusal; positive43 and original55/79 remain separate."""
import argparse
from loop_resident_rx_native import execute


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('expect-revision','current-build','current-build-sha256','output'):p.add_argument('--'+name,required=True)
    return execute(p.parse_args(),cache8=True,group_descriptor=True,cached_direct_context=True,cached_direct_aba=True)


if __name__=='__main__':raise SystemExit(main())
