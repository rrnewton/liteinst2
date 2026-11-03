#!/usr/bin/env python3
"""One fixed actual CACHE8 guest-effect cohort; old native49 remains separate."""
import argparse
import loop_resident_rx_native as shared


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in('expect-revision','current-build','current-build-sha256','output'):p.add_argument('--'+name,required=True)
    p.add_argument('--effect',required=True,type=int,choices=(2,3,4))
    a=p.parse_args()
    return shared.execute(a,cache8=True,effects_case=a.effect)


if __name__=='__main__':raise SystemExit(main())
