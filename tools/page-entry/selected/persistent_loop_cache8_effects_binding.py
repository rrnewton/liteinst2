#!/usr/bin/env python3
"""Three literal actual guest effects; no old positive capture or authority cast."""
from pathlib import Path
import sys
from persistent_loop_resident_rx_binding import (LEAVES as RX_LEAVES, CACHE8_INPUTS,
    CACHE8_OBSERVE_INPUTS, CACHE8_EFFECTS_INPUTS, write_binding, need)
LEAVES=RX_LEAVES+CACHE8_INPUTS+CACHE8_OBSERVE_INPUTS+CACHE8_EFFECTS_INPUTS

def main():
    need(len(sys.argv)==7 and sys.argv[5] in ('release','differential') and
         sys.argv[6] in ('2','3','4') and (sys.argv[6]=='2' or sys.argv[5]=='differential'),
         'exact real-effect positive or differential refusal subject')
    paths=[Path(x).resolve(strict=True) for x in sys.argv[1:5]]
    write_binding(*paths,sys.argv[5],cache8=True,cache8_effects=int(sys.argv[6]))

if __name__=='__main__':main()
