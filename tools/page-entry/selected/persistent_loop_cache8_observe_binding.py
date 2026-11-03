#!/usr/bin/env python3
"""One fixed >2-root application/observer over the shared cache8 writer."""
from pathlib import Path
import sys
from persistent_loop_resident_rx_binding import (LEAVES as RX_LEAVES, CACHE8_INPUTS,
    CACHE8_OBSERVE_INPUTS, write_binding, need)
LEAVES=RX_LEAVES+CACHE8_INPUTS+CACHE8_OBSERVE_INPUTS

def main():
    need(len(sys.argv)==7 and sys.argv[5] in ('release','differential') and
         sys.argv[6] in ('0','1') and (sys.argv[6]=='0' or sys.argv[5]=='differential'),
         'exact cache8 positive or differential predicate controls')
    paths=[Path(x).resolve(strict=True) for x in sys.argv[1:5]]
    write_binding(*paths,sys.argv[5],cache8=True,cache8_observe=int(sys.argv[6]))

if __name__=='__main__':main()
