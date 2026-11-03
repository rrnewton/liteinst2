#!/usr/bin/env python3
"""Exact eight-slot/member profile through the shared actual binding writer."""
from pathlib import Path
import sys
from persistent_loop_resident_rx_binding import LEAVES as RX_LEAVES, CACHE8_INPUTS, write_binding, need
LEAVES=RX_LEAVES+CACHE8_INPUTS

def main():
    need(len(sys.argv)==6 and sys.argv[5] in ('release','differential'),
         'exact cache8 release/differential binding arguments')
    paths=[Path(x).resolve(strict=True) for x in sys.argv[1:5]]
    write_binding(*paths,sys.argv[5],cache8=True)

if __name__=='__main__':main()
