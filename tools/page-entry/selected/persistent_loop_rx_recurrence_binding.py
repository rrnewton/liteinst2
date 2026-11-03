#!/usr/bin/env python3
"""One literal observation profile over the shared actual RX binding writer."""
from pathlib import Path
import sys
from persistent_loop_resident_rx_binding import LEAVES as RX_LEAVES, RECURRENCE_INPUTS, write_binding, need
LEAVES=RX_LEAVES+RECURRENCE_INPUTS

def main():
    need(len(sys.argv)==6 and sys.argv[5]=='release','exact recurrence release binding arguments')
    paths=[Path(x).resolve(strict=True) for x in sys.argv[1:5]]
    write_binding(*paths,'release',recurrence=True)

if __name__=='__main__':main()
