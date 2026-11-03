#!/usr/bin/env python3
"""Terminal-only descriptor program binding through the unchanged shared writer."""
from pathlib import Path
import sys
from persistent_loop_resident_rx_binding import LEAVES as RX_LEAVES, CACHE8_INPUTS, CACHE8_PROGRAM_INPUTS, GROUP_DESCRIPTOR_INPUTS, GROUP_DESCRIPTOR_PROGRAM_INPUTS, write_binding, need
LEAVES=RX_LEAVES+CACHE8_INPUTS+CACHE8_PROGRAM_INPUTS+GROUP_DESCRIPTOR_INPUTS+GROUP_DESCRIPTOR_PROGRAM_INPUTS

def main():
    need(len(sys.argv)==6 and sys.argv[5]=='release','exact descriptor release program binding arguments')
    paths=[Path(x).resolve(strict=True) for x in sys.argv[1:5]]
    write_binding(*paths,sys.argv[5],cache8=True,cache8_program=True,group_descriptor=True)

if __name__=='__main__':main()
