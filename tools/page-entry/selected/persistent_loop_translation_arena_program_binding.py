#!/usr/bin/env python3
"""Actual terminal values for twelve nodes and eight active bindings."""
from pathlib import Path
import sys
from persistent_loop_resident_rx_binding import LEAVES as RX_LEAVES, CACHE8_INPUTS, CACHE8_PROGRAM_INPUTS, GROUP_DESCRIPTOR_INPUTS, GROUP_DESCRIPTOR_PROGRAM_INPUTS, ARENA_INPUTS, ARENA_PROGRAM_INPUTS, write_binding, need
LEAVES=RX_LEAVES+CACHE8_INPUTS+CACHE8_PROGRAM_INPUTS+GROUP_DESCRIPTOR_INPUTS+GROUP_DESCRIPTOR_PROGRAM_INPUTS+ARENA_INPUTS+ARENA_PROGRAM_INPUTS

def main():
    need(len(sys.argv)in(6,7) and sys.argv[5]=='release' and
         (len(sys.argv)==6 or sys.argv[6]=='128'),'exact arena release program binding arguments')
    paths=[Path(x).resolve(strict=True) for x in sys.argv[1:5]]
    write_binding(*paths,sys.argv[5],cache8=True,cache8_program=True,group_descriptor=True,
                  arena=True,arena_program=True,arena_capacity=len(sys.argv)==7)

if __name__=='__main__':main()
