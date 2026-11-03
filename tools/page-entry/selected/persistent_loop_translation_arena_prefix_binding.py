#!/usr/bin/env python3
"""Distinct capacity128 diagnostic at the literal 1024th offer."""
from pathlib import Path
import sys
from persistent_loop_resident_rx_binding import LEAVES as RX_LEAVES, CACHE8_INPUTS, CACHE8_PROGRAM_INPUTS, GROUP_DESCRIPTOR_INPUTS, GROUP_DESCRIPTOR_PROGRAM_INPUTS, ARENA_INPUTS, ARENA_PROGRAM_INPUTS, ARENA_PREFIX_INPUTS, write_binding, need
LEAVES=RX_LEAVES+CACHE8_INPUTS+CACHE8_PROGRAM_INPUTS+GROUP_DESCRIPTOR_INPUTS+GROUP_DESCRIPTOR_PROGRAM_INPUTS+ARENA_INPUTS+ARENA_PROGRAM_INPUTS+ARENA_PREFIX_INPUTS

def main():
    need(len(sys.argv)==7 and sys.argv[5]=='release' and sys.argv[6]=='128',
         'exact release capacity128 prefix binding arguments')
    paths=[Path(x).resolve(strict=True) for x in sys.argv[1:5]]
    write_binding(*paths,sys.argv[5],cache8=True,cache8_program=True,group_descriptor=True,
                  arena=True,arena_program=True,arena_capacity=True,arena_prefix=True)

if __name__=='__main__':main()
