#!/usr/bin/env python3
"""Twelve immutable nodes, eight fresh active bindings; shared planner/emitter."""
from pathlib import Path
import sys
from persistent_loop_resident_rx_binding import LEAVES as RX_LEAVES, CACHE8_INPUTS, GROUP_DESCRIPTOR_INPUTS, ARENA_INPUTS, ARENA_OBSERVE_INPUTS, write_binding, need
LEAVES=RX_LEAVES+CACHE8_INPUTS+GROUP_DESCRIPTOR_INPUTS+ARENA_INPUTS+ARENA_OBSERVE_INPUTS

def main():
    need(len(sys.argv)==7 and sys.argv[5] in ('release','differential') and
         sys.argv[6] in ('0','1','2') and (sys.argv[6]=='0' or sys.argv[5]=='differential'),
         'exact arena release/differential binding arguments')
    paths=[Path(x).resolve(strict=True) for x in sys.argv[1:5]]
    write_binding(*paths,sys.argv[5],cache8=True,group_descriptor=True,arena=True,arena_observe=int(sys.argv[6]))

if __name__=='__main__':main()
