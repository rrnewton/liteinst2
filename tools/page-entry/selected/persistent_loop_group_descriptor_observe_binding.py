#!/usr/bin/env python3
"""Literal ABC255 positive or one independently eligible RAW exposure subject."""
from pathlib import Path
import sys
from persistent_loop_resident_rx_binding import (LEAVES as RX_LEAVES,CACHE8_INPUTS,
    GROUP_DESCRIPTOR_INPUTS,GROUP_DESCRIPTOR_OBSERVE_INPUTS,write_binding,need)
LEAVES=RX_LEAVES+CACHE8_INPUTS+GROUP_DESCRIPTOR_INPUTS+GROUP_DESCRIPTOR_OBSERVE_INPUTS

def main():
    need(len(sys.argv)==7 and sys.argv[5] in ('release','differential') and
         sys.argv[6] in tuple(map(str,range(7))) and (sys.argv[6]=='0' or sys.argv[5]=='differential'),
         'literal descriptor mode and complete independent exposure subject')
    paths=[Path(x).resolve(strict=True) for x in sys.argv[1:5]]
    write_binding(*paths,sys.argv[5],cache8=True,group_descriptor=True,group_descriptor_observe=int(sys.argv[6]))

if __name__=='__main__':main()
