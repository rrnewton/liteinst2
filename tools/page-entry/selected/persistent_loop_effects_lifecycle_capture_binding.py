#!/usr/bin/env python3
"""Schema17 selectors; every original lifecycle ELF byte is authenticated."""
from pathlib import Path
import sys
from persistent_loop_lifecycle_capture_binding import configuration as old_configuration, need

def configuration(data):
    prior=old_configuration(data)
    literal=b'#define LI2_PLC_CAPTURE_VERSION 15\n'
    need(prior.count(literal)==1,'one exact original lifecycle schema literal')
    return prior.replace(literal,b'#define LI2_PLC_CAPTURE_VERSION 17\n',1)

def main():
    need(len(sys.argv)==3,'actual lifecycle image and existing output directory')
    image,output=(Path(x).resolve(strict=True)for x in sys.argv[1:])
    need(image.is_file()and output.is_dir(),'actual regular image and output directory')
    with(output/'persistent_loop_effects_lifecycle_capture_config.h').open('xb')as stream:
        stream.write(configuration(image.read_bytes()))

if __name__=='__main__':main()
