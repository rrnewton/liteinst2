#!/usr/bin/env python3
"""Explicit schema16 observation selectors; all paired fixture bytes stay exact."""
from pathlib import Path
import sys
from persistent_loop_capture_binding import configuration as old_configuration, need

def configuration(data):
    prior = old_configuration(data)
    literal = b'#define LI2_PLO_CAPTURE_VERSION 14\n'
    need(prior.count(literal) == 1, 'one exact old observation schema literal')
    return prior.replace(literal, b'#define LI2_PLO_CAPTURE_VERSION 16\n', 1)

def main():
    need(len(sys.argv) == 3, 'actual paired image and existing output directory')
    image, output = (Path(x).resolve(strict=True) for x in sys.argv[1:])
    need(image.is_file() and output.is_dir(), 'actual regular image and output directory')
    with (output/'persistent_loop_capture_config.h').open('xb') as stream:
        stream.write(configuration(image.read_bytes()))

if __name__ == '__main__':
    main()
