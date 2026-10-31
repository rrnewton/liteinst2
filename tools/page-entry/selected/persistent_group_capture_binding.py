#!/usr/bin/env python3
"""Derive observation-only head/trampoline selectors from the actual group fixture ELF.

These constants never participate in runtime eligibility or source authority.
The group release binder remains unchanged and owns the archive/policy proof.
"""
from pathlib import Path
import struct
import sys


def need(condition, message):
    if not condition:
        raise ValueError(message)


def configuration(data):
    def take(at, size):
        need(type(at) is int and type(size) is int and 0 <= at <= len(data) and
             0 <= size <= len(data)-at, 'bounded actual observation ELF range')
        return data[at:at+size]
    h = struct.unpack('<16sHHIQQQIHHHHHH', take(0, 64))
    need(h[0][:7] == b'\x7fELF\x02\x01\x01' and h[1:4] == (2, 62, 1) and
         h[8:10] == (64, 56) and 0 < h[10] <= 32 and h[11] == 64 and 0 < h[12] <= 256,
         'bounded x86-64 ET_EXEC fixture')
    programs = [struct.unpack('<IIQQQQQQ', take(h[5]+i*56, 56)) for i in range(h[10])]
    sections = [struct.unpack('<IIQQQQIIQQ', take(h[6]+i*64, 64)) for i in range(h[12])]
    tables = [s for s in sections if s[1] == 2]
    need(len(tables) == 1, 'one full symbol table')
    t = tables[0]
    need(t[9] == 24 and t[5] % 24 == 0 and t[6] < len(sections), 'complete table bounds')
    strings = sections[t[6]]
    need(strings[1] == 3, 'actual symbol string table')
    names = take(strings[4], strings[5]); found = {}
    wanted = {b'region_app_head', b'region_app_a_exit', b'region_app_second_page'}
    for at in range(t[4], t[4]+t[5], 24):
        n, info, other, section, address, size = struct.unpack('<IBBHQQ', take(at, 24))
        need(n < len(names) and b'\0' in names[n:], 'complete symbol name')
        name = names[n:names.index(b'\0', n)]
        if name in wanted:
            need(section and name not in found, 'unique actual defined observation symbol')
            if name == b'region_app_head':
                need(info & 15 == 2, 'actual observation function')
            found[name] = (address, size)
    need(set(found) == wanted, 'all actual observation symbols')
    first = found[b'region_app_head'][0] & ~4095
    need(4096 <= first and first+8192 < 1 << 31 and
         found[b'region_app_head'] == (first+0xe00, 125) and
         found[b'region_app_a_exit'] == (first+0xf0a, 0) and
         found[b'region_app_second_page'][0] == first+4096,
         'exact adjacent source pair and loop observation geometry')
    owners = [p for p in programs if p[0] == 1 and p[1] == 5 and p[5] <= p[6] and
              p[3] <= first and first-p[3]+8192 <= p[5]]
    need(len(owners) == 1 and all(p == owners[0] for p in programs if p[0] == 1 and
         p[3] < first+8192 and first < p[3]+p[6]), 'one full RX source file owner without overlap')
    segment = owners[0]
    source = take(segment[2]+first-segment[3], 8192)
    need(source[0xdfe:0xe00] == b'\x66\x90' and source[0xf0a:0xf13] == bytes.fromhex('4987ca4d87dc41ffe3'), 'actual genuine predecessor')
    values = [('HEAD', found[b'region_app_head'][0]), ('EXIT', found[b'region_app_a_exit'][0])]
    return ('#ifndef LI2_PERSISTENT_GROUP_CAPTURE_CONFIG_H\n'
            '#define LI2_PERSISTENT_GROUP_CAPTURE_CONFIG_H\n'
            '#define LI2_PG_CAPTURE_VERSION 1\n'+
            ''.join('#define LI2_PG_'+key+'_RVA 0x%xULL\n' % value for key, value in values)+
            '#endif\n').encode()


def main():
    need(len(sys.argv) == 3, 'actual image and existing output directory')
    image, output = (Path(x).resolve(strict=True) for x in sys.argv[1:])
    need(image.is_file() and output.is_dir(), 'actual regular image and output directory')
    with (output/'persistent_group_capture_config.h').open('xb') as stream:
        stream.write(configuration(image.read_bytes()))


if __name__ == '__main__':
    main()
