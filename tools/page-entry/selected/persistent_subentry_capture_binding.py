"""Observation selectors for the complete cold/root then guarded-subentry fixture.

These selectors supply no admission or publication authority.
"""
import hashlib
from pathlib import Path
import struct
import sys


def need(value, message):
    if not value:
        raise ValueError(message)


def configuration(data):
    def take(at, size):
        need(type(at) is int and type(size) is int and 0 <= at <= len(data)
             and 0 <= size <= len(data)-at, 'complete ELF range')
        return data[at:at+size]
    h = struct.unpack('<16sHHIQQQIHHHHHH', take(0, 64))
    need(h[0][:7] == b'\x7fELF\x02\x01\x01' and h[1:4] == (2, 62, 1)
         and h[8:10] == (64, 56) and 0 < h[10] <= 32
         and h[11] == 64 and 0 < h[12] <= 256, 'actual bounded ET_EXEC')
    programs = [struct.unpack('<IIQQQQQQ', take(h[5]+i*56, 56)) for i in range(h[10])]
    sections = [struct.unpack('<IIQQQQIIQQ', take(h[6]+i*64, 64)) for i in range(h[12])]
    tables = [s for s in sections if s[1] == 2]
    need(len(tables) == 1, 'one complete symbol table')
    t = tables[0]
    need(t[9] == 24 and t[5] % 24 == 0 and t[6] < len(sections), 'symbol bounds')
    strings = sections[t[6]]
    need(strings[1] == 3, 'symbol names')
    names = take(strings[4], strings[5])
    found = {}
    wanted = {b'region_app_page', b'region_app_head', b'region_app_predecessor',
              b'region_app_second_page', b'region_app_source_end', b'region_app_a_exit',
              b'region_app_block_b', b'region_app_b_exit', b'region_app_trampoline',
              b'region_app_capture', b'region_app_subentry_pointer'}
    for at in range(t[4], t[4]+t[5], 24):
        n, info, _, section, address, size = struct.unpack('<IBBHQQ', take(at, 24))
        need(n < len(names) and b'\0' in names[n:], 'complete symbol name')
        name = names[n:names.index(b'\0', n)]
        if name in wanted:
            need(section and name not in found, 'unique defined source symbol')
            if name == b'region_app_head':
                need(info & 15 == 2 and size == 257, 'actual complete root sequence')
            found[name] = address
    need(set(found) == wanted, 'all source pair symbols')
    first = found[b'region_app_page']
    need(first >= 4096 and not first % 4096 and first+8192 < 1 << 31
         and found[b'region_app_head'] == first+0x200
         and found[b'region_app_predecessor'] == first+0x1fe
         and found[b'region_app_a_exit'] == first+0x2fc
         and found[b'region_app_block_b'] == first+0x1100
         and found[b'region_app_b_exit'] == first+0x1107
         and found[b'region_app_trampoline'] == first+0x1120
         and found[b'region_app_second_page'] == first+4096
         and found[b'region_app_source_end'] == first+8192, 'exact whole source geometry')
    owners = [p for p in programs if p[0] == 1 and p[1] == 5 and p[5] <= p[6]
              and p[3] <= first and first-p[3]+8192 <= p[5]]
    need(len(owners) == 1 and all(p == owners[0] for p in programs if p[0] == 1
         and p[3] < first+8192 and first < p[3]+p[6]), 'one nonoverlapping RX source owner')
    p = owners[0]
    source = take(p[2]+first-p[3], 8192)
    expected = bytearray(b'\xcc'*8192)
    expected[0x1fe:0x200] = bytes.fromhex('6690')
    expected[0x200:0x2fc] = bytes.fromhex('4883c001')*63
    expected[0x2fc:0x301] = b'\xe9'+struct.pack('<i',0x1100-0x301)
    expected[0x1100:0x110a] = bytes.fromhex('4889074883c20141ff23')
    pointer = found[b'region_app_subentry_pointer']
    displacement = pointer-(first+0x112e)
    need(-(1<<31) <= displacement < 1<<31, 'actual ordinary trampoline displacement')
    expected[0x1120:0x112e] = bytes.fromhex('49924c87c74d87e3ff25')+struct.pack('<i',displacement)
    need(source == bytes(expected), 'entire actual8192-byte source including padding and alternate frontiers')
    pointers = [p for p in programs if p[0] == 1 and p[1] == 4 and
                p[3] <= pointer and pointer-p[3]+8 <= p[5]]
    need(len(pointers) == 1, 'one immutable original subentry pointer owner')
    q = pointers[0]
    need(struct.unpack('<Q',take(q[2]+pointer-q[3],8))[0] == first+0x1100,
         'actual ordinary memory-JMP target is certified head64')
    next_pc = found[b'region_app_capture']
    need(next_pc == first+8192 and any(p[0] == 1 and p[1] == 5 and
         p[3] <= next_pc and next_pc-p[3]+6 <= p[5] for p in programs),
         'actual original RX suffix follows complete source pair')
    values = [('ROOT',first+0x200),('HEAD',first+0x1100),('EXIT',first+0x1107),
              ('TRAMPOLINE',first+0x1120),('NEXT',next_pc)]
    return ('#ifndef LI2_PERSISTENT_SUBENTRY_CAPTURE_CONFIG_H\n'
            '#define LI2_PERSISTENT_SUBENTRY_CAPTURE_CONFIG_H\n'
            '#define LI2_PSO_CAPTURE_VERSION 7\n'+
            ''.join('#define LI2_PSO_'+key+'_RVA 0x%xULL\n' % value
                    for key,value in values)+'#endif\n').encode()


if __name__ == '__main__':
    need(len(sys.argv) == 3, 'actual image and existing output directory')
    image, output = (Path(x).resolve(strict=True) for x in sys.argv[1:])
    need(image.is_file() and output.is_dir(), 'regular image and output')
    with (output/'persistent_subentry_capture_config.h').open('xb') as stream:
        stream.write(configuration(image.read_bytes()))
