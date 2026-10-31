#!/usr/bin/env python3
"""Derive observation-only head/dispatch/suffix selectors from the actual cold-admission fixture ELF.

These constants never participate in runtime eligibility or source authority.
The direct-frontier release binder remains unchanged and owns the archive/policy proof.
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
    offsets = {b'region_app_page':0,b'region_app_predecessor':0x10fe,b'region_app_head':0x1100,
        b'region_app_second_page':0x1000,b'region_app_target':0x1000,b'region_app_seed_jump':0x1102,
        b'region_app_branch_table':0x100,b'region_app_capture_pointer':0x118,
        b'region_app_direct_e9':0x200,b'region_app_direct_taken':0x220,b'region_app_direct_fallthrough':0xffa,
        b'region_app_wrong_target':0x240,b'region_app_return_frontier':0x1013,
        b'region_app_final_frontier':0x1011,b'region_app_first_store':0x1000,
        b'region_app_second_store':0x1007,b'region_app_source_end':0x4000}
    sizes = {b'region_app_head':7,b'region_app_target':21,b'region_app_direct_e9':5,
        b'region_app_direct_taken':6,b'region_app_direct_fallthrough':6,b'region_app_wrong_target':2,
        b'region_app_branch_table':24,b'region_app_capture_pointer':8}
    wanted = set(offsets)|{b'region_app_capture',b'region_app_capture_high'}
    for at in range(t[4], t[4]+t[5], 24):
        n, info, other, section, address, size = struct.unpack('<IBBHQQ', take(at, 24))
        need(n < len(names) and b'\0' in names[n:], 'complete symbol name')
        name = names[n:names.index(b'\0', n)]
        if name in wanted:
            need(section and name not in found, 'unique actual defined observation symbol')
            if name in (b'region_app_head',b'region_app_target',b'region_app_direct_e9',b'region_app_direct_taken',b'region_app_direct_fallthrough'):
                need(info & 15 == 2, 'actual observation function')
            found[name] = (address, size)
    need(set(found) == wanted, 'all actual observation symbols')
    first = found[b'region_app_page'][0]
    need(4096 <= first and not first%4096 and first+16384 < 1 << 31 and
         all(found[name] == (first+offset,sizes.get(name,0)) for name,offset in offsets.items()),
         'exact immutable seed/target pair, all three branches and whole source geometry')
    owners = [p for p in programs if p[0] == 1 and p[1] == 5 and p[5] <= p[6] and
              p[3] <= first and first-p[3]+16384 <= p[5]]
    need(len(owners) == 1 and all(p == owners[0] for p in programs if p[0] == 1 and
         p[3] < first+16384 and first < p[3]+p[6]), 'one full RX source file owner without overlap')
    segment = owners[0]
    source = take(segment[2]+first-segment[3], 16384)
    expected = bytearray(b'\xcc'*16384)
    for i,offset in enumerate((0x200,0x220,0xffa)):
        expected[0x100+8*i:0x108+8*i] = struct.pack('<Q',first+offset)
    expected[0x118:0x120] = struct.pack('<Q',first+0x4000)
    expected[0x200:0x205] = b'\xe9'+struct.pack('<i',0x1000-0x205)
    expected[0x220:0x228] = bytes.fromhex('0f85')+struct.pack('<i',0x1000-0x226)+bytes.fromhex('0f0b')
    expected[0x240:0x242] = bytes.fromhex('0f0b')
    expected[0xffa:0x1000] = bytes.fromhex('0f84')+struct.pack('<i',0x240-0x1000)
    expected[0x1000:0x1015] = bytes.fromhex('4889074883c007488947084883e9017502ff23ff26')
    expected[0x10fe:0x1107] = bytes.fromhex('66906690e9')+struct.pack('<i',0x1013-0x1107)
    need(source == bytes(expected), 'whole actual16384-byte seed/target source, every alternate byte and pointer')
    next_pc, next_size = found[b'region_app_capture']
    need(4096 <= next_pc < 1 << 31 and next_pc % 4096 == 0 and next_size == 6 and
         next_pc == first+16384, 'distinct actual next-TRACE suffix page')
    next_owner = [p for p in programs if p[0] == 1 and p[1] == 5 and p[5] <= p[6] and
                  p[3] <= next_pc and next_pc-p[3]+4096 <= p[5]]
    need(len(next_owner) == 1 and all(p == next_owner[0] for p in programs if p[0] == 1 and
         p[3] < next_pc+4096 and next_pc < p[3]+p[6]), 'one complete nonoverlapping RX suffix file page')
    p = next_owner[0]
    high,high_size = found[b'region_app_capture_high']
    need(high_size > 0 and sum(p[0] == 1 and p[1] == 5 and p[5] <= p[6] and
         p[3] <= high and high-p[3]+high_size <= p[5] for p in programs) == 1,
         'one complete high capture function in actual RX file bytes')
    need(take(p[2]+next_pc-p[3], 4096) == bytes.fromhex('ff2500000000')+
         struct.pack('<Q',high)+b'\xcc'*(4096-14), 'whole transparent suffix page and actual high target')
    values = [('A',found[b'region_app_head'][0]),('B',found[b'region_app_target'][0]),('NEXT',next_pc),
              ('RETURN',found[b'region_app_return_frontier'][0]),('FINAL',found[b'region_app_final_frontier'][0]),
              ('BRANCH0',found[b'region_app_direct_e9'][0]),('BRANCH1',found[b'region_app_direct_taken'][0]),
              ('BRANCH2',found[b'region_app_direct_fallthrough'][0]),('HIGH',high)]
    return ('#ifndef LI2_PERSISTENT_COLD_ADMISSION_CAPTURE_CONFIG_H\n'
            '#define LI2_PERSISTENT_COLD_ADMISSION_CAPTURE_CONFIG_H\n'
            '#define LI2_PCA_CAPTURE_VERSION 11\n'+
            ''.join('#define LI2_PCA_'+key+'_RVA 0x%xULL\n' % value for key, value in values)+
            '#endif\n').encode()


def main():
    need(len(sys.argv) == 3, 'actual image and existing output directory')
    image, output = (Path(x).resolve(strict=True) for x in sys.argv[1:])
    need(image.is_file() and output.is_dir(), 'actual regular image and output directory')
    with (output/'persistent_cold_admission_capture_config.h').open('xb') as stream:
        stream.write(configuration(image.read_bytes()))


if __name__ == '__main__':
    main()
