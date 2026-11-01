#!/usr/bin/env python3
"""Independent fixed direct-E8 fixture selector; no runtime eligibility authority."""
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
    offsets = {b'region_app_page':0, b'region_app_predecessor':0x1fe,
        b'region_app_head':0x200, b'region_app_branch':0x204,
        b'region_app_call':0x20a, b'region_app_call_next':0x20d,
        b'region_app_return_exit':0x211, b'region_app_block_b':0x300,
        b'region_app_b_branch':0x304, b'region_app_b_exit':0x30a, b'region_app_ret':0x30a,
        b'region_app_miss_predecessor':0x5fe, b'region_app_miss_head':0x600,
        b'region_app_miss_branch':0x604, b'region_app_miss_call':0x60a,
        b'region_app_miss_return':0x60f, b'region_app_miss_exit':0x613,
        b'region_app_second_page':0x1000, b'region_app_source_end':0x2000,
        b'region_app_unknown_page':0x2000, b'region_app_unknown':0x2100,
        b'region_app_unknown_exit':0x2104, b'region_app_unknown_end':0x3000}
    sizes = {b'region_app_head':20, b'region_app_block_b':11,
             b'region_app_miss_head':22, b'region_app_unknown':7}
    wanted = set(offsets)|{b'region_app_capture', b'region_app_capture_high', b'region_app_capture_pointer'}
    for at in range(t[4], t[4]+t[5], 24):
        n, info, other, section, address, size = struct.unpack('<IBBHQQ', take(at, 24))
        need(n < len(names) and b'\0' in names[n:], 'complete symbol name')
        name = names[n:names.index(b'\0', n)]
        if name in wanted:
            need(section and name not in found, 'unique actual defined observation symbol')
            if name in sizes:
                need(info & 15 == 2, 'actual observation function')
            found[name] = (address, size)
    need(set(found) == wanted, 'all actual observation symbols')
    first = found[b'region_app_page'][0]
    need(first == 0x410000 and all(found[name] == (first+offset,sizes.get(name,0))
         for name,offset in offsets.items()), 'exact whole source pair, U and RET symbol geometry')
    def region(address, size, flags):
        owners = [p for p in programs if p[0] == 1 and p[1] == flags and p[5] <= p[6] and
                  p[3] <= address and address-p[3]+size <= p[5]]
        need(len(owners) == 1 and all(p == owners[0] for p in programs if p[0] == 1 and
             p[3] < address+size and address < p[3]+p[6]), 'one complete nonoverlapping file owner')
        p = owners[0]
        return take(p[2]+address-p[3],size)
    source = region(first,8192,5)
    expected = bytearray(b'\xcc'*8192)
    expected[0x1fe:0x200] = bytes.fromhex('ffe3')
    expected[0x200:0x214] = bytes.fromhex('4883c0010f84f600000041ffd44883c00941ff23')
    expected[0x300:0x30b] = bytes.fromhex('4883c0050f8403ffffffc3')
    expected[0x5fe:0x600] = bytes.fromhex('ffe3')
    expected[0x600:0x616] = bytes.fromhex('4883c0010f8403fcffffe8f1fcffff4883c00941ff23')
    need(source == bytes(expected), 'whole8192-byte source pair, all alternate arms and padding')
    outside = bytearray(b'\xcc'*4096)
    outside[0x100:0x107] = bytes.fromhex('4883c00941ff23')
    need(region(first+8192,4096,5) == bytes(outside), 'whole4096-byte outside-directory U page')
    low, low_size = found[b'region_app_capture']
    high, high_size = found[b'region_app_capture_high']
    need(low == 0x414000 and low_size == 6 and high_size > 0 and high != low,
         'unchanged low suffix and distinct actual high capture')
    region(high,high_size,5)
    need(region(low,4096,5) == bytes.fromhex('ff2500000000')+struct.pack('<Q',high)+b'\xcc'*(4096-14),
         'whole unused transparent suffix retains its actual target')
    pointer, pointer_size = found[b'region_app_capture_pointer']
    need(pointer_size == 0 and region(pointer,8,4) == struct.pack('<Q',high),
         'actual immutable memory-JMP target word')
    values = [('PAGE',first),('U_PAGE',first+8192),('A',found[b'region_app_head'][0]),
              ('A_MISS',found[b'region_app_miss_head'][0]),('B',found[b'region_app_block_b'][0]),
              ('RET',found[b'region_app_ret'][0]),('U',found[b'region_app_unknown'][0]),
              ('CAPTURE',high)]
    return ('#ifndef LI2_PERSISTENT_RET_OWNER_CONFIG_H\n#define LI2_PERSISTENT_RET_OWNER_CONFIG_H\n'
            '#define LI2_PRTO_VERSION 1\n'+
            ''.join('#define LI2_PRTO_'+key+'_RVA 0x%xULL\n' % value for key,value in values)+
            '#endif\n').encode()


def main():
    need(len(sys.argv) == 3, 'actual image and existing output directory')
    image, output = (Path(x).resolve(strict=True) for x in sys.argv[1:])
    need(image.is_file() and output.is_dir(), 'actual regular image and output directory')
    with (output/'persistent_ret_owner_config.h').open('xb') as stream:
        stream.write(configuration(image.read_bytes()))


if __name__ == '__main__':
    main()
