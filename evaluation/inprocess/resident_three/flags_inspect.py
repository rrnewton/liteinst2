#!/usr/bin/env python3
"""Whole emitted probe bootstrap/epilogue check; file parsing only."""
import argparse
import hashlib
import json
from pathlib import Path
import struct


def need(ok, message):
    if not ok:
        raise ValueError(message)


def inspect(path):
    data = path.read_bytes()
    need(data[:7] == b'\x7fELF\2\1\1' and len(data) >= 64, 'ELF64 little endian')
    need(struct.unpack_from('<HH', data, 16) == (2, 62), 'actual non-PIE x86-64 executable')
    phoff, shoff = struct.unpack_from('<QQ', data, 32)
    phsize, phnum, shsize, shnum = struct.unpack_from('<HHHH', data, 54)
    need(phsize == 56 and 0 < phnum <= 64 and phoff+phnum*phsize <= len(data), 'bounded PHDR')
    need(shsize == 64 and 0 < shnum <= 256 and shoff+shnum*shsize <= len(data), 'bounded SHDR')
    ph = [struct.unpack_from('<IIQQQQQQ', data, phoff+i*phsize) for i in range(phnum)]
    sh = [struct.unpack_from('<IIQQQQIIQQ', data, shoff+i*shsize) for i in range(shnum)]
    need(all(p[1] & 3 != 3 for p in ph if p[0] == 1), 'no writable executable LOAD')
    stacks = [p for p in ph if p[0] == 0x6474E551]
    need(len(stacks) == 1 and not stacks[0][1] & 1, 'non-executable GNU stack')
    symbols = {}
    for section in sh:
        if section[1] != 2:
            continue
        need(section[9] == 24 and section[5] % 24 == 0 and section[4]+section[5] <= len(data),
             'whole ordinary symbol table')
        need(section[6] < len(sh), 'symbol string table index')
        strings_section = sh[section[6]]
        strings = data[strings_section[4]:strings_section[4]+strings_section[5]]
        need(len(strings) == strings_section[5], 'whole symbol strings')
        for offset in range(section[4], section[4]+section[5], 24):
            n, info, other, index, value, size = struct.unpack_from('<IBBHQQ', data, offset)
            need(n < len(strings) and b'\0' in strings[n:], 'bounded symbol name')
            name = strings[n:strings.index(b'\0', n)].decode('ascii')
            if name.startswith('probe_'):
                need(name not in symbols and index < len(sh) and index != 0, 'unique defined probe symbol')
                symbols[name] = (value, size, index, info)

    required = ('probe_enter', 'probe_reload', 'probe_return', 'probe_seed', 'probe_flags',
                'probe_pc', 'probe_caller', 'probe_vectors', 'probe_mxcsr',
                'probe_scratch', 'probe_scratch_end', 'probe_handler',
                'probe_handler_entry', 'probe_handler_flags')
    need(set(symbols) == set(required), 'complete exact probe symbol set')

    def address(name):
        return symbols[name][0]

    def image(address_value, size):
        found = [p for p in ph if p[0] == 1 and p[3] <= address_value and
                 address_value+size <= p[3]+p[5]]
        need(len(found) == 1, 'one complete file-backed LOAD')
        p = found[0]
        offset = p[2]+address_value-p[3]
        result = data[offset:offset+size]
        need(len(result) == size, 'whole file-backed bytes')
        return result, p[1]

    def permission(name, size, expected):
        a = address(name)
        found = [p for p in ph if p[0] == 1 and p[3] <= a and a+size <= p[3]+p[6]]
        need(len(found) == 1 and found[0][1] == expected, 'exact symbol LOAD permissions: '+name)

    permission('probe_enter', symbols['probe_enter'][1], 5)
    permission('probe_return', symbols['probe_return'][1], 5)
    for name, size in (('probe_seed', 128), ('probe_flags', 8), ('probe_pc', 8),
                       ('probe_caller', 56), ('probe_scratch', 4096)):
        permission(name, size, 6)
    need(address('probe_scratch_end') == address('probe_scratch')+4096 and
         address('probe_scratch') % 16 == 0, 'literal private scratch geometry')
    need(image(address('probe_mxcsr'), 4) == (struct.pack('<I', 0x1F80), 4), 'whole MXCSR literal')
    need(image(address('probe_vectors'), 256) ==
         (b''.join(struct.pack('<Q', 0x3141592653589793+i) for i in range(1, 33)), 4),
         'whole vector literals')

    def relative(out, start, opcode, destination):
        delta = destination-(start+len(out)+len(opcode)+4)
        need(-(1 << 31) <= delta < (1 << 31), 'exact RIP-relative displacement')
        out.extend(opcode+struct.pack('<i', delta))

    def mov(out, start, register, destination, load):
        prefix = bytes((0x48 | (4 if register >= 8 else 0), 0x8B if load else 0x89,
                        ((register & 7) << 3) | 5))
        relative(out, start, prefix, destination)

    start = address('probe_enter')
    expected = bytearray()
    for i, register in enumerate((4, 3, 5, 12, 13, 14, 15)):
        mov(expected, start, register, address('probe_caller')+8*i, False)
    expected.extend(b'\xdb\xe3\xd9\xe8\xd9\xeb')  # FNINIT, FLD1, FLDPI.
    relative(expected, start, b'\x0f\xae\x15', address('probe_mxcsr'))
    for register in range(16):
        prefix = b'\x66'+(b'\x44' if register >= 8 else b'')+b'\x0f\x6f'+bytes((((register & 7) << 3) | 5,))
        relative(expected, start, prefix, address('probe_vectors')+16*register)
    need(start+len(expected) == address('probe_reload'), 'exact reload boundary')
    relative(expected, start, b'\x48\x8d\x25', address('probe_scratch_end'))
    relative(expected, start, b'\xff\x35', address('probe_flags'))
    expected.extend(b'\x9d')  # POPFQ uses the private scratch stack.
    for register in range(16):
        mov(expected, start, register, address('probe_seed')+8*register, True)
    relative(expected, start, b'\xff\x25', address('probe_pc'))
    need(symbols['probe_enter'][1] == len(expected) and image(start, len(expected)) == (expected, 5),
         'every emitted entry/reload byte exactly reconstructed')
    need(start+len(expected) == address('probe_return'), 'no hidden interposed instructions')
    start_return = address('probe_return')
    returned = bytearray(b'\xfc')
    for i, register in enumerate((3, 5, 12, 13, 14, 15), 1):
        mov(returned, start_return, register, address('probe_caller')+8*i, True)
    mov(returned, start_return, 4, address('probe_caller'), True)
    returned.extend(b'\xc3')
    need(symbols['probe_return'][1] == len(returned) and image(start_return, len(returned)) == (returned, 5),
         'every emitted recovery byte exactly reconstructed')
    start_handler = address('probe_handler_entry')
    need(start_handler == start_return+len(returned), 'exact new wrapper follows unchanged return')
    permission('probe_handler_entry', symbols['probe_handler_entry'][1], 5)
    permission('probe_handler', symbols['probe_handler'][1], 5)
    permission('probe_handler_flags', 8, 6)
    need(address('probe_handler_flags') % 8 == 0 and symbols['probe_handler_flags'][1] == 8,
         'aligned complete live-handler-flags observation')
    entered = bytearray(b'\x9c')
    relative(entered, start_handler, b'\x8f\x05', address('probe_handler_flags'))
    entered.extend(b'\x9c\x48\x81\x24\x24'+struct.pack('<i', -279809)+b'\x9d')
    relative(entered, start_handler, b'\xe9', address('probe_handler'))
    need(symbols['probe_handler_entry'][1] == len(entered) and
         image(start_handler, len(entered)) == (entered, 5),
         'every aligned AC-safe actual handler-wrapper byte; saved kernel UC untouched')
    interpreters = []
    for p in ph:
        if p[0] == 3:
            value = data[p[2]:p[2]+p[5]]
            need(value.startswith(b'/') and value.endswith(b'\0') and b'\0' not in value[:-1], 'actual interpreter')
            interpreters.append(value[:-1].decode())
    need(len(interpreters) == 1, 'one actual interpreter')
    return {'schema': 1, 'status': 'source_bytes_inspected', 'elf_bytes': len(data),
            'elf_sha256': hashlib.sha256(data).hexdigest(), 'interpreter': interpreters[0],
            'entry_bytes': len(expected), 'return_bytes': len(returned),
            'reload_address': address('probe_reload'), 'scratch_end_address': address('probe_scratch_end'),
            'entry_sha256': hashlib.sha256(expected).hexdigest(),
            'return_sha256': hashlib.sha256(returned).hexdigest(),
            'handler_bytes': len(entered), 'handler_sha256': hashlib.sha256(entered).hexdigest(),
            'handler_address': start_handler,
            'native_execution': False, 'qualification_credit': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('elf', type=Path)
    args = parser.parse_args()
    print(json.dumps(inspect(args.elf), sort_keys=True))


if __name__ == '__main__':
    main()
