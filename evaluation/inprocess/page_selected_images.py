#!/usr/bin/env python3
"""Emit exact supplied ELF streams; no inferred compiler instruction inventory."""
import hashlib
import json
from pathlib import Path
import struct
import sys

PAGE = 4096
DATA = 0x600000
SONAME = b'li2-stream.so\0'
EH = struct.Struct('<16sHHIQQQIHHHHHH')
PH = struct.Struct('<IIQQQQQQ')
MOV_EAX_EXIT = bytes.fromhex('b83c000000')
SYSCALL = bytes.fromhex('0f05')


def mov32(reg, value):
    return bytes(([0x41] if reg >= 8 else []) + [0xb8 + (reg & 7)]) + struct.pack('<I', value)


def mov64(reg, value):
    return bytes([0x49 if reg >= 8 else 0x48, 0xb8 + (reg & 7)]) + struct.pack('<Q', value)


def streams():
    rows = []
    for kind, opcode in ((2, 'f7'), (3, 'ff')):
        for width, prefix in ((16, '66'), (32, ''), (64, '48')):
            name = ('rdrand' if kind == 2 else 'rdseed') + str(width)
            rows.append(dict(name=name, code=bytes.fromhex(prefix + '0fc7' + opcode) + MOV_EAX_EXIT + SYSCALL,
                             kind=kind, width=width, destination=7, steps=1, faults=3, syscalls=1, offset=0,
                             category='random', selected_first=True))
    rdpid = bytes.fromhex('f3480fc7ff')
    rows.append(dict(name='rdpid64', code=rdpid + MOV_EAX_EXIT + SYSCALL, kind=4, width=64,
                     destination=7, steps=1, faults=3, syscalls=1, offset=0, category='id', selected_first=True))
    rows.append(dict(name='mov_exit', code=mov32(7, 43) + MOV_EAX_EXIT + SYSCALL,
                     kind=0, width=0, destination=0, steps=2, faults=3, syscalls=1,
                     offset=0, category='deterministic', exit=43, selected_first=False))
    rows.append(dict(name='prefix_random', code=b'\x90' + mov64(12, 0x1122334455667788) +
                     bytes.fromhex('480fc7f7') + MOV_EAX_EXIT + SYSCALL,
                     kind=2, width=64, destination=7, steps=3, faults=5, syscalls=1,
                     offset=0, category='random', selected_first=False))
    rows.append(dict(name='cross_mov', code=mov64(7, 0x123456789abcdef0) +
                     bytes.fromhex('480fc7f7') + MOV_EAX_EXIT + SYSCALL,
                     kind=2, width=64, destination=7, steps=2, faults=4, syscalls=1,
                     offset=PAGE-2, category='random', selected_first=False))
    rows.append(dict(name='cross_selected', code=rdpid + MOV_EAX_EXIT + SYSCALL,
                     kind=4, width=64, destination=7, steps=1, faults=3, syscalls=1,
                     offset=PAGE-2, category='id', selected_first=True))
    rows.append(dict(name='rsp_refusal', code=bytes.fromhex('480fc7f4') + MOV_EAX_EXIT + SYSCALL,
                     kind=2, width=64, destination=4, steps=0, faults=1, syscalls=0,
                     offset=0, category='refusal', failure=629, detail=7, selected_first=True))
    for name, sig in (('query_trap', 5), ('query_trap_highbits', (1 << 32) | 5), ('query_usr1', 10)):
        # All address/argument preparation is in the qualified MOV-immediate
        # inventory. ET_EXEC supplies a genuine writable output page at DATA.
        query = (mov64(7, sig) if sig > 0xffffffff else mov32(7, sig))
        query += mov32(6, 0) + mov32(2, DATA) + mov32(10, 8) + mov32(0, 13) + SYSCALL
        # Observe the actual kernel-written action; initial bytes are A5, not
        # the expected zero/default result. No unsupported result-copy MOV.
        output = mov32(7, 1) + mov32(6, DATA) + mov32(2, 32) + mov32(0, 1) + SYSCALL
        tail = mov32(7, 0) + MOV_EAX_EXIT + SYSCALL
        refused = sig != 10
        rows.append(dict(name=name, code=query + output + tail, kind=0, width=0, destination=0,
                         steps=5 if refused else 11, faults=6 if refused else 14,
                         syscalls=1 if refused else 3, offset=0, category='query',
                         failure=206 if refused else 0, detail=13 if refused else 0,
                         exit=0, selected_first=False))
    assert len(rows) == 15
    return rows


def header(elf_type, entry, ph):
    ident = b'\x7fELF\x02\x01\x01' + bytes(9)
    return EH.pack(ident, elf_type, 62, 1, entry, EH.size, 0, 0, EH.size, PH.size, len(ph), 0, 0, 0)


def segment(kind, flags, offset, address, size, align=PAGE):
    return (kind, flags, offset, address, address, size, size, align)


def emit(path, elf_type, entry, ph, pieces, size):
    b = bytearray(size)
    b[:EH.size] = header(elf_type, entry, ph)
    for i, row in enumerate(ph):
        PH.pack_into(b, EH.size+i*PH.size, *row)
    occupied = [(0, EH.size+len(ph)*PH.size)]
    for offset, data in pieces:
        assert offset >= 0 and offset+len(data) <= size
        assert all(offset+len(data) <= a or end <= offset for a, end in occupied)
        b[offset:offset+len(data)] = data
        occupied.append((offset, offset+len(data)))
    path.write_bytes(b); path.chmod(0o700)
    return hashlib.sha256(b).hexdigest()


def make(directory):
    directory.mkdir(parents=True, exist_ok=False)
    result = []
    for spec in streams():
        here = directory/spec['name']; here.mkdir()
        interp = (here/'interpreter.so').absolute()
        dynamic, strings = 0x400, 0x480
        dyn = b''.join(struct.pack('<qQ', tag, value) for tag, value in
                       ((5, strings), (10, len(SONAME)+1), (14, 1), (0, 0)))
        ph = [segment(1, 4, 0, 0, PAGE), segment(1, 5, PAGE, PAGE, 2*PAGE),
              segment(2, 4, dynamic, dynamic, len(dyn), 8), segment(0x6474e551, 6, 0, 0, 0, 16)]
        code = spec.pop('code')
        entry = PAGE + spec['offset']
        ih = emit(interp, 3, entry, ph, [(dynamic, dyn), (strings, b'\0'+SONAME),
                                       (entry, code)], 3*PAGE)
        # Namespace resolves this DT_NEEDED name to exactly the original
        # interpreter bytes, not a substitute object with guessed identity.
        (here/SONAME[:-1].decode()).write_bytes(interp.read_bytes())
        path = bytes(str(interp), 'utf-8') + b'\0'
        assert len(path) <= 512
        main_dynamic = b''.join(struct.pack('<qQ', tag, value) for tag, value in
                                ((1, 1), (5, 0x400000+strings), (10, len(SONAME)+1), (0, 0)))
        main_ph = [segment(6, 4, EH.size, 0x400000+EH.size, 7*PH.size, 8),
                   segment(3, 4, 0x500, 0x400500, len(path), 1),
                   segment(1, 4, 0, 0x400000, PAGE), segment(1, 5, PAGE, 0x401000, PAGE),
                   segment(1, 6, 2*PAGE, DATA, PAGE),
                   segment(2, 4, dynamic, 0x400000+dynamic, len(main_dynamic), 8),
                   segment(0x6474e551, 6, 0, 0, 0, 16)]
        main_code = mov32(7, 98) + MOV_EAX_EXIT + SYSCALL
        main = here/'original'
        mh = emit(main, 2, 0x401000, main_ph,
                  [(dynamic, main_dynamic), (strings, b'\0'+SONAME), (0x500, path),
                   (PAGE, main_code), (2*PAGE, b'\xa5'*32)], 3*PAGE)
        result.append(dict(spec, interpreter=str(interp), original=str(main.absolute()),
                           library_root=str(here.absolute()), interpreter_sha256=ih, original_sha256=mh,
                           entry_vaddr=entry, entry_file_offset=entry, exact_stream_hex=code.hex(),
                           soname_sha256=ih, data_address=DATA, data_initial_hex=('a5'*32)))
    (directory/'images.json').write_text(json.dumps(result, indent=2, sort_keys=True)+'\n')


if __name__ == '__main__':
    assert len(sys.argv) == 2
    make(Path(sys.argv[1]).resolve())
