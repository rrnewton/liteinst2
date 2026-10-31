#!/usr/bin/env python3
"""File-only actual handler operand-load inspection; no executable loading."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct


def need(ok, message):
    if not ok:
        raise ValueError(message)


def inspect(elf, disassembly):
    raw = elf.read_bytes()
    need(raw[:7] == b'\x7fELF\2\1\1' and len(raw) >= 64, 'whole ELF64 input')
    h = struct.unpack_from('<16sHHIQQQIHHHHHH', raw)
    need(h[1:4] == (2, 62, 1) and h[8:10] == (64, 56) and h[11] == 64 and
         0 < h[10] <= 64 and 0 < h[12] <= 256, 'bounded actual non-PIE ELF tables')
    def take(at, count):
        need(0 <= at <= len(raw) and 0 <= count <= len(raw)-at, 'whole ELF range')
        return raw[at:at+count]
    ph = [struct.unpack('<IIQQQQQQ', take(h[5]+56*i,56)) for i in range(h[10])]
    sh = [struct.unpack('<IIQQQQIIQQ', take(h[6]+64*i,64)) for i in range(h[12])]
    tables = [x for x in sh if x[1] == 2]
    need(len(tables) == 1, 'one whole static symbol table')
    table = tables[0]
    need(table[9] == 24 and table[5] % 24 == 0 and table[6] < len(sh), 'whole SYMTAB records')
    strings = sh[table[6]];names = take(strings[4],strings[5]);symbols = {}
    for at in range(table[4],table[4]+table[5],24):
        n,info,other,index,value,size = struct.unpack('<IBBHQQ',take(at,24))
        need(n < len(names) and b'\0' in names[n:], 'terminated symbol name')
        name = names[n:names.index(b'\0',n)].decode('ascii')
        if name in ('handler','record'):
            need(name not in symbols and 0 < index < len(sh) and other == 0, 'unique defined exact symbol')
            symbols[name] = (value,size,info,index)
    need(set(symbols) == {'handler','record'} and symbols['handler'][2] == 2 and
         symbols['record'][1:3] == (191928,1), 'exact local handler and complete record object')
    address,size,_,_ = symbols['handler']
    loads = [x for x in ph if x[0] == 1 and x[1] == 5 and x[3] <= address and address+size <= x[3]+x[5]]
    need(len(loads) == 1 and size > 0, 'whole actual handler in file-backed RX LOAD')
    load = loads[0];body = take(load[2]+address-load[3],size)
    record = symbols['record'][0]
    need(sum(x[0] == 1 and x[1] == 6 and x[3] <= record and record+191928 <= x[3]+x[6] for x in ph) == 1,
         'whole observed record in one RW/NX LOAD')
    rows = []
    for line in disassembly.read_text().splitlines():
        m = re.fullmatch(r'\s*([0-9a-f]+):\s+((?:[0-9a-f]{2} )*[0-9a-f]{2})\s+(.+)',line)
        if m:
            pc = int(m[1],16);code = bytes.fromhex(m[2])
            need(address <= pc < address+size, 'only requested handler instruction range')
            rows.append((pc,code,m[3]))
    need(rows and rows[0][0] == address and
         all(a[0]+len(a[1]) == b[0] for a,b in zip(rows,rows[1:])) and
         rows[-1][0]+len(rows[-1][1]) == address+size and b''.join(x[1] for x in rows) == body,
         'every actual disassembled instruction byte exactly reconstructs whole handler')
    def rip(row, opcode, target):
        pc,b,_ = row
        if len(b) != 7 or b[0] not in (0x48,0x4c) or b[1] != opcode or b[2]&0xc7 != 5:
            return None
        if pc+7+struct.unpack_from('<i',b,3)[0] != target:
            return None
        return ((b[2]>>3)&7) | ((b[0]&4)<<1)
    # This exact compiler schedule is bound to the retained failed build. The
    # intervening operations are checked, never skipped: a private-cell pointer
    # read and the address-taken C local's store on the handler alternate stack.
    need([x[1] for x in rows[:6]] == [bytes.fromhex(x) for x in
         ('55','4889e5','4155','4154','53','4883ec18')],
         'exact handler frame: RBP anchor and 48 bytes below it')
    matches = []
    for i in range(len(rows)-4):
        pointer = rip(rows[i],0x8b,record+64)  # record.h[8]: original guest SP
        cell = rip(rows[i+1],0x8b,record+160)  # record.h[20]: separate private cell
        if pointer != 6 or cell != 7:  # actual RSI/RDI; neither aliases RBP or RAX
            continue
        pc,b,_ = rows[i+2]
        if b != bytes.fromhex('488b06'):  # one qword MOV [RSI] -> RAX
            continue
        if rows[i+3][1] != bytes.fromhex('488945d8'):  # RAX -> handler local [RBP-40]
            continue
        if rip(rows[i+4],0x89,record+96) != 0:  # same loaded RAX -> record.h[12]
            continue
        matches.append((i,pc))
    need(len(matches) == 1,
         'one exact five-instruction schedule with one guest operand load and two checked private operations')
    i,pc = matches[0]
    return dict(status='single_operand_load_inspected',elf_sha256=hashlib.sha256(raw).hexdigest(),
        disassembly_sha256=hashlib.sha256(disassembly.read_bytes()).hexdigest(),
        handler_address=address,handler_bytes=size,handler_sha256=hashlib.sha256(body).hexdigest(),
        record_address=record,record_bytes=191928,guest_load_address=pc,
        exact_sequence=[dict(address=a,bytes=b.hex(),text=t) for a,b,t in rows[i:i+5]],
        native_execution=False,production_continuation=False,qualification_credit=False)

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('elf',type=Path);p.add_argument('disassembly',type=Path)
    a = p.parse_args()
    print(json.dumps(inspect(a.elf,a.disassembly),sort_keys=True))


if __name__ == '__main__':
    main()
