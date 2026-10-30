#!/usr/bin/env python3
"""Pure bounded GNU objdump text-to-head transport; no decoder or tool authority."""
import hashlib
from pathlib import Path
import re
import sys
import types

if sys.flags.optimize:
    raise SystemExit('assertions required')

CAP = 1048576
ADAPTER_SHA = '0ae4995cccbeeb3d414849962b9b946b5e9c3fa3b391cdfd403ea5405730e374'
path = Path(__file__).resolve().with_name('disassembly.py')
with path.open('rb') as stream:
    raw = stream.read(CAP + 1)
assert len(raw) <= CAP and hashlib.sha256(raw).hexdigest() == ADAPTER_SHA
D = types.ModuleType('authenticated_head_capture_disassembly')
D.__file__ = str(path)
exec(compile(raw, str(path), 'exec'), D.__dict__)

SYMBOLS = {'start': '_start', 'kernel': 'kernel', 'hook': 'null_hook'}
HEADER = re.compile(r'([0-9a-f]{1,16}) <([A-Za-z_.$][A-Za-z0-9_.$]*)>:')
INSTRUCTION = re.compile(r' *([0-9a-f]{1,16}):\t([0-9a-f ]{1,48})\t([\x20-\x7e\t]+)')


def body(raw, role, image, obj, size, count):
    assert type(raw) is bytes and 0 < len(raw) <= CAP and raw.endswith(b'\n'), 'capture bound/LF'
    assert re.fullmatch(rb'[\x20-\x7e\t\n]+', raw), 'ASCII capture'
    lines = raw.decode('ascii').splitlines()
    assert all(len(line) <= 4096 for line in lines), 'line bound'
    base = D.BASES['.text.' + role]
    code = image.owned(base, size, 5)[1]
    cursor, stage, heads, labels = base, 0, [], set()
    for line in lines:
        if not line:
            continue
        if stage == 0:
            # The display pathname is syntax only, never file identity authority.
            assert re.fullmatch(r'[\x20-\x7e]+:[ \t]+file format elf64-x86-64', line), 'format header'
            stage = 1
        elif stage == 1:
            assert line == 'Disassembly of section .text:', 'one text section'
            stage = 2
        elif stage == 2:
            match = HEADER.fullmatch(line)
            assert match and int(match[1], 16) == base and match[2] == SYMBOLS[role], 'selected FUNC header'
            labels.add(match[2]); stage = 3
        else:
            match = HEADER.fullmatch(line)
            if match:
                name = match[2]
                assert int(match[1], 16) == cursor < base + size and name not in labels, 'label head/order'
                symbol = obj.named[name]
                assert symbol == (0, 0, obj.by_name['.text.' + role], cursor - base, 0), 'local NOTYPE label'
                assert image.named[name] == (0, 0, image.by_name['.text'], cursor, 0), 'linked label'
                labels.add(name)
                continue
            match = INSTRUCTION.fullmatch(line)
            assert match and int(match[1], 16) == cursor, 'instruction line/order'
            column = match[2].rstrip(' ')
            assert re.fullmatch(r'[0-9a-f]{2}(?: [0-9a-f]{2}){0,15}', column), 'instruction byte column'
            chunk = bytes.fromhex(column)
            assert 1 <= len(chunk) <= 15 and len(heads) < count, 'instruction size/count'
            assert match[3].strip(' \t') and '(bad)' not in match[3], 'rendered diagnostic'
            offset = cursor - base
            assert cursor + len(chunk) <= base + size and code[offset:offset + len(chunk)] == chunk, 'exact image bytes'
            heads.append((offset, chunk)); cursor += len(chunk)
    assert stage == 3 and cursor == base + size and len(heads) == count, 'complete selected FUNC'
    return heads


def capture(program, original, obj, outputs):
    """Return LI2AUTHORED-HEADS bytes or refuse; caller owns all first pins/custody.

    outputs maps exactly start/kernel/hook to three independently retained stdout
    byte strings. This function does not establish which command produced them.
    """
    assert type(program) is str and program in D.COUNTS
    assert type(outputs) is dict and set(outputs) == set(D.ROLES), 'three captures'
    image, reloc, sizes = D.ownership(original, obj, program)
    heads = {role: body(outputs[role], role, image, reloc, sizes[role], count)
             for role, count in zip(D.ROLES, (61, len(D.C.instructions(program)), 1))}
    D.code_and_relocations(image, reloc, heads, program)
    rows = ['LI2AUTHORED-HEADS 1', 'program ' + program,
            'original ' + D.sha(original), 'object ' + D.sha(obj)]
    for role in D.ROLES:
        rows.extend(f'head {role} {index} {offset} {code.hex()}'
                    for index, (offset, code) in enumerate(heads[role]))
    result = ('\n'.join(rows) + '\n').encode('ascii')
    assert len(result) <= CAP
    assert D.head_transport(program, result, original, obj, sizes) == heads
    return result
