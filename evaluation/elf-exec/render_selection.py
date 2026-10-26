#!/usr/bin/env python3
"""Render one bounded selection for the authored kernel-exec fixture only."""
import argparse
import hashlib
import os
from pathlib import Path
import re
import stat
import struct
import sys

if sys.flags.optimize:
    raise SystemExit("optimized Python disables fixture validation")

PAGE = 4096
LIMIT = 1024 * 1024
SUBJECT = 0x401100
CARRIER = 0x418000
IMAGE = 0x420000
SUBJECT_BYTES = bytes.fromhex("b8 05 00 00 00 c3")
JOURNAL_BYTES = (bytes.fromhex("48 8b 07 48 89 05")
                 + struct.pack("<i", 0x404008 - (0x401220 + 10))
                 + bytes.fromhex("48 83 05")
                 + struct.pack("<i", 0x404000 - (0x401220 + 18))
                 + bytes.fromhex("01 c3"))
LOADS = [(0x400000, PAGE, 4), (0x401000, PAGE, 5),
         (0x403000, PAGE, 6), (0x404000, PAGE, 6),
         (0x406000, 16 * PAGE, 6)]


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def read_bounded(path, limit):
    with path.open("rb") as stream:
        assert stat.S_ISREG(os.fstat(stream.fileno()).st_mode), "regular input required"
        raw = stream.read(limit + 1)
    assert 0 < len(raw) <= limit, "input byte bound"
    return raw


def target_record(raw):
    text = raw.decode("ascii")
    assert text.endswith("\n") and text.count("\n") == 1, "one target record required"
    fields = text[:-1].split(" ")
    assert fields[:2] == ["target", "xsave64"] and 3 <= len(fields) <= 11
    assert all(fields) and all(re.fullmatch(r"[0-9]+(?::[0-9]+:[0-9]+)?", x)
                               for x in fields[2:])
    assert fields[2].isdigit()
    mask = int(fields[2])
    assert mask & 3 == 3 and mask & ~0x2e7 == 0, "preserved state envelope"
    avx512 = (1 << 5) | (1 << 6) | (1 << 7)
    assert mask & avx512 == 0 or mask & (avx512 | 4) == avx512 | 4
    seen, last, extents = 3, 2, []
    for token in fields[3:]:
        values = token.split(":")
        assert len(values) == 3
        feature, offset, size = map(int, values)
        assert feature > last and feature & (feature - 1) == 0 and feature & mask
        assert offset >= 576 and size > 0 and offset + size <= 0x7fffffc0
        assert all(offset >= end or start >= offset + size for start, end in extents)
        assert feature != 512 or size >= 8
        extents.append((offset, offset + size))
        seen |= feature
        last = feature
    assert seen == mask, "complete target component table"
    return text


def fixture(raw):
    assert len(raw) >= 64
    header = struct.unpack_from("<16sHHIQQQIHHHHHH", raw)
    ident, kind, machine, version, entry, phoff, shoff, flags, ehsize, phsize, phnum, shsize, shnum, shstr = header
    assert ident == b"\x7fELF" + bytes([2, 1, 1, 0, 0]) + bytes(7)
    assert (kind, machine, version, entry, flags, ehsize, phsize, phnum) == (2, 62, 1, 0x401000, 0, 64, 56, 7)
    assert phoff == 64 and phoff + phsize * phnum <= PAGE
    headers = [struct.unpack_from("<IIQQQQQQ", raw, phoff + i * phsize) for i in range(phnum)]
    assert [p[0] for p in headers] == [6, 1, 1, 1, 1, 1, 0x6474e551]
    ph = headers[0]
    assert ph[:7] == (6, 4, phoff, 0x400000 + phoff, 0x400000 + phoff, phnum * phsize, phnum * phsize)
    assert ph[7] == 8
    stack_policy = headers[-1]
    assert stack_policy[1] == 6 and stack_policy[3:7] == (0, 0, 0, 0)
    loads = headers[1:6]
    file_ranges = []
    for p, (va, size, permissions) in zip(loads, LOADS):
        _, perm, offset, address, physical, file_size, memory_size, alignment = p
        assert (address, physical, file_size, memory_size, perm, alignment) == (va, va, size, size, permissions, PAGE)
        assert offset % PAGE == address % PAGE and offset + size <= len(raw)
        assert all(offset >= end or start >= offset + size for start, end in file_ranges)
        file_ranges.append((offset, offset + size))
    assert loads[0][2] == 0

    def owned(address, size, permissions):
        matches = [p for p in loads if p[3] <= address and address + size <= p[3] + p[5]]
        assert len(matches) == 1 and matches[0][1] == permissions, "unique exact LOAD owner"
        offset = matches[0][2] + address - matches[0][3]
        return offset, raw[offset:offset + size]

    source_offset, source = owned(SUBJECT, 6, 5)
    assert source == SUBJECT_BYTES, "exact authored MOV5/RET body"
    assert owned(0x401080, 5, 5)[1] == b"\xe8" + struct.pack("<i", SUBJECT - 0x401085)
    assert owned(0x401090, 5, 5)[1] == b"\xe8" + struct.pack("<i", SUBJECT + 5 - 0x401095)
    assert owned(0x401200, 1, 5)[1] == b"\xc3"
    assert owned(0x401220, 19, 5)[1] == JOURNAL_BYTES, "exact authored journal stores"
    assert owned(0x401300, 13, 5)[1] == b"elf exec ok\n\0"
    assert owned(0x403000, PAGE, 6)[1] == bytes((i * 37 + 11) & 255 for i in range(PAGE))
    assert owned(0x404000, PAGE, 6)[1] == bytes(PAGE)
    assert owned(0x406000, 16 * PAGE, 6)[1] == bytes([0x5a]) * (16 * PAGE)
    assert all(not (p[3] < 0x406000 and 0x405000 < p[3] + p[6]) for p in loads), "stack guard stays unmapped"
    assert all(p[3] + p[6] <= 0x416000 for p in loads)
    assert CARRIER >= 0x416000 and IMAGE >= CARRIER + PAGE

    # Stripping may retain a section table. Only the unstripped companion has
    # SHT_SYMTAB; load ownership and selected byte checks do not depend on it.
    assert shnum <= 256 and shsize in (0, 64)
    assert (shnum == 0 and shoff == 0 and shstr == 0) or (shnum > 0 and shsize == 64 and shstr < shnum and shoff + shnum * shsize <= len(raw))
    sections = [struct.unpack_from("<IIQQQQIIQQ", raw, shoff + i * shsize) for i in range(shnum)]
    symtabs = [s for s in sections if s[1] == 2]
    assert len(symtabs) <= 1
    if symtabs:
        table = symtabs[0]
        assert table[9] == 24 and table[5] % 24 == 0 and table[4] + table[5] <= len(raw)
        assert table[6] < shnum
        strings = sections[table[6]]
        assert strings[1] == 3 and strings[4] + strings[5] <= len(raw)
        names = raw[strings[4]:strings[4] + strings[5]]
        wanted = {b"subject_value": (SUBJECT, 6), b"fixture_null_hook": (0x401200, 1),
                  b"fixture_journal_hook": (0x401220, 19)}
        observed = {}
        for offset in range(table[4], table[4] + table[5], 24):
            name, info, other, section, value, size = struct.unpack_from("<IBBHQQ", raw, offset)
            assert name < len(names)
            end = names.find(b"\0", name)
            assert end >= name
            key = names[name:end]
            if key in wanted:
                assert key not in observed and 0 < section < shnum
                assert info & 15 == 2
                observed[key] = (value, size)
        assert observed == wanted, "unstripped source/hook symbols"
    return source_offset, owned


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("original", type=Path)
    parser.add_argument("target_record", type=Path)
    parser.add_argument("hook", choices=("null", "journal"))
    parser.add_argument("new_selection", type=Path)
    args = parser.parse_args()
    original = read_bounded(args.original, LIMIT)
    target = read_bounded(args.target_record, PAGE)
    target_line = target_record(target)
    offset, owned = fixture(original)
    hook_id, hook_pc, hook_len = (2, 0x401200, 1) if args.hook == "null" else (3, 0x401220, 19)
    hook_bytes = owned(hook_pc, hook_len, 5)[1]
    original_hash = digest(original)
    provenance = digest(("ELF-exec authored MOV5/RET entry declaration v1\n"
                         + original_hash + "\n0x401100 0x401105\n").encode())
    selection = ("LI2TOOL 1\noriginal " + original_hash + "\n" + target_line
        + "domain 1\ncarrier 0x418000\n"
        + "limits 1048576 1 1 4096 2 1048576 32768 64 1048576\n"
        + f"hook {hook_id} {hook_pc} {hook_len} {digest(hook_bytes)}\n"
        + f"site 1 {SUBJECT} 5 {offset} {SUBJECT} 6 {SUBJECT} 6 {SUBJECT} 6 {hook_id} observe original-decode\n"
        + f"entries 1 complete {provenance} {SUBJECT}:0 {SUBJECT + 5}:0\n"
        + "resumes 1 none\nsearch 1 B1 0 5 1 none 0 0\n"
        + "allocation 1 selected 0x420000 1 4096 0x420000:4096\n"
        + "allocation 1 victim none 0 4096 0x420000:4096\n").encode()
    assert read_bounded(args.original, LIMIT) == original and read_bounded(args.target_record, PAGE) == target, "inputs changed"
    # All validation precedes exclusive output creation; no compiler or child.
    fd = os.open(args.new_selection, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as output:
        output.write(selection)
        output.flush()
        os.fsync(output.fileno())
    print(f"selection prepared: sites=1 heads=2 hook={args.hook} qualification_complete=false")


if __name__ == "__main__":
    main()
