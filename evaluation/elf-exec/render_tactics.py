#!/usr/bin/env python3
"""Render a forced selection for one authored B2/T1/T2/T3 exec fixture."""
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
ENTRY = 0x401000
SUBJECT = 0x421100
CARRIER = 0x422000
SENTINEL = 0x1122334400000011
LOADS = [(0x400000, PAGE, 4), (ENTRY, PAGE, 5),
         (0x403000, PAGE, 6), (0x404000, PAGE, 6),
         (0x406000, 16 * PAGE, 6), (0x421000, PAGE, 5)]
FAMILIES = {
    "B2": (2, (0, 3, 8), "0f1f00b82a000000c3", 9, 3,
           (42, 42, SENTINEL)),
    "T1": (3, (0, 2, 7), "89c0b82a000000c3", 8, 2,
           (42, 42, SENTINEL)),
    "T2": (4, (0, 3, 11, 16, 64, 74), "0f1f000f1f840000000000b82a000000c3", 17, 3,
           (42, 42, 42, SENTINEL, 42, SENTINEL)),
    "T3": (5, (0, 2, 3, 64, 74), "750190c3", 2, 2,
           (SENTINEL, SENTINEL, SENTINEL, 42, SENTINEL)),
}


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


def subject_bytes(tactic):
    body = bytes.fromhex(FAMILIES[tactic][2])
    if tactic in ("T2", "T3"):
        body += bytes([0x90]) * (64 - len(body))
        body += b"\x48\xb8" + struct.pack("<Q", 42) + b"\xc3"
    return body


def placements(tactic):
    selected = {"B2": SUBJECT + 5 + 0x2ab80000 + 0x8000,
                "T1": SUBJECT + 6 + 0x2ab8,
                "T2": SUBJECT + 5 + 0x56e90000 + 0x8000,
                "T3": SUBJECT + 0x4000000}[tactic]
    victim = SUBJECT + 8 + 0x00123456 if tactic == "T2" else SUBJECT + 0x6000000
    return selected, victim


def startup_page(tactic):
    """Exact authored instruction/data bytes, not an assembler or CFG inference."""
    number, heads, _, _, _, returns = FAMILIES[tactic]
    page = bytearray([0xcc] * PAGE)
    occupied = set()

    def region(offset, parts):
        encoded = bytearray()
        for part in parts:
            if isinstance(part, tuple):
                opcode, target, tail = part
                delta = target - (ENTRY + offset + len(encoded) + len(opcode) + 4 + len(tail))
                encoded += opcode + struct.pack("<i", delta) + tail
            else:
                encoded += part
        assert 0 <= offset < offset + len(encoded) <= PAGE
        positions = set(range(offset, offset + len(encoded)))
        assert not occupied & positions, "authored regions overlap"
        occupied.update(positions)
        page[offset:offset + len(encoded)] = encoded

    def hx(value):
        return bytes.fromhex(value)

    def jump(destination):
        return b"\xe9", ENTRY + destination, b""

    def branch(op, destination):
        return bytes([0x0f, op]), ENTRY + destination, b""

    region(0, [hx("48833c2401"), branch(0x84, 0x50), hx("48833c2402"),
               branch(0x85, 0x5d0), hx("488b7c2410"), hx("807f0100"),
               branch(0x85, 0x5d0), hx("440fb627"), hx("4183ec30"),
               hx("4183fc") + bytes([len(heads)]), branch(0x83, 0x5d0),
               hx("41be01000000"), hx("4531ed"), jump(0x80)])
    region(0x50, [hx("4531f6"), hx("4531e4"), hx("4531ed"), jump(0x80)])
    region(0x80, [(hx("488d25"), 0x415f00, b""), (hx("488d35"), 0x403200, b""),
                  b"\x48\xb8" + struct.pack("<Q", SENTINEL),
                  (hx("4c8d3d"), ENTRY + 0x390, b""), hx("4f8b3ce7"),
                  hx("4983fd01"), hx("41ffe7")])
    region(0x200, [b"\xc3"])
    region(0x220, [hx("488b07"), (hx("488905"), 0x404008, b""),
                   (hx("488305"), 0x404000, b"\x01"), b"\xc3"])
    region(0x300, [b"elf tactics ok\n\0"])
    region(0x340, [b"LI2TACT1" + struct.pack("<8Q", number, len(heads),
                  *(heads + (0,) * (6 - len(heads))))])
    calls = tuple(ENTRY + 0x400 + 16 * i for i in range(len(heads)))
    region(0x390, [struct.pack("<6Q", *(calls + (0,) * (6 - len(heads))))])
    region(0x3c0, [struct.pack("<6Q", *(returns + (0,) * (6 - len(heads))))])
    for i, head in enumerate(heads):
        region(0x400 + i * 16, [(b"\xe8", SUBJECT + head, b""), jump(0x500)])
    region(0x500, [(hx("4c8d3d"), ENTRY + 0x3c0, b""), hx("4b3b04e7"),
                   branch(0x85, 0x5d0), hx("4585f6"), branch(0x85, 0x580),
                   hx("41ffc4"), hx("4183fc") + bytes([len(heads)]),
                   branch(0x82, 0x80), hx("4531e4"), hx("41ffc5"), hx("4183fd02"),
                   branch(0x82, 0x80), jump(0x580)])
    region(0x580, [hx("b801000000"), hx("bf01000000"),
                   (hx("488d35"), ENTRY + 0x300, b""), hx("ba0f000000"),
                   hx("0f05"), hx("4883f80f"), branch(0x85, 0x5d0),
                   hx("31ff"), hx("b83c000000"), hx("0f05"), hx("0f0b")])
    region(0x5d0, [hx("bf09000000"), hx("b83c000000"), hx("0f05"), hx("0f0b")])
    return bytes(page)


def fixture(raw, tactic):
    assert len(raw) >= 64
    header = struct.unpack_from("<16sHHIQQQIHHHHHH", raw)
    ident, kind, machine, version, entry, phoff, shoff, flags, ehsize, phsize, phnum, shsize, shnum, shstr = header
    assert ident == b"\x7fELF" + bytes([2, 1, 1, 0, 0]) + bytes(7)
    assert (kind, machine, version, entry, flags, ehsize, phsize, phnum) == (2, 62, 1, ENTRY, 0, 64, 56, 8)
    assert phoff == 64 and phoff + phsize * phnum <= PAGE
    headers = [struct.unpack_from("<IIQQQQQQ", raw, phoff + i * phsize) for i in range(phnum)]
    assert [p[0] for p in headers] == [6, 1, 1, 1, 1, 1, 1, 0x6474e551]
    ph = headers[0]
    assert ph[:7] == (6, 4, phoff, 0x400000 + phoff, 0x400000 + phoff, phnum * phsize, phnum * phsize)
    assert ph[7] == 8
    stack_policy = headers[-1]
    assert stack_policy[1] == 6 and stack_policy[3:7] == (0, 0, 0, 0)
    loads = headers[1:7]
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

    body = subject_bytes(tactic)
    assert owned(ENTRY, PAGE, 5)[1] == startup_page(tactic), "complete authored startup, CALL, hook, tables and output bytes"
    source_page = bytes([0xcc]) * 0xf0 + bytes([0x90]) * 16 + body
    source_page += bytes([0xcc]) * (PAGE - len(source_page))
    assert owned(0x421000, PAGE, 5)[1] == source_page, "complete authored subject RX page"
    assert owned(0x403000, PAGE, 6)[1] == bytes((i * 37 + 11) & 255 for i in range(PAGE))
    assert owned(0x404000, PAGE, 6)[1] == bytes(PAGE)
    assert owned(0x406000, 16 * PAGE, 6)[1] == bytes([0x5a]) * (16 * PAGE)
    assert all(not (p[3] < 0x406000 and 0x405000 < p[3] + p[6]) for p in loads), "stack guard stays unmapped"
    selected, victim = placements(tactic)
    original_ranges = [(p[3], p[3] + p[6]) for p in loads]
    new_ranges = [(CARRIER, CARRIER + PAGE), (selected & ~4095, (selected & ~4095) + 8192)]
    if tactic in ("T2", "T3"):
        new_ranges.append((victim & ~4095, (victim & ~4095) + 8192))
    for i, (start, end) in enumerate(new_ranges):
        assert all(start >= high or low >= end for low, high in original_ranges + new_ranges[:i]), "whole future LOAD permits must be disjoint"

    # The stripped companion may retain section headers. Its LOADs and entry
    # ownership are authenticated above without relying on symbol presence.
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
        wanted = {b"subject_value": (SUBJECT, len(body)), b"fixture_null_hook": (0x401200, 1),
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
    return owned(SUBJECT, FAMILIES[tactic][4], 5)[0], owned


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("original", type=Path)
    parser.add_argument("target_record", type=Path)
    parser.add_argument("tactic", choices=tuple(FAMILIES))
    parser.add_argument("hook", choices=("null", "journal"))
    parser.add_argument("new_selection", type=Path)
    args = parser.parse_args()
    original = read_bounded(args.original, LIMIT)
    target = read_bounded(args.target_record, PAGE)
    target_line = target_record(target)
    offset, owned = fixture(original, args.tactic)
    _, heads, _, block_length, selected_length, _ = FAMILIES[args.tactic]
    body_length = len(subject_bytes(args.tactic))
    selected, victim = placements(args.tactic)
    hook_id, hook_pc, hook_length = (2, 0x401200, 1) if args.hook == "null" else (3, 0x401220, 19)
    original_hash = digest(original)
    head_text = " ".join(f"{SUBJECT + h}:0" for h in heads)
    provenance = digest(("ELF-exec authored tactic entry declaration v1\n" + args.tactic
                         + "\n" + original_hash + "\n" + head_text + "\n").encode())
    selection = ("LI2TOOL 1\noriginal " + original_hash + "\n" + target_line
        + f"domain 1\ncarrier {CARRIER}\n"
        + "limits 1048576 16 16 65536 64 1048576 262144 64 4294967296\n"
        + f"hook {hook_id} {hook_pc} {hook_length} {digest(owned(hook_pc, hook_length, 5)[1])}\n"
        + f"site 1 {SUBJECT} {selected_length} {offset} {SUBJECT - 16} {body_length + 16} {SUBJECT} {body_length} {SUBJECT} {block_length} {hook_id} observe original-decode\n"
        + f"entries 1 complete {provenance} {head_text}\nresumes 1 none\n"
        + f"search 1 {args.tactic} 0 80 1 {SUBJECT + 64} 64 256\n"
        + f"allocation 1 selected {selected} 256 8192 {selected & ~4095}:8192\n"
        + f"allocation 1 victim {victim} 256 8192 {victim & ~4095}:8192\n").encode()
    assert read_bounded(args.original, LIMIT) == original and read_bounded(args.target_record, PAGE) == target, "inputs changed"
    parent = args.new_selection.parent
    assert parent.is_dir() and parent.resolve(strict=True) == parent.absolute(), "canonical nonsymlink output parent required"
    assert not args.new_selection.exists() and not args.new_selection.is_symlink(), "fresh output required"
    # All validation precedes exclusive output creation. No child or candidate.
    fd = os.open(args.new_selection, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as output:
        output.write(selection)
        output.flush()
        os.fsync(output.fileno())
    print(f"selection prepared: sites=1 heads={len(heads)} tactic={args.tactic} hook={args.hook} qualification_complete=false")


if __name__ == "__main__":
    main()
