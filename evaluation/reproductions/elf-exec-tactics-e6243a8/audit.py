#!/usr/bin/env python3
"""Offline, finite audit of a closed four-family tactic capture tree.

No subject/compiler/helper is run; only saved files and Git blobs are read.
The old B1 audit is separate. This audit never refreshes a saved identity.
"""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import struct
import subprocess
import sys

REPO = None
EXPECTED_REVISION = "e6243a862fda2572304cccbcfe698ac9ea6212a6"
FIXTURE_SHA256 = "622db2cca51521b2e088e0003a28c164175fd249e03c0f72d2b6f65bc2f84aec"
PINS_SHA256 = "2c6d667264f9ae1822397e4ea85740989101f0f44424beba88c9858438f24cab"
READS = {}
U64 = (1 << 64) - 1
DEBUGGER_FLAGS = (1 << 8) | (1 << 16)
ENTRY, SUBJECT, CARRIER = 0x401000, 0x421100, 0x422000
DATA, JOURNAL, STACK, STACK_END, RSP = 0x403000, 0x404000, 0x406000, 0x416000, 0x415f00
SEEDS = (0x1234567887654320, 0xfedcba9801234567)
FLAGS = (0xa97, 0xed7)
ORIGINAL_LOADS = ((0x400000,4096,4),(ENTRY,4096,5),(DATA,4096,6),
                  (JOURNAL,4096,6),(STACK,65536,6),(SUBJECT & ~4095,4096,5))
RUNTIME_ENV = dict(LC_ALL="C", PATH="/usr/bin:/bin", PYTHONDONTWRITEBYTECODE="1")
RECEIPT_KEYS = {"request_sha256", "helper_sha256", "exit", "wall_timeout", "unexpected_descendants",
                "absence_proof", "stdout_sha256", "stderr_sha256", "elapsed_seconds", "cleanup_events",
                "cleanup_error", "aborted", "inputs_unchanged"}
SUFFIXES = ("regs", "xstate", "data", "stack")
FIXED_TRACE = {"exec.maps", "exec.map-files", "exec.auxv", "terminal.maps", "terminal.map-files",
               "terminal.auxv", "startup-pcs.bin", "before-seed.tsv", "journal.bin", "transfers.tsv", "complete.tsv"}
HOOK_FILES = {"hook-call.tsv", "hook-ret.tsv", "hook-context.bin", "hook-saved-xstate.bin"}
COPY_NAMES = ("original-unstripped", "original-stripped", "candidate-0", "candidate-1", "candidate-2", "candidate-3")

def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def read(path):
    path = Path(path)
    before = path.lstat()
    assert stat.S_ISREG(before.st_mode), str(path)
    assert 0 <= before.st_size <= 128 * 1024 * 1024
    value = path.read_bytes()
    after = path.lstat()
    fields = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    assert fields(before) == fields(after) and len(value) == before.st_size
    key, digest = str(path.absolute()), sha(value)
    assert key not in READS or READS[key] == digest, key
    READS[key] = digest
    return value


def js(path):
    return json.loads(read(path))


def finite(value):
    assert type(value) in (int, float) and math.isfinite(value) and value >= 0


def tsv(path):
    rows = [line.split("\t") for line in read(path).decode().splitlines()]
    assert all(len(row) == 2 for row in rows) and len({row[0] for row in rows}) == len(rows)
    return dict(rows)


def unsigned(value):
    assert re.fullmatch(rb"[0-9]{1,20}", value)
    result = int(value)
    assert result <= (1 << 64) - 1
    return result


def provider_record(path, executable):
    value, cursor = read(path), 0

    def line():
        nonlocal cursor
        end = value.index(b"\n", cursor)
        result = value[cursor:end]
        cursor = end + 1
        return result

    def field(name):
        parts = line().split(b"\t")
        assert len(parts) == 2 and parts[0] == name
        return unsigned(parts[1])

    assert line() == b"elf-exec-provider-v1"
    device, inode, size = field(b"stat_dev"), field(b"stat_inode"), field(b"stat_bytes")
    length = field(b"fdinfo_bytes")
    assert 0 < length <= 4096 and cursor + length <= len(value)
    fdinfo = value[cursor:cursor + length]
    cursor += length
    assert fdinfo.endswith(b"\n")
    length = field(b"mount_record_bytes")
    assert 0 < length <= 1024 * 1024 and cursor + length == len(value)
    mount = value[cursor:cursor + length]
    assert mount.endswith(b"\n") and mount.count(b"\n") == 1
    fields = mount.split()
    assert len(fields) >= 10
    separator = fields.index(b"-")
    assert separator >= 6 and separator + 4 == len(fields)
    assert unsigned(fields[1]) > 0 and fields[3].startswith(b"/") and fields[4].startswith(b"/")

    def fd_field(name):
        found = [row[len(name):].strip() for row in fdinfo.splitlines() if row.startswith(name)]
        assert len(found) == 1
        return unsigned(found[0])

    mount_id = fd_field(b"mnt_id:")
    assert mount_id > 0 and unsigned(fields[0]) == mount_id
    assert inode > 0 and fd_field(b"ino:") == inode
    pair = fields[2].split(b":")
    assert len(pair) == 2
    mapping_device = tuple(unsigned(part) for part in pair)
    owner = executable.lstat()
    assert stat.S_ISREG(owner.st_mode)
    assert (owner.st_dev, owner.st_ino, owner.st_size) == (device, inode, size)
    return dict(stat_device=device, inode=inode, bytes=size, mount_id=mount_id,
                mapping_device=mapping_device, record_sha256=sha(value), mount_record_sha256=sha(mount))


def map_file_records(path, maps, executable, provider):
    value = read(path)
    prefix = b"elf-exec-map-files-v1\n"
    assert value.startswith(prefix)
    cursor, count = len(prefix), 0
    expected_path = os.fsencode(str(executable.resolve(strict=True)))
    for row in maps.splitlines():
        fields = row.split(None, 5)
        assert len(fields) >= 5
        inode = unsigned(fields[4])
        if inode == 0:
            continue
        assert re.fullmatch(rb"[0-9a-f]+-[0-9a-f]+", fields[0])
        start, end = (int(part, 16) for part in fields[0].split(b"-"))
        assert start < end
        pair = fields[3].split(b":")
        assert len(pair) == 2 and all(re.fullmatch(rb"[0-9a-f]+", part) for part in pair)
        assert tuple(int(part, 16) for part in pair) == provider["mapping_device"]
        assert inode == provider["inode"]
        end = value.index(b"\n", cursor)
        recorded = value[cursor:end].split(b"\t")
        assert len(recorded) == 2 and recorded[0] == fields[0]
        length = unsigned(recorded[1])
        cursor = end + 1
        assert cursor + length < len(value)
        assert value[cursor:cursor + length] == expected_path
        cursor += length
        assert value[cursor:cursor + 1] == b"\n"
        cursor += 1
        count += 1
    assert count > 0 and cursor == len(value)
    return count


def git_source(revision):
    assert re.fullmatch("[0-9a-f]{40}", revision)
    prefix = ["/usr/bin/git", "-C", str(REPO)]
    tree = subprocess.check_output(prefix + ["ls-tree", "-rz", revision], timeout=20)
    records = []
    for row in tree.split(b"\0")[:-1]:
        meta, name = row.split(b"\t", 1)
        mode, kind, oid = meta.split()
        assert mode in (b"100644", b"100755") and kind == b"blob"
        records.append((name.decode(), oid.decode()))
    batch = subprocess.check_output(prefix + ["cat-file", "--batch"],
                                    input="".join(oid + "\n" for _, oid in records).encode(), timeout=30)
    at, result = 0, {}
    for name, oid in records:
        end = batch.index(b"\n", at)
        actual, kind, size = batch[at:end].split()
        assert actual.decode() == oid and kind == b"blob"
        size = int(size)
        at = end + 1
        result[name] = sha(batch[at:at + size])
        at += size
        assert batch[at:at + 1] == b"\n"
        at += 1
    assert at == len(batch)
    return result


def exact_tsv(path, pairs):
    assert read(path) == "".join(f"{k}\t{v}\n" for k, v in pairs).encode(), str(path)


def word(raw, at=0):
    assert 0 <= at and at + 8 <= len(raw)
    return struct.unpack_from("<Q", raw, at)[0]


def transfer(opcode, pc, target):
    return bytes([opcode]) + struct.pack("<i", target - pc - 5)


def logical_path(f, head, seed):
    return [SUBJECT + n for n in f["paths"][str(f["heads"][head])][f"ZF{seed}"]] + [0x401405 + 16 * head]


def target_layout(path):
    rows = [r.split("\t") for r in read(path).decode().splitlines()]
    assert rows[:7] == [["LI2TARGET", "1"], ["os", "linux"], ["isa", "x86-64-legacy-evex"],
                        ["cet", "unqualified"], ["page_bytes", "4096"], ["bias_domain", "1"],
                        ["format", "xsave64-standard"]]
    assert [r[0] for r in rows[7:11]] == ["allocation_bytes", "image_bytes", "xcr0_mask", "qualification_complete"]
    assert all(len(r) == 2 for r in rows[:11]) and rows[10][1] == "false"
    allocation, extent, mask = [int(r[1]) for r in rows[7:10]]
    assert 576 <= extent <= allocation <= 32768 and allocation == (extent + 63) & ~63
    assert mask & 3 == 3 and mask < 1 << 64
    components, bits, intervals = [], 3, []
    for row in rows[11:]:
        assert len(row) == 4 and row[0] == "component"
        feature, start, size = map(int, row[1:])
        assert feature >= 4 and feature & (feature - 1) == 0 and feature & mask and not feature & bits
        assert 576 <= start < start + size <= extent
        assert all(start + size <= a or b <= start for a, b in intervals)
        components.append((feature.bit_length() - 1, start, size))
        intervals.append((start, start + size)); bits |= feature
    assert bits == mask and components == sorted(components)
    assert extent == max([576] + [b for _, b in intervals])
    return allocation, extent, mask, components


class Elf:
    def __init__(self, path, f, candidate):
        self.path, self.raw = path, read(path)
        b = self.raw
        assert 64 <= len(b) <= 1024 * 1024
        assert b[:16] == b"\x7fELF" + bytes([2, 1, 1, 0, 0]) + bytes(7)
        assert struct.unpack_from("<HHIQ", b, 16) == (2, 62, 1, ENTRY)
        assert struct.unpack_from("<HH", b, 52) == (64, 56)
        self.phoff, self.phnum = word(b, 32), struct.unpack_from("<H", b, 56)[0]
        assert self.phnum == (9 + f["expected_image_count"] if candidate else 8)
        assert self.phoff + self.phnum * 56 <= len(b)
        headers = [struct.unpack_from("<IIQQQQQQ", b, self.phoff + i * 56) for i in range(self.phnum)]
        self.loads = sorted([p for p in headers if p[0] == 1], key=lambda p: p[3])
        assert len(self.loads) == (7 + f["expected_image_count"] if candidate else 6)
        assert all(p[0] in (1, 6, 0x6474e551) for p in headers)
        phdr = [p for p in headers if p[0] == 6]
        stack = [p for p in headers if p[0] == 0x6474e551]
        assert len(phdr) == len(stack) == 1 and stack[0][1] == 6
        assert phdr[0][1:3] == (4, self.phoff) and phdr[0][5:7] == (self.phnum * 56,) * 2
        self.phdr_address = phdr[0][3]
        assert sum(p[1] == 4 and p[3] <= self.phdr_address and self.phdr_address + self.phnum * 56 <= p[3] + p[5]
                   and p[2] + self.phdr_address - p[3] == self.phoff for p in self.loads) == 1
        for triple in ORIGINAL_LOADS:
            assert sum((p[3], p[5], p[1]) == triple for p in self.loads) == 1
        allowed = {a: (size, flags) for a, size, flags in ORIGINAL_LOADS}
        if candidate:
            allowed[CARRIER] = (self.phnum * 56 + len(b"LI2TOOL-CANDIDATE-UNREADY-V1\0") + 64, 4)
            allowed[f["selected_address"] & ~4095] = (None, 5)
            if f["expected_image_count"] == 2:
                allowed[f["victim_address"] & ~4095] = (None, 5)
        assert set(p[3] for p in self.loads) == set(allowed)
        self.pages = {}
        for p in self.loads:
            assert p[3] == p[4] and p[2] % 4096 == p[3] % 4096 == 0 and p[7] == 4096
            assert 0 < p[5] == p[6] and p[2] + p[5] <= len(b)
            size, flags = allowed[p[3]]
            assert p[1] == flags and (p[5] == size if size is not None else p[5] <= 8192)
            for address in range(p[3], (p[3] + p[5] + 4095) & ~4095, 4096):
                assert address not in self.pages
                offset = p[2] + address - p[3]
                self.pages[address] = (offset, flags, b[offset:offset + 4096].ljust(4096, b"\0"))
        assert 21 <= len(self.pages) <= 26
        if not candidate:
            assert len(self.pages) == 21
            assert sha(self.slice(ENTRY, 4096)) == f["startup_page_sha256"]
            assert sha(self.slice(SUBJECT & ~4095, 4096)) == f["subject_page_sha256"]
            assert self.slice(DATA, 4096) == bytes((i * 37 + 11) & 255 for i in range(4096))
            assert self.slice(JOURNAL, 4096) == bytes(4096) and self.slice(STACK, 65536) == b"\x5a" * 65536
        else:
            marker = b"LI2TOOL-CANDIDATE-UNREADY-V1\0"
            assert self.slice(CARRIER + self.phnum * 56, len(marker)) == marker

    def slice(self, address, length):
        owners = [p for p in self.loads if p[3] <= address and address + length <= p[3] + p[5]]
        assert len(owners) == 1
        at = owners[0][2] + address - owners[0][3]
        return self.raw[at:at + length]

    def mappings(self, directory, phase, provider):
        text = read(directory / (phase + ".maps"))
        assert len(text) <= 65536
        map_file_records(directory / (phase + ".map-files"), text, self.path, provider)
        rows = []
        for line in text.splitlines():
            fields = line.split(None, 5)
            assert len(fields) >= 5
            start, end = (int(v, 16) for v in fields[0].split(b"-"))
            assert start < end and (end <= 0x405000 or start >= STACK)
            rows.append((start, end, fields[1], int(fields[2], 16),
                         tuple(int(v, 16) for v in fields[3].split(b":")), int(fields[4])))
        assert all(a[1] <= b[0] for a, b in zip(rows, rows[1:]))
        for address, (offset, flags, _) in self.pages.items():
            owners = [r for r in rows if r[0] <= address and address + 4096 <= r[1]]
            assert len(owners) == 1
            r = owners[0]
            assert r[2] == {4: b"r--p", 5: b"r-xp", 6: b"rw-p"}[flags]
            assert r[3] + address - r[0] == offset
            assert (r[4], r[5]) == (provider["mapping_device"], provider["inode"])
        aux = read(directory / (phase + ".auxv"))
        assert 0 < len(aux) <= 8192 and len(aux) % 16 == 0
        pairs = list(struct.iter_unpack("<QQ", aux))
        for key, value in ((3, self.phdr_address), (4, 56), (5, self.phnum), (9, ENTRY), (7, 0)):
            assert [v for k, v in pairs if k == key] == [value]


def authenticate_candidate(directory, original, selection, f):
    names = {"COMPLETE", "bundle-index.tsv", "candidate.elf", "image-0000.bin", "ledger.tsv", "metadata.li2meta",
             "plan-ledger.tsv", "report.tsv", "selection.txt", "site-1.diagnostics.txt", "source.li2sparse", "target.tsv"}
    if f["expected_image_count"] == 2:
        names.add("image-0001.bin")
    assert set(p.name for p in directory.iterdir()) == names
    contents = {n: read(directory / n) for n in sorted(names)}
    assert all(len(b) <= 1024 * 1024 for b in contents.values())
    assert all(stat.S_IMODE((directory / n).lstat().st_mode) == 0o600 for n in names)
    assert contents["COMPLETE"] == ("LI2TOOL-DIRECTORY 1\nindex_sha256 " + sha(contents["bundle-index.tsv"])
              + "\ncandidate_complete true\nqualification_complete false\n").encode()
    expected = ["LI2BUNDLE\t1", "original_sha256\t" + sha(original.raw), "qualification_complete\tfalse",
                "consumer_action\tRuntimeScan-while-gated-until-qualified"]
    expected += [f"file\t{n}\t{len(contents[n])}\t{sha(contents[n])}" for n in sorted(names - {"COMPLETE", "bundle-index.tsv"})]
    assert contents["bundle-index.tsv"] == ("\n".join(expected) + "\n").encode()
    assert contents["selection.txt"] == read(selection)
    return {n: sha(b) for n, b in contents.items()}


def candidate_routes(directory, elf, f, hook_index):
    text = read(directory / "plan-ledger.tsv")
    assert len(text) <= 65536 and text.startswith(b"LI2LEDGER\t1\n")
    rows = [r.split("\t") for r in text.decode().splitlines()]
    def one(kind):
        found = [r for r in rows if r[0] == kind]
        assert len(found) == 1
        return found[0]
    assert one("qualification_complete") == ["qualification_complete", "false"]
    assert one("execution_authority") == ["execution_authority", "none"]
    images = [r for r in rows if r[0] == "image"]
    assert len(images) == f["expected_image_count"]
    wanted = {f["selected_address"]: SUBJECT}
    if f["expected_image_count"] == 2:
        wanted[f["victim_address"]] = SUBJECT + f["actual_victim_head"]
    restored, addresses, image_by_id = {}, set(), {}
    for i, row in enumerate(images):
        assert len(row) == 7 and row[1:3] == [str(i), "1"] and row[6] == f"image-{i:04}.bin"
        address, length = int(row[3]), int(row[4])
        assert address in wanted and address not in addresses
        addresses.add(address)
        body = read(directory / row[6])
        assert len(body) == length > 0 and address + length <= (address & ~4095) + 8192
        assert elf.slice(address, length) == body
        assert [(p[1], p[5]) for p in elf.loads if p[3] == address & ~4095] == [(5, address % 4096 + length)]
        logical = wanted[address]
        assert [r for r in rows if r[:2] == ["route", str(i)]] == [["route", str(i), str(logical), str(address)]]
        boundaries = [r for r in rows if r[:2] == ["restored-boundary", str(i)]]
        assert len(boundaries) == 1 and len(boundaries[0]) == 4 and int(boundaries[0][2]) == logical
        generated = int(boundaries[0][3])
        assert address <= generated < address + length and logical not in restored
        ranges = [r for r in rows if r[:2] == ["pc-range", str(i)]]
        assert ranges and all(len(r) == 5 for r in ranges)
        parsed = [tuple(map(int, r[2:])) for r in ranges]
        assert all(address <= a < b <= address + length and pc - SUBJECT in f["heads"] for a, b, pc in parsed)
        assert all(a[1] <= b[0] for a, b in zip(parsed, parsed[1:]))
        assert sum(a <= generated < b and pc == logical for a, b, pc in parsed) == 1
        restored[logical] = generated
        image_by_id[i] = (address, body)
    assert addresses == set(wanted)
    hook = 0x401200 if hook_index == 0 else 0x401220
    h = one("hook")
    assert h[:4] == ["hook", str(2 + hook_index), str(hook), str(1 if hook_index == 0 else 19)] and len(h) == 5
    assert h[4] == sha(elf.slice(hook, 1 if hook_index == 0 else 19))
    fields = [r for r in rows if r[0] == "field"]
    calls = [r for r in fields if bytes.fromhex(r[8]) == b"HookCall"]
    assert len(calls) == 1 and len(calls[0]) == 10
    c = calls[0]; address, body = image_by_id[int(c[1])]
    at, width, origin, target = int(c[2]), int(c[3]), int(c[5]), int(c[6])
    assert address == f["selected_address"] and c[4] == "Relative" and width == 4 and origin == at + 4
    assert c[7] == "1" and target == hook and bytes.fromhex(c[9]) == body[at:at + 4]
    ret = address + origin
    assert body[at - 1:at + 4] == transfer(0xe8, ret - 5, hook)
    return restored, hook, ret


def canonical_parts(value):
    # The source GETREGSET buffer is 64 KiB; canonicalization replaces its
    # legacy/header area with 363 bytes and at most 62 component descriptors.
    assert 363 <= len(value) <= 363 + 65536 - 576 + 62 * 12
    at, parts, previous = 363, {}, 1
    while at < len(value):
        assert at + 12 <= len(value)
        bit, size = struct.unpack_from("<IQ", value, at); at += 12
        assert previous < bit < 64 and 0 < size <= 65536 and at + size <= len(value)
        parts[bit] = value[at:at + size]; at += size; previous = bit
    assert at == len(value)
    return value[:363], parts


def state(directory, stem, pc, layout):
    values = [read(directory / (stem + "." + suffix)) for suffix in SUFFIXES]
    assert len(values[0]) == 216 and len(values[2]) == 4096 and len(values[3]) == 392
    regs = list(struct.unpack("<27Q", values[0])); assert regs[16] == pc
    _, parts = canonical_parts(values[1])
    # Every trace, including bypasses, must retain the recorded target state.
    # Extra NT_XSTATE components remain present and compare in full below.
    for bit, _, size in layout[3]:
        assert bit in parts and len(parts[bit]) == size
    return regs, values[1], values[2], values[3]


def same_state(expected, actual):
    # Same register normalization as the existing assert_state: logical RIP is
    # independently checked by state(); only debugger TF/RF bits are excluded.
    a, b = list(expected[0]), list(actual[0])
    a[16] = b[16] = 0
    a[18] &= U64 ^ DEBUGGER_FLAGS; b[18] &= U64 ^ DEBUGGER_FLAGS
    assert a == b and expected[1:] == actual[1:]


def check_seed(value, seed_index, call):
    r = value[0]; n = SEEDS[seed_index]
    for index in (10, 5, 11, 12, 4, 9, 8, 7, 6, 3, 2, 1, 0):
        n ^= n << 13 & U64; n ^= n >> 7; n ^= n << 17 & U64
        assert r[index] == n
    assert (r[13], r[14], r[15], r[16], r[19], r[21], r[22]) == (DATA + 512, DATA + 256, U64, call, RSP, 0, 0)
    assert r[18] & (U64 ^ DEBUGGER_FLAGS) == FLAGS[seed_index]
    assert value[2] == bytes((i * 37 + 11) & 255 for i in range(4096))
    assert value[3] == b"\x5a" * 392


def original_effects(tactic, points, path, head):
    count = 0
    for i, (old, new) in enumerate(zip(points, points[1:])):
        offset = path[i] - SUBJECT; r = old[0].copy()
        if tactic == "T1" and offset == 0:
            r[10] &= 0xffffffff
        elif (tactic, offset) in (("B2", 3), ("T1", 2), ("T2", 11), ("T2", 64), ("T3", 64)):
            r[10] = 42
        elif offset == ({"B2": 8, "T1": 7, "T2": 16, "T3": 3}[tactic]) or offset == 74:
            assert r[19] == RSP - 8 and path[i + 1] == 0x401405 + 16 * head
            r[19] += 8
        elif tactic == "T3" and offset == 0:
            assert path[i + 1] == SUBJECT + (2 if r[18] & 64 else 3)
        else:
            assert (tactic, offset) in (("B2", 0), ("T2", 0), ("T2", 3), ("T3", 2))
        r[16] = path[i + 1]
        same_state((r,) + old[1:], new); count += 1
    return count


def edges(tactic, f, head):
    rows = []
    if head == 0:
        if tactic == "T3":
            rows = [(SUBJECT, SUBJECT + 69, b"\xeb\x43"),
                    (SUBJECT + 69, f["selected_address"], transfer(0xe9, SUBJECT + 69, f["selected_address"]))]
        elif tactic == "T1":
            rows = [(SUBJECT, f["selected_address"], b"\x2e" + transfer(0xe9, SUBJECT + 1, f["selected_address"]))]
        else:
            rows = [(SUBJECT, f["selected_address"], transfer(0xe9, SUBJECT, f["selected_address"]))]
    if f["actual_victim_head"] is not None and (tactic == "T2" and head <= 1 or f["heads"][head] == f["actual_victim_head"]):
        pc = SUBJECT + f["actual_victim_head"]
        rows.append((pc, f["victim_address"], transfer(0xe9, pc, f["victim_address"])))
    return rows


def hook_witness(directory, baseline, hook, ret, layout):
    allocation, extent, mask, components = layout
    c = read(directory / "hook-context.bin"); image = read(directory / "hook-saved-xstate.bin")
    assert len(c) == 176 and len(image) == allocation
    r = baseline[0]
    expected = [SUBJECT, r[19]] + [r[i] for i in (0,1,2,3,6,7,8,9,14,13,4,5,12,11,10)]
    assert list(struct.unpack_from("<17Q", c)) == expected
    assert word(c,136) & (U64 ^ DEBUGGER_FLAGS) == r[18] & (U64 ^ DEBUGGER_FLAGS)
    assert (word(c,152),word(c,160),word(c,168)) == (allocation,mask,2)
    assert word(c,144) % 64 == 0 and STACK <= word(c,144) and word(c,144) + allocation <= RSP - 8 - 128
    call = tsv(directory / "hook-call.tsv")
    rsp = int(call["rsp"])
    exact_tsv(directory / "hook-call.tsv", (("pc",hook),("rsp",rsp),("return_word",ret)))
    exact_tsv(directory / "hook-ret.tsv", (("pc",hook + (18 if hook == 0x401220 else 0)),("return_pc",ret),("rsp_before",rsp)))
    assert STACK <= rsp and rsp + 8 <= RSP - 8 - 128 and rsp % 16 == 8
    # Reconstruct the existing architectural XSAVE view from recorded target
    # components, without CPUID of the audit host or a new mask. Allocation
    # padding remains fully retained; it is not architectural image state.
    raw = image[:extent]; assert len(raw) >= 576 and raw[520:528] == bytes(8)
    in_use = word(raw,512)
    x87 = raw[:24] if in_use & 1 else b"\x7f\x03" + bytes(22)
    base = x87[:5] + x87[6:24]
    base += b"".join(raw[32+16*i:42+16*i] if in_use & 1 else bytes(10) for i in range(8))
    base += raw[24:28] + (raw[160:416] if in_use & 2 else bytes(256))
    expected_base, expected_parts = canonical_parts(baseline[1])
    assert base == expected_base
    for bit, start, size in components:
        assert bit in expected_parts and len(expected_parts[bit]) == size
        assert (raw[start:start + size] if in_use & 1 << bit else bytes(size)) == expected_parts[bit]


def trace(directory, elf, provider, f, head, seed, variant, route, layout):
    path = logical_path(f, head, seed); call = 0x401400 + 16 * head
    startup = read(directory / "startup-pcs.bin")
    assert startup == b"".join(struct.pack("<Q", x) for x in f["native_arrival_heads"])
    before_seed = tsv(directory / "before-seed.tsv"); pid = int(before_seed["pid"])
    assert pid > 0
    exact_tsv(directory / "before-seed.tsv", (("entry",ENTRY),("call",call),("startup_steps",len(startup)//8),("pid",pid)))
    complete = tsv(directory / "complete.tsv"); steps = int(complete["steps"])
    assert len(startup)//8 < steps <= 20000
    exact_tsv(directory / "complete.tsv", (("status","passed"),("steps",steps),("terminal",call+5),("owned_tracee_killed_and_reaped","true")))
    for phase in ("exec", "terminal"):
        elf.mappings(directory, phase, provider)
    for address, (_, _, content) in elf.pages.items():
        assert read(directory / f"loaded-{address:x}.bin") == content
    before = state(directory, "before-call", call, layout); after = state(directory, "after-call", path[0], layout)
    check_seed(before, seed, call)
    assert elf.slice(call, 5) == transfer(0xe8, call, path[0])
    r = before[0].copy(); r[16] = path[0]; r[19] -= 8
    stack = bytearray(before[3]); stack[128:136] = struct.pack("<Q", call + 5)
    same_state((r, before[1], before[2], bytes(stack)), after)
    points = [state(directory, f"point-{i}", route.get(pc, pc), layout) for i, pc in enumerate(path)]
    assert points[-1][0][19] == RSP and points[-1][3][128:136] == struct.pack("<Q",call+5)
    ret_pc = route.get(path[-2], path[-2])
    assert elf.slice(ret_pc,1) == b"\xc3" and points[-2][0][19] == RSP-8
    assert points[-2][3][128:136] == struct.pack("<Q",call+5)
    expected_journal = bytearray(4096)
    if variant == "hook-1" and head == 0:
        expected_journal[:16] = struct.pack("<QQ",1,SUBJECT)
    assert read(directory / "journal.bin") == expected_journal
    return (before, after, points), steps


def commands(raw, fixture, source):
    results = js(raw / "results.json")
    assert len(results) == 93
    first = results[0]; environment = first["env"].copy()
    assert first["name"] == "codec-compile" and Path(first["cwd"]) == REPO
    cargo = first["argv"][0]; tool = Path(cargo).parent
    assert tool.is_absolute() and tool.name == "bin" and Path(cargo).name == "cargo"
    assert set(environment) == {"CARGO_BUILD_JOBS","CARGO_INCREMENTAL","CARGO_NET_OFFLINE","CARGO_TARGET_DIR",
        "CARGO_HOME","HOME","RUSTC","RUSTDOC","RUSTC_WORKSPACE_WRAPPER","RUSTC_WRAPPER","RUST_TEST_THREADS",
        "LC_ALL","PATH","PYTHONDONTWRITEBYTECODE","TMPDIR"}
    assert Path(environment["HOME"]).is_absolute() and Path(environment["CARGO_HOME"]).is_absolute()
    expected_env = dict(CARGO_BUILD_JOBS="4", CARGO_INCREMENTAL="0", CARGO_NET_OFFLINE="true",
        CARGO_TARGET_DIR=str(REPO / "target"), CARGO_HOME=environment["CARGO_HOME"], HOME=environment["HOME"],
        RUSTC=str(tool/"rustc"), RUSTDOC=str(tool/"rustdoc"), RUSTC_WORKSPACE_WRAPPER="", RUSTC_WRAPPER="",
        RUST_TEST_THREADS="4", LC_ALL="C", PATH=str(tool)+":/usr/bin:/bin", PYTHONDONTWRITEBYTECODE="1")
    assert environment == dict(expected_env, TMPDIR=str(raw/"codec-compile/tmp"))
    native = [r for r in results if r["name"] == "native-B2"]
    assert len(native) == 1
    driver = Path(native[0]["argv"][0]); b1 = driver.parent.parent
    assert driver == b1/"artifacts/elf-exec-oracle" and b1.is_absolute() and b1.resolve() == b1
    assert b1.is_relative_to(REPO/"ignored") and not b1.is_relative_to(raw) and not raw.is_relative_to(b1)
    prerequisite = js(raw/"b1-prerequisite-inputs.json")
    assert prerequisite == js(raw/"b1-prerequisite-inputs-after.json")
    for name, digest in prerequisite.items():
        p = Path(name)
        assert p.is_relative_to(b1) and p.resolve(strict=True) == p and sha(read(p)) == digest
    assert js(b1/"source.json") == js(b1/"source-after.json") == source
    assert str(driver) in prerequisite and str(b1/"artifacts/liteinst-rewrite") in prerequisite
    assert str(b1/"target/stdout.txt") in prerequisite
    assert str(b1/"captures/runtime-target.tsv") in prerequisite
    wanted = [("codec-compile", [cargo,"build","-p","liteinst-rewrite","--example","verify_elf_tactics",
        "--example","check_elf_tactic_refusals","--offline","--locked","--message-format=json"], None)]
    for tactic, f in fixture.items():
        subject = raw/"subjects"/tactic; original = subject/"original-unstripped"; stripped = subject/"original-stripped"
        wanted.extend([
            ("assemble-"+tactic,["/usr/bin/gcc","-c","-nostdlib","-fno-pie","-Wa,--fatal-warnings",
                "-Wa,--defsym,TACTIC="+str(f["assembler_TACTIC"]),str(REPO/"tests/fixtures/elf-exec-tactics/subject.S"),"-o",str(subject/"subject.o")],b""),
            ("link-"+tactic,["/usr/bin/ld","-m","elf_x86_64","-nostdlib","--build-id=none","-z","noexecstack","-T",
                str(REPO/"tests/fixtures/elf-exec-tactics/subject.ld"),str(subject/"subject.o"),"-o",str(original)],b""),
            ("strip-"+tactic,["/usr/bin/strip","--strip-all","-o",str(stripped),str(original)],b"")])
        candidates = []
        for strip in ("unstripped","stripped"):
            for hook in ("null","journal"):
                name = f"{tactic}-{strip}-{hook}"; selection = subject/f"{strip}-{hook}.selection"
                output = raw/(name+"-candidate"); candidates.append(str(output))
                wanted.extend([
                    ("select-"+name,["/usr/bin/python3.9","-B",str(REPO/"evaluation/elf-exec/render_tactics.py"),
                        str(subject/("original-"+strip)),str(b1/"target/stdout.txt"),tactic,hook,str(selection)],
                        f"selection prepared: sites=1 heads={len(f['heads'])} tactic={tactic} hook={hook} qualification_complete=false\n".encode()),
                    ("prepare-"+name,[str(b1/"artifacts/liteinst-rewrite"),"prepare",str(subject/("original-"+strip)),str(selection),str(output)],
                        b"candidate_complete=true qualification_complete=false sites=1\n"),
                    ("verify-"+name,[str(raw/"artifacts/verify_elf_tactics"),str(subject/("original-"+strip)),str(selection),tactic,str(output)],
                        f"elf tactics artifact verified: tactic={tactic} metadata=1 sparse_pages=1 images={f['expected_image_count']} qualification_complete=false\n".encode())])
        control_lines = [tactic+" unknown-entries Refused(7) no-artifact", tactic+" source-byte-tamper original-identity",
            tactic+" hook-byte-tamper-rebound-original hook-identity", tactic+" selected-placement-unavailable Refused(11) no-artifact"]
        if tactic in ("T2","T3"):
            control_lines.append(tactic+" one-image-budget Refused(11) no-artifact")
        control_lines.append(f"PASS adjacent tactic refusals: tactic={tactic} cases={len(control_lines)} qualification_complete=false")
        wanted.extend([
            ("controls-"+tactic,[str(raw/"artifacts/check_elf_tactic_refusals"),str(original),str(subject/"unstripped-null.selection"),tactic],
                ("\n".join(control_lines)+"\n").encode()),
            ("native-"+tactic,[str(driver),"run-tactics",tactic,str(original),str(stripped),*candidates,str(raw/("captures-"+tactic))],f["stdout"].encode())])
        wanted.extend(("ordinary-"+tactic+"-"+name,[str(raw/("captures-"+tactic)/name)],b"elf tactics ok\n") for name in COPY_NAMES)
    assert len(wanted) == 93 and js(raw/"stage-inventory.json") == [r[0] for r in wanted]
    receipts = {}
    for result, (name, argv, stdout) in zip(results, wanted):
        directory = raw/name; compiler = name == "codec-compile"
        assert result == js(directory/"result.json")
        command = js(directory/"command.json")
        assert set(result) == set(command) | {"exit","elapsed_seconds"}
        assert {k:v for k,v in result.items() if k in command} == command
        assert set(command) == {"name","argv","cwd","env","start_utc","request","outer_argv","outer_env","parent_timeout_seconds"}
        assert type(result["exit"]) is int and result["exit"] == 0
        finite(result["elapsed_seconds"])
        env = dict(expected_env if compiler else RUNTIME_ENV, TMPDIR=str(directory/"tmp"))
        request = dict(argv=argv,cwd=str(REPO),env=env,stdout=str(directory/"stdout.txt"),stderr=str(directory/"stderr.txt"),
            cpu_seconds=60 if compiler else 20,wall_seconds=90 if compiler else 30,file_bytes=(128 if compiler else 16)*1024*1024)
        assert command["name"] == name and command["argv"] == argv and command["cwd"] == str(REPO) and command["env"] == env
        assert command["request"] == js(directory/"request.json") == request
        assert command["outer_argv"] == ["/usr/bin/timeout","--signal=TERM","--kill-after=10s","100s" if compiler else "40s",
            "/usr/bin/python3.9","-B",str(REPO/"tools/unwind-oracle/bounded_command.py"),"--request",str(directory/"request.json"),"--receipt",str(directory/"receipt.json")]
        assert command["outer_env"] == RUNTIME_ENV and command["parent_timeout_seconds"] == (115 if compiler else 55)
        receipt = js(directory/"receipt.json")
        assert set(receipt) == RECEIPT_KEYS and type(receipt["exit"]) is int and receipt["exit"] == 0
        assert receipt["wall_timeout"] is False and receipt["inputs_unchanged"] is True and receipt["absence_proof"] == "ECHILD"
        assert receipt["cleanup_events"] == receipt["unexpected_descendants"] == []
        assert receipt["cleanup_error"] is receipt["aborted"] is None
        finite(receipt["elapsed_seconds"])
        assert receipt["request_sha256"] == sha(read(directory/"request.json"))
        assert receipt["helper_sha256"] == source["files"]["tools/unwind-oracle/bounded_command.py"]
        assert read(directory/"helper.stdout") == (json.dumps(dict(exit=0,wall_timeout=False,absence_proof="ECHILD",descendants=0,success=True))+"\n").encode()
        assert read(directory/"helper.stderr") == b""
        for stream in ("stdout","stderr"):
            assert receipt[stream+"_sha256"] == sha(read(directory/(stream+".txt")))
        if stdout is not None:
            assert read(directory/"stdout.txt") == stdout and read(directory/"stderr.txt") == b""
        receipts[name] = sha(read(directory/"receipt.json"))
    cargo_rows = [json.loads(line) for line in read(raw/"codec-compile/stdout.txt").splitlines()]
    assert 1 <= len(cargo_rows) <= 256 and cargo_rows[-1] == {"reason":"build-finished","success":True}
    assert sum(r.get("reason") == "build-finished" for r in cargo_rows) == 1
    assert all(r.get("reason") in ("compiler-artifact","build-script-executed","build-finished") for r in cargo_rows)
    assert not any(line.startswith((b"warning:",b"error:")) for line in read(raw/"codec-compile/stderr.txt").splitlines())
    artifacts = js(raw/"artifacts.json")
    assert set(artifacts) == {"verify_elf_tactics","check_elf_tactic_refusals"}
    for name, record in artifacts.items():
        selected = [r for r in cargo_rows if r.get("reason") == "compiler-artifact" and r["target"]["name"] == name and r.get("executable")]
        assert selected == [record["artifact"]]
        r = selected[0]
        assert r["manifest_path"] == str(REPO/"tools/elf-rewrite/Cargo.toml")
        assert r["target"]["src_path"] == str(REPO/"tools/elf-rewrite/examples"/(name+".rs"))
        assert r["target"]["kind"] == ["example"] and r["target"]["crate_types"] == ["bin"]
        assert r["profile"] == dict(opt_level="0",debuginfo=2,debug_assertions=True,overflow_checks=True,test=False)
        assert r["features"] == [] and type(r["fresh"]) is bool
        assert r["filenames"] == [str(REPO/"target/debug/examples"/name)] and r["executable"] == r["filenames"][0]
        assert sha(read(raw/"artifacts"/name)) == record["sha256"]
    return receipts, b1


def family_audit(raw, tactic, f, target_bytes):
    captures = raw/("captures-"+tactic); subject = raw/"subjects"/tactic
    assert read(captures/"runtime-target.tsv") == target_bytes
    layout = target_layout(captures/"runtime-target.tsv")
    elfs, providers, candidates, routes = [], [], [], []
    for i, name in enumerate(COPY_NAMES):
        e = Elf(captures/name,f,i >= 2)
        assert stat.S_IMODE(e.path.lstat().st_mode) == 0o500
        if i < 2:
            assert e.raw == read(subject/name)
            shoff, shnum = word(e.raw,40), struct.unpack_from("<H",e.raw,60)[0]
            assert struct.unpack_from("<H",e.raw,58)[0] == 64 and 0 < shnum <= 64 and shoff+64*shnum <= len(e.raw)
            kinds = [struct.unpack_from("<I",e.raw,shoff+64*j+4)[0] for j in range(shnum)]
            assert kinds.count(2) == (1 if i == 0 else 0) and 11 not in kinds
        else:
            strip = (i-2)//2; hook = (i-2)%2
            name = tactic+("-unstripped-" if strip == 0 else "-stripped-")+("null" if hook == 0 else "journal")
            directory = raw/(name+"-candidate"); candidates.append((name,directory))
            assert e.raw == read(directory/"candidate.elf")
            assert read(directory/"target.tsv") == target_bytes
            routes.append(candidate_routes(directory,e,f,hook))
        elfs.append(e); providers.append(provider_record(e.path.with_suffix(".provider"),e.path))
    originals = js(raw/("originals-"+tactic+".json"))
    assert originals == {"unstripped":sha(elfs[0].raw),"stripped":sha(elfs[1].raw)}
    for p in elfs[0].loads:
        left, right = bytearray(elfs[0].slice(p[3],p[5])), bytearray(elfs[1].slice(p[3],p[5]))
        if p[2] == 0:
            for a,b in ((40,48),(58,64)):
                left[a:b] = right[a:b] = bytes(b-a)
        assert left == right
    authenticated = {}
    for i,(name,directory) in enumerate(candidates):
        strip, hook = i//2,i%2
        selection = subject/(("unstripped" if strip == 0 else "stripped")+("-null.selection" if hook == 0 else "-journal.selection"))
        authenticated[name] = authenticate_candidate(directory,elfs[strip],selection,f)
    assert authenticated == js(raw/("candidate-files-before-"+tactic+".json")) == js(raw/("candidate-files-after-"+tactic+".json"))
    names = set(COPY_NAMES) | {n+".provider" for n in COPY_NAMES} | {"runtime-target.tsv","capture-inventory.tsv","complete.tsv"}
    directories, rows = set(), []
    # Expected coverage is fixed before reading any success or per-trace file.
    for strip in range(2):
        for head in range(len(f["heads"])):
            for seed in range(2):
                path = logical_path(f,head,seed)
                for variant in ("original","hook-0","hook-1"):
                    directory = f"strip-{strip}-head-{head}-seed-{seed}-{variant}"
                    index = strip if variant == "original" else 2+2*strip+int(variant[-1])
                    directories.add(directory); rows.append((directory,strip,head,seed,variant,index,path))
                    local = FIXED_TRACE | {f"loaded-{a:x}.bin" for a in elfs[index].pages}
                    for stem in ["before-call","after-call"]+[f"point-{j}" for j in range(len(path))]:
                        local |= {stem+"."+suffix for suffix in SUFFIXES}
                    if variant != "original" and head == 0:
                        local |= HOOK_FILES
                    names.update(directory+"/"+n for n in local)
    assert len(rows) == 12*len(f["heads"])
    coefficient, constant = {"B2":(6,1415),"T1":(6,1415),"T2":(12,2831),"T3":(10,2255)}[tactic]
    assert len(names) == constant + coefficient * sum(len(e.pages) for e in elfs[2:])
    inventory = ("elf-exec-tactics-captures-v1\n"+"".join(n+"\n" for n in sorted(names))).encode()
    assert read(raw/("expected-captures-"+tactic+".tsv")) == read(captures/"capture-inventory.tsv") == inventory
    actual = list(captures.rglob("*"))
    assert all(stat.S_ISDIR(p.lstat().st_mode) or stat.S_ISREG(p.lstat().st_mode) for p in actual)
    assert {str(p.relative_to(captures)) for p in actual if stat.S_ISDIR(p.lstat().st_mode)} == directories
    assert {str(p.relative_to(captures)) for p in actual if stat.S_ISREG(p.lstat().st_mode)} == names
    hashes = {n:sha(read(captures/n)) for n in sorted(names)}
    assert hashes == js(raw/("capture-files-"+tactic+".json"))
    baseline, steps, comparisons, effects, hooks, journals, transfers = {}, {}, 0, 0, 0, 0, 0
    for directory,strip,head,seed,variant,index,path in rows:
        d = captures/directory; route = {} if variant == "original" else routes[index-2][0]
        current, count = trace(d,elfs[index],providers[index],f,head,seed,variant,route,layout)
        steps[directory] = count; key = (strip,head,seed)
        expected_edges = [] if variant == "original" else edges(tactic,f,head)
        assert read(d/"transfers.tsv") == ("source\ttarget\tbytes\n"+"".join(f"{a}\t{b}\t{c.hex()}\n" for a,b,c in expected_edges)).encode()
        for a,b,c in expected_edges:
            assert elfs[index].slice(a,len(c)) == c
        transfers += len(expected_edges)
        if variant == "original":
            same_state(current[1],current[2][0])
            baseline[key] = current
            effects += original_effects(tactic,current[2],path,head)
        else:
            old = baseline[key]
            for a,b in zip(old[:2],current[:2]):
                same_state(a,b); comparisons += 1
            assert len(old[2]) == len(current[2]) == len(path)
            for a,b in zip(old[2],current[2]):
                same_state(a,b); comparisons += 1
            if head == 0:
                hook_witness(d,old[2][0],routes[index-2][1],routes[index-2][2],layout); hooks += 1
                journals += int(variant == "hook-1")
    n = len(f["heads"])
    assert len(baseline) == 4*n and comparisons == f["comparisons"] and hooks == 8 and journals == 4
    assert effects == {"B2":24,"T1":24,"T2":52,"T3":34}[tactic]
    assert transfers == {"B2":8,"T1":8,"T2":24,"T3":24}[tactic]
    exact_tsv(captures/"complete.tsv", (("status","passed"),("tactic",tactic),("original_traces",4*n),
        ("rewritten_traces",8*n),("full_state_comparisons",comparisons),("subject_call_ret_witnesses",12*n),
        ("hook_call_return_witnesses",hooks),("recording_hook_rows",journals),("manual_load_mappings",0),
        ("post_seed_state_repairs",0),("capture_files",len(names))))
    return dict(original_traces=4*n,rewritten_traces=8*n,traces=12*n,full_state_comparisons=comparisons,
        snapshots=sum(2+len(row[-1]) for row in rows),
        original_ISA_effect_comparisons=effects,subject_call_ret_witnesses=12*n,hook_call_return_witnesses=hooks,
        recording_hook_rows=journals,gateway_transfer_rows=transfers,ordinary_processes=6,
        captures_count=len(names),captures_sha256=sha(read(raw/("capture-files-"+tactic+".json"))),
        capture_inventory_sha256=sha(inventory),trace_steps=steps,
        candidate_files_before_sha256=sha(read(raw/("candidate-files-before-"+tactic+".json"))),
        candidate_files_after_sha256=sha(read(raw/("candidate-files-after-"+tactic+".json"))))


def main():
    global REPO
    assert not sys.flags.optimize, "Assertions required"
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw", type=Path, required=True)
    raw = parser.parse_args().raw
    assert raw.is_absolute() and raw.resolve(strict=True) == raw and raw.is_dir()
    roots = [p.parent for p in raw.parents if p.name == "ignored"]
    assert len(roots) == 1
    REPO = roots[0]
    output = raw/"runtime-audit-tactics-v1"
    assert not output.exists()
    support = Path(__file__).resolve().parent
    assert sha(read(support/"fixture.json")) == FIXTURE_SHA256
    assert sha(read(support/"source-pins.json")) == PINS_SHA256
    fixture = js(support/"fixture.json"); pins = js(support/"source-pins.json")
    assert list(fixture) == ["B2","T1","T2","T3"] and sum(len(f["heads"]) for f in fixture.values()) == 17
    source = js(raw/"source.json")
    assert source == js(raw/"source-after.json") and source["revision"] == EXPECTED_REVISION
    assert set(source) == {"revision","files"} and source["files"] == git_source(source["revision"])
    assert all(source["files"][name] == digest for name,digest in pins.items())
    receipts,b1 = commands(raw,fixture,source)
    target = read(b1/"captures/runtime-target.tsv")
    _, _, mask, components = target_layout(b1/"captures/runtime-target.tsv")
    compact = ("target xsave64 " + str(mask)
        + "".join(f" {1 << bit}:{offset}:{size}" for bit, offset, size in components) + "\n").encode()
    assert read(b1/"target/stdout.txt") == compact
    families = {name:family_audit(raw,name,f,target) for name,f in fixture.items()}
    assert js(raw/"summary.json") == {name:dict(original_traces=f["original_traces"],rewritten_traces=f["rewritten_traces"],
        comparisons=f["full_state_comparisons"],capture_files=f["captures_count"],ordinary_processes=6,qualification_complete=False)
        for name,f in families.items()}
    totals = {key:sum(f[key] for f in families.values()) for key in ("original_traces","rewritten_traces","traces",
        "full_state_comparisons","original_ISA_effect_comparisons","subject_call_ret_witnesses",
        "hook_call_return_witnesses","recording_hook_rows","gateway_transfer_rows","ordinary_processes","captures_count","snapshots")}
    assert [totals[k] for k in ("original_traces","rewritten_traces","traces","full_state_comparisons",
        "original_ISA_effect_comparisons","subject_call_ret_witnesses","hook_call_return_witnesses","recording_hook_rows","ordinary_processes")] == [68,136,204,676,134,204,32,16,24]
    assert totals["snapshots"] == 1014 and totals["gateway_transfer_rows"] == 64
    hardware = js(raw/"hardware.json")
    assert hardware["architecture"] == "x86_64" and type(hardware["logical_cpus"]) is int and hardware["logical_cpus"] > 0
    for p,digest in list(READS.items()):
        assert sha(read(Path(p))) == digest
    report = dict(schema=1,status="PASS_SAVED_CAPTURE_COMPARISON",source_revision=source["revision"],
        source_files=source["files"],source_sha256=sha(read(raw/"source.json")),
        audit_source_sha256=sha(read(Path(__file__).resolve())),source_pins_sha256=sha(read(support/"source-pins.json")),
        fixture_contract_sha256=sha(read(support/"fixture.json")),stages=93,helper_receipts=receipts,
        b1_prerequisite_inputs_sha256=sha(read(raw/"b1-prerequisite-inputs.json")),
        b1_scope="Separate closed prerequisite; its 27 commands and 1,230 captures are not requalified by this audit.",
        hardware=hardware,hardware_sha256=sha(read(raw/"hardware.json")),families=families,totals=totals,
        limits=dict(whole_child_steps=20000,whole_child_seconds=15),qualification_complete=False,
        scope="Four finite ET_EXEC fixtures; original state assertions corroborated by complete serialized-state comparisons.",
        limitations=["No subject/helper/compiler execution by this audit and no shared Cargo target file reads.",
            "Parent process closure requires the separately recorded root observation; successful files alone do not prove it.",
            "Live descriptor/proc-exe/mount rechecks and intermediate per-step assertions remain driver execution evidence.",
            "No CET, arbitrary ELF, performance, full tool closure or common-corpus comparison claim."],
        read_files_sha256=READS.copy())
    output.mkdir()
    with (output/"audit.json").open("x") as stream:
        json.dump(report,stream,indent=2,sort_keys=True); stream.write("\n")


if __name__ == "__main__":
    main()
