"""Literal owned function extraction; no native/tool execution on import."""
import sys
if sys.flags.optimize: raise SystemExit("optimized Python forbidden")
sys.dont_write_bytecode = True
import hashlib
import os
import struct
from pathlib import Path

def elf(data):
    assert data[:7] == b"\x7fELF\x02\x01\x01" and len(data) >= 64
    assert struct.unpack_from("<H", data, 18)[0] == 62
    phoff, shoff = struct.unpack_from("<QQ", data, 32)
    phent, phnum, shent, shnum = struct.unpack_from("<HHHH", data, 54)
    assert phent == 56 and 0 < phnum < 64 and phoff + 56 * phnum <= len(data)
    phdr = [struct.unpack_from("<IIQQQQQQ", data, phoff + i * 56) for i in range(phnum)]
    for typ, flags, offset, vaddr, _, filesz, memsz, align in phdr:
        assert offset + filesz <= len(data)
        if typ == 1:
            assert filesz <= memsz and vaddr + memsz < 1 << 47
            assert offset % 4096 == vaddr % 4096
            assert align in (0, 1) or align & (align - 1) == 0
    if shnum:
        assert shent == 64 and shoff + 64 * shnum <= len(data)
    sections = [struct.unpack_from("<IIQQQQIIQQ", data, shoff + i * 64) for i in range(shnum)]
    return phdr, sections


def translate(headers, address, length):
    owners = [p for p in headers if p[0] == 1 and p[3] <= address and address + length <= p[3] + p[5]]
    assert len(owners) == 1
    owner = owners[0]
    offset = owner[2] + address - owner[3]
    inverse = [p for p in headers if p[0] == 1 and p[2] <= offset and offset + length <= p[2] + p[5]]
    assert inverse == owners and owner[1] & 1
    return offset


def metadata_offset(data, headers, address, length):
    """Translate unique readable file-backed metadata, without requiring PF_X."""
    assert 0 <= address < 1 << 64 and 0 < length < 1 << 64
    end = address + length
    assert end <= 1 << 64
    owners = [p for p in headers if p[0] == 1 and p[6] and address < p[3] + p[6] and p[3] < end]
    assert len(owners) == 1, "ambiguous or absent metadata LOAD owner"
    owner = owners[0]
    assert owner[1] & 4, "metadata LOAD is not readable"
    assert owner[3] <= address and end <= owner[3] + owner[5], "metadata is not fully file-backed"
    offset = owner[2] + address - owner[3]
    assert 0 <= offset < offset + length <= len(data)
    aliases = [p for p in headers if p[0] == 1 and p[5] and offset < p[2] + p[5] and p[2] < offset + length]
    assert aliases == owners, "ambiguous metadata file ownership"
    return offset


def validate_launch_environment(environment, preload_bytes):
    assert environment == {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}, "unexpected child environment"
    assert preload_bytes is None or not any(
        line.split(b"#", 1)[0].strip() for line in preload_bytes.splitlines()
    ), "active system preload"


NOTE_BYTES = struct.pack("<III", 7, 16, 0x4c493201) + b"LI2CAL\0\0" + struct.pack("<QQ", 1, 0)
assert len(NOTE_BYTES) == 36

def executable_offset(data, headers, address, length):
    offset = metadata_offset(data, headers, address, length)
    assert translate(headers, address, length) == offset
    owners = [p for p in headers if p[0] == 1 and p[3] <= address and address + length <= p[3] + p[5]]
    assert len(owners) == 1 and owners[0][1] == 5, "code must be uniquely RX and not writable"
    return offset


def fixture_note(data, headers):
    notes = [p for p in headers if p[0] == 4]
    assert len(notes) == 1, "exactly one declared PT_NOTE required"
    note = notes[0]
    assert note[1] == 4 and note[5] == note[6] == 36 and note[7] == 4, "wrong note geometry or permissions"
    assert note[2] % 4 == note[3] % 4 == 0
    offset = metadata_offset(data, headers, note[3], note[5])
    assert offset == note[2]
    owners = [p for p in headers if p[0] == 1 and p[3] <= note[3] and note[3] + note[5] <= p[3] + p[5]]
    assert len(owners) == 1 and owners[0][1] == 4, "inert note must have an R-only LOAD owner"
    assert data[offset:offset + note[5]] == NOTE_BYTES, "wrong note owner/schema/type/padding"
    return {"header": list(note), "bytes_sha256": hashlib.sha256(NOTE_BYTES).hexdigest()}


def fixture_loader_contract(data, kind, interpreter, expected_init):
    """The new declared note/RET-init profile; never accepts E9 output."""
    assert kind in {"pie", "exec", "libcarrierfixture.so"}
    headers, _ = elf(data)
    is_main = kind != "libcarrierfixture.so"
    assert struct.unpack_from("<H", data, 16)[0] == (2 if kind == "exec" else 3)
    loader = os.fsencode(interpreter)
    assert loader.startswith(b"/") and b"\0" not in loader
    interps = [p for p in headers if p[0] == 3]
    assert len(interps) == int(is_main), "wrong PT_INTERP inventory"
    if is_main:
        interp = interps[0]
        offset = metadata_offset(data, headers, interp[3], interp[5])
        assert offset == interp[2]
        assert data[offset:offset + interp[5]] == loader + b"\0", "PT_INTERP differs from pinned resolved loader"
    dynamic = [p for p in headers if p[0] == 2]
    assert len(dynamic) == 1, "wrong PT_DYNAMIC inventory"
    dynamic = dynamic[0]
    assert 0 < dynamic[5] <= 256 * 16 and dynamic[5] % 16 == 0
    offset = metadata_offset(data, headers, dynamic[3], dynamic[5])
    assert offset == dynamic[2]
    slots = [struct.unpack_from("<qQ", data, at) for at in range(offset, offset + dynamic[5], 16)]
    terminators = [i for i, (tag, _) in enumerate(slots) if tag == 0]
    assert terminators, "missing DT_NULL"
    stop = terminators[0]
    assert all(pair == (0, 0) for pair in slots[stop:]), "nonzero dynamic data after DT_NULL"
    # Only the DSO has the exact authenticated RET initializer checked below.
    # Audit/filter/config, extra hooks and alternative search tags stay forbidden.
    allowed = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 14, 15, 20, 21, 23, 0x6FFFFEF5, 0x6FFFFFFB}
    tags = {}
    for tag, value in slots[:stop]:
        assert tag in allowed, f"unsupported fixture dynamic tag {tag:#x}"
        assert tag not in tags, f"duplicate fixture dynamic tag {tag:#x}"
        tags[tag] = value
    assert 5 in tags and 10 in tags and 0 < tags[10] <= 65536
    strings_offset = metadata_offset(data, headers, tags[5], tags[10])
    strings = data[strings_offset:strings_offset + tags[10]]
    assert strings[0] == 0 and strings[-1] == 0

    def string(tag):
        index = tags[tag]
        assert index < len(strings), "dynamic string offset outside DT_STRSZ"
        end = strings.find(b"\0", index)
        assert end != -1, "unterminated dynamic string"
        return strings[index:end].decode("ascii")

    needed = [string(1)] if 1 in tags else []
    rpath = [string(15)] if 15 in tags else []
    soname = string(14) if 14 in tags else None
    assert needed == (["libcarrierfixture.so"] if is_main else []), "unexpected DT_NEEDED contract"
    assert rpath == (["$ORIGIN"] if is_main else []), "unexpected DT_RPATH contract"
    assert soname == (None if is_main else "libcarrierfixture.so"), "unexpected DT_SONAME contract"
    if 0x6FFFFFFB in tags:
        assert kind == "pie" and tags[0x6FFFFFFB] == 0x08000000, "unexpected dynamic loader flags"
    note = fixture_note(data, headers)
    if is_main:
        assert expected_init is None and 12 not in tags, "main initializer forbidden"
        init_offset = None
    else:
        assert type(expected_init) is int and 0 < expected_init < (1 << 47), "missing authenticated initializer address"
        assert tags.get(12) == expected_init, "DT_INIT does not name the authenticated fixture initializer"
        init_offset = executable_offset(data, headers, expected_init, 1)
        assert data[init_offset:init_offset + 1] == b"\xc3", "initializer is not exactly RET at the certified symbol"
    return {
        "fixture_note": note,
        "fixture_init": expected_init,
        "fixture_init_file_offset": init_offset,
        "kind": kind, "elf_type": struct.unpack_from("<H", data, 16)[0],
        "interpreter": os.fsdecode(loader) if is_main else None,
        "needed": needed, "rpath": rpath, "soname": soname,
        "dynamic_file_offset": offset, "dynamic_bytes": dynamic[5],
        "dynamic_tags": [tag for tag, _ in slots[:stop]],
        "string_table_file_offset": strings_offset, "string_table_bytes": len(strings),
    }

