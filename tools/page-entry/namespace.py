"""Bounded, explicit sealed dependency namespace for the loader experiment.

This is trusted local preparation, not ld.so search-path emulation. The target
linker still performs all ELF mapping, relocation, TLS, and initialization.
"""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import struct

EH = struct.Struct("<16sHHIQQQIHHHHHH")
PH = struct.Struct("<IIQQQQQQ")
DY = struct.Struct("<qQ")
MAX_FILE = 16 * 1024 * 1024
MAX_OBJECTS = 32
SEALS = fcntl.F_SEAL_SEAL | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW | fcntl.F_SEAL_WRITE


def read_file(path):
    path = Path(path).resolve(strict=True)
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_mode & (stat.S_ISUID | stat.S_ISGID):
            raise ValueError("dependency is privileged or not regular")
        if not EH.size <= before.st_size <= MAX_FILE:
            raise ValueError("dependency size")
        try:
            if os.getxattr(fd, "security.capability"):
                raise ValueError("dependency has file capabilities")
        except OSError as error:
            if error.errno not in (61, 95):
                raise
        chunks = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(fd, min(remaining, 65536))
            if not chunk:
                raise ValueError("dependency became short")
            chunks.append(chunk)
            remaining -= len(chunk)
        after = os.fstat(fd)
        if os.read(fd, 1) or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
                            before.st_ctime_ns) != (after.st_dev, after.st_ino, after.st_size,
                                                   after.st_mtime_ns, after.st_ctime_ns):
            raise ValueError("dependency changed during copy")
        return path, b"".join(chunks)
    finally:
        os.close(fd)


def parse(data):
    if not EH.size <= len(data) <= MAX_FILE:
        raise ValueError("dependency ELF size")
    h = EH.unpack_from(data)
    if h[0][:7] != b"\x7fELF\x02\x01\x01" or h[1] not in (2, 3) or h[2:4] != (62, 1):
        raise ValueError("dependency ELF platform")
    if h[8] != EH.size or h[9] != PH.size or not 1 <= h[10] <= 32 or h[5] + h[10] * PH.size > len(data):
        raise ValueError("dependency ELF table")
    ph = [PH.unpack_from(data, h[5] + i * PH.size) for i in range(h[10])]
    if any(p[2] > len(data) or p[5] > len(data) - p[2] or p[5] > p[6] for p in ph):
        raise ValueError("dependency segment extent")
    dynamics = [p for p in ph if p[0] == 2]
    if len(dynamics) != 1 or dynamics[0][5] % DY.size or dynamics[0][5] // DY.size > 4096:
        raise ValueError("dependency dynamic table")
    p = dynamics[0]
    tags = []
    for offset in range(p[2], p[2] + p[5], DY.size):
        row = DY.unpack_from(data, offset)
        if row[0] == 0:
            break
        tags.append(row)
    else:
        raise ValueError("dependency dynamic table is unterminated")
    # RPATH/RUNPATH, audit, filters, and auxiliary object policies require
    # distinct loader semantics. Refuse them instead of resolving approximately.
    if any(tag in (15, 29, 0x6FFFFEFC, 0x6FFFFEFB, 0x7FFFFFFF, 0x7FFFFFFD) for tag, _ in tags):
        raise ValueError("dependency has unsupported search/audit/filter policy")

    def unique(tag, required=True):
        values = [value for key, value in tags if key == tag]
        if (required and len(values) != 1) or (not required and len(values) > 1):
            raise ValueError("dependency dynamic singleton")
        return values[0] if values else None

    address, size = unique(5), unique(10)
    if not size or size > MAX_FILE:
        raise ValueError("dependency string table size")
    owners = [p for p in ph if p[0] == 1 and address >= p[3] and
              address - p[3] <= p[5] and size <= p[5] - (address - p[3])]
    if len(owners) != 1:
        raise ValueError("dependency string table owner")
    start = owners[0][2] + address - owners[0][3]
    strings = data[start:start + size]

    def name(offset):
        if offset >= len(strings):
            raise ValueError("dependency string offset")
        end = strings.find(b"\0", offset)
        if end == -1 or not 1 <= end - offset <= 255:
            raise ValueError("dependency string extent")
        value = strings[offset:end].decode("ascii")
        if value in (".", "..") or "/" in value or any(not (c.isalnum() or c in "._+-") for c in value):
            raise ValueError("dependency name is not a plain SONAME")
        return value

    needed = [name(value) for tag, value in tags if tag == 1]
    if len(needed) > MAX_OBJECTS or len(needed) != len(set(needed)):
        raise ValueError("dependency list bound/duplicate")
    soname = unique(14, required=False)
    interps = [p for p in ph if p[0] == 3]
    if len(interps) > 1:
        raise ValueError("multiple interpreter headers")
    interp = None
    if interps:
        p = interps[0]
        value = data[p[2]:p[2] + p[5]]
        if not 2 <= len(value) <= 4096 or value[:1] != b"/" or value[-1:] != b"\0" or b"\0" in value[:-1]:
            raise ValueError("dependency interpreter path")
        interp = Path(os.fsdecode(value[:-1]))
    return {"elf_type": h[1], "needed": needed,
            "soname": name(soname) if soname is not None else None, "interpreter": interp}


def plan(original, roots, original_hash, interpreter_hash):
    roots = [Path(root).resolve(strict=True) for root in roots]
    if not roots or len(roots) > 8 or len(set(roots)) != len(roots) or any(not root.is_dir() for root in roots):
        raise ValueError("explicit library roots")
    original, source = read_file(original)
    if hashlib.sha256(source).digest() != original_hash:
        raise ValueError("namespace main differs from carrier")
    main = parse(source)
    if main["interpreter"] is None:
        raise ValueError("namespace requires a dynamic original")
    interp_path, interp_source = read_file(main["interpreter"])
    if hashlib.sha256(interp_source).digest() != interpreter_hash:
        raise ValueError("namespace interpreter differs from carrier")
    interp = parse(interp_source)
    if interp["elf_type"] != 3 or interp["interpreter"] is not None:
        raise ValueError("namespace interpreter is not unchained ET_DYN")
    objects, by_path, names = [], {}, {}
    pending = list(main["needed"]) + list(interp["needed"])
    cursor = 0
    while cursor < len(pending):
        needed = pending[cursor]
        cursor += 1
        if needed in names:
            continue
        path = next((root / needed for root in roots if (root / needed).exists()), None)
        if path is None:
            raise ValueError("dependency absent from explicit roots: " + needed)
        path = path.resolve(strict=True)
        if path in by_path:
            index = by_path[path]
        else:
            if len(objects) >= MAX_OBJECTS:
                raise ValueError("sealed dependency count")
            path, data = read_file(path)
            info = parse(data)
            if info["elf_type"] != 3:
                raise ValueError("dependency is not ET_DYN")
            # libc is also a directly executable ET_DYN and has PT_INTERP.
            # ld.so does not exec dependencies; retain that descriptive header,
            # and permit it only when it names this same original interpreter.
            if info["interpreter"] is not None:
                _, dependency_interp = read_file(info["interpreter"])
                if dependency_interp != interp_source:
                    raise ValueError("dependency PT_INTERP identity differs")
            # A needed interpreter SONAME must denote the exact authenticated
            # original interpreter, even when roots use another pathname.
            if interp["soname"] is not None and (needed == interp["soname"] or info["soname"] == interp["soname"]) and data != interp_source:
                raise ValueError("dependency interpreter SONAME identity")
            index = len(objects)
            objects.append({"path": path, "bytes": data, "info": info, "names": []})
            by_path[path] = index
            pending.extend(info["needed"])
        item = objects[index]
        for alias in (needed, item["info"]["soname"]):
            if alias is None:
                continue
            if alias in names and names[alias] != index:
                raise ValueError("ambiguous dependency SONAME")
            names[alias] = index
            if alias not in item["names"]:
                item["names"].append(alias)
    return objects, {"roots": [str(root) for root in roots], "original": str(original),
                     "original_sha256": original_hash.hex(), "interpreter": str(interp_path),
                     "interpreter_sha256": interpreter_hash.hex()}


def sealed_bytes(name, data, inheritable):
    fd = os.memfd_create(name, os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    try:
        at = 0
        while at < len(data):
            n = os.write(fd, memoryview(data)[at:])
            if n <= 0:
                raise OSError("short sealed-object write")
            at += n
        fcntl.fcntl(fd, fcntl.F_ADD_SEALS, SEALS)
        if fcntl.fcntl(fd, fcntl.F_GET_SEALS) != SEALS or os.fstat(fd).st_size != len(data):
            raise ValueError("sealed-object identity")
        os.set_inheritable(fd, inheritable)
        return fd
    except BaseException:
        os.close(fd)
        raise


def prepare(original, roots, directory, original_hash, interpreter_hash):
    objects, description = plan(original, roots, original_hash, interpreter_hash)
    directory = Path(directory).absolute()
    directory.mkdir(mode=0o700, parents=False, exist_ok=False)
    fds, rows = [], []
    try:
        for item in objects:
            fd = sealed_bytes("li2-dependency-" + str(len(fds)), item["bytes"], True)
            fds.append(fd)
            st = os.fstat(fd)
            row = {"fd": fd, "size": len(item["bytes"]), "sha256": hashlib.sha256(item["bytes"]).hexdigest(),
                   "source": str(item["path"]), "names": item["names"], "needed": item["info"]["needed"],
                   "descriptive_pt_interp": str(item["info"]["interpreter"]) if item["info"]["interpreter"] else None,
                   "device": st.st_dev, "inode": st.st_ino, "seals": fcntl.fcntl(fd, fcntl.F_GET_SEALS)}
            rows.append(row)
            for name in item["names"]:
                (directory / name).symlink_to("/proc/self/fd/" + str(fd))
        description.update({"schema_version": 1, "scope": "explicit_sealed_dependency_namespace",
                            "status": "prepared_not_executed", "directory": str(directory), "objects": rows,
                            "search_policy": "explicit roots; no RPATH/RUNPATH/cache emulation",
                            "identity_policy": "sealed copies and private paths; not filesystem transparency"})
        (directory / "namespace.json").write_text(json.dumps(description, indent=2, sort_keys=True) + "\n")
        return fds, directory
    except BaseException:
        for fd in reversed(fds):
            os.close(fd)
        raise
