#!/usr/bin/env python3
"""One bounded read-only file mapping; no executable mapping or fixture execution."""
import argparse
import hashlib
import json
import mmap
import os
from pathlib import Path
import stat


def fields(value):
    return {"device": value.st_dev, "major": os.major(value.st_dev),
            "minor": os.minor(value.st_dev), "inode": value.st_ino,
            "mode": value.st_mode, "bytes": value.st_size,
            "mtime_ns": value.st_mtime_ns, "ctime_ns": value.st_ctime_ns}


def observation(function):
    try:
        return {"ok": True, "value": function()}
    except OSError as error:
        return {"ok": False, "errno": error.errno, "error": str(error)}


def maps():
    text = Path("/proc/self/maps").read_text()
    assert len(text) <= 1024 * 1024
    rows = []
    for line in text.splitlines():
        words = line.split(None, 5)
        start, end = words[0].split("-")
        major, minor = words[3].split(":")
        rows.append({"range": words[0], "start": int(start, 16), "end": int(end, 16),
                     "permissions": words[1], "offset": int(words[2], 16),
                     "device": [int(major, 16), int(minor, 16)], "inode": int(words[4]),
                     "path": words[5] if len(words) == 6 else None, "literal": line})
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("--expected-sha256", required=True)
    args = parser.parse_args()
    path = args.input
    assert path.is_absolute() and path.resolve(strict=True) == path and not path.is_symlink()
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        assert stat.S_ISREG(before.st_mode) and 0 < before.st_size <= 1024 * 1024
        source = os.pread(fd, before.st_size, 0)
        assert len(source) == before.st_size
        digest = hashlib.sha256(source).hexdigest()
        assert digest == args.expected_sha256
        fdinfo = Path(f"/proc/self/fdinfo/{fd}").read_text()
        mount_ids = [line.split(":", 1)[1].strip() for line in fdinfo.splitlines() if line.startswith("mnt_id:")]
        assert len(mount_ids) == 1
        mountinfo = Path("/proc/self/mountinfo").read_text()
        provider = [line for line in mountinfo.splitlines() if line.split()[0] == mount_ids[0]]
        assert len(provider) == 1
        before_maps = maps()
        assert not any(row["path"] == str(path) for row in before_maps)
        with mmap.mmap(fd, before.st_size, flags=mmap.MAP_PRIVATE, prot=mmap.PROT_READ) as mapping:
            mapped = mapping[:]
            assert mapped == source
            rows = [row for row in maps() if row["path"] == str(path)]
            assert len(rows) == 1
            row = rows[0]
            assert row["permissions"] == "r--p" and row["offset"] == 0
            assert row["end"] - row["start"] == (before.st_size + 4095) // 4096 * 4096
            owner = Path("/proc/self/map_files") / row["range"]
            row["map_files_readlink"] = observation(lambda: os.readlink(owner))
            row["map_files_stat"] = observation(lambda: fields(os.stat(owner)))
            during = fields(os.fstat(fd))
        after_maps = maps()
        assert not any(row["path"] == str(path) for row in after_maps)
        after = fields(os.fstat(fd))
        assert fields(before) == during == after == fields(path.stat())
        assert os.pread(fd, before.st_size, 0) == source
        model = next(line.split(":", 1)[1].strip() for line in Path("/proc/cpuinfo").read_text().splitlines() if line.startswith("model name"))
        result = {"scope": "READ_ONLY_PROVIDER_DIAGNOSTIC_NOT_NATIVE_QUALIFICATION",
                  "input": str(path), "sha256": digest, "fstat_before": fields(before),
                  "fstat_during": during, "fstat_after": after, "fdinfo": fdinfo,
                  "fd_readlink": os.readlink(f"/proc/self/fd/{fd}"), "mountinfo_provider": provider[0],
                  "mountinfo_sha256": hashlib.sha256(mountinfo.encode()).hexdigest(),
                  "mapping": row, "mapped_bytes_equal": True, "mapping_closed": True,
                  "hardware": {"cpu_model": model, "machine": os.uname().machine,
                               "kernel_release": os.uname().release},
                  "application_instructions_executed": False, "executable_mapping_created": False}
    finally:
        os.close(fd)
    result["descriptor_closed"] = True
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
