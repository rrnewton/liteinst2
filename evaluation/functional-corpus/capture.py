#!/usr/bin/env -S /usr/bin/python3.9 -I -B
"""Transparent bounded stdin capture; no E9 rewriting or result interpretation."""
import os
import sys

if not __debug__ or not sys.flags.isolated or not sys.dont_write_bytecode:
    raise SystemExit("Use assertions-enabled isolated Python without bytecode")
if sys.argv[1:] != ["--static-loader"]:
    raise SystemExit("Unexpected forwarded backend arguments")
fd = os.open("request.jsonl", os.O_WRONLY | os.O_CREAT | os.O_EXCL |
             os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
try:
    total = 0
    while True:
        data = os.read(0, 65536)
        if not data:
            break
        total += len(data)
        if total > 203238400:
            raise RuntimeError("RPC capture exceeds derived maximum")
        view = memoryview(data)
        while view:
            count = os.write(fd, view)
            if count <= 0:
                raise RuntimeError("Short RPC write")
            view = view[count:]
    if total == 0:
        raise RuntimeError("Empty RPC")
    os.fsync(fd)
finally:
    os.close(fd)
