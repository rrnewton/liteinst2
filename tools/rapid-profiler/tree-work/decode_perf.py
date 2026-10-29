"""Bounded perf.data syntax inspection; never capture or accounting approval."""
import sys

if sys.flags.optimize:
    print('{"authority":"syntax only; no capture or accounting qualification",'
          '"error":{"code":"assertions_required","offset":null},"status":"REFUSED"}')
    raise SystemExit(2)
sys.dont_write_bytecode = True

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat

MAX_BYTES = 16 * 1024 * 1024
MAX_COMMAND_BYTES = 64 * 1024
MAX_SUMMARY_BYTES = 4 * 1024 * 1024
EXIT = {"DECODED_UNQUALIFIED": 0, "REFUSED": 2, "UNSUPPORTED": 3}
AUTHORITY = "syntax only; no capture or accounting qualification"


class InputRefusal(Exception):
    pass


def arguments(words):
    allowed = {"--data", "--sha256", "--command-json", "--command-sha256"}
    out = {}
    if len(words) not in (4, 8):
        raise InputRefusal("arguments")
    for name, value in zip(words[::2], words[1::2]):
        if name not in allowed or name in out or not value or "\0" in value:
            raise InputRefusal("arguments")
        out[name] = value
    if not {"--data", "--sha256"} <= out.keys():
        raise InputRefusal("arguments")
    if ("--command-json" in out) != ("--command-sha256" in out):
        raise InputRefusal("arguments")
    for name in ("--sha256", "--command-sha256"):
        if name in out and (len(out[name]) != 64 or any(c not in "0123456789abcdef" for c in out[name])):
            raise InputRefusal("hash_domain")
    return out


def read_bound(path, limit, expected, label):
    # NONBLOCK avoids blocking on a FIFO before fstat can refuse it. NOFOLLOW
    # refuses a final-component symlink; ancestor path custody remains external.
    try:
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode) or not 0 <= before.st_size <= limit:
                raise InputRefusal(label + "_regular_or_size")
            with os.fdopen(fd, "rb", closefd=False) as stream:
                data = stream.read(limit + 1)
            after = os.fstat(fd)
            stamp = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
            if stamp(before) != stamp(after) or len(data) != before.st_size or len(data) > limit:
                raise InputRefusal(label + "_changed_or_size")
        finally:
            os.close(fd)
    except (OSError, ValueError, UnicodeError):
        raise InputRefusal(label + "_io") from None
    if hashlib.sha256(data).hexdigest() != expected:
        raise InputRefusal(label + "_hash")
    return data


def command_words(data):
    try:
        words = json.loads(data.decode("utf-8"))
        if type(words) is not list or not words:
            raise InputRefusal("command_argv")
        raw, count = [], 0
        for word in words:
            if type(word) is not str or "\0" in word:
                raise InputRefusal("command_argv")
            encoded = os.fsencode(word)
            count += len(encoded) + 1
            if b"\0" in encoded or count > MAX_COMMAND_BYTES:
                raise InputRefusal("command_argv")
            raw.append(encoded)
        return raw
    except (ValueError, UnicodeError, RecursionError):
        raise InputRefusal("command_json_or_encoding") from None


def inspect(words):
    args = arguments(words)
    data = read_bound(args["--data"], MAX_BYTES, args["--sha256"], "data")
    command = None
    if "--command-json" in args:
        encoded = read_bound(args["--command-json"], MAX_COMMAND_BYTES,
                             args["--command-sha256"], "command")
        command = command_words(encoded)
    # The enclosing owner authenticates these source files before invocation.
    # Resolve the sibling directly, without a same-named sys.path import.
    path = Path(__file__).resolve().with_name("perf_data.py")
    spec = importlib.util.spec_from_file_location("_decode_perf_data", path)
    if spec is None or spec.loader is None:
        raise InputRefusal("decoder_import")
    decoder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(decoder)
    if decoder.MAX_BYTES != MAX_BYTES:
        raise InputRefusal("decoder_size_contract")
    return decoder.decode(data, command)["summary"]


def main(words):
    try:
        summary = inspect(words)
        status = summary["status"]
        if status not in EXIT:
            raise InputRefusal("decoder_status_contract")
        wire = json.dumps(summary, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True, allow_nan=False)
        if len(wire) + 1 > MAX_SUMMARY_BYTES:
            # No normal type inventory is truncated: 100,000 u32 type/count
            # entries fit this cap. A changed summary contract fails explicitly.
            summary = {"status": "REFUSED", "error": {"code": "summary_output_cap", "offset": None},
                       "decoder_status": status, "record_count": summary["record_count"],
                       "decoded_record_count": summary["decoded_record_count"],
                       "record_bytes": summary["record_bytes"], "authority": AUTHORITY}
            status = "REFUSED"
            wire = json.dumps(summary, sort_keys=True, separators=(",", ":"))
    except Exception as error:
        code = str(error) if type(error) is InputRefusal else "unexpected_decoder_or_wrapper_error"
        summary = {"status": "REFUSED", "error": {"code": code, "offset": None},
                   "authority": AUTHORITY}
        status = "REFUSED"
        wire = json.dumps(summary, sort_keys=True, separators=(",", ":"))
    print(wire)
    return EXIT[status]


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
