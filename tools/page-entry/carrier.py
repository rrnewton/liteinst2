#!/usr/bin/env python3
"""Make an explicit private ELF carrier, or execute it from a sealed memfd."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import struct
import sys

sys.dont_write_bytecode = True

EH = struct.Struct("<16sHHIQQQIHHHHHH")
PH = struct.Struct("<IIQQQQQQ")
META = struct.Struct("<8s9Q32s32s")
FOOT = struct.Struct("<8sQQ")
MAX_FILE = 16 * 1024 * 1024


def read_elf(path):
    data = path.read_bytes()
    if not EH.size <= len(data) <= MAX_FILE:
        raise ValueError("ELF size")
    h = EH.unpack_from(data)
    if h[0][:7] != b"\x7fELF\x02\x01\x01" or h[1] not in (2, 3) or h[2] != 62 or h[3] != 1:
        raise ValueError("ELF platform")
    if h[8] != EH.size or h[9] != PH.size or not 1 <= h[10] <= 32 or h[5] + h[10] * PH.size > len(data):
        raise ValueError("ELF program table")
    return data, h, [PH.unpack_from(data, h[5] + i * PH.size) for i in range(h[10])]


def make(original, bridge, output):
    original, bridge = original.resolve(strict=True), bridge.resolve(strict=True)
    mode = original.stat().st_mode
    if not stat.S_ISREG(mode) or mode & (stat.S_ISUID | stat.S_ISGID):
        raise ValueError("private carrier excludes privileged/nonregular images")
    try:
        if os.getxattr(original, "security.capability"):
            raise ValueError("private carrier excludes file capabilities")
    except OSError as error:
        if error.errno not in (61, 95):
            raise
    source, h, ph = read_elf(original)
    bridge_bytes, bridge_h, bridge_ph = read_elf(bridge)
    if bridge_h[1] != 3 or any(p[0] == 3 for p in bridge_ph):
        raise ValueError("bridge must be freestanding ET_DYN")
    interp_indexes = [i for i, p in enumerate(ph) if p[0] == 3]
    if len(interp_indexes) != 1:
        raise ValueError("exactly one original interpreter required")
    index = interp_indexes[0]
    p = ph[index]
    name = source[p[2]:p[2] + p[5]]
    if len(name) != p[5] or len(name) < 2 or name[-1:] != b"\0" or b"\0" in name[:-1] or name[:1] != b"/":
        raise ValueError("original interpreter path")
    interp = Path(os.fsdecode(name[:-1])).resolve(strict=True)
    interpreter, ih, ip = read_elf(interp)
    if ih[1] != 3 or any(p[0] == 3 for p in ip):
        raise ValueError("original interpreter must be unchained ET_DYN")
    path = os.fsencode(interp) + b"\0"
    bridge_path = os.fsencode(bridge) + b"\0"
    if max(len(path), len(bridge_path)) > 4096:
        raise ValueError("interpreter pathname length")
    changed = bytearray(source)
    for i, row in enumerate(ph):
        item = list(row)
        if item[0] == 1:
            item[1] &= ~1  # PF_X withheld by the kernel's initial main mapping.
        if i == index:
            item = [3, 4, len(source), 0, 0, len(bridge_path), len(bridge_path), 1]
        PH.pack_into(changed, h[5] + i * PH.size, *item)
    changed.extend(bridge_path)
    while len(changed) % 8:
        changed.append(0)
    offset = len(changed)
    metadata = META.pack(b"LI2BOOT1", 1, len(source), h[5], h[10], h[4], len(path), len(interpreter), index, 0,
                         hashlib.sha256(source).digest(), hashlib.sha256(interpreter).digest())
    metadata += source[h[5]:h[5] + h[10] * PH.size] + path
    changed.extend(metadata)
    changed.extend(FOOT.pack(b"LI2END01", offset, len(metadata)))
    if len(changed) > MAX_FILE:
        raise ValueError("final carrier size")
    output.write_bytes(changed)
    output.chmod(0o700)
    print(json.dumps({"scope": "private_carrier", "original_sha256": hashlib.sha256(source).hexdigest(),
                      "interpreter_sha256": hashlib.sha256(interpreter).hexdigest(),
                      "bridge_sha256": hashlib.sha256(bridge_bytes).hexdigest(),
                      "carrier_sha256": hashlib.sha256(changed).hexdigest(),
                      "original_size": len(source), "program_headers": h[10],
                      "main_pf_x_cleared": True, "logical_phdr_restored_in_place": "required_at_runtime"}, sort_keys=True))


def execute(carrier, argv):
    data = carrier.read_bytes()
    if not 0 < len(data) <= MAX_FILE:
        raise ValueError("carrier size")
    fd = os.memfd_create("li2-private-carrier", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    at = 0
    while at < len(data):
        count = os.write(fd, data[at:])
        if count <= 0:
            raise OSError("short carrier write")
        at += count
    seals = fcntl.F_SEAL_SEAL | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW | fcntl.F_SEAL_WRITE
    fcntl.fcntl(fd, fcntl.F_ADD_SEALS, seals)
    if fcntl.fcntl(fd, fcntl.F_GET_SEALS) != seals:
        raise ValueError("carrier sealing failed")
    # Actual exec supplies the new stack/credential/FD transition; the memfd
    # becomes /proc/self/exe. This is deliberately not original-file identity.
    os.execve(fd, argv or [str(carrier)], os.environ.copy())


def counter_descriptor(counter_fd, counter_nonce, parent):
    if (type(counter_fd) is not int or counter_fd <= 2 or type(counter_nonce) is not int or
            not 0 < counter_nonce < 1 << 64):
        raise ValueError("single-process explicit counter descriptor/nonce")
    cs = os.fstat(counter_fd)
    ch = os.pread(counter_fd, 4096, 0)
    if (not stat.S_ISREG(cs.st_mode) or cs.st_mode & 0o7777 != 0o600 or cs.st_nlink != 0 or
            cs.st_size != 4096 or not os.get_inheritable(counter_fd) or
            fcntl.fcntl(counter_fd, fcntl.F_GETFL) & os.O_ACCMODE != os.O_RDWR or
            fcntl.fcntl(counter_fd, fcntl.F_GET_SEALS) != 6 or len(ch) != 4096 or
            struct.unpack_from('<8Q', ch) != (0x31434f554e544750, 2, 752, 4096, counter_nonce,
                                            parent, cs.st_dev, cs.st_ino) or any(ch[64:])):
        raise ValueError("exact initial diagnostic memfd identity/seals/header")

def execute_loader(carrier, original, roots, directory, argv, fork_fds=None, child_failure=0, disable_rseq=False, provider_policy=None, *, late_sonames=(), counter_fd=None, counter_nonce=None):
    # This separate command intentionally supplies a private namespace and a
    # closed environment. The original fixture's make/exec path is unchanged.
    if provider_policy not in (None, "mask-random-v1", "deterministic-builtins-v1"):
        raise ValueError("unknown selected provider policy")
    if (counter_fd is None) != (counter_nonce is None):
        raise ValueError("both explicit counter descriptor and nonce required")
    if counter_fd is not None:
        if fork_fds is not None:
            raise ValueError("counter carrier forbids fork profile")
        counter_descriptor(counter_fd, counter_nonce, os.getppid())
    import namespace
    with carrier.open("rb") as stream:
        data = stream.read(MAX_FILE + 1)
    if not FOOT.size + META.size <= len(data) <= MAX_FILE:
        raise ValueError("loader carrier size")
    magic, offset, size = FOOT.unpack_from(data, len(data) - FOOT.size)
    if magic != b"LI2END01" or offset + size != len(data) - FOOT.size or size < META.size:
        raise ValueError("loader carrier footer")
    meta = META.unpack_from(data, offset)
    if meta[0] != b"LI2BOOT1" or meta[1] != 1 or meta[9] != 0 or not 1 <= meta[4] <= 32:
        raise ValueError("loader carrier metadata")
    if size != META.size + meta[4] * PH.size + meta[6]:
        raise ValueError("loader carrier metadata extent")
    fds, directory = namespace.prepare(original, roots, directory, meta[10], meta[11], late_sonames=late_sonames)
    fd = None
    try:
        fd = namespace.sealed_bytes("li2-private-loader-carrier", data, False)
        argv = argv[1:] if argv[:1] == ["--"] else argv
        argv = argv or [str(original)]
        env = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C", "TZ": "UTC",
               "LD_LIBRARY_PATH": str(directory), "LD_BIND_NOW": "1",
               "LI2_DEPENDENCY_FDS": ",".join(str(item) for item in fds)}
        if counter_fd is not None:
            if counter_fd in fds or counter_fd == fd:
                raise ValueError("counter descriptor is separate from carrier/dependencies")
            env["LI2_GROUP_COUNTER_FD"] = str(counter_fd)
            env["LI2_GROUP_COUNTER_NONCE"] = str(counter_nonce)
        if provider_policy is not None:
            env["LI2_SELECTED_PROVIDER"] = provider_policy
        if disable_rseq:
            # Explicit named workload only; never inherit arbitrary caller tunables.
            env["GLIBC_TUNABLES"] = "glibc.pthread.rseq=0"
        if fork_fds is not None:
            if len(fork_fds) != 2 or fork_fds[0] == fork_fds[1] or any(item <= 2 for item in fork_fds):
                raise ValueError("distinct fork report descriptors")
            for item in fork_fds:
                if not stat.S_ISFIFO(os.fstat(item).st_mode):
                    raise ValueError("fork report descriptor is not a pipe")
            env["LI2_RAW_FORK"] = "1"
            env["LI2_FORK_REPORT_FDS"] = ",".join(str(item) for item in fork_fds)
            if child_failure:
                if child_failure not in (1, 2, 3, 4):
                    raise ValueError("child failure step")
                env["LI2_FORK_CHILD_FAILURE"] = str(child_failure)
        # Preparation is reproducible and retained even if exec fails. This is
        # not an execution receipt and cannot claim the linker used these files.
        (directory / "launch.json").write_text(json.dumps({
            "schema_version": 1, "scope": "first_entry_loader_candidate", "status": "prepared_not_executed",
            "carrier_sha256": hashlib.sha256(data).hexdigest(), "carrier_size": len(data),
            "argv": argv, "environment": env, "dependency_fds": fds,
        }, indent=2, sort_keys=True) + "\n")
        os.execve(fd, argv, env)
    finally:
        if fd is not None:
            os.close(fd)
        for item in reversed(fds):
            os.close(item)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="mode", required=True)
    create = sub.add_parser("make")
    create.add_argument("original", type=Path)
    create.add_argument("bridge", type=Path)
    create.add_argument("output", type=Path)
    run = sub.add_parser("exec")
    run.add_argument("carrier", type=Path)
    run.add_argument("argv", nargs=argparse.REMAINDER)
    loader = sub.add_parser("exec-loader", help="explicit sealed dependency namespace; separate loader backend")
    loader.add_argument("--library-root", action="append", type=Path, required=True)
    loader.add_argument("--namespace", type=Path, required=True)
    loader.add_argument("--late-soname", action="append", default=[], metavar="NAME",
                        help="preauthorize a sealed late DSO and its dependencies; does not preload or admit it")
    loader.add_argument("--disable-rseq", action="store_true", help="explicit glibc.pthread.rseq=0 workload")
    loader.add_argument("--provider-policy", choices=("mask-random-v1", "deterministic-builtins-v1"),
                        help="explicit configured selected-provider policy; native behavior remains the default")
    loader.add_argument("--counter-fd", type=int, help="explicit final-counter memfd, separate from dependencies")
    loader.add_argument("--counter-nonce", type=int, help="exact parent-initialized counter identity")
    loader.add_argument("carrier", type=Path)
    loader.add_argument("original", type=Path)
    loader.add_argument("argv", nargs=argparse.REMAINDER)
    fork = sub.add_parser("exec-fork", help="one raw fork; distinct report pipes")
    fork.add_argument("--library-root", action="append", type=Path, required=True)
    fork.add_argument("--namespace", type=Path, required=True)
    fork.add_argument("--report-parent", type=int, required=True)
    fork.add_argument("--report-child", type=int, required=True)
    fork.add_argument("--child-failure", type=int, choices=(0, 1, 2, 3, 4), default=0)
    fork.add_argument("carrier", type=Path)
    fork.add_argument("original", type=Path)
    fork.add_argument("argv", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if args.mode == "make":
        make(args.original, args.bridge, args.output)
    elif args.mode == "exec":
        execute(args.carrier, args.argv)
    elif args.mode == "exec-fork":
        execute_loader(args.carrier, args.original, args.library_root, args.namespace, args.argv,
                       (args.report_parent, args.report_child), args.child_failure)
    else:
        execute_loader(args.carrier, args.original, args.library_root, args.namespace, args.argv,
                       disable_rseq=args.disable_rseq, provider_policy=args.provider_policy, late_sonames=args.late_soname,
                       counter_fd=args.counter_fd, counter_nonce=args.counter_nonce)


if __name__ == "__main__":
    main()
