#!/usr/bin/env python3
"""Inspect one existing, hash-pinned ELF. Never build or execute that ELF.

This is a closed reproduction of the fa12329 static frame finding, not a general
stack analyzer. Raw tool output is private. The public JSON contains no paths or
raw logs. Failed validation publishes no summary; publication is atomic and
never overwrites an existing target.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import signal
import stat
import subprocess
import tempfile
import time

REVISION = "fa12329fd56f2181083ca640a7ace55e37447830"
ELF_SHA = "754ca894d1d71fc437c9bd3f06201c1b51f0d37851c374353cbe87f548f1fe81"
RECEIPT_SHA = "dec7b726d50369473da97db2d29b2016f70f32c9b5c852741ed273a4bbadf688"
LOG_SHA = "1bbeb3f8d8cbaf7e57a2fb1de60a080edd2becd316ea0999cd94aec9bb18ebb9"
TOOLS = {
    "nm": ("1e9d014468a356a030a32edf4f709b521cac91112fe2dda10a505c6e4189e4ed", "GNU nm (GNU Binutils) 2.37"),
    "objdump": ("02e21a57741c6d64f20b1f148c533ffb7373d064b46594d439c05dc4f66d0216", "GNU objdump (GNU Binutils) 2.37"),
}
# ELF-relative virtual addresses, not observed runtime addresses.
FRAMES = (
    ("prepare_kernel", 0xC4DEA0, 0xC50280, 0xD2000, 0x948),
    ("prepared_new", 0x8C4970, 0x8C4A40, 0x64000, 0x528),
    ("array_from_fn", 0xA4F440, 0xA4F4A0, 0x5D000, 0xCE8),
    ("array_try_from_fn", 0xA47630, 0xA476C0, 0x119000, 0x698),
)
EDGES = (
    ("prepare_kernel", 0xC4FB0D, "prepared_new", 0x8C4970),
    ("prepared_new", 0x8C4A0E, "array_from_fn", 0xA4F440),
    ("array_from_fn", 0xA4F473, "array_try_from_fn", 0xA47630),
)
CASE = "linux::remote::dynamic::owner::admission::runtime::kernel::native_tests::runtime_kernel_cross_page_syscall_preserves_exact_fetch"
MIB = 1024 * 1024


def require(value: bool, label: str) -> None:
    if not value:
        raise ValueError(label)


def digest_fd(fd: int, limit: int) -> tuple[str, os.stat_result]:
    before = os.fstat(fd)
    require(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= limit, "invalid bounded regular input")
    digest = hashlib.sha256()
    position = 0
    while position < before.st_size:
        chunk = os.pread(fd, min(MIB, before.st_size - position), position)
        require(bool(chunk), "short input read")
        digest.update(chunk)
        position += len(chunk)
    after = os.fstat(fd)
    require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
            == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns), "input changed during read")
    return digest.hexdigest(), after


def open_input(path: Path) -> int:
    return os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)


def read_small(path: Path, expected: str, limit: int) -> bytes:
    fd = open_input(path)
    try:
        digest, metadata = digest_fd(fd, limit)
        require(digest == expected, "input digest mismatch")
        data = os.pread(fd, metadata.st_size + 1, 0)
        require(len(data) == metadata.st_size and hashlib.sha256(data).hexdigest() == expected, "input changed")
        return data
    finally:
        os.close(fd)


def capture(tool_fd: int, tool_name: str, args: list[str], elf_fd: int, limit: int) -> bytes:
    """Bound output and wall time; on failure kill/reap only this tool group."""
    until = time.monotonic() + 30.0
    selector = None
    process = subprocess.Popen(
        [tool_name, *args], executable=f"/proc/self/fd/{tool_fd}",
        pass_fds=(tool_fd, elf_fd), stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True,
        env={"LANG": "C", "LC_ALL": "C", "PATH": os.defpath},
    )
    try:
        output = {"stdout": bytearray(), "stderr": bytearray()}
        selector = selectors.DefaultSelector()
        for stream, label in ((process.stdout, "stdout"), (process.stderr, "stderr")):
            selector.register(stream, selectors.EVENT_READ, label)
        while selector.get_map():
            remaining = until - time.monotonic()
            require(remaining > 0, "inspection tool timeout")
            for key, _ in selector.select(remaining):
                block = os.read(key.fileobj.fileno(), 65536)
                if not block:
                    selector.unregister(key.fileobj)
                    continue
                require(sum(map(len, output.values())) + len(block) <= limit, "inspection capture limit exceeded")
                output[key.data].extend(block)
        remaining = until - time.monotonic()
        require(remaining > 0, "inspection tool timeout")
        require(process.wait(timeout=remaining) == 0, "inspection tool failed")
        require(not output["stderr"], "unexpected inspection diagnostic")
        return bytes(output["stdout"])
    finally:
        try:
            if process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=5)
        finally:
            try:
                if selector is not None:
                    selector.close()
            finally:
                try:
                    process.stdout.close()
                finally:
                    process.stderr.close()


def publish_summary(path: Path, serialized: str) -> None:
    """Publish complete bytes exclusively; a failed write leaves no target."""
    descriptor, name = tempfile.mkstemp(prefix=".runtime-stack-", dir=path.parent)
    try:
        stream = os.fdopen(descriptor, "wb")
        descriptor = None
        with stream:
            payload = serialized.encode("utf-8")
            require(stream.write(payload) == len(payload), "short summary write")
            stream.flush()
            os.fsync(stream.fileno())
        # The complete, closed temporary is on the destination filesystem.
        # Hard-link publication is atomic and refuses an existing destination.
        os.link(name, path, follow_symlinks=False)
    finally:
        try:
            if descriptor is not None:
                os.close(descriptor)
        finally:
            os.unlink(name)


def instructions(text: str) -> dict[int, str]:
    result = {}
    for line in text.splitlines():
        match = re.match(r"^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s+)+)(.*)$", line)
        if match and match[3].strip():
            address = int(match[1], 16)
            require(address not in result, "duplicate instruction address")
            result[address] = match[3].strip()
    return result


def frame_bytes(code: dict[int, str], start: int, expected_pages: int, expected_tail: int) -> int:
    checks = (
        (0, r"mov\s+%rsp,%r11"),
        (3, rf"sub\s+\$0x{expected_pages:x},%r11"),
        (10, r"sub\s+\$0x1000,%rsp"),
        (17, r"movq\s+\$0x0,\(%rsp\)"),
        (25, r"cmp\s+%r11,%rsp"),
        (28, rf"jne\s+{start + 10:x}\s+<.*>"),
        (30, rf"sub\s+\$0x{expected_tail:x},%rsp"),
    )
    for offset, pattern in checks:
        require(re.fullmatch(pattern, code.get(start + offset, "")) is not None, "unexpected frame prologue")
    require(expected_pages > 0 and expected_pages % 4096 == 0 and 0 <= expected_tail < 4096, "invalid frame components")
    return expected_pages + expected_tail


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--elf", required=True, type=Path)
    parser.add_argument("--receipt", required=True, type=Path)
    parser.add_argument("--workspace-log", required=True, type=Path)
    parser.add_argument("--private-dir", required=True, type=Path)
    parser.add_argument("--summary", required=True, type=Path)
    args = parser.parse_args()
    require(not args.summary.exists(), "summary already exists")
    receipt = json.loads(read_small(args.receipt, RECEIPT_SHA, 8 * MIB))
    require(receipt["source"]["revision"] == REVISION and receipt["status"] == "failed", "wrong receipt identity")
    matches = [row for row in receipt["commands"] if row["id"] == "workspace_tests"]
    require(len(matches) == 1, "workspace command identity differs")
    command = matches[0]
    require(command["argv"] == ["cargo", "test", "--workspace"] and command["private_log_sha256"] == LOG_SHA, "workspace command differs")
    log = read_small(args.workspace_log, LOG_SHA, 8 * MIB).decode("utf-8")
    diagnostic = f'runtime isolated case "{CASE}" failed: isolated child did not exit normally with zero: signal=17, code=3, status=11, expected_pid=true'
    require(log.splitlines().count(diagnostic) == 1, "saved child status differs")
    require(log.splitlines().count("     Running unittests src/lib.rs (target/debug/deps/liteinst_launch-11d49a8d76592146)") == 1, "saved artifact reference differs")
    args.private_dir.mkdir(mode=0o700, parents=False, exist_ok=False)
    elf_fd = open_input(args.elf)
    tool_fds = {}
    try:
        elf_sha, elf_metadata = digest_fd(elf_fd, 256 * MIB)
        require(elf_sha == ELF_SHA and os.pread(elf_fd, 6, 0) == b"\x7fELF\x02\x01", "wrong ELF")
        tool_records = {}
        for name, (expected_sha, expected_version) in TOOLS.items():
            located = shutil.which(name)
            require(located is not None, "inspection tool missing")
            fd = open_input(Path(located).resolve(strict=True))
            tool_fds[name] = fd
            digest, _ = digest_fd(fd, 64 * MIB)
            require(digest == expected_sha, "inspection tool digest differs")
            version = capture(fd, name, ["--version"], elf_fd, 65536).decode("utf-8").splitlines()[0]
            require(version == expected_version, "inspection tool version differs")
            tool_records[name] = {"sha256": digest, "version": version}
        elf_argument = f"/proc/self/fd/{elf_fd}"
        symbols = capture(tool_fds["nm"], "nm", ["-C", "--defined-only", elf_argument], elf_fd, 16 * MIB).decode("utf-8")
        names = {}
        starts = {row[1] for row in FRAMES}
        for line in symbols.splitlines():
            match = re.fullmatch(r"([0-9a-f]{16}) [tT] (.+)", line)
            if match and int(match[1], 16) in starts:
                address = int(match[1], 16)
                require(address not in names, "duplicate selected symbol")
                names[address] = match[2]
        require(set(names) == starts, "missing selected symbol")
        (args.private_dir / "symbols.txt").write_text("\n".join(f"{address:016x} {names[address]}" for address in sorted(names)) + "\n")
        codes = {}
        frames = []
        for ident, start, end, pages, tail in FRAMES:
            argv = ["-d", "-C", f"--start-address={start:#x}", f"--stop-address={end:#x}", elf_argument]
            data = capture(tool_fds["objdump"], "objdump", argv, elf_fd, MIB)
            (args.private_dir / f"{ident}.txt").write_bytes(data)
            codes[ident] = instructions(data.decode("utf-8"))
            frames.append({"id": ident, "function": names[start], "elf_virtual_address": start,
                           "probe_bytes": pages, "tail_bytes": tail,
                           "frame_bytes": frame_bytes(codes[ident], start, pages, tail)})
        edges = []
        for caller, address, callee, target in EDGES:
            require(re.fullmatch(rf"call\s+{target:x}\s+<.*>", codes[caller].get(address, "")) is not None, "call edge differs")
            edges.append({"caller": caller, "call_site": address, "callee": callee, "target": target})
        require(re.fullmatch(r"call\s+996f70\s+<.*catch_unwind.*>", codes["prepare_kernel"].get(0xC4FFA5, "")) is not None, "later catch boundary differs")
        require(digest_fd(elf_fd, 256 * MIB)[0] == ELF_SHA, "ELF changed during inspection")
        for name, fd in tool_fds.items():
            require(digest_fd(fd, 64 * MIB)[0] == TOOLS[name][0], "inspection tool changed")
        build_tools = {name: {key: value for key, value in row.items() if key in ("version", "launcher_sha256", "executable_sha256")} for name, row in receipt["toolchain"].items()}
        result = {
            "schema_version": 1, "kind": "static_retained_elf_frame_evidence",
            "summary_origin": "read_only_reproduction_script",
            "source_revision": REVISION, "source_manifest_sha256": receipt["source"]["source_manifest_sha256"],
            "receipt": {"run_id": receipt["run_id"], "sha256": RECEIPT_SHA, "status": receipt["status"]},
            "elf": {"sha256": ELF_SHA, "size_bytes": elf_metadata.st_size, "format": "ELF64 little-endian x86-64"},
            "artifact_association": "The saved command log names the retained artifact. The original receipt did not hash the ELF; the inspection hash binds the artifact read afterward.",
            "recorded_command": {key: command[key] for key in ("argv", "status", "exit_code", "seconds", "timeout_seconds", "cleanup_complete", "reaped_descendants")},
            "recorded_child_failure": {"test": CASE, "wait_signal": 17, "wait_code": 3, "wait_status": 11, "expected_pid": True, "wait_signal_name": "SIGCHLD",
                                       "wait_code_name": "CLD_DUMPED", "wait_status_signal_name": "SIGSEGV"},
            "build_toolchain_from_receipt": build_tools, "hardware_from_receipt": receipt["hardware"],
            "inspection_tools": tool_records,
            "inspection_commands": [["nm", "-C", "--defined-only", "ELF"]] + [
                ["objdump", "-d", "-C", f"--start-address={start:#x}", f"--stop-address={end:#x}", "ELF"]
                for _, start, end, _, _ in FRAMES
            ],
            "frames": frames, "direct_call_edges": edges,
            "frame_sum_lower_bound_bytes": sum(row["frame_bytes"] for row in frames),
            "bound_meaning": "Sum of the four simultaneous frame reservations on the identified nested call path if reached; excludes other callers, deeper callees, return addresses and additional stack use.",
            "later_inner_catch_call_site": 0xC4FFA5,
            "limitations": {"actual_fault_address_recorded": False, "actual_stack_extent_measured": False,
                            "actual_deepest_call_reached_proven": False, "stack_overflow_cause_proven": False,
                            "native_qualification": False, "benchmark": False, "elf_executed_by_inspector": False},
        }
        serialized = json.dumps(result, sort_keys=True, indent=2) + "\n"
        publish_summary(args.summary, serialized)
    finally:
        for fd in tool_fds.values():
            os.close(fd)
        os.close(elf_fd)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, UnicodeError, subprocess.SubprocessError):
        raise SystemExit("static inspection failed; no ELF execution was performed") from None
