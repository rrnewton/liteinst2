#!/usr/bin/env python3
"""Closed read-only inspection of the saved 260338fa test ELF.

Never build or execute the inspected ELF. Hash-pin all inputs and inspection
programs, bound tool output/time, and publish normalized evidence exclusively.
This is not a general stack analyzer and does not locate the historical fault.
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

REVISION = "260338fa41073f67f88f451d1de3548955dc94c3"
ELF_SHA = "e9f45affbb2c348d1857d2d5137c6151635a705c2be57540fc8aeb5c65fbcc43"
RECEIPT_SHA = "4ceb4285d31309e2c3f94a332346514b7db221f8041539d0cd861d036aff9738"
LOG_SHA = "23a78f94c861436ff9c1bad937160ea22e737480f5e071da4dd49e57334fd4c1"
TOOLS = {
    "nm": ("1e9d014468a356a030a32edf4f709b521cac91112fe2dda10a505c6e4189e4ed", "GNU nm (GNU Binutils) 2.37"),
    "objdump": ("02e21a57741c6d64f20b1f148c533ffb7373d064b46594d439c05dc4f66d0216", "GNU objdump (GNU Binutils) 2.37"),
}
CASE = "linux::remote::dynamic::owner::admission::runtime::kernel::native_tests::runtime_kernel_default_native_and_cpu_refusals_keep_current_state"
MIB = 1024 * 1024
# Closed ELF-relative addresses, sizes, names and prologues; not runtime PCs.
FRAMES = [
    {
        "id": "with_owner",
        "start": 8936592,
        "size": 3423,
        "symbol": "liteinst_launch::linux::remote::dynamic::owner::admission::runtime::kernel::native_tests::support::with_owner::<liteinst_launch::linux::remote::dynamic::owner::admission::runtime::kernel::native_tests::old_refusal::{closure#0}>",
        "style": "loop",
        "probe_bytes": 122880,
        "tail_bytes": 536,
        "push_bytes": 0,
        "restore": 8939823
    },
    {
        "id": "execute_admission",
        "start": 9960224,
        "size": 6811,
        "symbol": "<liteinst_launch::linux::remote::dynamic::owner::Owner>::execute_admission",
        "style": "loop",
        "probe_bytes": 155648,
        "tail_bytes": 3928,
        "push_bytes": 0,
        "restore": 9966540
    },
    {
        "id": "execute_runtime",
        "start": 10078112,
        "size": 4525,
        "symbol": "<liteinst_launch::linux::remote::dynamic::owner::Owner>::execute_runtime",
        "style": "loop",
        "probe_bytes": 290816,
        "tail_bytes": 904,
        "push_bytes": 0,
        "restore": 10079893
    },
    {
        "id": "runtime_execute",
        "start": 12644256,
        "size": 3296,
        "symbol": "<liteinst_launch::linux::remote::dynamic::owner::admission::runtime::RuntimeOwner>::execute",
        "style": "sub32",
        "probe_bytes": 0,
        "tail_bytes": 2760,
        "push_bytes": 0,
        "restore": 12647475
    },
    {
        "id": "advance",
        "start": 12640896,
        "size": 3347,
        "symbol": "<liteinst_launch::linux::remote::dynamic::owner::admission::runtime::RuntimeOwner>::advance",
        "style": "sub32",
        "probe_bytes": 0,
        "tail_bytes": 2824,
        "push_bytes": 0,
        "restore": 12644201
    },
    {
        "id": "prepare_selected",
        "start": 12749936,
        "size": 10451,
        "symbol": "<liteinst_launch::linux::remote::dynamic::owner::admission::runtime::RuntimeOwner>::prepare_selected",
        "style": "loop",
        "probe_bytes": 442368,
        "tail_bytes": 2064,
        "push_bytes": 8,
        "restore": 12752561
    },
    {
        "id": "selected_allocate",
        "start": 16581040,
        "size": 4124,
        "symbol": "<liteinst_launch::linux::remote::dynamic::owner::admission::runtime::selected::native::PreparedNativeSelected>::allocate",
        "style": "loop",
        "probe_bytes": 221184,
        "tail_bytes": 1192,
        "push_bytes": 0,
        "restore": 16584324
    },
    {
        "id": "array_from_fn",
        "start": 14095680,
        "size": 88,
        "symbol": "core::array::from_fn::<liteinst_launch::linux::remote::dynamic::owner::admission::runtime_native::profile::ControlProfile, 3, <liteinst_launch::linux::remote::dynamic::owner::admission::runtime::selected::native::PreparedNativeSelected>::allocate::{closure#0}>",
        "style": "loop",
        "probe_bytes": 102400,
        "tail_bytes": 2408,
        "push_bytes": 0,
        "restore": 14095760
    },
    {
        "id": "array_try_from_fn",
        "start": 14063392,
        "size": 160,
        "symbol": "core::array::try_from_fn::<core::ops::try_trait::NeverShortCircuit<liteinst_launch::linux::remote::dynamic::owner::admission::runtime_native::profile::ControlProfile>, 3, <core::ops::try_trait::NeverShortCircuit<liteinst_launch::linux::remote::dynamic::owner::admission::runtime_native::profile::ControlProfile>>::wrap_mut_1<usize, <liteinst_launch::linux::remote::dynamic::owner::admission::runtime::selected::native::PreparedNativeSelected>::allocate::{closure#0}>::{closure#0}>",
        "style": "loop",
        "probe_bytes": 311296,
        "tail_bytes": 3096,
        "push_bytes": 0,
        "restore": 14063544
    },
    {
        "id": "array_erased",
        "start": 14084560,
        "size": 592,
        "symbol": "core::array::try_from_fn_erased::<core::ops::try_trait::NeverShortCircuit<liteinst_launch::linux::remote::dynamic::owner::admission::runtime_native::profile::ControlProfile>, <core::ops::try_trait::NeverShortCircuit<liteinst_launch::linux::remote::dynamic::owner::admission::runtime_native::profile::ControlProfile>>::wrap_mut_1<usize, <liteinst_launch::linux::remote::dynamic::owner::admission::runtime::selected::native::PreparedNativeSelected>::allocate::{closure#0}>::{closure#0}>",
        "style": "loop",
        "probe_bytes": 278528,
        "tail_bytes": 1096,
        "push_bytes": 0,
        "restore": 14084722
    },
    {
        "id": "wrap_mut",
        "start": 11766608,
        "size": 106,
        "symbol": "<core::ops::try_trait::NeverShortCircuit<liteinst_launch::linux::remote::dynamic::owner::admission::runtime_native::profile::ControlProfile>>::wrap_mut_1::<usize, <liteinst_launch::linux::remote::dynamic::owner::admission::runtime::selected::native::PreparedNativeSelected>::allocate::{closure#0}>::{closure#0}",
        "style": "loop",
        "probe_bytes": 32768,
        "tail_bytes": 2200,
        "push_bytes": 0,
        "restore": 11766706
    },
    {
        "id": "allocate_closure",
        "start": 16386384,
        "size": 35,
        "symbol": "<liteinst_launch::linux::remote::dynamic::owner::admission::runtime::selected::native::PreparedNativeSelected>::allocate::{closure#0}",
        "style": "sub8",
        "probe_bytes": 0,
        "tail_bytes": 24,
        "push_bytes": 0,
        "restore": 16386414
    },
    {
        "id": "control_default",
        "start": 12221104,
        "size": 285,
        "symbol": "<liteinst_launch::linux::remote::dynamic::owner::admission::runtime_native::profile::ControlProfile as core::default::Default>::default",
        "style": "loop",
        "probe_bytes": 32768,
        "tail_bytes": 2168,
        "push_bytes": 0,
        "restore": 12221381
    },
    {
        "id": "cet_default",
        "start": 16840864,
        "size": 168,
        "symbol": "<liteinst_launch::linux::remote::dynamic::owner::lifecycle::thread::cet::bounded::BoundedCet as core::default::Default>::default",
        "style": "loop",
        "probe_bytes": 32768,
        "tail_bytes": 1976,
        "push_bytes": 0,
        "restore": 16841024
    },
    {
        "id": "status_array_default",
        "start": 16851440,
        "size": 170,
        "symbol": "<[liteinst_launch::linux::remote::dynamic::owner::lifecycle::thread::cet::bounded::CetStatus; 2] as core::default::Default>::default",
        "style": "loop",
        "probe_bytes": 32768,
        "tail_bytes": 200,
        "push_bytes": 0,
        "restore": 16851602
    },
    {
        "id": "status_default",
        "start": 16824688,
        "size": 258,
        "symbol": "<liteinst_launch::linux::remote::dynamic::owner::lifecycle::thread::cet::bounded::CetStatus as core::default::Default>::default",
        "style": "unrolled",
        "probe_bytes": 16384,
        "tail_bytes": 72,
        "push_bytes": 0,
        "restore": 16824938
    }
]
DIRECT_EDGES = (('prepare_selected', 12756289, 'selected_allocate', 16581040), ('selected_allocate', 16582638, 'array_from_fn', 14095680), ('array_from_fn', 14095731, 'array_try_from_fn', 14063392), ('array_try_from_fn', 14063467, 'array_erased', 14084560), ('array_erased', 14084715, 'wrap_mut', 11766608), ('wrap_mut', 11766676, 'allocate_closure', 16386384), ('allocate_closure', 16386405, 'control_default', 12221104), ('control_default', 12221196, 'cet_default', 16840864), ('cet_default', 16840929, 'status_array_default', 16851440), ('status_array_default', 16851492, 'status_default', 16824688))
ANCESTOR_DIRECT_EDGES = (('execute_admission', 9960916, 'execute_runtime', 10078112), ('runtime_execute', 12645388, 'advance', 12640896), ('advance', 12643595, 'prepare_selected', 12749936))

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


def frame_bytes(code: dict[int, str], row: dict) -> int:
    start, pages, tail, pushed = (row[key] for key in ("start", "probe_bytes", "tail_bytes", "push_bytes"))
    allowed_writes = set()

    def exact(address: int, pattern: str, writes: bool = False) -> None:
        require(re.fullmatch(pattern, code.get(address, "")) is not None, "unexpected frame instruction")
        if writes:
            allowed_writes.add(address)

    if pushed:
        require(pushed == 8, "unexpected saved register size")
        exact(start, r"push\s+%rbx", True)
        start += 1
    if row["style"] == "loop":
        require(pages > 0 and pages % 4096 == 0 and 0 <= tail < 4096, "invalid probe components")
        exact(start, r"mov\s+%rsp,%r11")
        exact(start + 3, rf"sub\s+\$0x{pages:x},%r11")
        exact(start + 10, r"sub\s+\$0x1000,%rsp", True)
        exact(start + 17, r"movq\s+\$0x0,\(%rsp\)")
        exact(start + 25, r"cmp\s+%r11,%rsp")
        exact(start + 28, rf"jne\s+{start + 10:x}\s+<.*>")
        exact(start + 30, rf"sub\s+\$0x{tail:x},%rsp", True)
    elif row["style"] == "unrolled":
        require(pages == 16384 and pushed == 0, "unexpected unrolled shape")
        for offset in (0, 15, 30, 45):
            exact(start + offset, r"sub\s+\$0x1000,%rsp", True)
            exact(start + offset + 7, r"movq\s+\$0x0,\(%rsp\)")
        exact(start + 60, rf"sub\s+\$0x{tail:x},%rsp", True)
    else:
        require(row["style"] in ("sub32", "sub8") and pages == 0 and pushed == 0, "unexpected simple shape")
        exact(start, rf"sub\s+\$0x{tail:x},%rsp", True)
    restored = row["restore"]
    exact(restored, rf"add\s+\$0x{pages + tail:x},%rsp", True)
    after_restore = restored + (4 if row["style"] == "sub8" else 7)
    if pushed:
        exact(after_restore, r"pop\s+%rbx", True)
        after_restore += 1
    exact(after_restore, r"ret")
    # Every other destination-RSP instruction would invalidate the closed frame
    # proof. The only restoration is immediately followed by the real return.
    for address, instruction in code.items():
        mnemonic = instruction.split(None, 1)[0]
        writes = mnemonic in ("push", "pop", "leave") or (
            instruction.endswith(",%rsp") and mnemonic not in ("cmp", "test"))
        require(not writes or address in allowed_writes, "unaccounted stack-pointer write")
    return pages + tail + pushed


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
    require(receipt["environment"]["RLIMIT_CORE"] == 0 and "RUST_MIN_STACK" not in receipt["environment"], "recorded stack/core configuration differs")
    matches = [row for row in receipt["commands"] if row["id"] == "workspace_tests"]
    require(len(matches) == 1, "workspace command identity differs")
    command = matches[0]
    require(command["argv"] == ["cargo", "test", "--workspace"] and command["private_log_sha256"] == LOG_SHA, "workspace command differs")
    require(command["status"] == "failed" and command["exit_code"] == 101, "recorded workspace result differs")
    log = read_small(args.workspace_log, LOG_SHA, 8 * MIB).decode("utf-8")
    diagnostic = f'runtime isolated case "{CASE}" failed: isolated child did not exit normally with zero: signal=17, code=3, status=11, expected_pid=true'
    require(log.splitlines().count(diagnostic) == 1, "saved child status differs")
    require(log.splitlines().count("     Running unittests src/lib.rs (target/debug/deps/liteinst_launch-11d49a8d76592146)") == 1, "saved artifact reference differs")
    require(log.splitlines().count('isolated stderr prefix: ""') == 1, "saved stderr record differs")
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
        symbols = capture(tool_fds["nm"], "nm", ["-S", "-C", "--defined-only", elf_argument], elf_fd, 16 * MIB).decode("utf-8")
        selected = {row["start"]: row for row in FRAMES}
        found = set()
        for line in symbols.splitlines():
            match = re.fullmatch(r"([0-9a-f]{16}) ([0-9a-f]{16}) [tT] (.+)", line)
            if match and int(match[1], 16) in selected:
                start = int(match[1], 16)
                row = selected[start]
                require(start not in found and int(match[2], 16) == row["size"] and match[3] == row["symbol"], "selected symbol differs")
                found.add(start)
        require(found == set(selected), "missing selected symbol")
        codes = {}
        frames = []
        for row in FRAMES:
            start, end = row["start"], row["start"] + row["size"]
            argv = ["-d", "-C", f"--start-address={start:#x}", f"--stop-address={end:#x}", elf_argument]
            data = capture(tool_fds["objdump"], "objdump", argv, elf_fd, MIB)
            (args.private_dir / f'{row["id"]}.txt').write_bytes(data)
            codes[row["id"]] = instructions(data.decode("utf-8"))
            frames.append({"id": row["id"], "function": row["symbol"], "elf_virtual_address": start,
                           "code_size_bytes": row["size"], "probe_bytes": row["probe_bytes"], "tail_bytes": row["tail_bytes"],
                           "saved_register_bytes": row["push_bytes"], "frame_bytes": frame_bytes(codes[row["id"]], row)})
        edges = []
        for kind, rows in (("direct_constructor_chain", DIRECT_EDGES), ("ancestor_direct_subset", ANCESTOR_DIRECT_EDGES)):
            for caller, address, callee, target in rows:
                require(re.fullmatch(rf"call\s+{target:x}\s+<.*>", codes[caller].get(address, "")) is not None, "call edge differs")
                edges.append({"kind": kind, "caller": caller, "call_site": address, "callee": callee, "target": target})
        require(digest_fd(elf_fd, 256 * MIB)[0] == ELF_SHA, "ELF changed during inspection")
        for name, fd in tool_fds.items():
            require(digest_fd(fd, 64 * MIB)[0] == TOOLS[name][0], "inspection tool changed")
        direct_sum = sum(row["frame_bytes"] for row in frames[5:])
        extended_sum = sum(row["frame_bytes"] for row in frames)
        require(direct_sum == 1519736 and extended_sum == 2100032, "closed arithmetic differs")
        build_tools = {name: {key: value for key, value in row.items() if key in ("version", "launcher_sha256", "executable_sha256")} for name, row in receipt["toolchain"].items()}
        result = {
            "schema_version": 1, "kind": "static_retained_selected_elf_frame_evidence",
            "summary_origin": "read_only_reproduction_script", "reproduction_script_executed": True,
            "source_revision": REVISION, "source_manifest_sha256": receipt["source"]["source_manifest_sha256"],
            "receipt": {"run_id": receipt["run_id"], "sha256": RECEIPT_SHA, "status": receipt["status"]},
            "elf": {"sha256": ELF_SHA, "size_bytes": elf_metadata.st_size, "format": "ELF64 little-endian x86-64"},
            "artifact_association": "The saved command log names the retained artifact. The original receipt did not hash the ELF; the inspection hash binds the artifact read afterward.",
            "recorded_command": {key: command[key] for key in ("argv", "status", "exit_code", "seconds", "timeout_seconds", "cleanup_complete", "reaped_descendants")},
            "recorded_child_failure": {"test": CASE, "wait_signal": 17, "wait_code": 3, "wait_status": 11, "expected_pid": True,
                                       "wait_signal_name": "SIGCHLD", "wait_code_name": "CLD_DUMPED", "wait_status_signal_name": "SIGSEGV", "stderr_empty": True},
            "recorded_core_limit_bytes": 0,
            "build_toolchain_from_receipt": build_tools, "hardware_from_receipt": receipt["hardware"],
            "inspection_tools": tool_records,
            "inspection_commands": [["nm", "-S", "-C", "--defined-only", "ELF"]] + [
                ["objdump", "-d", "-C", f'--start-address={row["start"]:#x}', f'--stop-address={row["start"] + row["size"]:#x}', "ELF"]
                for row in FRAMES],
            "frames": frames, "direct_call_edges": edges,
            "direct_constructor_chain": {"frame_ids": [row["id"] for row in frames[5:]], "frame_sum_lower_bound_bytes": direct_sum,
                                         "connection": "All ten direct call edges are checked in the retained ELF."},
            "source_connected_extension": {"frame_ids": [row["id"] for row in frames], "conditional_frame_sum_bytes": extended_sum,
                                           "default_stack_request_bytes": 2 * MIB, "above_default_request_bytes": extended_sum - 2 * MIB,
                                           "connection": "Pinned source connects the five additional ancestors through closure/catch boundaries; only the three listed ancestor direct edges are checked here. This is not a fully machine-reconstructed call chain."},
            "bound_meaning": "Conditional sums of simultaneously reserved frames if the named source path reaches the deepest constructor. Both exclude return addresses, unlisted trampolines, other callers and deeper callees; neither is an upper bound or a measurement of the historical execution.",
            "limitations": {"actual_fault_address_recorded": False, "actual_stack_extent_measured": False,
                            "actual_deepest_call_reached_proven": False, "stack_overflow_cause_proven": False,
                            "native_qualification": False, "benchmark": False, "elf_executed_by_inspector": False},
        }
        publish_summary(args.summary, json.dumps(result, sort_keys=True, indent=2) + "\n")
    finally:
        for fd in tool_fds.values():
            os.close(fd)
        os.close(elf_fd)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, UnicodeError, subprocess.SubprocessError):
        raise SystemExit("static inspection failed; no ELF execution was performed") from None
