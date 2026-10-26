"""One actual exec/ld.so invocation with a pre-syscall mapping witness.

This is a closed fixture driver, not general MAP_FIXED authorization. It never
sets registers, writes tracee memory, installs breakpoints, or replaces an
application instruction. Every declared launch remains a separate invocation.
"""
import ctypes as C
import json
import os
from pathlib import Path
import signal
import struct
import sys
import time
from bootstrap_validate import PAGE, Invalid, need, sha, up
from common import indirect_definition, intersects
from frozen_profile import elf, validate_launch_environment
from mapping_identity import require_mapping_identity
from ownership import generated_owner, module_bias, source_owner
from trace_primitives import (authenticate_page, cstring, file_fd_identity,
                              map_rows, ptrace, readmem, registers, stopped,
                              wait_owned)

PTRACE_SYSCALL = 24
PTRACE_SETOPTIONS = 0x4200
PTRACE_GET_SYSCALL_INFO = 0x420e
OPTIONS = 0x1 | 0x2 | 0x4 | 0x8 | 0x10 | 0x100000
EXPECTED_STDOUT = bytes.fromhex("63617272696572206d6978206f6b0a00")
ENV = {"LC_ALL": "C", "PATH": "/usr/bin:/bin"}
MAX_STOPS = 20000
TRACE_SECONDS = 15


def save(path, value):
    with path.open("x") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")


def syscall_info(pid):
    # Linux UAPI ptrace_syscall_info: fixed header24, entry nr+args56,
    # exit result+is_error9. No entry/exit toggle inference around EXEC.
    raw = (C.c_ubyte * 88)()
    size = ptrace(PTRACE_GET_SYSCALL_INFO, pid, 88, C.byref(raw))
    data = bytes(raw)
    op = data[0]
    need(op in (1, 2) and size >= (80 if op == 1 else 33), "full syscall entry/exit metadata")
    arch = struct.unpack_from("<I", data, 4)[0]
    need(arch == 0xc000003e, "native x86-64 syscall ABI")
    ip, sp = struct.unpack_from("<QQ", data, 8)
    if op == 1:
        return dict(op=op, ip=ip, sp=sp, nr=struct.unpack_from("<Q", data, 24)[0],
                    args=list(struct.unpack_from("<6Q", data, 32)))
    return dict(op=op, ip=ip, sp=sp, result=struct.unpack_from("<q", data, 24)[0], is_error=data[32])


def one_thread(pid):
    entries = []
    with os.scandir(f"/proc/{pid}/task") as scan:
        for entry in scan:
            entries.append(Path(entry.path))
            need(len(entries) <= 1, "unexpected peer detected without unbounded enumeration")
    need(len(entries) == 1 and entries[0].name == str(pid), "closed fixture has exactly one thread")
    return [int(p.name) for p in entries]


def stack_buffer(pid, address, length, sp):
    _, rows = map_rows(pid)
    owners = [m for m in rows if m["lo"] <= address and address + length <= m["hi"]]
    need(len(owners) == 1 and owners[0]["perms"] == "rw-p" and owners[0]["path"] == "[stack]", "whole actual bootstrap stack buffer")
    need(owners[0]["lo"] <= sp < owners[0]["hi"], "buffer and live RSP share actual stack")


def module_runtime(pid, module):
    _, rows = map_rows(pid)
    headers, _ = elf(module["original_blob"])
    bias = module_bias(rows, module["path"], module["identity"]["backing"], headers)
    need(module["case"]["elf_type"] != 2 or bias == 0, "ET_EXEC actually loaded at linked address")
    prior = module.get("bias")
    need(prior is None or prior == bias, "module bias immutable within invocation")
    module["bias"] = bias
    return bias


def bootstrap_at(pid, pc, modules):
    _, rows = map_rows(pid)
    found = []
    for module in modules.values():
        if module["origin"] != "E9-output":
            continue
        led = module["verified"]["ledger"]
        owners = [m for m in rows if m["path"] == module["path"] and m["lo"] <= pc < m["hi"]]
        if not owners:
            continue
        need(len(owners) == 1, "single actual bootstrap VMA owner")
        m = owners[0]
        file_at = m["offset"] + pc - m["lo"]
        p = led["loader"]
        if not p["offset"] <= file_at < p["offset"] + p["filesz"]:
            continue
        need(m["perms"] == "r-xp", "bootstrap exact RX mapping")
        require_mapping_identity(tuple(module["identity"]["backing"]), m["major"], m["minor"], m["inode"])
        bias = module_runtime(pid, module)
        need(pc == bias + p["vaddr"] + file_at - p["offset"], "bootstrap VMA exact bias/file relation")
        need(readmem(pid, bias + p["vaddr"], p["filesz"]) == module["blob"][p["offset"]:p["offset"] + p["filesz"]], "full actual compiled and generated bootstrap bytes")
        found.append(module)
    need(len(found) <= 1, "unambiguous bootstrap identity")
    return found[0] if found else None


def admit_bootstrap(pid, info, module):
    nr, args = info["nr"], info["args"]
    pc = info["ip"] - 2
    led = module["verified"]["ledger"]
    state = module["state"]
    bias = module["bias"]
    local = pc - bias - led["loader"]["vaddr"]
    need(readmem(pid, pc, 2) == b"\x0f\x05", "actual syscall instruction at recorded PC")
    need(state["calls"] < 7, "seven closed bootstrap syscalls")
    rows = [row for row in led["rows"] if row["syscall"] == local]
    item = dict(pc=pc, nr=nr, args=args, module=module["case"]["id"])
    if rows:
        need(len(rows) == 1 and state["file_fd"] is not None, "single decoded mapping with authenticated fd")
        row = rows[0]
        need(row == led["rows"][len(state["mapped"])] and nr == 9, "ordered mapping ledger")
        want = [bias + row["address"], row["length"], 5, 0x12, state["file_fd"], row["offset"]]
        need(args == want and row["length"] == PAGE, "exact actual MAP_FIXED tuple")
        raw, maps = map_rows(pid)
        if row["address"] == led["source_page"]:
            original_headers, _ = elf(module["original_blob"])
            p = next(p for p in original_headers if p[0] == 1 and p[3] // PAGE * PAGE == led["source_page"])
            old_offset = p[2] // PAGE * PAGE
            ownership = source_owner(maps, args[0], old_offset, module["path"], module["identity"]["backing"])
            need(readmem(pid, args[0], PAGE) == module["original_blob"][old_offset:old_offset + PAGE].ljust(PAGE, b"\0"), "entire old source page before overwrite")
        else:
            output_headers, _ = elf(module["blob"])
            ownership = generated_owner(maps, args[0], PAGE, module["path"], module["identity"]["backing"], bias, output_headers)
        item.update(kind="mmap", row=row, ownership=ownership, maps_before=raw)
    elif local == led["close_pc"]:
        need(nr == 3 and args[0] == state["file_fd"] and len(state["mapped"]) == 2, "exact close after both redirects")
        item["kind"] = "close"
    else:
        need(local < led["compiled"]["prefix_size"], "no unknown generated-suffix syscall")
        if nr == 2:
            path = cstring(pid, args[0])
            if state["directory_fd"] is None:
                need(state["calls"] == 0 and path == "/proc/self/map_files/" and args[1:3] == [0x10000, 0], "exact first bootstrap directory open")
                item["kind"] = "directory"
            else:
                need(state["calls"] == 3 and state["file_fd"] is None and path == module["path"] and args[1:3] == [0, 0], "exact mapped-module backing open")
                item["kind"] = "file"
            item["path"] = path
        elif nr == 217:
            need(state["calls"] == 1 and args[0] == state["directory_fd"] and args[2] == 8192, "one finite directory batch")
            stack_buffer(pid, args[1], args[2], info["sp"])
            item["kind"] = "getdents"
        elif nr == 89:
            need(state["calls"] == 2 and args[2] == 8192, "one exact bootstrap readlink")
            raw, maps = map_rows(pid)
            owners = [m for m in maps if m["lo"] <= pc < m["hi"]]
            need(len(owners) == 1, "unique loader readlink VMA")
            m = owners[0]
            path = cstring(pid, args[0])
            need(path == f"/proc/self/map_files/{m['lo']:x}-{m['hi']:x}", "exact actual loader map_files link")
            stack_buffer(pid, args[1], args[2], info["sp"])
            item.update(kind="readlink", path=path, maps_before=raw)
        else:
            raise Invalid("unexpected bootstrap syscall before execution: " + str(nr))
    return item


def finish_bootstrap(pid, info, item, module, protected):
    need(info["is_error"] == 0 and info["result"] >= 0, "bootstrap syscall succeeded")
    result, state = info["result"], module["state"]
    item["result"] = result
    kind = item["kind"]
    if kind == "directory":
        state["directory_fd"] = result
    elif kind == "getdents":
        need(0 < result <= 8192, "nonempty bounded directory batch")
    elif kind == "readlink":
        need(result == len(os.fsencode(module["path"])), "complete exact module readlink length")
        need(readmem(pid, item["args"][1], result) == os.fsencode(module["path"]), "exact module readlink bytes")
    elif kind == "file":
        state["file_fd"] = result
        state["file_identity"] = file_fd_identity(pid, result, module["path"], module["blob"])
        need(state["file_identity"]["backing"] == module["identity"]["backing"], "opened backing and initial VMA identity agree")
        item["file_identity"] = state["file_identity"]
    elif kind == "mmap":
        row = item["row"]
        need(result == module["bias"] + row["address"], "exact returned mapping address")
        item["page_after"] = authenticate_page(pid, result, row["offset"], 5, module["path"], module["blob"], state["file_identity"])
        state["mapped"].append(row)
        protected.append((result, PAGE))
    elif kind == "close":
        need(result == 0, "exact bootstrap fd close")
        state["closed"] = True
    state["calls"] += 1


def final_modules(pid, modules):
    dso = modules["dso"]
    dso_bias = module_runtime(pid, dso)
    indirect = dso_bias + indirect_definition(dso["original_blob"])
    result = {}
    for name, module in modules.items():
        bias = module_runtime(pid, module)
        verified = module["verified"]
        pages = []
        if module["origin"] == "E9-output":
            state = module["state"]
            need(state["calls"] == 7 and state["closed"] and len(state["mapped"]) == 2, "all seven bootstrap syscalls and both pages required")
            for row in verified["ledger"]["rows"]:
                pages.append(authenticate_page(pid, bias + row["address"], row["offset"], 5, module["path"], module["blob"], module["identity"]))
        else:
            need(module["state"]["calls"] == 0, "explicit zero bootstrap calls for original")
            headers, _ = elf(module["original_blob"])
            p = next(p for p in headers if p[0] == 1 and p[1] == 5)
            pages.append(authenticate_page(pid, bias + p[3] // PAGE * PAGE, p[2] // PAGE * PAGE, 5, module["path"], module["blob"], module["identity"]))
        writes = []
        for row in verified["relocation_writes"]:
            need(row["width"] == 8, "exact eight-byte declared dynamic write")
            value = indirect if row["kind"] == 7 else bias + row["symbol_value"]
            address = bias + row["target"]
            raw, maps = map_rows(pid)
            owners = [m for m in maps if m["lo"] <= address and address + 8 <= m["hi"]]
            need(len(owners) == 1 and owners[0]["perms"] == "rw-p", "whole relocation target still RW")
            m = owners[0]
            need(m["path"] == module["path"] and m["offset"] + address - m["lo"] == row["target_file_offset"], "relocation target exact file ownership")
            require_mapping_identity(tuple(module["identity"]["backing"]), m["major"], m["minor"], m["inode"])
            actual = readmem(pid, address, 8)
            need(actual == struct.pack("<Q", value), "exact dynamic relocation value, no pointer normalization")
            writes.append(dict(address=address, expected=value, bytes_hex=actual.hex(), record=row, vma=m))
        need(len(writes) == 1, "one dynamic write in each common fixture")
        result[name] = dict(bias=bias, path=module["path"], file_sha256=sha(module["blob"]),
                            identity=module["identity"], pages=pages, dynamic_writes=writes,
                            bootstrap_calls=module["state"]["calls"])
    return result


def trace(case, modules, interpreter, out):
    """Called only after exact source/artifact/request binding by the entrypoint."""
    need(set(modules) == {"main", "dso"}, "two fixed modules")
    validate_launch_environment(ENV, None)
    out.mkdir()
    owned = False
    pid = None
    fds = []
    events = []
    pending = None
    executed = False
    app_write = False
    final = None
    protected = []
    loader_evidence = None
    deadline = time.monotonic() + TRACE_SECONDS
    try:
        for module in modules.values():
            path = Path(module["path"])
            need(path.is_absolute() and not path.is_symlink() and path.read_bytes() == module["blob"], "exact immutable launch file")
            fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
            fds.append(fd)
            module["identity"] = file_fd_identity(os.getpid(), fd, str(path), module["blob"])
            module["state"] = dict(directory_fd=None, file_fd=None, calls=0, mapped=[], closed=False)
        loader_blob = Path(interpreter["path"]).read_bytes()
        need(sha(loader_blob) == interpreter["sha256"], "whole pinned interpreter bytes")
        loader_fd = os.open(interpreter["path"], os.O_RDONLY | os.O_CLOEXEC)
        fds.append(loader_fd)
        loader_identity = file_fd_identity(os.getpid(), loader_fd, interpreter["path"], loader_blob)
        so = os.open(out / "application.stdout", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        se = os.open(out / "application.stderr", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            pid = os.fork()
            if pid == 0:
                try:
                    os.dup2(so, 1); os.dup2(se, 2)
                    os.close(so); os.close(se)
                    for fd in fds: os.close(fd)
                    os.chdir(Path(modules["main"]["path"]).parent)
                    ptrace(0, 0)
                    os.kill(os.getpid(), signal.SIGSTOP)
                    os.execve(modules["main"]["path"], [modules["main"]["path"]], ENV)
                except BaseException:
                    os._exit(127)
            owned = True
        finally:
            os.close(so); os.close(se)
        stopped(wait_owned(pid, deadline), signal.SIGSTOP)
        need(os.readlink(f"/proc/{pid}/ns/mnt") == os.readlink("/proc/self/ns/mnt"), "parent file descriptors and child VMAs share mount namespace")
        one_thread(pid)
        ptrace(PTRACE_SETOPTIONS, pid, data=OPTIONS)
        for stop_index in range(MAX_STOPS):
            ptrace(PTRACE_SYSCALL, pid)
            status = wait_owned(pid, deadline)
            if os.WIFEXITED(status) or os.WIFSIGNALED(status):
                owned = False
                need(os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0, "actual application successful exit")
                need(executed and app_write and final is not None, "real exec, checked value/output path and module evidence required")
                break
            need(os.WIFSTOPPED(status), "owned stopped process")
            one_thread(pid)
            event = status >> 16
            if event:
                need(event == 4 and not executed, "one EXEC event, no unexpected forks/clones/peers")
                executed = True
                need(os.readlink(f"/proc/{pid}/exe") == modules["main"]["path"], "actual executable file")
                _, maps = map_rows(pid)
                actual_loader = [m for m in maps if m["path"] == interpreter["path"] and m["perms"] == "r-xp"]
                need(len(actual_loader) == 1, "kernel selected the exact pinned interpreter")
                lm = actual_loader[0]
                require_mapping_identity(tuple(loader_identity["backing"]), lm["major"], lm["minor"], lm["inode"])
                need(0 < lm["hi"] - lm["lo"] <= 256 * PAGE, "finite actual interpreter RX inventory")
                pages = [authenticate_page(pid, a, lm["offset"] + a - lm["lo"], 5, interpreter["path"], loader_blob, loader_identity)
                         for a in range(lm["lo"], lm["hi"], PAGE)]
                loader_evidence = dict(identity=loader_identity, pages=pages)
                continue
            stopped(status, signal.SIGTRAP | 0x80)
            info = syscall_info(pid)
            if info["op"] == 1:
                need(pending is None, "no unmatched syscall entry")
                nr, args = info["nr"], info["args"]
                if not executed:
                    need(nr == 59 and cstring(pid, args[0]) == modules["main"]["path"], "only exact requested exec before loader")
                    pending = dict(kind="exec", info=info)
                    continue
                need(nr not in (56, 57, 58, 435, 101, 311, 323), "no clone/fork/ptrace/remote-write/userfault authority")
                module = bootstrap_at(pid, info["ip"] - 2, modules)
                if module is not None:
                    item = admit_bootstrap(pid, info, module)
                    pending = dict(kind="bootstrap", item=item, module=module, info=info)
                else:
                    # Once installed, even trusted loader code cannot change
                    # these mappings while this witness claims exact ownership.
                    if nr in (9, 10, 11, 25, 329) and protected:
                        length = args[1]
                        need(length > 0 and all(not intersects(args[0], length, a, n) for a, n in protected), "no later mapping/protection mutation of admitted code")
                        if nr == 25 and args[3] & 2:
                            need(all(not intersects(args[4], args[2], a, n) for a, n in protected), "no mremap destination over admitted code")
                    if nr == 1:
                        need(not app_write and args[0] == 1 and args[2] == len(EXPECTED_STDOUT), "one exact fixture output syscall")
                        main_bias = module_runtime(pid, modules["main"])
                        headers, _ = elf(modules["main"]["original_blob"])
                        need(any(p[0] == 1 and p[1] == 5 and main_bias + p[3] <= info["ip"] - 2 < main_bias + p[3] + p[5] for p in headers), "output from actual original main RX body")
                        need(readmem(pid, args[1], args[2]) == EXPECTED_STDOUT, "exact application output buffer")
                        final = final_modules(pid, modules)
                        raw, maps = map_rows(pid)
                        allowed_files = {m["path"] for m in modules.values()} | {interpreter["path"]}
                        for m in maps:
                            if "x" in m["perms"]:
                                need(m["path"] in allowed_files or m["path"] in ("[vdso]", "[vsyscall]"), "no other executable file or anonymous code")
                        need(loader_evidence is not None, "actual interpreter entry proof required")
                        for page in loader_evidence["pages"]:
                            authenticate_page(pid, page["address"], page["offset"], 5, interpreter["path"], loader_blob, loader_identity)
                        (out / "final-maps.txt").write_text(raw)
                        app_write = True
                    if nr in (60, 231):
                        need(app_write and args[0] == 0, "fixture exits only after its checked output path")
                    pending = dict(kind="ordinary", info=info)
            else:
                need(pending is not None, "no unmatched syscall exit")
                if pending["kind"] == "bootstrap":
                    finish_bootstrap(pid, info, pending["item"], pending["module"], protected)
                    events.append(pending["item"])
                elif pending["kind"] == "exec":
                    need(executed and info["result"] == 0 and not info["is_error"], "actual successful exec return stop")
                elif pending["info"]["nr"] == 1:
                    need(info["result"] == len(EXPECTED_STDOUT) and not info["is_error"], "complete original output write")
                pending = None
        else:
            raise Invalid("20,000-stop trace bound")
        need((out / "application.stdout").read_bytes() == EXPECTED_STDOUT and (out / "application.stderr").read_bytes() == b"", "literal required stdout/stderr")
        expected_modules = sum(m["origin"] == "E9-output" for m in modules.values())
        need(len(events) == 7 * expected_modules, "exact bootstrap count, including explicit baseline zero")
        for module in modules.values():
            need(Path(module["path"]).read_bytes() == module["blob"], "launch files unchanged afterward")
        save(out / "complete.json", dict(status="PASS_CLOSED_FIXTURE_LOADER_WITNESS", case=case,
             stops=stop_index + 1, elapsed_seconds=time.monotonic() - (deadline - TRACE_SECONDS),
             expected_bootstrap_modules=expected_modules, bootstrap_syscalls=events, modules=final,
             interpreter=loader_evidence,
             application_stdout_sha256=sha(EXPECTED_STDOUT), application_stderr_sha256=sha(b""),
             single_thread_checks=True, register_writes=0, memory_writes=0,
             architectural_state_oracle=False, generic_loader_admission=False))
    except BaseException as error:
        for sig in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT): signal.signal(sig, signal.SIG_IGN)
        save(out / "failed-incomplete.json", dict(status="FAILED", case=case, error=repr(error),
             observed_bootstrap_syscalls=events, owned_child=pid if owned else None))
        raise
    finally:
        if owned:
            os.kill(pid, signal.SIGKILL)
            status = wait_owned(pid, time.monotonic() + 2)
            need(os.WIFSIGNALED(status) and os.WTERMSIG(status) == signal.SIGKILL, "owned tracee cleanup")
            owned = False
        for fd in fds: os.close(fd)
