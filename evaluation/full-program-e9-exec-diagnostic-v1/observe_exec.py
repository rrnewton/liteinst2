"""GDB-only, one-run observer; CONFIG is supplied by the bounded owner argv."""
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import time
import gdb

C = json.loads(Path(CONFIG).read_bytes())
OUT = Path(C["out"])
TRACE = (OUT / "trace.jsonl").open("x")
written = 0
last = None
exited = None
pid = None
entered = False
pending_syscall = None
exec_seen = False
entry_seen = False
negative_return = None
entry_break = None


def emit(kind, **values):
    global written
    raw = json.dumps(dict(kind=kind, monotonic=time.monotonic(), **values), sort_keys=True) + "\n"
    size = len(raw.encode())
    if written + size > 262144:
        raise RuntimeError("diagnostic trace cap")
    written += size
    TRACE.write(raw); TRACE.flush()


def small(path, cap=65536):
    with open(path, "rb") as f:
        data = f.read(cap + 1)
    if len(data) > cap:
        raise RuntimeError("bounded metadata read")
    return data


def reg(name):
    return int(gdb.parse_and_eval("$" + name)) & ((1 << 64) - 1)


def optional(command):
    try:
        return gdb.execute(command, to_string=True)
    except gdb.error as e:
        return "UNAVAILABLE: " + str(e)


def text_at(address):
    data = bytearray()
    for i in range(4096):
        b = bytes(gdb.selected_inferior().read_memory(address + i, 1))
        if b == b"\0":
            return data.decode("ascii")
        data += b
    raise RuntimeError("unterminated exec string")


def vector_at(address):
    result = []
    for i in range(8):
        p, = struct.unpack("<Q", bytes(gdb.selected_inferior().read_memory(address + i * 8, 8)))
        if p == 0:
            return result
        result.append(text_at(p))
    raise RuntimeError("exec vector cap")


def snapshot():
    result = dict(pid=gdb.selected_inferior().pid)
    for name in ("stat", "status", "limits", "maps"):
        try:
            result[name] = small(f"/proc/{result['pid']}/{name}").decode()
        except (OSError, RuntimeError) as e:
            result[name + "_unavailable"] = str(e)
    try:
        result["exe"] = os.readlink(f"/proc/{result['pid']}/exe")
    except OSError as e:
        result["exe_unavailable"] = str(e)
    return result


def stopped(event):
    global last
    last = dict(type=type(event).__name__, details=dict(getattr(event, "details", {})))
    if isinstance(event, gdb.BreakpointEvent):
        last["breakpoints"] = [b.number for b in event.breakpoints]
    if isinstance(event, gdb.SignalEvent):
        last["signal"] = event.stop_signal


def ended(event):
    global exited
    exited = dict(exit_code=getattr(event, "exit_code", None))
    try:
        exited["exit_signal"] = int(gdb.parse_and_eval("$_exitsignal"))
    except (gdb.error, TypeError, ValueError):
        exited["exit_signal"] = None
    emit("inferior_exited", **exited)


def catch(command):
    old = {b.number for b in gdb.breakpoints() or ()}
    gdb.execute(command)
    new = [b for b in gdb.breakpoints() if b.number not in old]
    if len(new) != 1 or not new[0].enabled:
        raise RuntimeError("catchpoint admission")
    return new[0]


complete = False
try:
    for command in ("set pagination off", "set confirm off", "set startup-with-shell off",
                    "set disable-randomization off", "set follow-exec-mode same",
                    "set detach-on-fork off", "set schedule-multiple off",
                    "set auto-solib-add off", "set print thread-events off",
                    "handle SIGSEGV SIGBUS SIGILL SIGABRT SIGFPE SIGSYS SIGXCPU SIGXFSZ stop print pass"):
        gdb.execute(command)
    syscall = catch("catch syscall execve execveat")
    successful_exec = catch("catch exec")
    gdb.events.stop.connect(stopped)
    gdb.events.exited.connect(ended)
    emit("armed_before_run", gdb_version=gdb.VERSION, syscall=syscall.number,
         exec_event=successful_exec.number, startup_with_shell=False, aslr_unchanged=True,
         planned_runs=1, candidate_entry_file_va=8857174016)
    gdb.execute("run")  # The only launch. No start/restart/attach or inferior function calls.
    for stop_number in range(16):
        if exited is not None:
            complete = True
            break
        inf = gdb.selected_inferior()
        if not last or not inf.pid or (pid is not None and pid != inf.pid):
            raise RuntimeError("missing stop or changed inferior PID")
        pid = inf.pid
        event = last; last = None
        emit("stop", number=stop_number, pid=pid, event=event,
             registers=optional("info registers rip rax orig_rax rdi rsi rdx r10 r8"))
        points = event.get("breakpoints", [])
        reason = event.get("details", {}).get("reason")
        if syscall.number in points:
            number = int(event["details"]["syscall-number"])
            if number != reg("orig_rax"):
                raise RuntimeError("syscall detail/register identity")
            if reason == "syscall-entry":
                if entered or pending_syscall is not None:
                    raise RuntimeError("second exec request refused before resume")
                if number == 322:
                    fd = reg("rdi")
                    if text_at(reg("rsi")) != "" or reg("r8") != 4096:
                        raise RuntimeError("execveat empty-path contract")
                    argv, env = vector_at(reg("rdx")), vector_at(reg("r10"))
                elif number == 59:
                    match = re.fullmatch(r"/proc/self/fd/([0-9]+)", text_at(reg("rdi")))
                    if not match:
                        raise RuntimeError("execve descriptor fallback contract")
                    fd = int(match.group(1))
                    argv, env = vector_at(reg("rsi")), vector_at(reg("rdx"))
                else:
                    raise RuntimeError("unexpected exec syscall")
                if fd < 3 or argv != ["e9patch", "--help"] or len(env) != 4 or dict(x.split("=", 1) for x in env) != C["subject_environment"]:
                    raise RuntimeError("candidate argv/environment/fd contract")
                q = snapshot()
                if q.get("status", "").split("Cpus_allowed_list:\t")[-1].splitlines()[0] != str(C["cpu"]):
                    raise RuntimeError("subject singleton CPU")
                limits = q.get("limits", "")
                for name, value in (("Max address space", 1073741824), ("Max cpu time", 5),
                                    ("Max file size", 65536), ("Max core file size", 0)):
                    if not re.search(r"^" + name + r"\s+" + str(value) + r"\s+" + str(value) + r"\s+", limits, re.M):
                        raise RuntimeError("subject limit readback: " + name)
                path = f"/proc/{pid}/fd/{fd}"
                with open(path, "rb") as f:
                    before = os.fstat(f.fileno())
                    data = os.pread(f.fileno(), 282325, 0)
                    after = os.fstat(f.fileno())
                fields = lambda s: [s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns]
                if fields(before) != fields(after) or fields(before) != C["candidate_stat"] or len(data) != 282324 or hashlib.sha256(data).hexdigest() != C["candidate_sha256"]:
                    raise RuntimeError("actual exec descriptor identity")
                emit("candidate_exec_request", syscall=number, fd=fd, argv=argv, environment=env,
                     fd_link=os.readlink(path), fd_stat=fields(before), metadata=q)
                entered = True
                pending_syscall = number
            elif reason == "syscall-return":
                if not entered or pending_syscall is None or number != pending_syscall:
                    raise RuntimeError("syscall return without matching authenticated request")
                # A successful exec may also produce an exec-syscall return stop.
                signed_rax = reg("rax") - (1 << 64) if reg("rax") >> 63 else reg("rax")
                emit("exec_syscall_return", syscall=number, signed_rax=signed_rax, successful_exec_seen=exec_seen)
                if not exec_seen and -4095 <= signed_rax < 0:
                    negative_return = signed_rax
                pending_syscall = None
                # Keep the catchpoint armed: a libc fallback is an explicit refusal, not a hidden retry.
            else:
                raise RuntimeError("syscall stop lacks explicit entry/return reason")
        elif successful_exec.number in points:
            if reason != "exec" or not entered or exec_seen or pending_syscall not in (59, 322):
                raise RuntimeError("exec event reason/order/pending request")
            exec_seen = True
            aux = small(f"/proc/{pid}/auxv", 4096)
            if len(aux) % 16:
                raise RuntimeError("auxv extent")
            pairs = list(struct.iter_unpack("<QQ", aux))
            tags = dict(pairs)
            if pairs[-1] != (0, 0) or len(tags) != len(pairs) or tags.get(4) != 56 or tags.get(5) != 13 or tags.get(9) != tags.get(3, 0) - 64 + 8857174016:
                raise RuntimeError("candidate AT_ENTRY/PHDR join")
            entry = tags[9]
            emit("successful_exec_event", at_entry=entry, auxv=pairs, metadata=snapshot())
            entry_break = catch("hbreak *" + hex(entry))
            if (not entry_break.enabled or entry_break.type != gdb.BP_HARDWARE_BREAKPOINT
                    or len(entry_break.locations) != 1 or entry_break.locations[0].address != entry):
                raise RuntimeError("hardware entry breakpoint unavailable")
            emit("candidate_entry_hardware_break_armed", breakpoint=entry_break.number, address=entry)
        elif entry_break is not None and entry_break.number in points:
            if not exec_seen or entry_seen or reg("rip") != entry_break.locations[0].address:
                raise RuntimeError("entry breakpoint order/address")
            entry_seen = True
            emit("candidate_entry_observed", rip=reg("rip"), metadata=snapshot())
            entry_break.enabled = False
        elif "signal" in event:
            emit("signal_delivery_stop", signal=event["signal"], registers=optional("info registers rip rsp rax orig_rax"),
                 siginfo=optional("p $_siginfo"), metadata=snapshot())
            gdb.execute("signal " + event["signal"])  # Forward the actual signal, never suppress/replace it.
            continue
        else:
            raise RuntimeError("unclassified stop")
        gdb.execute("continue")
    if not complete:
        raise RuntimeError("stop bound or missing terminal event")
    observation = ("CANDIDATE_ENTRY_OBSERVED" if entry_seen else
                   "EXEC_EVENT_WITHOUT_OBSERVED_CANDIDATE_ENTRY" if exec_seen else
                   "EXEC_RETURNED_ERROR" if negative_return is not None else
                   "NO_EXEC_EVENT_OR_ENTRY_OBSERVED_AFTER_REQUEST" if entered else "NO_CANDIDATE_EXEC_REQUEST")
    emit("observation", classification=observation, negative_return=negative_return,
         candidate_exec_requests=int(entered), cause="UNRESOLVED", qualification_complete=False)
except BaseException as error:
    complete = False
    emit("diagnostic_incomplete", error=type(error).__name__, message=str(error))
finally:
    if gdb.selected_inferior().pid:
        gdb.execute("kill")
    emit("observer_closed", inferior_pid=gdb.selected_inferior().pid, observation_complete=complete)
    TRACE.close()
gdb.execute("quit " + ("0" if complete else "1"))
