"""Bounded, dedicated-subreaper command custody for raw-fork evaluation."""
import hashlib
import json
import os
from pathlib import Path
import resource
import select
import signal
import subprocess
import time

FILE_LIMIT = 16 * 1024 * 1024
CAPTURE_LIMIT = 64 * 1024
REPORT_LIMIT = 4096
STATE_BYTES = 135936
ENV = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C", "TZ": "UTC",
       "PYTHONDONTWRITEBYTECODE": "1"}


def limits(original_mask):
    resource.setrlimit(resource.RLIMIT_CPU, (5, 5))
    resource.setrlimit(resource.RLIMIT_AS, (512 * 1024 * 1024,) * 2)
    # This physical per-file bound also covers namespace dependency memfds.
    # Accepted stdout/stderr remain independently limited to 64 KiB below.
    resource.setrlimit(resource.RLIMIT_FSIZE, (FILE_LIMIT,) * 2)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    # No NPROC override: the native fork controls must create a real child.
    signal.pthread_sigmask(signal.SIG_SETMASK, original_mask)


def error_record(phase, error):
    return {"phase": phase, "type": type(error).__name__,
            "errno": getattr(error, "errno", None), "message": str(error)}


def need(condition, message):
    if not condition:
        raise ValueError(message)


class Attempt:
    """The row is installed before the first directory, FD, or child exists.

    No poll()/wait() is allowed before all numeric process-group kill decisions
    are over. WNOWAIT pins the leader, even when it has already exited. Once a
    reap succeeds or ECHILD makes that pin unknown, numeric kill is forbidden.
    """

    def __init__(self, rows, folder, label, mode, case, failure_step=0, control=None):
        self.row = {"label": label, "mode": mode, "case": case,
                    "failure_step": failure_step, "command": None,
                    "leader_pid": None, "exit_code": None, "timeout": False,
                    "failure": None, "secondary_errors": [], "reports": [],
                    "cleanup_complete": False, "leader_observed": False,
                    "leader_reaped": False, "leader_pin_lost": False,
                    "echild": False, "adopted_reaps": [], "kills": [],
                    "fds": [], "captures": {}, "control": {},
                    "resource_profile": {"cpu_seconds": 5, "address_bytes": 512*1024*1024,
                        "per_file_bytes_including_captures": FILE_LIMIT,
                        "accepted_capture_bytes": CAPTURE_LIMIT,
                        "accepted_report_bytes": REPORT_LIMIT,
                        "wall_seconds": 15, "cleanup_seconds": 2,
                        "process_count_override": None}}
        rows.append(self.row)
        self.folder = Path(folder)
        self.control = control
        self.process = None
        self.leader_pin = False
        self.readers = {}
        self.passed = []
        self.report_fds = []
        self.state_paths = []
        self.report_bytes = [b"", b""]
        self.stdout = self.stderr = b""
        self.states = []
        self.cleanup_error = False
        self.started = time.monotonic()
        self.cleanup_deadline = None
        self.row["environment"] = dict(ENV)

    def fail(self, phase, error, cleanup=False):
        record = error_record(phase, error)
        if self.row["failure"] is None:
            self.row["failure"] = record
        else:
            self.row["secondary_errors"].append(record)
        self.cleanup_error |= cleanup

    def guarded(self, phase, function, *args, cleanup=False):
        try:
            return function(*args)
        except BaseException as error:
            self.fail(phase, error, cleanup)
            return None

    def own(self, fd, name):
        self.row["fds"].append({"fd": fd, "name": name, "state": "owned", "errno": None})
        return fd

    def fd_row(self, fd):
        rows = [r for r in self.row["fds"] if r["fd"] == fd and r["state"] == "owned"]
        need(len(rows) == 1, "unique current FD owner")
        return rows[0]

    def close(self, fd):
        entry = self.fd_row(fd)
        entry["state"] = "close_attempted"
        try:
            os.close(fd)
        except BaseException as error:
            # Linux close errors do not authorize retrying the same number.
            entry["errno"] = getattr(error, "errno", None)
            self.fail("close:" + entry["name"], error, cleanup=True)
            return
        entry["state"] = "closed"
        # A control may now issue an actual invalid second close. Ownership was
        # already released; that failing observation cannot recreate an owner.
        if self.control:
            self.guarded("control_close", self.control.after_close, self, entry, cleanup=True)

    def pipe(self, name):
        read, write = os.pipe2(os.O_CLOEXEC)
        self.own(read, name + "-read")
        self.own(write, name + "-write")
        return read, write

    def prepare(self, command_builder, state_count):
        self.folder.mkdir()
        for index in range(2):
            read, write = self.pipe("report-" + str(index))
            self.report_fds.append(read)
            self.readers[read] = bytearray()
            os.set_blocking(read, False)
            self.passed.append(write)
        for index in range(state_count):
            path = self.folder / ("state-" + str(index))
            fd = self.own(os.open(path, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600),
                          "state-" + str(index))
            self.state_paths.append(path)
            self.passed.append(fd)
        command = command_builder(self)
        self.row["command"] = command
        self.row["passed_fds"] = list(self.passed)
        out = self.own(os.open(self.folder / "stdout", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600), "stdout")
        err = self.own(os.open(self.folder / "stderr", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600), "stderr")
        # Defer parent SIGINT across Popen's otherwise ambiguous assignment
        # window. The exec child restores the exact prior mask in preexec.
        original_mask = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGINT})
        try:
            self.process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                env=ENV, pass_fds=tuple(self.passed), start_new_session=True,
                preexec_fn=lambda: limits(original_mask))
            self.leader_pin = True
            self.row["leader_pid"] = self.process.pid
        except BaseException as error:
            self.fail("spawn", error)
        finally:
            self.guarded("restore_parent_sigmask", signal.pthread_sigmask, signal.SIG_SETMASK,
                         original_mask, cleanup=True)
        if self.process is None:
            return
        self.own(os.pidfd_open(self.process.pid, 0), "leader-pidfd")
        for fd in [out, err, *self.passed]:
            self.close(fd)
        self.passed.clear()

    def observe_leader(self):
        if not self.leader_pin:
            return
        try:
            event = os.waitid(os.P_PID, self.process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
        except ChildProcessError:
            self.leader_pin = False
            self.row["leader_pin_lost"] = True
            raise
        if event is not None:
            self.row["leader_observed"] = True
            self.row["leader_observation"] = {"pid": event.si_pid, "code": event.si_code, "status": event.si_status}

    def drain(self, delay):
        if not self.readers:
            if delay:
                time.sleep(delay)
            return
        ready, _, _ = select.select(list(self.readers), [], [], delay)
        for fd in ready:
            value = os.read(fd, REPORT_LIMIT + 1)
            buffer = self.readers[fd]
            if value:
                remaining = REPORT_LIMIT + 1 - len(buffer)
                buffer.extend(value[:max(0, remaining)])
                self.report_bytes[self.report_fds.index(fd)] = bytes(buffer)
                need(len(buffer) <= REPORT_LIMIT and len(value) <= remaining, "report exceeded one PIPE_BUF record")
            else:
                self.report_bytes[self.report_fds.index(fd)] = bytes(buffer)
                del self.readers[fd]

    def wait_body(self):
        deadline = self.started + 15
        while True:
            self.observe_leader()
            self.drain(0.01)
            if self.control:
                self.control.progress(self)
            if self.row["leader_observed"] and not self.readers:
                return
            local_deadline = self.row["control"].get("ready_deadline", deadline)
            if time.monotonic() >= min(deadline, local_deadline):
                self.row["timeout"] = True
                raise TimeoutError("bounded fork cohort deadline")

    def kill_group(self):
        need(self.leader_pin and not self.row["leader_reaped"], "numeric group kill requires unreaped owned leader")
        event = {"before_leader_reap": True, "result": None, "errno": None}
        self.row["kills"].append(event)
        try:
            os.killpg(self.process.pid, signal.SIGKILL)
            event["result"] = "sent"
        except ProcessLookupError as error:
            event["result"], event["errno"] = "absent", error.errno
        except BaseException as error:
            event["result"], event["errno"] = "failed", getattr(error, "errno", None)
            raise

    def reap_leader(self):
        need(self.leader_pin and self.row["leader_observed"], "leader reap requires actual WNOWAIT exit")
        try:
            pid, status = os.waitpid(self.process.pid, os.WNOHANG)
        except ChildProcessError:
            self.leader_pin = False
            self.row["leader_pin_lost"] = True
            raise
        need(pid == self.process.pid, "observed leader was not actually reaped")
        self.leader_pin = False
        self.row["leader_reaped"] = True
        self.row["leader_wait_status"] = status
        self.row["exit_code"] = os.waitstatus_to_exitcode(status)
        self.process.returncode = self.row["exit_code"]
        if self.control:
            self.control.after_reap(self)

    def reap_adoptees(self):
        need(self.row["leader_reaped"], "adopted reap follows actual leader reap")
        while True:
            try:
                pid, status = os.waitpid(-1, os.WNOHANG)
            except ChildProcessError:
                self.row["echild"] = True
                return
            if pid:
                self.row["adopted_reaps"].append({"pid": pid, "status": status,
                                                "exit_code": os.waitstatus_to_exitcode(status)})
            elif time.monotonic() >= self.cleanup_deadline:
                raise TimeoutError("adopted descendants not reaped within cleanup bound")
            else:
                time.sleep(0.005)

    def cleanup(self):
        self.cleanup_deadline = time.monotonic() + 2
        if self.process is not None:
            if self.row["failure"] or not self.row["leader_observed"] or self.readers:
                # One bounded cleanup, no fresh local timer and no post-reap kill.
                while time.monotonic() < self.cleanup_deadline:
                    if self.leader_pin:
                        self.guarded("kill_group", self.kill_group, cleanup=True)
                    self.guarded("cleanup_drain", self.drain, 0.01, cleanup=True)
                    self.guarded("cleanup_observe", self.observe_leader, cleanup=True)
                    if self.row["leader_observed"] and not self.readers:
                        break
                    if not self.leader_pin:
                        break
            if self.leader_pin and self.row["leader_observed"]:
                self.guarded("reap_leader", self.reap_leader, cleanup=True)
            if self.row["leader_reaped"]:
                self.guarded("reap_adoptees", self.reap_adoptees, cleanup=True)
            if self.control:
                self.guarded("control_terminal", self.control.terminal, self, cleanup=True)
        # Each independent owner is considered even after another close fails.
        for entry in self.row["fds"]:
            if entry["state"] == "owned":
                self.guarded("close_owner", self.close, entry["fd"], cleanup=True)
        process_complete = self.process is None or (
            self.row["leader_reaped"] and self.row["echild"] and not self.readers)
        self.row["cleanup_complete"] = bool(process_complete and not self.cleanup_error and
            all(entry["state"] == "closed" for entry in self.row["fds"]))
        if not self.row["cleanup_complete"] and self.row["failure"] is None:
            self.fail("cleanup", RuntimeError("physical cleanup incomplete"), cleanup=True)

    def capture(self, path, acceptance):
        extent = path.stat().st_size
        digest = hashlib.sha256()
        content = bytearray()
        with path.open("rb") as handle:
            while True:
                block = handle.read(65536)
                if not block:
                    break
                digest.update(block)
                if len(content) <= acceptance:
                    content.extend(block[:max(0, acceptance + 1 - len(content))])
        self.row["captures"][path.name] = {"bytes": extent, "sha256": digest.hexdigest()}
        need(extent <= acceptance, "capture exceeds accepted extent: " + path.name)
        need(len(content) == extent, "capture extent changed during read")
        return bytes(content)

    def materialize(self):
        for index, value in enumerate(self.report_bytes):
            path = self.folder / ("report-" + str(index))
            self.guarded("write_report", path.write_bytes, value)
            self.guarded("hash_report", self.capture, path, REPORT_LIMIT)
        for name in ("stdout", "stderr"):
            value = self.guarded("capture:" + name, self.capture, self.folder / name, CAPTURE_LIMIT)
            if value is not None:
                setattr(self, name, value)
        for path in self.state_paths:
            value = self.guarded("capture:" + path.name, self.capture, path, STATE_BYTES)
            self.states.append(value)

    def save(self):
        self.row["duration_seconds"] = time.monotonic() - self.started
        def write():
            (self.folder / "command.json").write_text(json.dumps(self.row, indent=2) + "\n")
        self.guarded("write_command", write)

    def run(self, command_builder, state_count=0, postprocess=None):
        try:
            self.prepare(command_builder, state_count)
            if self.row["failure"] is None:
                self.wait_body()
        except BaseException as error:
            self.fail("body", error)
        finally:
            # No cleanup exception is allowed to replace the first failure or
            # remove this already-installed attempted row.
            self.guarded("cleanup_outer", self.cleanup, cleanup=True)
            self.guarded("capture_outer", self.materialize)
            if postprocess is not None:
                self.guarded("postprocess", postprocess, self)
            self.save()
        return self.row, self.stdout, self.stderr
