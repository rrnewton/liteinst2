"""Actual supervisor syscall/interrupt controls; never fake child status."""
import errno
import os
import re
import select
import signal
import time

from fork_supervise import Attempt, need

NAMES = ("normal", "timeout_live", "timeout_exited", "interrupt_live",
         "interrupt_exited", "close_error", "reap_error", "parser_error",
         "timeout_close_error")


class Control:
    def __init__(self, name):
        need(name in NAMES, "closed supervisor control")
        self.name = name
        self.child_fd = None
        self.close_fired = self.reap_fired = False

    @property
    def program_mode(self):
        if self.name in ("timeout_live", "interrupt_live", "timeout_close_error"):
            return "live"
        if self.name in ("timeout_exited", "interrupt_exited"):
            return "exited"
        return "malformed" if self.name == "parser_error" else "normal"

    def progress(self, attempt):
        facts = attempt.row["control"]
        if facts.get("ready"):
            return
        data = attempt.report_bytes[0]
        if b"\n" not in data:
            return
        match = re.fullmatch(rb"READY ([1-9][0-9]*) ([1-9][0-9]*) ([1-9][0-9]*)\n", data)
        need(match is not None, "actual supervisor READY framing")
        leader, child, observed_parent = map(int, match.groups())
        need(leader == attempt.row["leader_pid"] and child != leader, "READY owned process identities")
        live = self.program_mode == "live"
        need(observed_parent == (leader if live else os.getpid()), "actual child parent after fork/adoption")
        if bool(attempt.row["leader_observed"]) == live:
            return  # Authenticate the required leader phase; no timer inference.
        self.child_fd = attempt.own(os.pidfd_open(child, 0), "control-child-pidfd")
        group = os.getpgid(child)
        need(group == leader, "actual child belongs to pinned owned process group")
        facts.update({"ready": True, "child_pid": child, "child_parent": observed_parent,
                      "child_pgid": group, "leader_exited_at_ready": not live,
                      "leader_owned_before_trigger": attempt.leader_pin,
                      "ready_channel": "report-0", "name": self.name})
        need(attempt.process is not None and attempt.leader_pin, "trigger only after registered Popen ownership")
        if self.name.startswith("interrupt_"):
            need(signal.getsignal(signal.SIGINT) is signal.default_int_handler,
                 "actual SIGINT control requires Python's normal handler")
            facts["sigint_target"] = os.getpid()
            facts["sigint_send_started"] = True
            os.kill(os.getpid(), signal.SIGINT)
            # On Python/Linux this may run only before the pending handler is
            # dispatched. Either way the body must catch actual KeyboardInterrupt.
            facts["sigint_send_returned"] = True
        elif self.name.startswith("timeout_"):
            facts["ready_deadline"] = time.monotonic() + 0.25

    def after_close(self, attempt, entry):
        if self.name not in ("close_error", "timeout_close_error") or self.close_fired or entry["name"] != "leader-pidfd":
            return
        self.close_fired = True
        need(entry["state"] == "closed", "first actual close relinquished ownership")
        facts = attempt.row["control"]
        facts["close_first_success"] = True
        # No intervening FD allocation: this exact now-unowned number must fail.
        try:
            os.close(entry["fd"])
        except OSError as error:
            facts["close_second_errno"] = error.errno
            raise
        raise ValueError("real second close unexpectedly succeeded")

    def after_reap(self, attempt):
        if self.name != "reap_error" or self.reap_fired:
            return
        self.reap_fired = True
        need(attempt.row["leader_reaped"] and not attempt.leader_pin, "first actual reap relinquished numeric kill authority")
        facts = attempt.row["control"]
        facts["reap_first_success"] = True
        try:
            os.waitpid(attempt.row["leader_pid"], os.WNOHANG)
        except ChildProcessError as error:
            facts["reap_second_errno"] = error.errno
            raise
        raise ValueError("real second leader wait unexpectedly succeeded")

    def terminal(self, attempt):
        if self.child_fd is not None:
            ready, _, _ = select.select([self.child_fd], [], [], 0)
            attempt.row["control"]["child_pidfd_terminal"] = bool(ready)
            need(bool(ready), "actual control child pidfd not terminal")

    def parse(self, attempt):
        need(attempt.row["control"].get("ready"), "control never authenticated READY")
        # The malformed case is deliberately produced by the actual child and
        # fails here, after cleanup. It still has an installed attempted row.
        need(attempt.report_bytes[1] == b"", "unexpected supervisor report payload")

    def verify(self, attempt):
        row, facts = attempt.row, attempt.row["control"]
        need(facts.get("ready") and facts.get("leader_owned_before_trigger"), "missing real control readiness")
        need(row["leader_reaped"] and row["echild"] and facts.get("child_pidfd_terminal"),
             "control lacks actual leader/child reap and ECHILD proofs")
        need(all(fd["state"] == "closed" for fd in row["fds"]), "control lost descriptor ownership")
        need(attempt.stdout == attempt.stderr == b"", "unexpected control output")
        need(len(row["adopted_reaps"]) == 1 and row["adopted_reaps"][0]["pid"] == facts["child_pid"],
             "actual adopted child identity/count")
        killed = self.name.startswith(("timeout_", "interrupt_"))
        expected_leader = -signal.SIGKILL if self.program_mode == "live" else 0
        need(row["exit_code"] == expected_leader and row["adopted_reaps"][0]["exit_code"] == (-signal.SIGKILL if killed else 42),
             "actual control terminal statuses")
        need(all(event["before_leader_reap"] for event in row["kills"]), "kill after leader identity release")
        need(bool(row["kills"]) == killed, "unexpected control kill path")
        expected = {"normal": None, "timeout_live": "TimeoutError", "timeout_exited": "TimeoutError",
                    "interrupt_live": "KeyboardInterrupt", "interrupt_exited": "KeyboardInterrupt",
                    "close_error": "OSError", "reap_error": "ChildProcessError",
                    "parser_error": "ValueError", "timeout_close_error": "TimeoutError"}[self.name]
        need((row["failure"]["type"] if row["failure"] else None) == expected, "original primary failure replaced")
        if self.name == "timeout_close_error":
            need(len(row["secondary_errors"]) == 1 and row["secondary_errors"][0]["phase"] == "control_close"
                 and row["secondary_errors"][0]["errno"] == errno.EBADF, "secondary close failure lost or extra failure occurred")
        else:
            need(row["secondary_errors"] == [], "unexpected secondary supervisor failure")
        operation_error = self.name in ("close_error", "reap_error", "timeout_close_error")
        need(row["cleanup_complete"] is (not operation_error), "cleanup error was relabelled complete")
        if self.name.startswith("timeout_"):
            need(row["timeout"] and facts.get("ready_deadline") is not None, "actual ready-then-timeout absent")
        if self.name.startswith("interrupt_"):
            need(facts.get("sigint_send_started") and facts.get("sigint_target") == os.getpid()
                 and not row["timeout"], "actual SIGINT cause absent")
        if self.close_fired:
            need(facts.get("close_first_success") and facts.get("close_second_errno") == errno.EBADF,
                 "actual close failure absent")
            errors = [row["failure"], *row["secondary_errors"]]
            need(any(e and e["phase"] == "control_close" and e["errno"] == errno.EBADF for e in errors),
                 "close error not retained independently")
        if self.reap_fired:
            need(facts.get("reap_first_success") and facts.get("reap_second_errno") == errno.ECHILD,
                 "actual second wait failure absent")
        if self.name == "parser_error":
            need(attempt.report_bytes[1] == b"BROKEN\n" and row["failure"]["phase"] == "postprocess",
                 "actual post-cleanup parse failure missing")
        return {"name": self.name, "expected_failure_observed": expected,
                "actual_cleanup_complete": row["cleanup_complete"],
                "actual_echild": row["echild"], "actual_child_terminal": True}


def run(build, output, rows):
    results = []
    for name in NAMES:
        control = Control(name)
        attempt = Attempt(rows, output / ("supervisor-" + name), "supervisor-" + name,
                          "supervisor-control", name, control=control)

        def command(owner):
            writers = [fd["fd"] for fd in owner.row["fds"] if fd["name"].endswith("-write")]
            return [str(build / "supervisor-probe"), control.program_mode,
                    str(writers[0]), str(writers[1]), str(os.getpid())]

        attempt.run(command, postprocess=control.parse)
        results.append(control.verify(attempt))
    return results
