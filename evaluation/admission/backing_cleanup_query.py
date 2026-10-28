"""Closed five-control/six-trajectory main-cc846 cleanup evidence.

Only the exact reviewed Cargo source/binary pair owns a removable protocol
block. Its parent authenticates private child receipts and physical pins before
emitting these observations. The stream is not a hostile-program authenticator.
No payload from an invalid record is copied into the public partial result.
"""

import copy
import json
import re

from parsing import InvalidEvidence, require


PREFIX = "LITEINST_BACKING_CLEANUP_V1 "
TARGET = "control/exec_backing_cleanup"
SOURCE = "tests/exec_backing_cleanup.rs"
BINARY = "exec_backing_cleanup"
MAX_LINE_BYTES = 1024
HEADER = re.compile(r"\s*Running tests/exec_backing_cleanup\.rs "
                    r"\(target/debug/deps/exec_backing_cleanup-[a-f0-9]{16}\)")
CARGO_HEADER = re.compile(r"\s*(?:Running |Doc-tests )")
CONTROLS = (
    "admitted_exec_native_backing_probes_close_exact_owned_resources",
    "admitted_exec_native_backing_read_and_unwind_preserve_cleanup",
    "exec_backing_native_invalid_unmap_aborts_isolated_owner",
    "admitted_exec_native_backing_query_preserves_cleanup",
    "admitted_exec_native_backing_enotty_uses_exact_legacy_projection",
)
TRAJECTORIES = ("complete", "read_error", "unwind", "invalid_unmap", "query_error", "legacy")
BEGIN = {"schema_version": 1, "kind": "begin", "controls": 5, "trajectories": 6}
END = {"schema_version": 1, "kind": "complete", "controls": 5,
       "trajectories": 6, "physical_cleanup": True}
ROWS = tuple({"schema_version": 1, "kind": "trajectory", "index": index,
              "id": identity, "control": CONTROLS[control], "outcome": outcome,
              "probes": probes, "errno": error, "terminal": terminal,
              "owner_cleanup": owner_cleanup, "physical_cleanup": True,
              "receipt_authenticated": True}
             for index, identity, control, outcome, probes, error, terminal, owner_cleanup in (
                 (0, "complete", 0, "complete", 6, 0, "exit0", True),
                 (1, "read_error", 1, "native_read_error", 1, 14, "exit0", True),
                 (2, "unwind", 1, "injected_unwind", 1, 0, "exit0", True),
                 (3, "invalid_unmap", 2, "expected_fail_stop", 1, 22, "sigabrt", False),
                 (4, "query_error", 3, "native_query_error", 1, 14, "exit0", True),
                 (5, "legacy", 4, "native_enotty_fallback", 6, 0, "exit0", True),
             ))


def specification():
    """Return a fresh exact catalog descriptor; it grants no native authority."""
    return {"id": TARGET, "source": SOURCE, "binary": BINARY,
            "protocol": PREFIX.rstrip(), "controls": list(CONTROLS),
            "trajectories": list(TRAJECTORIES)}


def typed_equal(actual, expected):
    """Exact recursive schema equality, including bool versus int."""
    if type(actual) is not type(expected):
        return False
    if type(expected) is dict:
        return (actual.keys() == expected.keys()
                and all(typed_equal(actual[key], value) for key, value in expected.items()))
    if type(expected) in (list, tuple):
        return len(actual) == len(expected) and all(
            typed_equal(left, right) for left, right in zip(actual, expected))
    return actual == expected


def require_inventory(corpus):
    """The real runner must require both targets before any command executes.

    Historical synthetic command_evidence callers may omit this new table;
    main never supplies that compatibility path to the real current corpus.
    """
    expected = {name: [specification()] for name in ("workspace_tests", "serial_launch")}
    require(typed_equal(corpus.get("backing_cleanup_harnesses"), expected),
            "invalid_backing_cleanup_inventory")


def _view(seen, accepted, successful, error):
    completed = [row["id"] for row in accepted if row["kind"] == "trajectory"]
    controls = []
    for name, needed in zip(CONTROLS, (("complete",), ("read_error", "unwind"), ("invalid_unmap",),
                                      ("query_error",), ("legacy",))):
        count = sum(identity in completed for identity in needed)
        controls.append({"id": name, "trajectories": list(needed),
                         "status": "complete" if count == len(needed) else
                         "incomplete" if count else "not_observed"})
    return {"id": TARGET, "source": SOURCE, "binary": BINARY, "schema_version": 1,
            "status": "invalid" if error else "complete" if len(accepted) == 8 else
                      "incomplete" if seen else "not_observed",
            "begin_observed": bool(accepted), "complete_observed": len(accepted) == 8,
            "observations": copy.deepcopy(accepted), "controls": controls,
            "command_succeeded": successful, "qualified_run": False}


def is_complete(row):
    """Qualification requires the complete exact typed observation, not counts."""
    expected = _view(True, [BEGIN, *ROWS, END], True, None)
    return (type(row) is dict and type(row.get("qualified_run")) is bool
            and typed_equal(row | {"qualified_run": False}, expected))


def _object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate_backing_cleanup_key")
        result[key] = value
    return result


def _constant(_value):
    raise InvalidEvidence("invalid_backing_cleanup_json")


def separate(output, inventory, successful):
    """Return old libtest text, one sanitized helper row and first parse error.

    Even an incomplete helper block is removed only after its exact Cargo
    source/binary header authenticates that scope. Every old harness line stays
    byte-for-byte. A bad helper still invalidates the command independently;
    it cannot conceal an old libtest failure or manufacture a summary.
    """
    require(type(output) is str and type(successful) is bool,
            "invalid_backing_cleanup_input")
    require(typed_equal(inventory, [specification()]), "invalid_backing_cleanup_inventory")
    remaining = []
    accepted = []
    seen = False
    active = False
    error = None
    expected = (BEGIN, *ROWS, END)

    def fail(code):
        nonlocal error
        if error is None:
            error = code

    for original in output.splitlines(keepends=True):
        line = original.rstrip("\r\n")
        if CARGO_HEADER.match(line):
            if active and len(accepted) != len(expected):
                fail("incomplete_backing_cleanup_protocol")
            active = False
            if HEADER.fullmatch(line):
                if seen:
                    fail("duplicate_backing_cleanup_harness")
                seen = active = True
                continue
            if BINARY in line:
                fail("invalid_backing_cleanup_header")
            remaining.append(original)
            continue
        if not active:
            if "LITEINST_BACKING_CLEANUP" in line:
                fail("backing_cleanup_record_outside_harness")
            remaining.append(original)
            continue
        if not line.strip():
            continue
        if error is not None:
            continue
        if not line.startswith(PREFIX):
            fail("unexpected_backing_cleanup_output")
            continue
        if len(line.encode("utf-8")) > MAX_LINE_BYTES:
            fail("oversized_backing_cleanup_record")
            continue
        if len(accepted) == len(expected):
            fail("extra_backing_cleanup_record")
            continue
        try:
            row = json.loads(line[len(PREFIX):], object_pairs_hook=_object,
                             parse_constant=_constant)
        except InvalidEvidence as invalid:
            fail(invalid.code)
            continue
        except (ValueError, RecursionError):
            fail("invalid_backing_cleanup_json")
            continue
        if not typed_equal(row, expected[len(accepted)]):
            fail("backing_cleanup_record_differs")
            continue
        # Copy the closed expected value, never unvalidated caller payload.
        accepted.append(copy.deepcopy(expected[len(accepted)]))
    if not seen:
        fail("missing_backing_cleanup_harness")
    elif len(accepted) != len(expected):
        fail("incomplete_backing_cleanup_protocol")
    return "".join(remaining), [_view(seen, accepted, successful, error)], error
