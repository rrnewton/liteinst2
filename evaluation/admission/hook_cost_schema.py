"""Closed, bounded parsing of the separately qualified cost experiment."""

import copy
from pathlib import Path
import re

from parsing import InvalidEvidence
from hook_cost_proof import require, sha, strict_json

PREFIX = "LITEINST_EVALUATION_B2_HOOK_COST:"
U64 = (1 << 64) - 1
IDENTITY = {"fixture", "phase", "pair_index", "round", "order_index", "lane"}
TIMES = {"completion_ns", "before_provider_ns", "checked_provider_ns", "after_provider_ns"}
ROW = {"ordinal", "class", "site_offset", "encoding_hex", "script_id", "validation_ns",
       "metrics_before", "metrics_after"} | TIMES
COMMON = {"schema_version", "kind"}
STAGES = {"arguments", "calibration", "fixture", "raw_reference", "launch", "validation",
          "completion", "cleanup", "agreement", "output", "run_validation"}
CLASSES = ["cpuid", "rdrand", "rdseed", "rdpid", "rdtsc", "rdtscp", "syscall"]
FIXTURES = ["masked_cpuid_random", "timestamps_processor_syscall", "prefixed_suffix",
            "embedded_alternate", "cross_page_call"]
PAGE_FIELDS = {"startup_ns", "admitted_pages", "untouched_pages", "observations",
               "covered_candidates", "collateral_guards", "collateral_completions", "first_touch_ns"}
SELECTED_FIELDS = {"callbacks", "native_completions", "scripted_completions",
                   "provider_faults", "native_signals", "refusals"}
PHASE_FIELDS = {"inspections", "hits", "runtime_scans", "no_entry", "stale", "corrupt",
                "refused", "decoded_starts", "lookup_elapsed_ns", "fresh_scan_elapsed_ns",
                "store_elapsed_ns", "saturated"}
DYNAMIC_FIELDS = {"resource_scan_decoded_starts", "retained_origins", "continuation_history_records",
                  "retained_call_obligations", "oldest_call_generation", "charged_source_bytes",
                  "retained_source_bytes", "bootstrap_xstate_bytes", "fetch_faults", "guard_stops",
                  "generation_changes"}
TOTALS = {"pairs": 65, "raw_references": 65, "production_sessions": 130,
          "selected_completions": 442, "warmup_completions": 102, "measured_completions": 340,
          "collateral_completions": 26, "semantic_mismatches": 0, "refusals": 0, "fallbacks": 0}


def integer(value, positive=False):
    require(type(value) is int and (1 if positive else 0) <= value <= U64, "invalid_wire_integer")


def closed(value, keys):
    require(type(value) is dict and set(value) == set(keys), "wire_fields_differ")


def integers(value, size=None, maximum=4096):
    require(type(value) is list and len(value) <= maximum
            and (size is None or len(value) == size), "invalid_wire_array")
    for item in value:
        integer(item)


def load_inventory(path=None, *, expected_sha256=None):
    path = path or Path(__file__).with_name("hook_cost_inventory.json")
    data = path.read_bytes()
    if expected_sha256 is not None:
        require(sha(data) == expected_sha256, "catalog_source_digest_differs")
    catalog = strict_json(data)
    require(type(catalog.get("schema_version")) is int and catalog["schema_version"] == 1,
            "catalog_schema")
    require(catalog.get("class_order") == CLASSES and catalog.get("argv") ==
            ["--warmup-pairs", "3", "--measured-pairs", "10", "--order-seed", "1"], "catalog_contract")
    require([f["fixture"] for f in catalog["fixtures"]] == FIXTURES
            and [len(f["rows"]) for f in catalog["fixtures"]] == [4, 4, 4, 3, 2], "catalog_fixture_inventory")
    for fixture in catalog["fixtures"]:
        closed(fixture, {"fixture", "covered", "collateral_completions", "rows"})
        require(type(fixture["covered"]) is bool and fixture["covered"] == (fixture["fixture"] != FIXTURES[0]),
                "catalog_coverage")
        integer(fixture["collateral_completions"])
        require(fixture["collateral_completions"] == int(fixture["fixture"] == "embedded_alternate"),
                "catalog_collateral")
        for n, row in enumerate(fixture["rows"]):
            closed(row, {"ordinal", "site_offset", "encoding_hex", "class", "script_id"})
            integer(row["ordinal"]); integer(row["site_offset"])
            require(row["ordinal"] == n and row["class"] in CLASSES
                    and type(row["encoding_hex"]) is str and re.fullmatch(r"(?:[0-9a-f]{2}){1,15}", row["encoding_hex"])
                    and row["script_id"] == fixture["fixture"] + ".row" + str(n), "catalog_row")
    # Independently reconstruct the declared seeded pairing, never accept output-defined order.
    expected, state = [], 1
    for fixture in FIXTURES:
        for phase, rounds in (("warmup", 3), ("measured", 10)):
            first_static = False
            for n in range(rounds):
                if n % 2 == 0:
                    state ^= (state << 13) & U64
                    state ^= state >> 7
                    state ^= (state << 17) & U64
                    first_static = bool(state & 1)
                else:
                    first_static = not first_static
                lanes = ["static_trap", "dynamic_page"] if first_static else ["dynamic_page", "static_trap"]
                expected.append({"fixture": fixture, "phase": phase, "round": n,
                                 "pair_index": len(expected), "lanes": lanes})
    require(catalog["pairs"] == expected, "catalog_pair_order")
    return catalog


def expected(catalog):
    fixtures = {row["fixture"]: row for row in catalog["fixtures"]}
    sequence, sessions, completions = [], [], []
    for pair in catalog["pairs"]:
        fixture = fixtures[pair["fixture"]]
        for order, lane in enumerate(pair["lanes"]):
            identity = {k: pair[k] for k in ("fixture", "phase", "round", "pair_index")}
            identity.update(order_index=order, lane=lane)
            session = identity | {"status": "not_observed", "qualified": False}
            sessions.append(session)
            sequence.append(("session", identity, fixture, session))
            for spec in fixture["rows"]:
                row = identity | spec | {"status": "not_observed", "qualified": False}
                completions.append(row)
                sequence.append(("completion", identity, spec, row))
    return sequence, sessions, completions


def snapshot(value, lane):
    closed(value, {"pages", "selected", "oracle", "dynamic"})
    closed(value["pages"], PAGE_FIELDS)
    for name, field in value["pages"].items():
        integers(field) if name == "first_touch_ns" else integer(field)
    closed(value["selected"], SELECTED_FIELDS)
    for name, field in value["selected"].items():
        integers(field, 7) if name == "callbacks" else integer(field)
    for name in ("native_completions", "provider_faults", "native_signals", "refusals"):
        require(value["selected"][name] == 0, "selected_failure_or_native_effect")
    closed(value["oracle"], {"preparation", "demand"})
    for phase in value["oracle"].values():
        closed(phase, PHASE_FIELDS)
        require(phase["saturated"] is False and phase["hits"] == 0, "cache_or_saturation")
        for name, field in phase.items():
            if name != "saturated":
                integer(field)
    require(all(v == 0 if type(v) is int else v is False
                for v in value["oracle"]["preparation"].values()), "unexpected_preparation_work")
    if lane == "static_trap":
        require(value["dynamic"] is None, "static_dynamic_metrics")
    else:
        closed(value["dynamic"], DYNAMIC_FIELDS)
        for name, field in value["dynamic"].items():
            if name != "oldest_call_generation" or field is not None:
                integer(field)
        require(value["dynamic"]["charged_source_bytes"] <= 64 * 1024 * 1024, "lifetime_limit_changed")


def row_fields(row, identity, spec, fixture_rows):
    for key, value in spec.items():
        require(type(row.get(key)) is type(value) and row[key] == value, "completion_identity_differs")
    for key in TIMES | {"validation_ns"}:
        integer(row[key])
    require(row["completion_ns"] == sum(row[k] for k in TIMES - {"completion_ns"}), "duration_sum_differs")
    snapshot(row["metrics_before"], identity["lane"])
    snapshot(row["metrics_after"], identity["lane"])
    before, after = row["metrics_before"], row["metrics_after"]
    prefix = [0] * len(CLASSES)
    for prior in fixture_rows[:spec["ordinal"]]:
        prefix[CLASSES.index(prior["class"])] += 1
    require(before["selected"]["callbacks"] == prefix
            and before["selected"]["scripted_completions"] == spec["ordinal"], "cumulative_selected_counts")
    require(after["selected"]["scripted_completions"] == before["selected"]["scripted_completions"] + 1,
            "completion_counter_differs")
    callbacks = before["selected"]["callbacks"][:]
    callbacks[CLASSES.index(spec["class"])] += 1
    require(after["selected"]["callbacks"] == callbacks, "callback_delta_differs")
    old_touch, new_touch = before["pages"]["first_touch_ns"], after["pages"]["first_touch_ns"]
    require(new_touch[:len(old_touch)] == old_touch, "publication_history_replaced")
    for phase in ("preparation", "demand"):
        for name in PHASE_FIELDS - {"saturated"}:
            require(after["oracle"][phase][name] >= before["oracle"][phase][name], "oracle_counter_decreased")
    if identity["lane"] == "dynamic_page":
        for name in DYNAMIC_FIELDS - {"oldest_call_generation"}:
            require(after["dynamic"][name] >= before["dynamic"][name], "dynamic_history_decreased")


def parse_capture(output, catalog):
    """Keep validated prefix rows on failure. Arbitrary diagnostic text stays private."""
    sequence, sessions, completions = expected(catalog)
    result = {"status": "incomplete", "sessions": sessions, "completions": completions,
              "calibration": None, "failure": None, "run_complete": None, "parser_error": None}
    cursor, ended = 0, False
    fixtures = {f["fixture"]: f for f in catalog["fixtures"]}
    try:
        require(type(output) is str and len(output.encode()) <= 8 * 1024 * 1024, "capture_limit")
        for line in output.splitlines():
            if PREFIX not in line:
                continue
            require(line.startswith(PREFIX) and len(line) <= 256 * 1024 and not ended, "wire_line_or_terminal")
            obj = strict_json(line[len(PREFIX):])
            require(type(obj) is dict and type(obj.get("schema_version")) is int
                    and obj["schema_version"] == 1, "wire_schema")
            kind = obj.get("kind")
            if kind == "calibration":
                closed(obj, COMMON | {"clock", "monotonic_resolution_ns", "subtracted", "samples_ns"})
                require(result["calibration"] is None and cursor == 0 and obj["clock"] == "std_instant"
                        and obj["subtracted"] is False, "calibration_position")
                integer(obj["monotonic_resolution_ns"], True); integers(obj["samples_ns"], 1000)
                result["calibration"] = obj
            elif kind in ("session", "completion"):
                require(result["calibration"] is not None and cursor < len(sequence), "unexpected_measurement")
                expected_kind, identity, spec, destination = sequence[cursor]
                require(kind == expected_kind and all(type(obj.get(k)) is type(v) and obj[k] == v
                        for k, v in identity.items()), "measurement_order_or_identity")
                if kind == "session":
                    closed(obj, COMMON | IDENTITY | {"covered", "raw_reference_completed", "callbacks",
                        "collateral_completions", "launch_total_ns", "validation_ns", "cleanup_ns", "completed", "cleanup"})
                    require(type(obj["covered"]) is bool and obj["covered"] == spec["covered"]
                            and obj["raw_reference_completed"] is True and obj["completed"] is True
                            and obj["cleanup"] is True, "session_proof_missing")
                    for key in ("callbacks", "collateral_completions", "launch_total_ns", "validation_ns", "cleanup_ns"):
                        integer(obj[key])
                    require(obj["callbacks"] == len(spec["rows"])
                            and obj["collateral_completions"] == spec["collateral_completions"], "session_count")
                else:
                    closed(obj, COMMON | IDENTITY | ROW | {"completed", "cleanup"})
                    require(type(obj["completed"]) is int and obj["completed"] == 1
                            and obj["cleanup"] is True, "completion_proof_missing")
                    row_fields(obj, identity, spec, fixtures[identity["fixture"]]["rows"])
                destination.update(copy.deepcopy(obj), status="observed_unqualified", qualified=False)
                cursor += 1
            elif kind == "run_complete":
                closed(obj, COMMON | set(TOTALS) | {"cleanup"})
                require(cursor == len(sequence) and result["calibration"] is not None
                        and obj["cleanup"] is True, "incomplete_run_terminal")
                for key, value in TOTALS.items():
                    integer(obj[key]); require(obj[key] == value, "run_denominator_differs")
                result["run_complete"] = obj
                ended = True
                result["status"] = "complete"
            elif kind == "failure":
                closed(obj, COMMON | IDENTITY | TIMES | {"stage", "ordinal", "partial_session", "partial_rows",
                    "cleanup", "emitted_sessions", "emitted_completions", "qualified"})
                require(obj["stage"] in STAGES and obj["qualified"] is False and type(obj["cleanup"]) is bool,
                        "failure_fields")
                for key in TIMES:
                    if obj[key] is not None:
                        integer(obj[key])
                if all(obj[key] is not None for key in TIMES):
                    require(obj["completion_ns"] == sum(obj[k] for k in TIMES - {"completion_ns"}), "partial_duration_sum")
                integer(obj["emitted_sessions"]); integer(obj["emitted_completions"])
                require(obj["emitted_sessions"] == sum(s["status"] != "not_observed" for s in sessions)
                        and obj["emitted_completions"] == sum(r["status"] != "not_observed" for r in completions),
                        "failure_emission_counts")
                null_id = all(obj[k] is None for k in IDENTITY)
                identity = {k: obj[k] for k in IDENTITY}
                if not null_id:
                    matches = [s for s in sessions if all(type(identity[k]) is type(s[k])
                               and identity[k] == s[k] for k in IDENTITY)]
                    require(len(matches) == 1, "failure_identity")
                    # Output/paired comparison may fail after the current session was emitted.
                    allowed = ([sequence[cursor][1]] if cursor < len(sequence) else [])
                    if cursor:
                        allowed.append(sequence[cursor - 1][1])
                    require(identity in allowed, "failure_position")
                else:
                    require(obj["stage"] in {"arguments", "calibration", "fixture"}, "failure_missing_identity")
                require(type(obj["partial_rows"]) is list and len(obj["partial_rows"]) <= 4, "partial_row_bound")
                if obj["ordinal"] is not None:
                    integer(obj["ordinal"])
                    require(not null_id and obj["ordinal"] < len(fixtures[obj["fixture"]]["rows"]), "failure_ordinal")
                pending = obj["partial_session"]
                if pending is None:
                    require(obj["partial_rows"] == [], "partial_session_missing")
                else:
                    require(not null_id, "partial_identity_missing")
                    closed(pending, {"covered", "launch_total_ns", "validation_ns", "cleanup_ns"})
                    require(type(pending["covered"]) is bool and pending["covered"] == fixtures[obj["fixture"]]["covered"],
                            "partial_coverage")
                    for key in ("launch_total_ns", "validation_ns"):
                        integer(pending[key])
                    if pending["cleanup_ns"] is not None:
                        integer(pending["cleanup_ns"])
                        require(obj["cleanup"] is True, "partial_cleanup_contradiction")
                    require(matches[0]["status"] == "not_observed", "partial_duplicate_session")
                    count = len(obj["partial_rows"])
                    require((obj["ordinal"] is None and count == 0)
                            or (obj["ordinal"] is not None and obj["ordinal"] in (count, count - 1)),
                            "partial_row_chronology")
                    for n, partial in enumerate(obj["partial_rows"]):
                        closed(partial, ROW)
                        specs = fixtures[obj["fixture"]]["rows"]
                        row_fields(partial, identity, specs[n], specs)
                    matches[0].update(copy.deepcopy(pending), status="partial_unqualified")
                    for partial in obj["partial_rows"]:
                        row = next(r for r in completions if all(r[k] == identity[k] for k in IDENTITY)
                                   and r["ordinal"] == partial["ordinal"])
                        row.update(copy.deepcopy(partial), status="partial_unqualified", qualified=False)
                result["failure"] = obj
                result["status"] = "failed"
                ended = True
            else:
                raise InvalidEvidence("unknown_wire_kind")
    except (InvalidEvidence, ValueError, TypeError, KeyError, IndexError, UnicodeError, RecursionError) as error:
        result["status"] = "invalid"
        result["parser_error"] = str(error) if isinstance(error, InvalidEvidence) else "malformed_wire"
    return result


def qualify(evidence, qualified):
    require(type(qualified) is bool, "invalid_qualification")
    require(not qualified or evidence["status"] == "complete", "cannot_qualify_incomplete")
    for collection in ("sessions", "completions"):
        for row in evidence[collection]:
            row["qualified"] = qualified
            if qualified:
                require(row["status"] == "observed_unqualified", "cannot_qualify_missing_row")
                row["status"] = "qualified"
            elif row["status"] == "qualified":
                row["status"] = "observed_unqualified"
