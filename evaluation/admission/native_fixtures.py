"""Exact named test outcomes for finite native validation cohorts.

These are fixture outcomes, not instruction samples or kernel-event telemetry.
The independent aggregate harness parser and all whole-run gates still apply.
Only trusted catalog identities and typed observations enter public receipts.
"""

import copy
import re

from parsing import InvalidEvidence, harness_id, require


NAME = re.compile(r"[A-Za-z0-9_]+(?:::[A-Za-z0-9_]+)*")
UNIT = "unit/liteinst_launch/lib"
REFERENCE = "test/b2_mode_reference"
SIGNAL_REFERENCE = "test/b3_signal_admission"
MAPPING_REFERENCE = "test/b3_mapping_admission"
EXEC_REFERENCE = "test/b3_exec_admission"
EXEC_TESTS = frozenset((
    "original_exec_replacement_matches_raw_replay_and_native_full_state",
    "stale_exec_source_reply_preserves_actual_replacement_without_commit",
    "resolver_panic_after_actual_exec_keeps_original_failure_and_cleanup",
    "blocked_exec_resolver_uses_original_deadline_and_owner_cleanup",
    "exec_full_comparator_rejects_each_state_input_map_and_identity_corruption",
))
EXEC_PRIVATE_PREFIX = "linux::remote::dynamic::owner::admission::exec::tests::native::"
EXEC_PRIVATE_TESTS = frozenset(EXEC_PRIVATE_PREFIX + name for name in (
    "admitted_exec_native_first_user_and_retired_history_are_exact",
    "admitted_exec_native_source_reply_refusal_keeps_new_mm_held",
    "admitted_exec_native_errno_exit_never_mints_replacement",
))
EXEC_FAILURE_PREFIX = EXEC_PRIVATE_PREFIX + "failures::"
EXEC_FAILURE_TESTS = frozenset(EXEC_FAILURE_PREFIX + name for name in (
    "admitted_exec_native_prefix_capacity_refuses_before_restore",
    "admitted_exec_native_getregs_capture_failure_retains_other_reads",
    "admitted_exec_native_bootstrap_failure_retains_first_user_prefix",
    "admitted_exec_native_input_bound_refuses_before_restore",
    "admitted_exec_native_source_profile_bound_refuses_after_exec",
    "admitted_exec_native_pending_flags_change_refuses_before_restore",
))
MAPPING_TESTS = frozenset((
    'original_rw_rx_rw_rx_unmap_matches_raw_full_state_and_two_runtime_sources',
    'stale_capture_reply_after_real_second_rx_preserves_partial_kernel_history',
    'resolver_panic_after_real_rx_keeps_failure_and_original_physical_cleanup',
    'blocked_resolver_expires_original_deadline_before_callback_is_released',
    'full_native_mapping_comparator_rejects_each_state_source_and_map_corruption',
))
RESET_PREFIX = "linux::remote::dynamic::launch::anchor::reset::tests::"
SOURCE_CENSUS_PREFIX = "linux::remote::dynamic::owner::tests::source_census::"
SOURCE_CENSUS_TEST = (SOURCE_CENSUS_PREFIX
                      + "changed_reserved_census_refuses_before_entry_patch_or_permission_change")
PREFIXES = (
    "linux::remote::dynamic::owner::kernel_journal::tests::native::",
    "linux::remote::dynamic::owner::admission::completion::journal_dispatch_tests::",
    "linux::remote::dynamic::owner::admission::completion::journal_native_budget_tests::",
)

# Closed runtime native modules. Pure runtime tests remain ordinary unit rows.
RUNTIME_COHORTS = (('b3_runtime_startup',
  'linux::remote::dynamic::owner::admission::runtime::native_tests::',
  ('initial_runtime_startup_preserves_real_boundary_state_sources_and_nx',
   'initial_runtime_owner_refuses_raw_bypass_and_repeated_start',
   'initial_runtime_expired_original_deadline_keeps_pristine_exec',
   'initial_runtime_one_short_bootstrap_reservation_keeps_pristine_exec',
   'initial_runtime_source_window_refusal_retains_completed_bootstrap',
   'initial_runtime_unwind_retains_native_bootstrap_until_physical_cleanup')),
 ('b3_runtime_ordinary',
  'linux::remote::dynamic::owner::admission::runtime::ordinary::native_tests::',
  ('runtime_ordinary_literal_moves_and_add_preserve_exact_checkpoints',
   'runtime_ordinary_single_step_stops_before_same_page_marker',
   'runtime_ordinary_conditional_branch_preserves_complete_state',
   'runtime_ordinary_same_pc_loop_consumes_distinct_origin',
   'runtime_ordinary_nop_matches_independent_raw_single_step')),
 ('b3_runtime_selected',
  'linux::remote::dynamic::owner::admission::runtime::selected::native::native_tests::',
  ('runtime_selected_cpu_and_ordinary_keep_exact_control_lineage',
   'runtime_selected_native_refuses_without_ordinary_fallback',
   'runtime_selected_syscall_refuses_without_ordinary_fallback',
   'runtime_ordinary_memory_and_stack_refuse_before_effects',
   'runtime_actual_dr7_refuses_before_original_release')))
RUNTIME_ROWS = tuple({"cohort": cohort, "harness": UNIT, "test": prefix + name}
                     for cohort, prefix, names in RUNTIME_COHORTS for name in names)
RUNTIME_IDENTITIES = {row["test"]: row for row in RUNTIME_ROWS}
RUNTIME_NATIVE_ROOTS = tuple(prefix.removesuffix("::") for _, prefix, _ in RUNTIME_COHORTS)


def catalog(fixtures):
    require(type(fixtures) is list, "invalid_native_fixture_catalog")
    identities = {}
    for row in fixtures:
        require(type(row) is dict and set(row) == {"cohort", "harness", "test"},
                "invalid_native_fixture_catalog")
        require(all(type(value) is str for value in row.values())
                and NAME.fullmatch(row["test"]), "invalid_native_fixture_catalog")
        require(not row["test"].startswith(RUNTIME_NATIVE_ROOTS)
                or row == RUNTIME_IDENTITIES.get(row["test"]), "invalid_native_fixture_scope")
        require(row["test"] not in MAPPING_TESTS
                or (row["cohort"] == "b3_mapping" and row["harness"] == MAPPING_REFERENCE),
                "invalid_native_fixture_scope")
        require(row["test"] not in EXEC_TESTS
                or (row["cohort"] == "b3_exec" and row["harness"] == EXEC_REFERENCE),
                "invalid_native_fixture_scope")
        require(not row["test"].startswith(EXEC_PRIVATE_PREFIX)
                or (row["cohort"] == "b3_exec_private" and row["harness"] == UNIT
                    and row["test"] in EXEC_PRIVATE_TESTS)
                or (row["cohort"] == "b3_exec_failure" and row["harness"] == UNIT
                    and row["test"] in EXEC_FAILURE_TESTS), "invalid_native_fixture_scope")
        require((row["cohort"] == "kernel_journal" and row["harness"] == UNIT
                 and row["test"].startswith(PREFIXES))
                or (row["cohort"] == "b2_reference" and row["harness"] == REFERENCE
                    and "::" not in row["test"])
                or (row["cohort"] == "b3_signal" and row["harness"] == SIGNAL_REFERENCE
                    and "::" not in row["test"])
                or (row["cohort"] == "b3_reset" and row["harness"] == UNIT
                    and row["test"].startswith(RESET_PREFIX))
                or (row["cohort"] == "b3_source_census" and row["harness"] == UNIT
                    and row["test"] == SOURCE_CENSUS_TEST)
                or (row["cohort"] == "b3_mapping" and row["harness"] == MAPPING_REFERENCE
                    and row["test"] in MAPPING_TESTS)
                or (row["cohort"] == "b3_exec" and row["harness"] == EXEC_REFERENCE
                    and row["test"] in EXEC_TESTS)
                or (row["cohort"] == "b3_exec_private" and row["harness"] == UNIT
                    and row["test"] in EXEC_PRIVATE_TESTS)
                or (row["cohort"] == "b3_exec_failure" and row["harness"] == UNIT
                    and row["test"] in EXEC_FAILURE_TESTS)
                or row == RUNTIME_IDENTITIES.get(row["test"]), "invalid_native_fixture_scope")
        key = (row["harness"], row["test"])
        require(key not in identities, "duplicate_native_fixture_catalog")
        identities[key] = row
    return identities


def fixture_outcomes(output, fixtures, successful_command):
    """Require every declared fixture's explicit terminal ok in its exact harness.

    An explicit empty catalog supports historical synthetic test cohorts. The
    real corpus pins every current fixture; no missing-key default is supplied.
    Within a monitored unit harness, other tests are structurally checked but
    never exported. Any unlisted test in the native modules is rejected.
    """
    expected = catalog(fixtures)
    require(type(successful_command) is bool, "invalid_native_fixture_command_status")
    require(type(output) is str, "invalid_native_fixture_output")
    if not expected:
        return []
    watched = {key[0] for key in expected}
    known_names = {key[1] for key in expected}
    observed = {}
    seen_harnesses = set()
    seen_tests = set()
    current = None
    active = None
    closed = False
    declared = False

    def partial():
        return [copy.deepcopy(observed.get(key, row | {
            "status": "not_observed", "test_result": None,
            "command_succeeded": successful_command, "qualified_run": False,
        })) for key, row in expected.items()]

    try:
        for line in output.splitlines():
            identity = harness_id(line)
            if identity:
                require(active is None, "native_fixture_missing_terminal")
                current, closed, declared = identity, False, False
                if current in watched:
                    require(current not in seen_harnesses, "duplicate_native_fixture_harness")
                    seen_harnesses.add(current)
                continue
            if re.match(r"\s*(Running |Doc-tests )", line):
                raise InvalidEvidence("unrecognized_harness_header")
            start = re.fullmatch(r"test (" + NAME.pattern + r") \.\.\. (.*)", line)
            if current not in watched:
                require(not start or start[1] not in known_names, "native_fixture_wrong_harness")
                continue
            run_start = re.fullmatch(r"running (\d+) tests?", line)
            if run_start:
                require(not declared and not closed, "duplicate_native_fixture_start")
                declared = True
                continue
            if start:
                require(declared, "native_fixture_before_start")
                require(not closed, "native_fixture_after_summary")
                require(active is None, "native_fixture_missing_terminal")
                key = (current, start[1])
                require(key not in seen_tests, "duplicate_native_fixture_test")
                require(start[1] not in known_names or key in expected,
                        "native_fixture_wrong_harness")
                require(key in expected or (current == UNIT and not start[1].startswith(
                    PREFIXES + (RESET_PREFIX, SOURCE_CENSUS_PREFIX, EXEC_PRIVATE_PREFIX)
                    + RUNTIME_NATIVE_ROOTS)),
                        "native_fixture_cohort_differs")
                seen_tests.add(key)
                active = key
                if key in expected:
                    observed[key] = expected[key] | {
                        "status": "incomplete", "test_result": None,
                        "command_succeeded": successful_command, "qualified_run": False,
                    }
                line = start[2]
            elif line.startswith("test ") and not line.startswith("test result:"):
                raise InvalidEvidence("invalid_native_fixture_name")
            if line.startswith("test result:"):
                require(declared and not closed, "native_fixture_summary_without_start")
                require(active is None, "native_fixture_missing_terminal")
                closed = True
                continue
            terminal = (line if line in ("ok", "FAILED", "ignored") else
                        "ignored" if line.startswith("ignored,") else None)
            if terminal:
                require(active is not None, "native_fixture_terminal_without_test")
                if active in expected:
                    observed[active]["test_result"] = terminal
                    observed[active]["status"] = "complete" if terminal == "ok" else "failed"
                active = None
        require(active is None, "native_fixture_missing_terminal")
        require(seen_harnesses == watched, "missing_native_fixture_harness")
        require(set(observed) == set(expected), "native_fixture_cohort_differs")
        require(all(row["test_result"] == "ok" for row in observed.values()),
                "native_fixture_not_passed")
        return partial()
    except InvalidEvidence as error:
        error.partial = partial()
        raise
