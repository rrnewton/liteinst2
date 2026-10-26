import copy
import unittest
from pathlib import Path
import tempfile
from unittest.mock import patch
from parsing import InvalidEvidence

from hook_cost_schema import IDENTITY, ROW, PREFIX, load_inventory, parse_capture, qualify
from hook_cost_summary import summarize, artifacts, publish_csv, partial_csv
from hook_cost_test_support import wire_records, wire, partial_failure


class HookCostWireTests(unittest.TestCase):
    def setUp(self):
        self.catalog, self.rows = wire_records()

    def parse(self, rows=None):
        return parse_capture(wire(self.rows if rows is None else rows), self.catalog)

    def reject(self, rows=None):
        evidence = self.parse(rows)
        self.assertEqual(evidence["status"], "invalid")
        self.assertFalse(any(r["qualified"] for r in evidence["completions"]))

    def test_full_denominators_are_observed_but_not_self_qualified(self):
        result = self.parse()
        self.assertEqual(result["status"], "complete")
        self.assertEqual(len(result["sessions"]), 130)
        self.assertEqual(len(result["completions"]), 442)
        self.assertEqual(sum(r["phase"] == "warmup" for r in result["completions"]), 102)
        self.assertTrue(all(not r["qualified"] for r in result["sessions"]))

    def test_missing_terminal_does_not_qualify_completed_rows(self):
        self.assertEqual(self.parse(self.rows[:-1])["status"], "incomplete")

    def test_duplicate_record_is_not_an_extra_sample(self):
        self.reject(self.rows[:3] + [self.rows[2]] + self.rows[3:])

    def test_swapped_lane_order_is_rejected(self):
        self.rows[1]["lane"] = "dynamic_page"
        self.reject()

    def test_wrong_round_or_encoding_is_rejected(self):
        for field, value in (("round", 2), ("encoding_hex", "0f31"), ("script_id", "foreign.row0")):
            with self.subTest(field=field):
                changed = copy.deepcopy(self.rows)
                changed[2][field] = value
                self.reject(changed)

    def test_boolean_durations_and_schema_are_not_integers(self):
        for index, field in ((0, "schema_version"), (2, "completed"), (2, "completion_ns")):
            changed = copy.deepcopy(self.rows)
            changed[index][field] = True
            self.reject(changed)

    def test_four_clock_intervals_must_sum_exactly(self):
        self.rows[2]["completion_ns"] += 1
        self.reject()

    def test_unknown_private_field_never_reaches_public_evidence(self):
        self.rows[2]["native_pid"] = 1234
        result = self.parse()
        self.assertEqual(result["status"], "invalid")
        self.assertNotIn("native_pid", str(result))

    def test_nonzero_initial_callback_baseline_is_rejected(self):
        self.rows[2]["metrics_before"]["selected"]["callbacks"][0] = 7
        self.rows[2]["metrics_after"]["selected"]["callbacks"][0] = 8
        self.reject()

    def test_nonzero_initial_completion_baseline_is_rejected(self):
        self.rows[2]["metrics_before"]["selected"]["scripted_completions"] = 7
        self.rows[2]["metrics_after"]["selected"]["scripted_completions"] = 8
        self.reject()

    def test_cache_hits_preparation_and_saturation_are_rejected(self):
        for phase, field, value in (("preparation", "inspections", 1), ("demand", "hits", 1), ("demand", "saturated", True)):
            changed = copy.deepcopy(self.rows)
            changed[2]["metrics_after"]["oracle"][phase][field] = value
            self.reject(changed)

    def test_page_gauge_decrease_is_retained_exactly(self):
        row = self.rows[7]
        self.assertEqual(row["lane"], "dynamic_page")
        row["metrics_before"]["pages"]["admitted_pages"] = 3
        row["metrics_after"]["pages"]["admitted_pages"] = 1
        result = self.parse()
        self.assertEqual(result["status"], "complete")
        observed = result["completions"][4]
        self.assertEqual(observed["metrics_after"]["pages"]["admitted_pages"] - observed["metrics_before"]["pages"]["admitted_pages"], -2)

    def test_publication_history_rewrite_is_rejected(self):
        self.rows[2]["metrics_after"]["pages"]["first_touch_ns"] = [11]
        self.reject()

    def test_history_counter_decrease_is_rejected(self):
        self.rows[7]["metrics_before"]["dynamic"]["charged_source_bytes"] = 1
        self.reject()

    def test_duplicate_json_key_and_nonfinite_value_are_rejected(self):
        for payload in ('{"schema_version":1,"schema_version":1,"kind":"calibration"}',
                        '{"schema_version":1,"kind":"calibration","samples_ns":[NaN]}'):
            result = parse_capture(PREFIX + payload, self.catalog)
            self.assertEqual(result["status"], "invalid")

    def test_deep_malformed_tail_retains_prior_typed_rows(self):
        text = wire(self.rows[:6]) + PREFIX + '[' * 2000 + '0' + ']' * 2000
        result = parse_capture(text, self.catalog)
        self.assertEqual(result["status"], "invalid")
        self.assertEqual(result["completions"][0]["status"], "observed_unqualified")
        self.assertEqual(result["completions"][4]["status"], "not_observed")

    def test_failed_second_lane_preserves_first_lane_unqualified(self):
        identity = {k: self.rows[6][k] for k in IDENTITY}
        partial = {k: self.rows[7][k] for k in ROW}
        failure = partial_failure(identity, [partial])
        failure.update(emitted_sessions=1, emitted_completions=4)
        result = self.parse(self.rows[:6] + [failure])
        self.assertEqual(result["status"], "failed")
        self.assertEqual([r["status"] for r in result["completions"][:6]],
                         ["observed_unqualified"] * 4 + ["partial_unqualified", "not_observed"])
        self.assertFalse(any(r["qualified"] for r in result["completions"]))

    def test_partial_ordinal_cannot_claim_unexecuted_prefix(self):
        identity = {k: self.rows[1][k] for k in IDENTITY}
        partial = [{k: r[k] for k in ROW} for r in self.rows[2:6]]
        failure = partial_failure(identity, partial)
        failure["ordinal"] = 0
        self.reject([self.rows[0], failure])

    def test_partial_cleanup_flag_cannot_contradict_duration(self):
        identity = {k: self.rows[1][k] for k in IDENTITY}
        failure = partial_failure(identity, [])
        failure["cleanup"] = False
        self.reject([self.rows[0], failure])

    def test_final_validation_failure_retains_entire_active_prefix(self):
        identity = {k: self.rows[6][k] for k in IDENTITY}
        partial = [{k: r[k] for k in ROW} for r in self.rows[7:11]]
        failure = partial_failure(identity, partial)
        failure.update(stage="cleanup", ordinal=3, emitted_sessions=1, emitted_completions=4)
        result = self.parse(self.rows[:6] + [failure])
        self.assertEqual(result["status"], "failed")
        self.assertEqual([r["status"] for r in result["completions"][:8]],
                         ["observed_unqualified"] * 4 + ["partial_unqualified"] * 4)
        self.assertTrue(all(result["failure"][key] is None for key in
            ("completion_ns", "before_provider_ns", "checked_provider_ns", "after_provider_ns")))

    def test_extra_terminal_or_wrong_total_is_rejected(self):
        self.reject(self.rows + [self.rows[-1]])
        self.rows[-1]["selected_completions"] = 441
        self.reject()

    def test_outer_disqualification_clears_every_row(self):
        result = self.parse()
        qualify(result, True)
        self.assertTrue(all(r["qualified"] for r in result["completions"]))
        qualify(result, False)
        self.assertTrue(all(r["status"] == "observed_unqualified" for r in result["completions"]))

    def test_missing_rows_cannot_be_qualified(self):
        with self.assertRaisesRegex(InvalidEvidence, "cannot_qualify_incomplete"):
            qualify(self.parse(self.rows[:-1]), True)

    def test_summary_has_ten_process_pairs_and_ignores_warmups(self):
        result = self.parse()
        for row in result["completions"]:
            if row["phase"] == "warmup":
                row["completion_ns"] = 10**12
            elif row["lane"] == "dynamic_page":
                row["completion_ns"] += row["round"] * 1000 + 10
            else:
                row["completion_ns"] += row["round"] * 1000
        qualify(result, True)
        values = summarize(result)
        self.assertEqual(len(values), 17 * 4)
        for row in values:
            self.assertEqual(row["static_trap"]["samples"], 10)
            self.assertEqual(row["paired_dynamic_minus_static"]["unit"], "independent_process_pair")
            if row["component"] == "completion_ns":
                self.assertEqual(row["paired_dynamic_minus_static"]["median_ns"], 10)
                self.assertEqual(row["paired_dynamic_minus_static"]["bootstrap_95_percentile_low_ns"], 10)
                self.assertEqual(row["paired_dynamic_minus_static"]["bootstrap_95_percentile_high_ns"], 10)

    def test_failed_run_produces_no_performance_summary(self):
        result = self.parse(self.rows[:6])
        self.assertEqual(summarize(result), [])
        self.assertEqual(len(artifacts(result)["summary"].splitlines()), 1)

    def test_partial_csv_publication_is_explicitly_unqualified(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            replace = Path.replace
            def fail_second(path, target):
                if path.name == "run-completions.pending":
                    raise OSError("synthetic storage failure")
                return replace(path, target)
            with patch("hook_cost_summary.artifacts", return_value={
                    "sessions": b"qualified\nTrue\n", "completions": b"qualified\nTrue\n", "summary": b"header\n"}), \
                 patch.object(Path, "replace", fail_second), self.assertRaises(OSError):
                publish_csv(directory, "run", {})
            receipt = partial_csv(directory, "run")
            self.assertEqual(set(receipt), {"sessions"})
            self.assertFalse(receipt["sessions"]["qualified"])
            self.assertFalse(receipt["sessions"]["publication_complete"])
            self.assertEqual((directory / "run-sessions.csv").read_bytes(), b"qualified\nTrue\n")


if __name__ == "__main__":
    unittest.main()
