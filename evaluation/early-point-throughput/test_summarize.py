"""Synthetic schema controls, never a native or timing invocation."""
import copy
import csv
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("point_statistics", Path(__file__).with_name("summarize.py"))
stats = importlib.util.module_from_spec(spec)
spec.loader.exec_module(stats)


class Schema(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="point-schema-", dir=Path.cwd() / "ignored")
        self.addCleanup(self.tmp.cleanup)
        self.folder = Path(self.tmp.name)
        self.order = "early-disabled,native,ordinary-disabled"
        self.summary = dict(status="PASS", profile="early-point-throughput-v1", order=self.order,
            pid=100, worker_tid=100, worker_cpu=5, source_bytes=7, enabled_controls=2,
            qualification_rows=3, warmup_rows=9, measured_rows=192, calls_per_batch=2048,
            checksum_per_batch=6296576, total_calls=417794, enabled_callbacks=2,
            retained_records=2, timed_callbacks=0, publication="direct-generated-entry", performance_threshold=False)
        roster = [("ordinary-enabled", "enabled-control", 0), ("early-enabled", "enabled-control", 0)]
        roster += [(a, "qualification", 0) for a in stats.ARMS]
        roster += [(a, "warmup" if i < 3 else "measured", i if i < 3 else i - 3)
                   for a in self.order.split(",") for i in range(67)]
        self.rows = []
        for arm, phase, index in roster:
            enabled = phase == "enabled-control"
            ns = "" if phase in ("enabled-control", "qualification") else str(2048 * (stats.ARMS.index(arm) + 1))
            self.rows.append(dict(pid="100", worker_tid="100", worker_cpu="5", arm=arm, phase=phase,
                batch=str(index), status="PASS", calls="1" if enabled else "2048", elapsed_ns=ns,
                checksum="18" if enabled else "6296576", callbacks="1" if enabled else "0",
                records="1" if enabled else "0", refusals="0"))

    def check(self, rows=None, summary=None):
        (self.folder / "summary.json").write_text(json.dumps(self.summary if summary is None else summary))
        with (self.folder / "measurements.csv").open("w", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=stats.HEADER)
            writer.writeheader(); writer.writerows(self.rows if rows is None else rows)
        return stats.cohort(self.folder, self.order, 5)

    def test_complete_population_exact_means_and_balanced_schedule(self):
        self.assertEqual(len(stats.schedule()), 12)
        self.assertEqual(len(set(stats.schedule())), 6)
        self.assertTrue(all(stats.schedule().count(order) == 2 for order in set(stats.schedule())))
        self.assertEqual(len(self.rows), 206)
        self.assertEqual(self.check(), {"native": 1.0, "ordinary-disabled": 2.0, "early-disabled": 3.0})

    def test_missing_enabled_work_and_invalid_timed_observation_refuse(self):
        changes = [(0, "callbacks", "0"), (1, "records", "0"), (1, "checksum", "7"),
            (1, "arm", "early-disabled"), (2, "checksum", "6296575"), (2, "elapsed_ns", "1"),
            (5, "callbacks", "1"), (5, "refusals", "1"), (5, "records", "1"),
            (8, "elapsed_ns", "0"), (8, "elapsed_ns", "90000000001"),
            (8, "worker_tid", "101"), (8, "worker_cpu", "4"), (8, "status", "FAILED")]
        for index, field, value in changes:
            with self.subTest(index=index, field=field, value=value):
                rows = copy.deepcopy(self.rows); rows[index][field] = value
                with self.assertRaises(AssertionError): self.check(rows)

    def test_full_denominator_and_summary_types_cannot_be_relabelled(self):
        for rows in [self.rows[1:], self.rows[:-1], self.rows + [self.rows[-1]],
                     self.rows[:-1] + [self.rows[-2]]]:
            with self.subTest(length=len(rows)):
                with self.assertRaises(AssertionError): self.check(rows)
        for key, value in [("profile", "owned-clock-admission-throughput-v1"), ("enabled_controls", 0),
                           ("worker_tid", 101), ("timed_callbacks", False), ("performance_threshold", 0)]:
            with self.subTest(key=key):
                summary = dict(self.summary); summary[key] = value
                with self.assertRaises(AssertionError): self.check(summary=summary)


if __name__ == "__main__":
    unittest.main()
