"""Pure schema controls; no generated code, build or timing campaign."""
import copy
import csv
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("admission_statistics", Path(__file__).with_name("summarize.py"))
stats = importlib.util.module_from_spec(spec)
spec.loader.exec_module(stats)


class Schema(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="admission-schema-", dir=Path.cwd() / "ignored")
        self.addCleanup(self.tmp.cleanup)
        self.folder = Path(self.tmp.name)
        self.order = "counter-batch,native,counter-per-call"
        self.summary = dict(status="PASS", profile="owned-clock-admission-throughput-v1", order=self.order,
            controller_cpu=3, worker_cpu=5, qualification_rows=3, warmup_rows=9, measured_rows=192,
            calls_per_batch=2048, encounters_per_lease=30720, quantum=64, stop_handoffs_per_batch=0,
            publisher_validation=False, full_state_after_callback=False, performance_threshold=False)
        roster = [(a, "qualification", 0) for a in stats.ARMS]
        roster += [(a, "warmup" if i < 3 else "measured", i if i < 3 else i-3)
                   for a in self.order.split(",") for i in range(67)]
        self.rows = []
        for arm, phase, index in roster:
            row = dict(pid="100", worker_tid="101", arm=arm, phase=phase, batch=str(index), status="PASS",
                calls="2048", expected_encounters="30720", expected_taken="22528", checksum="24576",
                elapsed_ns="" if phase == "qualification" else str(2048 * (stats.ARMS.index(arm) + 1)),
                clock_encounters="" if arm == "native" else "30720",
                clock_taken="" if arm == "native" else "22528", stops="0",
                remaining="" if arm == "native" else "64")
            self.rows.append(row)

    def check(self, rows=None, summary=None):
        (self.folder / "summary.json").write_text(json.dumps(self.summary if summary is None else summary))
        with (self.folder / "measurements.csv").open("w", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=stats.HEADER)
            writer.writeheader()
            writer.writerows(self.rows if rows is None else rows)
        return stats.cohort(self.folder, self.order, [3, 5])

    def test_fixed_schedule_and_exact_means(self):
        self.assertEqual(len(stats.schedule()), 12)
        self.assertEqual(len(set(stats.schedule())), 6)
        self.assertTrue(all(stats.schedule().count(order) == 2 for order in set(stats.schedule())))
        self.assertEqual(self.check(), {"native": 1.0, "counter-per-call": 2.0, "counter-batch": 3.0})

    def test_changed_labels_work_and_timing_refuse(self):
        for index, field, value in [(1, "arm", "counter-batch"), (2, "arm", "stop"),
                (2, "stops", "352"), (2, "clock_taken", "22527"), (2, "checksum", "24575"),
                (2, "elapsed_ns", "1"), (3, "phase", "measured"), (6, "elapsed_ns", "0"),
                (6, "status", "FAIL")]:
            with self.subTest(index=index, field=field, value=value):
                rows = copy.deepcopy(self.rows)
                rows[index][field] = value
                with self.assertRaises(AssertionError):
                    self.check(rows)

    def test_missing_duplicate_and_wrong_profile_refuse(self):
        variants = [self.rows[:-1], self.rows + [self.rows[-1]], self.rows[:-1] + [self.rows[-2]]]
        for rows in variants:
            with self.subTest(length=len(rows)):
                with self.assertRaises(AssertionError):
                    self.check(rows)
        for key, value in [("profile", "owned-two-backedge-throughput-v1"), ("stop_handoffs_per_batch", 352)]:
            summary = dict(self.summary)
            summary[key] = value
            with self.subTest(key=key):
                with self.assertRaises(AssertionError):
                    self.check(summary=summary)


if __name__ == "__main__":
    unittest.main()
