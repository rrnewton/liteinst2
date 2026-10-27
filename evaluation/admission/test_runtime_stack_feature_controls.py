"""Pure inventory/capture/receipt controls; never launch Cargo or native code."""

import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import runtime_stack_feature_controls as feature
from parsing import InvalidEvidence

REVISION = "a" * 40
RUN_ID = "20261027T010203.123456Z-runtime-stack-feature-" + REVISION[:12]
BASE = feature.LIBRARY + "lib.rs"
EXTRA = feature.LIBRARY + "linux/remote/dynamic/owner/kernel_journal/runtime/consumer_oracle.rs"
METHODS = ["linux::kernel_journal::consumer_oracle::first", "linux::kernel_journal::consumer_oracle::second"]
HEADER = "     Running unittests src/lib.rs (target/debug/deps/liteinst_launch-0123456789abcdef)"


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def fixture():
    # Literal synthetic source census: two default and two feature methods.
    # No production cohort count is supplied as a default by the runner.
    files = {BASE: b"#[test]\nfn native_control() {}\n#[test]\nfn ordinary_control() {}\n",
        EXTRA: b"#[test]\nfn first() {}\n#[test]\nfn second() {}\n",
        feature.CARGO: b'[features]\ndev-owned-stack-consumer-oracle = []\n'}
    corpus = {"schema_version": 1, "harness_test_counts": {
        group: {feature.HARNESS: {"tests": 2, "ignored": 0}}
        for group in ("workspace_tests", "serial_launch")},
        "native_validation_fixtures": [{"harness": feature.HARNESS, "test": "tests::native_control"}]}
    files["evaluation/admission/corpus.json"] = encoded(corpus)
    inventory = {"schema_version": 1, "finalized": True, "feature": feature.FEATURE,
        "filter": feature.FILTER, "harness": feature.HARNESS, "classification": "source_reviewed_pure",
        "cargo_sha256": feature.run.sha(files[feature.CARGO]),
        "source_rows": [{"path": path, "sha256": feature.run.sha(files[path]), "test_functions": names}
            for path, names in ((BASE, ["native_control", "ordinary_control"]), (EXTRA, ["first", "second"]))],
        "compiled_methods": [{"name": name, "path": path, "scope": scope}
            for name, path, scope in [(METHODS[0], EXTRA, "feature_pure"), (METHODS[1], EXTRA, "feature_pure"),
                ("tests::native_control", BASE, "default"), ("tests::ordinary_control", BASE, "default")]]}
    inventory["source_rows"].sort(key=lambda row: row["path"])
    files[feature.INVENTORY] = encoded(inventory)
    source = {"revision": REVISION, "tree": "b" * 40, "tracked_clean": True, "head_sources_match": True,
        "source_manifest_sha256": "c" * 64, "tracked_diff_sha256": "d" * 64,
        "source_sha256": {path: feature.run.sha(data) for path, data in files.items()} | {feature.RUNNER: "e" * 64}}
    return files, corpus, inventory, source


def log(methods=METHODS, filtered=2):
    return ("\n".join(["    Finished `test` profile in 0.01s", HEADER, "", f"running {len(methods)} tests",
        *(f"test {name} ... ok" for name in methods), "",
        f"test result: ok. {len(methods)} passed; 0 failed; 0 ignored; 0 measured; {filtered} filtered out; finished in 0.02s", ""])).encode()


def selected():
    return {"methods": list(METHODS), "filtered_out": 2, "native_methods": 0}


def command(data=None):
    data = log() if data is None else data
    value = feature.command_spec() | {"start_utc": "2026-10-27T01:02:03.123456+00:00", "exit_code": 0,
        "termination": None, "seconds": 0.02, "private_log_sha256": feature.run.sha(data),
        "cleanup_complete": True, "reaped_descendants": 0, "child_discovery_strategy": "proc_children"}
    feature.observe(value, data, selected())
    return value


def record(source):
    value = {"schema_version": 1, "experiment": "runtime-stack-feature-controls", "run_id": RUN_ID,
        "qualification_protocol": False, "claim_scope": "source_reviewed_feature_pure_controls",
        "performance_claim": None, "qualified": True, "status": "passed", "source": source,
        "configuration": {"files": []}, "hardware": {"affinity_cpu_count": 8}, "toolchain": {"cargo": "synthetic"},
        "runner_sha256": source["source_sha256"][feature.RUNNER],
        "corpus_sha256": source["source_sha256"]["evaluation/admission/corpus.json"],
        "method_inventory_sha256": source["source_sha256"][feature.INVENTORY],
        "pure_methods": 2, "native_methods": 0, "filtered_out": 2, "affinity_cpu_count": 8,
        "environment": feature.public_environment(), "inherited_location_variables": list(feature.run.LOCATION_VARIABLES),
        "log_limit_bytes_per_command": feature.LOG_LIMIT, "cleanup_seconds": 3, "cleanup_scope": "outer_supervisor",
        "reproduce": ["python3", feature.RUNNER, "--expect-revision", REVISION], "commands": [command()],
        "first_failure": None, "secondary_failures": [], **{key: True for key in feature.STABILITY}}
    return value


def metadata(value, source):
    feature.prerequisite_metadata(value, source=source, configuration={"files": []}, hardware={"affinity_cpu_count": 8},
        toolchain={"cargo": "synthetic"}, corpus_digest=source["source_sha256"]["evaluation/admission/corpus.json"],
        inventory=selected(), inventory_digest=source["source_sha256"][feature.INVENTORY])


class RuntimeStackFeatureControlsTests(unittest.TestCase):
    def test_feature_inventory_is_closed_final_and_source_bound(self):
        files, corpus, inventory, source = fixture()
        self.assertEqual(feature.validate_inventory(inventory, source, corpus), selected())
        for update in ({"finalized": False}, {"schema_version": True}, {"feature": "other"},
                       {"filter": ""}, {"harness": "unit/other/lib"}, {"classification": "native"},
                       {"extra": 1}, {"cargo_sha256": "f" * 64}, {"compiled_methods": []}):
            with self.subTest(update=update), self.assertRaises(InvalidEvidence):
                feature.validate_inventory(inventory | update, source, corpus)
        for changed in (inventory | {"source_rows": inventory["source_rows"][:-1]},
                        inventory | {"compiled_methods": inventory["compiled_methods"][:-1]}):
            with self.assertRaises(InvalidEvidence):
                feature.validate_inventory(changed, source, corpus)
        with patch.object(feature, "bounded_read", side_effect=FileNotFoundError):
            with self.assertRaises(FileNotFoundError):
                feature.load_inventory(source, corpus)
        with patch.object(feature, "bounded_read", return_value=files[feature.INVENTORY] + b" "):
            with self.assertRaisesRegex(InvalidEvidence, "feature_inventory_source"):
                feature.load_inventory(source, corpus)

    def test_feature_inventory_refuses_native_duplicates_and_default_count_drift(self):
        _, corpus, inventory, source = fixture()
        changed = copy.deepcopy(corpus)
        changed["native_validation_fixtures"].append({"harness": feature.HARNESS, "test": METHODS[0]})
        with self.assertRaisesRegex(InvalidEvidence, "feature_native_intersection"):
            feature.validate_inventory(inventory, source, changed)
        for count in (1, 3, True):
            changed = copy.deepcopy(corpus)
            for group in ("workspace_tests", "serial_launch"):
                changed["harness_test_counts"][group][feature.HARNESS]["tests"] = count
            with self.assertRaises(InvalidEvidence):
                feature.validate_inventory(inventory, source, changed)
        for modify in (lambda v: v["compiled_methods"].append(v["compiled_methods"][0]),
                       lambda v: v["compiled_methods"][0].update(scope="default"),
                       lambda v: v["compiled_methods"][0].update(path=BASE),
                       lambda v: v["compiled_methods"][0].update(name="not_selected::first")):
            changed = copy.deepcopy(inventory)
            modify(changed)
            with self.assertRaises(InvalidEvidence):
                feature.validate_inventory(changed, source, corpus)

    def test_feature_source_guard_requires_every_test_exactly(self):
        files, _, inventory, source = fixture()

        def read(path, limit):
            data = files[str(path.relative_to(feature.ROOT))]
            self.assertLessEqual(len(data), limit)
            return data

        feature.source_guard(inventory, source, read)
        for text in (b"#[test]\nfn first() {}\n", b"#[test]\nasync fn first() {}\n#[test]\nfn second() {}\n",
                     b"#[test]\n#[ignore]\nfn first() {}\n#[test]\nfn second() {}\n",
                     files[EXTRA] + b"#[test]\nfn third() {}\n"):
            old = files[EXTRA]
            files[EXTRA] = text
            changed = copy.deepcopy(inventory)
            next(row for row in changed["source_rows"] if row["path"] == EXTRA)["sha256"] = feature.run.sha(text)
            with self.assertRaisesRegex(InvalidEvidence, "feature_source_test_census"):
                feature.source_guard(changed, source, read)
            files[EXTRA] = old
        files[EXTRA] += b"// changed\n"
        with self.assertRaisesRegex(InvalidEvidence, "feature_source_bytes"):
            feature.source_guard(inventory, source, read)

    def test_feature_capture_requires_exact_named_cohort_and_filtered_count(self):
        observed = feature.parse_capture(log(), selected())
        self.assertEqual(observed["status"], "complete")
        self.assertEqual(observed["methods"], [{"test": name, "status": "ok"} for name in METHODS])
        self.assertEqual(observed["outer"], {"result": "ok", "passed": 2, "failed": 0,
            "ignored": 0, "measured": 0, "filtered": 2, "seconds": 0.02})
        self.assertEqual(feature.parse_capture(log(list(reversed(METHODS))), selected())["outer"], observed["outer"])
        for count in (0, 1, 3):
            with self.assertRaisesRegex(InvalidEvidence, "feature_capture_summary_counts"):
                feature.parse_capture(log(filtered=count), selected())
        for before, after in (("src/lib.rs", "examples/other.rs"), ("target/debug/deps/", "target/debug/examples/"),
                              ("liteinst_launch-", "other-"), ("0123456789abcdef", "NOTHEX")):
            with self.assertRaisesRegex(InvalidEvidence, "feature_capture_header"):
                feature.parse_capture(log().replace(before.encode(), after.encode()), selected())

    def test_feature_capture_refuses_unknown_duplicate_ignored_nested_and_partial(self):
        base = log()
        bad = [base.replace(METHODS[0].encode(), b"private::unknown"), base + base,
            base.replace(METHODS[1].encode(), METHODS[0].encode()),
            base.replace(b"running 2 tests", b"running 2 tests\nrunning 1 test"),
            base.replace(b"... ok", b"... ignored", 1),
            base.replace(b"0 measured", b"1 measured"),
            base[:base.index(b"test result:")], base.replace(b"... ok", b"... FAILED", 1),
            base + b"Doc-tests other\n", base.replace(b"src/lib.rs", b"/PRIVATE_SENTINEL/lib.rs")]
        for text in bad:
            with self.subTest(text=text), self.assertRaises(InvalidEvidence) as caught:
                feature.parse_capture(text, selected())
            self.assertNotIn("PRIVATE_SENTINEL", json.dumps(caught.exception.partial))
            self.assertNotIn("PRIVATE_SENTINEL", str(caught.exception))
            self.assertTrue(all(row["test"] in METHODS for row in caught.exception.partial["methods"]))
        partial = base[:base.index(("test " + METHODS[1]).encode())]
        with self.assertRaises(InvalidEvidence) as caught:
            feature.parse_capture(partial, selected())
        self.assertEqual(caught.exception.partial["methods"], [{"test": METHODS[0], "status": "ok"}])

    def test_feature_failed_command_never_qualifies_complete_rows(self):
        _, _, _, source = fixture()
        for key, value in (("exit_code", 101), ("exit_code", True), ("termination", "timeout"),
                           ("cleanup_complete", False), ("reaped_descendants", 1), ("reaped_descendants", False)):
            item = record(source)
            item["commands"][0][key] = value
            feature.observe(item["commands"][0], log(), selected())
            feature.qualify(item)
            self.assertFalse(item["qualified"])
            self.assertEqual(item["commands"][0]["evidence_status"], "complete")
        item = record(source)
        failure = InvalidEvidence("feature_command_failed")
        feature.remember(item, "command", failure)
        feature.remember(item, "capture", InvalidEvidence("feature_capture_changed"))
        feature.remember(item, "postflight", KeyboardInterrupt())
        self.assertEqual(item["first_failure"], {"stage": "command", "code": str(failure)})
        self.assertEqual(item["secondary_failures"], [{"stage": "capture", "code": "feature_capture_changed"},
            {"stage": "postflight", "code": "interrupted"}])
        feature.qualify(item)
        self.assertFalse(item["qualified"])
        # Actual process fields must survive both a failed capture read and a
        # changed postflight, without replacing the first subprocess outcome.
        item = record(source)
        item["commands"] = [feature.command_spec()]
        actual = {key: value for key, value in command().items() if key in {
            "start_utc", "exit_code", "termination", "seconds", "private_log_sha256",
            "cleanup_complete", "reaped_descendants", "child_discovery_strategy"}}
        actual.update(exit_code=-9, termination="timeout", reaped_descendants=1)
        published = []
        with patch.object(feature, "run_command", return_value=actual) as invoked, \
                patch.object(feature, "bounded_read", side_effect=OSError):
            guards = iter((None, InvalidEvidence("feature_environment_changed")))

            def stable():
                error = next(guards)
                if error is not None:
                    raise error

            feature.execute(item, {}, Path("unused_private_model"), selected(),
                lambda: published.append(copy.deepcopy(item)), stable)
        invoked.assert_called_once_with(list(feature.ARGV), {}, Path("unused_private_model/feature_pure.log"),
                                        180, 8 * 1024 * 1024)
        self.assertEqual(item["first_failure"], {"stage": "command", "code": "feature_command_failed"})
        self.assertEqual([row["stage"] for row in item["secondary_failures"]], ["capture", "postflight"])
        self.assertEqual({key: item["commands"][0][key] for key in actual}, actual)
        self.assertEqual(published[1]["commands"][0]["termination"], "timeout")
        self.assertNotIn("observation", published[1]["commands"][0])

    def test_feature_receipt_binds_source_environment_limits_and_runner(self):
        _, _, _, source = fixture()
        metadata(record(source), source)
        for key, value in (("qualified", False), ("qualification_protocol", True), ("runner_sha256", "f" * 64),
            ("method_inventory_sha256", "f" * 64), ("pure_methods", 23), ("native_methods", True),
            ("filtered_out", 3), ("affinity_cpu_count", 9), ("cleanup_seconds", 4),
            ("log_limit_bytes_per_command", feature.LOG_LIMIT + 1), ("extra", "PRIVATE_SENTINEL"),
            ("run_id", "../private"), ("first_failure", {"stage": "command", "code": "feature_command_failed"})):
            with self.subTest(key=key), self.assertRaises(InvalidEvidence):
                metadata(record(source) | {key: value}, source)
        for modify in (lambda v: v["environment"].update(RUST_TEST_THREADS="1"),
                       lambda v: v["environment"].update(RLIMIT_CORE=False),
                       lambda v: v["commands"][0].update(timeout_seconds=181),
                       lambda v: v["commands"][0]["argv"].append("--ignored"),
                       lambda v: v["commands"][0].update(environment_delta={"RUST_TEST_THREADS": None}),
                       lambda v: v["commands"].append(copy.deepcopy(v["commands"][0]))):
            changed = record(source)
            modify(changed)
            with self.assertRaises(InvalidEvidence):
                metadata(changed, source)

    def test_feature_authentication_replays_actual_hash_bound_capture(self):
        files, corpus, _, source = fixture()
        item = record(source)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name, data in files.items():
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
            capture = root / "target/evaluation/admission" / RUN_ID / "feature_pure.log"
            capture.parent.mkdir(parents=True)
            capture.write_bytes(log())
            kwargs = {"source": source, "configuration": {"files": []}, "hardware": {"affinity_cpu_count": 8},
                "toolchain": {"cargo": "synthetic"}, "corpus": corpus,
                "corpus_digest": source["source_sha256"]["evaluation/admission/corpus.json"]}
            with patch.object(feature, "ROOT", root):
                self.assertEqual(feature.authenticate_prerequisite(item, **kwargs), {
                    "qualified": True, "revision": REVISION, "private_log_sha256": feature.run.sha(log()),
                    "method_inventory_sha256": source["source_sha256"][feature.INVENTORY],
                    "pure_methods": 2, "native_methods": 0, "policy": feature.POLICY})
                changed = copy.deepcopy(item)
                changed["commands"][0]["observation"]["methods"][0]["status"] = "ignored"
                with self.assertRaisesRegex(InvalidEvidence, "feature_receipt_replay"):
                    feature.authenticate_prerequisite(changed, **kwargs)
                capture.write_bytes(log() + b" ")
                with self.assertRaisesRegex(InvalidEvidence, "feature_receipt_capture_hash"):
                    feature.authenticate_prerequisite(item, **kwargs)
                capture.write_bytes(log().replace(METHODS[1].encode(), METHODS[0].encode()))
                changed = copy.deepcopy(item)
                changed["commands"][0]["private_log_sha256"] = feature.run.sha(capture.read_bytes())
                with self.assertRaisesRegex(InvalidEvidence, "feature_receipt_replay"):
                    feature.authenticate_prerequisite(changed, **kwargs)
