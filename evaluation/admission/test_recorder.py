"""Orchestration regressions: no ambient campaign override or premature pass."""

import contextlib
import io
import json
import os
import subprocess
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import run


class RecorderTests(unittest.TestCase):
    def temporary(self):
        root = run.ROOT / "target/evaluation/test-recorder"
        root.mkdir(parents=True, exist_ok=True)
        return tempfile.TemporaryDirectory(dir=root)

    def test_absent_ptrace_policy_metadata_is_unknown_never_implicitly_zero(self):
        original = Path.read_text
        def without_policy(path, *args, **kwargs):
            if path == Path("/proc/sys/kernel/yama/ptrace_scope"):
                raise FileNotFoundError()
            return original(path, *args, **kwargs)
        with patch.object(Path, "read_text", without_policy):
            hardware = run.hardware()
        self.assertIsNone(hardware["ptrace_scope"])
        self.assertEqual(hardware["ptrace_scope_status"], "interface_absent")
        self.assertIs(type(hardware["cap_sys_ptrace"]), bool)

    def test_ambient_campaign_and_compiler_overrides_cannot_select_the_run(self):
        inherited = {"PATH": "/usr/bin", "HOME": "/cache", "CARGO_HOME": "/cargo-cache",
                     "LITEINST_RUNTIME_CONTROL_ORACLE_MODE": "emitter",
                     "LITEINST_EVALUATION": "1", "LIBTEST_FILTER": "one_test",
                     "RUST_TEST_THREADS": "1", "RUST_TEST_NOCAPTURE": "1",
                     "CARGO_ENCODED_RUSTFLAGS": "unexpected", "CARGO_PROFILE_TEST_OPT_LEVEL": "3",
                     "RUSTUP_TOOLCHAIN": "unreviewed", "RUSTC": "replacement",
                     "LD_PRELOAD": "unexpected", "PYTHONPATH": "unexpected"}
        env = run.controlled_environment(inherited, Path("private/tmp"))
        self.assertEqual(env["RUST_TEST_THREADS"], "4")
        self.assertEqual(env["PATH"], "/usr/bin")
        for key in set(inherited) - set(run.LOCATION_VARIABLES) - set(run.ENV):
            self.assertNotIn(key, env)
        self.assertEqual(env["CARGO_NET_OFFLINE"], "true")

    def test_relative_locations_are_refused_independent_of_invocation_directory(self):
        for overrides in ({"HOME": "relative"}, {"CARGO_HOME": "cache"},
                          {"PATH": "/usr/bin:relative"}, {"PATH": "/usr/bin:"}):
            with self.subTest(overrides=overrides), self.assertRaises(run.InvalidEvidence):
                run.controlled_environment({"PATH": "/usr/bin", "HOME": "/cache"} | overrides,
                                           Path("private/tmp"))

    def test_hidden_worktree_edit_and_ambient_git_redirect_cannot_authenticate_head(self):
        with self.temporary() as temporary:
            root = Path(temporary)
            env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
            def git(*args):
                return subprocess.check_output(["git", *args], cwd=root, env=env,
                                               stderr=subprocess.DEVNULL)
            git("init", "-q")
            (root / "fixture.rs").write_text("original")
            git("add", "fixture.rs")
            git("-c", "user.name=Evaluation Fixture", "-c", "user.email=fixture@example.invalid",
                "-c", "commit.gpgsign=false", "commit", "-qm", "fixture")
            expected = git("rev-parse", "HEAD").decode().strip()
            for flag in ("--assume-unchanged", "--skip-worktree"):
                (root / "fixture.rs").write_text("original")
                git("update-index", "--no-assume-unchanged", "--no-skip-worktree", "fixture.rs")
                git("update-index", flag, "fixture.rs")
                (root / "fixture.rs").write_text("hidden mutation")
                self.assertFalse(git("status", "--porcelain"))
                with patch.object(run, "ROOT", root), patch.dict(os.environ, {
                        "GIT_DIR": "/missing/repository", "GIT_WORK_TREE": "/different/checkout",
                        "GIT_INDEX_FILE": "/missing/index"}):
                    state = run.source_state()
                self.assertEqual(state["revision"], expected)
                self.assertFalse(state["head_sources_match"])
                self.assertFalse(state["tracked_clean"])

    def test_cargo_configuration_cannot_inject_campaign_or_build_settings(self):
        with self.temporary() as temporary:
            root = Path(temporary)
            (root / ".cargo").mkdir()
            (root / ".cargo/config.toml").write_text('[env]\nLITEINST_RUNTIME_CONTROL_ORACLE_MODE="emitter"\n')
            with patch.object(run, "ROOT", root), self.assertRaisesRegex(
                    run.InvalidEvidence, "unsupported_cargo_configuration"):
                run.cargo_configuration({"HOME": str(root)})

    def test_refusal_is_persisted_before_any_command_runs(self):
        for dirty, revision, untracked, expected in (
                (True, "a" * 40, [], "dirty_tracked_source"),
                (False, "b" * 40, [], "revision_differs"),
                (False, "a" * 40, ["new_source.rs"], "untracked_input")):
            with self.subTest(reason=expected), self.temporary() as temporary:
                root = Path(temporary)
                here = root / "evaluation/admission"
                here.mkdir(parents=True)
                (here / "corpus.json").write_text('{}')
                source = {"revision": revision, "tracked_clean": not dirty}
                with patch.object(run, "ROOT", root), patch.object(run, "HERE", here), \
                     patch.object(run, "source_state", return_value=source), \
                     patch.object(run, "git", return_value="\n".join(untracked).encode()), \
                     patch.object(run, "run_command") as command, \
                     patch("sys.argv", ["run.py", "--expect-revision", "a" * 40]), \
                     contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(run.main(), 1)
                command.assert_not_called()
                files = list((here / "results").glob("*.json"))
                self.assertEqual(len(files), 1)
                record = json.loads(files[0].read_text())
                self.assertEqual(record["status"], "refused")
                self.assertEqual(record["error_code"], expected)
                self.assertTrue(all(c["status"] == "not_run" for c in record["commands"]))

    def test_missing_corpus_is_a_durable_refusal(self):
        with self.temporary() as temporary:
            root = Path(temporary)
            source = {"revision": "a" * 40, "tracked_clean": True}
            with patch.object(run, "ROOT", root), patch.object(run, "HERE", root), \
                 patch.object(run, "source_state", return_value=source), \
                 patch.object(run, "git", return_value=b""), \
                 patch.object(run, "run_command") as command, \
                 patch("sys.argv", ["run.py", "--expect-revision", "a" * 40]), \
                 contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(run.main(), 1)
            command.assert_not_called()
            record = json.loads(next((root / "results").glob("*.json")).read_text())
            self.assertEqual(record["status"], "refused")
            self.assertEqual(record["error_type"], "FileNotFoundError")
            self.assertIsNone(record["corpus_sha256"])

    def test_same_count_with_skips_or_expected_failures_cannot_pass_recorder(self):
        for terminal in ("OK (skipped=1)", "OK (expected failures=1)"):
            command = {"id": "recorder_tests", "status": "passed", "exit_code": 0}
            corpus = {"recorder_tests": 12, "harness_test_counts": {}}
            run.command_evidence(command, "Ran 12 tests in 0.1s\n\n" + terminal, corpus)
            self.assertEqual(command["status"], "invalid_evidence")
            self.assertNotIn("tests_passed", command)

    def test_failed_recorder_retains_assertion_observations_without_qualifying_command(self):
        command = {"id": "recorder_tests", "status": "failed", "exit_code": 0,
                   "termination": "descendants_after_exit"}
        corpus = {"recorder_tests": 52, "harness_test_counts": {}}
        run.command_evidence(command, "Ran 52 tests in 0.1s\n\nOK\n", corpus)
        self.assertEqual(command["status"], "failed")
        self.assertEqual(command["recorder_observations"],
                         {"tests_run": 52, "exact_ok_terminal": True})
        self.assertNotIn("tests_passed", command)

    def test_partial_compile_failure_retains_primary_exit_and_missing_observations(self):
        command = {"id": "workspace_tests", "status": "failed", "exit_code": 101}
        corpus = {"harness_test_counts": {"workspace_tests": {"unit/example/lib":
                  {"tests": 2, "ignored": 0}}}}
        run.command_evidence(command, "compiler failed", corpus)
        self.assertEqual(command["status"], "failed")
        self.assertEqual(command["exit_code"], 101)
        self.assertEqual(command["evidence_status"], "incomplete")
        self.assertEqual(command["harnesses"][0]["id"], "unit/example/lib")
        self.assertNotIn("compiler failed", json.dumps(command))

    def test_successful_exit_without_expected_cohort_is_invalid(self):
        command = {"id": "workspace_tests", "status": "passed", "exit_code": 0}
        corpus = {"harness_test_counts": {"workspace_tests": {"unit/example/lib":
                  {"tests": 2, "ignored": 0}}}}
        run.command_evidence(command, "", corpus)
        self.assertEqual(command["status"], "invalid_evidence")

    def test_source_or_configuration_drift_disqualifies_prior_native_success(self):
        for source_ok, config_ok in ((False, True), (True, False), (None, True)):
            record = {"source_unchanged": source_ok, "configuration_unchanged": config_ok,
                      "commands": [{"status": "passed", "native_cases": [
                          {"qualified_run": False, "command_succeeded": True}]}]}
            run.qualify(record)
            self.assertEqual(record["status"], "failed")
            self.assertFalse(record["commands"][0]["native_cases"][0]["qualified_run"])

    def test_later_command_failure_or_nonexecution_disqualifies_native_success(self):
        for status in ("failed", "not_run", "invalid_evidence"):
            record = {"source_unchanged": True, "configuration_unchanged": True,
                      "commands": [{"status": "passed", "native_cases": [
                          {"qualified_run": False, "command_succeeded": True}]}, {"status": status}]}
            run.qualify(record)
            self.assertEqual(record["status"], "failed")
            self.assertFalse(record["commands"][0]["native_cases"][0]["qualified_run"])

    def test_completed_unchanged_experiment_qualifies_only_successful_command_rows(self):
        record = {"source_unchanged": True, "configuration_unchanged": True,
                  "commands": [{"status": "passed", "native_cases": [
                      {"qualified_run": False, "command_succeeded": True}]}]}
        run.qualify(record)
        self.assertEqual(record["status"], "passed")
        self.assertTrue(record["commands"][0]["native_cases"][0]["qualified_run"])


if __name__ == "__main__":
    unittest.main()
