"""Fabricated CLI controls only; no capture, PMU or native qualification."""
import sys

if sys.flags.optimize:
    raise SystemExit("assertions required")
sys.dont_write_bytecode = True

from contextlib import redirect_stdout
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent


def sibling(name):
    spec = importlib.util.spec_from_file_location("_cli_test_" + name, HERE / (name + ".py"))
    if spec is None or spec.loader is None:
        raise RuntimeError("missing local test dependency")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


C, F = sibling("decode_perf"), sibling("test_perf_data")


def sha(data):
    return hashlib.sha256(data).hexdigest()


def wire(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False) + "\n").encode("ascii")


class DecodePerfTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="decode-perf-", dir=os.environ.get("TMPDIR"))
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.data = self.root / "data"
        self.command = self.root / "command.json"
        self.data.write_bytes(F.file())
        self.command.write_bytes(wire([os.fsdecode(a) for a in F.ARGV]))

    def args(self, data=None, command=False):
        data = self.data if data is None else data
        args = ["--data", str(data), "--sha256", sha(self.data.read_bytes())]
        if command:
            args += ["--command-json", str(self.command), "--command-sha256", sha(self.command.read_bytes())]
        return args

    def run_cli(self, args, *, script=None, prefix=(), env=None):
        script = HERE / "decode_perf.py" if script is None else script
        run = subprocess.run([sys.executable, *prefix, str(script), *args], cwd=self.root,
                             env=env, capture_output=True, timeout=5, check=False)
        self.assertEqual(run.stderr, b"")
        self.assertEqual(run.stdout.count(b"\n"), 1)
        return run, json.loads(run.stdout)

    def refused(self, args, code=None, **kwargs):
        run, summary = self.run_cli(args, **kwargs)
        self.assertEqual((run.returncode, summary["status"]), (2, "REFUSED"))
        if code is not None:
            self.assertEqual(summary["error"]["code"], code)
        self.assertNotIn(str(self.root).encode(), run.stdout)
        return summary

    def test_actual_cli_preserves_all_three_statuses_and_adverse_summary(self):
        cases = [(F.file(), 0), (F.file()[:-1], 2),
                 (F.file([F.sample(), F.record(0xffffffff), F.final_read()]), 3),
                 (F.file([F.sample(period=0, lost=2, enabled=2, running=1)]), 0)]
        for data, status in cases:
            with self.subTest(status=status, digest=sha(data)):
                self.data.write_bytes(data)
                expected = F.P.decode(data, F.ARGV)["summary"]
                run, _ = self.run_cli(self.args(command=True))
                self.assertEqual(run.returncode, status)
                self.assertEqual(run.stdout, wire(expected))
                self.assertNotIn(b"/fixture", run.stdout)
        self.assertTrue(expected["adverse"])

    def test_hashes_precede_import_and_file_reads_are_bounded_regular(self):
        isolated = self.root / "isolated"
        isolated.mkdir()
        script = isolated / "decode_perf.py"
        script.write_bytes((HERE / "decode_perf.py").read_bytes())
        (isolated / "perf_data.py").write_text("from pathlib import Path\nPath('imported').touch()\nraise RuntimeError('must not import')\n")
        args = self.args(command=True)
        for index, code in ((3, "data_hash"), (7, "command_hash")):
            wrong = args.copy()
            wrong[index] = ("0" if wrong[index][0] != "0" else "1") + wrong[index][1:]
            self.refused(wrong, code, script=script)
        self.assertFalse((self.root / "imported").exists())
        self.assertEqual(C.MAX_BYTES, 16 * 1024 * 1024)
        small = self.root / "small"
        small.write_bytes(b"12345678")
        self.assertEqual(C.read_bound(small, 8, sha(b"12345678"), "data"), b"12345678")
        small.write_bytes(b"123456789")
        with self.assertRaisesRegex(C.InputRefusal, "^data_regular_or_size$"):
            C.read_bound(small, 8, sha(b"123456789"), "data")
        self.command.write_bytes(b" " * (C.MAX_COMMAND_BYTES + 1))
        self.refused(self.args(command=True), "command_regular_or_size", script=script)
        fifo, link = self.root / "fifo", self.root / "link"
        os.mkfifo(fifo)
        link.symlink_to(self.data)
        for path, code in ((self.root, "data_regular_or_size"), (fifo, "data_regular_or_size"), (link, "data_io")):
            self.refused(self.args(data=path), code, script=script)
        self.assertFalse((self.root / "imported").exists())

    def test_command_json_preserves_raw_argv_and_refuses_mismatch_or_bad_shape(self):
        words = ["/fixture/perf", "", "line\nword", "\u03bc", "\udcff"]
        raw = [os.fsencode(word) for word in words]
        features = F.default_features(F.attr())
        features[11] = F.u32(len(raw)) + b"".join(F.text(word) for word in raw)
        data = F.file(features=features)
        self.data.write_bytes(data)
        self.command.write_bytes(wire(words))
        run, _ = self.run_cli(self.args(command=True))
        self.assertEqual((run.returncode, run.stdout), (0, wire(F.P.decode(data, raw)["summary"])))
        self.command.write_bytes(wire(words + ["different"]))
        self.refused(self.args(command=True), "cmdline_authority_mismatch")
        for invalid in (b"{", b"[]", b"{}", b'["\\u0000"]', b'["\\ud800"]', b'[1]', b"\xff", b"[NaN]"):
            self.command.write_bytes(invalid)
            self.refused(self.args(command=True))
        run, summary = self.run_cli(self.args())
        self.assertEqual(run.returncode, 0)
        self.assertIn("command_authority_not_supplied", summary["unresolved"])

    def test_closed_options_and_hash_domains_never_echo_paths(self):
        args = self.args()
        bad = [[], args[:-1], args + args, ["--unknown", str(self.data), *args[2:]],
               ["--data=" + str(self.data), *args[2:]], args + ["--command-json", str(self.command)],
               args + ["--command-sha256", "0" * 64]]
        for digest in ("", "A" * 64, "g" * 64, "0" * 63, "0" * 65):
            bad.append([*args[:3], digest])
        for words in bad:
            self.refused(words)
        run, _ = self.run_cli(args[2:] + args[:2])
        self.assertEqual(run.returncode, 0)

    def test_optimization_sibling_locality_and_no_bytecode(self):
        good = self.root / "good"
        good.mkdir()
        for name in ("decode_perf.py", "perf_data.py", "perf_records.py"):
            (good / name).write_bytes((HERE / name).read_bytes())
        for name in ("perf_data.py", "perf_records.py"):
            (self.root / name).write_text("raise RuntimeError('path hijack')\n")
        env = dict(os.environ, PYTHONPATH=str(self.root))
        env.pop("PYTHONDONTWRITEBYTECODE", None)
        script = good / "decode_perf.py"
        run, _ = self.run_cli(self.args(command=True), script=script, env=env)
        self.assertEqual(run.returncode, 0)
        for prefix in (("-O",), ("-O", "-c", "import runpy,sys;runpy.run_path(sys.argv[1],run_name='__main__')")):
            self.refused([], "assertions_required", script=script, prefix=prefix, env=env)
        self.assertFalse((good / "__pycache__").exists())
        self.assertFalse((self.root / "__pycache__").exists())

    def test_full_type_inventory_capacity_and_fixed_exception_privacy(self):
        summary = F.P.decode(F.file([F.record(0xffffffff)]), F.ARGV)["summary"]
        summary.update(type_counts={str(0xffffffff - i): 1 for i in range(100000)},
                       record_count=100000, decoded_record_count=0, record_bytes=800000)
        def invoke(**seam):
            output = io.StringIO()
            with patch.object(C, "inspect", **seam), redirect_stdout(output):
                status = C.main([])
            return status, output.getvalue().encode("ascii")
        status, output = invoke(return_value=summary)
        self.assertEqual((status, output), (3, wire(summary)))
        self.assertLessEqual(len(output), C.MAX_SUMMARY_BYTES)
        large = dict(summary, unresolved=["x" * C.MAX_SUMMARY_BYTES])
        status, output = invoke(return_value=large)
        limited = json.loads(output)
        self.assertEqual((status, limited["status"], limited["error"]["code"]), (2, "REFUSED", "summary_output_cap"))
        self.assertEqual((limited["decoder_status"], limited["record_count"], limited["decoded_record_count"], limited["record_bytes"]),
                         ("UNSUPPORTED", 100000, 0, 800000))
        status, output = invoke(side_effect=RuntimeError("/private/path --secret-argv"))
        self.assertEqual((status, json.loads(output)["error"]["code"]), (2, "unexpected_decoder_or_wrapper_error"))
        self.assertEqual(output, wire({"status": "REFUSED", "error": {"code": "unexpected_decoder_or_wrapper_error", "offset": None},
                                       "authority": "syntax only; no capture or accounting qualification"}))


if __name__ == "__main__":
    unittest.main()
