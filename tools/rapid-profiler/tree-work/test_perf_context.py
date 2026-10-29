"""Fabricated context-diagnostic controls; no capture or attribution evidence."""
import sys

if sys.flags.optimize:
    raise SystemExit("assertions required")
sys.dont_write_bytecode = True

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("_context_fixtures", HERE / "test_perf_data.py")
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("missing local fixture module")
F = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(F)
P = F.P
U64 = (1 << 64) - 1


def sample(mode=2, *, ip=0x401004, exact=False, **kwargs):
    raw = F.set_value(F.sample(**kwargs), 4, mode | (0x4000 if exact else 0), 2)
    return F.set_value(raw, 16, ip)


class PerfContextTests(unittest.TestCase):
    def diagnostic(self, data, argv=F.ARGV):
        return P.decode_context_diagnostic(data, argv)

    def refused(self, raw, code, relative, *, fields=0x10197, read=23, status="REFUSED"):
        data = F.file([raw, F.sample(fields=fields, read=read)], a=F.attr(sample=fields, read=read))
        out = self.diagnostic(data)
        self.assertEqual(out["summary"]["status"], status)
        self.assertEqual(out["error"], {"code": code, "offset": out["inventory"][0]["offset"] + relative})
        self.assertEqual(len(out["inventory"]), 2)
        self.assertEqual(out["records"], [])
        self.assertIs(out["source_bytes"], data)
        self.assertIsNone(out["summary"]["file_sample_period_sum"])
        self.assertEqual(out["summary"]["unattributed_period_sum"], 0)
        return out

    def test_strict_profile_and_output_remain_separate(self):
        user = F.file()
        kernel = F.file([sample(1)])
        unknown = F.file([sample(3)])
        cases = [user, kernel, unknown, user[:-1]]
        before = [P.decode(data, F.ARGV) for data in cases]
        self.assertEqual([x["summary"]["status"] for x in before],
                         ["DECODED_UNQUALIFIED", "REFUSED", "REFUSED", "REFUSED"])
        for out in before[1:3]:
            self.assertEqual(out["error"], {"code": "sample_not_host_user", "offset": out["inventory"][0]["offset"] + 4})
        for data in cases:
            self.diagnostic(data)
        self.assertEqual([P.decode(data, F.ARGV) for data in cases], before)
        self.assertNotIn("profile", before[0]["summary"])
        self.assertNotIn("sample_context", before[0]["records"][0])
        self.assertNotIn("attribution", before[0]["records"][0])
        self.assertEqual(P.decode(kernel, F.ARGV)["records"], [])

    def test_mixed_host_contexts_keep_raw_bytes_and_exact_period_partition(self):
        raw = [sample(2, period=11), sample(1, ip=0, period=13),
               sample(2, period=17), F.final_read()]
        data = F.file(raw)
        out = self.diagnostic(data)
        summary = out["summary"]
        self.assertEqual(summary["status"], "CONTEXT_DIAGNOSTIC_UNQUALIFIED")
        self.assertEqual(summary["profile"], "host-user-kernel-context-v1")
        self.assertEqual(summary["sample_contexts"], {"host_user": {"records": 2, "period_sum": 28},
                                                    "host_kernel": {"records": 1, "period_sum": 13}})
        self.assertEqual((summary["decoded_sample_period_sum"], summary["file_sample_period_sum"],
                          summary["unattributed_period_sum"]), (41, 41, 41))
        self.assertEqual((summary["framed_sample_count"], summary["decoded_sample_count"]), (3, 3))
        self.assertEqual((summary["attribution"], summary["period_assignment"]), ("NOT_ATTEMPTED", "UNATTRIBUTED"))
        self.assertIs(out["source_bytes"], data)
        for index, original in enumerate(raw):
            entry, row = out["inventory"][index], out["records"][index]
            at = entry["offset"]
            self.assertEqual(data[at:at + entry["size"]], original)
            self.assertEqual(entry["sha256"], hashlib.sha256(original).hexdigest())
            self.assertEqual((row["offset"], row["misc"], row["size"]), (at, entry["misc"], len(original)))
        for row, mode, ip, period in zip(out["records"][:3], (2, 1, 2), (0x401004, 0, 0x401004), (11, 13, 17)):
            self.assertEqual((row["misc"], row["ip"], row["period"], row["attribution"]), (mode, ip, period, "UNATTRIBUTED"))
            self.assertEqual((row["identifier"], row["pid"], row["tid"], row["time"], row["cpu"]), (7, 101, 101, 80, 3))
        self.assertEqual(out["records"][-1], P.decode(F.file([F.final_read()]), F.ARGV)["records"][0] |
                         {"offset": out["records"][-1]["offset"]})
        self.assertNotIn("/fixture", json.dumps(summary))

    def test_kernel_ips_and_exact_bit_never_create_user_attribution(self):
        for ip in (0, 0x401004, U64):
            for exact in (False, True):
                data = F.file([sample(1, ip=ip, exact=exact, period=U64)])
                out = self.diagnostic(data)
                row, summary = out["records"][0], out["summary"]
                self.assertEqual((row["ip"], row["misc"], row["sample_context"], row["attribution"]),
                                 (ip, 1 | (0x4000 if exact else 0), "host_kernel", "UNATTRIBUTED"))
                self.assertEqual(summary["sample_contexts"], {"host_user": {"records": 0, "period_sum": 0},
                                                            "host_kernel": {"records": 1, "period_sum": U64}})
                self.assertEqual((summary["unattributed_period_sum"], summary["file_sample_period_sum"]), (U64, U64))
                self.assertIn("kernel_sample_context_not_user_attribution", summary["unresolved"])
                self.assertEqual(P.decode(data, F.ARGV)["error"]["code"], "sample_not_host_user")

    def test_unknown_modes_misc_and_kernel_payload_fail_at_exact_offsets(self):
        for mode in (0, 3, 4, 5, 6, 7):
            for exact in (False, True):
                self.refused(sample(mode, exact=exact), "unsupported_sample_context", 4, status="UNSUPPORTED")
        for bit in (*range(3, 14), 15):
            self.refused(F.set_value(sample(1), 4, 1 | (1 << bit), 2),
                         "sample_misc_extension", 4, status="UNSUPPORTED")
        raw = sample(1)
        for at, value, width, code, relative in (
                (8, 8, 8, "unknown_sample_id", 8), (24, 0, 4, "sample_task_domain", 0),
                (28, 0, 4, "sample_task_domain", 0), (44, 1, 4, "nonzero_reserved_or_padding", 44),
                (80, 8, 8, "unknown_read_id", 56), (72, 21, 8, "running_exceeds_enabled", 56)):
            self.refused(F.set_value(raw, at, value, width), code, relative)
        self.refused(F.record(9, raw[8:-1], 1), "truncated_field", 88)
        self.refused(F.record(9, raw[8:] + bytes(8), 1), "unconsumed_record_bytes", 96)
        optional = sample(1, fields=0x101d7)
        self.refused(F.set_value(optional, 40, 8), "sample_read_id_mismatch", 0, fields=0x101d7)
        for fields in (0x10197, 0x101d7, 0x10397, 0x103d7):
            for read in (7, 23):
                data = F.file([sample(1, fields=fields, read=read)], a=F.attr(sample=fields, read=read))
                self.assertEqual(self.diagnostic(data)["summary"]["status"], "CONTEXT_DIAGNOSTIC_UNQUALIFIED")

    def test_later_refusal_keeps_inventory_and_partial_mass_unresolved(self):
        for bad, code, relative in ((sample(3, period=11), "unsupported_sample_context", 4),
                                    (F.record(22), "unsupported_record_type", 0)):
            data = F.file([sample(2, period=5), sample(1, period=7), bad, sample(2, period=13)])
            out = self.diagnostic(data)
            summary = out["summary"]
            self.assertEqual(summary["status"], "UNSUPPORTED")
            self.assertEqual(out["error"], {"code": code, "offset": out["inventory"][2]["offset"] + relative})
            self.assertEqual((len(out["inventory"]), len(out["records"])), (4, 2))
            self.assertEqual((summary["decoded_sample_period_sum"], summary["unattributed_period_sum"]), (12, 12))
            self.assertEqual(summary["framed_sample_count"], 4 if code == "unsupported_sample_context" else 3)
            self.assertEqual(summary["decoded_sample_count"], 2)
            self.assertIsNone(summary["file_sample_period_sum"])
            self.assertIn("undecoded mass unresolved", summary["period_sum_scope"])
            self.assertIs(out["source_bytes"], data)
            last = out["inventory"][-1]
            self.assertEqual(last["sha256"], hashlib.sha256(data[last["offset"]:last["offset"] + last["size"]]).hexdigest())
        data = F.file([sample(1, period=5), F.set_value(F.record(68), 6, 7, 2)])
        out = self.diagnostic(data)
        self.assertFalse(out["walk_complete"])
        self.assertEqual((len(out["inventory"]), out["records"]), (1, []))
        self.assertEqual((out["summary"]["framed_sample_count"], out["summary"]["decoded_sample_count"]), (1, 0))
        self.assertIsNone(out["summary"]["file_sample_period_sum"])

    def test_zero_max_loss_read_caps_and_import_guards_remain_visible(self):
        lost = F.record(2, F.u64(7) + F.u64(9) + F.suffix())
        data = F.file([sample(2, period=0), sample(1, period=U64, lost=3, enabled=2, running=1),
                       sample(2, period=U64), lost, F.final_read()])
        out = self.diagnostic(data)
        self.assertEqual(out["summary"]["file_sample_period_sum"], 2 * U64)
        self.assertEqual(out["summary"]["unattributed_period_sum"], 2 * U64)
        self.assertEqual(set(out["adverse"]), {"zero_sample_period", "sample_read_lost_nonzero",
                                             "sample_read_enabled_running_unequal", "lost_records_nonzero"})
        self.assertEqual((out["records"][3]["lost"], out["records"][4]["read"]["value"]), (9, 12345))
        self.assertEqual(out["summary"]["sample_contexts"]["host_user"], {"records": 2, "period_sum": U64})
        self.assertIsNone(self.diagnostic(bytes(16 * 1024 * 1024 + 1))["summary"]["file_sample_period_sum"])
        at_cap = self.diagnostic(F.file([F.record(68)] * 100000))
        self.assertEqual((at_cap["summary"]["record_count"], at_cap["summary"]["file_sample_period_sum"]), (100000, 0))
        del at_cap
        over = self.diagnostic(F.file([F.record(68)] * 100001))
        self.assertEqual(over["error"]["code"], "record_count_cap")
        self.assertIsNone(over["summary"]["file_sample_period_sum"])
        for invalid in (None, "PERFILE2", bytearray(b"PERFILE2")):
            self.assertEqual(self.diagnostic(invalid)["error"]["code"], "bytes_required")
        with tempfile.TemporaryDirectory(prefix="perf-context-", dir=os.environ.get("TMPDIR")) as directory:
            root = Path(directory)
            (root / "perf_records.py").write_text("raise RuntimeError('path hijack')\n")
            for name in ("perf_data.py", "test_perf_context.py"):
                run = subprocess.run([sys.executable, "-O", str(HERE / name)], cwd=root,
                                     capture_output=True, timeout=5, check=False)
                self.assertEqual((run.returncode, run.stdout, run.stderr), (1, b"", b"assertions required\n"))
            code = ("import importlib.util,sys;s=importlib.util.spec_from_file_location('x',sys.argv[1]);"
                    "m=importlib.util.module_from_spec(s);s.loader.exec_module(m);"
                    "print(m.decode_context_diagnostic(b'')['summary']['profile'])")
            run = subprocess.run([sys.executable, "-B", "-c", code, str(HERE / "perf_data.py")], cwd=root,
                                 capture_output=True, timeout=5, check=False)
            self.assertEqual((run.returncode, run.stdout, run.stderr), (0, b"host-user-kernel-context-v1\n", b""))


if __name__ == "__main__":
    unittest.main()
