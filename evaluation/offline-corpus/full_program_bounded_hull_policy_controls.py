#!/usr/bin/env python3
"""Pure mandatory controls; no planner/native execution and no skipped inputs."""
import argparse
import hashlib
import importlib.util
from pathlib import Path
import unittest

if not __debug__:
    raise SystemExit("assertions required")


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


P = module("bounded_hull_policy", "full_program_bounded_hull_policy.py")
LEGACY = module("legacy_full_policy", "full_program_policy.py")
INPUTS = POLICY = None


class BoundedHullControls(unittest.TestCase):
    def test_clip_preserves_priority_duplicates_and_both_boundaries(self):
        ranges = [(P.HIGH - 8192, 16384), (0, P.LOW + 4096),
                  (P.HIGH, 4096), (P.LOW + 8192, 4096), (P.LOW + 8192, 4096)]
        self.assertEqual(P.clip_permits(ranges),
            [(P.HIGH - 8192, 8192), (P.LOW, 4096), (P.LOW + 8192, 4096), (P.LOW + 8192, 4096)])
        self.assertEqual(ranges[0], (P.HIGH - 8192, 16384))

    def test_empty_intersections_refuse_the_role_without_inventing_ranges(self):
        self.assertEqual(P.clip_permits([(0, P.LOW), (P.HIGH, 4096)]), [])
        for role in ("selected", "victim"):
            with self.assertRaisesRegex(P.Refusal, "complete policy refused"):
                P.allocation(f"allocation 7 {role} {P.LOW} 1 4096 0:{P.LOW} {P.HIGH}:4096", 7, role)

    def test_exact_upper_boundary_has_no_page_above_the_arena(self):
        self.assertEqual(P.clip_permits([(P.HIGH - 4096, 4096)]), [(P.HIGH - 4096, 4096)])
        self.assertEqual(P.clip_permits([(P.HIGH, 4096)]), [])
        self.assertEqual(P.clip_permits([(P.HIGH - 4096, 8192)]), [(P.HIGH - 4096, 4096)])
        line = f"allocation 1 selected {P.HIGH + 1} 1 4096 {P.HIGH - 4096}:8192"
        bounded = P.allocation(line, 1, "selected").split()
        self.assertEqual(bounded[:6], line.split()[:6])
        self.assertEqual(bounded[6:], [f"{P.HIGH - 4096}:4096"])
        # Retaining a numerical hint does not add its page to the permissions.
        self.assertNotIn(f"{P.HIGH}:4096", bounded)

    def test_invalid_geometry_overflow_and_existing_range_cap_refuse(self):
        invalid = [[(True, 4096)], [(0, True)], [(-4096, 4096)], [(0, 0)],
                   [(P.LOW + 1, 4096)], [(P.LOW, 4095)], [(P.U64 - 4095, 4096)],
                   [(P.U64 + 1, 4096)], [], [(P.LOW + i * 4096, 4096) for i in range(17)]]
        for ranges in invalid:
            with self.subTest(ranges=ranges), self.assertRaises(P.Refusal):
                P.clip_permits(ranges)

    def test_allocation_preserves_hints_and_rejects_changed_role_caps(self):
        line = f"allocation 19 victim {P.LOW + 23} 1 4096 {P.HIGH}:4096 {P.LOW}:8192"
        self.assertEqual(P.allocation(line, 19, "victim"), f"allocation 19 victim {P.LOW + 23} 1 4096 {P.LOW}:8192")
        for invalid in (line.replace(" 1 4096 ", " 2 4096 "),
                        line.replace(" 1 4096 ", " 1 8192 "),
                        line.replace("allocation 19", "allocation 18"),
                        line.replace(" victim ", " selected "), line + " 0:0"):
            with self.subTest(row=invalid), self.assertRaises(P.Refusal):
                P.allocation(invalid, 19, "victim")

    def test_complete_pinned_population_and_legacy_outputs_remain_exact(self):
        self.assertIsNotNone(INPUTS, "four pinned inputs are mandatory; no skipped full-source case")
        self.assertIsNotNone(POLICY, "the exact legacy 2GiB policy is mandatory")
        legacy = LEGACY.policies(INPUTS)
        self.assertEqual(set(legacy), {"policy-16m.txt", "policy-2g.txt"})
        self.assertEqual(legacy["policy-2g.txt"], POLICY)
        self.assertEqual(hashlib.sha256(legacy["policy-16m.txt"]).hexdigest(),
                         "d097e98b33b96421657e70bbbca4aa7fe48335adb6908746a04efc76d662f672")
        self.assertEqual(hashlib.sha256(legacy["policy-2g.txt"]).hexdigest(), P.POLICY_PIN[1])
        before = dict(legacy)
        raw, summary = P.bounded_policy(POLICY, INPUTS)
        self.assertEqual(legacy, before)
        old, new = POLICY.decode("ascii").splitlines(), raw.decode("ascii").splitlines()
        self.assertEqual(len(new), len(old))
        self.assertEqual(len(new), 8 + 3 * 2053)
        self.assertEqual(new[:6], old[:6]); self.assertEqual(new[7], old[7])
        self.assertEqual(new[6].split()[:-1], old[6].split()[:-1])
        self.assertEqual(new[6].split()[-1], "536870912")
        self.assertEqual(summary["selected_sites"], 2053); self.assertEqual(summary["heads"], 13143)
        self.assertEqual(summary["status"], "GENERATED_UNQUALIFIED")
        self.assertFalse(summary["qualification_complete"])
        self.assertEqual(summary["sha256"], hashlib.sha256(raw).hexdigest())
        self.assertEqual(summary["arena"], dict(start=262144, end_exclusive=536870912))
        self.assertLessEqual(len(raw), 1048576)
        seen = []
        for sid in range(1, 2054):
            at = 8 + 3 * (sid - 1)
            self.assertEqual(new[at], old[at])
            self.assertEqual(new[at], f"search {sid} preferred 64 256 64 none 256 4096")
            for offset, role in ((1, "selected"), (2, "victim")):
                a, b = old[at + offset].split(), new[at + offset].split()
                self.assertEqual(b[:6], a[:6]); self.assertEqual(b[:3], ["allocation", str(sid), role])
                self.assertEqual(b[4:6], ["1", "4096"])
                expected = []
                for token in a[6:]:
                    start, length = map(int, token.split(":"))
                    end = start + length
                    if end > 262144 and start < 536870912:
                        first = start if start >= 262144 else 262144
                        last = end if end <= 536870912 else 536870912
                        expected.append(f"{first}:{last - first}")
                self.assertEqual(b[6:], expected)
                self.assertGreaterEqual(len(b[6:]), 1); self.assertLessEqual(len(b[6:]), 16)
                for token in b[6:]:
                    start, length = map(int, token.split(":"))
                    self.assertEqual(start % 4096, 0); self.assertEqual(length % 4096, 0)
                    self.assertGreaterEqual(start, 262144); self.assertGreater(length, 0)
                    self.assertLessEqual(start + length, 536870912)
                seen.append((sid, role))
        self.assertEqual(seen, [(sid, role) for sid in range(1, 2054) for role in ("selected", "victim")])

    def test_input_and_legacy_policy_identity_failures_are_not_repaired(self):
        self.assertIsNotNone(INPUTS, "mandatory pinned input set")
        self.assertIsNotNone(POLICY, "mandatory pinned legacy policy")
        for name in P.PINS:
            with self.subTest(name=name), self.assertRaisesRegex(P.Refusal, name + " pin"):
                P.bounded_policy(POLICY, dict(INPUTS, **{name: INPUTS[name] + b"\0"}))
        with self.assertRaisesRegex(P.Refusal, "legacy 2GiB policy pin"):
            P.bounded_policy(POLICY + b"\n", INPUTS)
        for inputs in ({k: v for k, v in INPUTS.items() if k != "target"}, dict(INPUTS, extra=b"")):
            with self.assertRaisesRegex(P.Refusal, "four pinned inputs"):
                P.bounded_policy(POLICY, inputs)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(allow_abbrev=False, add_help=False)
    for name in P.PINS:
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--policy-2g", type=Path, required=True)
    args, rest = parser.parse_known_args()
    INPUTS = {}
    for name in P.PINS:
        with getattr(args, name).open("rb") as stream:
            INPUTS[name] = stream.read(1048577)
    with args.policy_2g.open("rb") as stream:
        POLICY = stream.read(1048577)
    unittest.main(argv=[__file__, *rest])
