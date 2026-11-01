#!/usr/bin/env python3
"""Pure controls; the complete-input case requires the four pinned CLI inputs."""
import argparse
import hashlib
import importlib.util
from pathlib import Path
import struct
import unittest

if not __debug__:
    raise SystemExit("assertions required")

SPEC = importlib.util.spec_from_file_location("owned_policy", Path(__file__).with_name("full_program_owned_policy.py"))
P = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(P)
INPUTS = None


class OwnedPolicyControls(unittest.TestCase):
    def test_ordinal_zero_mask_projection_and_collision(self):
        physical = 0x2000
        mask = (False, True, False, False)
        left = P.projection(physical, mask, 0x70000)
        right = P.projection(physical, mask, 0x71000)
        self.assertEqual(left, 0x62700)
        self.assertEqual(left, right)
        self.assertNotEqual(left & -4096, 0x70000)
        self.assertEqual(P.projection(physical, (False,) * 4, 0x70000), 0x70000)
        self.assertEqual(P.projection(physical, (True,) * 4, 0x70000), physical + 5 + 0x06060606)

    def test_u64_signed32_boundaries_and_negative_projection(self):
        physical = 1 << 32
        for delta in (-(1 << 31), (1 << 31) - 1):
            hint = physical + 5 + delta
            self.assertEqual(P.projection(physical, (False,) * 4, hint), hint)
        for delta in (-(1 << 31) - 1, 1 << 31):
            self.assertIsNone(P.projection(physical, (False,) * 4, physical + 5 + delta))
        self.assertIsNone(P.projection(P.U64 - 5, (False,) * 4, P.U64))
        self.assertIsNone(P.projection(0, (True, True, True, False), 0))
        for invalid in (-1, P.U64 + 1, True):
            with self.assertRaises(P.Refusal):
                P.projection(invalid, (False,) * 4, 0)

    def test_preferred_and_ordered_permit_are_not_rescue_search(self):
        window = (0x40ff0, 0x410f0)
        ranges = [(0x40000, 4096), (0x41000, 4096)]
        self.assertEqual(P.first_pun(window, 0x41080, ranges), 0x41080)
        self.assertEqual(P.first_pun(window, 0x80000, ranges), 0x40ff0)
        self.assertEqual(P.first_pun(window, 0x80000, list(reversed(ranges))), 0x41000)
        self.assertEqual(P.first_pun(window, None, [(0x40001, 8191)]), 0x41000)
        self.assertIsNone(P.first_pun(window, None, [(0x42000, 4096)]))
        # An in-window preferred target wins even outside permitted ranges.
        self.assertEqual(P.first_pun(window, 0x40ff5, [(0x42000, 4096)]), 0x40ff5)

    def test_t2_overlay_permit_and_independent_aligned_preference(self):
        pc, delta = 0x2000, 4
        victim = 0x100000 + ((pc + 7 + delta) % 65536)
        redirect = b"\xe9" + struct.pack("<i", victim - (pc + 7))
        window = P.pun_window(pc, redirect[:3])
        self.assertEqual(window, (0x50905, 0x50a05))
        selected = window[0]
        ranges = [(0x50000, 4096), (0x80000, 4096)]
        self.assertEqual(P.first_pun(window, 0x80000, ranges), selected)
        self.assertEqual(P.projection(pc, (False,) * 4, 0x80000), 0x80000)
        self.assertEqual(P.first_pun(window, selected + 1, ranges), selected + 1)

    def test_tail_and_window_refusals_are_not_hidden_by_other_pages(self):
        window = (0x40ff0, 0x41000)
        first = P.first_pun(window, 0x80000, [(0x40000, 4096), (0x41000, 4096)])
        self.assertEqual(first, 0x40ff0)
        self.assertTrue(P.fits_page(first, 16))
        self.assertFalse(P.fits_page(first, 17))
        self.assertFalse(P.fits_page(first, 4097))
        self.assertIsNone(P.pun_window(0, b"\xff\xff\xff"))
        self.assertEqual(P.window_pages((0x3fff0, 0x40010)), [0x40000])
        self.assertEqual(P.window_pages((P.SPAN - 16, P.SPAN + 16)), [P.SPAN - 4096])

    def test_physical_domain_order_and_mask_uses_all_heads(self):
        site = (1, 0x2041, 2, 0, 0x2000, 256, 0x2000, 128)
        heads = [0x1fff, 0x2000, 0x2001, 0x2038, 0x2039, 0x203e, 0x2041, 0x2043, 0x2044]
        actual = P.physicals(site, heads)
        self.assertEqual([p for p, _ in actual], [0x2041, 0x2038, 0x2001, 0x203e, 0x2039])
        self.assertEqual(actual[0][1], (False, True, True, False))
        self.assertEqual(actual[3][1], (False, False, True, False))

    def test_permits_keep_priority_and_existing_range_cap(self):
        self.assertEqual(P.permits([0x42000, 0x40000, 0x41000, 0x42000]),
                         [(0x42000, 4096), (0x40000, 8192)])
        with self.assertRaisesRegex(P.Refusal, "16-permit"):
            P.permits([0x40000 + i * 8192 for i in range(17)])
        with self.assertRaises(P.Refusal):
            P.permits([0x3f000])

    def test_complete_roster_overlap_and_missing_site_refuse(self):
        sites = [(i, 8192 + i * 8, 5, 0, 0, 0, 0, 0) for i in range(1, 2054)]
        allocations = {i: (P.LOW + i * 4096, [(P.LOW + i * 4096, 4096)], P.LOW + i * 4096)
                       for i in range(1, 2054)}
        P.validate(sites, allocations)
        with self.assertRaisesRegex(P.Refusal, "missing or extra"):
            P.validate(sites, {k: v for k, v in allocations.items() if k != 2053})
        collision = dict(allocations)
        collision[2053] = collision[1]
        with self.assertRaisesRegex(P.Refusal, "overlapping"):
            P.validate(sites, collision)
        with self.assertRaisesRegex(P.Refusal, "full allocation roster"):
            P.validate(sites[:-1], allocations)

    def test_full_pinned_source_policy_roster_and_unchanged_caps(self):
        self.assertIsNotNone(INPUTS, "four pinned inputs are mandatory; no skipped full-source case")
        raw, summary = P.policy(INPUTS)
        rows = raw.decode("ascii").splitlines()
        self.assertEqual(rows[0], "LI2DISASM-WHOLE-POLICY 1")
        self.assertEqual(rows[6], "limits 1048576 4096 2896 11862016 2936 12120064 12026544 2910 2147483648")
        self.assertEqual(len(rows), 8 + 3 * 2053)
        self.assertLessEqual(len(raw), 1048576)
        self.assertEqual(summary["heads"], 13143)
        self.assertEqual(summary["sites"], 2053)
        self.assertFalse(summary["qualification_complete"])
        self.assertEqual(summary["sha256"], hashlib.sha256(raw).hexdigest())
        for i in range(2053):
            self.assertEqual(rows[8 + 3 * i], f"search {i + 1} preferred 64 256 64 none 256 4096")
            for role, row in zip(("selected", "victim"), rows[9 + 3 * i:11 + 3 * i]):
                fields = row.split()
                self.assertEqual(fields[:3], ["allocation", str(i + 1), role])
                self.assertEqual(fields[4:6], ["1", "4096"])
                self.assertLessEqual(len(fields) - 6, 16)
        counts = summary["counters"]
        self.assertEqual(counts["b1_physical_candidates"], counts.get("b1_permitted_projections", 0)
                         + counts.get("b1_unavailable_arithmetic_or_hull", 0)
                         + counts.get("b1_unavailable_owned_or_reserved", 0))
        bad = dict(INPUTS, original=INPUTS["original"] + b"\0")
        with self.assertRaisesRegex(P.Refusal, "original pin"):
            P.policy(bad)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(allow_abbrev=False, add_help=False)
    for name in P.PINS:
        parser.add_argument("--" + name, type=Path, required=True)
    args, rest = parser.parse_known_args()
    INPUTS = {}
    for name in P.PINS:
        with getattr(args, name).open("rb") as stream:
            INPUTS[name] = stream.read(1048577)
    unittest.main(argv=[__file__, *rest])
