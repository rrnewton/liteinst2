#!/usr/bin/env python3
"""Prospective synthetic saved-record controls only; no producer/main execution."""
import hashlib
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest

if sys.flags.optimize:
    raise SystemExit('assertions required')

SOURCE = Path(__file__).resolve().with_name('produce.py')
SPEC = importlib.util.spec_from_file_location('production_profile_subject', SOURCE)
P = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(P)  # Definitions only: producer main is never invoked.
OWNED = 'owned-foreign-neighbors-v1'
MARKER = b'LI2PLANNING\t1\nprofile\towned-foreign-neighbors-v1\nqualification_complete\tfalse\n'
ORIGINAL = b'synthetic original identity, not an ELF/application'
SELECTION = b'synthetic full two-site selection\n'
SITES = [dict(id='11', pc='0x1000', length='2', file_offset='64'),
         dict(id='29', pc='0x2000', length='5', file_offset='128')]
INV = dict(sites=SITES, data={'selection.txt': SELECTION})


def digest(data):
    return hashlib.sha256(data).hexdigest()


def envelope():
    return dict(schema=1, preparation={}, build_admission='pending', cells={},
                products={}, tools={}, files={})


def bundle(directory, complete, marker=None, rows=2, selection=SELECTION,
           duplicate=False, unindexed=False, wrong_marker_digest=False):
    flag = str(complete).lower()
    header = ['LI2REPORT\t1', 'original_sha256\t' + digest(ORIGINAL),
              'selection_sha256\t' + digest(SELECTION), 'candidate_complete\t' + flag,
              'qualification_complete\tfalse',
              'site\tpc\tfile_offset\tlength\tcore_tactic\tcandidate_emitted\trefusal_code\tstage\tdetail_hex']
    for site in SITES[:rows]:
        header.append('\t'.join([site['id'], str(int(site['pc'], 0)), site['file_offset'], site['length'],
            'Relocation' if complete else 'none', flag, 'none' if complete else '9',
            'none' if complete else 'core', '']))
    files = {'selection.txt': selection, 'report.tsv': ('\n'.join(header) + '\n').encode()}
    if complete:
        files['candidate.elf'] = b'synthetic candidate identity; never executed'
    if marker is not None:
        files['planning-profile.tsv'] = marker
    index = ['LI2BUNDLE\t1', 'original_sha256\t' + digest(ORIGINAL),
             'qualification_complete\tfalse', 'consumer_action\tRuntimeScan-while-gated-until-qualified']
    for name, data in sorted(files.items()):
        if unindexed and name == 'planning-profile.tsv':
            continue
        sha = '0' * 64 if wrong_marker_digest and name == 'planning-profile.tsv' else digest(data)
        line = f'file\t{name}\t{len(data)}\t{sha}'
        index.append(line)
        if duplicate and name == 'planning-profile.tsv':
            index.append(line)
    index_bytes = ('\n'.join(index) + '\n').encode()
    files['bundle-index.tsv'] = index_bytes
    files['COMPLETE'] = (f'LI2TOOL-DIRECTORY 1\nindex_sha256 {digest(index_bytes)}\n'
                         f'candidate_complete {flag}\nqualification_complete false\n').encode()
    for name, data in files.items():
        (directory / name).write_bytes(data)


class ProductionProfile(unittest.TestCase):
    def check_bundle(self, profile, complete, marker=None, **options):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary).resolve()
            bundle(directory, complete, marker, **options)
            return P.profiled_core_product(directory, INV, ORIGINAL, profile)

    def test_legacy_envelope_keeps_old_exact_schema(self):
        self.assertIsNone(P.planning_profile(envelope(), 'legacy'))
        with self.assertRaises(AssertionError):
            P.planning_profile(dict(envelope(), planning_profile=OWNED), 'legacy')

    def test_opt_in_requires_matching_caller_and_exact_command_marker(self):
        actual = P.planning_profile(dict(envelope(), planning_profile=OWNED), OWNED)
        self.assertEqual(actual, dict(schema=1, planning_profile=OWNED,
            core_subcommand='prepare-owned-neighbors', marker='planning-profile.tsv',
            marker_sha256=digest(MARKER), marker_bytes=len(MARKER), qualification_complete=False))
        self.assertEqual(P.CORE_PROFILES['legacy'], 'prepare')

    def test_missing_unknown_mismatched_or_extra_profile_refuses(self):
        cases = [(envelope(), OWNED), (dict(envelope(), planning_profile='legacy'), OWNED),
                 (dict(envelope(), planning_profile=OWNED, extra=True), OWNED),
                 (dict(envelope(), planning_profile=OWNED, schema=True), OWNED),
                 (envelope(), 'unknown')]
        for supplied, requested in cases:
            with self.subTest(requested=requested, supplied=supplied):
                with self.assertRaises(AssertionError):
                    P.planning_profile(supplied, requested)

    def test_legacy_complete_and_withheld_results_remain_distinct(self):
        for complete in (True, False):
            with self.subTest(complete=complete):
                self.assertIs(self.check_bundle('legacy', complete), complete)

    def test_owned_complete_and_withheld_results_keep_both_requested_rows(self):
        for complete in (True, False):
            with self.subTest(complete=complete):
                self.assertIs(self.check_bundle(OWNED, complete, MARKER), complete)

    def test_changed_but_self_consistently_indexed_marker_refuses(self):
        variants = [MARKER[:-1], MARKER.replace(b'\t1\n', b'\t2\n', 1),
                    MARKER.replace(b'owned-foreign-neighbors-v1', b'unknown'),
                    MARKER.replace(b'false', b'true')]
        for marker in variants:
            with self.subTest(marker=marker):
                with self.assertRaisesRegex(AssertionError, 'exact complete indexed planning marker required'):
                    self.check_bundle(OWNED, True, marker)

    def test_missing_opt_in_marker_refuses_at_profile_guard(self):
        with self.assertRaisesRegex(AssertionError, 'exact complete indexed planning marker required'):
            self.check_bundle(OWNED, False)

    def test_legacy_cannot_relabel_an_owned_bundle(self):
        with self.assertRaisesRegex(AssertionError, 'legacy preparation must not carry an opt-in marker'):
            self.check_bundle('legacy', True, MARKER)

    def test_unindexed_duplicate_or_bad_hash_marker_keeps_old_index_refusals(self):
        for options in (dict(unindexed=True), dict(duplicate=True), dict(wrong_marker_digest=True)):
            with self.subTest(options=options):
                with self.assertRaises(AssertionError):
                    self.check_bundle(OWNED, True, MARKER, **options)

    def test_profile_does_not_bypass_complete_selection_or_original_rows(self):
        for complete in (True, False):
            for options in (dict(rows=1), dict(selection=b'different complete selection\n')):
                with self.subTest(complete=complete, options=options):
                    with self.assertRaises(AssertionError):
                        self.check_bundle(OWNED, complete, MARKER, **options)


if __name__ == '__main__':
    unittest.main()
