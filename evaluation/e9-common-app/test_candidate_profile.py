#!/usr/bin/env python3
"""Prospective synthetic saved-record controls; never run a candidate or recipe main."""
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest

if sys.flags.optimize:
    raise SystemExit('assertions required')

SPEC = importlib.util.spec_from_file_location('ordinary_profile_subject', Path(__file__).with_name('run_candidates.py'))
P = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(P)  # Definitions only; main and all process launch paths remain unused.
OWNED = 'owned-foreign-neighbors-v1'
MARKER = b'LI2PLANNING\t1\nprofile\towned-foreign-neighbors-v1\nqualification_complete\tfalse\n'
SITES = [dict(id='11', pc='0x1000', file_offset='64', length='2'),
         dict(id='29', pc='0x2000', file_offset='128', length='5')]
KEYS = [h + '-' + s + '-' + v for h in ('null', 'journal') for s in ('jump-site', 'heap-write') for v in ('unstripped', 'stripped')]
LANES = ('stock-algorithm', 'bootstrap-patched-reference')


def digest(data):
    return hashlib.sha256(data).hexdigest()


def put(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(value if type(value) is bytes else json.dumps(value, sort_keys=True).encode())


def get(path):
    return json.loads(path.read_bytes())


def profile_record():
    return dict(schema=1, planning_profile=OWNED, core_subcommand='prepare-owned-neighbors',
                marker='planning-profile.tsv', marker_sha256=digest(MARKER),
                marker_bytes=len(MARKER), qualification_complete=False)


def ordinary_envelope():
    return dict(schema=1, source_epoch='synthetic', preparation={}, build_admission='synthetic',
                observation_content_admission='synthetic', production_admission='synthetic',
                runtime_admission='synthetic', tools={}, files={})


class SavedProduction:
    """Small explicit input fixture, not actual compiler/helper/native evidence."""
    def __init__(self, base, profile):
        self.base, self.root, self.profile = base, base / 'production', profile
        self.root.mkdir()
        self.originals = {v: ('synthetic original ' + v).encode() for v in ('unstripped', 'stripped')}
        self.original_paths = {v: str(base / ('original-' + v)) for v in self.originals}
        for variant, data in self.originals.items():
            put(Path(self.original_paths[variant]), data)
        self.products = {'liteinst-rewrite': str(base / 'never-executed-core'), 'common_sites': str(base / 'never-executed-sites')}
        self.tracked = dict(revision='a' * 40, files={})
        self.inv, self.cells, self.rows = {}, {}, []
        for number, key in enumerate(KEYS):
            inventory = base / 'inventory' / key
            put(inventory / 'selection.txt', ('complete synthetic two-site selection ' + key + '\n').encode())
            self.inv[key] = dict(directory=str(inventory), sites=SITES)
            if number == 4:
                self.rows += [dict(name=n, status='UNRUN') for n in ('hook-compile', 'hook-link')]
            complete = number == 0
            self.bundle(key, complete, MARKER if profile == OWNED else None)
            directory = self.root / (key + '-core')
            variant = 'unstripped' if key.endswith('-unstripped') else 'stripped'
            request = dict(argv=[self.products['liteinst-rewrite'], 'prepare-owned-neighbors' if profile == OWNED else 'prepare',
                self.original_paths[variant], str(inventory / 'selection.txt'), str(self.root / key / 'core')],
                cwd=str(base), env={'LC_ALL': 'C'}, stdout=str(directory / 'stdout.txt'),
                stderr=str(directory / 'stderr.txt'), cpu_seconds=20, wall_seconds=30, file_bytes=16 * 1024 * 1024)
            put(directory / 'request.json', request)
            put(directory / 'stdout.txt', b'synthetic saved stdout\n'); put(directory / 'stderr.txt', b'')
            self.rows.append(dict(name=key + '-core', status='PASS' if complete else 'FAILED', exit=0 if complete else 2))
            self.rows += [dict(name=key + '-' + lane + '-' + phase, status='UNRUN')
                          for lane in LANES for phase in ('transport', 'producer', 'adapter', 'compare')]
            self.cells[key] = dict(core=dict(complete=complete), references={})
        evidence = [str(base / 'review.json'), str(base / 'parent.json')]
        for value in evidence:
            put(Path(value), dict(synthetic=True))
        self.admission = dict(schema=1, authority='CALLER_ADMITTED_COMMON_PRODUCTION_ARTIFACTS',
            scope='closed-production-artifacts-only', source_revision=self.tracked['revision'],
            directory=str(self.root), review_binding=evidence[0], evidence_files=evidence,
            parent_closed_reaped=True, parent_observation=evidence[1])
        build = base / 'build.json'
        put(build, dict(authority='CALLER_AUTHENTICATED_BUILD_PRODUCTS', scope='core-cli-and-common-sites-build-only',
            source_revision=self.tracked['revision'], source_files_sha256=digest(b'{}'),
            products=dict(core=self.products['liteinst-rewrite'], common_sites=self.products['common_sites']),
            required_products=[], evidence_files=evidence))
        inputs = dict(schema=1, preparation=dict(originals=self.original_paths), build_admission=str(build),
                      cells={k: dict(directory=v['directory']) for k, v in self.inv.items()}, products={}, tools={}, files={})
        summary = dict(revision=self.tracked['revision'], fatal=None, successful=False, planned_stages=74,
                       ordinary_dataset_executions=0, native_executions=0, qualification_complete=False)
        if profile == OWNED:
            self.admission['planning_profile'] = inputs['planning_profile'] = OWNED
            summary['planning_profile'] = profile_record()
            put(self.root / 'planning-profile.json', profile_record())
        put(self.root / 'inputs.json', inputs); put(self.root / 'summary.json', summary)
        put(self.root / 'source-before.json', self.tracked); put(self.root / 'source-after.json', self.tracked)
        self.seal()

    def bundle(self, key, complete, marker, count=2, duplicate=False, unindexed=False, bad_hash=False):
        directory = self.root / key / 'core'
        if directory.exists():
            for child in directory.iterdir():
                child.unlink()  # Only this fresh synthetic fixture's regular files.
        variant = 'unstripped' if key.endswith('-unstripped') else 'stripped'
        original = self.originals[variant]
        selection = (Path(self.inv[key]['directory']) / 'selection.txt').read_bytes()
        flag = str(complete).lower()
        report = ['LI2REPORT\t1', 'original_sha256\t' + digest(original), 'selection_sha256\t' + digest(selection),
                  'candidate_complete\t' + flag, 'qualification_complete\tfalse',
                  'site\tpc\tfile_offset\tlength\tcandidate_emitted\trefusal_code']
        report += ['\t'.join([s['id'], str(int(s['pc'], 0)), s['file_offset'], s['length'], flag, 'none' if complete else '9']) for s in SITES[:count]]
        files = {'selection.txt': selection, 'report.tsv': ('\n'.join(report) + '\n').encode()}
        if complete:
            files['candidate.elf'] = b'synthetic candidate bytes; not executable'
        if marker is not None:
            files['planning-profile.tsv'] = marker
        lines = ['LI2BUNDLE\t1', 'original_sha256\t' + digest(original), 'qualification_complete\tfalse',
                 'consumer_action\tRuntimeScan-while-gated-until-qualified']
        for name, data in sorted(files.items()):
            if unindexed and name == 'planning-profile.tsv':
                continue
            sha = '0' * 64 if bad_hash and name == 'planning-profile.tsv' else digest(data)
            line = f'file\t{name}\t{len(data)}\t{sha}'
            lines.append(line)
            if duplicate and name == 'planning-profile.tsv':
                lines.append(line)
        index = ('\n'.join(lines) + '\n').encode()
        files['bundle-index.tsv'] = index
        files['COMPLETE'] = (f'LI2TOOL-DIRECTORY 1\nindex_sha256 {digest(index)}\ncandidate_complete {flag}\nqualification_complete false\n').encode()
        for name, data in files.items():
            put(directory / name, data)

    def seal(self, omit_profile_index=False):
        # Mutations may be self-consistently hashed, so profile/old schema guards
        # are tested rather than merely failing at a stale synthetic digest.
        for row in self.rows:
            if row['status'] == 'UNRUN':
                continue
            directory = self.root / row['name']
            receipt = dict(request_sha256=digest((directory / 'request.json').read_bytes()), helper_sha256=P.HELPER_SHA,
                exit=row['exit'], wall_timeout=False, unexpected_descendants=[], absence_proof='ECHILD',
                stdout_sha256=digest((directory / 'stdout.txt').read_bytes()), stderr_sha256=digest(b''),
                elapsed_seconds=0.001, cleanup_events=[], cleanup_error=None, aborted=None, inputs_unchanged=True)
            put(directory / 'receipt.json', receipt)
            row['receipt_sha256'] = digest((directory / 'receipt.json').read_bytes())
        put(self.root / 'results.json', self.rows); put(self.root / 'cells.json', self.cells)
        index = {str(p.relative_to(self.root)): dict(sha256=digest(p.read_bytes()), bytes=p.stat().st_size)
                 for p in self.root.rglob('*') if p.is_file() and p != self.root / 'raw-files.json'}
        if omit_profile_index:
            del index['planning-profile.json']
        put(self.root / 'raw-files.json', index)
        self.catalog = {str(p): P.read(p) for p in self.base.rglob('*') if p.is_file()}

    def bound(self, value):
        data, owner = P.read(value)
        assert self.catalog[value] == (data, owner), 'synthetic caller owner/hash changed; no refresh'
        return data

    def consume(self, legacy_default=False):
        args = (self.admission, self.tracked, self.products, self.inv, self.originals, self.bound)
        return P.production_inputs(*args) if legacy_default else P.production_inputs(*args, self.profile)


class CandidateProfile(unittest.TestCase):
    def fixture(self, profile=OWNED):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        return SavedProduction(Path(temporary.name).resolve(), profile)

    def test_exact_ordinary_caller_schema_and_explicit_opt_in(self):
        self.assertIsNone(P.planning_profile(ordinary_envelope(), 'legacy'))
        self.assertIsNone(P.planning_profile(dict(ordinary_envelope(), planning_profile=OWNED), OWNED))
        for inputs, profile in [(ordinary_envelope(), OWNED), (dict(ordinary_envelope(), planning_profile=OWNED), 'legacy'),
                                (dict(ordinary_envelope(), planning_profile='legacy'), OWNED),
                                (dict(ordinary_envelope(), planning_profile=OWNED, extra=True), OWNED),
                                (ordinary_envelope(), 'unknown')]:
            with self.subTest(profile=profile, inputs=inputs), self.assertRaises(AssertionError):
                P.planning_profile(inputs, profile)

    def test_both_profiles_preserve_all_74_statuses_and_24_artifact_denominators(self):
        for profile in ('legacy', OWNED):
            with self.subTest(profile=profile):
                f = self.fixture(profile)
                root, summary, rows, artifacts = f.consume(legacy_default=profile == 'legacy')
                self.assertEqual(root, f.root)
                self.assertFalse(summary['successful'])
                self.assertEqual(rows, f.rows)
                self.assertEqual([sum(r['status'] == s for r in rows) for s in ('PASS', 'FAILED', 'UNRUN')], [1, 7, 66])
                self.assertEqual(list(artifacts), [k + '-' + lane for k in KEYS for lane in ('core', *LANES)])
                self.assertEqual(sum(a['eligible'] for a in artifacts.values()), 1)
                self.assertEqual(len(artifacts) * 8, 192)
                for key in KEYS:
                    core = artifacts[key + '-core']
                    self.assertEqual(len(core['site_rows']), 2)
                    if key != KEYS[0]:
                        self.assertIsNone(core['candidate'])
                        self.assertEqual([r['refusal_code'] for r in core['site_rows']], ['9', '9'])
                        self.assertEqual(core['reason'], 'core refused complete candidate; no executable artifact')

    def test_unchanged_six_argument_caller_does_not_silently_adopt_owned_profile(self):
        with self.assertRaisesRegex(AssertionError, 'legacy producer envelope has no planning profile'):
            self.fixture().consume(legacy_default=True)

    def test_profile_must_join_admission_input_summary_record_and_raw_index(self):
        for role in ('admission', 'inputs', 'summary', 'record', 'raw-index'):
            with self.subTest(role=role):
                f = self.fixture()
                if role == 'admission':
                    f.admission['planning_profile'] = 'legacy'
                elif role in ('inputs', 'summary'):
                    p = f.root / (role + '.json'); value = get(p)
                    value['planning_profile'] = 'legacy'; put(p, value)
                elif role == 'record':
                    p = f.root / 'planning-profile.json'; value = get(p)
                    value['qualification_complete'] = True; put(p, value)
                f.seal(omit_profile_index=role == 'raw-index')
                with self.assertRaises(AssertionError):
                    f.consume()

    def test_every_attempted_core_verb_is_checked_including_withheld_candidates(self):
        for key in KEYS:
            with self.subTest(key=key):
                f = self.fixture(); p = f.root / (key + '-core') / 'request.json'
                request = get(p); request['argv'][1] = 'prepare'; put(p, request); f.seal()
                with self.assertRaisesRegex(AssertionError, 'exact core planning profile argv required'):
                    f.consume()

    def test_full_core_command_original_selection_destination_and_arity_are_exact(self):
        for index, replacement in [(0, 'wrong-core'), (2, 'wrong-original'), (3, 'wrong-selection'), (4, 'wrong-output'), (5, 'extra')]:
            with self.subTest(index=index):
                f = self.fixture(); p = f.root / (KEYS[0] + '-core') / 'request.json'
                request = get(p)
                if index == 5:
                    request['argv'].append(replacement)
                else:
                    request['argv'][index] = str(f.base / replacement)
                put(p, request); f.seal()
                with self.assertRaisesRegex(AssertionError, 'exact core planning profile argv required'):
                    f.consume()

    def test_marker_presence_and_whole_self_consistent_bytes_required_for_both_outcomes(self):
        for key, complete in ((KEYS[0], True), (KEYS[1], False)):
            for marker in (None, MARKER.replace(b'false', b'true'), MARKER[:-1]):
                with self.subTest(key=key, marker=marker):
                    f = self.fixture(); f.bundle(key, complete, marker); f.seal()
                    with self.assertRaisesRegex(AssertionError, 'exact complete indexed planning marker required'):
                        f.consume()

    def test_old_bundle_index_and_complete_selection_guards_stay_active(self):
        for options in (dict(duplicate=True), dict(unindexed=True), dict(bad_hash=True), dict(count=1)):
            with self.subTest(options=options):
                f = self.fixture(); f.bundle(KEYS[0], True, MARKER, **options); f.seal()
                with self.assertRaises(AssertionError):
                    f.consume()

    def test_legacy_refuses_owned_marker_or_record_without_changing_legacy_schema(self):
        for extra in ('marker', 'record'):
            with self.subTest(extra=extra):
                f = self.fixture('legacy')
                if extra == 'marker':
                    f.bundle(KEYS[0], True, MARKER)
                else:
                    put(f.root / 'planning-profile.json', profile_record())
                f.seal()
                with self.assertRaises(AssertionError):
                    f.consume(legacy_default=True)

    def test_profile_does_not_relabel_failed_history_or_tolerate_missing_stage(self):
        for alteration in ('successful', 'missing-stage', 'fatal', 'source-after'):
            with self.subTest(alteration=alteration):
                f = self.fixture()
                if alteration == 'missing-stage':
                    f.rows.pop()
                elif alteration == 'source-after':
                    put(f.root / 'source-after.json', dict(f.tracked, changed=True))
                else:
                    p = f.root / 'summary.json'; value = get(p)
                    value[alteration] = True if alteration == 'successful' else {'message': 'synthetic owner failure'}
                    put(p, value)
                f.seal()
                with self.assertRaises(AssertionError):
                    f.consume()

    def test_pinned_bytes_and_six_owner_epoch_are_not_refreshed(self):
        f = self.fixture()
        put(f.root / 'planning-profile.json', dict(profile_record(), qualification_complete=True))
        with self.assertRaisesRegex(AssertionError, 'synthetic caller owner/hash changed; no refresh'):
            f.consume()


if __name__ == '__main__':
    unittest.main()
