#!/usr/bin/env python3
"""Fabricated orchestration controls; no hardware, subprocess-ownership or study credit."""
import sys
if sys.flags.optimize:
    raise SystemExit('assertions required')
from copy import deepcopy
import csv
import importlib.util
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest

_spec = importlib.util.spec_from_file_location('reference_study_under_test',
    Path(__file__).with_name('reference_study.py'))
check = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(check)


def owned():
    request = dict(argv=['/fixture/binary', 'normal-reference-leg', 'calibration', '1', 'installed'],
        cwd='/fixture/repo', env={'LC_ALL': 'C'}, stdout='/fixture/stdout', stderr='/fixture/stderr',
        cpu_seconds=20, wall_seconds=30, file_bytes=1048576)
    stdout, stderr = b'finite output\n', b''
    request_hash = check.content(check.encoded(request))['sha256']
    helper_hash = 'd'*64
    receipt = dict(exit=0, wall_timeout=False, inputs_unchanged=True, absence_proof='ECHILD',
        unexpected_descendants=[], cleanup_events=[], cleanup_error=None, aborted=None,
        request_sha256=request_hash, helper_sha256=helper_hash,
        stdout_sha256=check.content(stdout)['sha256'], stderr_sha256=check.content(stderr)['sha256'])
    closed = dict(exit_code=0, termination=None, cleanup_complete=True, reaped_descendants=0)
    parent = dict(exit=0, wall_timeout=False, absence_proof='ECHILD', descendants=0, success=True)
    return [request, deepcopy(request), request_hash, helper_hash, receipt, closed, parent, stdout, stderr]


def catalog():
    # Shape-only orchestration fixture, not the production hash schedule.
    rows = []
    for phase in ('calibration', 'holdout', 'comparison'):
        for trial in range(1, 101):
            for position, leg in enumerate(('installed',) if phase != 'comparison' else
                    ('original', 'installed'), 1):
                rows.append(dict(process=len(rows)+1, phase=phase, trial=trial,
                    leg=leg, seed='%064x' % trial, position=position))
    return rows


def observation(key):
    installed = key['leg'] == 'installed'
    return dict(key, base=0, aux=0, pid=12, tid=12, generation=17 if installed else None,
        rows=[dict(process=key['process'], call=i, reference_start_offset=0, reference_end_offset=0,
            start_offset=0 if installed else None, end_offset=0 if installed else None)
            for i in range(1, 25)])


def first_hundred():
    keys = catalog(); progress = check.Progress(keys)
    for key in keys[:100]:
        progress.start(key); progress.finish(key, observation(key))
    return progress, keys


def prerequisite():
    names = tuple('stage%d' % i for i in range(30))
    result = dict(revision='a'*40, status='PASS', stage='complete',
        stages=[dict(name=n, status='PASS') for n in names],
        closure=dict(owned_stages=30, nested_normal_helpers=46, nested_outer_owners=48, rescues=0),
        native=dict(pairs=17, stable_pairs=16, crossed_pairs=1, children=34,
            target_calls=68, target_returns=68, outer_returns=34, helper_joins=1))
    for name, count in (('reference_exact', 13), ('reference_work', 3), ('reference_leg', 4)):
        result[name] = dict(status='PASS', stages=[dict(status='PASS') for _ in range(count)],
            closure=dict(owned_stages=count, normal_helpers=count, outer_owners=count, rescues=0))
    result['reference_exact'].update(old_exact=dict(status='PASS'), reference=dict(status='PASS'),
        complete_populations=dict(old_exact_pairs=4, reference_pairs=4, children=16,
            old_exact_comparisons=1696, reference_comparisons=1736, reference_reader_checks=32,
            reference_output_stores=96, reference_returned_cells=16))
    result['reference_work']['collector'] = dict(status='PASS')
    result['reference_leg']['legs'] = [dict(phase='qualification', trial=1, leg=leg, calls=24, status='PASS')
        for leg in ('original', 'installed')]
    return result, names


class StudyDriver(unittest.TestCase):
    def test_owned_receipt_requires_normal_exact_closure_and_all_hashes(self):
        check.join_owned(*owned())
        changes = {
            4: dict(exit=1, wall_timeout=True, inputs_unchanged=False, absence_proof='unknown',
                unexpected_descendants=[1], cleanup_events=[{}], cleanup_error='error', aborted='interrupt',
                request_sha256='0'*64, helper_sha256='0'*64,
                stdout_sha256='0'*64, stderr_sha256='0'*64),
            5: dict(exit_code=1, termination='timeout', cleanup_complete=False, reaped_descendants=1),
            6: dict(exit=1, wall_timeout=True, absence_proof='unknown', descendants=1, success=False)}
        for index, fields in changes.items():
            for name, value in fields.items():
                args = owned(); args[index][name] = value
                with self.subTest(index=index, field=name), self.assertRaises(AssertionError):
                    check.join_owned(*args)
        for index, name in ((4, 'exit'), (5, 'exit_code'), (5, 'reaped_descendants'),
                (6, 'exit'), (6, 'descendants')):
            args = owned(); args[index][name] = False
            with self.assertRaises(AssertionError): check.join_owned(*args)

    def test_request_identity_and_actual_output_mutations_refuse(self):
        for name, value in dict(argv=['/different'], cwd='/elsewhere', env={},
                stdout='/wrong', stderr='/wrong', cpu_seconds=21, wall_seconds=31,
                file_bytes=1048575).items():
            args = owned(); args[1][name] = value
            with self.subTest(field=name), self.assertRaises(AssertionError): check.join_owned(*args)
        args = owned(); args[1]['cpu_seconds'] = 20.0
        with self.assertRaises(AssertionError): check.join_owned(*args)
        for index, data in ((7, b'changed'), (8, b'error'), (7, b'x'*(1048576+1))):
            args = owned(); args[index] = data
            if len(data) > 1048576:
                args[4]['stdout_sha256'] = check.content(data)['sha256']
            with self.assertRaises(AssertionError): check.join_owned(*args)

    def test_prerequisite_requires_all_thirty_stages_and_unchanged_populations(self):
        result, names = prerequisite()
        check.prerequisite_ok(result, 'a'*40, names)
        mutations = [
            lambda x: x.update(revision='b'*40), lambda x: x.update(status='FAILED'),
            lambda x: x['stages'].pop(), lambda x: x['stages'].reverse(),
            lambda x: x['stages'][0].update(status='UNRUN'),
            lambda x: x['closure'].update(rescues=1),
            lambda x: x['native'].update(pairs=16),
            lambda x: x['reference_exact']['complete_populations'].update(reference_pairs=3),
            lambda x: x['reference_work']['collector'].update(status='FAILED'),
            lambda x: x['reference_leg']['legs'][0].update(phase='comparison')]
        for group in ('reference_exact', 'reference_work', 'reference_leg'):
            mutations.extend((lambda x, g=group: x[g]['stages'][0].update(status='FAILED'),
                lambda x, g=group: x[g]['closure'].update(rescues=1)))
        for mutate in mutations:
            changed = deepcopy(result); mutate(changed)
            with self.assertRaises(AssertionError): check.prerequisite_ok(changed, 'a'*40, names)

    def test_prefix_ownership_refuses_retry_skip_duplicate_or_false_completion(self):
        keys = catalog(); progress = check.Progress(keys)
        with self.assertRaises(AssertionError): progress.start(keys[1])
        with self.assertRaises(AssertionError): progress.finish(keys[0], observation(keys[0]))
        progress.start(keys[0])
        with self.assertRaises(AssertionError): progress.start(keys[0])
        with self.assertRaises(AssertionError): progress.start(keys[1])
        wrong = observation(keys[0]); wrong['leg'] = 'original'
        with self.assertRaises(AssertionError): progress.finish(keys[0], wrong)
        self.assertEqual(progress.rows[0]['status'], 'FAILED')
        self.assertTrue(all(row['status'] == 'UNRUN' for row in progress.rows[1:]))
        with self.assertRaises(AssertionError): progress.complete()
        progress.finish(keys[0], observation(keys[0]))
        with self.assertRaises(AssertionError): progress.finish(keys[0], observation(keys[0]))
        with self.assertRaises(AssertionError): progress.complete()

    def test_frozen_calibration_is_required_before_holdout_and_overflow_is_retained(self):
        for status, b in (('EMPIRICAL_BUDGET', 0), ('UNRESOLVED_OVERFLOW', None)):
            progress, keys = first_hundred()
            budget = dict(status=status, Ue=0 if b == 0 else (1 << 64)-1, Ur=0 if b == 0 else 1,
                B=b, calibration_sha256='c'*64)
            analysis = SimpleNamespace(calibrate=lambda rows: deepcopy(budget), canonical=check.encoded)
            with self.assertRaises(AssertionError): progress.start(keys[100])
            changed = dict(budget, Ue=1)
            with self.assertRaises(AssertionError):
                progress.frozen_budget(changed, check.encoded(changed), analysis)
            with self.assertRaises(AssertionError):
                progress.frozen_budget(budget, check.encoded(budget)+b' ', analysis)
            progress.frozen_budget(budget, check.encoded(budget), analysis)
            with self.assertRaises(AssertionError):
                progress.frozen_budget(budget, check.encoded(budget), analysis)
            for key in keys[100:]:
                progress.start(key); progress.finish(key, observation(key))
            progress.complete()
            self.assertEqual(len(progress.observations), 400)
            self.assertEqual(sum(len(row['rows']) for row in progress.observations), 9600)
        empty = check.Progress(catalog())
        with self.assertRaises(AssertionError): empty.frozen_budget(budget, check.encoded(budget), analysis)

    def test_public_projection_retains_all_keys_and_exact_prefix_without_private_fields(self):
        keys = catalog(); progress = check.Progress(keys)
        progress.start(keys[0]); progress.finish(keys[0], observation(keys[0]))
        progress.start(keys[1]); progress.rows[1]['private'] = '/private/host/path'
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            check.exports(directory, progress, 'a'*64)
            with (directory/'processes.csv').open() as stream:
                process = list(csv.DictReader(stream))
            with (directory/'endpoints.csv').open() as stream:
                rows = list(csv.DictReader(stream))
            self.assertEqual(len(process), 400); self.assertEqual(len(rows), 24)
            self.assertEqual([row['status'] for row in process[:3]], ['FUNCTIONAL_PASS', 'FAILED', 'UNRUN'])
            self.assertEqual([int(row['call']) for row in rows], list(range(1, 25)))
            self.assertTrue(all(row['reference_start_offset'] == row['start_offset'] == '0' for row in rows))
            self.assertNotIn('/private/', (directory/'processes.csv').read_text())
            # Exact original absence remains empty even at the largest raw endpoint.
            key = keys[200]; original = observation(key)
            original['rows'][0]['reference_end_offset'] = (1 << 64)-1
            progress.observations = [original]
            check.exports(directory, progress, 'a'*64)
            with (directory/'endpoints.csv').open() as stream:
                rows = list(csv.DictReader(stream))
            self.assertEqual(rows[0]['reference_end_offset'], str((1 << 64)-1))
            self.assertTrue(all(row['start_offset'] == row['end_offset'] == '' for row in rows))

    def test_optimized_entry_refuses_before_any_project_import_or_cli(self):
        result = subprocess.run([sys.executable, '-O', '-B', str(Path(check.__file__).resolve()), '--help'],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, b'')
        self.assertEqual(result.stderr, b'assertions required\n')

    def test_completed_process_and_control_files_refuse_drift_and_pin_refresh(self):
        for label in ('process-001', 'test_reference_study'):
            with tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)/label; directory.mkdir()
                pins, row = {}, {}
                originals = {filename: (filename+'\n').encode('ascii') for _, filename in check.FILES}
                for filename, data in originals.items():
                    path = directory/filename; path.write_bytes(data)
                    check.retain(pins, path, check.content(data))
                check.record_files(row, directory, pins)
                expected_pins, expected_row = deepcopy(pins), deepcopy(row)
                check.pinned_unchanged(pins)
                for filename, original in originals.items():
                    path = directory/filename; path.write_bytes(original+b'changed')
                    with self.subTest(label=label, filename=filename):
                        with self.assertRaises(AssertionError): check.pinned_unchanged(pins)
                        with self.assertRaises(AssertionError): check.retain(pins, path, check.digest(path))
                        with self.assertRaises(AssertionError): check.record_files(row, directory, pins)
                        self.assertEqual(pins, expected_pins)
                        self.assertEqual(row, expected_row)
                    path.write_bytes(original)
                check.pinned_unchanged(pins)
                (directory/'stdout.txt').unlink()
                with self.assertRaises(FileNotFoundError): check.pinned_unchanged(pins)

    def test_prerequisite_parent_log_requires_exact_closed_hash_and_retention(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)/'parent.log'
            data = b'{"exit":0,"success":true}\n'; path.write_bytes(data)
            closed = dict(private_log_sha256=check.content(data)['sha256'])
            with self.assertRaises(AssertionError):
                check.retain_parent_log({}, path, dict(private_log_sha256='0'*64))
            pins = {}
            self.assertEqual(check.retain_parent_log(pins, path, closed), data)
            expected = deepcopy(pins)
            path.write_bytes(data+b' ')
            with self.assertRaises(AssertionError): check.retain_parent_log(pins, path, closed)
            with self.assertRaises(AssertionError): check.pinned_unchanged(pins)
            coherent = dict(private_log_sha256=check.digest(path)['sha256'])
            with self.assertRaises(AssertionError): check.retain_parent_log(pins, path, coherent)
            self.assertEqual(pins, expected)
            path.write_bytes(data); check.pinned_unchanged(pins)

    def test_shared_cases_receipt_digest_and_immutable_manifest_are_joined(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)/'cases.json'
            data = check.encoded([dict(id=1, length=1)])
            path.write_bytes(data)
            expected = check.content(data); pins = {}
            check.retain(pins, path, expected)
            receipt = dict(status='FAILED')
            check.bind_cases(receipt, path, pins)
            self.assertEqual(receipt, dict(status='FAILED', cases=expected))
            self.assertIn(b'"cases":', check.encoded(receipt))
            path.write_bytes(check.encoded([dict(id=1, length=64)]))
            with self.assertRaises(AssertionError): check.bind_cases(receipt, path, pins)
            with self.assertRaises(AssertionError): check.pinned_unchanged(pins)
            self.assertEqual(receipt['cases'], expected)
            self.assertEqual(pins[path], expected)


if __name__ == '__main__':
    unittest.main()
