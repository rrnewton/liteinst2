"""Reproduce the baseline and four stable-generation cases on one externally reserved CPU."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'evaluation/inprocess'))
from checks import source


def need(ok, message):
    if not ok:
        raise ValueError(message)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expect-revision', required=True)
    parser.add_argument('--cpu', type=int, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    need(not sys.flags.optimize and re.fullmatch('[0-9a-f]{40}', args.expect_revision),
         'assertions enabled and exact revision')
    need(args.cpu >= 0 and sorted(os.sched_getaffinity(0)) == [args.cpu],
         'one externally reserved CPU')
    os.chdir(ROOT)
    initial = source()
    need(initial['revision'] == args.expect_revision and initial['tracked_clean'],
         'clean complete current source')
    output = args.output.resolve()
    need(output.parent == ROOT / 'target/evaluation/inprocess' and not output.exists(),
         'fresh direct child output')
    cases = ('getters', 'equal-protection', 'mapping-aba', 'failed-getter')
    names = ('archive', 'flags', 'helper', 'baseline-run', 'baseline-audit',
             *(case + '-' + kind for case in cases for kind in ('run', 'audit')))
    directories = {name: output.with_name(output.name + '-' + name) for name in names}
    need(all(not path.exists() for path in directories.values()), 'all thirteen fixed stage outputs fresh')
    output.mkdir()
    record = dict(schema=1, profile='resident-generation-reproduction-v1', status='running',
                  revision=args.expect_revision, source=initial, cpu=args.cpu,
                  stages=[], no_retries=True, original_child_bounds_unchanged=True,
                  qualification_credit=False, performance_credit=False, equivalence_credit=False)
    receipt = output / 'cohort.json'
    hardware = None

    def save():
        receipt.write_text(json.dumps(record, indent=2, sort_keys=True) + '\n')

    def stage(name, script, extra, expected, expected_profile):
        nonlocal hardware
        need(sorted(os.sched_getaffinity(0)) == [args.cpu] and source() == initial,
             'same CPU and complete source before each stage')
        argv = [sys.executable, '-B', script, '--expect-revision', args.expect_revision,
                '--cpu', str(args.cpu), *map(str, extra), '--output', str(directories[name])]
        row = dict(name=name, argv=argv, script_sha256=sha(script), status='running', exit=None)
        record['stages'].append(row)
        save()
        start = time.monotonic_ns()
        with (output / (name + '.stdout')).open('xb') as out, (output / (name + '.stderr')).open('xb') as err:
            row['exit'] = subprocess.run(argv, stdout=out, stderr=err, check=False).returncode
        row['duration_ns'] = time.monotonic_ns() - start
        row['stdout_sha256'] = sha(output / (name + '.stdout'))
        row['stderr_sha256'] = sha(output / (name + '.stderr'))
        child_receipt = directories[name] / 'receipt.json'
        row['receipt_sha256'] = sha(child_receipt) if child_receipt.is_file() else None
        value = json.loads(child_receipt.read_bytes()) if child_receipt.is_file() else {}
        row['status'] = value.get('status', 'no_receipt')
        save()
        print(json.dumps(dict(stage=name, exit=row['exit'], status=row['status']), sort_keys=True), flush=True)
        need(row['exit'] == 0 and row['status'] == expected and
             value.get('profile') == expected_profile,
             name + ' failed; no retry or downstream substitution')
        need(all(value[key] is True for key in ('source_unchanged', 'inputs_unchanged', 'cleanup_complete')),
             name + ' complete closure')
        need(value['revision'] == args.expect_revision and value['cpu'] == args.cpu and
             value['source'] == initial, name + ' same exact source and CPU')
        need(value['error'] is None and value['final_errors'] == [] and
             value['qualification_credit'] is False and value['performance_credit'] is False,
             name + ' no errors or qualification promotion')
        if hardware is None:
            hardware = value['hardware']
            record['hardware_sha256'] = hashlib.sha256(
                json.dumps(hardware, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
        need(value['hardware'] == hardware, name + ' same complete hardware')
        need(sha(script) == row['script_sha256'] and sha(child_receipt) == row['receipt_sha256'],
             'stage executable and whole receipt unchanged')
        need(source() == initial and sorted(os.sched_getaffinity(0)) == [args.cpu],
             'same complete source and CPU after each stage')
        return child_receipt, row['receipt_sha256']

    try:
        archive, archive_sha = stage('archive', 'evaluation/inprocess/call_owner/prepare_archive.py',
            [], 'passed', 'call-decoder-archive-v1')
        archive_args = ['--archive-receipt', archive, '--archive-receipt-sha256', archive_sha]
        flags, flags_sha = stage('flags', 'evaluation/inprocess/resident_three/flags_native.py',
            archive_args, 'observed_unqualified', 'flag-stack-native-collector-v1')
        helper, helper_sha = stage('helper', 'evaluation/inprocess/resident_three/helper_native.py',
            archive_args, 'observed_unqualified', 'helper-tf-bounded-native-v1')
        prerequisite_args = [*archive_args,
            '--flags-native-receipt', flags, '--flags-native-receipt-sha256', flags_sha,
            '--helper-native-receipt', helper, '--helper-native-receipt-sha256', helper_sha]
        baseline, baseline_sha = stage('baseline-run', 'evaluation/inprocess/resident_three/run.py',
            prerequisite_args, 'bounded_subjects_completed', 'resident-three-observation-v1')
        audit, audit_sha = stage('baseline-audit', 'evaluation/inprocess/resident_three/audit.py',
            ['--receipt', baseline, '--receipt-sha256', baseline_sha],
            'observed_unqualified', 'resident-three-offline-audit-v1')
        generation_args = [*prerequisite_args, '--baseline-audit-receipt', audit,
                           '--baseline-audit-receipt-sha256', audit_sha]
        for effect, case in enumerate(cases):
            observed, observed_sha = stage(case + '-run', 'evaluation/inprocess/resident_generation/run.py',
                [*generation_args, '--effect', effect],
                'bounded_subjects_completed' if effect == 0 else 'refusal_prefix_retained',
                'resident-generation-observation-v1')
            stage(case + '-audit', 'evaluation/inprocess/resident_generation/audit.py',
                ['--receipt', observed, '--receipt-sha256', observed_sha],
                'observed_unqualified' if effect == 0 else 'observed_failed_prefix_unqualified',
                'resident-generation-offline-audit-v1')
        need(tuple(row['name'] for row in record['stages']) == names,
             'all thirteen stages exactly once in their fixed order')
        need(source() == initial and sorted(os.sched_getaffinity(0)) == [args.cpu],
             'same complete source and CPU after all stages')
        record['status'] = 'finite_experiment_completed'
    except BaseException as error:
        record['status'] = 'failed'
        record['error'] = repr(error)
        raise
    finally:
        save()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
