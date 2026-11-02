#!/usr/bin/env python3
"""Run the effects collectors plus all original stages and the60+2 comparison.

From a clean checkout, on one externally reserved CPU:
  python3 -B /path/to/reproduce_effects_tunables.py --expect-revision REV --cpu N \
      --sdk /path/to/DynamoRIO-11.91.0 --attempt tunables-reproduction-1
The working directory is the repository root. The driver may be copied outside
the checkout to reproduce an older revision without modifying its tracked files.
Requires Python3.12, the collectors' Linux x86-64/toolchain/GDB/strace environment,
the locked Cargo dependencies cached for offline builds, and SDK client API1191.
No private authoring packets or SDK-install metadata are required. Keep every
fresh predecessor artifact until completion. Initial reserve is1280MiB and the
repository allocation cap is20GB, as in the original nine-stage orchestration.

The explicit effects profiles add component40 and retain every original
population, bound and qualification gate. There are no
retries, skipped stages or partial medians. The compact outer receipt and stdout/
stderr captures are private command custody; collector public JSON/CSV provide
publication results. Exit0 means a complete comparison meeting both10x targets;
exit2 means a complete comparison missing the target; exit1 means failure.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

ROOT = Path.cwd().resolve()
CAP, RESERVE = 20_000_000_000, 1280 << 20
# name, tracked collector, expected status, output pointer kind, receipt profile
STAGES = (
    ('native41', 'direct_frontier_loop.py', 'passed', 'public', 'persistent-direct-frontier-finite-v1'),
    ('bounded_block', 'bounded_block_owner.py', 'observed_unqualified', 'private', 'bounded-block-owner-v1'),
    ('fused_component', 'bounded_fusion_component/run.py', 'components_passed', 'component', 'experimental-bounded-fused-component-v1'),
    ('bounded_fused', 'bounded_fused_owner.py', 'observed_unqualified', 'private', 'bounded-fused-owner-v1'),
    ('loop_native', 'persistent_loop_effects_native.py', 'observed_native_references', 'private', 'persistent-loop-effects-native-v1'),
    ('loop_components', 'loop_components/run.py', 'components_passed', 'component', 'experimental-loop-components-v1'),
    ('effects_component', 'loop_effects13_component.py', 'observed_component_comparisons', 'private', 'loop-effects13-component-v1'),
    ('loop_owner', 'persistent_loop_effects_owner.py', 'observed_focal_unqualified', 'private', 'persistent-loop-effects-owner-v1'),
    ('loop_lifecycle', 'persistent_loop_effects_lifecycle.py', 'observed_lifecycle_unqualified', 'private', 'persistent-loop-effects-lifecycle-v1'),
    ('program', 'tunables_effects_program.py', 'completed_unqualified', 'public', 'tunables-effects-program-probe-v1'),
    ('fixed', 'persistent_epoch.py', 'passed', 'legacy', 'persistent-epoch-finite-v1'),
    ('dynamic', 'persistent_dynamic.py', 'passed', 'legacy', 'persistent-dynamic-finite-v1'),
    ('group', 'persistent_group.py', 'passed', 'legacy', 'persistent-group-loop-v1'),
    ('resident', 'persistent_resident.py', 'passed', 'legacy', 'persistent-resident-finite-v2'),
    ('retained', 'persistent_retained_two.py', 'passed', 'legacy', 'persistent-retained-two-finite-v3'),
    ('joint392', 'persistent_joint_startup.py', 'passed', 'legacy', 'persistent-joint-subentry-finite-v1'),
    ('cross522', 'cross_pair_loop.py', 'passed', 'public', 'persistent-cross-pair-finite-v1'),
    ('qualification', 'cross_pair_qualification.py', 'passed', 'public', 'persistent-cross-pair-qualification-v1'),
    ('benchmark', 'tunables_effects_performance.py', 'passed', 'public', 'tunables-effects-performance-v1'),
)
COUNTS = dict(native41=139, bounded_block=101, fused_component=44, bounded_fused=105,
              loop_native=82, loop_components=60, effects_component=71, loop_owner=126, loop_lifecycle=116)
OLD_FEATURES = ['scalar-region', 'scalar-span', 'linked-epoch', 'mov-guard']
NEW_FEATURES = OLD_FEATURES + ['scalar-read', 'loop-effects']
LOOP_CASES = ('scalar_span_metadata', 'scalar_read', 'loop_envelope', 'bounded_fusion_plan', 'loop_plan')
BOUNDS = {'build': [120, 2 << 30, 128 << 20, 150],
          'metadata': [30, 512 << 20, 64 << 20, 60],
          'inspect': [10, 256 << 20, 4 << 20, 20],
          'release_build': [30, 512 << 20, 16 << 20, 60],
          'program': [30, 512 << 20, 16 << 20, 60],
          'seed': [5, 512 << 20, 16 << 20, 15],
          'finite': [5, 512 << 20, 16 << 20, 15]}
COMPONENT_BOUNDS = {'build': [30, 512 << 20, 16 << 20, 60],
                    'component': [5, 512 << 20, 16 << 20, 15]}
EFFECTS_COMPONENT_BOUNDS = {k: [30, 512 << 20, 16 << 20, 60]
                            for k in ('metadata', 'build', 'native')}


def fact(path):
    data = Path(path).read_bytes()
    return dict(bytes=len(data), sha256=hashlib.sha256(data).hexdigest())


def whole(path):
    path = Path(path)
    assert path.is_file() and not path.is_symlink()
    return dict(**fact(path), mode=path.stat().st_mode & 0o777)


def decode(data):
    def unique(items):
        value = dict(items)
        assert len(value) == len(items)
        return value
    return json.loads(data, object_pairs_hook=unique)


def inside(name):
    relative = Path(name)
    assert not relative.is_absolute() and '..' not in relative.parts
    path = ROOT / relative
    assert path.resolve(strict=True) == path and path.is_file()
    return path


def git(*argv):
    return subprocess.check_output(['git', '-c', 'index.threads=1',
        '-c', 'core.preloadIndex=false', *argv])


def usage():
    return int(subprocess.check_output(['du', '-sx', '-B1', '.']).split()[0])


def populations(name, actual):
    if name in COUNTS: assert len(actual['commands']) == COUNTS[name]
    if name == 'loop_native':
        assert [(c['lane'], c['mode'], c['placement']) for c in actual['cases']] == [
            (0, c, p) for c in range(7) for p in range(4)]
        assert all(c['status'] == 'observed_native_reference' and c['exit'] == 0 for c in actual['cases'])
    elif name == 'loop_components':
        assert len(actual['components']) == 5 and set(actual['components']) == set(LOOP_CASES)
        assert all(actual['components'][k]['status'] == 'passed' for k in LOOP_CASES)
        assert actual['archive_builds'] == 0 and actual['archive_source_provenance_verified'] is False
        assert actual['native_execution'] == actual['generated_execution'] == 0
    elif name == 'effects_component':
        cases = actual['result']['cases']
        assert [c['mode'] for c in cases] == list(range(40))
        assert all(c['expected_exit'] == (125 if c['mode'] in (24,25,26,27) else 0) and
            c['status'] == ('observed_required_write_fault' if c['mode'] in (24,25,26,27)
                            else 'observed_component_comparison') and c['error'] is None and
            len(c['controls']['refusals']) == len(set(c['controls']['refusals'])) == 52
            for c in cases)
        assert 'metadata' in actual['result'] and actual['owner_credit'] is False
    elif name == 'loop_owner':
        assert [(c['build_lane'], c['mode'], c['placement']) for c in actual['cases']] == [
            (l, c, p) for l in ('maintained', 'differential') for c in range(7) for p in range(4)]
        assert all(c['exit'] == (125 if c['mode'] >= 5 else 0) and c['status'] == (
            'observed_required_read_fault' if c['mode'] >= 5 else 'observed_focal_completion')
            for c in actual['cases'])
    elif name == 'loop_lifecycle':
        assert [(c['lane'], c['mode'], c['placement']) for c in actual['native_cases']] == [
            (0, c, p) for c in range(2) for p in range(2)]
        assert [(c['build_lane'], c['mode'], c['placement']) for c in actual['cases']] == [
            (l, c, p) for l in ('maintained', 'differential') for c in range(2) for p in range(2)]
        assert all(c['status'] == 'observed_native_reference' and c['exit'] == 0 for c in actual['native_cases'])
        assert all(c['status'] == 'observed_lifecycle' and c['exit'] == 0 for c in actual['cases'])
    elif name == 'program':
        assert [(c['program'], c['lane']) for c in actual['cases']] == [
            (k, l) for k in ('ls', 'true') for l in ('native', 'counted')]
        assert all(c['exit'] == 0 and c['status'] == ('completed_native_reference' if c['lane'] == 'native'
            else 'completed_unqualified') for c in actual['cases'])
    elif name in ('fixed', 'dynamic', 'group', 'resident', 'retained', 'joint392', 'cross522'):
        assert len(actual['cases']) == dict(fixed=5, dynamic=5, group=2, resident=2,
                                           retained=2, joint392=3, cross522=3)[name]
    if name not in ('qualification', 'benchmark'):
        for key in ('qualification_credit', 'performance_credit', 'whole_profile_qualified'):
            if key in actual: assert actual[key] is False


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--expect-revision', required=True)
    ap.add_argument('--cpu', type=int, required=True)
    ap.add_argument('--sdk', type=Path, required=True)
    ap.add_argument('--attempt', required=True)
    args = ap.parse_args()
    assert not sys.flags.optimize and sys.version_info[:2] == (3, 12)
    assert re.fullmatch('[0-9a-f]{40}', args.expect_revision)
    assert re.fullmatch('tunables-[a-z0-9][a-z0-9-]{0,63}', args.attempt)
    cpu, rev = args.cpu, args.expect_revision
    assert os.sched_getaffinity(0) == {cpu}
    assert git('rev-parse', 'HEAD').decode().strip() == rev
    assert not git('status', '--porcelain', '--untracked-files=no')
    tree = git('rev-parse', 'HEAD^{tree}').decode().strip()
    driver = Path(__file__).resolve(strict=True); driver_fact = whole(driver)
    sdk = args.sdk.resolve(strict=True); assert sdk.is_dir()
    base = ROOT/'target/evaluation/inprocess'
    out = base/(args.attempt+'-orchestration')
    outputs = {name: base/(args.attempt+'-'+name.replace('_', '-'))
               for name, _, _, kind, _ in STAGES if kind in ('private', 'component')}
    assert not out.exists() and all(not p.exists() for p in outputs.values())
    initial_usage = usage(); assert initial_usage + RESERVE < CAP
    out.mkdir(parents=True)
    record = dict(schema=1, profile='tunables-effects-public-reproduction-v1', status='running',
        revision=rev, tree=tree, cpu=cpu, driver=driver_fact, argv=[sys.executable, '-B', *sys.argv],
        stage_order=[s[0] for s in STAGES], stages=[], source_unchanged=False,
        initial_usage_bytes=initial_usage, initial_reserve_bytes=RESERVE, slot_cap_bytes=CAP,
        performance_target_met=None, error=None, qualification_credit=False, performance_credit=False,
        scope='Outer command custody only; existing child receipts retain all validation and comparison authority.')
    retained, results, actuals = {}, {}, {}

    def save():
        (out/'receipt.json').write_text(json.dumps(record, sort_keys=True, indent=2)+'\n')

    def retain(path):
        path = Path(path); value = whole(path)
        assert str(path) not in retained or retained[str(path)] == value
        retained[str(path)] = value
        return value

    def guard():
        assert os.sched_getaffinity(0) == {cpu}
        assert git('rev-parse', 'HEAD').decode().strip() == rev
        assert git('rev-parse', 'HEAD^{tree}').decode().strip() == tree
        assert not git('status', '--porcelain', '--untracked-files=no')
        assert usage() < CAP and whole(driver) == driver_fact
        for name, value in retained.items(): assert whole(Path(name)) == value

    def run(name, options):
        spec = STAGES[len(record['stages'])]; assert name == spec[0]
        _, script, status, kind, profile = spec
        guard()
        argv = [sys.executable, '-B', 'evaluation/inprocess/'+script, '--expect-revision', rev, *options]
        row = dict(name=name, argv=argv, exit=None, expected_status=status)
        record['stages'].append(row); save()
        stdout, stderr = out/(name+'.stdout'), out/(name+'.stderr')
        start = time.monotonic_ns()
        with stdout.open('xb') as stream, stderr.open('xb') as errors:
            proc = subprocess.run(argv, stdout=stream, stderr=errors)
        row.update(exit=proc.returncode, duration_ns_validation_only=time.monotonic_ns()-start,
                   captures=dict(stdout=retain(stdout), stderr=retain(stderr)))
        save(); print(json.dumps(dict(stage=name, exit=proc.returncode)), flush=True)
        try:
            result = decode(stdout.read_text().splitlines()[-1])
            pointer = 'summary' if kind == 'component' else ('result' if kind == 'legacy' else 'receipt')
            path = inside(result[pointer]); summary = decode(path.read_bytes()); retain(path)
            if kind in ('public', 'legacy'):
                assert path.parent == ROOT/'evaluation/inprocess/results' and path.suffix == '.json'
                private = base/path.stem/'receipt.json'
                key = 'private_receipt' if kind == 'legacy' or name == 'benchmark' else 'receipt'
                assert fact(private) == summary[key]; retain(path.with_suffix('.csv'))
            elif kind == 'component':
                assert path == outputs[name]/'summary.json'; private = path.with_name('receipt.json')
                assert dict(**fact(private), mode=format(private.stat().st_mode & 0o777, '04o')) == summary['receipt']
            else:
                assert kind == 'private' and path == outputs[name]/'receipt.json'; private = path
                for leaf in (('summary.json', 'summary.csv') if name == 'effects_component'
                             else ('public.json', 'public.csv')):
                    if (private.parent/leaf).is_file(): retain(private.parent/leaf)
            row.update(result=result, receipt=fact(path),
                       private_receipt=dict(file=str(private.relative_to(ROOT)), **retain(private)))
            actual = decode(private.read_bytes()); row['actual_status'] = actual['status']
            assert actual.get('revision', actual.get('expected_revision')) == rev and actual['cpu'] == cpu
            assert actual['profile'] == summary['profile'] == profile
            if name == 'native41': record.update(source=actual['source'], hardware=actual['hardware'])
            assert actual['source'] == record['source'] and actual['hardware'] == record['hardware']
            row.update(source_unchanged=actual['source_unchanged'], cleanup_complete=actual['cleanup_complete'])
            if proc.returncode == 0:
                assert actual['status'] == summary['status'] == result['status'] == status
                assert actual['source_unchanged'] is True and actual['cleanup_complete'] is True
                if 'inputs_unchanged' in actual: assert actual['inputs_unchanged'] is True
                assert actual['error'] is None
                if name != 'qualification': assert actual['final_errors'] == []
                bounds = dict(EFFECTS_COMPONENT_BOUNDS if name == 'effects_component' else
                              COMPONENT_BOUNDS if kind == 'component' else BOUNDS)
                if name == 'benchmark': bounds['program_dr'] = [30, 16 << 30, 16 << 20, 60]
                assert actual['bounds'] == bounds
                populations(name, actual)
                if name == 'qualification':
                    assert actual['required'] == summary['required'] == ['original392', 'cross_pair522']
                    assert actual['whole_profile_qualified'] is summary['whole_profile_qualified'] is True
                if name == 'benchmark':
                    assert summary['comparison_complete'] is True and len(actual['cases']) == 62
                    assert all(c['status'] == 'passed' for c in actual['cases'])
                    for workload in ('ls', 'true'):
                        stats = summary['statistics'][workload]
                        for lane in ('native', 'release', 'dynamorio'):
                            assert stats[lane]['planned'] == stats[lane]['passed'] == 10
                            assert stats[lane]['timing_credit'] is True
                        assert stats['differential']['planned'] == stats['differential']['passed'] == 1
                        assert stats['differential']['timing_credit'] is False
                        ratio = stats['release']['median_ns']/stats['dynamorio']['median_ns']
                        assert stats['release_ratios']['dynamorio'] == ratio
                        assert stats['within_10x_dynamorio'] is (ratio <= 10)
                    target = all(summary['statistics'][k]['within_10x_dynamorio'] for k in ('ls', 'true'))
                    assert summary['performance_target_met'] is target
                    record['performance_target_met'] = target
                    record['benchmark_result'] = dict(file=str(path.relative_to(ROOT)), **fact(path))
            results[name], actuals[name] = path, actual
        except Exception as error:
            row['result_error'] = repr(error)
            if name in outputs and 'private_receipt' not in row:
                failed = outputs[name]/'receipt.json'
                if failed.is_file() and not failed.is_symlink():
                    row['failed_receipt'] = dict(file=str(failed.relative_to(ROOT)), **retain(failed))
        row['usage_after_bytes'] = usage(); save(); guard()
        if proc.returncode: raise RuntimeError(name+' failed; no dependent stage launched')
        assert 'result_error' not in row
        return results[name]

    def archive(stage, features):
        actual = actuals[stage]; row = next(r for r in record['stages'] if r['name'] == stage)
        private = inside(row['private_receipt']['file']); build = actual['build']
        stored = build['artifacts']['decoder.a']; path = Path(stored['path'])
        assert path == private.parent/'artifacts/decoder.a'
        assert build['status'] == 'passed' and build['command_completed'] is True
        assert build['decoder_features'] == features
        assert fact(path) == {k: stored[k] for k in ('bytes', 'sha256')}
        assert whole(path) == actual['artifacts'][str(path)]
        with path.open('rb') as stream: assert stream.read(8) == b'!<arch>\n'
        record[stage+'_archive'] = dict(file=str(path.relative_to(ROOT)), **retain(path))
        return path

    def reference(option, path, sha=True):
        result = ['--'+option+'-receipt', str(path.relative_to(ROOT))]
        return result + (['--'+option+'-receipt-sha256', fact(path)['sha256']] if sha else [])

    def fixed(name): return ['--cpu', str(cpu), '--output', str(outputs[name].relative_to(ROOT))]

    def refs(*names):
        return [word for name in names for word in reference(name, results[name], sha=False)]

    save()
    try:
        direct = run('native41', []); old_archive = archive('native41', OLD_FEATURES)
        assert fact(old_archive) == decode(direct.read_bytes())['archive']
        block = run('bounded_block', reference('direct', direct)+fixed('bounded_block'))
        component = run('fused_component', ['--archive', str(old_archive), '--archive-sha256',
            fact(old_archive)['sha256']]+fixed('fused_component')).with_name('receipt.json')
        fused = run('bounded_fused', reference('direct', direct)+reference('block', block)+
                    reference('fused-component', component)+fixed('bounded_fused'))
        native = run('loop_native', fixed('loop_native')); new_archive = archive('loop_native', NEW_FEATURES)
        assert new_archive != old_archive and fact(new_archive) != fact(old_archive)
        components = run('loop_components', ['--archive', str(new_archive), '--archive-sha256',
            fact(new_archive)['sha256']]+fixed('loop_components')).with_name('receipt.json')
        effects = run('effects_component', reference('native', native)+['--archive', str(new_archive),
            '--archive-sha256', fact(new_archive)['sha256']]+fixed('effects_component'))
        legacy = reference('direct', direct)+reference('block', block)+reference('fused', fused)+reference('loop-component', components)
        owner = run('loop_owner', legacy+reference('loop-native', native)+reference('effects-component', effects)+fixed('loop_owner'))
        lifecycle = run('loop_lifecycle', legacy+reference('effects-component', effects)+fixed('loop_lifecycle'))
        run('program', reference('direct', direct, sha=False)+reference('block', block)+reference('fused', fused)+
            reference('loop-component', components)+reference('effects-component', effects)+reference('loop-native', native)+
            reference('loop-owner', owner)+reference('loop-lifecycle', lifecycle))
        counted = inside(next(r for r in record['stages'] if r['name'] == 'program')['private_receipt']['file'])
        run('fixed', [])
        run('dynamic', refs('fixed'))
        run('group', refs('fixed', 'dynamic'))
        run('resident', refs('fixed', 'dynamic', 'group'))
        run('retained', refs('fixed', 'dynamic', 'group', 'resident'))
        run('joint392', refs('fixed', 'dynamic', 'group', 'resident', 'retained'))
        run('cross522', [])
        qualification = run('qualification', reference('joint', results['joint392'], sha=False)+
                             reference('cross-pair', results['cross522'], sha=False))
        run('benchmark', reference('counted', counted)+reference('qualification', qualification)+['--sdk', str(sdk)])
        assert [r['name'] for r in record['stages']] == [s[0] for s in STAGES]
        record['status'] = 'completed_target_met' if record['performance_target_met'] else 'completed_target_missed'
    except BaseException as error:
        record.update(status='failed', error=repr(error))
    finally:
        try: guard(); record['source_unchanged'] = True
        except BaseException as error:
            record.update(status='failed', source_unchanged=False, final_error=repr(error))
        save()
    print(json.dumps(dict(status=record['status'], performance_target_met=record['performance_target_met'],
        receipt=str((out/'receipt.json').relative_to(ROOT)))), flush=True)
    return 0 if record['status'] == 'completed_target_met' else (2 if record['status'] == 'completed_target_missed' else 1)


if __name__ == '__main__': raise SystemExit(main())
