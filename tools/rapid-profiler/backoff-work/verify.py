#!/usr/bin/env python3
"""Run the unchanged 27 prerequisites, then two finite functional backoff trials."""
import argparse
import csv
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import traceback

if sys.flags.optimize:
    raise SystemExit('assertions required')
sys.dont_write_bytecode = True
MIB = 1048576
FLAGS = ('exact-work', 'concurrent-epochs', 'retire-epochs', 'drain-completed', 'streamed-epochs', 'stream-history')
FIELDS = ('originals k calls arms reports actions sampled unsampled initial closed removed max_entry_prefix sampled_after_closed '
    'epoch_limit call_limit stop_reason max_arm_late_ns stop_ack_ns removed_ns controller_done_ns call_batches history_batches '
    'accepted_exports written_exports written_bytes worker_detached actual_threads_joined export_synced result_input_rsp_checked scope mandatory_hooks').split()
FIXED = dict(stop_reason='epoch-limit', worker_detached='true', export_synced='true', result_input_rsp_checked='true',
    scope='finite-functional-raw-uncalibrated', mandatory_hooks='on')


def parse_terminal(data, k, export_bytes):
    assert type(k) is int and k in (10, 1000) and type(export_bytes) is int
    assert 0 < len(data) <= 4096 and data.endswith(b'\n') and b'\r' not in data
    words = data[:-1].decode('ascii').split(' ')
    assert words[:2] == ['backoff-work', 'COMPLETE'] and len(words) == 2 + len(FIELDS)
    pairs = [word.split('=') for word in words[2:]]
    assert all(len(pair) == 2 for pair in pairs) and [pair[0] for pair in pairs] == FIELDS
    row = dict(pairs)
    for key, value in FIXED.items(): assert row[key] == value
    assert row['sampled_after_closed'] in ('true', 'false')
    row['sampled_after_closed'] = row['sampled_after_closed'] == 'true'
    for key in set(FIELDS) - set(FIXED) - {'sampled_after_closed'}:
        assert re.fullmatch(r'0|[1-9][0-9]*', row[key])
        row[key] = int(row[key]); assert row[key] < 2**64
    assert (row['originals'], row['k'], row['epoch_limit'], row['call_limit']) == (8, k, 520, 100000)
    assert row['arms'] == row['reports'] == 520 and row['actions'] == row['history_batches'] == 521
    n = row['calls']; assert 32 < n < 100000
    assert 0 < row['sampled'] <= min(n, 520*k)
    assert row['sampled'] + row['unsampled'] == n
    assert row['initial'] + row['closed'] + row['removed'] == row['unsampled']
    assert 512 < row['max_entry_prefix'] <= row['actions']
    if k == 10: assert row['closed'] > 0 and row['sampled_after_closed']
    assert row['max_arm_late_ns'] <= 2000000
    ack, removed, done = (row[key] for key in ('stop_ack_ns', 'removed_ns', 'controller_done_ns'))
    assert 5200000000 <= ack <= removed <= done < min(ack + 2000000000, 7200000000)
    assert (n+3)//4 <= row['call_batches'] <= n
    assert row['accepted_exports'] == row['written_exports'] == row['call_batches'] + 521 + 520
    assert 0 < row['written_bytes'] == export_bytes <= 64*MIB and row['actual_threads_joined'] == 3
    return row


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def closed_ok(row):
    assert type(row['exit_code']) is int and row['exit_code'] == 0 and row['termination'] is None
    assert row['cleanup_complete'] is True and type(row['reaped_descendants']) is int and row['reaped_descendants'] == 0


def profile(artifact, test):
    p = artifact['profile']
    assert p == dict(opt_level='3', debuginfo=0, test=test, debug_assertions=True, overflow_checks=True)
    assert type(p['debuginfo']) is int and p['test'] is test and p['debug_assertions'] is p['overflow_checks'] is True
    assert type(artifact['cargo_fresh']) is bool


def main():
    ap = argparse.ArgumentParser(description=__doc__); ap.add_argument('--revision', required=True)
    for key in ('raw', 'toolchain', 'user-home', 'cargo-home'): ap.add_argument('--'+key, type=Path, required=True)
    a = ap.parse_args(); repo = Path(__file__).resolve().parents[3]; raw = a.raw
    assert Path(__file__).resolve() == repo/'tools/rapid-profiler/backoff-work/verify.py'
    assert re.fullmatch('[0-9a-f]{40}', a.revision)
    for p in (repo, a.toolchain, a.user_home, a.cargo_home): assert p.is_absolute() and p.resolve(strict=True) == p and p.is_dir()
    assert raw.is_absolute() and raw.is_relative_to(repo/'ignored') and not raw.exists() and raw.parent.resolve(strict=True) == raw.parent
    raw.mkdir(mode=0o700); public = raw/'public'; public.mkdir()
    receipt = dict(schema=1, status='FAILED', revision=a.revision, stage='preflight',
        cases=[dict(k=k, status='UNRUN') for k in (10, 1000)],
        prerequisite=dict(status='UNRUN'),
        failure_history=['evaluation/history-stream-4f2ddf8/README.md'],
        reproduce=['$PYTHON', '-B', '$REPO/tools/rapid-profiler/backoff-work/verify.py', '--revision', a.revision,
            '--raw', '$RAW', '--toolchain', '$TOOLCHAIN', '--user-home', '$USER_HOME', '--cargo-home', '$CARGO_HOME'],
        scope='finite functional driver/metadata qualification; input/journal/return checks and Report counts are source-attested; no complete independent history/Report replay, new inflight-stop/full-state, cheap-off, timing-accuracy, throughput or indefinite-service credit')
    save = lambda p, v: p.write_text(json.dumps(v, indent=2, sort_keys=True, allow_nan=False)+'\n')
    try:
        cpus = sorted(os.sched_getaffinity(0))[:4]; assert len(cpus) == 4
        os.sched_setaffinity(0, cpus); assert set(os.sched_getaffinity(0)) == set(cpus)
        tools = {n: (a.toolchain/'bin'/n).resolve(strict=True) for n in ('cargo', 'rustc')}
        tools.update(python=Path(sys.executable).resolve(strict=True), git=Path('/usr/bin/git').resolve(strict=True), gcc=Path('/usr/bin/gcc').resolve(strict=True))
        env = dict(HOME=str(a.user_home), CARGO_HOME=str(a.cargo_home), PATH=str(a.toolchain/'bin')+':/usr/bin:/bin',
            RUSTC=str(tools['rustc']), CC=str(tools['gcc']), CARGO_TARGET_DIR=str(repo/'target'), CARGO_INCREMENTAL='0', CARGO_BUILD_JOBS='4',
            CARGO_NET_OFFLINE='true', CARGO_PROFILE_RELEASE_OPT_LEVEL='3', CARGO_PROFILE_RELEASE_DEBUG='0',
            CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS='true', CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS='true',
            CARGO_TERM_COLOR='never', LC_ALL='C', PYTHONDONTWRITEBYTECODE='1', PYTHONNOUSERSITE='1')
        def git(*args): return subprocess.check_output([str(tools['git']), '-C', str(repo), *args], env=env, timeout=15)
        def clean():
            assert git('rev-parse', '--show-toplevel').decode().strip() == str(repo)
            assert git('rev-parse', 'HEAD').decode().strip() == a.revision and git('status', '--porcelain', '--untracked-files=no') == b''
        clean()
        old_path = repo/'tools/rapid-profiler/verify_ordinary_interval.py'
        assert old_path.read_bytes() == git('show', a.revision+':tools/rapid-profiler/verify_ordinary_interval.py')
        old = load('backoff_prerequisite', old_path); digest, save = old.digest, old.save
        names = ['tools/rapid-profiler/backoff-work/'+n for n in ('verify.py', 'test_recipe.py', 'README.md')]
        names += ['tools/rapid-profiler/ordinary-interval/backoff.rs', 'tools/rapid-profiler/ordinary-interval/main.rs',
            'tools/rapid-profiler/src/frontend_native/mod.rs', 'tools/rapid-profiler/verify_ordinary_interval.py',
            'evaluation/admission/processes.py', 'tools/unwind-oracle/bounded_command.py']
        names += git('ls-files', '-z', '--', 'tools/rapid-profiler/src/frontend_native/backoff/').decode().strip('\0').split('\0')
        assert '' not in names and len(names) == len(set(names))
        def sources(selected):
            clean(); answer = {}
            for name in selected:
                assert not Path(name).is_absolute() and '..' not in Path(name).parts
                expected = git('show', a.revision+':'+name)
                answer[name] = digest(repo/name)
                assert answer[name] == dict(sha256=hashlib.sha256(expected).hexdigest(), bytes=len(expected))
            return answer
        before = sources(names); tool_hashes = {n: digest(p) for n, p in tools.items()}
        save(raw/'sources-before.json', before); save(raw/'tools.json', {n: dict(path=str(p), **tool_hashes[n]) for n, p in tools.items()})
        processes = load('backoff_processes', repo/'evaluation/admission/processes.py')
        log_root = repo/'target/evaluation'; log_root.mkdir(parents=True, exist_ok=True)
        logs = Path(tempfile.mkdtemp(prefix='backoff-', dir=log_root))
        def stable():
            assert sources(names) == before and {n: digest(p) for n, p in tools.items()} == tool_hashes
            assert set(os.sched_getaffinity(0)) == set(cpus)
        def parent(name, argv, seconds):
            directory = raw/name; directory.mkdir()
            save(directory/'parent-command.json', dict(argv=argv, env=env, affinity=cpus, wall_seconds=seconds, max_log_bytes=MIB))
            closed = processes.run_command(argv, env, logs/(name+'.log'), seconds, MIB)
            save(directory/'parent-closed.json', closed)
            data = (logs/(name+'.log')).read_bytes(); (directory/'parent.log').write_bytes(data)
            assert hashlib.sha256(data).hexdigest() == closed['private_log_sha256']
            closed_ok(closed); stable()
            return directory, closed
        receipt['stage'] = 'prerequisite'
        receipt['prerequisite']['status'] = 'FAILED'
        receipt['commands'] = [['$PYTHON', '-B', '$REPO/tools/rapid-profiler/verify_ordinary_interval.py', '--revision', a.revision,
            '--raw', '$RAW/prerequisite', '--toolchain', '$TOOLCHAIN', '--user-home', '$USER_HOME', '--cargo-home', '$CARGO_HOME', *['--'+f for f in FLAGS]]]
        prior_raw = raw/'prerequisite'
        argv = [str(tools['python']), '-B', str(old_path), '--revision', a.revision, '--raw', str(prior_raw),
            '--toolchain', str(a.toolchain), '--user-home', str(a.user_home), '--cargo-home', str(a.cargo_home), *['--'+f for f in FLAGS]]
        prior_parent, prior_closed = parent('prerequisite-parent', argv, 900)
        prior = json.loads((prior_raw/'result.json').read_text())
        assert prior['status'] == 'PASS' and prior['revision'] == a.revision and prior['stage'] == 'complete'
        assert all(prior[f.replace('-', '_')+'_requested'] is True for f in FLAGS)
        stages = ['c-build', 'build', 'oracle', 'native', 'exact-build', 'exact-oracle']
        stages += [f'exact-{s}-k{k}' for s in ('short', 'long', 'alternating', 'late-long') for k in (24, 1, 10)]
        stages += ['concurrent-oracle', 'concurrent-test-build', 'concurrent-native', 'timed-native',
            'retirement-sixteen-epochs', 'retirement-function-closed', 'drain-native', 'streamed-native', 'history-native']
        assert len(stages) == len(prior['commands']) == 27
        for stage in stages:
            r = prior[stage]
            assert r['process_exit'] == 0 and r['strict_cleanup'] is True
            closed_ok(json.loads((prior_raw/stage/'parent-closed.json').read_text()))
        source_map = prior['sources']
        assert json.loads((prior_raw/'sources-before.json').read_text()) == json.loads((prior_raw/'sources-after.json').read_text()) == source_map
        assert sources(source_map) == source_map and prior['tools'] == tool_hashes
        assert {n: {k: v for k, v in row.items() if k != 'path'} for n, row in json.loads((prior_raw/'tools.json').read_text()).items()} == tool_hashes
        names = sorted(set(names) | set(source_map)); before = sources(names)
        save(raw/'sources-qualified.json', before)
        artifacts = prior['build']['artifacts']; assert set(artifacts) == {'ordinary-interval', 'frontend-native-oracle'}
        products = {repo/'target/release'/name: item['binary'] for name, item in artifacts.items()}
        for item in artifacts.values(): profile(item, False)
        test = prior['concurrent_epochs']['test_artifact']; profile(test, True)
        test_path = Path(json.loads((prior_raw/'concurrent-native/request.json').read_text())['argv'][0])
        assert test_path.resolve(strict=True) == test_path and test_path.parent == repo/'target/release/deps' and re.fullmatch('rapid_profiler-[0-9a-f]+', test_path.name)
        products[test_path] = test['binary']
        candidate, trusted = (prior_raw/name for name in ('candidate.so', 'trusted.so'))
        products[candidate] = products[trusted] = prior['dso']
        assert prior['binary'] == artifacts['ordinary-interval']['binary']
        assert (candidate.stat().st_dev, candidate.stat().st_ino) != (trusted.stat().st_dev, trusted.stat().st_ino)
        def products_stable():
            stable(); assert {str(p): digest(p) for p in products} == {str(p): v for p, v in products.items()}
        products_stable()
        receipt.update(tools=tool_hashes, versions=prior['versions'], sources=before,
            hardware=dict(prior['hardware'], backoff_parent_affinity_cpus=4, backoff_worker_affinity_cpus=1, backoff_controller_affinity_cpus=1, backoff_sink_affinity_cpus=1, backoff_main_affinity_cpus=1, backoff_distinct_application_cpus=4),
            artifacts=dict(artifacts, libtest=test), dso=prior['dso'],
            prerequisite=dict(status='PASS', stages=27, result=digest(prior_raw/'result.json'), parent=digest(prior_parent/'parent-closed.json')))
        binary = repo/'target/release/ordinary-interval'; helper = repo/'tools/unwind-oracle/bounded_command.py'
        for case in receipt['cases']:
            k = case['k']; label = f'backoff-k{k}'; receipt['stage'] = label; case['status'] = 'FAILED'; products_stable()
            directory = raw/label; directory.mkdir(); (directory/'tmp').mkdir()
            export = directory/'export.txt'
            argv = [str(binary), 'backoff-work', str(candidate), str(trusted), str(k), '520', '100000', str(export)]
            receipt['commands'].append(['$REPO/target/release/ordinary-interval', 'backoff-work', '$RAW/prerequisite/candidate.so',
                '$RAW/prerequisite/trusted.so', str(k), '520', '100000', '$RAW/'+label+'/export.txt'])
            request = dict(argv=argv, cwd=str(repo), env=dict(env, TMPDIR=str(directory/'tmp')), stdout=str(directory/'stdout.txt'),
                stderr=str(directory/'stderr.txt'), cpu_seconds=20, wall_seconds=30, file_bytes=64*MIB)
            save(directory/'request.json', request)
            invocation = [str(tools['python']), '-B', str(helper), '--request', str(directory/'request.json'), '--receipt', str(directory/'receipt.json')]
            parent_dir, closed = parent(label+'-parent', invocation, 55)
            r = json.loads((directory/'receipt.json').read_text())
            assert type(r['exit']) is int and r['exit'] == 0 and r['wall_timeout'] is False and r['inputs_unchanged'] is True
            assert r['request_sha256'] == digest(directory/'request.json')['sha256'] and r['helper_sha256'] == before['tools/unwind-oracle/bounded_command.py']['sha256']
            assert r['absence_proof'] == 'ECHILD' and r['unexpected_descendants'] == r['cleanup_events'] == []
            assert r['cleanup_error'] is r['aborted'] is None
            for stream in ('stdout', 'stderr'): assert r[stream+'_sha256'] == digest(directory/(stream+'.txt'))['sha256']
            assert json.loads((parent_dir/'parent.log').read_text()) == dict(exit=0, wall_timeout=False, absence_proof='ECHILD', descendants=0, success=True)
            assert digest(directory/'stderr.txt')['bytes'] == 0
            exported = digest(export)
            with (directory/'stdout.txt').open('rb') as stream: data = stream.read(4097)
            case.update(parse_terminal(data, k, exported['bytes']))
            products_stable()
            case.update(status='PASS', export=exported, request=digest(directory/'request.json'), receipt=digest(directory/'receipt.json'),
                parent=digest(parent_dir/'parent-closed.json'), operation_seconds=closed['seconds'], cpu_seconds=20, wall_seconds=30, file_bytes=64*MIB)
        products_stable(); save(raw/'sources-after.json', sources(names))
        receipt.update(status='PASS', stage='complete')
    except BaseException as error:
        (raw/'failure.txt').write_text(traceback.format_exc())
        receipt['error_class'] = type(error).__name__
    columns = ['k', 'status', *[k for k in FIELDS if k != 'k']]
    with (public/'cases.csv').open('x', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=columns, extrasaction='ignore', lineterminator='\n')
        writer.writeheader(); writer.writerows(receipt['cases'])
    save(public/'receipt.json', receipt)
    print(json.dumps(dict(status=receipt['status'], stage=receipt['stage'], cases=[dict(k=c['k'], status=c['status']) for c in receipt['cases']]), sort_keys=True))
    return 0 if receipt['status'] == 'PASS' else 1


if __name__ == '__main__': raise SystemExit(main())
