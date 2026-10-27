#!/usr/bin/env python3
"""One root-admitted synthetic router control invocation; no common campaign."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import signal
import stat
import subprocess
import sys
import time
from types import SimpleNamespace

MIB = 1048576
HELPER_SHA = 'c0d8d24d9538e2ffd9dee09f8b7efc8a68eb2bfd41b0744d47167d7932d8df44'
OBSERVER_SHA = '0d3697eaaf433fc76d22f4ec7b6bc8047d0260f90bf9227072ad8dee2f4662ba'
SOURCES = ('tests/support/e9_common_core.rs', 'tests/support/e9_common_router_contract.rs',
           'tests/support/e9_common_router_controls.rs', 'tests/support/e9_common_router_native.rs',
           'tests/support/elf_exec_driver.rs', 'tools/elf-rewrite/examples/support/common_core_router.rs',
           'tools/elf-rewrite/examples/verify_common_core.rs')
NAMES = ('legacy-0.tsv', 'legacy-1.tsv', 'evex-0.tsv', 'evex-1.tsv', 'complete.tsv')
COMPLETE = (b'LI2COMMONROUTERCONTROLS\t1\nsynthetic_roundtrips\t4\nfull_state_comparisons\t12\n'
            b'refused_deliveries\t2\nchildren\t10\ncommon_corpus_credit\tfalse\nqualification_complete\tfalse\n')


def sha(data):
    return hashlib.sha256(data).hexdigest()


def six(s):
    return [s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns]


def read(p, limit=16 * MIB):
    p = Path(p)
    assert p.is_absolute() and '..' not in p.parts and p.parent.resolve(strict=True) == p.parent
    with os.fdopen(os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as f:
        a = os.fstat(f.fileno())
        assert stat.S_ISREG(a.st_mode) and 0 <= a.st_size <= limit
        data = f.read(a.st_size + 1)
        assert six(a) == six(os.fstat(f.fileno())) == six(p.lstat()) and len(data) == a.st_size
    return data, dict(sha256=sha(data), bytes=len(data), stat=six(a))


def main():
    if sys.flags.optimize:
        raise SystemExit('assertions are required')
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--binding', type=Path, required=True)
    ap.add_argument('--binding-sha256', required=True)
    ap.add_argument('--raw', type=Path, required=True)
    args = ap.parse_args()
    data, binding_owner = read(args.binding)
    assert sha(data) == args.binding_sha256
    b = json.loads(data)
    assert b.keys() == {'schema', 'authority', 'repo', 'revision', 'caller_sha256', 'source_manifest',
                       'build', 'build_launch', 'build_parent_source', 'tools', 'files'}
    assert type(b['schema']) is int and b['schema'] == 1
    assert b['authority'] == 'ROOT_REVIEWED_SYNTHETIC_ROUTER_CONTROL_INPUTS'
    if b['revision'] is None:
        raise SystemExit('activation pending exact committed source, build and product binding')
    assert type(b['revision']) is str and re.fullmatch('[0-9a-f]{40}', b['revision'])
    repo, raw = Path(b['repo']), args.raw
    assert repo.is_absolute() and repo.resolve(strict=True) == repo
    assert raw.is_absolute() and raw.is_relative_to(repo / 'ignored') and not raw.exists() and not raw.is_symlink()
    assert raw.parent.resolve(strict=True) == raw.parent
    assert args.binding.is_relative_to(repo / 'ignored') and not args.binding.is_relative_to(raw)
    script = Path(__file__).resolve(strict=True)
    own, own_owner = read(script)
    assert sha(own) == b['caller_sha256']
    observer = repo / 'evaluation/trampoline-parallel.py'
    observed_source, _ = read(observer)
    assert sha(observed_source) == OBSERVER_SHA
    # Whole verified source, definitions only: no second unchecked module read.
    namespace = dict(__name__='_router_control_observation', __file__=str(observer))
    exec(compile(observed_source, str(observer), 'exec'), namespace)
    observe = SimpleNamespace(**namespace)
    env = dict(PATH='/usr/bin:/bin', LANG='C.UTF-8', LC_ALL='C.UTF-8',
               PYTHONDONTWRITEBYTECODE='1', PYTHONNOUSERSITE='1', TMPDIR=str(raw / 'tmp'))
    helper = repo / 'tools/unwind-oracle/bounded_command.py'
    paths = dict(python='/usr/bin/python3.9', timeout='/usr/bin/timeout', git='/usr/bin/git', helper=str(helper))
    assert b['tools'].keys() == paths.keys()
    assert Path(sys.executable).resolve(strict=True) == Path(paths['python']).resolve(strict=True)
    assert 1 <= len(b['files']) <= 64
    watched = {}
    def bound(value):
        p = Path(value)
        assert p.is_relative_to(repo / 'ignored') and not p.is_relative_to(raw)
        content, owner = read(p)
        pin = b['files'][value]
        assert pin.keys() == {'sha256', 'bytes', 'stat'} and type(pin['bytes']) is int
        assert type(pin['sha256']) is str and re.fullmatch('[0-9a-f]{64}', pin['sha256'])
        assert len(pin['stat']) == 6 and all(type(v) is int for v in pin['stat'])
        assert owner == pin
        assert value not in watched or watched[value] == owner
        watched[value] = owner
        return content
    for p in b['files']:
        bound(p)
    assert bound(str(script)) == own
    formatted = json.loads(bound(b['source_manifest']))
    assert formatted.keys() == set(SOURCES)
    build, build_launch = Path(b['build']), Path(b['build_launch'])
    for old in (build, build_launch):
        assert not raw.is_relative_to(old) and not old.is_relative_to(raw)
    def record(root, name):
        return json.loads(bound(str(root / name)))
    before_build = bound(str(build / 'inputs-before.json'))
    assert before_build == bound(str(build / 'inputs-after.json'))
    source = json.loads(before_build)['source']
    assert source['revision'] == b['revision']
    for p, pin in formatted.items():
        assert pin == {k: source['files'][p][k] for k in ('sha256', 'bytes')}
    summary, product = record(build, 'summary.json'), record(build, 'product.json')
    build_command = record(build, 'command.json')
    assert summary['revision'] == product['revision'] == build_command['source_revision'] == b['revision']
    assert summary['phase'] == 'native-build' and summary['status'] == 'PASS' and summary['source_tools_configs_equal'] is True
    assert summary['command']['exit_code'] == 0 and summary['command']['cleanup_complete'] is True
    assert summary['command']['termination'] is None and summary['command']['reaped_descendants'] == 0
    assert product['build_summary_sha256'] == sha(bound(str(build / 'summary.json')))
    assert product['build_log_sha256'] == summary['command']['private_log_sha256'] == sha(bound(str(build / 'command.log')))
    assert build_command['argv'] == ['cargo', 'build', '-p', 'liteinst2', '--bin', 'elf-exec-oracle', '--message-format=json']
    executable = repo / 'target/debug/elf-exec-oracle'
    cargo = product['artifact']
    assert cargo['reason'] == 'compiler-artifact' and cargo['executable'] == str(executable) and cargo['filenames'] == [str(executable)]
    assert cargo['target']['name'] == 'elf-exec-oracle' and cargo['target']['kind'] == cargo['target']['crate_types'] == ['bin']
    assert cargo['target']['src_path'] == str(repo / 'tests/support/elf_exec_driver.rs') and cargo['features'] == []
    assert cargo['target']['edition'] == '2024' and cargo['manifest_path'] == str(repo / 'Cargo.toml')
    assert cargo['package_id'] == 'path+' + repo.as_uri() + '#liteinst2@0.1.0'
    assert cargo['profile'] == dict(debug_assertions=True, debuginfo=0, opt_level='0', overflow_checks=True, test=False)
    parent, start, command = record(build_launch, 'closed.json'), record(build_launch, 'started.json'), record(build_launch, 'command.json')
    assert parent['exit'] == 0 and parent['parent_wait_returned'] is True and parent['parent_error'] is None and parent['pid'] == start['pid']
    assert command['source_revision'] == b['revision'] and command['cwd'] == str(repo)
    assert command['source_sha256'] == build_command['caller_sha256'] == sha(bound(command['argv'][2]))
    assert command['parent_source_sha256'] == sha(bound(b['build_parent_source']))
    for stream in ('stdout', 'stderr'):
        assert parent[stream + '_sha256'] == sha(bound(str(build_launch / (stream + '.txt'))))
    assert not bound(str(build_launch / 'stderr.txt'))
    def snapshot():
        tools = {k: observe.tool(Path(v)) for k, v in paths.items()}
        assert tools == b['tools'] and tools['helper']['sha256'] == HELPER_SHA
        actual = observe.tool(executable)
        s = executable.stat()
        assert actual['stat'] == six(s) and actual['lookup_stat'] == six(s) and actual['resolved'] == str(executable)
        assert product['product'] == dict(path=str(executable), sha256=actual['sha256'], bytes=actual['bytes'],
            dev=s.st_dev, ino=s.st_ino, mode=s.st_mode, mtime_ns=s.st_mtime_ns, ctime_ns=s.st_ctime_ns, uid=s.st_uid, gid=s.st_gid)
        assert s.st_mode & 0o111
        current = observe.source(repo, paths['git'], env)
        assert current == source
        assert read(args.binding)[1] == binding_owner and read(script)[1] == own_owner
        for p in watched:
            assert read(p)[1] == watched[p]
        return dict(source=current, tools=tools, product=actual, metadata=watched.copy(), binding=binding_owner, caller=own_owner)
    before = snapshot()
    os.sched_setaffinity(0, [0, 1, 2, 3])
    assert os.sched_getaffinity(0) == {0, 1, 2, 3}
    raw.mkdir(mode=0o700)
    (raw / 'tmp').mkdir()
    def save(name, value):
        with (raw / name).open('x') as stream:
            json.dump(value, stream, indent=2, sort_keys=True, allow_nan=False); stream.write('\n')
    with (raw / 'binding.json').open('xb') as stream:
        stream.write(data)
    save('inputs-before.json', before)
    save('hardware.json', dict(host_label='AMD EPYC Zen 5 dev host', architecture=platform.machine(),
         cpu_model=next(x.split(':', 1)[1].strip() for x in Path('/proc/cpuinfo').read_text().splitlines() if x.startswith('model name')),
         kernel_release=platform.release(), libc=platform.libc_ver(), affinity=[0, 1, 2, 3]))
    request = dict(argv=[str(executable), 'common-core-router-controls', str(raw / 'controls')], cwd=str(repo), env=env,
        stdout=str(raw / 'stdout.txt'), stderr=str(raw / 'stderr.txt'), cpu_seconds=60, wall_seconds=90, file_bytes=64 * MIB)
    save('request.json', request)
    argv = [paths['timeout'], '--signal=TERM', '--kill-after=10s', '100s', paths['python'], '-B', str(helper),
            '--request', str(raw / 'request.json'), '--receipt', str(raw / 'receipt.json')]
    save('command.json', dict(argv=argv, cwd=str(repo), env=env, affinity=[0, 1, 2, 3], parent_timeout_seconds=115,
         request_sha256=sha(read(raw / 'request.json')[0]), binding_sha256=args.binding_sha256, caller_sha256=sha(own)))
    passed, launched, failure, stable = False, False, None, False
    began = time.monotonic()
    try:
        with (raw / 'helper.stdout').open('xb') as stdout, (raw / 'helper.stderr').open('xb') as stderr:
            child = subprocess.Popen(argv, cwd=repo, env=env, stdin=subprocess.DEVNULL,
                                     stdout=stdout, stderr=stderr, start_new_session=True)
            launched = True; error = None
            try:
                save('started.json', dict(pid=child.pid))
                code = child.wait(timeout=115)
            except BaseException as exception:
                error = repr(exception)
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except BaseException as kill_error:
                    # Even a failed/interrupted kill must not bypass the wait.
                    error += '; kill: ' + repr(kill_error)
                while True:
                    try:
                        code = child.wait(); break
                    except BaseException as interruption:
                        error += '; ' + repr(interruption)
        save('closed.json', dict(exit=code, pid=child.pid, parent_wait_returned=True, parent_error=error,
            seconds=time.monotonic() - began, stdout_sha256=sha(read(raw / 'helper.stdout', 64 * MIB)[0]),
            stderr_sha256=sha(read(raw / 'helper.stderr', 64 * MIB)[0])))
        receipt = json.loads(read(raw / 'receipt.json')[0]); save('receipt-observed.json', receipt)
        assert code == 0 and error is None and receipt['exit'] == 0 and receipt['absence_proof'] == 'ECHILD'
        assert receipt['request_sha256'] == sha(read(raw / 'request.json')[0]) and receipt['helper_sha256'] == HELPER_SHA
        assert receipt['inputs_unchanged'] is True and receipt['wall_timeout'] is False
        assert receipt['unexpected_descendants'] == receipt['cleanup_events'] == []
        assert receipt['cleanup_error'] is None and receipt['aborted'] is None
        for stream in ('stdout', 'stderr'):
            content = read(raw / (stream + '.txt'), 64 * MIB)[0]
            assert sha(content) == receipt[stream + '_sha256'] and content == b''
        assert json.loads(read(raw / 'helper.stdout')[0]) == dict(exit=0, wall_timeout=False, absence_proof='ECHILD', descendants=0, success=True)
        assert read(raw / 'helper.stderr')[0] == b''
        controls = raw / 'controls'
        assert controls.is_dir() and not controls.is_symlink() and {p.name for p in controls.iterdir()} == set(NAMES)
        outputs = {n: read(controls / n, 64 * MIB)[1] for n in NAMES}
        assert read(controls / 'complete.tsv')[0] == COMPLETE
        assert all(outputs[n]['bytes'] > 0 for n in NAMES)
        save('control-files.json', outputs)
        passed = True
    except BaseException as exception:
        failure = dict(type=type(exception).__name__, message=str(exception))
    finally:
        try:
            after = snapshot(); save('inputs-after.json', after)
            assert before == after; stable = True
        except BaseException as exception:
            save('closure-error.json', dict(type=type(exception).__name__, message=str(exception)))
        result = dict(status='PASS_COMMAND_AND_SYNTHETIC_COMPLETE_MARKER' if passed and stable else 'FAILED',
            revision=b['revision'], launched=launched, fatal=failure, source_tools_product_equal=stable,
            planned_roundtrips=4, planned_full_state_comparisons=12, planned_negative_cases=2, planned_children=10,
            positive_stops_source_contract=34,
            completed_roundtrips=4 if passed and stable else None,
            source_attested_full_state_comparisons=12 if passed and stable else None,
            completed_negative_cases=2 if passed and stable else None,
            completed_children=10 if passed and stable else None,
            scope='standalone synthetic router mechanism controls; full-state assertions are source-attested',
            independent_saved_trace_review_required=True, common_corpus_credit=False, qualification_complete=False,
            operational_timings_not_performance=True, external_caller_parent_record_required=True)
        save('summary.json', result)
    print(json.dumps(result, sort_keys=True))
    return 0 if passed and stable else 1


if __name__ == '__main__':
    raise SystemExit(main())
