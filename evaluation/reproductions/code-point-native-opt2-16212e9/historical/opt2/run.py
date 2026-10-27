#!/usr/bin/env python3
"""Fixed root-admitted byte point native controls; no complete A4 qualification."""
import argparse
import hashlib
import json
import math
import struct
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

REVISION = '16212e9ab00a18ce003a305f7265bce8633e1c0e'
MIB = 1048576
CASES_SHA = '16878c690a95f52845968272354d7f692ac2ff03776b589d2df4373df852de1f'
HELPER_SHA = 'c0d8d24d9538e2ffd9dee09f8b7efc8a68eb2bfd41b0744d47167d7932d8df44'
OBSERVER_SHA = '0d3697eaaf433fc76d22f4ec7b6bc8047d0260f90bf9227072ad8dee2f4662ba'
SOURCES = ('tests/support/native_interval_oracle.rs', 'tests/support/native_point.rs',
           'tools/rapid-profiler/Cargo.toml', 'tools/rapid-profiler/native-point/main.rs')


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



def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False)+'\n').encode()

def host_interpreter(data):
    # Exact bounded host ELF parser from reviewed E9 runner v2; no loader closure claim.
    assert len(data) >= 64 and data[:7] == b'\x7fELF\x02\x01\x01'
    assert struct.unpack_from('<HHI', data, 16) in ((2, 62, 1), (3, 62, 1))
    assert struct.unpack_from('<HH', data, 52) == (64, 56)
    off, count = struct.unpack_from('<Q', data, 32)[0], struct.unpack_from('<H', data, 56)[0]
    assert 1 <= count <= 128 and off + 56 * count <= len(data)
    rows = [struct.unpack_from('<IIQQQQQQ', data, off + 56 * i) for i in range(count)]
    selected = [r for r in rows if r[0] == 3]
    assert len(selected) == 1
    r = selected[0]
    assert 1 < r[5] <= 4096 and r[2] + r[5] <= len(data)
    value = data[r[2]:r[2] + r[5]]
    assert value[-1:] == b'\0' and b'\0' not in value[:-1]
    return value[:-1].decode()

def output_names(case):
    if 'control' in case:return {'control.txt':None, 'child.json':(0,0)}
    result={}
    for entry, boundaries in (('mov-entry',3),('ret-entry',2)):
        result[entry+'/original.json']=(boundaries,0)
        for phase in case['phases']:
            result[entry+'/'+phase+'/child.json']=(boundaries,boundaries)
            result[entry+'/'+phase+'/lifecycle.txt']=None
    assert len(result)==case['output_files']
    return result


def main():
    if sys.flags.optimize:
        raise SystemExit('assertions are required')
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--binding', type=Path, required=True)
    ap.add_argument('--binding-sha256', required=True)
    ap.add_argument('--raw', type=Path, required=True)
    args = ap.parse_args()
    if REVISION is None:
        raise SystemExit('activation pending exact committed source and caller review')
    assert re.fullmatch('[0-9a-f]{40}', REVISION)
    data, binding_owner = read(args.binding)
    assert sha(data) == args.binding_sha256
    b = json.loads(data)
    assert b.keys() == {'schema', 'authority', 'repo', 'revision', 'caller_sha256', 'source_manifest',
                       'build', 'build_launch', 'build_parent_source', 'tools', 'files', 'cases', 'runtime', 'capacity'}
    assert type(b['schema']) is int and b['schema'] == 1
    assert b['authority'] == 'ROOT_REVIEWED_BYTE_POINT_NATIVE_INPUTS'
    assert b['revision'] == REVISION
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
    namespace = dict(__name__='_byte_point_observation', __file__=str(observer))
    exec(compile(observed_source, str(observer), 'exec'), namespace)
    observe = SimpleNamespace(**namespace)
    env = dict(PATH='/usr/bin:/bin', LANG='C.UTF-8', LC_ALL='C.UTF-8',
               PYTHONDONTWRITEBYTECODE='1', PYTHONNOUSERSITE='1', TMPDIR=str(raw / 'tmp'))
    helper = repo / 'tools/unwind-oracle/bounded_command.py'
    paths = dict(python='/usr/bin/python3.9', timeout='/usr/bin/timeout', git='/usr/bin/git', helper=str(helper), du='/usr/bin/du')
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
    case_bytes = bound(b['cases']); assert sha(case_bytes) == CASES_SHA
    case_catalog = json.loads(case_bytes); cases = case_catalog['commands']
    assert len(cases) == 13 and len({row['id'] for row in cases}) == 13
    assert all(row['status'] == 'UNRUN' for row in cases)
    assert case_catalog['totals'] == dict(actual_completed=0, candidate_children=52, children=75,
        commands=13, full_state_comparisons=130, original_children=20, output_files=130, refusal_children=3)
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
    assert build_command['argv'] == ['cargo', 'build', '-p', 'rapid-profiler', '--bin', 'frontend-native-point', '--message-format=json']
    executable = repo / 'target/debug/frontend-native-point'
    cargo = product['artifact']
    assert cargo['reason'] == 'compiler-artifact' and cargo['executable'] == str(executable) and cargo['filenames'] == [str(executable)]
    assert cargo['target']['name'] == 'frontend-native-point' and cargo['target']['kind'] == cargo['target']['crate_types'] == ['bin']
    assert cargo['target']['src_path'] == str(repo / 'tools/rapid-profiler/native-point/main.rs') and cargo['features'] == []
    assert cargo['target']['edition'] == '2024' and cargo['manifest_path'] == str(repo / 'tools/rapid-profiler/Cargo.toml')
    assert cargo['package_id'] == 'path+' + (repo / 'tools/rapid-profiler').as_uri() + '#0.1.0'
    assert cargo['profile'] == dict(debug_assertions=True, debuginfo=0, opt_level='2', overflow_checks=True, test=False)
    assert {key: build_command['env'][key] for key in (
        'CARGO_PROFILE_DEV_OPT_LEVEL', 'CARGO_PROFILE_DEV_DEBUG_ASSERTIONS',
        'CARGO_PROFILE_DEV_OVERFLOW_CHECKS', 'CARGO_PROFILE_DEV_DEBUG')} == dict(
            CARGO_PROFILE_DEV_OPT_LEVEL='2', CARGO_PROFILE_DEV_DEBUG_ASSERTIONS='true',
            CARGO_PROFILE_DEV_OVERFLOW_CHECKS='true', CARGO_PROFILE_DEV_DEBUG='0')
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
    runtime = json.loads(bound(b['runtime']))
    assert runtime.keys() == {'schema', 'authority', 'scope', 'revision', 'driver_sha256', 'python_sha256', 'owners'}
    assert runtime['schema'] == 1 and runtime['authority'] == 'ROOT_REVIEWED_BYTE_POINT_SELECTED_RUNTIME'
    assert runtime['scope'] == 'selected-host-owners-only' and runtime['revision'] == REVISION
    assert runtime['owners'].keys() == {'driver_interpreter', 'python_interpreter', 'libc', 'loader_cache'}
    assert runtime['owners']['loader_cache']['path'] == '/etc/ld.so.cache'
    capacity = json.loads(bound(b['capacity']))
    assert capacity == dict(schema=1, authority='ROOT_REVIEWED_BYTE_POINT_CAPACITY', revision=REVISION,
        raw=str(raw), max_slot_bytes=20000000000, reserved_growth_bytes=1024*MIB,
        minimum_available_memory_bytes=512*MIB, sole_writer_required=True)
    old_snapshot = snapshot
    def snapshot():
        result = old_snapshot()
        build_inputs = json.loads(before_build)
        configurations = observe.configuration(repo, Path(build_command['env']['CARGO_HOME']))
        assert configurations == build_inputs['configurations']
        compiler_tools = {name: observe.tool(Path(row['path'])) for name, row in build_inputs['tools'].items()}
        assert compiler_tools == build_inputs['tools']
        owners = {name: observe.tool(Path(row['path'])) for name, row in runtime['owners'].items()}
        assert owners == runtime['owners']
        driver, driver_owner = read(executable, 128*MIB)
        python, python_owner = read(Path(result['tools']['python']['resolved']), 128*MIB)
        assert driver_owner['sha256'] == runtime['driver_sha256'] == result['product']['sha256']
        assert python_owner['sha256'] == runtime['python_sha256'] == result['tools']['python']['sha256']
        assert host_interpreter(driver) == owners['driver_interpreter']['path']
        assert host_interpreter(python) == owners['python_interpreter']['path']
        result.update(configurations=configurations, compiler_tools=compiler_tools, selected_runtime=owners)
        assert len(encoded(result)) <= 16*MIB
        return result
    def capacity_now():
        argv = ['/usr/bin/du', '-sx', '--block-size=1', str(repo)]
        query = subprocess.run(argv, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=40, check=False)
        assert query.returncode == 0 and query.stderr == b''
        match = re.fullmatch(rb'([0-9]+)\t'+re.escape(str(repo).encode())+rb'\n', query.stdout)
        assert match is not None
        disk = os.statvfs(repo)
        memory = Path('/proc/meminfo').read_text()
        available = re.findall(r'^MemAvailable:\s+([0-9]+) kB$', memory, re.M)
        assert len(available) == 1
        return dict(slot_bytes=int(match[1]), filesystem_free_bytes=disk.f_bavail*disk.f_frsize,
            available_memory_bytes=int(available[0])*1024, du_argv=argv, du_stdout_sha256=sha(query.stdout))
    before = snapshot()
    capacity_before = capacity_now()
    assert capacity_before['slot_bytes'] + capacity['reserved_growth_bytes'] <= capacity['max_slot_bytes']
    assert capacity_before['filesystem_free_bytes'] >= capacity['reserved_growth_bytes']
    assert capacity_before['available_memory_bytes'] >= capacity['minimum_available_memory_bytes']
    assert {0, 1, 2, 3} <= os.sched_getaffinity(0)
    os.sched_setaffinity(0, [0, 1, 2, 3])
    assert os.sched_getaffinity(0) == {0, 1, 2, 3}
    raw.mkdir(mode=0o700)
    (raw/'tmp').mkdir()
    def save_at(root, name, value, cap=MIB):
        data = encoded(value); assert len(data) <= cap
        with (root/name).open('xb') as stream:stream.write(data)
    def save(name, value, cap=MIB):save_at(raw, name, value, cap)
    with (raw/'binding.json').open('xb') as stream:stream.write(data)
    save('inputs-before.json', before, 16*MIB)
    save('capacity-before.json', capacity_before)
    save('hardware.json', dict(host_label='AMD EPYC Zen 5 dev host', architecture=platform.machine(),
        cpu_model=next(x.split(':', 1)[1].strip() for x in Path('/proc/cpuinfo').read_text().splitlines() if x.startswith('model name')),
        kernel_release=platform.release(), libc=platform.libc_ver(), affinity=[0, 1, 2, 3]))
    results = [dict(id=row['id'], status='UNRUN', planned_children=row['children'],
        planned_comparisons=row['full_state_comparisons'], attempted=False) for row in cases]
    save('planned.json', dict(cases=cases, commands=13, children=75, full_state_comparisons=130,
        unimplemented_modes=case_catalog['modes'], qualification_complete=False))
    stopped = False
    for case, result in zip(cases, results):
        if stopped:break
        case_raw = raw/case['id'];case_raw.mkdir();(case_raw/'tmp').mkdir()
        case_env = dict(env, TMPDIR=str(case_raw/'tmp'))
        result['status'] = 'FAILED'
        child = None; parent_error = None; failure = None; stable = False; passed = False
        began = time.monotonic()
        try:
            observed_before = snapshot(); assert observed_before == before
            save_at(case_raw, 'inputs-before.json', observed_before, 16*MIB)
            native_argv = [str(executable), case['mode'], case.get('member', case.get('control')),
                str(case['seed_index']), str(case_raw/'output')]
            request = dict(argv=native_argv, cwd=str(repo), env=case_env,
                stdout=str(case_raw/'stdout.txt'), stderr=str(case_raw/'stderr.txt'),
                cpu_seconds=20, wall_seconds=30, file_bytes=MIB)
            save_at(case_raw, 'request.json', request)
            argv = [paths['timeout'], '--signal=TERM', '--kill-after=10s', '40s', paths['python'], '-B', str(helper),
                '--request', str(case_raw/'request.json'), '--receipt', str(case_raw/'receipt.json')]
            save_at(case_raw, 'command.json', dict(argv=argv, cwd=str(repo), env=case_env,
                affinity=[0,1,2,3], parent_timeout_seconds=55, parent_failure_cleanup_seconds=10,
                request_sha256=sha(read(case_raw/'request.json')[0]), binding_sha256=args.binding_sha256,
                caller_sha256=sha(own)))
            with (case_raw/'helper.stdout').open('xb') as stdout, (case_raw/'helper.stderr').open('xb') as stderr:
                try:
                    child = subprocess.Popen(argv, cwd=repo, env=case_env, stdin=subprocess.DEVNULL,
                        stdout=stdout, stderr=stderr, start_new_session=True)
                    result['attempted'] = True
                    save_at(case_raw, 'started.json', dict(pid=child.pid))
                    child.wait(timeout=55)
                except BaseException as exception:
                    parent_error = type(exception).__name__ + ': ' + str(exception)
                    if child is not None:
                        if child.poll() is None:
                            try:os.killpg(child.pid, signal.SIGKILL)
                            except BaseException as error:parent_error += '; kill: ' + repr(error)
                        try:child.wait(timeout=10)
                        except BaseException as error:parent_error += '; cleanup: ' + repr(error)
                    raise
                finally:
                    if child is not None:
                        save_at(case_raw, 'closed.json', dict(exit=child.returncode, pid=child.pid,
                            parent_wait_returned=child.returncode is not None, parent_error=parent_error,
                            seconds=time.monotonic()-began,
                            stdout_sha256=sha(read(case_raw/'helper.stdout', MIB)[0]),
                            stderr_sha256=sha(read(case_raw/'helper.stderr', MIB)[0])))
            receipt = json.loads(read(case_raw/'receipt.json', MIB)[0])
            assert set(receipt) == {'request_sha256','helper_sha256','exit','wall_timeout','unexpected_descendants',
                'absence_proof','stdout_sha256','stderr_sha256','elapsed_seconds','cleanup_events','cleanup_error','aborted','inputs_unchanged'}
            assert child.returncode == 0 and parent_error is None and type(receipt['exit']) is int and receipt['exit'] == 0
            assert receipt['absence_proof'] == 'ECHILD' and receipt['inputs_unchanged'] is True and receipt['wall_timeout'] is False
            assert receipt['request_sha256'] == sha(read(case_raw/'request.json')[0]) and receipt['helper_sha256'] == HELPER_SHA
            assert receipt['unexpected_descendants'] == receipt['cleanup_events'] == []
            assert receipt['cleanup_error'] is receipt['aborted'] is None
            assert type(receipt['elapsed_seconds']) in (int,float) and math.isfinite(receipt['elapsed_seconds']) and 0<=receipt['elapsed_seconds']<=30
            streams = {name:read(case_raw/(name+'.txt'),MIB)[0] for name in ('stdout','stderr')}
            assert all(sha(content)==receipt[name+'_sha256'] for name,content in streams.items())
            assert streams['stderr'] == b''
            terminal = dict(mode=case['mode'], children=case['children'], full_state_comparisons=case['full_state_comparisons'], status='PASS')
            if 'member' in case:terminal.update(member=case['member'], seed_index=case['seed_index'])
            else:terminal.update(control=case['control'])
            assert streams['stdout'].endswith(b'\n') and streams['stdout'].count(b'\n')==1 and json.loads(streams['stdout'])==terminal
            assert json.loads(read(case_raw/'helper.stdout',MIB)[0]) == dict(exit=0,wall_timeout=False,absence_proof='ECHILD',descendants=0,success=True)
            assert read(case_raw/'helper.stderr',MIB)[0] == b''
            expected = output_names(case)
            output = case_raw/'output'; assert output.is_dir() and not output.is_symlink()
            entries = list(output.rglob('*'))
            assert all(not p.is_symlink() and (p.is_dir() or p.is_file()) for p in entries)
            assert {str(p.relative_to(output)) for p in entries if p.is_file()} == set(expected)
            expected_dirs = {str(parent) for name in expected for parent in Path(name).parents if str(parent)!='.'}
            assert {str(p.relative_to(output)) for p in entries if p.is_dir()} == expected_dirs
            outputs = {}
            total_children = total_comparisons = 0
            for name, count in expected.items():
                content, owner = read(output/name,MIB); assert content
                outputs[name] = owner
                if count is None:continue
                record = json.loads(content)
                assert set(record)=={'pid','wait_status','echild','steps','boundaries','full_state_comparisons','trace_seconds','max_steps'}
                assert type(record['pid']) is int and record['pid']>0 and record['wait_status']==0 and record['echild'] is True
                assert type(record['steps']) is int and 0<=record['steps']<=20000
                assert record['trace_seconds']==15 and record['max_steps']==20000
                assert record['full_state_comparisons']==count[1] and record['boundaries']==count[0]
                total_children += 1; total_comparisons += count[1]
            assert total_children==case['children'] and total_comparisons==case['full_state_comparisons']
            save_at(case_raw, 'output-files.json', outputs)
            passed = True
        except BaseException as exception:
            failure = dict(type=type(exception).__name__, message=str(exception))
        finally:
            try:
                observed_after = snapshot();save_at(case_raw,'inputs-after.json',observed_after,16*MIB)
                assert observed_after==before;stable=True
            except BaseException as exception:
                save_at(case_raw,'closure-error.json',dict(type=type(exception).__name__,message=str(exception)))
            result.update(status='PASS' if passed and stable else 'FAILED', fatal=failure,
                source_tools_configs_product_runtime_equal=stable,
                completed_children=case['children'] if passed and stable else None,
                source_attested_full_state_comparisons=case['full_state_comparisons'] if passed and stable else None,
                qualification_complete=False)
            save_at(case_raw,'summary.json',result)
            stopped = result['status']!='PASS'
    final_stable = False; final_error = None
    try:
        after = snapshot();save('inputs-after.json',after,16*MIB);assert after==before;final_stable=True
        capacity_after = capacity_now();save('capacity-after.json',capacity_after)
        assert capacity_after['slot_bytes']<=capacity['max_slot_bytes']
        assert capacity_after['slot_bytes']-capacity_before['slot_bytes']<=capacity['reserved_growth_bytes']
    except BaseException as exception:
        final_error = dict(type=type(exception).__name__,message=str(exception))
    success = final_stable and final_error is None and all(row['status']=='PASS' for row in results)
    result = dict(schema=1,revision=REVISION,status='PASS_SOURCE_ATTESTED_BYTE_CONTROLS' if success else 'FAILED',
        cases=results,planned_commands=13,planned_children=75,planned_full_state_comparisons=130,
        attempted=sum(r['attempted'] for r in results),passed=sum(r['status']=='PASS' for r in results),
        failed=sum(r['status']=='FAILED' for r in results),unrun=sum(r['status']=='UNRUN' for r in results),
        final_source_tools_configs_product_runtime_equal=final_stable,final_error=final_error,
        source_attested_native_assertions=True,independent_saved_state_audit=False,
        unimplemented_modes=[r['mode'] for r in case_catalog['modes'] if r['status']=='UNIMPLEMENTED'],
        whole_A4=False,qualification_complete=False,operational_timings_not_performance=True,
        external_caller_parent_record_required=True)
    save('summary.json',result)
    print(json.dumps(result,sort_keys=True))
    return 0 if success else 1

if __name__ == '__main__':
    raise SystemExit(main())
