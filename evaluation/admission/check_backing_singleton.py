#!/usr/bin/env python3
"""Bounded sequential cleanup qualification; stop on the first failed attempt."""
import argparse
import csv
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import resource
import subprocess
import sys
import tempfile

HELPER_SHA = '0dfc4f40943252950e122c9e9fffb837448cba12140d0614acfa9d3621f2e31f'
MIB = 1048576
PREFIX = 'LITEINST_BACKING_CLEANUP_V1 '
ARGV = ['test', '-p', 'liteinst-launch', '--test', 'exec_backing_cleanup']
CONTROL = ['admitted_exec_native_backing_probes_close_exact_owned_resources',
    'admitted_exec_native_backing_read_and_unwind_preserve_cleanup',
    'exec_backing_native_invalid_unmap_aborts_isolated_owner',
    'admitted_exec_native_backing_query_preserves_cleanup',
    'admitted_exec_native_backing_enotty_uses_exact_legacy_projection']
ROLES = [('complete', 0, 'complete', 6, 0, 'exit0', True),
    ('read_error', 1, 'native_read_error', 1, 14, 'exit0', True),
    ('unwind', 1, 'injected_unwind', 1, 0, 'exit0', True),
    ('invalid_unmap', 2, 'expected_fail_stop', 1, 22, 'sigabrt', False),
    ('query_error', 3, 'native_query_error', 1, 14, 'exit0', True),
    ('legacy', 4, 'native_enotty_fallback', 6, 0, 'exit0', True)]
EXPECTED = [dict(schema_version=1, kind='begin', controls=5, trajectories=6)] + [
    dict(schema_version=1, kind='trajectory', index=i, id=name, control=CONTROL[control], outcome=outcome,
        probes=probes, errno=error, terminal=terminal, owner_cleanup=owner,
        physical_cleanup=True, receipt_authenticated=True)
    for i, (name, control, outcome, probes, error, terminal, owner) in enumerate(ROLES)
] + [dict(schema_version=1, kind='complete', controls=5, trajectories=6, physical_cleanup=True)]


def digest(path):
    with path.open('rb') as stream:
        value = hashlib.sha256()
        for block in iter(lambda: stream.read(MIB), b''): value.update(block)
    return value.hexdigest()


def object_(pairs):
    result = {}
    for key, value in pairs:
        assert key not in result, 'duplicate protocol key'
        result[key] = value
    return result


def protocol(data, repo):
    assert 0 < len(data) <= 8*MIB and data.endswith(b'\n') and b'\r' not in data
    lines = data.decode('utf-8').splitlines()
    header = re.compile(r'\s*Running tests/exec_backing_cleanup\.rs \((?:target|'+re.escape(str(repo))+r'/target)/debug/deps/exec_backing_cleanup-[0-9a-f]{16}\)')
    heads = [i for i, line in enumerate(lines) if re.match(r'\s*(?:Running |Doc-tests )', line)]
    assert len(heads) == 1 and header.fullmatch(lines[heads[0]]), 'wrong Cargo harness'
    assert not any('LITEINST_BACKING_CLEANUP' in line for line in lines[:heads[0]])
    records = [line for line in lines[heads[0]+1:] if line.strip()]
    assert len(records) == 8, 'missing or extra protocol record'
    for line, expected in zip(records, EXPECTED):
        assert line.startswith(PREFIX) and len(line.encode('utf-8')) <= 1024
        actual = json.loads(line[len(PREFIX):], object_pairs_hook=object_)
        # Canonical JSON distinguishes booleans, integers, floats and strings.
        assert json.dumps(actual, sort_keys=True, allow_nan=False) == json.dumps(expected, sort_keys=True, allow_nan=False), 'typed protocol differs'


def main():
    if sys.flags.optimize: raise SystemExit('assertions required')
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('toolchain', 'cargo-home', 'output'): parser.add_argument('--'+name, type=Path, required=True)
    parser.add_argument('--revision', required=True)
    parser.add_argument('--repetitions', type=int, default=100)
    args = parser.parse_args(); repo = Path(__file__).resolve().parents[2]; out = args.output.absolute()
    assert re.fullmatch('[0-9a-f]{40}', args.revision) and 1 <= args.repetitions <= 100
    assert out.is_relative_to(repo/'ignored') and out.parent.resolve(strict=True) == out.parent and not out.exists()
    toolchain, cargo_home = args.toolchain.resolve(strict=True), args.cargo_home.resolve(strict=True)
    assert toolchain.is_dir() and cargo_home.is_dir()
    os.chdir(repo); resource.setrlimit(resource.RLIMIT_CORE, (0, 0)); out.mkdir(mode=0o700)
    env = dict(HOME=os.environ['HOME'], PATH=str(toolchain/'bin')+':/usr/bin:/bin',
        RUSTC=str(toolchain/'bin/rustc'), RUSTDOC=str(toolchain/'bin/rustdoc'), CARGO_HOME=str(cargo_home),
        CARGO_TARGET_DIR=str(repo/'target'), CARGO_INCREMENTAL='0', CARGO_BUILD_JOBS='4', CARGO_NET_OFFLINE='true',
        CARGO_TERM_COLOR='never', CARGO_PROFILE_DEV_DEBUG='0', CARGO_PROFILE_TEST_DEBUG='0',
        CARGO_PROFILE_DEV_OPT_LEVEL='0', CARGO_PROFILE_TEST_OPT_LEVEL='0', CARGO_PROFILE_DEV_DEBUG_ASSERTIONS='true',
        CARGO_PROFILE_TEST_DEBUG_ASSERTIONS='true', CARGO_PROFILE_DEV_OVERFLOW_CHECKS='true',
        CARGO_PROFILE_TEST_OVERFLOW_CHECKS='true', LANG='C.UTF-8', LC_ALL='C.UTF-8', PYTHONDONTWRITEBYTECODE='1', LITEINST_EVALUATION='1')
    helper = repo/'evaluation/admission/processes.py'; script = Path(__file__).resolve()
    selected = ['Cargo.toml', 'Cargo.lock', 'crates/liteinst-launch/Cargo.toml', 'crates/liteinst-launch/src/lib.rs',
        'crates/liteinst-launch/tests/exec_backing_cleanup.rs', 'crates/liteinst-launch/tests/support/b3_exec_cleanup.rs',
        'crates/liteinst-launch/tests/support/b3_exec/mod.rs', 'crates/liteinst-launch/tests/support/b3_exec/raw.rs',
        'crates/liteinst-launch/tests/support/b3_signal/bootstrap.rs',
        'crates/liteinst-launch/src/linux/remote/dynamic/owner/admission/exec/native_support.rs',
        'crates/liteinst-launch/src/linux/remote/dynamic/owner/admission/exec/native_support/backing_cleanup.rs',
        'crates/liteinst-launch/src/linux/remote/dynamic/owner/admission/source_identity/backing.rs',
        'crates/liteinst-launch/src/linux/remote/dynamic/owner/admission/source_identity/backing/query.rs',
        'evaluation/admission/processes.py', 'evaluation/admission/check_backing_singleton.py']
    result = dict(schema=1, status='FAILED', revision=args.revision, phase='preflight', requested=args.repetitions, attempts=[],
        argv=['$TOOLCHAIN/bin/cargo', *ARGV], wall_limit_seconds=180, max_log_bytes=8*MIB, helper_sha256=HELPER_SHA,
        runner_sha256=digest(script), compiler_jobs=4, controls=CONTROL, trajectories=[r[0] for r in ROLES],
        parallelism='Sequential processes; no affinity change or RUST_TEST_THREADS override; no libtest thread cap.',
        scope='Functional regression qualification. Operational durations are not performance measurements. Expected InvalidUnmap SIGABRT is one explicit trajectory; any other command failure remains FAILED.')
    def save():
        result.update(attempted=len(result['attempts']), passed=sum(a['status']=='PASS' for a in result['attempts']),
            unrun=args.repetitions-len(result['attempts']))
        body=json.dumps(result,indent=2,sort_keys=True,allow_nan=False)+'\n'
        assert all(s not in body for s in ('/home/', '.facebook.com', '.fbinfra.net'))
        (out/'receipt.json').write_text(body)
        text=io.StringIO(newline=''); fields=['attempt','status','exit','seconds','cleanup_complete','rescued','controls','trajectories','log_sha256']
        writer=csv.DictWriter(text,fields,lineterminator='\n'); writer.writeheader()
        for row in result['attempts']:
            c=row['closed'] or {}; writer.writerow(dict(attempt=row['attempt'],status=row['status'],exit=c.get('exit_code'),
                seconds=c.get('seconds'),cleanup_complete=c.get('cleanup_complete'),rescued=c.get('reaped_descendants'),
                controls=5 if row['status']=='PASS' else 0,trajectories=6 if row['status']=='PASS' else 0,log_sha256=c.get('private_log_sha256')))
        (out/'attempts.csv').write_text(text.getvalue())
    save()
    try:
        def git(*argv): return subprocess.check_output(['/usr/bin/git','--no-optional-locks',*argv],env=env,timeout=10)
        def unchanged():
            assert git('rev-parse','--show-toplevel').decode().strip()==str(repo)
            assert git('rev-parse','HEAD').decode().strip()==args.revision
            assert git('status','--porcelain','--untracked-files=no')==b''
            assert digest(script)==result['runner_sha256'] and digest(helper)==HELPER_SHA
            assert sorted(os.sched_getaffinity(0))==affinity
        affinity=sorted(os.sched_getaffinity(0)); unchanged()
        assert set(git('ls-files','-z','--',*selected).decode().rstrip('\0').split('\0'))==set(selected)
        result['sources_before']={n:digest(repo/n) for n in selected}
        tools={'cargo':toolchain/'bin/cargo','rustc':toolchain/'bin/rustc','python':Path(sys.executable).resolve(), 'git':Path('/usr/bin/git')}
        result['tools']={n:digest(p) for n,p in tools.items()}
        versions={n:subprocess.check_output([str(tools[n]),'--version'],env=env,timeout=10).decode().strip() for n in ('cargo','rustc','git')}
        assert re.fullmatch(r'cargo [0-9A-Za-z.+_-]+ \([0-9a-f]{7,40} [0-9-]+\)',versions['cargo'])
        assert re.fullmatch(r'rustc [0-9A-Za-z.+_-]+ \([0-9a-f]{7,40} [0-9-]+\)',versions['rustc'])
        assert re.fullmatch(r'git version [0-9.]+',versions['git']); versions['python']=list(sys.version_info[:3]); result['versions']=versions
        cpus=[dict((k.strip(),v.strip()) for k,v in (line.split(':',1) for line in block.splitlines() if ':' in line)) for block in Path('/proc/cpuinfo').read_text().split('\n\n') if block.strip()]
        observed=[c for c in cpus if int(c['processor']) in affinity]; assert {int(c['processor']) for c in observed}==set(affinity)
        models={(c['vendor_id'],*(int(c[k]) for k in ('cpu family','model','stepping'))) for c in observed}; assert len(models)==1
        vendor,family,model,stepping=models.pop(); assert vendor in ('AuthenticAMD','GenuineIntel')
        system=os.uname(); kernel=system.release.split('-',1)[0]; assert system.machine=='x86_64' and re.fullmatch(r'[0-9.]+',kernel)
        result['hardware']=dict(owner_label='AMD EPYC Zen 5 dev host',owner_label_origin='owner-specified',architecture=system.machine,
            kernel_version=kernel,vendor=vendor,family=family,model=model,stepping=stepping,available_affinity_cpus=len(affinity))
        spec=importlib.util.spec_from_file_location('backing_processes',helper); processes=importlib.util.module_from_spec(spec); spec.loader.exec_module(processes)
        log_root=repo/'target/evaluation'; log_root.mkdir(parents=True,exist_ok=True); logs=Path(tempfile.mkdtemp(prefix='backing-singleton-',dir=log_root))
        for index in range(1,args.repetitions+1):
            result['phase']='attempt'; unchanged()
            row=dict(attempt=index,status='FAILED',closed=None); result['attempts'].append(row); save()
            log=logs/f'attempt-{index:03}.log'
            row['closed']=processes.run_command([str(tools['cargo']),*ARGV],env,log,180,8*MIB); save()
            data=log.read_bytes(); (out/log.name).write_bytes(data)
            c=row['closed']; assert len(data)<=8*MIB and hashlib.sha256(data).hexdigest()==c['private_log_sha256']
            assert c['exit_code']==0 and c['termination'] is None and c['cleanup_complete'] is True and c['reaped_descendants']==0
            protocol(data,repo); unchanged(); row['status']='PASS'; save(); print(f'attempt={index} PASS controls=5 trajectories=6',flush=True)
        result['phase']='final-source-check'; unchanged()
        result['sources_after']={n:digest(repo/n) for n in selected}
        assert result['sources_after']==result['sources_before'] and {n:digest(p) for n,p in tools.items()}==result['tools']
        assert len(result['attempts'])==args.repetitions and all(a['status']=='PASS' for a in result['attempts'])
        result.update(status='PASS',phase='complete')
    except BaseException as error:
        result['failure']=dict(phase=result['phase'],kind=type(error).__name__)
    finally:
        save()
    return 0 if result['status']=='PASS' else 1


if __name__ == '__main__': raise SystemExit(main())
