#!/usr/bin/env python3
"""One existing serial-launch command; private records, no admission qualification."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import resource
import subprocess
import sys

REVISION = '41a236dff00295a70b5c4cf2982eb91359e5b2c1'
PINS = {
    'evaluation/admission/processes.py': '0dfc4f40943252950e122c9e9fffb837448cba12140d0614acfa9d3621f2e31f',
    'evaluation/trampoline-parallel.py': '0d3697eaaf433fc76d22f4ec7b6bc8047d0260f90bf9227072ad8dee2f4662ba',
    'evaluation/admission/run.py': '5797f92dc1f93a1c257960f866c4012a91d7b0310e87a69ac60f4f3ea8d21de9',
}
ARGV = ['cargo', 'test', '-p', 'liteinst-launch', '--tests', '--',
        '--test-threads=1', '--nocapture']

def main():
    if sys.flags.optimize:
        raise SystemExit('optimized Python is unsupported')
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('repo','output','toolchain','user-home','cargo-home'):
        parser.add_argument('--'+name,type=Path,required=True)
    parser.add_argument('--cpus',required=True)
    args=parser.parse_args()
    repo,out=args.repo,args.output
    for p in (repo,args.toolchain,args.user_home,args.cargo_home):
        assert p.is_absolute() and p.resolve(strict=True)==p and p.is_dir()
    assert out.is_absolute() and out.parent.resolve(strict=True)==out.parent
    assert out.is_relative_to(repo/'ignored') and not out.exists() and not out.is_symlink()
    cpus=[int(v) for v in args.cpus.split(',')]
    assert len(cpus)==len(set(cpus))==4 and all(c>=0 for c in cpus)
    assert set(cpus)<=os.sched_getaffinity(0)
    env=dict(HOME=str(args.user_home),CARGO_HOME=str(args.cargo_home),
        PATH=str(args.toolchain/'bin')+':/usr/bin:/bin',CARGO_INCREMENTAL='0',
        CARGO_BUILD_JOBS='4',CARGO_NET_OFFLINE='true',RUST_TEST_THREADS='4',
        CARGO_TERM_COLOR='never',PYTHONDONTWRITEBYTECODE='1',RUSTFLAGS='',
        RUSTDOCFLAGS='',RUSTC_WRAPPER='',RUSTC_WORKSPACE_WRAPPER='',
        CARGO_TARGET_DIR=str(repo/'target'),TMPDIR=str(out/'tmp'),LANG='C.UTF-8',
        LC_ALL='C.UTF-8',LITEINST_EVALUATION='1')
    def git(*parts):
        r=subprocess.run(['/usr/bin/git','--no-optional-locks','--no-replace-objects',
            '-c','core.fsmonitor=false','-C',str(repo),*parts],env=env,
            stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
            timeout=30,check=True)
        assert not r.stderr
        return r.stdout
    assert git('rev-parse','HEAD').decode().strip()==REVISION
    assert not git('diff','--no-ext-diff','--no-textconv','--binary','HEAD','--')
    for name,digest in PINS.items():
        data=(repo/name).read_bytes()
        assert hashlib.sha256(data).hexdigest()==digest and git('show',REVISION+':'+name)==data
    def load(name,path):
        spec=importlib.util.spec_from_file_location(name,path)
        module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        return module
    observed=load('merged_source_observation',repo/'evaluation/trampoline-parallel.py')
    processes=load('merged_serial_processes',repo/'evaluation/admission/processes.py')
    assert processes.ROOT==repo and processes.CLEANUP_SECONDS==3.0
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    os.sched_setaffinity(0,set(cpus))
    assert os.sched_getaffinity(0)==set(cpus)
    out.mkdir(); (out/'tmp').mkdir()
    # Retain the unchanged supervisor's target/evaluation log restriction.
    # The closed log is copied byte-exact into ignored/; neither copy is removed.
    log=repo/'target/evaluation'/(out.name+'-serial.log')
    log.parent.mkdir(parents=True,exist_ok=True)
    assert log.parent.resolve(strict=True)==log.parent and not log.exists() and not log.is_symlink()
    selected=dict(cargo=args.toolchain/'bin/cargo',rustc=args.toolchain/'bin/rustc',
        rustdoc=args.toolchain/'bin/rustdoc',python=Path(sys.executable),git=Path('/usr/bin/git'))
    def snapshot():
        return dict(source=observed.source(repo,'/usr/bin/git',env),
            tools={n:observed.tool(p) for n,p in selected.items()},
            configurations=observed.configuration(repo,args.cargo_home),
            affinity=sorted(os.sched_getaffinity(0)))
    caller,caller_owner=observed.read(Path(__file__).resolve(strict=True))
    before=snapshot(); assert before['source']['revision']==REVISION
    observed.write(out/'inputs-before.json',before)
    hardware=dict(host_label='AMD EPYC Zen 5 dev host',architecture=platform.machine(),
        cpu_model=next(s.split(':',1)[1].strip() for s in Path('/proc/cpuinfo').read_text().splitlines() if s.startswith('model name')),
        kernel_release=platform.release(),libc=platform.libc_ver(),logical_cpus=os.cpu_count())
    observed.write(out/'hardware.json',hardware)
    observed.write(out/'command.json',dict(argv=ARGV,cwd=str(repo),env=env,affinity=sorted(cpus),
        timeout_seconds=180,max_log_bytes=8*1024*1024,cleanup_seconds=3,
        source_revision=REVISION,source_pins=PINS,caller_sha256=hashlib.sha256(caller).hexdigest(),
        caller_owner=caller_owner,private_supervisor_log=str(log),
        scope='Single serial-launch command, not the six-command admission protocol'))
    result=processes.run_command(ARGV,env,log,180,8*1024*1024)
    observed.write(out/'process-result.json',result)
    data,log_owner=observed.read(log)
    assert hashlib.sha256(data).hexdigest()==result['private_log_sha256']
    with (out/'serial.log').open('xb') as f: f.write(data)
    observed.write(out/'log-copy.json',dict(source=str(log),source_owner=log_owner,
        destination='serial.log',bytes=len(data),sha256=result['private_log_sha256']))
    after=snapshot(); observed.write(out/'inputs-after.json',after)
    caller_stable=observed.read(Path(__file__).resolve(strict=True))==(caller,caller_owner)
    passed=(result['exit_code']==0 and result['termination'] is None
        and result['cleanup_complete'] is True and result['reaped_descendants']==0
        and after==before and caller_stable)
    summary=dict(status='PASS_COMMAND_AND_STABLE_INPUTS' if passed else 'FAILED',
        revision=REVISION,command=result,inputs_before_after_equal=after==before,
        caller_unchanged=caller_stable,enclosing_parent_closed=None,
        log_accounting='Pending independent complete saved-log review',
        full_admission_protocol=False,qualification_complete=False,
        durations='Operational diagnostics only, not performance measurements')
    observed.write(out/'summary.json',summary)
    print(json.dumps(dict(status=summary['status'],revision=REVISION,exit=result['exit_code'],
        termination=result['termination'],cleanup_complete=result['cleanup_complete'])),flush=True)
    return 0 if passed else 1

if __name__=='__main__':
    raise SystemExit(main())
