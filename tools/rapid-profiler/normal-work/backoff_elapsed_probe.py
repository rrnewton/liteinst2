#!/usr/bin/env python3
"""Twenty fixed four-mode elapsed observations; no accuracy or speedup claim."""
import sys
if sys.flags.optimize:
    raise SystemExit('assertions required')
sys.dont_write_bytecode = True
import argparse
import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import traceback

MIB = 1048576
PROTOCOL = '13cec7f96bd6aae664ba5ffd5f74130a17d2b02c929703004b5e5d3d776890b3'
WIRE = 'fa31e1d3284ea7afd684673e2142b23f5076b7dea39bba620ed0788d534e64a7'
MODES = ('native', 'always-on', 'backoff-k10', 'backoff-k1000')
CHECKER = (
    'test_complete_k10_k1000_population_and_lossless_timing',
    'test_empty_epochs_all_sampled_and_maximum_history',
    'test_zero_full_width_and_separate_clock_origins',
    'test_actual_grammar_framing_caps_and_request_domains',
    'test_functional_terminal_policy_identity_counts_and_order',
    'test_complete_work_owner_stack_ack_and_history_report_joins',
    'test_timing_population_order_and_columns',
    'test_timing_numbers_arithmetic_and_enclosure_boundaries',
    'test_timing_terminal_and_request_identity',
    'test_old_grammars_remain_distinct',
    'test_source_local_import_and_optimized_entrypoints')
CONTROLS = (
    'test_fixed_twenty_catalog_and_exact_timer_role_argv',
    'test_all_four_observation_identities_and_raw_clock_separation',
    'test_printed_success_nonzero_is_failure_and_missing_identity_stops',
    'test_owner_prerequisites_and_custody_gate_the_frozen_remainder',
    'test_projection_keeps_all_rows_and_only_joined_nonzero_ratios',
    'test_exact_old_and_new_censuses_and_authenticated_prerequisite',
    'test_request_closure_and_completed_pins_are_not_refreshable',
    'test_local_import_optimized_refusal_and_exact_control_census')
STAGES = ('prerequisite', 'throughput-checker', 'backoff-checker', 'pending-checker',
    'elapsed-checker', 'throughput-driver', 'backoff-driver', 'elapsed-driver', 'timer-controls',
    'throughput-rust', 'backoff-rust', 'pending-rust', 'elapsed-rust', 'timer-build')
FIELDS = ('trial','block','mode','status','reason','exit','native_exit','native_signal','cpu','pid','tid',
    'controller_tid','arms','sampled','unsampled','wire_rows','zero_raw_spans','observed_generations','rearmed',
    'sampled_after_closed','unobserved_generations','function_closed','later_generation_calls','later_generation_samples','setup_ns','body_ns','service_ns','zero_body_spans',
    'process_wall_ns','child_user_us','child_system_us','child_cpu_us',
    'stdout_sha256','stderr_sha256','result_sha256')
TIMING_FIELDS = ('trial','kind','index','start_ns','end_ns')
SCOPE = ('Fixed four-mode configuration observations only: no retries, warmup, subtraction, '
    'outlier removal, accuracy, confidence, pure observer overhead, application speedup, '
    'continuous throughput or full-A5 claim. First preflight precedes service; later '
    'preflights, postflight and checkpoints are inside. Validation and controller costs '
    'differ by mode. RAW and process-timer MONOTONIC have separate origins. '
    'All original strict 2 ms and 520-arm outcomes remain separate and unchanged.')


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def catalog():
    return [dict(trial=4*b+i+1, block=b+1, mode=MODES[(b+i)%4])
            for b in range(5) for i in range(4)]


def timed_argv(shared, taskset, timer, record, token, binary, key, cpus,
               subject, trusted, elf_va, caller_candidate, caller):
    assert key in catalog() and len(cpus) == 4 and cpus == sorted(set(cpus))
    assert all(type(c) is int and 0 <= c <= 1023 for c in cpus)
    assert type(elf_va) is int and 0 < elf_va <= (1<<64)-38
    tail = [subject, trusted, str(elf_va), '37', caller_candidate, caller]
    if key['mode'] in MODES[:2]:
        app = [binary, 'normal-observer-throughput', key['mode'], *tail]
        return shared.timed_argv(taskset, timer, record, token, app, cpus)
    k = 10 if key['mode'] == 'backoff-k10' else 1000
    inner = list(map(str, (taskset, '--cpu-list', f'{cpus[1]},{cpus[3]}', binary,
        'normal-observer-backoff-elapsed', k, cpus[1], cpus[3], *tail)))
    return [str(taskset), '--cpu-list', str(cpus[2]), str(timer), str(record), token(inner), '--', *inner], inner


def observation_join(shared, parsed, timer, key, cpus):
    mode = key['mode']; assert key in catalog()
    if mode in MODES[:2]:
        shared.observation_join(parsed, timer, mode, cpus[1])
    else:
        k = 10 if mode == 'backoff-k10' else 1000
        assert parsed['status'] == 'TIMING_COMPLETE'
        assert (parsed['k'], parsed['app_cpu'], parsed['controller_cpu']) == (k, cpus[1], cpus[3])
        f = parsed['functional']
        assert f['status'] == 'FUNCTIONAL_PASS'
        assert (f['k'], f['app_cpu'], f['controller_cpu']) == (k, cpus[1], cpus[3])
        assert f['pid'] == f['tid'] == timer['child_pid'] == timer['wait_pid']
        assert 0 < f['controller_tid'] < 2**31 and f['controller_tid'] != f['tid']
        assert (f['calls'], f['helper_calls'], f['instructions'], f['batches'], len(f['rows'])) == (3072,1536,614400,128,3072)
        assert f['sampled'] == f['records'] and f['sampled']+f['unsampled'] == 3072
    assert parsed['clock'] == 'CLOCK_MONOTONIC_RAW' and parsed['units'] == 'ns'
    assert parsed['timing_rows'] == 130 and len(parsed['body']) == 128


class AppIdentityUnconfirmed(Exception):
    """A timer/taskset child alone cannot authenticate a failed APP execution."""


def observe(shared, timing, checker, stdout, stderr, timer_bytes, app_argv, direct, key, cpus):
    measured = timing.parse(timer_bytes, app_argv)
    normal = shared.timer_status(measured, direct)
    try:
        if key['mode'] in MODES[:2]:
            parsed = checker(stdout, stderr, key['mode'])
        else:
            parsed = checker(stdout, stderr, 10 if key['mode'] == 'backoff-k10' else 1000, cpus[1], cpus[3])
    except AssertionError as error:
        raise AppIdentityUnconfirmed('APP_EXEC_UNCONFIRMED') from error
    observation_join(shared, parsed, measured, key, cpus)
    return measured, parsed, normal


def advance(rows, index):
    assert len(rows) == 20 and 0 <= index < 20
    assert all(all(r[k] == v for k,v in key.items()) for r,key in zip(rows,catalog()))
    assert all(r['status'] in ('PASS','FAILED') and r.get('closed') is True and r.get('identity_joined') is True for r in rows[:index])
    assert all(r['status'] == 'UNRUN' for r in rows[index:])
    rows[index]['status'] = 'FAILED'


def comparisons(rows, complete):
    result = []
    for block in range(1,6):
        group = [r for r in rows if r['block'] == block]
        native = next(r for r in group if r['mode'] == 'native')
        for mode in MODES[1:]:
            other = next(r for r in group if r['mode'] == mode)
            pair = dict(block=block, mode=mode, native_trial=native['trial'], observed_trial=other['trial'],
                status='UNRESOLVED_MEMBER', body=None, service=None)
            valid = all(r['status']=='PASS' and r.get('closed') is True and r.get('identity_joined') is True for r in (native,other))
            if valid and not complete: pair['status'] = 'UNQUALIFIED_CUSTODY'
            if valid and complete:
                pair['status'] = 'FUNCTIONALLY_VALID_PAIR'
                for kind in ('body','service'):
                    n,d = other[kind+'_ns'],native[kind+'_ns']
                    assert type(n) is type(d) is int and 0 <= n < 2**64 and 0 <= d < 2**64
                    pair[kind] = dict(status='EXACT_RATIO' if d else 'UNRESOLVED_ZERO',numerator=n,denominator=d)
            result.append(pair)
    return result


def projection(rows, result_pins, complete):
    assert type(complete) is bool and len(rows)==20
    assert all(all(r[k]==v for k,v in key.items()) for r,key in zip(rows,catalog()))
    assert all(r['status'] in ('PASS','FAILED','UNRUN') for r in rows)
    assert all(type(i) is int and 1 <= i <= 20 for i in result_pins)
    for pin in result_pins.values():
        assert type(pin['bytes']) is int and pin['bytes'] >= 0 and re.fullmatch('[0-9a-f]{64}',pin['sha256'])
    if complete:
        assert set(result_pins)==set(range(1,21))
        assert all(r['status'] in ('PASS','FAILED') and r.get('closed') is True and r.get('identity_joined') is True for r in rows)
        assert all(len(r['timing'])==130 and 'timer' in r for r in rows)
    trials=[]
    for r in rows:
        row={k:r.get(k) for k in FIELDS}
        row.update({k:r.get('timer',{}).get(k) for k in ('process_wall_ns','child_user_us','child_system_us','child_cpu_us')})
        row.update({k+'_sha256':r.get('files',{}).get(k+'.txt',{}).get('sha256') for k in ('stdout','stderr')})
        row['result_sha256']=result_pins.get(r['trial'],{}).get('sha256'); trials.append(row)
    timing_rows=[dict(trial=r['trial'],**{k:t[k] for k in TIMING_FIELDS[1:]}) for r in rows for t in r.get('timing',[])]
    return dict(status='DESCRIPTIVE_PROJECTION' if complete else 'INCOMPLETE_UNQUALIFIED',trials=trials,
        timing=timing_rows,pairs=comparisons(rows,complete),pass_count=sum(r['status']=='PASS' for r in rows),
        failed_count=sum(r['status']=='FAILED' for r in rows),unrun_count=sum(r['status']=='UNRUN' for r in rows))


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--revision',required=True);ap.add_argument('--reservation-tag',required=True)
    for name in ('raw','toolchain','user-home','cargo-home'):ap.add_argument('--'+name,type=Path,required=True)
    a=ap.parse_args();repo=Path(__file__).resolve().parents[3]
    assert re.fullmatch('[0-9a-f]{40}',a.revision) and re.fullmatch('[a-z0-9-]{1,128}',a.reservation_tag)
    for p in (repo,a.toolchain,a.user_home,a.cargo_home):assert p.is_absolute() and p.resolve(strict=True)==p and p.is_dir()
    assert a.raw.is_absolute() and a.raw.is_relative_to(repo/'ignored') and not a.raw.exists()
    assert a.raw.parent.resolve(strict=True)==a.raw.parent
    env=dict(HOME=str(a.user_home),CARGO_HOME=str(a.cargo_home),PATH=str(a.toolchain/'bin')+':/usr/bin:/bin',
        RUSTC=str(a.toolchain/'bin/rustc'),CC=str(Path('/usr/bin/gcc').resolve(strict=True)),CARGO_TARGET_DIR=str(repo/'target'),
        CARGO_INCREMENTAL='0',CARGO_BUILD_JOBS='4',CARGO_NET_OFFLINE='true',CARGO_PROFILE_RELEASE_OPT_LEVEL='3',
        CARGO_PROFILE_RELEASE_DEBUG='0',CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS='true',CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS='true',
        CARGO_TERM_COLOR='never',LC_ALL='C',PYTHONDONTWRITEBYTECODE='1',PYTHONNOUSERSITE='1')
    def git(*args):
        data=subprocess.check_output(['/usr/bin/git','-C',str(repo),*args],env=env,timeout=15)
        assert len(data)<=4*MIB;return data
    assert git('rev-parse','--show-toplevel').decode().strip()==str(repo)
    assert git('rev-parse','HEAD').decode().strip()==a.revision and git('status','--porcelain','--untracked-files=no')==b''
    required={'evaluation/admission/processes.py','tools/unwind-oracle/bounded_command.py','tests/call_tree_truth.rs'}
    required.update('tools/rapid-profiler/'+p for p in ('verify_normal_interval.py','selected-work/check_output.py',
        'selected-work/provenance.py','normal-work/exact_fixture.py','normal-work/observer_work.py',
        'normal-work/throughput_probe.py','normal-work/test_throughput_probe.py','normal-work/throughput_work.py',
        'normal-work/test_throughput_work.py','normal-work/backoff_probe.py','normal-work/test_backoff_probe.py',
        'normal-work/backoff_work.py','normal-work/test_backoff_work.py','normal-work/backoff_pending_owner.py',
        'normal-work/test_backoff_pending_owner.py','normal-work/backoff_elapsed_probe.py','normal-work/test_backoff_elapsed_probe.py',
        'normal-work/backoff_elapsed_work.py','normal-work/test_backoff_elapsed_work.py','tree-work/process_timer.c',
        'tree-work/process_timing.py','tree-work/test_process_timing.py','tree-work/comparison_runner.py',
        'ordinary-interval/normal/observer/throughput.rs','ordinary-interval/normal/observer/throughput/tests.rs',
        'ordinary-interval/normal/observer/backoff.rs','ordinary-interval/normal/observer/backoff/check.rs',
        'ordinary-interval/normal/observer/backoff/tests.rs','ordinary-interval/normal/observer/backoff/pending_owner.rs',
        'ordinary-interval/normal/observer/backoff/elapsed.rs','ordinary-interval/normal/observer/backoff/elapsed/tests.rs'))
    names=git('ls-files','-z','--','src','tests/support','tools/rapid-profiler','Cargo.toml','Cargo.lock','README.md','build.rs',
        ':(glob)**/Cargo.toml',*sorted(required)).decode().rstrip('\0').split('\0')
    assert all(names) and len(names)==len(set(names)) and required.issubset(names)
    before={}
    for n in names:
        data=(repo/n).read_bytes();assert data==git('show',a.revision+':'+n)
        before[n]=dict(bytes=len(data),sha256=hashlib.sha256(data).hexdigest())
    # Project imports begin only after complete tracked-source authentication.
    work=repo/'tools/rapid-profiler/normal-work';tree=repo/'tools/rapid-profiler/tree-work'
    P=load('elapsed_shared',work/'throughput_probe.py');B=load('elapsed_backoff',work/'backoff_probe.py')
    pins=P.Pins()
    for n,h in before.items():pins.retain(repo/n,h)
    tools={n:p.resolve(strict=True) for n,p in (('python',Path(sys.executable)),('gcc',Path('/usr/bin/gcc')),
        ('taskset',Path('/usr/bin/taskset')),('git',Path('/usr/bin/git')),('cargo',a.toolchain/'bin/cargo'),('rustc',a.toolchain/'bin/rustc'))}
    tool_pins={n:pins.retain(p) for n,p in tools.items()}
    processes=P.load('elapsed_processes',repo/'evaluation/admission/processes.py')
    prior=P.load('elapsed_prior',repo/'tools/rapid-profiler/verify_normal_interval.py')
    census=P.load('elapsed_census',repo/'tools/rapid-profiler/selected-work/check_output.py')
    fixture=P.load('elapsed_fixture',work/'exact_fixture.py');timing=P.load('elapsed_timer',tree/'process_timing.py')
    checker=P.load('elapsed_checker',work/'backoff_elapsed_work.py')
    old_checker=P.load('elapsed_old_checker',work/'throughput_work.py')
    owner_checker=P.load('elapsed_owner_checker',work/'backoff_pending_owner.py')
    cpus=sorted(os.sched_getaffinity(0));assert len(cpus)==4 and all(0<=c<=1023 for c in cpus)
    a.raw.mkdir(mode=0o700);logs_root=repo/'target/evaluation';logs_root.mkdir(parents=True,exist_ok=True)
    assert logs_root.resolve(strict=True)==logs_root
    logs=Path(tempfile.mkdtemp(prefix='backoff-elapsed-',dir=logs_root))
    result=dict(schema=1,status='FAILED',stage='setup',revision=a.revision,protocol_sha256=PROTOCOL,wire_sha256=WIRE,
        owner_protocol_sha256=B.OWNER_PROTOCOL,owner_wire_sha256=B.OWNER_WIRE,scope=SCOPE,
        outer_owner_required=dict(wall_seconds=1200,log_bytes=8*MIB),
        reservation=dict(tag=a.reservation_tag,inherited_cpus=cpus,producer_cpu=cpus[0],app_cpu=cpus[1],timer_cpu=cpus[2],
            controller_cpu=cpus[3],verified=False,authority='Root must join actual allocator command/log and hard AllowedCPUs; tag/affinity prove neither reservation nor quiet hardware.'),
        stages=[dict(name=n,status='UNRUN') for n in STAGES],trials=[dict(k,status='UNRUN') for k in catalog()],
        owner_controls=[dict(k,status='UNRUN') for k in B.owner_catalog()],
        sources=dict(count=len(before),manifest=P.freeze(a.raw/'sources-before.json',P.encoded(before),pins)),tools=tool_pins)
    result['catalog']=P.freeze(a.raw/'catalog.json',P.encoded(catalog()),pins)
    result['owner_catalog']=P.freeze(a.raw/'owner-catalog.json',P.encoded(B.owner_catalog()),pins)
    os.sched_setaffinity(0,{cpus[0]})
    def save():
        p=a.raw/'result.tmp';p.write_bytes(P.encoded(result));p.replace(a.raw/'result.json')
    def unchanged():
        assert git('rev-parse','HEAD').decode().strip()==a.revision and git('status','--porcelain','--untracked-files=no')==b''
        assert sorted(os.sched_getaffinity(0))==[cpus[0]];pins.check()
    def observation():
        assert sorted(os.sched_getaffinity(0))==[cpus[0]]
        return dict(utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),affinity=[cpus[0]],
            reservation_tag=a.reservation_tag,load_average=list(os.getloadavg()))
    def retained(path):pins.retain(path);return json.loads(path.read_bytes())
    def prepare(directory,argv):
        directory.mkdir();(directory/'tmp').mkdir();r=P.request(argv,repo,env,directory);P.check_request(r,r)
        P.freeze(directory/'request.json',P.encoded(r),pins)
        command=[str(tools['python']),'-B',str(repo/'tools/unwind-oracle/bounded_command.py'),'--request',str(directory/'request.json'),'--receipt',str(directory/'receipt.json')]
        P.freeze(directory/'command.json',P.encoded(dict(argv=command,env=env,wall_seconds=55,log_bytes=MIB,
            request=pins.values[directory/'request.json'])),pins);return r
    def bounded(directory,r,row):
        unchanged();P.check_request(retained(directory/'request.json'),r)
        parent=[str(tools['python']),'-B',str(repo/'tools/unwind-oracle/bounded_command.py'),'--request',str(directory/'request.json'),'--receipt',str(directory/'receipt.json')]
        assert retained(directory/'command.json')==dict(argv=parent,env=env,wall_seconds=55,log_bytes=MIB,request=pins.values[directory/'request.json'])
        row['before']=observation();save();log=logs/(directory.name+'.log')
        closed=processes.run_command(parent,env,log,55,MIB)
        P.freeze(directory/'parent-closed.json',P.encoded(closed),pins);P.freeze(directory/'parent.log',log.read_bytes(),pins)
        row['after']=observation();row['parent_exit']=closed['exit_code']
        row['files']={n:pins.values[directory/n] for n in ('request.json','command.json','parent-closed.json','parent.log')};save()
        P.outer_closed(closed,closed['exit_code']) # No child-file read before complete outer custody.
        fs={n:pins.retain(directory/n) for n in ('request.json','command.json','parent-closed.json','parent.log','receipt.json','stdout.txt','stderr.txt')}
        row['files']=fs;save()
        direct=P.closed_request(closed,retained(directory/'receipt.json'),json.loads((directory/'parent.log').read_bytes()),fs,
            fs['request.json']['sha256'],before['tools/unwind-oracle/bounded_command.py']['sha256'],MIB)
        unchanged();row.update(closed=True,exit=direct);return direct
    def stage(name,argv,validate):
        row=result['stages'][STAGES.index(name)];assert row['status']=='UNRUN'
        assert all(s['status']=='PASS' for s in result['stages'][:STAGES.index(name)])
        row['status']='FAILED';result['stage']=name;save();d=a.raw/name
        r=prepare(d,argv);assert bounded(d,r,row)==0;validate(d);unchanged()
        row['status']='PASS';row['result']=P.freeze(d/'result.json',P.encoded(row),pins);save()
    def tables(directory,row,parsed):
        f=parsed['functional'];pairs=[('calls','table')]
        if row['mode'] in MODES[2:]:pairs.extend((('history','history_table'),('reports','report_table')))
        for name,key in pairs:row['files'][name+'.csv']=P.freeze(directory/(name+'.csv'),f[key],pins)
        row['files']['timing.csv']=P.freeze(directory/'timing.csv',parsed['timing_table'],pins)
    def public(directory,complete):
        rp={r['trial']:pins.values[p] for r in result['trials'] if (p:=a.raw/('trial-%02d'%r['trial'])/'result.json') in pins.values}
        if complete:
            B.owners_complete(result['owner_controls'])
            assert all(s['status']=='PASS' and s.get('closed') is True and 'result' in s for s in result['stages'])
        view=projection(result['trials'],rp,complete);d=a.raw/directory;d.mkdir()
        exports=dict(trials=P.freeze(d/'trials.csv',P.csv_bytes(FIELDS,view['trials']),pins),
            timing=P.freeze(d/'timing.csv',P.csv_bytes(TIMING_FIELDS,view['timing']),pins),
            pairs=P.freeze(d/'pairs.json',P.encoded(view['pairs']),pins))
        receipt=dict(status=view['status'],outcome=result['status'],revision=a.revision,protocol_sha256=PROTOCOL,wire_sha256=WIRE,scope=SCOPE,
            owner_protocol_sha256=B.OWNER_PROTOCOL,owner_wire_sha256=B.OWNER_WIRE,reservation=result['reservation'],
            failure=result.get('failure'),error_type=result.get('error_type'),outer_owner_required=result['outer_owner_required'],
            hardware=result.get('hardware'),sources=result['sources'],tools=tool_pins,catalog=result['catalog'],commands=result.get('commands'),
            prerequisite=result.get('prerequisite'),artifacts=result.get('artifacts'),
            stages=[dict(name=s['name'],status=s['status'],result=s.get('result')) for s in result['stages']],
            owner_catalog=result['owner_catalog'],owner_commands=result.get('owner_commands'),
            owner_controls=[{k:r.get(k) for k in ('control','name','k','hold_ordinal','status','reason','exit','wire_rows','result')} for r in result['owner_controls']],
            exports=exports,timing_rows=len(view['timing']),functional_rows=sum(r.get('wire_rows',0) for r in result['trials']),
            owner_wire_rows=sum(r.get('wire_rows',0) for r in result['owner_controls']),counts={k:view[k] for k in ('pass_count','failed_count','unrun_count')},
            normal_outer_owners=sum(r.get('closed') is True for r in result['stages']+result['owner_controls']+result['trials']),
            observations=[dict(trial=r['trial'],before=r.get('before'),after=r.get('after')) for r in result['trials']],
            identity_scope='Measured members require exact timer argv/token/wait PID joined to accepted actual APP output. Untimed owner controls retain collector self-identity; bounded_command has no direct-child PID field.',
            completion_authority='Final private result, immutable sources and root-owned complete outer closure/reservation are required; projection alone proves none of these.')
        return P.freeze(d/'receipt.json',P.encoded(receipt),pins)
    active=active_row=None
    try:
        row=result['stages'][0];row['status']='FAILED';result['stage']='prerequisite';save();unchanged()
        qualified=a.raw/'qualification'
        argv=[str(tools['taskset']),'--cpu-list',','.join(map(str,cpus)),str(tools['python']),'-B',str(repo/'tools/rapid-profiler/verify_normal_interval.py'),
            '--revision',a.revision,'--raw',str(qualified),'--toolchain',str(a.toolchain),'--user-home',str(a.user_home),'--cargo-home',str(a.cargo_home),
            '--reference-exact','--reference-work','--reference-leg','--observer-work']
        P.freeze(a.raw/'prerequisite-command.json',P.encoded(dict(argv=argv,env=env,wall_seconds=1200,log_bytes=8*MIB,affinity=cpus)),pins)
        closed=processes.run_command(argv,env,logs/'prerequisite.log',1200,8*MIB)
        P.freeze(a.raw/'prerequisite-closed.json',P.encoded(closed),pins);P.freeze(a.raw/'prerequisite.log',(logs/'prerequisite.log').read_bytes(),pins)
        row['files']={n:pins.values[a.raw/n] for n in ('prerequisite-command.json','prerequisite-closed.json','prerequisite.log')}
        row['exit']=closed['exit_code'];save();P.outer_closed(closed,closed['exit_code']);row['closed']=True
        assert pins.values[a.raw/'prerequisite.log']['sha256']==closed['private_log_sha256']
        if (qualified/'result.json').exists():row['private_result']=pins.retain(qualified/'result.json')
        P.outer_closed(closed,0)
        q=P.qualified_inputs(repo,qualified,a.revision,env,cpus,before,tools,pins,prior,census,fixture,
            B.INVENTORY_PREFIX,B.RUST+B.OWNER_RUST+B.ELAPSED_RUST)
        assert {n for n in q['inventory'] if n.startswith(P.PREFIX)}==set(P.RUST)
        result['artifacts'],result['prerequisite']=q['artifacts'],q['prerequisite']
        result['hardware']={k:v for k,v in q['old']['hardware'].items() if k in ('description','vendor','family','model','stepping')}
        unchanged();row['status']='PASS';row['result']=P.freeze(a.raw/'prerequisite-result.json',P.encoded(row),pins);save()
        for name,source,klass,methods in (
                ('throughput-checker',work/'test_throughput_work.py','Controls',P.CHECKER),
                ('backoff-checker',work/'test_backoff_work.py','Controls',B.CHECKER),
                ('pending-checker',work/'test_backoff_pending_owner.py','Controls',B.OWNER_CHECKER),
                ('elapsed-checker',work/'test_backoff_elapsed_work.py','Controls',CHECKER),
                ('throughput-driver',work/'test_throughput_probe.py','Controls',P.CONTROLS),
                ('backoff-driver',work/'test_backoff_probe.py','Controls',B.CONTROLS),
                ('elapsed-driver',work/'test_backoff_elapsed_probe.py','Controls',CONTROLS),
                ('timer-controls',tree/'test_process_timing.py','ProcessTiming',P.TIMER_CONTROLS)):
            P.python_census(source.read_bytes(),klass,methods)
            stage(name,[tools['python'],'-B',source],lambda d,methods=methods:P.python_controls((d/'stdout.txt').read_bytes(),(d/'stderr.txt').read_bytes(),methods))
        for name,methods in (('throughput-rust',P.RUST),('backoff-rust',B.RUST),('pending-rust',B.OWNER_RUST),('elapsed-rust',B.ELAPSED_RUST)):
            stage(name,[q['test_binary'],*methods,'--exact','--test-threads=1'],lambda d,methods=methods:
                census.controls((d/'stdout.txt').read_bytes(),(d/'stderr.txt').read_bytes(),methods,q['inventory']))
        timer=a.raw/'process-timer'
        def built(d):
            assert (d/'stdout.txt').read_bytes()==(d/'stderr.txt').read_bytes()==b''
            assert 0<pins.retain(timer)['bytes']<=MIB
        stage('timer-build',[tools['gcc'],'-O3','-std=c11','-Wall','-Wextra','-Werror',tree/'process_timer.c','-o',timer],built)
        result['artifacts']['timer']=pins.values[timer]
        plans=[]
        for key in catalog():
            d=a.raw/('trial-%02d'%key['trial'])
            argv,inner=timed_argv(P,tools['taskset'],timer,d/'timing.txt',timing.token,q['binary'],key,cpus,
                q['subject'],q['trusted'],q['details']['elf_va'],q['caller_candidate'],q['caller'])
            r=prepare(d,argv);plans.append(dict(key,app_argv=inner,request=r,request_digest=pins.values[d/'request.json']))
        result['commands']=P.freeze(a.raw/'commands.json',P.encoded(plans),pins)
        owner_plans=[]
        for key in B.owner_catalog():
            argv=B.trial_argv(tools['taskset'],q['binary'],key,cpus,q['subject'],q['trusted'],q['details']['elf_va'],q['caller_candidate'],q['caller'],True)
            d=a.raw/key['name'];r=prepare(d,argv);owner_plans.append(dict(key,request=r,request_digest=pins.values[d/'request.json']))
        result['owner_commands']=P.freeze(a.raw/'owner-commands.json',P.encoded(owner_plans),pins)
        for index,plan in enumerate(owner_plans):
            unchanged();assert retained(a.raw/'owner-catalog.json')==B.owner_catalog() and retained(a.raw/'owner-commands.json')==owner_plans
            assert fixture.authenticate(q['subject'],q['trusted'],q['details']['elf_va'],37,q['selection'],pins.values[q['selection']]['sha256'])==q['selected']
            assert all(r['status'] in ('PASS','FAILED') and r.get('closed') is True for r in result['owner_controls'][:index])
            row=result['owner_controls'][index];assert row['status']=='UNRUN';row['status']='FAILED'
            active=a.raw/row['name'];active_row=row;result['stage']=row['name'];save()
            direct=bounded(active,plan['request'],row);parsed=None
            try:parsed=owner_checker.check((active/'stdout.txt').read_bytes(),(active/'stderr.txt').read_bytes(),row['k'],cpus[1],cpus[3])
            except AssertionError:pass
            row['status'],row['reason']=B.outcome(direct,parsed)
            if parsed is not None:
                assert parsed['hold_ordinal']==row['hold_ordinal'];row['wire_rows']=len(parsed['rows']);row['terminal']=parsed['terminal'];row['phases']=parsed['phases']
                for name,key in (('calls','table'),('history','history_table'),('reports','report_table'),('phases','phase_table')):
                    row['files'][name+'.csv']=P.freeze(active/(name+'.csv'),parsed[key],pins)
            unchanged();row['result']=P.freeze(active/'result.json',P.encoded(row),pins);active=active_row=None;save()
        try:B.owners_complete(result['owner_controls'])
        except AssertionError as error:raise B.OwnerPrerequisiteFailed() from error
        for index,plan in enumerate(plans):
            unchanged();assert retained(a.raw/'catalog.json')==catalog() and retained(a.raw/'commands.json')==plans
            assert fixture.authenticate(q['subject'],q['trusted'],q['details']['elf_va'],37,q['selection'],pins.values[q['selection']]['sha256'])==q['selected']
            advance(result['trials'],index);row=result['trials'][index];active=a.raw/('trial-%02d'%row['trial']);active_row=row;result['stage']=active.name;save()
            direct=bounded(active,plan['request'],row)
            row['files']['timing.txt']=pins.retain(active/'timing.txt')
            # Retain parsed timer evidence even if APP identity subsequently refuses.
            row['timer']=timing.parse((active/'timing.txt').read_bytes(),plan['app_argv'])
            row.update(native_exit=row['timer']['exit'],native_signal=row['timer']['signal']);save()
            measured,parsed,normal=observe(P,timing,old_checker.check if row['mode'] in MODES[:2] else checker.check,
                (active/'stdout.txt').read_bytes(),(active/'stderr.txt').read_bytes(),(active/'timing.txt').read_bytes(),
                plan['app_argv'],direct,{k:row[k] for k in ('trial','block','mode')},cpus)
            f=parsed['functional'];row.update(status='PASS' if normal else 'FAILED',reason=None if normal else 'FUNCTIONAL_EXIT',
                identity_joined=True,wire_rows=len(f['rows']),zero_raw_spans=f['zero_raw_spans'],native_exit=measured['exit'],native_signal=measured['signal'],cpu=cpus[1],pid=f['pid'],tid=f['tid'],
                setup_ns=parsed['setup_ns'],body_ns=parsed['body_ns'],service_ns=parsed['service_ns'],zero_body_spans=parsed['zero_body_spans'],
                timing=[parsed['setup'],*parsed['body'],parsed['service']],division_status=parsed['division_status'])
            if row['mode'] in MODES[2:]:
                row.update({k:f[k] for k in ('controller_tid','arms','sampled','unsampled','observed_generations','rearmed','sampled_after_closed')})
                row['coverage']=f['coverage'];row['unobserved_generations']=len(f['coverage']['published_but_unobserved'])
                row.update({k:f['coverage'][k] for k in ('function_closed','later_generation_calls','later_generation_samples')})
            tables(active,row,parsed);unchanged();P.freeze(active/'result.json',P.encoded(row),pins);active=active_row=None;save()
        unchanged();result['sources']['after']=P.freeze(a.raw/'sources-after.json',P.encoded({n:P.digest(repo/n) for n in names}),pins);unchanged()
        result['status']='COMPLETE' if all(r['status']=='PASS' for r in result['trials']) else 'COMPLETE_WITH_FAILURES'
        result['stage']='complete';pin=public('public-pending',True);unchanged()
        assert not (a.raw/'public').exists();(a.raw/'public-pending').rename(a.raw/'public');result['public_receipt']=pin
    except BaseException as error:
        result['status']='FAILED';result['error_type']=type(error).__name__
        result['failure']=P.freeze(a.raw/'failure.txt',traceback.format_exc().encode('utf-8'),pins)
        reason='APP_EXEC_UNCONFIRMED' if isinstance(error,AppIdentityUnconfirmed) else 'OWNER_PREREQUISITE_FAILED' if isinstance(error,B.OwnerPrerequisiteFailed) else 'AUTHORITY_CUSTODY_OR_PREREQUISITE_FAILURE'
        for r in result['trials']+result['owner_controls']:
            if r['status']=='UNRUN':r['reason']=reason
        if active is not None:
            active_row.update(status='FAILED',reason=reason)
            if active/'result.json' not in pins.values:active_row['result']=P.freeze(active/'result.json',P.encoded(active_row),pins)
        for s in result['stages']:
            if s['status']=='FAILED' and 'result' not in s:s['result']=P.freeze(a.raw/(s['name']+'-failed.json'),P.encoded(s),pins)
        result['withheld_public_pending']=(a.raw/'public-pending').exists()
        if not (a.raw/'public').exists():result['public_receipt']=public('public',False)
        else:result['withheld_public']=True
    finally:save()
    print('backoff-elapsed-probe '+result['status']+' stage='+result['stage'])
    return 0 if result['status']=='COMPLETE' else 1


if __name__=='__main__':
    raise SystemExit(main())
