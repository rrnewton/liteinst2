#!/usr/bin/env python3
"""Ten fixed functional back-off trials; no timer or performance qualification."""
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
PROTOCOL = '8bc5ec049eb2d53561544b46d0cbc50541313a1c14fa2f6aa23ccad5c2719c20'
WIRE = 'b0d27d0aac38e5a834a1c3e98a9bb1a8c24daabcda6d6d901e4e208fd4973b4a'
OWNER_PROTOCOL = '145c1932ab600bf0d482e7c999216c0ec88922fe747a69ecbc4731b0edb5a985'
OWNER_WIRE = '807fc9c3f4e3b8296322bfb6d31c939aabd30f772143792a4bd40064b149a38e'
PREFIX = 'normal::observer::backoff::tests::'
INVENTORY_PREFIX = 'normal::observer::backoff::'
RUST = tuple(PREFIX+n for n in (
    'arguments_cpu_roles_and_complete_task_identity_are_exact',
    'fixed_work_and_guarded_pairs_never_accept_aggregate_only_results',
    'mixed_batches_keep_absolute_ordinals_sample_sequences_and_stack_clock',
    'every_journal_word_and_absolute_prefix_high_bits_are_authenticated',
    'complete_owner_population_refuses_reopen_reorder_missing_or_wrong_history',
    'all_report_payloads_ranges_empty_generations_and_terminal_dispositions_join',
    'owned_schedule_handoff_keeps_original_requested_deadline_and_pending_transfer',
    'bounded_wire_retains_all_rows_empty_reports_zero_and_full_width_ticks'))
OWNER_RUST = tuple('normal::observer::backoff::pending_owner::tests::'+n for n in (
    'phase_requires_exact_held_and_released_totals',
    'copied_snapshot_requires_same_slot_payload_history_and_bank_count',
    'reclaim_requires_old_slot_absence_and_unchanged_copy',
    'boundary_rows_require_actual_next_entry_before_checkpoint',
    'command_phase_refuses_skip_repeat_and_identity_substitution',
    'control_wire_requires_complete_counts_and_three_phase_rows'))
OWNER_CHECKER = (
    'test_complete_k10_and_k1000_and_lossless_phases',
    'test_phase_order_identity_totals_and_refusal_counts',
    'test_reclaim_must_precede_same_block_checkpoint',
    'test_exact_owner_boundary_and_full_sampled_closed_population',
    'test_work_history_reports_and_full_framing_refuse',
    'test_strict_timed_checker_stays_separate',
    'test_raw_clocks_zero_max_and_expected_roles',
    'test_local_import_and_optimized_entrypoints_refuse')
CHECKER = (
    'test_complete_mixed_populations_and_lossless_tables',
    'test_unexercised_epochs_empty_reports_and_k_domains',
    'test_all_fixed_work_population_and_column_mutations',
    'test_sampled_closed_invocations_sequences_and_prefixes',
    'test_history_and_report_identity_counts_and_order',
    'test_stack_continuations_ack_and_batch_boundaries',
    'test_raw_clock_aux_zero_max_and_no_cross_call_inference',
    'test_terminal_census_identity_coverage_and_expected_request',
    'test_framing_canonical_domains_and_all_caps',
    'test_local_import_and_optimized_entrypoints_refuse')
CONTROLS = (
    'test_fixed_catalog_role_argv_and_request_bounds',
    'test_closed_exit_and_signal_failures_continue_without_pass',
    'test_custody_failures_and_changed_catalog_withhold_remainder',
    'test_projection_preserves_all_outcomes_and_raw_counts_without_timing',
    'test_qualified_inputs_return_exact_authenticated_context',
    'test_qualified_inputs_refuse_mutated_context_and_artifact_authority',
    'test_shared_closure_inventory_and_pins_remain_strict',
    'test_local_import_and_optimized_refusal')
STAGES = ('prerequisite', 'checker-controls', 'pending-checker-controls', 'shared-controls',
    'driver-controls', 'rust-controls', 'pending-rust-controls')
FIELDS = ('trial','qualification','k','status','reason','exit','wire_rows','arms','sampled',
    'unsampled','observed_generations','rearmed','sampled_after_closed','app_cpu','controller_cpu','pid','tid','controller_tid',
    'zero_raw_spans','unobserved_generations','function_closed','later_generation_calls','later_generation_samples',
    'stdout_sha256','stderr_sha256','calls_sha256','history_sha256','reports_sha256','result_sha256')
SCOPE = ('Fixed ten-process functional catalog only. No timing, throughput, accuracy, '
    'cheap-off, 520-arm or full-A5 qualification. Both separate pending-owner controls '
    'must pass first; they run no timed Schedule and add no scheduling credit. '
    'Prior strict deadline qualifications remain separate and unchanged.')
IDENTITY = ('PID/TID and singleton roles are authenticated collector self-observations. '
    'bounded_command authenticates exact requests, streams and normal closure but '
    'exports no direct-child PID; no external receipt-to-terminal PID join is claimed.')


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def catalog():
    return [dict(trial=i+1, qualification=i//2+1, k=(10,1000)[i%2]) for i in range(10)]


def owner_catalog():
    return [dict(control=i+1,name='pending-owner-k'+str(k),k=k,hold_ordinal=t)
        for i,(k,t) in enumerate(((10,22),(1000,1006)))]


def owners_complete(rows):
    assert len(rows)==2 and all(all(r[k]==v for k,v in key.items()) for r,key in zip(rows,owner_catalog()))
    assert all(r['status']=='PASS' and r.get('closed') is True for r in rows)


class OwnerPrerequisiteFailed(Exception):
    """Both closed owner controls were retained; their functional gate did not pass."""


def trial_argv(taskset, binary, key, cpus, subject, trusted, elf_va, caller_candidate, caller, owner=False):
    assert len(cpus) == 4 and cpus == sorted(set(cpus))
    assert all(type(c) is int and 0 <= c <= 1023 for c in cpus)
    assert type(owner) is bool and key in (owner_catalog() if owner else catalog())
    assert type(elf_va) is int and 0 < elf_va <= (1<<64)-38
    return list(map(str, (taskset,'--cpu-list',f'{cpus[1]},{cpus[3]}',binary,
        'normal-observer-backoff'+('-pending-owner' if owner else ''),key['k'],cpus[1],cpus[3],subject,trusted,elf_va,37,
        caller_candidate,caller)))


def advance(rows, index):
    assert 0 <= index < 10 and len(rows) == 10
    assert all(all(row[k] == v for k,v in key.items()) for row,key in zip(rows,catalog()))
    assert all(r['status'] in ('PASS','FAILED') and r.get('closed') is True for r in rows[:index])
    assert all(r['status'] == 'UNRUN' for r in rows[index:])
    rows[index]['status'] = 'FAILED'


def outcome(direct, parsed):
    assert type(direct) is int
    if parsed is not None:
        assert parsed['status'] == 'FUNCTIONAL_PASS'
        assert parsed['calls'] == parsed['row_count'] == len(parsed['rows']) == 3072
        assert (parsed['helper_calls'],parsed['instructions'],parsed['batches']) == (1536,614400,128)
    return ('PASS',None) if direct == 0 and parsed is not None else (
        'FAILED', 'CLOSED_CHILD_SIGNAL' if direct < 0 else 'CLOSED_CHILD_NONZERO' if direct else 'FUNCTIONAL_OUTPUT_REFUSAL')


def projection(rows, result_pins, complete):
    assert type(complete) is bool and len(rows) == 10
    assert all(all(r[k] == v for k,v in key.items()) for r,key in zip(rows,catalog()))
    assert all(r['status'] in ('PASS','FAILED','UNRUN') for r in rows)
    assert all(type(k) is int and 1 <= k <= 10 for k in result_pins)
    for pin in result_pins.values():
        assert type(pin['bytes']) is int and pin['bytes'] >= 0
        assert re.fullmatch('[0-9a-f]{64}',pin['sha256'])
    if complete:
        assert set(result_pins) == set(range(1,11))
        assert all(r['status'] != 'UNRUN' and r.get('closed') is True for r in rows)
    result = []
    for r in rows:
        row = {k:r.get(k) for k in FIELDS}
        for name in ('stdout','stderr','calls','history','reports'):
            row[name+'_sha256'] = r.get('files',{}).get(name+'.'+('txt' if name in ('stdout','stderr') else 'csv'),{}).get('sha256')
        row['result_sha256'] = result_pins.get(r['trial'],{}).get('sha256')
        result.append(row)
    return dict(status='COMPLETE_OBSERVATIONS_UNQUALIFIED' if complete else 'INCOMPLETE_UNQUALIFIED',
        trials=result, wire_rows=sum(r.get('wire_rows',0) for r in rows),
        pass_count=sum(r['status']=='PASS' for r in rows), failed_count=sum(r['status']=='FAILED' for r in rows),
        unrun_count=sum(r['status']=='UNRUN' for r in rows))


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--revision',required=True); ap.add_argument('--reservation-tag',required=True)
    for name in ('raw','toolchain','user-home','cargo-home'): ap.add_argument('--'+name,type=Path,required=True)
    a=ap.parse_args(); repo=Path(__file__).resolve().parents[3]
    assert re.fullmatch('[0-9a-f]{40}',a.revision) and re.fullmatch('[a-z0-9-]{1,128}',a.reservation_tag)
    for p in (repo,a.toolchain,a.user_home,a.cargo_home):
        assert p.is_absolute() and p.resolve(strict=True)==p and p.is_dir()
    assert a.raw.is_absolute() and a.raw.is_relative_to(repo/'ignored') and not a.raw.exists()
    assert a.raw.parent.resolve(strict=True)==a.raw.parent
    env=dict(HOME=str(a.user_home),CARGO_HOME=str(a.cargo_home),PATH=str(a.toolchain/'bin')+':/usr/bin:/bin',
        RUSTC=str(a.toolchain/'bin/rustc'),CC=str(Path('/usr/bin/gcc').resolve(strict=True)),CARGO_TARGET_DIR=str(repo/'target'),
        CARGO_INCREMENTAL='0',CARGO_BUILD_JOBS='4',CARGO_NET_OFFLINE='true',CARGO_PROFILE_RELEASE_OPT_LEVEL='3',
        CARGO_PROFILE_RELEASE_DEBUG='0',CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS='true',CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS='true',
        CARGO_TERM_COLOR='never',LC_ALL='C',PYTHONDONTWRITEBYTECODE='1',PYTHONNOUSERSITE='1')
    def git(*args):
        data=subprocess.check_output(['/usr/bin/git','-C',str(repo),*args],env=env,timeout=15)
        assert len(data)<=4*MIB; return data
    assert git('rev-parse','--show-toplevel').decode().strip()==str(repo)
    assert git('rev-parse','HEAD').decode().strip()==a.revision and git('status','--porcelain','--untracked-files=no')==b''
    required={'evaluation/admission/processes.py','tools/unwind-oracle/bounded_command.py','tests/call_tree_truth.rs'}
    required.update('tools/rapid-profiler/'+p for p in ('verify_normal_interval.py','selected-work/check_output.py',
        'selected-work/provenance.py','normal-work/throughput_probe.py','normal-work/test_throughput_probe.py',
        'normal-work/backoff_probe.py','normal-work/test_backoff_probe.py','normal-work/backoff_work.py',
        'normal-work/test_backoff_work.py','normal-work/backoff_pending_owner.py','normal-work/test_backoff_pending_owner.py',
        'normal-work/exact_fixture.py','ordinary-interval/normal/observer/backoff.rs',
        'ordinary-interval/normal/observer/backoff/check.rs','ordinary-interval/normal/observer/backoff/tests.rs'))
    names=git('ls-files','-z','--','src','tests/support','tools/rapid-profiler','Cargo.toml','Cargo.lock','README.md','build.rs',
        ':(glob)**/Cargo.toml',*sorted(required)).decode().rstrip('\0').split('\0')
    assert all(names) and len(names)==len(set(names)) and required.issubset(names)
    before={}
    for n in names:
        data=(repo/n).read_bytes(); assert data==git('show',a.revision+':'+n)
        before[n]=dict(bytes=len(data),sha256=hashlib.sha256(data).hexdigest())
    # No project import precedes complete tracked-source byte authentication.
    P=load('backoff_shared',repo/'tools/rapid-profiler/normal-work/throughput_probe.py')
    pins=P.Pins()
    for n,h in before.items(): pins.retain(repo/n,h)
    tools={n:p.resolve(strict=True) for n,p in (('python',Path(sys.executable)),('gcc',Path('/usr/bin/gcc')),
        ('taskset',Path('/usr/bin/taskset')),('git',Path('/usr/bin/git')),('cargo',a.toolchain/'bin/cargo'),('rustc',a.toolchain/'bin/rustc'))}
    tool_pins={n:pins.retain(p) for n,p in tools.items()}
    processes=P.load('backoff_processes',repo/'evaluation/admission/processes.py')
    prior=P.load('backoff_prior',repo/'tools/rapid-profiler/verify_normal_interval.py')
    census=P.load('backoff_census',repo/'tools/rapid-profiler/selected-work/check_output.py')
    fixture=P.load('backoff_fixture',repo/'tools/rapid-profiler/normal-work/exact_fixture.py')
    checker=P.load('backoff_checker',repo/'tools/rapid-profiler/normal-work/backoff_work.py')
    owner_checker=P.load('backoff_owner_checker',repo/'tools/rapid-profiler/normal-work/backoff_pending_owner.py')
    cpus=sorted(os.sched_getaffinity(0)); assert len(cpus)==4 and all(0<=c<=1023 for c in cpus)
    a.raw.mkdir(mode=0o700); logs_root=repo/'target/evaluation';logs_root.mkdir(parents=True,exist_ok=True)
    assert logs_root.resolve(strict=True)==logs_root
    logs=Path(tempfile.mkdtemp(prefix='backoff-probe-',dir=logs_root))
    result=dict(schema=1,status='FAILED',stage='setup',revision=a.revision,protocol_sha256=PROTOCOL,wire_sha256=WIRE,
        owner_protocol_sha256=OWNER_PROTOCOL,owner_wire_sha256=OWNER_WIRE,scope=SCOPE,
        outer_owner_required=dict(wall_seconds=1200,log_bytes=8*MIB),
        reservation=dict(tag=a.reservation_tag,inherited_cpus=cpus,producer_cpu=cpus[0],app_cpu=cpus[1],
            controller_cpu=cpus[3],spare_cpu=cpus[2],verified=False,authority='External allocator and hard AllowedCPUs must be joined by root; affinity and tag prove no reservation or quiet hardware.'),
        stages=[dict(name=n,status='UNRUN') for n in STAGES],trials=[dict(k,status='UNRUN') for k in catalog()],
        owner_controls=[dict(k,status='UNRUN') for k in owner_catalog()],
        sources=dict(count=len(before),manifest=P.freeze(a.raw/'sources-before.json',P.encoded(before),pins)),tools=tool_pins)
    result['catalog']=P.freeze(a.raw/'catalog.json',P.encoded(catalog()),pins)
    result['owner_catalog']=P.freeze(a.raw/'owner-catalog.json',P.encoded(owner_catalog()),pins)
    os.sched_setaffinity(0,{cpus[0]})
    def save():
        p=a.raw/'result.tmp';p.write_bytes(P.encoded(result));p.replace(a.raw/'result.json')
    def unchanged():
        assert git('rev-parse','HEAD').decode().strip()==a.revision and git('status','--porcelain','--untracked-files=no')==b''
        assert sorted(os.sched_getaffinity(0))==[cpus[0]]; pins.check()
    def observation():
        assert sorted(os.sched_getaffinity(0))==[cpus[0]]
        return dict(utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),affinity=[cpus[0]],
            reservation_tag=a.reservation_tag,load_average=list(os.getloadavg()))
    def retained(path): pins.retain(path);return json.loads(path.read_bytes())
    def prepare(directory,argv):
        directory.mkdir();(directory/'tmp').mkdir();r=P.request(argv,repo,env,directory);P.check_request(r,r)
        P.freeze(directory/'request.json',P.encoded(r),pins)
        command=[str(tools['python']),'-B',str(repo/'tools/unwind-oracle/bounded_command.py'),'--request',str(directory/'request.json'),'--receipt',str(directory/'receipt.json')]
        P.freeze(directory/'command.json',P.encoded(dict(argv=command,env=env,wall_seconds=55,log_bytes=MIB,
            request=pins.values[directory/'request.json'])),pins);return r
    def bounded(directory,r,row):
        unchanged();P.check_request(retained(directory/'request.json'),r)
        command=retained(directory/'command.json');parent=[str(tools['python']),'-B',str(repo/'tools/unwind-oracle/bounded_command.py'),
            '--request',str(directory/'request.json'),'--receipt',str(directory/'receipt.json')]
        assert command==dict(argv=parent,env=env,wall_seconds=55,log_bytes=MIB,request=pins.values[directory/'request.json'])
        row['before']=observation();save();log=logs/(directory.name+'.log')
        closed=processes.run_command(parent,env,log,55,MIB)
        P.freeze(directory/'parent-closed.json',P.encoded(closed),pins);P.freeze(directory/'parent.log',log.read_bytes(),pins)
        row['after']=observation();row['parent_exit']=closed['exit_code']
        row['files']={n:pins.values[directory/n] for n in ('request.json','command.json','parent-closed.json','parent.log')};save()
        P.outer_closed(closed,closed['exit_code']) # No child-file read before normal outer custody.
        fs={n:pins.retain(directory/n) for n in ('request.json','command.json','parent-closed.json','parent.log','receipt.json','stdout.txt','stderr.txt')}
        row['files']=fs;save()
        direct=P.closed_request(closed,retained(directory/'receipt.json'),json.loads((directory/'parent.log').read_bytes()),fs,
            fs['request.json']['sha256'],before['tools/unwind-oracle/bounded_command.py']['sha256'],MIB)
        unchanged();row.update(closed=True,exit=direct);return direct
    def observe(directory,request,row,check,owner=False):
        direct=bounded(directory,request,row);parsed=None
        try:parsed=check((directory/'stdout.txt').read_bytes(),(directory/'stderr.txt').read_bytes(),row['k'],cpus[1],cpus[3])
        except AssertionError:pass # Closed functional refusal, never a PASS or retry.
        row['status'],row['reason']=outcome(direct,parsed)
        if parsed is not None:
            row.update({k:parsed[k] for k in ('arms','sampled','unsampled','observed_generations','rearmed','sampled_after_closed','app_cpu','controller_cpu','pid','tid','controller_tid')})
            row['wire_rows']=len(parsed['rows']);row['terminal']=parsed['terminal'];row['zero_raw_spans']=parsed['zero_raw_spans']
            if not owner:
                row['coverage']=parsed['coverage'];row['unobserved_generations']=len(parsed['coverage']['published_but_unobserved'])
                row.update({k:parsed['coverage'][k] for k in ('function_closed','later_generation_calls','later_generation_samples')})
            tables=[('calls','table'),('history','history_table'),('reports','report_table')]
            if owner:
                assert parsed['hold_ordinal']==row['hold_ordinal']
                row['phases']=parsed['phases'];tables.append(('phases','phase_table'))
            for name,key in tables:row['files'][name+'.csv']=P.freeze(directory/(name+'.csv'),parsed[key],pins)
    active=None;active_row=None
    def public(directory,complete):
        rp={r['trial']:pins.values[p] for r in result['trials'] if (p:=a.raw/('trial-%02d'%r['trial'])/'result.json') in pins.values}
        view=projection(result['trials'],rp,complete); d=a.raw/directory;d.mkdir()
        exports=dict(trials=P.freeze(d/'trials.csv',P.csv_bytes(FIELDS,view['trials']),pins))
        receipt=dict(status=view['status'],outcome=result['status'],revision=a.revision,protocol_sha256=PROTOCOL,wire_sha256=WIRE,
            owner_protocol_sha256=OWNER_PROTOCOL,owner_wire_sha256=OWNER_WIRE,scope=SCOPE,identity_scope=IDENTITY,reservation=result['reservation'],
            failure=result.get('failure'),error_type=result.get('error_type'),
            outer_owner_required=result['outer_owner_required'],hardware=result.get('hardware'),sources=result['sources'],tools=tool_pins,
            catalog=result['catalog'],commands=result.get('commands'),prerequisite=result.get('prerequisite'),artifacts=result.get('artifacts'),
            stages=[dict(name=s['name'],status=s['status'],result=s.get('result')) for s in result['stages']],
            owner_catalog=result['owner_catalog'],owner_commands=result.get('owner_commands'),
            owner_controls=[{k:r.get(k) for k in ('control','name','k','hold_ordinal','status','reason','exit','wire_rows','result')} for r in result['owner_controls']],
            exports=exports,counts={k:view[k] for k in ('wire_rows','pass_count','failed_count','unrun_count')},
            owner_wire_rows=sum(r.get('wire_rows',0) for r in result['owner_controls']),
            normal_outer_owners=sum(r.get('closed') is True for r in result['stages']+result['owner_controls']+result['trials']),
            observations=[dict(trial=r['trial'],before=r.get('before'),after=r.get('after')) for r in result['trials']],
            completion_authority='Require final private result and root-owned normal outer closure/source join; public projection alone grants neither completion nor reservation.')
        pin=P.freeze(d/'receipt.json',P.encoded(receipt),pins)
        return pin
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
        q=P.qualified_inputs(repo,qualified,a.revision,env,cpus,before,tools,pins,prior,census,fixture,INVENTORY_PREFIX,RUST+OWNER_RUST)
        result['artifacts'],result['prerequisite']=q['artifacts'],q['prerequisite']
        result['hardware']={k:v for k,v in q['old']['hardware'].items() if k in ('description','vendor','family','model','stepping')}
        unchanged();row['status']='PASS';row['result']=P.freeze(a.raw/'prerequisite-result.json',P.encoded(row),pins);save()
        work=repo/'tools/rapid-profiler/normal-work'
        for name,source,methods in (('checker-controls',work/'test_backoff_work.py',CHECKER),
                ('pending-checker-controls',work/'test_backoff_pending_owner.py',OWNER_CHECKER),
                ('shared-controls',work/'test_throughput_probe.py',P.CONTROLS),('driver-controls',work/'test_backoff_probe.py',CONTROLS)):
            row=result['stages'][STAGES.index(name)];row['status']='FAILED';result['stage']=name;save()
            P.python_census(source.read_bytes(),'Controls',methods);d=a.raw/name;r=prepare(d,[tools['python'],'-B',source])
            assert bounded(d,r,row)==0;P.python_controls((d/'stdout.txt').read_bytes(),(d/'stderr.txt').read_bytes(),methods)
            unchanged();row['status']='PASS';row['result']=P.freeze(d/'result.json',P.encoded(row),pins);save()
        for name,methods in (('rust-controls',RUST),('pending-rust-controls',OWNER_RUST)):
            row=result['stages'][STAGES.index(name)];row['status']='FAILED';result['stage']=name;save();d=a.raw/name
            r=prepare(d,[q['test_binary'],*methods,'--exact','--test-threads=1']);assert bounded(d,r,row)==0
            census.controls((d/'stdout.txt').read_bytes(),(d/'stderr.txt').read_bytes(),methods,q['inventory'])
            unchanged();row['status']='PASS';row['result']=P.freeze(d/'result.json',P.encoded(row),pins);save()
        plans=[]
        for key in catalog():
            argv=trial_argv(tools['taskset'],q['binary'],key,cpus,q['subject'],q['trusted'],q['details']['elf_va'],q['caller_candidate'],q['caller'])
            d=a.raw/('trial-%02d'%key['trial']);r=prepare(d,argv);plans.append(dict(key,request=r,request_digest=pins.values[d/'request.json']))
        result['commands']=P.freeze(a.raw/'commands.json',P.encoded(plans),pins)
        owner_plans=[]
        for key in owner_catalog():
            argv=trial_argv(tools['taskset'],q['binary'],key,cpus,q['subject'],q['trusted'],q['details']['elf_va'],q['caller_candidate'],q['caller'],True)
            d=a.raw/key['name'];r=prepare(d,argv);owner_plans.append(dict(key,request=r,request_digest=pins.values[d/'request.json']))
        result['owner_commands']=P.freeze(a.raw/'owner-commands.json',P.encoded(owner_plans),pins)
        for index,plan in enumerate(owner_plans):
            unchanged();assert retained(a.raw/'owner-catalog.json')==owner_catalog() and retained(a.raw/'owner-commands.json')==owner_plans
            assert fixture.authenticate(q['subject'],q['trusted'],q['details']['elf_va'],37,q['selection'],pins.values[q['selection']]['sha256'])==q['selected']
            assert all(r['status'] in ('PASS','FAILED') and r.get('closed') is True for r in result['owner_controls'][:index])
            row=result['owner_controls'][index];assert row['status']=='UNRUN';row['status']='FAILED'
            active=a.raw/row['name'];active_row=row;result['stage']=row['name'];save()
            observe(active,plan['request'],row,owner_checker.check,True)
            unchanged();row['result']=P.freeze(active/'result.json',P.encoded(row),pins);active=active_row=None;save()
        try:owners_complete(result['owner_controls'])
        except AssertionError as error:raise OwnerPrerequisiteFailed() from error
        for index,plan in enumerate(plans):
            unchanged();assert retained(a.raw/'catalog.json')==catalog() and retained(a.raw/'commands.json')==plans
            assert fixture.authenticate(q['subject'],q['trusted'],q['details']['elf_va'],37,q['selection'],pins.values[q['selection']]['sha256'])==q['selected']
            advance(result['trials'],index);row=result['trials'][index];active=a.raw/('trial-%02d'%row['trial']);active_row=row;result['stage']=active.name;save()
            observe(active,plan['request'],row,checker.check)
            unchanged();P.freeze(active/'result.json',P.encoded(row),pins);active=active_row=None;save()
        unchanged();result['sources']['after']=P.freeze(a.raw/'sources-after.json',P.encoded({n:P.digest(repo/n) for n in names}),pins);unchanged()
        result['status']='FUNCTIONAL_COMPLETE_UNQUALIFIED' if all(r['status']=='PASS' for r in result['trials']) else 'COMPLETE_WITH_FAILURES'
        result['stage']='complete';pin=public('public-pending',True);unchanged()
        assert not (a.raw/'public').exists();(a.raw/'public-pending').rename(a.raw/'public')
        result['public_receipt']=pin
    except BaseException as error:
        result['status']='FAILED';result['error_type']=type(error).__name__
        result['failure']=P.freeze(a.raw/'failure.txt',traceback.format_exc().encode('utf-8'),pins)
        reason='OWNER_PREREQUISITE_FAILED' if isinstance(error,OwnerPrerequisiteFailed) else 'AUTHORITY_CUSTODY_OR_PREREQUISITE_FAILURE'
        for r in result['trials']+result['owner_controls']:
            if r['status']=='UNRUN':r['reason']=reason
        if active is not None:
            active_row.update(status='FAILED',reason='AUTHORITY_OR_CUSTODY_FAILURE')
            if active/'result.json' not in pins.values:
                active_row['result']=P.freeze(active/'result.json',P.encoded(active_row),pins)
        for s in result['stages']:
            if s['status']=='FAILED' and 'result' not in s:
                s['result']=P.freeze(a.raw/(s['name']+'-failed.json'),P.encoded(s),pins)
        result['withheld_public_pending']=(a.raw/'public-pending').exists()
        if not (a.raw/'public').exists():result['public_receipt']=public('public',False)
        else:result['withheld_public']=True
    finally:save()
    print('backoff-probe '+result['status']+' stage='+result['stage'])
    return 0 if result['status']=='FUNCTIONAL_COMPLETE_UNQUALIFIED' else 1


if __name__=='__main__':
    raise SystemExit(main())
