#!/usr/bin/env python3
"""Prepare Exact37 once, then run one separately accepted 2,048-call attempt."""
import sys
if not __debug__:
    raise SystemExit('assertions required')
sys.dont_write_bytecode = True
import argparse
import datetime as dt
import hashlib
import importlib.util
import json
import os
import re
from pathlib import Path
import subprocess
import time

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
MIB = 1048576
PROFILE = 'selected-accuracy-functional-first-v1'
PHASE_PROFILE = 'selected-accuracy-phase-functional-first-v1'
PREPARED_PHASE_PROFILE = 'selected-accuracy-prepared-phase-functional-first-v1'
STAGES = ('truth','assembly','elf','disassembly')
PREMISES = ('complete_symbol_extent','complete_cfg_and_return','complete_elf_and_source_page',
    'complete_ordinary_rust_caller','immutable_path_and_object_lifetime','scalar_sysv_abi_and_readable_inputs',
    'termination_no_hidden_calls_or_exits','sole_worker_no_reentry_or_concurrency','cet_and_signal_preconditions')


def profile(epoch_phase, prepared=False):
    assert type(prepared) is bool and (not prepared or epoch_phase is not None)
    assert epoch_phase is None or (type(epoch_phase) is str and epoch_phase in ('random','locked'))
    return PREPARED_PHASE_PROFILE if prepared else (PROFILE if epoch_phase is None else PHASE_PROFILE)


def chosen_policy(checker, producer, epoch_phase, prepared=False):
    profile(epoch_phase, prepared)
    return dict(producer.POLICY) if epoch_phase is None else producer.phase_policy(checker, epoch_phase)


def prepare_phase(epoch_phase, prepared=False):
    profile(epoch_phase, prepared)
    return 'prepared-phase-prepare' if prepared else ('accuracy-prepare' if epoch_phase is None else 'phase-prepare')


def preparation_status(epoch_phase, prepared=False):
    profile(epoch_phase, prepared)
    return 'PREPARED_PHASE_PREPARATION_PASS' if prepared else ('ACCURACY_PREPARATION_PASS' if epoch_phase is None else 'PHASE_PREPARATION_PASS')


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def reference(path, digest):
    return dict(path=str(path), sha256=digest)


def qualifications():
    return dict(hardware_status='UNRESOLVED', requested_phase_status='UNRESOLVED',
        native_state_qualified=False, metric_qualified=False, performance_qualified=False,
        matrix_complete=False, executable_retirement=False)


def phase_commands(directory, tools, producer):
    t = {k:str(v) for k,v in tools.items()}
    return (
        [t['python'],'-B',str(ROOT/'evaluation/ordinary-accuracy/truth.py'),'--master',producer.MASTER,
         '--phase','calibration','--trial','1','--workload','late_expensive','--output',str(directory/'truth-data')],
        [t['gcc'],'-O2','-fPIC','-shared','-nostdlib','-fno-builtin','-fno-stack-protector','-fomit-frame-pointer',
         '-fno-tree-vectorize','-fno-tree-slp-vectorize','-fno-asynchronous-unwind-tables','-fno-unwind-tables',
         '-fcf-protection=none','-Wl,-z,now','-Wl,-z,noexecstack',str(ROOT/'tools/rapid-profiler/exact-work/exact_work.S'),
         '-o',str(directory/'exact-final.so')],
        [t['readelf'],'--wide','--file-header','--program-headers','--section-headers','--symbols','--dynamic','--relocs',str(directory/'exact-final.so')],
        [t['objdump'],'-d','-M','intel','--insn-width=16','--disassemble=exact_work_nonempty',str(directory/'exact-final.so')],
    )


def check_truth(run, driver, recipe, directory, checker, producer):
    files, manifest = checker.truth.artifacts(producer.MASTER,'calibration',1,'late_expensive')
    expected = dict(files, **{'manifest.json':checker.truth.canonical(manifest)})
    assert set(expected) == set(producer.MATERIALS)
    assert sorted(p.name for p in (directory/'truth-data').iterdir()) == sorted(expected)
    for name, value in expected.items():
        assert driver.raw_pin(run,recipe,directory/'truth-data'/name,cap=MIB) == value
    return {name:str(directory/'truth-data'/name) for name in producer.MATERIALS}


def geometry_facts(run, driver, recipe, directory, build, fixture, checker, producer, *, epoch_phase=None, prepared=False):
    trusted, candidate = directory/'exact-final.so', directory/'exact-candidate.so'
    whole = driver.raw_pin(run,recipe,trusted,cap=MIB)
    details = fixture.describe(whole)
    selection = dict(details, revision=run.a.revision)
    assert driver.read_json(run,recipe,directory/'selection.json') == selection
    fixture.authenticate(candidate,trusted,details['elf_va'],37,directory/'selection.json',
        run.retained[str(directory/'selection.json')]['sha256'])
    driver.raw_pin(run,recipe,candidate,recipe.pin(whole),MIB)
    build_dir = run.a.build.parent
    disassembly = driver.raw_pin(run,recipe,build_dir/'ordinary-interval-disassembly/stdout',cap=4*MIB)
    shape = run.m['csv'].caller_geometry(disassembly.decode('ascii'))
    assert shape['length'] == 20 and shape['continuation_offset'] == 15 and len(bytes.fromhex(shape['call_bytes'])) == 2
    instructions = [line.split('\t') for line in disassembly.decode('ascii').splitlines()
        if re.match(r'^\s+[0-9a-f]+:',line)]
    heads = [int(parts[0].strip()[:-1],16)-shape['elf_va'] for parts in instructions]
    assert heads == [0,1,4,7,10,13,15,18,19]
    body = b''.join(bytes.fromhex(parts[1]) for parts in instructions)
    assert len(body) == 20 and body[-1:] == b'\xc3'
    shape = dict(shape,head_offsets=heads,code_sha256=driver.sha(body))
    symbols = driver.raw_pin(run,recipe,build_dir/'ordinary-interval-elf/stdout',cap=4*MIB).decode('ascii')
    selected = '\n'.join(line for line in symbols.splitlines() if len(line.split()) == 8 and line.split()[-1] == 'liteinst_csv_call_and_store')
    run.m['module'].caller_symbols(selected, shape)
    table = [dict(function_id=41,operation='exact_work_nonempty',policy='whole',elf_va=details['elf_va'],extent=37,returns=[36])]
    binary = build_dir/'products/ordinary-interval'
    driver.raw_pin(run,recipe,binary,build['products']['ordinary-interval'],128*MIB)
    materials = check_truth(run,driver,recipe,directory,checker,producer)
    args = dict(manifest_bytes=recipe.read(Path(materials['manifest.json']),65536),
        input_bytes=recipe.read(Path(materials['input.csv']),MIB), selected_bytes=recipe.read(Path(materials['selected.txt']),MIB),
        truth_bytes=recipe.read(Path(materials['truth.csv']),MIB), table=tuple(dict(r,returns=tuple(r['returns'])) for r in table),
        caller=dict(extent=20,continuation=15),body_bytes=producer.BODY,abi=producer.ABI,policy=chosen_policy(checker,producer,epoch_phase,prepared),cpus=tuple(run.cpus[:2]))
    checker.authority(**args)
    facts = dict(revision=run.a.revision,profile=profile(epoch_phase, prepared),build=reference(run.a.build,run.a.build_sha),
        selection=selection, trusted=dict(path=str(trusted),**recipe.pin(whole)),
        candidate=dict(path=str(candidate),**recipe.pin(whole)), binary=dict(path=str(binary),**build['products']['ordinary-interval']),
        caller_actual=shape, caller=dict(extent=20,continuation=15),table=table,abi=producer.ABI,
        caller_captures={name:run.retained[str(build_dir/name/'stdout')] for name in ('ordinary-interval-elf','ordinary-interval-disassembly')},
        materials={name:dict(path=path,**run.retained[path]) for name,path in materials.items()},
        coordinate=dict(master=producer.MASTER,phase='calibration',trial=1,workload='late_expensive',records=2048),
        policy=chosen_policy(checker,producer,epoch_phase,prepared), **qualifications())
    if prepared:
        facts['prepared_phase'] = producer.prepared_target(facts['policy'])
    return facts


def prepare(run, driver, recipe, builder, result, build, fixture, checker, producer, *, epoch_phase=None, prepared=False):
    commands = phase_commands(run.raw,run.tools,producer)
    result['commands'] = commands
    for name, argv in zip(STAGES, commands):
        row, out, err = builder.bounded(run,driver,recipe,name,run.raw/name,argv,(20,30,MIB))
        result['preparation_stages'].append(row)
        assert err == b''
        if name == 'truth':
            materials = check_truth(run,driver,recipe,run.raw,checker,producer)
            manifest = recipe.read(Path(materials['manifest.json']),65536)
            assert json.loads(out) == dict(status='INPUTS_PREPARED',**recipe.pin(manifest))
        if name == 'assembly':
            assert out == b''
            whole = driver.raw_pin(run,recipe,run.raw/'exact-final.so',cap=MIB)
            details = fixture.describe(whole)
            builder.copy_product(run,recipe,run.raw/'exact-final.so',run.raw/'exact-candidate.so')
            run.freeze(run.raw/'selection.json',dict(details,revision=run.a.revision))
    result['facts'] = geometry_facts(run,driver,recipe,run.raw,build,fixture,checker,producer,epoch_phase=epoch_phase, prepared=prepared)
    run.freeze(run.raw/'geometry-facts.json',result['facts'])
    result['status'] = preparation_status(epoch_phase, prepared)


def read_preparation(run, driver, recipe, adapter, result, build, fixture, checker, producer, *, epoch_phase=None, prepared=False):
    a = run.a
    previous = driver.read_json(run,recipe,a.preparation,a.preparation_sha,32*MIB)
    directory = a.preparation.parent
    assert previous['status'] == preparation_status(epoch_phase, prepared) and previous['profile'] == profile(epoch_phase, prepared)
    assert previous['phase'] == prepare_phase(epoch_phase, prepared) and previous['revision'] == a.revision
    assert previous['custody_closed'] is True and previous['retention_verified'] is True
    assert previous['source_unchanged'] is True and previous['functional'] == initial_row(epoch_phase, prepared)
    assert previous['cpus'] == run.cpus and previous['hardware'] == a.hardware
    assert previous['reservation_tag'] == a.reservation_tag
    assert all(previous[k] == v for k,v in qualifications().items())
    assert previous['build'] == reference(a.build,a.build_sha) and previous['controls'] == reference(a.controls,a.controls_sha)
    assert previous['build_owner'] == reference(a.build_owner,a.build_owner_sha) and previous['controls_owner'] == reference(a.controls_owner,a.controls_owner_sha)
    env = dict(run.env,TMPDIR=str(directory/'tmp'))
    assert previous['environment'] == env
    assert driver.read_json(run,recipe,directory/'sources-before.json') == run.sources
    assert driver.read_json(run,recipe,directory/'sources-after.json') == run.sources
    for name,pin in previous['retained'].items():
        driver.raw_pin(run,recipe,name,pin,512*MIB)
    assert previous['tool_pins'] == run.tool_pins
    outer = driver.read_json(run,recipe,a.preparation_owner,a.preparation_owner_sha)
    recipe.normal_closed(outer['closed'])
    assert outer['closed']['exit_code'] == 0 and outer['base'] == a.revision
    assert outer['working_source_sha256'] == {} and outer['source_unchanged'] is True and outer['log_archived'] is True
    assert outer['attempts'] == 1 and outer['reserved_cpus'] == run.cpus and outer['hardware'] == a.hardware
    assert outer['wall_limit_seconds'] == 1200 and outer['output_limit_bytes'] == 8*MIB
    options = dict(previous['arguments'], owner=str(a.preparation_owner))
    expected = {k:str(getattr(a,k.replace('-','_'))) for k in adapter.COMMON+adapter.extras(prepare_phase(epoch_phase, prepared))
        if k not in ('phase','owner','raw')}
    expected.update(phase=prepare_phase(epoch_phase, prepared),owner=str(a.preparation_owner),raw=str(directory))
    assert options == expected
    invocation, command = adapter.commands(options,str(run.tools['python']),outer['public_owner']['invocation'][2])
    assert outer['public_owner'] == dict(schema=adapter.SCHEMA,phase=prepare_phase(epoch_phase, prepared),revision=a.revision,
        recipe='evaluation/ordinary-selected-session/accuracy_functional_owner.py',
        recipe_sha256=run.sources[str(HERE/'accuracy_functional_owner.py')]['sha256'],invocation=invocation)
    assert outer['command'] == command == previous['invocation']
    assert outer['env'] == dict(HOME=options['user-home'],CARGO_HOME=options['cargo-home'],
        PATH=options['toolchain']+'/bin:/usr/bin:/bin',PYTHONDONTWRITEBYTECODE='1',PYTHONNOUSERSITE='1',LC_ALL='C')
    log = driver.raw_pin(run,recipe,a.preparation_owner.with_suffix('.log'),cap=8*MIB)
    assert driver.sha(log) == outer['closed']['private_log_sha256'] and json.loads(log) == summary(previous)
    commands = phase_commands(directory,run.tools,producer)
    assert previous['commands'] == [list(command) for command in commands]
    assert [r['name'] for r in previous['preparation_stages']] == list(STAGES)
    assert [r['name'] for r in previous['attempted_stages']] == [n+'-owner' for n in STAGES]
    for name, argv, row, owned in zip(STAGES,commands,previous['preparation_stages'],previous['attempted_stages']):
        d = directory/name
        request = dict(argv=argv,cwd=str(ROOT),env=env,stdout=str(d/'stdout'),stderr=str(d/'stderr'),
            cpu_seconds=20,wall_seconds=30,file_bytes=MIB)
        code,out,err,receipt = driver.closed_stage(run,recipe,d,request,row['closed'])
        assert code == 0 and err == b'' and owned == dict(name=name+'-owner',status='CLOSED_EXIT_0',closed=row['closed'])
        assert row == dict(name=name,request_sha256=run.retained[str(d/'request.json')]['sha256'],
            receipt_sha256=run.retained[str(d/'receipt.json')]['sha256'],closed=row['closed'],
            stdout_sha256=driver.sha(out),stderr_sha256=driver.sha(err))
        parent = directory/(name+'-owner')
        assert driver.read_json(run,recipe,parent/'command.json') == dict(argv=[str(run.tools['python']),'-B',
            str(ROOT/'tools/unwind-oracle/bounded_command.py'),'--request',str(d/'request.json'),'--receipt',str(d/'receipt.json')],
            cwd=str(ROOT),env=env,wall_seconds=55,log_bytes=MIB)
        assert driver.read_json(run,recipe,parent/'closed.json') == row['closed']
        assert driver.raw_pin(run,recipe,parent/'parent.log',cap=MIB) == recipe.read(d/'owner.log',MIB)
        if name == 'assembly':
            assert out == b''
        if name == 'truth':
            manifest = recipe.read(directory/'truth-data/manifest.json',65536)
            assert json.loads(out) == dict(status='INPUTS_PREPARED',**recipe.pin(manifest))
    facts = geometry_facts(run,driver,recipe,directory,build,fixture,checker,producer,epoch_phase=epoch_phase, prepared=prepared)
    assert previous['facts'] == facts == driver.read_json(run,recipe,directory/'geometry-facts.json')
    result['preparation'] = reference(a.preparation,a.preparation_sha)
    return facts


def accept_geometry(value, facts, preparation_sha, revision, *, epoch_phase=None, prepared=False):
    assert set(value) == {'kind','status','scope','revision','preparation_sha256','facts','premises','review','native_state'}
    assert value['kind'] == ('selected-accuracy-prepared-phase-functional-geometry-acceptance-v1' if prepared else
        ('selected-accuracy-functional-geometry-acceptance-v1' if epoch_phase is None
         else 'selected-accuracy-phase-functional-geometry-acceptance-v1'))
    assert value['status'] == 'INDEPENDENTLY_ACCEPTED_FOR_FIXED_SCALAR_EXECUTION'
    assert value['scope'] == profile(epoch_phase, prepared) and value['revision'] == revision and value['preparation_sha256'] == preparation_sha
    assert value['facts'] == facts and value['native_state'] == 'UNRUN_SEPARATE_REQUIRED'
    assert set(value['premises']) == set(PREMISES) and all(value['premises'][k] is True for k in PREMISES)
    assert type(value['review']) is str and 1 <= len(value['review']) <= 16384
    # This explicit external acceptance is an unsafe premise, not a fact derived
    # from equal body bytes, control success, or a self-computed geometry digest.


def input_plan(run, recipe, facts, producer, *, epoch_phase=None, prepared=False):
    pins = dict(run.sources, **run.tool_pins)
    pins.update({item['path']:{k:item[k] for k in ('bytes','sha256')} for item in facts['materials'].values()})
    for key in ('binary','candidate','trusted'):
        item = facts[key]
        pins[item['path']] = {k:item[k] for k in ('bytes','sha256')}
    pins[str(run.a.geometry)] = run.retained[str(run.a.geometry)]
    pins[str(run.a.preparation)] = run.retained[str(run.a.preparation)]
    paths = {name:item['path'] for name,item in facts['materials'].items()}
    plan = dict(profile=profile(epoch_phase, prepared),revision=run.a.revision,attempt=1,cpus=run.cpus,policy=dict(producer.POLICY) if epoch_phase is None else dict(facts['policy']),
        pins=pins,materials=paths,geometry=str(run.a.geometry),facts=facts,
        preparation=str(run.a.preparation),preparation_sha256=run.a.preparation_sha,table=facts['table'],caller=facts['caller'],
        binary=facts['binary']['path'],candidate=facts['candidate']['path'],trusted=facts['trusted']['path'],
        input_sha256=facts['materials']['input.csv']['sha256'])
    plan['argv'] = [plan['binary'],'normal-selected-accuracy-session',plan['candidate'],plan['trusted'],paths['selected.txt'],
        '10','10','520','1','41','exact_work_nonempty',str(facts['table'][0]['elf_va']),'37','whole']
    if epoch_phase is not None:
        assert plan['policy']['phase'] == epoch_phase
        plan['argv'][1] = 'normal-selected-accuracy-phase-session'
        plan['argv'][8:8] = [epoch_phase,str(plan['policy']['delay_ns'])]
    if prepared:
        plan['prepared_phase'] = producer.prepared_target(plan['policy'])
        assert facts['prepared_phase'] == plan['prepared_phase']
        assert all(type(facts['prepared_phase'][k]) is int for k in plan['prepared_phase'])
        plan['argv'][1] = 'normal-selected-accuracy-prepared-phase-session'
        plan['argv'][10:10] = ['1']
    return plan


def delivery(result, size):
    assert result['normal_reaps'] == 1 and result['rescue'] is False and result['cleanup_error'] is None
    assert type(result['child_pid']) is int and result['child_pid'] > 0 and result['child_exit'] == 0
    assert result['sent_bytes'] == size and result['overflow'] is None
    ready, end, prior, sent = result['ready_receipt_ns'], result['eof_close_ns'], 0, 0
    assert type(ready) is int and 0 < ready <= end
    assert type(result['writes']) is list and 0 < len(result['writes']) <= size
    for row in result['writes']:
        assert type(row) is list and len(row) == 4 and all(type(n) is int for n in row)
        before, after, cumulative, count = row
        assert max(ready,prior) <= before <= after <= end and 0 < count <= 8192
        sent += count
        assert cumulative == sent <= size
        prior = after
    assert sent == size


def json_records(value):
    if isinstance(value, bytes):
        return {'bytes_hex':value.hex()}
    if isinstance(value, dict):
        return {k:json_records(v) for k,v in value.items()}
    if isinstance(value, (tuple,list)):
        return [json_records(v) for v in value]
    assert value is None or type(value) in (str,int,bool)
    return value


def functional(run, driver, recipe, result, facts, checker, producer, *, epoch_phase=None, prepared=False):
    accepted = driver.read_json(run,recipe,run.a.geometry,run.a.geometry_sha)
    accept_geometry(accepted,facts,run.a.preparation_sha,run.a.revision,epoch_phase=epoch_phase, prepared=prepared)
    plan = input_plan(run,recipe,facts,producer,epoch_phase=epoch_phase, prepared=prepared)
    args = producer.prepared_phase_arguments(plan,checker) if prepared else (producer.arguments(plan,checker) if epoch_phase is None else producer.phase_arguments(plan,checker))
    run.freeze(run.raw/'plan.json',plan,MIB)
    raw = run.raw/'application'
    argv = [run.tools['python'],'-B',HERE/'accuracy_produce.py','--plan',run.raw/'plan.json',
        '--plan-sha',run.retained[str(run.raw/'plan.json')]['sha256'],'--raw',raw]
    if epoch_phase is not None:
        argv += ['--profile',profile(epoch_phase, prepared)]
    d = run.raw/'functional-io'
    request = run.request(d,argv,cpu=20,wall=30,cap=8*MIB)
    run.plan_bounded('functional',d,request)
    generated = ((raw/'stdout.txt',8*MIB),(raw/'stderr.txt',8*MIB),(raw/'result.json',8*MIB),
        (raw/'overflow.bin',8192),(run.raw/'joined.json',24*MIB))
    assert time.monotonic()+58 < run.deadline
    run.budget.room(recipe.bounded_growth(request,generated,app_files=True))
    result['functional'].update(status='FAILED',attempts=1)
    code,out,err = run.bounded('functional',d,request,generated=generated,app_files=True)
    result['functional']['producer_exit'] = code
    # Keep this reservation active through raw closure, reader and final pin joins.
    run.safe = False
    run_result = driver.read_json(run,recipe,raw/'result.json',cap=8*MIB)
    transcript = driver.raw_pin(run,recipe,raw/'stdout.txt',cap=8*MIB)
    errors = driver.raw_pin(run,recipe,raw/'stderr.txt',cap=8*MIB)
    overflow = driver.raw_pin(run,recipe,raw/'overflow.bin',cap=8192)
    result['functional'].update(result=run_result,raw={name:run.retained[str(raw/name)]
        for name in ('result.json','stdout.txt','stderr.txt','overflow.bin')})
    assert err == b'' and json.loads(out) == run_result
    assert (run_result['profile'],run_result['revision'],run_result['attempt']) == (profile(epoch_phase, prepared),run.a.revision,1)
    assert run_result['stdout_sha256'] == driver.sha(transcript) and run_result['stderr_sha256'] == driver.sha(errors)
    assert run_result['normal_reaps'] == 1 and run_result['rescue'] is False and run_result['cleanup_error'] is None
    if run_result['overflow'] is None:
        assert overflow == b''
    else:
        observed = run_result['overflow']
        assert observed['stream'] in ('out','err') and 0 < len(overflow) <= 8192
        prefix = transcript if observed['stream'] == 'out' else errors
        assert observed == dict(stream=observed['stream'],prefix_bytes=len(prefix),bytes=len(overflow),sha256=driver.sha(overflow))
        assert len(prefix) <= 8*MIB < len(prefix)+len(overflow)
    producer.pins_unchanged(plan['pins'])
    run.unchanged()
    run.safe = True
    if code != 0 or run_result['status'] != 'PASS':
        assert code == 1 and run_result['status'] == 'FAILED'
        run.budget.complete()
        return
    assert run_result['metric_qualified'] is run_result['native_state_qualified'] is run_result['performance_qualified'] is False
    assert run_result['hardware_status'] == run_result['requested_phase_status'] == 'UNRESOLVED'
    delivery(run_result,len(args['input_bytes']))
    checked = checker.check(transcript,errors,**args)
    assert checked['numeric']['rows']['READY'][0]['pid'] == run_result['child_pid']
    assert checked['totals'] == run_result['totals'] and checked['status'] == 'STRUCTURALLY_COMPLETE'
    # Raw streams are retained separately; no byte or endpoint is synthesized.
    joined = {k:v for k,v in checked.items() if k not in ('raw','stderr','wire_rows','numeric')}
    joined['numeric'] = {k:v for k,v in checked['numeric'].items() if k != 'rows'}
    joined['numeric_rows'] = checked['numeric']['rows']
    run.freeze(run.raw/'joined.json',json_records(joined),24*MIB)
    run.unchanged()
    run.budget.complete()
    result['functional'].update(status='PASS',records=2048,totals=checked['totals'],
        joined=reference(run.raw/'joined.json',run.retained[str(run.raw/'joined.json')]['sha256']))
    result['status'] = 'PREPARED_PHASE_FUNCTIONAL_STRUCTURAL_PASS' if prepared else ('ACCURACY_FUNCTIONAL_STRUCTURAL_PASS' if epoch_phase is None else 'PHASE_FUNCTIONAL_STRUCTURAL_PASS')


def initial_row(epoch_phase=None, prepared=False):
    profile(epoch_phase, prepared)
    suffix = ('-prepared-phase-'+epoch_phase) if prepared else ('' if epoch_phase is None else '-phase-'+epoch_phase)
    return dict(name='calibration-trial1-late_expensive-k10-period10-e520'+suffix,status='UNRUN',attempts=0,records=2048)


def summary(result):
    assert result['profile'] in (PROFILE,PHASE_PROFILE,PREPARED_PHASE_PROFILE)
    return dict(status=result['status'],profile=result['profile'],phase=result['phase'],revision=result['revision'],
        functional={k:result['functional'][k] for k in ('name','status','attempts','records')},
        custody_closed=result['custody_closed'],retention_verified=result['retention_verified'],**qualifications())


def main():
    started = time.monotonic()
    # Authenticate the finite adapter before importing any project helper.
    own = Path(__file__).resolve()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--phase',choices=('accuracy-prepare','accuracy-functional','phase-prepare','phase-functional','prepared-phase-prepare','prepared-phase-functional'),required=True)
    for name in ('revision','reservation-tag','hardware'):
        parser.add_argument('--'+name,required=True)
    for name in ('raw','toolchain','user-home','cargo-home','build','build-owner','controls','controls-owner'):
        parser.add_argument('--'+name,type=Path,required=True)
    for name in ('build-sha','build-owner-sha','controls-sha','controls-owner-sha'):
        parser.add_argument('--'+name,required=True)
    for name in ('preparation','preparation-owner','geometry'):
        parser.add_argument('--'+name,type=Path)
    for name in ('preparation-sha','preparation-owner-sha','geometry-sha'):
        parser.add_argument('--'+name)
    parser.add_argument('--epoch-phase',choices=('random','locked'))
    a = parser.parse_args()
    prepared = a.phase in ('prepared-phase-prepare','prepared-phase-functional')
    assert (a.epoch_phase is not None) == (prepared or a.phase in ('phase-prepare','phase-functional'))
    epoch_phase = a.epoch_phase
    extras = (a.preparation,a.preparation_sha,a.preparation_owner,a.preparation_owner_sha,a.geometry,a.geometry_sha)
    assert all(x is not None for x in extras) if a.phase in ('accuracy-functional','phase-functional','prepared-phase-functional') else all(x is None for x in extras)
    for name in ('accuracy_functional.py','accuracy_functional_owner.py','build.py'):
        path = HERE/name
        assert path.is_file() and not path.is_symlink() and path.stat().st_size <= MIB
        assert path.read_bytes() == subprocess.check_output(['/usr/bin/git','-C',ROOT,'show',a.revision+':'+str(path.relative_to(ROOT))],timeout=15)
    builder = load('_accuracy_functional_builder',HERE/'build.py')
    driver = builder.load_driver(a.revision)
    a.profile = driver.WHOLE_PROFILE
    run,recipe,_,leaf,owners,git = driver.bootstrap_context(a,started)
    run.deadline = started+1200
    adapter = load('_accuracy_functional_adapter',HERE/'accuracy_functional_owner.py')
    keys = tuple(k for k in adapter.COMMON+adapter.extras(a.phase) if k != 'owner')
    arguments = {k:str(getattr(a,k.replace('-','_'))) for k in keys}
    invocation = [str(run.tools['python']),'-B',str(own)]+[word for k in keys for word in ('--'+k,arguments[k])]
    assert invocation == [str(run.tools['python']),'-B',sys.argv[0],*sys.argv[1:]]
    result = dict(status='FAILED',profile=profile(epoch_phase, prepared),phase=a.phase,revision=a.revision,arguments=arguments,invocation=invocation,
        build=reference(a.build,a.build_sha),build_owner=reference(a.build_owner,a.build_owner_sha),
        controls=reference(a.controls,a.controls_sha),controls_owner=reference(a.controls_owner,a.controls_owner_sha),
        functional=initial_row(epoch_phase, prepared),preparation_stages=[],environment=run.env,hardware=a.hardware,cpus=run.cpus,
        reservation_tag=a.reservation_tag,load_before=list(os.getloadavg()),source_unchanged=False,**qualifications())
    try:
        build = driver.accept_build(run,recipe,a.build,a.build_sha,a.build_owner,a.build_owner_sha,git)
        assert 'producer' in build and build['revision'] == a.revision and build['hardware'] == a.hardware and build['cpus'] == run.cpus
        assert build['producer']['options']['reservation-tag'] == a.reservation_tag
        driver.replay_controls(run,recipe,leaf,owners,a.controls,a.controls_sha,a.controls_owner,a.controls_owner_sha,build,a.build,git)
        controls = driver.read_json(run,recipe,a.controls,a.controls_sha,32*MIB)
        assert controls['affinity'] == run.cpus and controls['reservation_tag'] == a.reservation_tag
        # Preserve both old exact source-map consumers above; add this new family's
        # independently Git-bound sources only before its first import/use.
        extra = builder.accuracy_source_additions(a.revision)
        assert not set(run.sources)&{str(ROOT/name) for name in extra}
        run.sources.update({str(ROOT/name):pin for name,pin in extra.items()})
        run.unchanged()
        run.freeze(run.raw/'sources-before.json',run.sources,16*MIB)
        fixture = load('_accuracy_exact_fixture',ROOT/'tools/rapid-profiler/normal-work/exact_fixture.py')
        reader_name = 'prepared_phase_output.py' if prepared else ('output.py' if epoch_phase is None else 'phase_output.py')
        checker = load('_accuracy_functional_checker',ROOT/'evaluation/ordinary-accuracy'/reader_name)
        producer = load('_accuracy_functional_producer',HERE/'accuracy_produce.py')
        if a.phase == prepare_phase(epoch_phase, prepared):
            prepare(run,driver,recipe,builder,result,build,fixture,checker,producer,epoch_phase=epoch_phase, prepared=prepared)
        else:
            facts = read_preparation(run,driver,recipe,adapter,result,build,fixture,checker,producer,epoch_phase=epoch_phase, prepared=prepared)
            functional(run,driver,recipe,result,facts,checker,producer,epoch_phase=epoch_phase, prepared=prepared)
        run.unchanged()
        run.freeze(run.raw/'sources-after.json',run.sources,16*MIB)
        assert run.retained[str(run.raw/'sources-before.json')] == run.retained[str(run.raw/'sources-after.json')]
        result['source_unchanged'] = True
    except BaseException as error:
        result.update(status='FAILED',error=type(error).__name__+': '+str(error))
    finally:
        run.budget.stopped()
        result.update(custody_closed=run.safe,retention_verified=False,retained=dict(run.retained),tool_pins=dict(run.tool_pins),
            attempted_stages=run.result['stages'],end_utc=dt.datetime.now(dt.timezone.utc).isoformat(),
            load_after=list(os.getloadavg()),evidence_budget=run.budget.summary())
        try:
            assert run.safe and result['source_unchanged'] is True and not run.budget.exceeded
            run.unchanged()
            result['retention_verified'] = True
        except BaseException as error:
            result.update(status='FAILED',final_error=type(error).__name__+': '+str(error))
        recipe.save(run.raw/'result.json',result,32*MIB)
        print(json.dumps(summary(result),sort_keys=True))
    return 0 if result['status'] in ('ACCURACY_PREPARATION_PASS','ACCURACY_FUNCTIONAL_STRUCTURAL_PASS','PHASE_PREPARATION_PASS','PHASE_FUNCTIONAL_STRUCTURAL_PASS','PREPARED_PHASE_PREPARATION_PASS','PREPARED_PHASE_FUNCTIONAL_STRUCTURAL_PASS') and time.monotonic() < run.deadline else 1


if __name__ == '__main__':
    raise SystemExit(main())
