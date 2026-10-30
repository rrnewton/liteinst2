#!/usr/bin/env python3
"""Consume closed selected-leaf builds; run exact controls or eight scalar cells.

No compiler, native-state oracle or new process owner is implemented here.
An external owner supplies exactly three reserved CPUs and the old 7200s bound.
"""
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
from pathlib import Path
import re
import subprocess
import time

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
MIB = 1048576
PROFILE = 'selected-session-functional-v1'
WHOLE_PROFILE = 'selected-session-whole-functional-v1'
PROFILES = (PROFILE, WHOLE_PROFILE)
RECIPE = 'evaluation/ordinary-module-session/reproduce.py'
RECIPE_SHA = '4389493950775ca1c494bf7e28ff8326cbd61d2fbbda0ef53af953a4ff24f659'
BUILD_ROOTS = ('.cargo', 'src', 'crates', 'tools', 'Cargo.toml', 'Cargo.lock', 'build.rs',
               'evaluation/ordinary-selected-session/leaves.c',
               'evaluation/ordinary-selected-session/reference.c')
BUILD_FILES = ('leaves.so', 'leaves-stripped.so', 'reference', 'ordinary-interval')
BUILD_STAGES = ('dso-unstripped', 'dso-stripped', 'original-reference', 'application-release') + tuple(
    name + '-elf' for name in BUILD_FILES) + tuple(name + '-disassembly' for name in BUILD_FILES)
DSO_FLAGS = ('-O2', '-std=c11', '-Wall', '-Wextra', '-Werror', '-fPIC', '-shared', '-nostdlib',
             '-fno-stack-protector', '-fno-asynchronous-unwind-tables', '-fno-unwind-tables',
             '-fno-tree-vectorize', '-fno-tree-slp-vectorize', '-fno-builtin', '-fno-ipa-icf',
             '-fno-toplevel-reorder', '-fno-jump-tables', '-fcf-protection=none',
             '-Wl,--build-id=none,-z,now,-z,noexecstack')
REFERENCE_FLAGS = ('-O2', '-std=c11', '-Wall', '-Wextra', '-Werror', '-fno-stack-protector',
                   '-fno-optimize-sibling-calls', '-fcf-protection=none')
SCOPE = ('Fixed compiled scalar execution and complete numeric history only. '
         'Build and execution revisions are distinct. No performance, strict 2ms fix, '
         'architectural-state, full old campaign or arbitrary ABI qualification.')


def load(name, path):
    spec = importlib.util.spec_from_file_location('_selected_driver_' + name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def sha(data):
    return hashlib.sha256(data).hexdigest()


def selected_profile(arguments):
    # Public products/tests have no profile selector; the historical default is
    # exact. A campaign's profile never comes from observed output or fallback.
    value = getattr(arguments, 'profile', PROFILE)
    assert type(value) is str and value in PROFILES
    return value


def profile_record(record, expected, field='profile'):
    assert type(expected) is str and expected in PROFILES
    assert type(record[field]) is str and record[field] == expected, 'selected profile mismatch'


def revision(value):
    assert type(value) is str and re.fullmatch('[0-9a-f]{40}', value)
    return value


def read_json(run, recipe, path, digest=None, cap=16*MIB):
    path = Path(path)
    assert path.is_absolute() and path.resolve(strict=True) == path
    data = recipe.read(path, cap)
    if digest is not None:
        assert re.fullmatch('[0-9a-f]{64}', digest) and sha(data) == digest
    run.remember(path, recipe.pin(data), cap)
    return json.loads(data)


def raw_pin(run, recipe, path, expected=None, cap=128*MIB):
    path = Path(path)
    assert path.is_absolute() and path.resolve(strict=True) == path
    data = recipe.read(path, cap)
    run.remember(path, expected, cap)
    return data


def closed_stage(run, recipe, directory, request, closed, *, suffix=''):
    """Authenticate the actual old bounded-helper files; never synthesize closure."""
    directory = Path(directory)
    actual = read_json(run, recipe, directory/'request.json')
    assert actual == request
    assert set(request) == {'argv','cwd','env','stdout','stderr','cpu_seconds','wall_seconds','file_bytes'}
    assert request['cwd'] == str(ROOT)
    assert request['stdout'] == str(directory/('stdout'+suffix))
    assert request['stderr'] == str(directory/('stderr'+suffix))
    observed = read_json(run, recipe, directory/'closed.json')
    assert observed == closed
    receipt = read_json(run, recipe, directory/'receipt.json')
    out = raw_pin(run, recipe, directory/('stdout'+suffix), cap=request['file_bytes'])
    err = raw_pin(run, recipe, directory/('stderr'+suffix), cap=request['file_bytes'])
    code = recipe.bounded_join(receipt, closed, run.retained[str(directory/'request.json')],
                              run.sources[str(ROOT/'tools/unwind-oracle/bounded_command.py')],
                              recipe.pin(out), recipe.pin(err))
    parent = raw_pin(run, recipe, directory/'owner.log', cap=MIB)
    assert sha(parent) == closed['private_log_sha256']
    assert json.loads(parent) == dict(exit=code, wall_timeout=False, absence_proof='ECHILD',
                                      descendants=0, success=code == 0)
    return code, out, err, receipt


def build_argv(tools, products):
    t = lambda name: tools[name]['path']
    commands = [
        [t('gcc'), *DSO_FLAGS, str(HERE/'leaves.c'), '-o', str(products/'leaves.so')],
        [t('strip'), '--strip-all', '-o', str(products/'leaves-stripped.so'), str(products/'leaves.so')],
        [t('gcc'), *REFERENCE_FLAGS, str(HERE/'reference.c'), '-ldl', '-o', str(products/'reference')],
        [t('cargo'), 'build', '--release', '-p', 'rapid-profiler', '--bin', 'ordinary-interval',
         '--locked', '--offline', '--jobs', '4', '--message-format=json-render-diagnostics']]
    for name in BUILD_FILES:
        commands.append([t('readelf'), '--wide', '--file-header', '--program-headers',
                         '--section-headers', '--symbols', str(products/name)])
    for name, symbol in zip(BUILD_FILES, (None, None, 'invoke', 'liteinst_csv_call_and_store')):
        command = [t('objdump'), '-d', '-M', 'intel', '--insn-width=16']
        if symbol is not None:
            command.append('--disassemble='+symbol)
        commands.append(command + [str(products/name)])
    return commands


def source_build_join(build, current, git):
    """All old build inputs stay pinned; compiled source membership is exact."""
    rev = revision(build['revision'])
    paths = git('ls-tree', '-r', '--name-only', '-z', rev, '--', '.cargo', 'src', 'crates',
                'tools', 'Cargo.toml', 'Cargo.lock', 'build.rs', 'evaluation/ordinary-selected-session')
    expected = paths.decode().rstrip('\0').split('\0')
    assert expected and len(expected) == len(set(expected)) and set(expected) == set(build['sources'])
    for name, digest in build['sources'].items():
        assert sha(git('show', rev+':'+name)) == digest
        assert current[str(ROOT/name)]['sha256'] == digest
    before = git('ls-tree', '-r', '--name-only', '-z', rev, '--', *BUILD_ROOTS)
    after = git('ls-files', '-z', '--', *BUILD_ROOTS)
    assert set(before.split(b'\0')) == set(after.split(b'\0'))


PUBLIC_BUILD_RECIPE = 'evaluation/ordinary-selected-session/build.py'
PUBLIC_BUILD_SCHEMA = 'selected-session-public-build-v1'
PUBLIC_BUILD_OPTIONS = ('phase','revision','reservation-tag','raw','toolchain','user-home','cargo-home','hardware')
PUBLIC_TEST_OPTIONS = ('build','build-sha','build-owner','build-owner-sha')


def public_build_invocation(producer, phase, rev, directory, python, hardware, previous=None):
    """Exact fresh schema, never a fallback for either historical builder."""
    assert set(producer) == {'schema','phase','revision','recipe','recipe_sha256','invocation','options',
                             'source_before','source_after'}
    assert producer['schema'] == PUBLIC_BUILD_SCHEMA and producer['recipe'] == PUBLIC_BUILD_RECIPE
    assert phase in ('products','tests') and producer['phase'] == phase and producer['revision'] == revision(rev)
    assert type(producer['recipe_sha256']) is str and re.fullmatch('[0-9a-f]{64}',producer['recipe_sha256'])
    options=producer['options']; keys=PUBLIC_BUILD_OPTIONS+(PUBLIC_TEST_OPTIONS if phase=='tests' else ())
    assert set(options)==set(keys) and all(type(v) is str and v for v in options.values())
    assert options['phase']==phase and options['revision']==rev and options['raw']==str(directory)
    assert options['hardware']==hardware and 1<=len(hardware)<=160 and hardware.isascii() and all(32<=ord(c)<127 for c in hardware)
    assert re.fullmatch('[A-Za-z0-9_.-]{1,128}',options['reservation-tag'])
    for key in ('raw','toolchain','user-home','cargo-home'):
        assert Path(options[key]).is_absolute()
    if phase=='tests':
        assert previous is not None and options['build']==previous['path'] and options['build-sha']==previous['sha256']
        assert Path(options['build']).is_absolute() and Path(options['build-owner']).is_absolute()
        assert re.fullmatch('[0-9a-f]{64}',options['build-owner-sha'])
    else: assert previous is None
    argv=producer['invocation']
    assert type(argv) is list and len(argv)==3+2*len(keys)
    assert argv[:2]==[python,'-B'] and argv[2] in (PUBLIC_BUILD_RECIPE,str(ROOT/PUBLIC_BUILD_RECIPE))
    expected=argv[:3]+[word for key in keys for word in ('--'+key,options[key])]
    assert argv==expected
    for label,name in (('source_before','sources-before.json'),('source_after','sources-after.json')):
        pin=producer[label]
        assert set(pin)=={'path','bytes','sha256'} and pin['path']==str(directory/name)
        assert type(pin['bytes']) is int and 0<pin['bytes']<=16*MIB
        assert type(pin['sha256']) is str and re.fullmatch('[0-9a-f]{64}',pin['sha256'])
    return argv


def fresh_build_producer(run,recipe,record,owner,directory,phase,git,previous_build=None):
    producer=record['producer']; rev=revision(record['revision'])
    tools=record['tools'] if phase=='products' else previous_build['tools']
    hardware=record['hardware'] if phase=='products' else previous_build['hardware']
    previous=record['original_build_receipt'] if phase=='tests' else None
    expected=public_build_invocation(producer,phase,rev,directory,tools['python']['path'],hardware,previous)
    assert owner['command']==expected and len(owner['reserved_cpus'])==3
    p=ROOT/PUBLIC_BUILD_RECIPE
    raw=raw_pin(run,recipe,p,cap=MIB)
    assert sha(raw)==producer['recipe_sha256']==sha(git('show',rev+':'+PUBLIC_BUILD_RECIPE))
    assert run.sources[str(p)]==recipe.pin(raw)
    for label in ('source_before','source_after'):
        pin=producer[label]; path=Path(pin['path'])
        raw_pin(run,recipe,path,{key:pin[key] for key in ('bytes','sha256')},16*MIB)
        assert read_json(run,recipe,path,cap=16*MIB)==run.sources
    options=producer['options']
    for key in ('toolchain','user-home','cargo-home'):
        path=Path(options[key]);assert path.resolve(strict=True)==path and path.is_dir()
    env=record['environment'] if phase=='products' else previous_build['environment']
    assert env['HOME']==options['user-home'] and env['CARGO_HOME']==options['cargo-home']
    for key in ('cargo','rustc','rustdoc'):
        assert str((Path(options['toolchain'])/'bin'/key).resolve(strict=True))==tools[key]['path']
    if phase=='tests':
        assert run.retained[options['build-owner']]['sha256']==options['build-owner-sha']


def accept_build(run, recipe, path, digest, owner_path, owner_digest, git):
    build = read_json(run, recipe, path, digest)
    directory = Path(path).parent
    assert build['status'] == 'BUILD_AND_ELF_CAPTURE_PASS'
    assert build['source_unchanged'] is True and type(build['native_dispatches']) is int and build['native_dispatches'] == 0
    assert tuple(row['name'] for row in build['stages']) == BUILD_STAGES
    assert set(build['products']) == set(BUILD_FILES)
    source_build_join(build, run.sources, git)
    frozen = read_json(run, recipe, directory/'frozen.json')
    assert frozen == {key: ([] if key == 'stages' else build[key]) for key in frozen}
    frozen_keys = {'revision','hardware','sources','tools','versions','environment','cpus','load_before','build_plan_sha256','stages'}
    assert set(frozen) == frozen_keys | ({'producer'} if 'producer' in build else set())
    assert read_json(run, recipe, directory/'closed-stages.json') == build['stages']
    raw_pin(run, recipe, directory/'consumed-build-plan.json', cap=MIB)
    assert run.retained[str(directory/'consumed-build-plan.json')]['sha256'] == build['build_plan_sha256']
    for name in set(build['tools']) & set(run.tools):
        assert build['tools'][name]['path']==str(run.tools[name])
    for item in build['tools'].values():
        p = Path(item['path']); value = {key:item[key] for key in ('bytes','sha256')}
        raw_pin(run, recipe, p, value, 512*MIB)
        if str(p) in run.tool_pins: assert run.tool_pins[str(p)] == value
        else: run.tool_pins[str(p)] = value
    env = build['environment']
    for key, value in {'CARGO_PROFILE_RELEASE_OPT_LEVEL':'3','CARGO_PROFILE_RELEASE_DEBUG':'0',
                       'CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS':'true','CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS':'true'}.items():
        assert env[key] == value
    owner = read_json(run, recipe, owner_path, owner_digest)
    recipe.normal_closed(owner['closed'])
    assert owner['closed']['exit_code'] == 0 and owner['base'] == build['revision']
    assert owner['working_source_sha256'] == {} and owner['source_unchanged'] is True
    assert owner['reserved_cpus'] == build['cpus'] and owner['attempts'] == 1
    if 'producer' in build:
        fresh_build_producer(run, recipe, build, owner, directory, 'products', git)
    else:
        assert owner['command'] == [build['tools']['python']['path'], '-B', str((directory/'build.py').relative_to(ROOT))]
        raw_pin(run, recipe, directory/'build.py', cap=MIB)
        assert run.retained[str(directory/'build.py')]['sha256']=='56a63bb5c7bf2b9450a67234a4fcbd861b7b46e2e2aac51f9cf5bfe83e7c6d60'
    owner_log = Path(owner_path).with_suffix('.log')
    outer_log=raw_pin(run, recipe, owner_log, {'bytes':owner_log.stat().st_size,'sha256':owner['closed']['private_log_sha256']}, 8*MIB)
    assert json.loads(outer_log)==dict(status=build['status'],revision=build['revision'],products=build['products'],native_dispatches=0)
    commands = build_argv(build['tools'], directory/'products')
    for index, (row, argv) in enumerate(zip(build['stages'], commands)):
        d = directory/row['name']
        limits = (120,180,128*MIB) if index < 4 else (20,30,4*MIB)
        request = dict(argv=argv,cwd=str(ROOT),env=env,stdout=str(d/'stdout'),stderr=str(d/'stderr'),
                       cpu_seconds=limits[0],wall_seconds=limits[1],file_bytes=limits[2])
        code,out,err,receipt = closed_stage(run,recipe,d,request,row['closed'])
        assert code == 0 and run.retained[str(d/'request.json')]['sha256'] == row['request_sha256']
        assert run.retained[str(d/'receipt.json')]['sha256'] == row['receipt_sha256']
        assert sha(out) == row['stdout_sha256'] and sha(err) == row['stderr_sha256']
        if index != 3: assert err == b''
        if index < 3: assert out == b''
    for name,value in build['products'].items(): raw_pin(run,recipe,directory/'products'/name,value)
    cargo = recipe.read(directory/'application-release/stdout',128*MIB)
    _, product = run.m['native'].artifact(cargo,'ordinary-interval','ordinary-interval/main.rs','bin',False)
    assert read_json(run,recipe,directory/'compiler-artifact.json') == product
    # The retained private application copy is authoritative for dispatch. Its
    # digest was captured while the original Cargo product still matched it.
    return build


def initial_rows():
    return [dict(leg=leg,index=i,variant=variant,k=k,n=2,epochs=520,
                 name=f'{leg}-{variant}-k{k}',status='UNRUN',attempts=0,attempt_limit=1,retries=0,
                 records=12 if k == 10 else 1001,calls=24 if k == 10 else 2002)
            for leg in ('reference','installed')
            for i,(variant,k) in enumerate((('unstripped',10),('unstripped',1000),('stripped',10),('stripped',1000)))]


def symbol_suffix(raw):
    """All bytes from the first exact symbol header to EOF; never filter rows."""
    assert type(raw) is bytes and raw.startswith(b'ELF Header:\n')
    marker = b"\nSymbol table '.dynsym' contains "
    assert raw.count(marker) == 1
    start = raw.index(marker) + 1
    return raw[start:]


def accept_geometry(run,recipe,new,build,build_path,path,digest):
    accepted = read_json(run,recipe,path,digest)
    assert accepted['kind'] == 'selected-session-geometry-acceptance-v1'
    assert accepted['build_result_sha256'] == run.retained[str(build_path)]['sha256']
    assert accepted['build_revision'] == build['revision'] and accepted['products'] == build['products']
    assert accepted['status'] == 'INDEPENDENTLY_ACCEPTED_FOR_FIXED_SCALAR_EXECUTION'
    profile_record(accepted, selected_profile(run.a), 'scope')
    assert accepted['native_state'] == 'UNRUN_SEPARATE_REQUIRED'
    required = ('complete_symbol_extents','complete_cfg_and_all_returns','complete_elf_and_source_pages',
                'strip_preserves_selected_bytes_and_pages','ordinary_rust_and_reference_callers',
                'immutable_path_and_object_lifetime','scalar_sysv_abi_and_readable_inputs',
                'termination_no_hidden_calls_exits_or_concurrency','cet_and_signal_preconditions')
    assert set(accepted['premises']) == set(required) and all(accepted['premises'][key] is True for key in required)
    assert type(accepted['review']) is str and accepted['review']
    assert accepted['fact_pins']
    for name,pin in accepted['fact_pins'].items(): raw_pin(run,recipe,name,pin)
    d=Path(build_path).parent
    definitions=new['geometry'].preserved(symbol_suffix(recipe.read(d/'leaves.so-elf/stdout',4*MIB)),
                                           symbol_suffix(recipe.read(d/'leaves-stripped.so-elf/stdout',4*MIB)))
    table=tuple(dict(row,returns=tuple(row['returns'])) for row in accepted['table'])
    new['output'].geometry(table,accepted['caller'],tuple(run.cpus[:2]),profile=selected_profile(run.a))
    assert len(definitions)==len(table)==2
    for definition,row in zip(definitions,table):
        assert (definition['name'],definition['elf_va'],definition['extent']) == (row['operation'],row['elf_va'],row['extent'])
    pages={address//4096 for row in table for address in (row['elf_va'],row['elf_va']+row['extent']-1)}
    assert 1<=len(pages)<=2 and accepted['source_pages']==sorted(pages)
    return table,accepted['caller']


def write_blob(run,recipe,path,data):
    assert type(data) is bytes and len(data)<=MIB
    run.budget.charge(str(path),len(data))
    with path.open('xb') as stream: stream.write(data)
    run.remember(path,recipe.pin(data),MIB)


def freeze_cells(run,recipe,new,build,build_path,table,caller):
    plans=run.raw/'plans';plans.mkdir()
    source=Path(build_path).parent/'products'
    copies={}
    for variant,name in (('unstripped','leaves.so'),('stripped','leaves-stripped.so')):
        paths={}
        data=recipe.read(source/name,MIB)
        original_pin=run.retained[str(source/name)]
        assert recipe.pin(data)==original_pin==build['products'][name]
        identities={( (source/name).stat().st_dev,(source/name).stat().st_ino)}
        for role in ('candidate','trusted','reference'):
            path=run.raw/(variant+'-'+role+'.so');write_blob(run,recipe,path,data)
            assert run.retained[str(path)]==original_pin
            identity=(path.stat().st_dev,path.stat().st_ino)
            assert identity not in identities;identities.add(identity);paths[role]=str(path)
        copies[variant]=paths
    for k in (10,1000):
        write_blob(run,recipe,plans/f'k{k}.csv',b''.join(record+b'\n' for record in new['oracle'].records(k)))
        write_blob(run,recipe,plans/f'k{k}.txt',new['oracle'].table(k))
    for row in run.result['cells']:
        k=row['k'];copy=copies[row['variant']]
        plan=dict(row,profile=selected_profile(run.a),revision=run.a.revision,cpus=run.cpus,table=list(table),caller=caller,
                  binary=str(source/'ordinary-interval'),reference_binary=str(source/'reference'),
                  candidate=copy['candidate'],trusted=copy['trusted'],reference_dso=copy['reference'],
                  stdin_file=str(plans/f'k{k}.csv'),expected_table=str(plans/f'k{k}.txt'),taskset=str(run.tools['taskset']))
        plan['data_sha256']=run.retained[plan['stdin_file']]['sha256']
        plan['table_sha256']=run.retained[plan['expected_table']]['sha256']
        if row['leg']=='installed':
            argv=[plan['binary'],'normal-selected-session',plan['candidate'],plan['trusted'],plan['expected_table'],str(k),'520','2']
            for leaf in table: argv += [str(leaf['function_id']),leaf['operation'],str(leaf['elf_va']),str(leaf['extent']),leaf['policy']]
        else: argv=[plan['taskset'],'--cpu-list',str(run.cpus[1]),plan['reference_binary'],plan['reference_dso'],str(row['records'])]
        plan['argv']=argv
        plan['pins']={path:pin['sha256'] for path,pin in (run.sources|run.tool_pins|run.retained).items()}
        new['producer'].plan_arguments(plan,new['oracle'],new['output'])
        plan_path=plans/(row['name']+'.json');run.freeze(plan_path,plan)
        directory=run.raw/(row['name']+'-io');child=run.raw/(row['name']+'-child')
        command=[run.tools['python'],'-B',HERE/'produce.py','--plan',plan_path,
                 '--plan-sha',run.retained[str(plan_path)]['sha256'],'--raw',child]
        request=run.request(directory,command);run.plan_bounded(row['name']+'-owner',directory,request)
        row.update(plan=str(plan_path),directory=str(directory),child=str(child),request=request)
    run.freeze(run.raw/'frozen-cells.json',run.result['cells'])


def execute_cells(run,recipe,new):
    cells=run.result['cells']
    assert len(cells)==8 and all(row['status']=='UNRUN' and row['attempts']==0 for row in cells)
    for row in cells:
        if row['leg']=='installed' and any(r['status']!='PASS' for r in cells[:4]): break
        run.unchanged();recipe.bounded_ready(run,row['request'],app_files=True)
        assert row['attempts']==0;row.update(status='FAILED',attempts=1)
        code,out,err=run.bounded(row['name']+'-owner',Path(row['directory']),row['request'],app_files=True)
        plan=json.loads(recipe.read(Path(row['plan']),MIB))
        result=new['closure'].complete_closed_cell(run,recipe,new['producer'],new['oracle'],new['output'],
                    plan,Path(row['child']),code,out,err)
        row.update(status=result['status'],child_exit=result['result']['child_exit'],
                   normal_reaps=result['result']['normal_reaps'],error=result['error'])
        if result['status']=='PASS':
            observed=result['observations'];row['values_sha256']=sha(recipe.canonical(observed['values']))
            if row['leg']=='installed': row['totals']=observed['totals']
        run.unchanged();run.freeze(run.raw/(row['name']+'-outcome.json'),row)
    return all(row['status']=='PASS' for row in cells)


SELECTED_PREFIX = 'normal::selected_session_controls::'
SELECTED_RUST = tuple(SELECTED_PREFIX + name for name in (
    'labels_are_fixed_copyable_csv_safe_identifiers',
    'labels_refuse_framing_injection_non_ascii_and_excess',
    'frozen_rows_keep_exact_raw_csv_bytes_and_full_u64_values',
    'returned_row_owns_its_frozen_inputs_after_table_retirement',
    'table_framing_requires_exact_version_spaces_lf_and_terminal_end',
    'all_cardinalities_preserve_exact_record_and_call_caps',
    'dimensions_reject_zero_overflow_and_disagreement',
    'function_rows_are_complete_unique_and_ordered',
    'record_rows_refuse_missing_duplicate_extra_or_reordered_ids',
    'value_columns_refuse_missing_extra_noncanonical_or_overflowed_values',
    'payloads_preserve_existing_printable_csv_grammar_and_64_byte_bound',
    'row_lookup_binds_input_id_bytes_and_complete_population',
    'returned_row_rechecks_input_and_column_before_exposing_expected_value',
    'completion_refuses_early_eof_and_excess_even_with_valid_prefix',
    'argument_loading_uses_exact_selected_functions_and_separate_table_path',
    'argument_limits_and_canonical_numbers_remain_closed',
    'selections_reject_duplicate_ids_labels_overlap_order_and_extent_overflow',
    'preparation_policies_keep_exact_extent_bounds',
    'complete_table_load_failure_cannot_fall_back_to_derived_operations',
    'builtin_models_protocol_and_completion_stay_exact',
    'frozen_witnesses_bind_complete_row_function_and_dimension',
    'frozen_witnesses_retain_oracle_and_reject_early_completion',
    'selected_guarded_returns_reject_each_value_and_guard_drift',
    'selected_full_u64_wire_keeps_old_bounds_and_old_refusal',
))

ORACLE_CONTROLS = (
    'test_literal_truth_and_fixed_complete_populations',
    'test_all_original_rows_exact_order_values_and_totals',
    'test_all_installed_values_coordinates_and_completion_are_exact',
    'test_framing_and_caps_do_not_promote_incomplete_scalar_output',
)
WIRE_CONTROLS = (
    'test_both_fixed_populations_retain_actual_wire_and_all_values',
    'test_old_public_wrapper_keeps_old_vocabulary_status_and_refusals',
    'test_selected_geometry_and_input_population_are_frozen',
    'test_every_wire_family_remains_required_and_unique_where_bounded',
    'test_scalar_coordinates_and_unmodified_structural_checks_refuse_drift',
    'test_shared_semantic_rows_are_complete_guarded_u64_values',
)
RUNNER_CONTROLS = (
    'test_all_eight_plans_bind_complete_population_exact_argv_and_cpu_roles',
    'test_fixed_plan_rejects_changed_population_labels_cpus_hashes_and_argv',
    'test_ready_gate_binds_actual_child_pid_and_only_selected_version',
    'test_both_legs_all_cells_require_full_join_before_budget_and_safe',
    'test_inactive_reservation_refuses_before_child_files_are_remembered',
    'test_normally_closed_failure_is_retained_without_scalar_success_credit',
    'test_unknown_or_rescued_envelope_never_completes_or_becomes_safe',
    'test_contradictory_pass_manifest_cannot_be_downgraded_to_safe_failure',
    'test_actual_raw_corruption_rejected_even_with_coherent_manifest_hash',
    'test_changed_first_pin_after_complete_output_stops_before_release',
)
GEOMETRY_CONTROLS = (
    'test_exact_named_origins_definitions_and_surviving_dynamic_table',
    'test_origin_cardinality_order_and_symbol_numbers_are_exact',
    'test_duplicate_missing_undefined_and_versioned_names_are_refused',
    'test_every_definition_component_and_bounded_extent_must_match',
    'test_strip_preservation_is_full_definition_not_only_extent',
    'test_framing_caps_and_unattributed_extra_text_are_refused',
)
CALL_PAIR_REFERENCE_CONTROLS = (
    'test_parent_original_rows_values_and_same_sum_mutation',
    'test_original_complete_elf_edge_caller_and_independent_copies',
    'test_original_exact_frames_refusals_and_empty_population',
    'test_original_caps_identity_domains_and_local_optimized_refusal',
)
# Additive to the complete inherited census, never a replacement for it. Both
# original-control scripts import their local original_output, which imports the
# shared LeafSet output module; root must pin all five before running either.
ORIGINAL_CONTROL_SOURCES = (
    'evaluation/ordinary-leaf-set-session/original_output.py',
    'evaluation/ordinary-leaf-set-session/original_controls.py',
    'evaluation/ordinary-call-pair-session/original_output.py',
    'evaluation/ordinary-call-pair-session/original_controls.py',
    'evaluation/ordinary-leaf-set-session/output.py',
)

DRIVER_CONTROLS = (
    'test_initial_rows_are_exact_eight_once_only_cells',
    'test_build_argv_keeps_all_twelve_exact_commands_and_flags',
    'test_source_join_checks_every_old_pin_and_exact_compiled_membership',
    'test_symbol_suffix_keeps_every_contiguous_byte_and_refuses_bad_headers',
    'test_execute_all_eight_cells_once_after_all_references_pass',
    'test_reference_failure_is_retained_and_all_installed_cells_stay_unrun',
    'test_closed_installed_failure_keeps_later_single_attempts',
    'test_uncertain_outer_or_child_closure_stops_all_later_unchanged_cells',
    'test_copy_source_substitution_refuses_before_identity_or_copy',
)

PROFILE_CONTROLS = (
    'test_explicit_owner_profile_forwards_only_controls_and_campaign',
    'test_old_default_and_unknown_profile_dispatch_stay_strict',
    'test_whole_profile_binds_all_eight_plans_and_exact_whole_argv',
    'test_profile_policy_and_mixed_tables_cannot_cross',
    'test_whole_geometry_retains_exact_extent_return_and_identity_bounds',
    'test_whole_wire_checks_both_complete_populations_without_projection',
    'test_whole_wire_keeps_every_row_family_and_scalar_join',
    'test_cross_profile_child_receipts_refuse_before_safe_release',
    'test_geometry_and_controls_scope_must_match_selected_profile',
    'test_profile_control_inventory_only_appends_to_unchanged_default',
)

CONTROL_STAGE_LABELS = (
    'controls-rust-list', 'controls-rust',
    'controls-python-module', 'controls-python-leaf-wire',
    'controls-python-leaf-runner', 'controls-python-leaf-reference',
    'controls-python-call-pair-reference',
    'controls-python-selected-oracle', 'controls-python-selected-wire',
    'controls-python-selected-runner', 'controls-python-selected-geometry',
    'controls-python-selected-driver',
)


def control_stage_labels(profile=PROFILE):
    assert type(profile) is str and profile in PROFILES
    return CONTROL_STAGE_LABELS + (() if profile == PROFILE else ('controls-python-selected-profile',))


def python_control_count(profile=PROFILE):
    assert type(profile) is str and profile in PROFILES
    return 94 if profile == PROFILE else 104


def selected_inventory(inventory, leaf, recipe, modules):
    assert len(inventory) == len(set(inventory))
    assert len(SELECTED_RUST) == len(set(SELECTED_RUST)) == 24
    assert set(name for name in inventory if name.startswith(SELECTED_PREFIX)) == set(SELECTED_RUST)
    old = tuple(leaf.ordinary_inventory(inventory, recipe, modules['single'], modules['module']))
    assert len(old) == len(set(old)) == 68
    expected = old + SELECTED_RUST
    assert len(expected) == len(set(expected)) == 92 and set(expected) <= set(inventory)
    return expected


def python_suites(leaf, recipe, profile=PROFILE):
    """Literal new names plus the unchanged, separately pinned old inventories."""
    rows = (
        ('controls-python-module', 'evaluation/ordinary-module-session/controls.py',
         tuple(recipe.PYTHON_CONTROLS), 26, 'recipe.python_controls'),
        ('controls-python-leaf-wire', 'evaluation/ordinary-leaf-set-session/controls.py',
         tuple(leaf.CHECKER_CONTROLS), 14, 'owners.reuse_python_controls'),
        ('controls-python-leaf-runner', 'evaluation/ordinary-leaf-set-session/runner_controls.py',
         tuple(leaf.RUNNER_CONTROLS), 9, 'owners.reuse_python_controls'),
        ('controls-python-leaf-reference', 'evaluation/ordinary-leaf-set-session/original_controls.py',
         tuple(leaf.REFERENCE_CONTROLS), 6, 'owners.reuse_python_controls'),
        ('controls-python-call-pair-reference', 'evaluation/ordinary-call-pair-session/original_controls.py',
         CALL_PAIR_REFERENCE_CONTROLS, 4, 'owners.reuse_python_controls'),
        ('controls-python-selected-oracle', 'evaluation/ordinary-selected-session/controls.py',
         ORACLE_CONTROLS, 4, 'owners.reuse_python_controls'),
        ('controls-python-selected-wire', 'evaluation/ordinary-selected-session/wire_controls.py',
         WIRE_CONTROLS, 6, 'owners.reuse_python_controls'),
        ('controls-python-selected-runner', 'evaluation/ordinary-selected-session/runner_controls.py',
         RUNNER_CONTROLS, 10, 'owners.reuse_python_controls'),
        ('controls-python-selected-geometry', 'evaluation/ordinary-selected-session/geometry_controls.py',
         GEOMETRY_CONTROLS, 6, 'owners.reuse_python_controls'),
        ('controls-python-selected-driver', 'evaluation/ordinary-selected-session/driver_controls.py',
         DRIVER_CONTROLS, 9, 'owners.reuse_python_controls'),
    )
    assert tuple(row[0] for row in rows) == CONTROL_STAGE_LABELS[2:]
    assert sum(row[3] for row in rows) == 94
    for _, _, names, count, _ in rows:
        assert len(names) == len(set(names)) == count
    assert type(profile) is str and profile in PROFILES
    if profile == WHOLE_PROFILE:
        assert len(PROFILE_CONTROLS) == len(set(PROFILE_CONTROLS)) == 10
        rows += (('controls-python-selected-profile', 'evaluation/ordinary-selected-session/profile_controls.py',
                  PROFILE_CONTROLS, 10, 'owners.reuse_python_controls'),)
    assert tuple(row[0] for row in rows) == control_stage_labels(profile)[2:]
    assert sum(row[3] for row in rows) == python_control_count(profile)
    return tuple(dict(name=name, path=path, expected=names, count=count, verifier=verifier)
                 for name, path, names, count, verifier in rows)


def run_controls(run, recipe, leaf, owners, new, test_binary):
    """Use existing bounded stages and return exact specs for closed-result replay.

    `new` is retained for the caller's common module API; expectations deliberately
    do not come from new-module exports or an observed test inventory. Root has
    already authenticated the test artifact and every module before this call.
    Stage specs identify the existing request, receipt and actual output paths;
    outer closure and unchanged first pins remain Run's required joins.
    """
    assert all(str(recipe.ROOT / path) in run.sources for path in ORIGINAL_CONTROL_SOURCES)
    census = run.m['census']
    specs, python_results = [], []

    def stage(name, argv, verifier, expected=()):
        directory = run.raw / (name + '-io')
        spec = dict(name=name, argv=list(map(str, argv)), cpu_seconds=20,
                    wall_seconds=30, file_bytes=recipe.MIB, owner_seconds=55,
                    request=str(directory / 'request.json'), receipt=str(directory / 'receipt.json'),
                    stdout=str(directory / 'stdout.txt'), stderr=str(directory / 'stderr.txt'),
                    owner_command=str(run.raw / name / 'command.json'),
                    owner_closed=str(run.raw / name / 'closed.json'),
                    owner_log=str(run.raw / name / 'parent.log'),
                    verifier=verifier, expected=list(expected))
        specs.append(spec)
        return run.stage(name, argv, cpu=20, wall=30, cap=recipe.MIB)

    stdout, stderr = stage('controls-rust-list', [test_binary, '--list'], 'census.census')
    inventory = census.census(stdout, stderr)
    expected = selected_inventory(inventory, leaf, recipe, run.m)
    stdout, stderr = stage('controls-rust', [test_binary, *expected, '--exact', '--test-threads=1'],
                           'census.controls', expected)
    rust = census.controls(stdout, stderr, expected, inventory)
    for suite in python_suites(leaf, recipe, selected_profile(run.a)):
        argv = [run.tools['python'], '-B', recipe.ROOT / suite['path'], '-v']
        stdout, stderr = stage(suite['name'], argv, suite['verifier'], suite['expected'])
        if suite['verifier'] == 'recipe.python_controls':
            recipe.python_controls(stdout, stderr)
        else:
            assert suite['verifier'] == 'owners.reuse_python_controls'
            owners.reuse_python_controls(stdout, stderr, suite['expected'])
        python_results.append(dict(name=suite['name'], status='PASS', count=suite['count'],
                                   expected=list(suite['expected'])))
    assert tuple(spec['name'] for spec in specs) == control_stage_labels(selected_profile(run.a))
    assert sum(row['count'] for row in python_results) == python_control_count(selected_profile(run.a))
    return dict(stage_specs=specs, inventory=list(inventory), rust=rust,
                python=python_results, rust_count=92, python_count=python_control_count(selected_profile(run.a)))


def accept_test_product(run,recipe,path,digest,owner_path,owner_digest,build,build_path,git):
    """Authenticate the real separately closed compile and its retained copy."""
    accepted=read_json(run,recipe,path,digest)
    directory=Path(path).parent;rev=revision(accepted['revision'])
    assert accepted['status']=='RELEASE_TEST_BUILD_PASS' and accepted['compiled_inputs_unchanged'] is True
    assert accepted['original_build_revision']==build['revision']
    assert accepted['original_build_receipt']==dict(path=str(build_path),sha256=run.retained[str(build_path)]['sha256'])
    assert type(accepted['native_dispatches']) is int and accepted['native_dispatches']==0
    expected=git('ls-tree','-r','--name-only','-z',rev,'--',*BUILD_ROOTS)
    assert set(expected.split(b'\0'))==set(git('ls-files','-z','--',*BUILD_ROOTS).split(b'\0'))
    for name,digest in build['sources'].items(): assert sha(git('show',rev+':'+name))==digest
    required={'request.json','receipt.json','closed.json','owner.log','stdout','stderr','compiler-artifact.json'}
    assert set(accepted['members'])==required
    for name,pin in accepted['members'].items(): raw_pin(run,recipe,directory/name,pin)
    request=json.loads(recipe.read(directory/'request.json',MIB))
    assert request['argv']==[str(run.tools['cargo']),'test','--release','-p','rapid-profiler','--bin',
                             'ordinary-interval','--no-run','--locked','--offline','--jobs','4',
                             '--message-format=json-render-diagnostics']
    assert request['env']==build['environment']
    assert (request['cpu_seconds'],request['wall_seconds'],request['file_bytes'])==(120,180,128*MIB)
    closed=json.loads(recipe.read(directory/'closed.json',MIB))
    code,out,_,_=closed_stage(run,recipe,directory,request,closed);assert code==0
    _,product=run.m['native'].artifact(out,'ordinary-interval','ordinary-interval/main.rs','bin',True)
    assert read_json(run,recipe,directory/'compiler-artifact.json')==product
    binary=Path(accepted['binary']['path']);assert binary==directory/'ordinary-interval-tests'
    raw_pin(run,recipe,binary,{key:accepted['binary'][key] for key in ('bytes','sha256')})
    owner=read_json(run,recipe,owner_path,owner_digest);recipe.normal_closed(owner['closed'])
    assert owner['closed']['exit_code']==0 and owner['base']==rev and owner['source_unchanged'] is True
    assert owner['working_source_sha256']=={} and owner['reserved_cpus']==accepted['cpu_affinity'] and owner['attempts']==1
    if 'producer' in accepted:
        fresh_build_producer(run, recipe, accepted, owner, directory, 'tests', git, build)
    else:
        assert owner['command']==[build['tools']['python']['path'],'-B',str((directory/'build.py').relative_to(ROOT))]
        raw_pin(run,recipe,directory/'build.py',cap=MIB)
        assert run.retained[str(directory/'build.py')]['sha256']=='bf695dae34cf7fa9390de9152e0d91d822a3678cd707010b9a31a381f1fdaee5'
    parent=raw_pin(run,recipe,Path(owner_path).with_suffix('.log'),cap=8*MIB)
    assert sha(parent)==owner['closed']['private_log_sha256'] and json.loads(parent)==accepted
    run.result['test_build_revision']=rev
    return binary


def replay_controls(run,recipe,leaf,owners,path,digest,owner_path,owner_digest,build,build_path,git):
    result=read_json(run,recipe,path,digest,32*MIB);directory=Path(path).parent
    profile_record(result, selected_profile(run.a))
    assert result['phase']=='controls' and result['status']=='SELECTED_CONTROLS_PASS'
    assert result['execution_revision']==run.a.revision
    assert result['custody_closed'] is True and result['retention_verified'] is True
    owner=read_json(run,recipe,owner_path,owner_digest);recipe.normal_closed(owner['closed'])
    assert owner['closed']['exit_code']==0 and owner['base']==run.a.revision
    assert owner['working_source_sha256']=={} and owner['source_unchanged'] is True and owner['attempts']==1
    assert owner['command']==result['invocation'] and owner['reserved_cpus']==result['affinity']
    parent=raw_pin(run,recipe,Path(owner_path).with_suffix('.log'),cap=8*MIB)
    assert sha(parent)==owner['closed']['private_log_sha256'] and json.loads(parent)==summary(result)
    assert result['environment']==dict(run.env,TMPDIR=str(directory/'tmp'))
    assert read_json(run,recipe,directory/'sources-before.json')==run.sources
    assert read_json(run,recipe,directory/'sources-after.json')==run.sources
    for name,pin in result['retained'].items(): raw_pin(run,recipe,name,pin,512*MIB)
    for name,pin in result['tool_pins'].items():
        raw_pin(run,recipe,name,pin,512*MIB)
        if name in run.tool_pins: assert run.tool_pins[name]==pin
        else: run.tool_pins[name]=pin
    actual=result['controls'];specs=actual['stage_specs']
    assert tuple(spec['name'] for spec in specs)==control_stage_labels(selected_profile(run.a))
    assert tuple(row['name'] for row in result['stages'])==control_stage_labels(selected_profile(run.a))
    assert actual['rust_count']==92 and actual['python_count']==python_control_count(selected_profile(run.a))
    observed=[]
    for spec,row in zip(specs,result['stages']):
        name=spec['name'];d=directory/(name+'-io');outer=directory/name
        assert row['status']=='CLOSED_EXIT_0'
        assert spec==dict(name=name,argv=spec['argv'],cpu_seconds=20,wall_seconds=30,file_bytes=MIB,
            owner_seconds=55,request=str(d/'request.json'),receipt=str(d/'receipt.json'),
            stdout=str(d/'stdout.txt'),stderr=str(d/'stderr.txt'),owner_command=str(outer/'command.json'),
            owner_closed=str(outer/'closed.json'),owner_log=str(outer/'parent.log'),
            verifier=spec['verifier'],expected=spec['expected'])
        request=read_json(run,recipe,d/'request.json')
        assert request==dict(argv=spec['argv'],cwd=str(ROOT),env=result['environment'],
            stdout=str(d/'stdout.txt'),stderr=str(d/'stderr.txt'),cpu_seconds=20,wall_seconds=30,file_bytes=MIB)
        command=read_json(run,recipe,outer/'command.json')
        assert command==dict(argv=[str(run.tools['python']),'-B',str(ROOT/'tools/unwind-oracle/bounded_command.py'),
            '--request',str(d/'request.json'),'--receipt',str(d/'receipt.json')],cwd=str(ROOT),
            env=result['environment'],wall_seconds=55,log_bytes=MIB)
        closed=read_json(run,recipe,outer/'closed.json');assert closed==row['closed']
        receipt=read_json(run,recipe,d/'receipt.json')
        out=raw_pin(run,recipe,d/'stdout.txt',cap=MIB);err=raw_pin(run,recipe,d/'stderr.txt',cap=MIB)
        assert recipe.bounded_join(receipt,closed,recipe.pin(recipe.read(d/'request.json',MIB)),
            run.sources[str(ROOT/'tools/unwind-oracle/bounded_command.py')],recipe.pin(out),recipe.pin(err))==0
        parent=raw_pin(run,recipe,outer/'parent.log',cap=MIB)
        assert sha(parent)==closed['private_log_sha256']
        assert json.loads(parent)==dict(exit=0,wall_timeout=False,absence_proof='ECHILD',descendants=0,success=True)
        observed.append((out,err))
    product_ref=result['test_product_receipt'];owner_ref=result['test_owner_receipt']
    binary=str(accept_test_product(run,recipe,Path(product_ref['path']),product_ref['sha256'],
        Path(owner_ref['path']),owner_ref['sha256'],build,build_path,git))
    assert binary==result['test_binary'] and binary in result['retained']
    assert result['test_build_revision']==run.result['test_build_revision']
    assert specs[0]['argv']==[binary,'--list'] and specs[0]['verifier']=='census.census' and specs[0]['expected']==[]
    inventory=run.m['census'].census(*observed[0]);expected=selected_inventory(inventory,leaf,recipe,run.m)
    assert specs[1]['argv']==[binary,*expected,'--exact','--test-threads=1']
    assert specs[1]['verifier']=='census.controls' and specs[1]['expected']==list(expected)
    assert run.m['census'].controls(*observed[1],expected,inventory)==actual['rust']
    assert list(inventory)==actual['inventory']
    suites=python_suites(leaf,recipe,selected_profile(run.a))
    assert actual['python']==[dict(name=suite['name'],status='PASS',count=suite['count'],expected=list(suite['expected'])) for suite in suites]
    for suite,spec,(out,err) in zip(suites,specs[2:],observed[2:]):
        assert spec['argv']==[str(run.tools['python']),'-B',str(ROOT/suite['path']),'-v']
        assert spec['expected']==list(suite['expected']) and spec['verifier']==suite['verifier']
        if suite['verifier']=='recipe.python_controls': recipe.python_controls(out,err)
        else: owners.reuse_python_controls(out,err,suite['expected'])
    return actual


def bootstrap(a,started):
    assert HERE==ROOT/'evaluation/ordinary-selected-session'
    revision(a.revision)
    assert re.fullmatch('[A-Za-z0-9_.-]{1,128}',a.reservation_tag)
    for path in (ROOT,a.toolchain,a.user_home,a.cargo_home): assert path.is_absolute() and path.resolve(strict=True)==path and path.is_dir()
    assert a.raw.is_absolute() and a.raw.parent.resolve(strict=True)==a.raw.parent
    assert a.raw.is_relative_to(ROOT/'ignored') and not os.path.lexists(a.raw)
    os.chdir(ROOT)
    tools={name:(a.toolchain/'bin'/name).resolve(strict=True) for name in ('cargo','rustc','rustdoc')}
    tools.update({name:Path('/usr/bin',name).resolve(strict=True) for name in ('git','gcc','strip','readelf','objdump','taskset','bash','rg')})
    tools['python']=Path(sys.executable).resolve(strict=True)
    env=dict(HOME=str(a.user_home),CARGO_HOME=str(a.cargo_home),PATH=str(a.toolchain/'bin')+':/usr/bin:/bin',
        RUSTC=str(tools['rustc']),RUSTDOC=str(tools['rustdoc']),CC=str(tools['gcc']),CARGO_TARGET_DIR=str(ROOT/'target'),
        CARGO_INCREMENTAL='0',CARGO_BUILD_JOBS='4',CARGO_NET_OFFLINE='true',CARGO_PROFILE_RELEASE_OPT_LEVEL='3',
        CARGO_PROFILE_RELEASE_DEBUG='0',CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS='true',CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS='true',
        CARGO_TERM_COLOR='never',LC_ALL='C',PYTHONDONTWRITEBYTECODE='1',PYTHONNOUSERSITE='1',LITEINST_EVALUATION='1',
        TMPDIR=str(a.raw/'tmp'))
    def git(*argv):
        data=subprocess.check_output([tools['git'],'-C',ROOT,*argv],env=env,timeout=15)
        assert len(data)<=32*MIB
        return data
    assert git('rev-parse','--show-toplevel').decode().strip()==str(ROOT)
    assert git('rev-parse','HEAD').decode().strip()==a.revision
    assert git('status','--porcelain','--untracked-files=no')==b''
    for name in (RECIPE,str(Path(__file__).relative_to(ROOT))):
        p=ROOT/name;assert p.is_file() and not p.is_symlink() and p.stat().st_size<=MIB
        assert p.read_bytes()==git('show',a.revision+':'+name)
    assert sha((ROOT/RECIPE).read_bytes())==RECIPE_SHA
    recipe=load('recipe',ROOT/RECIPE)
    roots=('.cargo','src','crates','tools','tests/support','Cargo.toml','Cargo.lock','README.md','build.rs',':(glob)**/Cargo.toml')
    extra_dirs=('ordinary-selected-session','ordinary-leaf-set-session','ordinary-module-session',
                'ordinary-module-native','ordinary-module','ordinary-csv','ordinary-call-pair-session')
    extra=set()
    for directory in extra_dirs:
        names=git('ls-files','-z','--','evaluation/'+directory).decode().rstrip('\0').split('\0')
        extra.update(name for name in names if Path(name).suffix in ('.py','.c','.rs','.S','.map','.md'))
    selected_required={str((HERE/name).relative_to(ROOT)) for name in (
        'README.md','leaves.c','reference.c','oracle.py','controls.py','output.py','wire_controls.py',
        'produce.py','closure.py','runner_controls.py','geometry.py','geometry_controls.py',
        'reproduce.py','driver_controls.py','build.py','build_controls.py','owner.py','BUILD.md','profile_controls.py')}
    # Exact inherited requirements stay mandatory even if an untracked file with
    # the same name happens to exist after a tracked source was removed.
    inherited_required={'evaluation/ordinary-leaf-set-session/reproduce.py',
        'evaluation/ordinary-leaf-set-session/catalog.py','evaluation/ordinary-leaf-set-session/produce.py',
        'evaluation/ordinary-leaf-set-session/output.py','evaluation/ordinary-leaf-set-session/controls.py',
        'evaluation/ordinary-leaf-set-session/runner_controls.py','evaluation/ordinary-leaf-set-session/original.c',
        'evaluation/ordinary-leaf-set-session/original_controls.c',
        'evaluation/ordinary-module-session/owners.py','evaluation/ordinary-module-session/controls.py',
        'evaluation/ordinary-module-session/original.c','evaluation/ordinary-module-session/original_mount_controls.c',
        'evaluation/ordinary-module-native/controls.py','tests/call_tree_truth.rs',RECIPE,
        'tools/rapid-profiler/normal-work/leaf_set.c','tools/rapid-profiler/normal-work/csv_fields.c',
        'tools/rapid-profiler/strnlen-work/localize.map','tools/unwind-oracle/bounded_command.py',
        'evaluation/admission/processes.py'}
    required=set(recipe.MODULES.values())|extra|set(ORIGINAL_CONTROL_SOURCES)|selected_required|inherited_required
    names=git('ls-files','-z','--',*roots,*sorted(required)).decode().rstrip('\0').split('\0')
    assert all(names) and len(names)==len(set(names)) and required<=set(names)
    sources={}
    for name in names:
        data=recipe.read(ROOT/name);assert data==git('show',a.revision+':'+name)
        sources[str(ROOT/name)]=recipe.pin(data)
    for name,expected in (('evaluation/admission/processes.py',recipe.OWNER_SHA),
        ('tools/unwind-oracle/bounded_command.py',recipe.BOUNDED_SHA),('evaluation/ordinary-module-session/corpus.py',recipe.CORPUS_SHA)):
        assert sources[str(ROOT/name)]['sha256']==expected
    modules={key:recipe.load(key,ROOT/path) for key,path in recipe.MODULES.items()}
    assert set(modules['native'].NATIVE_SOURCES)|set(modules['native'].MODULES.values())<=set(names)
    new={key:load(key,HERE/name) for key,name in {'producer':'produce.py','output':'output.py','oracle':'oracle.py',
                                               'closure':'closure.py','geometry':'geometry.py'}.items()}
    leaf=load('leaf',ROOT/'evaluation/ordinary-leaf-set-session/reproduce.py')
    owners=load('owners',ROOT/'evaluation/ordinary-module-session/owners.py')
    pins={str(path):recipe.pin(recipe.read(path,512*MIB)) for path in tools.values()}
    a.raw.mkdir(mode=0o700);(a.raw/'tmp').mkdir()
    run=recipe.Run(a,a.raw,tools,env,sources,modules,started,pins)
    run.result.update(profile=selected_profile(a),phase=a.phase,execution_revision=a.revision,build_revision=None,
        status='FAILED',cells=initial_rows(),population_counts_are_expected=True,scope=SCOPE,native_state='UNRUN_SEPARATE_REQUIRED',performance='UNRUN',
        environment=env,controls=None,invocation=[str(tools['python']),'-B',sys.argv[0],*sys.argv[1:]])
    run.freeze(a.raw/'sources-before.json',sources,16*MIB)
    run.freeze(a.raw/'initial-plan.json',dict(profile=selected_profile(a),phase=a.phase,execution_revision=a.revision,
        cells=initial_rows(),control_stages=control_stage_labels(selected_profile(a)),scope=SCOPE,cpus=run.cpus,
        owner_seconds=7200,cpu_seconds=20,wall_seconds=30,producer_seconds=15,retries=0))
    return run,recipe,new,leaf,owners,git


def summary(result):
    return dict(status=result['status'],profile=result['profile'],phase=result['phase'],
        build_revision=result['build_revision'],execution_revision=result['execution_revision'],
        cells=[dict({key:row.get(key) for key in ('name','status','attempts','child_exit','normal_reaps')},
                    expected_records=row['records'],expected_calls=row['calls']) for row in result['cells']],
        custody_closed=result['custody_closed'],retention_verified=result['retention_verified'],scope=SCOPE)


def main():
    started=time.monotonic()
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--phase',choices=('controls','campaign'),required=True)
    parser.add_argument('--profile',choices=PROFILES,default=PROFILE)
    for name in ('revision','reservation-tag'): parser.add_argument('--'+name,required=True)
    for name in ('raw','toolchain','user-home','cargo-home','build','build-owner'):
        parser.add_argument('--'+name,type=Path,required=True)
    for name in ('build-sha','build-owner-sha'): parser.add_argument('--'+name,required=True)
    for name in ('test-product','test-owner','controls','controls-owner','geometry'): parser.add_argument('--'+name,type=Path)
    for name in ('test-product-sha','test-owner-sha','controls-sha','controls-owner-sha','geometry-sha'): parser.add_argument('--'+name)
    a=parser.parse_args()
    if a.phase=='controls': assert all(value is not None for value in (a.test_product,a.test_product_sha,a.test_owner,a.test_owner_sha))
    else: assert all(value is not None for value in (a.controls,a.controls_sha,a.controls_owner,a.controls_owner_sha,a.geometry,a.geometry_sha))
    run,recipe,new,leaf,owners,git=bootstrap(a,started)
    try:
        build=accept_build(run,recipe,a.build,a.build_sha,a.build_owner,a.build_owner_sha,git)
        run.result['build_revision']=build['revision']
        if a.phase=='controls':
            test=accept_test_product(run,recipe,a.test_product,a.test_product_sha,a.test_owner,a.test_owner_sha,build,a.build,git)
            run.result['test_binary']=str(test)
            run.result['test_product_receipt']=dict(path=str(a.test_product),sha256=a.test_product_sha)
            run.result['test_owner_receipt']=dict(path=str(a.test_owner),sha256=a.test_owner_sha)
            run.result['controls']=run_controls(run,recipe,leaf,owners,new,test)
            run.result['status']='SELECTED_CONTROLS_PASS'
        else:
            run.result['controls']=replay_controls(run,recipe,leaf,owners,a.controls,a.controls_sha,a.controls_owner,a.controls_owner_sha,build,a.build,git)
            table,caller=accept_geometry(run,recipe,new,build,a.build,a.geometry,a.geometry_sha)
            freeze_cells(run,recipe,new,build,a.build,table,caller)
            if execute_cells(run,recipe,new): run.result['status']='SELECTED_SCALAR_FUNCTIONAL_PASS'
        run.unchanged();run.freeze(a.raw/'sources-after.json',run.sources,16*MIB)
    except BaseException as error:
        run.result.update(status='FAILED',error=type(error).__name__+': '+str(error))
    finally:
        run.budget.stopped()
        run.result.update(custody_closed=run.safe,retention_verified=False,retained=dict(run.retained),
            tool_pins=dict(run.tool_pins),end_utc=dt.datetime.now(dt.timezone.utc).isoformat(),
            load_after=list(os.getloadavg()),evidence_budget=run.budget.summary())
        try:
            assert run.safe and not run.budget.exceeded and run.budget.used<=recipe.EVIDENCE_LIMIT-recipe.FINAL_ALLOWANCE
            run.unchanged();run.result['retention_verified']=True
        except BaseException as error: run.result.update(status='FAILED',final_error=type(error).__name__+': '+str(error))
        # Keep bulky private source/output pins private; publication consumes the
        # exact receipt plus eight rows, never this raw inventory as public data.
        recipe.save(a.raw/'result.json',run.result,32*MIB)
        print(json.dumps(summary(run.result),sort_keys=True))
    return 0 if run.result['status'] in ('SELECTED_CONTROLS_PASS','SELECTED_SCALAR_FUNCTIONAL_PASS') and time.monotonic()<run.deadline else 1


if __name__=='__main__':
    raise SystemExit(main())
