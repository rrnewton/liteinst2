#!/usr/bin/env python3
"""One fixed release old48 prerequisite then explicit-whole LeafSet1280 cohort.

Run once under an external hard three-CPU reservation,1200s/8MiB owner.
Native480CPU/510wall/1MiB and pair15s/20000-step bounds are unchanged.
"""
import sys
if sys.flags.optimize:
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
import shutil
import subprocess
import time

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
MIB = 1048576
PROFILE = 'leaf-set-whole-rust-v1'
SEEDS = (1311768467139281696, 18364758542526924135)
POLICIES = ('certified', 'whole', 'whole', 'whole')
LEAF_SOURCES = ('tests/support/native_copied_rust/effects.rs', 'tests/support/native_copied_rust.rs', 'tests/support/native_leaf_set_copied/scanner/tests.rs', 'tests/support/native_leaf_set_copied/scanner.rs', 'tests/support/native_leaf_set_copied/tests.rs', 'tests/support/native_leaf_set_copied/trace.rs', 'tests/support/native_leaf_set_copied.rs', 'tests/support/native_normal_caller.rs', 'tests/support/native_normal_module.rs', 'tools/rapid-profiler/native-interval/calibrations.rs', 'tools/rapid-profiler/native-interval/main.rs', 'tools/rapid-profiler/native-interval/normal/leaf_set_copied/check/tests.rs', 'tools/rapid-profiler/native-interval/normal/leaf_set_copied/check.rs', 'tools/rapid-profiler/native-interval/normal/leaf_set_copied.rs', 'tools/rapid-profiler/native-interval/normal.rs')
LEAF_SOURCE_SHA = 'ead926a7716b243772929a4ef59b8cee95a4ff1ce5c1a20b0e62dd1795f5dfa8'
SYMBOLS = ('csv_fields', 'leaf_length', 'leaf_ascii_digits', 'leaf_ascii_spaces')
SCOPE = ('Copied complete admitted Rust body only; no original-address Rust call-site ABI, '
         'threaded worker, K exhaustion, bank reuse, Schedule, timing or full-A5 credit. '
         'External hard reservation and exact-command outer closure remain required.')
STAGES = ('tool-cc1', 'tool-collect2', 'tool-as', 'tool-ld', 'legacy-module-build', 'legacy-module-symbols', 'legacy-csv_fields-disassembly', 'legacy-strnlen-disassembly', 'leaf-module-build', 'leaf-module-symbols', 'leaf-csv_fields-disassembly', 'leaf-leaf_length-disassembly', 'leaf-leaf_ascii_digits-disassembly', 'leaf-leaf_ascii_spaces-disassembly', 'application-build', 'application-caller-disassembly', 'application-caller-symbols', 'native-build', 'state-build', 'sdk-build', 'state-list', 'state-controls', 'sdk-list', 'sdk-control', 'legacy-python-controls', 'session-python-controls', 'copied-python-controls', 'copied-runner-controls', 'leaf-python-controls', 'runner-controls', 'legacy-native-outer', 'leaf-native-outer')
LEAF_CALIBRATIONS = ('oracle::native_ordinary::normal_caller::leaf_set_copied::tests::leaf_set_profile_refuses_invalid_tables_and_preserves_old_discriminators', 'oracle::native_ordinary::normal_caller::leaf_set_copied::tests::leaf_set_geometry_retains_noncontiguous_pages_and_complete_union', 'oracle::native_ordinary::normal_caller::leaf_set_copied::tests::leaf_set_ready_joins_parent_plan_caller_table_and_selection', 'oracle::native_ordinary::normal_caller::leaf_set_copied::scanner::tests::leaf_set_scanner_truth_preserves_all_literal_inputs_and_results', 'oracle::native_ordinary::normal_caller::leaf_set_copied::scanner::tests::leaf_set_scanner_effects_check_widths_flags_and_branches', 'oracle::native_ordinary::normal_caller::leaf_set_copied::scanner::tests::leaf_set_scanner_refuses_unsupported_and_out_of_bounds_effects', 'oracle::native_ordinary::normal_caller::leaf_set_copied::tests::leaf_set_pair_requires_target_and_real_copied_outer_returns', 'normal_leaf_set_copied_check::tests::leaf_set_batch_joins_all_identity_rank_sequence_and_journal_words', 'normal_leaf_set_copied_check::tests::leaf_set_history_report_and_reclaim_require_complete_state', 'oracle::native_ordinary::normal_caller::leaf_set_copied::tests::leaf_set_population_retains_all_subsets_k_seeds_cases_and_counts', 'oracle::native_ordinary::normal_caller::leaf_set_copied::tests::leaf_set_coverage_preserves_csv_subset_and_full_other_cfg_rules', 'oracle::native_ordinary::normal_caller::leaf_set_copied::tests::leaf_set_output_caps_and_partial_rows_never_qualify', 'oracle::native_ordinary::normal_caller::leaf_set_copied::tests::leaf_set_whole_policy_extent_and_complete_table_are_fixed', 'oracle::native_ordinary::normal_caller::leaf_set_copied::tests::leaf_set_whole_ready_version_and_coherent_oversize_refuse')
LEAF_CONTROLS = ('test_all1280_pairs_and128_coverage_groups_bind_independent_geometry', 'test_full_catalog_order_missing_duplicate_and_coherent_subset_changes', 'test_literal_inputs_values_and_raw_outer_rax_domains', 'test_full_table_caller_geometry_and_complete_ret_coverage', 'test_csv_observed_union_remains_distinct_from_full_other_cfg', 'test_raw_absence_canonical_numbers_caps_and_all_counters', 'test_partial_failed_unrun_or_unclosed_population_cannot_qualify', 'test_source_local_import_and_optimization_guard', 'test_whole_policy_and_full_table_extent_boundaries', 'test_old_profile_and_status_cannot_be_relabelled')
RUNNER_CONTROLS = ('test_profile_catalog_preserves_old48_and_fixed_new1280', 'test_exact_native_calibration_union_refuses_missing_extra', 'test_whole_request_policies_extents_coordinates_and_cpu', 'test_complete_independent_body_geometry_and_operation_order', 'test_prefix_retention_keeps_missing_keys_unrun_without_qualification', 'test_once_only_failure_and_closed_output_custody', 'test_public_projection_keeps_final_and_external_authority_separate')
SDK_CONTROL = 'frontend_native::always_on::site::ordinary::normal_leaf_set::tests::leaf_set_roles_and_policies_cover_all_members'


def calibration_inventory(prior, inventory, ignored):
    assert type(prior) is dict and len(prior) == 179 and ignored not in prior
    expected = dict(prior)
    assert len(LEAF_CALIBRATIONS) == len(set(LEAF_CALIBRATIONS)) == 14
    for name in LEAF_CALIBRATIONS:
        assert name not in expected
        expected[name] = False
    assert len(expected) == 193 and len(inventory) == len(set(inventory))
    assert set(inventory) == set(expected) | {ignored}
    return expected


def catalog(kind):
    assert kind in ('legacy', 'leaf')
    if kind == 'legacy':
        return [(seed, name, case) for seed in SEEDS for name, count in (('csv',16),('length',8))
                for case in range(1,count+1)]
    return [(mask,k,seed,op,case) for mask in range(1,16) for k in (10,1000) for seed in SEEDS
            for op,count in enumerate((16,8,8,8),1) if mask & (1 << (op-1)) for case in range(1,count+1)]


def initial_cohort(kind):
    count = 48 if kind == 'legacy' else 1280
    keys = catalog(kind); assert len(keys) == count and len(set(keys)) == count
    return dict(name=kind, status='UNRUN', attempts=0, required_pairs=count,
                required_children=2*count, required_target_calls=2*count,
                required_target_returns=2*count, required_outer_returns=2*count,
                required_normal_reaps=2*count, catalog=keys, observed=[], prefix_error=None)


def begin(row):
    assert row['status'] == 'UNRUN' and type(row['attempts']) is int and row['attempts'] == 0
    row.update(status='FAILED', attempts=1)


def request_shape(request, cpus):
    assert set(request) == {'argv','cwd','env','stdout','stderr','pins','cpu'}
    assert type(cpus) is list and len(cpus) == 3 and cpus == sorted(set(cpus))
    assert all(type(cpu) is int and 0 <= cpu < 1024 for cpu in cpus)
    assert type(request['cpu']) is int and request['cpu'] == cpus[1]
    argv = request['argv']
    assert type(argv) is list and len(argv) == 15 and all(type(x) is str and '\0' not in x for x in argv)
    assert argv[:2] == [str(ROOT/'target/release/frontend-native-oracle'),'normal-leaf-set-rust-state']
    assert all(re.fullmatch('[1-9][0-9]{0,19}', word) for word in argv[7:])
    ranges=[]; pages=set()
    for index in range(4):
        va, size = map(int,argv[7+2*index:9+2*index]); maximum = 256 if index == 0 else 80
        assert va > 0 and 5 <= size <= maximum and va+size <= (1 << 64)-1
        assert all(va+size <= a or b <= va for a,b in ranges)
        ranges.append((va,va+size)); pages.update((va//4096,(va+size-1)//4096))
    assert 1 <= len(pages) <= 2
    cohort = Path(request['stdout']).parent; raw = cohort.parent
    assert raw.is_absolute() and raw.resolve(strict=True) == raw and raw.is_relative_to(ROOT/'ignored')
    assert cohort.name == 'leaf-native' and cohort.resolve(strict=True) == cohort
    assert request['stdout'] == str(cohort/'stdout.txt') and request['stderr'] == str(cohort/'stderr.txt')
    assert argv[2:7] == list(map(str,[raw/'leaf-module-candidate.so',raw/'leaf-module-trusted.so',
        raw/'application-candidate',raw/'application-trusted',cohort/'output']))
    assert request['cwd'] == str(ROOT) and type(request['env']) is dict and request['env']['LITEINST_EVALUATION'] == '1'
    assert {str(HERE/'reproduce.py'),argv[0],*argv[2:6]} <= request['pins'].keys()
    return cohort


def native_exec(path, expected_hash):
    # Same existing limit/exec implementation; authenticate its source before import.
    assert re.fullmatch('[0-9a-f]{64}',expected_hash)
    import stat
    with os.fdopen(os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK),'rb') as stream:
        before=os.fstat(stream.fileno()); assert stat.S_ISREG(before.st_mode) and 0 < before.st_size <= MIB
        data=stream.read(MIB+1); after=os.fstat(stream.fileno())
        assert before == after and len(data) == before.st_size
    assert hashlib.sha256(data).hexdigest() == expected_hash
    request=json.loads(data); cpus=sorted(os.sched_getaffinity(0)); cohort=request_shape(request,cpus)
    assert path == cohort/'request.json'
    helper=ROOT/'evaluation/ordinary-module-native/reproduce.py'
    data=helper.read_bytes(); assert len(data) <= MIB
    assert request['pins'][str(helper)] == dict(bytes=len(data),sha256=hashlib.sha256(data).hexdigest())
    spec=importlib.util.spec_from_file_location('_leaf_native_limits',helper)
    assert spec and spec.loader
    module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    module.pins_ok(request['pins'])
    os.sched_setaffinity(0,{request['cpu']}); assert sorted(os.sched_getaffinity(0)) == [request['cpu']]
    module._native_exec(path,expected_hash,lambda value:request_shape(value,cpus))


def full_body_geometry(native, rows, va, size, operation):
    assert type(operation) is int and 1 <= operation <= 4
    assert 5 <= size <= (256 if operation == 1 else 80)
    full=native.body_geometry(rows,va,size)
    # Reuse the old reachable/NOP and RET checks; preserve the complete graph separately.
    if operation != 1: native.body_geometry(rows,va,size,True)
    edges=[]
    for pc,code,asm in rows:
        word=asm.split()[0]
        if word == 'ret': continue
        if word.startswith('j'):
            match=re.fullmatch(r'j[a-z]+\s+([0-9a-f]+) <[^>]+>',asm); assert match
            edges.append([pc-va,int(match[1],16)-va])
            if word == 'jmp': continue
        edges.append([pc-va,pc+len(code)-va])
    edges=sorted(edges); assert len(edges) == len({tuple(x) for x in edges}) == full['edges']
    return dict(operation=operation,function_id=300+operation,elf_va=va,length=size,
                heads=full['heads'],edges=edges,returns=full['returns'])


def closed_output(closed, parent_log):
    # Retention-only custody. Native acceptance still uses unchanged exit-zero,
    # no-rescue/reap and empty-parent-log predicates in copied.accept_closure.
    assert closed['cleanup_complete'] is True
    assert type(closed['reaped_descendants']) is int and closed['reaped_descendants'] >= 0
    assert hashlib.sha256(parent_log).hexdigest() == closed['private_log_sha256']

def prefix_rows(data, header, kind):
    """Retain only consecutive complete numeric rows; never qualify or resynchronize."""
    assert kind in ('legacy','leaf') and type(data) is bytes
    assert len(data) <= (65536 if kind == 'legacy' else MIB)
    result=[]; keys=catalog(kind); fields=header.split(',')
    complete=data.split(b'\n'); tail=complete.pop()
    if not complete or complete.pop(0) != header.encode('ascii'):
        return result,'HEADER_OR_TRUNCATION'
    profile='copied-rust-invoke-v1' if kind == 'legacy' else PROFILE
    names=('seed','function','case') if kind == 'legacy' else ('subset','k','seed','function','case')
    for line in complete:
        try:
            assert len(result) < len(keys) and len(line)+1 <= (65536 if kind == 'legacy' else 768)
            assert all(32 <= b < 127 for b in line)
            values=line.decode('ascii').split(','); assert len(values) == len(fields)
            row=dict(zip(fields,values)); assert row['profile'] == profile and row['status'] == 'PASS'
            csv=row['function'] == ('csv' if kind == 'legacy' else '1')
            for name,value in tuple(row.items()):
                if name in ('profile','status') or kind == 'legacy' and name == 'function': continue
                if csv and name in ('input_reads','input_bytes'):
                    assert value == ''; row[name]=None
                else:
                    assert re.fullmatch(r'0|[1-9][0-9]{0,19}',value)
                    row[name]=int(value); assert row[name] <= (1 << 64)-1
            assert tuple(row[name] for name in names) == keys[len(result)]
            result.append(row)
        except (AssertionError,ValueError,UnicodeError,KeyError):
            return result,'FIRST_INVALID_ROW'
    return result,('TRUNCATED_TAIL' if tail else None)


def public_projection(result):
    # Even a complete local result still needs the external final receipt.
    cohorts=[]
    for row in result['cohorts']:
        assert row['catalog'] == catalog(row['name']) and len(row['observed']) <= len(row['catalog'])
        cohorts.append(dict(name=row['name'],status=row['status'],attempts=row['attempts'],
            required_pairs=row['required_pairs'],observed_rows=len(row['observed']),prefix_error=row['prefix_error'],
            outcomes=[dict(key=key,status='OBSERVED_UNQUALIFIED' if i < len(row['observed']) else 'UNRUN',
                           values=row['observed'][i] if i < len(row['observed']) else None)
                      for i,key in enumerate(row['catalog'])]))
    return dict(status='UNQUALIFIED_PENDING_FINAL_RECEIPT',local_status=result['status'],
        revision=result['revision'],profile=PROFILE,policies=list(POLICIES),cohorts=cohorts,
        custody_closed=result.get('custody_closed',False),retention_verified=result.get('retention_verified',False),
        external_owner_required=True,scope=SCOPE)


def copy_artifact(run, recipe, source, target):
    content=recipe.read(source,512*MIB); assert content
    run.budget.charge(str(target),len(content))
    with target.open('xb') as stream: stream.write(content)
    assert (target.stat().st_dev,target.stat().st_ino) != (source.stat().st_dev,source.stat().st_ino)
    run.remember(target,run.retained[str(source)])


def capture_prefix(run, recipe, row, cohort, directory, closed, checker):
    assert run.safe
    parent_log=recipe.read(directory/'parent.log',MIB)
    closed_output(closed,parent_log)
    row.update(closed=closed,load_after=list(os.getloadavg()),affinity_after=sorted(os.sched_getaffinity(0)))
    kind=row['name']
    pairs_name='copied-rust-pairs.csv' if kind == 'legacy' else 'leaf-set-rust-pairs.csv'
    coverage_name='copied-rust-coverage.csv' if kind == 'legacy' else 'leaf-set-rust-coverage.csv'
    output=cohort/'output'
    if output.exists(): assert output.is_dir() and not output.is_symlink()
    files=[('stdout.txt',1024),('stderr.txt',MIB),('output/'+pairs_name,65536 if kind == 'legacy' else MIB),('output/'+coverage_name,65536)]
    for name,cap in files:
        path=cohort/name
        if path.exists(): run.remember(path,cap=cap)
    pairs=output/pairs_name
    if pairs.exists():
        row['observed'],row['prefix_error']=prefix_rows(recipe.read(pairs,files[2][1]),checker.HEADER,kind)
    return pairs_name,coverage_name,files[2][1],parent_log


def execute_cohort(run, recipe, copied, row, request, request_pin, checker, bodies, caller):
    kind=row['name']; cohort=Path(request['stdout']).parent; name=kind+'-native-outer'
    script=ROOT/'evaluation/ordinary-rust-invoke-native/reproduce.py' if kind == 'legacy' else HERE/'reproduce.py'
    command=[run.tools['python'],'-B',script,'--native-request',cohort/'request.json',request_pin['sha256']]
    run.command(name,command,510); begin(row)
    row.update(load_before=list(os.getloadavg()),affinity_before=sorted(os.sched_getaffinity(0)))
    run.freeze(cohort/'attempt.json',dict(status='FAILED',attempts=1))
    try:
        directory,closed=run.owned(name,command,510,growth=16*MIB)
    except BaseException:
        # Retain a failed, already closed numeric prefix without interpreting it
        # as a native pass. Unknown custody never reaches the output reader.
        stage=next((r for r in run.result['stages'] if r['name'] == name),None)
        if run.safe and stage is not None and 'closed' in stage:
            try:
                capture_prefix(run,recipe,row,cohort,run.raw/name,stage['closed'],checker)
            except BaseException:
                row['prefix_error']='RETENTION_CUSTODY_OR_PREFIX_REFUSED'
        raise
    pairs_name,coverage_name,pair_cap,parent_log=capture_prefix(run,recipe,row,cohort,directory,closed,checker)
    # Exact old normal-exit-zero/log/reap predicate governs both cohorts.
    copied.accept_closure(row,closed,parent_log)
    output=cohort/'output'; assert output.is_dir() and not output.is_symlink()
    assert {p.name for p in output.iterdir()} == {pairs_name,coverage_name}
    parsed=checker.check(recipe.read(output/pairs_name,pair_cap),recipe.read(output/coverage_name,65536),
        recipe.read(cohort/'stdout.txt',1024),recipe.read(cohort/'stderr.txt',MIB),bodies=bodies,caller=caller)
    expected='COPIED_RUST_INVOKE_TRANSCRIPT_VALIDATED' if kind == 'legacy' else 'LEAF_SET_WHOLE_TRANSCRIPT_VALIDATED'
    assert parsed['status'] == expected and row['prefix_error'] is None and len(row['observed']) == row['required_pairs']
    assert parsed['rows'] == row['observed']
    run.closed_inventory(cohort); run.budget.complete(); run.unchanged()
    row.update(status='LOCAL_NATIVE_CHECKS_COMPLETE',comparisons=parsed['comparisons'])


def main():
    started=time.monotonic()
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--revision',required=True); ap.add_argument('--reservation-tag',required=True)
    for name in ('raw','toolchain','user-home','cargo-home'): ap.add_argument('--'+name,type=Path,required=True)
    a=ap.parse_args()
    assert re.fullmatch('[0-9a-f]{40}',a.revision) and re.fullmatch('[A-Za-z0-9_.-]{1,128}',a.reservation_tag)
    assert HERE == ROOT/'evaluation/ordinary-leaf-set-native'
    for p in (ROOT,a.toolchain,a.user_home,a.cargo_home):
        assert p.is_absolute() and p.resolve(strict=True) == p and p.is_dir()
    assert a.raw.is_absolute() and a.raw.parent.resolve(strict=True) == a.raw.parent
    assert a.raw.is_relative_to(ROOT/'ignored') and not os.path.lexists(a.raw)
    assert not os.path.lexists(ROOT/'target/evaluation'/a.raw.name)
    os.chdir(ROOT)
    tools={n:(a.toolchain/'bin'/n).resolve(strict=True) for n in ('cargo','rustc','rustdoc')}
    tools.update({n:Path('/usr/bin',n).resolve(strict=True) for n in ('git','gcc','readelf','objdump','bash','rg')})
    tools['python']=Path(sys.executable).resolve(strict=True)
    env=dict(HOME=str(a.user_home),CARGO_HOME=str(a.cargo_home),PATH=str(a.toolchain/'bin')+':/usr/bin:/bin',
        RUSTC=str(tools['rustc']),RUSTDOC=str(tools['rustdoc']),CC=str(tools['gcc']),CARGO_TARGET_DIR=str(ROOT/'target'),
        CARGO_INCREMENTAL='0',CARGO_BUILD_JOBS='4',CARGO_NET_OFFLINE='true',CARGO_PROFILE_RELEASE_OPT_LEVEL='3',
        CARGO_PROFILE_RELEASE_DEBUG='0',CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS='true',CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS='true',
        CARGO_TERM_COLOR='never',LC_ALL='C',PYTHONDONTWRITEBYTECODE='1',PYTHONNOUSERSITE='1',
        LITEINST_EVALUATION='1',TMPDIR=str(a.raw/'tmp'))
    def git(*args):
        data=subprocess.check_output(['/usr/bin/git','-C',ROOT,*args],env=env,timeout=15)
        assert len(data) <= 32*MIB
        return data
    assert git('rev-parse','--show-toplevel').decode().strip() == str(ROOT)
    assert git('rev-parse','HEAD').decode().strip() == a.revision
    assert git('status','--porcelain','--untracked-files=no') == b''
    # Bootstrap only stdlib until self and the first helper match requested Git bytes.
    for name in ('evaluation/ordinary-leaf-set-native/reproduce.py','evaluation/ordinary-module-session/reproduce.py'):
        p=ROOT/name; assert not p.is_symlink() and p.is_file() and p.stat().st_size <= MIB
        assert p.read_bytes() == git('show',a.revision+':'+name)
    spec=importlib.util.spec_from_file_location('_leaf_whole_session',ROOT/'evaluation/ordinary-module-session/reproduce.py')
    assert spec and spec.loader
    recipe=importlib.util.module_from_spec(spec); spec.loader.exec_module(recipe)
    required=set(recipe.MODULES.values()) | set(LEAF_SOURCES) | {
        'evaluation/ordinary-rust-invoke-native/reproduce.py','evaluation/ordinary-rust-invoke-native/caller.py',
        'evaluation/ordinary-rust-invoke-native/rust_invoke.py','evaluation/ordinary-rust-invoke-native/controls.py',
        'evaluation/ordinary-rust-invoke-native/runner_controls.py','evaluation/ordinary-module-session/reproduce.py',
        'evaluation/ordinary-module-session/controls.py','evaluation/ordinary-module-native/controls.py',
        'evaluation/ordinary-leaf-set-session/reproduce.py','evaluation/ordinary-leaf-set-native/reproduce.py',
        'evaluation/ordinary-leaf-set-native/runner_controls.py','evaluation/ordinary-leaf-set-native/leaf_set_native.py',
        'evaluation/ordinary-leaf-set-native/controls.py','tools/unwind-oracle/bounded_command.py','tests/call_tree_truth.rs',
        'tools/rapid-profiler/reference-work/check_output.py','tools/rapid-profiler/verify_normal_interval.py',
        'tools/rapid-profiler/verify_strnlen_interval.py','tools/rapid-profiler/normal-work/leaf_set.c',
        'tools/rapid-profiler/normal-work/csv_fields.c','tools/rapid-profiler/strnlen-work/strnlen.c',
        'tools/rapid-profiler/strnlen-work/localize.map'}
    names=git('ls-files','-z','--','src','tests/support','tools/rapid-profiler','Cargo.toml','Cargo.lock','README.md','build.rs',
              ':(glob)**/Cargo.toml',*sorted(required)).decode().rstrip('\0').split('\0')
    assert all(names) and len(names) == len(set(names)) and required <= set(names)
    sources={}
    for name in names:
        data=recipe.read(ROOT/name); assert data == git('show',a.revision+':'+name)
        sources[str(ROOT/name)]=recipe.pin(data)
    for name,expected in (('evaluation/admission/processes.py',recipe.OWNER_SHA),
        ('tools/unwind-oracle/bounded_command.py',recipe.BOUNDED_SHA),('evaluation/ordinary-module-session/corpus.py',recipe.CORPUS_SHA)):
        assert sources[str(ROOT/name)]['sha256'] == expected
    tool_pins={str(p):recipe.pin(recipe.read(p,512*MIB)) for p in tools.values()}
    assert git('rev-parse','HEAD').decode().strip() == a.revision and git('status','--porcelain','--untracked-files=no') == b''
    modules={key:recipe.load(key,ROOT/path) for key,path in recipe.MODULES.items()}
    native=modules['native']
    copied=recipe.load('leaf_copied_recipe',ROOT/'evaluation/ordinary-rust-invoke-native/reproduce.py')
    old=recipe.load('leaf_copied_checker',ROOT/'evaluation/ordinary-rust-invoke-native/rust_invoke.py')
    caller_parser=recipe.load('leaf_caller_geometry',ROOT/'evaluation/ordinary-rust-invoke-native/caller.py')
    leaf=recipe.load('leaf_whole_checker',HERE/'leaf_set_native.py')
    library=recipe.load('leaf_library_artifact',ROOT/'evaluation/ordinary-leaf-set-session/reproduce.py')
    assert sources[str(ROOT/'tools/rapid-profiler/normal-work/csv_fields.c')]['sha256'] == native.CSV_SOURCE_SHA
    assert sources[str(ROOT/'tools/rapid-profiler/strnlen-work/strnlen.c')]['sha256'] == native.LENGTH_SOURCE_SHA
    assert sources[str(ROOT/'tools/rapid-profiler/normal-work/leaf_set.c')]['sha256'] == LEAF_SOURCE_SHA
    assert leaf.PROFILE == PROFILE and tuple(leaf.POLICIES) == POLICIES
    a.raw.mkdir(mode=0o700); (a.raw/'tmp').mkdir()
    run=recipe.Run(a,a.raw,tools,env,sources,modules,started,tool_pins); run.deadline=started+1200
    cohorts=[initial_cohort(kind) for kind in ('legacy','leaf')]
    run.result.update(kind='leaf-set-whole-native-release-v1',scope=SCOPE,originals=[],installed=[],controls=[],prerequisites={},
        cohorts=cohorts,policies=list(POLICIES),cpu_roles=dict(supervisor_build_controls=run.cpus,native_parent_and_tracees=run.cpus[1]),
        planned_stages=[dict(name=n,status='UNRUN') for n in STAGES])
    try:
        run.result['sources_before']=run.freeze(a.raw/'sources-before.json',sources,cap=16*MIB)
        run.result['plan']=run.freeze(a.raw/'initial-plan.json',dict(revision=a.revision,stages=STAGES,cohorts=cohorts,
            attempts_each=1,retries=0,policies=POLICIES,pair_seconds=15,steps_per_child=20000,native_wall_seconds=510,
            native_cpu_seconds=480,native_file_bytes=MIB,outer_seconds=1200,outer_log_bytes=8*MIB,
            reservation_tag=a.reservation_tag,affinity=run.cpus,reservation_authority='external owner only',scope=SCOPE))
        for name in ('cc1','collect2','as','ld'):
            out,err=run.stage('tool-'+name,[tools['gcc'],'-print-prog-name='+name])
            assert err == b'' and out.endswith(b'\n') and out.count(b'\n') == 1
            reported=out[:-1].decode('utf-8'); p=Path(reported) if '/' in reported else Path(shutil.which(reported,path=env['PATH']) or '')
            assert p.is_absolute(); p=p.resolve(strict=True); value=recipe.pin(recipe.read(p,512*MIB))
            if str(p) in run.tool_pins: assert run.tool_pins[str(p)] == value
            else: run.tool_pins[str(p)]=value
        run.result['tools']=run.freeze(a.raw/'tools.json',run.tool_pins)
        geometry={}; dsos={}
        for kind in ('legacy','leaf'):
            prefix='module' if kind == 'legacy' else 'leaf-module'
            trusted=a.raw/(prefix+'-trusted.so'); candidate=a.raw/(prefix+'-candidate.so')
            inputs=[ROOT/'tools/rapid-profiler/normal-work/csv_fields.c',ROOT/'tools/rapid-profiler/strnlen-work/strnlen.c'] if kind == 'legacy' else [ROOT/'tools/rapid-profiler/normal-work/leaf_set.c']
            out,err=run.stage(kind+'-module-build',[tools['gcc'],*native.MODULE_FLAGS,*inputs,'-o',trusted],generated=((trusted,MIB),))
            assert out == err == b''; copy_artifact(run,recipe,trusted,candidate)
            symbols,err=run.stage(kind+'-module-symbols',[tools['readelf'],'--wide','--syms',trusted]); assert err == b''
            labels=('csv_fields','strnlen') if kind == 'legacy' else SYMBOLS
            spans=[native.selection(symbols,name,256 if i == 0 else 80) for i,name in enumerate(labels)]
            bodies=[]
            for i,(name,(va,size)) in enumerate(zip(labels,spans)):
                out,err=run.stage(kind+'-'+name+'-disassembly',[tools['objdump'],'-d','-M','intel','--insn-width=16','--disassemble='+name,trusted])
                assert err == b''; decoded=native.geometry(out,name,va,size)
                bodies.append(native.body_geometry(decoded,va,size,i == 1) if kind == 'legacy' else full_body_geometry(native,decoded,va,size,i+1))
            if kind == 'legacy':
                (cv,cl),(lv,ll)=spans; assert cv+cl <= lv and cv//4096 == (lv+ll-1)//4096
            geometry[kind]=dict(selections=spans,bodies=bodies); dsos[kind]=(candidate,trusted)
        cargo=['--locked','--offline','--release','--jobs','4','-p','rapid-profiler','--message-format=json-render-diagnostics']
        out,_=run.stage('application-build',[tools['cargo'],'build','--bin','ordinary-interval',*cargo],120,180,128*MIB)
        application,product=native.artifact(out,'ordinary-interval','ordinary-interval/main.rs','bin',False); run.remember(application)
        run.result['application']=run.freeze(a.raw/'application-artifact.json',dict(product=product,binary=run.retained[str(application)]))
        app_trusted=a.raw/'application-trusted'; app_candidate=a.raw/'application-candidate'
        for target in (app_trusted,app_candidate): copy_artifact(run,recipe,application,target)
        assert len({(p.stat().st_dev,p.stat().st_ino) for p in (application,app_trusted,app_candidate)}) == 3
        disassembly,err=run.stage('application-caller-disassembly',[tools['objdump'],'-d','-M','intel','--insn-width=16',
            '--disassemble=liteinst_csv_call_and_store',app_trusted]); assert err == b''
        shape=modules['csv'].caller_geometry(disassembly.decode('ascii'))
        symbols,err=run.stage('application-caller-symbols',recipe.caller_symbol_command(tools,app_trusted)); assert err == b''
        modules['module'].caller_symbols(symbols.decode('ascii'),shape)
        caller=caller_parser.geometry(native.geometry(disassembly,'liteinst_csv_call_and_store',shape['elf_va'],shape['length']),shape['elf_va'],shape['length'])
        assert caller['continuation_offset'] == shape['continuation_offset']
        old.geometry(geometry['legacy']['bodies'],caller); leaf.geometry(geometry['leaf']['bodies'],caller)
        run.result['geometry']=run.freeze(a.raw/'geometry.json',dict(cohorts=geometry,caller=caller,policies=POLICIES))
        bins={}
        for label,target,source,kind,test,flags in (
            ('native','frontend-native-oracle','native-interval/main.rs','bin',False,['build','--bin','frontend-native-oracle']),
            ('state','frontend-native-calibrations','native-interval/calibrations.rs','test',True,['test','--test','frontend-native-calibrations','--no-run'])):
            out,_=run.stage(label+'-build',[tools['cargo'],*flags,*cargo],120,180,128*MIB)
            binary,product=native.artifact(out,target,source,kind,test); run.remember(binary); bins[label]=binary
            run.freeze(a.raw/(label+'-artifact.json'),dict(product=product,binary=run.retained[str(binary)]))
        out,_=run.stage('sdk-build',[tools['cargo'],'test','--lib','--no-run',*cargo],120,180,128*MIB)
        sdk,product=library.library_artifact(out); run.remember(sdk)
        run.freeze(a.raw/'sdk-artifact.json',dict(product=product,binary=run.retained[str(sdk)]))
        peers={key:recipe.load('leaf_'+key,ROOT/native.MODULES[key]) for key in ('legacy','normal','whole')}
        prior=native.calibration_manifest(peers['legacy'],peers['normal'],peers['whole'])
        out,err=run.stage('state-list',[bins['state'],'--list']); inventory=modules['census'].census(out,err)
        manifest=calibration_inventory(prior,inventory,native.IGNORED)
        run.freeze(a.raw/'controls.json',dict(rust=manifest,ignored={native.IGNORED:native.IGNORE_REASON},sdk=[SDK_CONTROL],
            legacy_python=native.PYTHON_CONTROLS,session_python=recipe.PYTHON_CONTROLS,copied_python=copied.PYTHON_CONTROLS,
            copied_runner=copied.RUNNER_CONTROLS,leaf_python=LEAF_CONTROLS,runner=RUNNER_CONTROLS))
        assert [len(x) for x in (native.PYTHON_CONTROLS,recipe.PYTHON_CONTROLS,copied.PYTHON_CONTROLS,copied.RUNNER_CONTROLS,LEAF_CONTROLS,RUNNER_CONTROLS)] == [18,26,10,4,10,7]
        out,err=run.stage('state-controls',[bins['state'],'--test-threads=1']); native.calibration_output(out,err,manifest)
        out,err=run.stage('sdk-list',[sdk,'--list']); inventory=modules['census'].census(out,err); assert SDK_CONTROL in inventory
        out,err=run.stage('sdk-control',[sdk,SDK_CONTROL,'--exact','--test-threads=1']); modules['census'].controls(out,err,[SDK_CONTROL],inventory)
        for name,path,names in (
            ('legacy-python-controls',ROOT/'evaluation/ordinary-module-native/controls.py',native.PYTHON_CONTROLS),
            ('session-python-controls',ROOT/'evaluation/ordinary-module-session/controls.py',recipe.PYTHON_CONTROLS),
            ('copied-python-controls',ROOT/'evaluation/ordinary-rust-invoke-native/controls.py',copied.PYTHON_CONTROLS),
            ('copied-runner-controls',ROOT/'evaluation/ordinary-rust-invoke-native/runner_controls.py',copied.RUNNER_CONTROLS),
            ('leaf-python-controls',HERE/'controls.py',LEAF_CONTROLS),('runner-controls',HERE/'runner_controls.py',RUNNER_CONTROLS)):
            out,err=run.stage(name,[tools['python'],'-B',path,'-v'])
            if name == 'legacy-python-controls': native.python_output(out,err)
            elif name == 'session-python-controls': recipe.python_controls(out,err)
            else: copied.python_controls(out,err,names)
        requests=[]
        for row in cohorts:
            kind=row['name']; cohort=a.raw/('native' if kind == 'legacy' else 'leaf-native'); cohort.mkdir()
            candidate,trusted=dsos[kind]; coords=[v for pair in geometry[kind]['selections'] for v in pair]
            argv=[bins['native'],'normal-rust-invoke-state',candidate,trusted,*coords,app_candidate,app_trusted,cohort/'output'] if kind == 'legacy' else [bins['native'],'normal-leaf-set-rust-state',candidate,trusted,app_candidate,app_trusted,cohort/'output',*coords]
            request=dict(argv=list(map(str,argv)),cwd=str(ROOT),env=env,stdout=str(cohort/'stdout.txt'),stderr=str(cohort/'stderr.txt'),
                cpu=run.cpus[1],pins=run.sources|run.tool_pins|run.retained)
            (copied.request_shape if kind == 'legacy' else request_shape)(request,run.cpus)
            value=run.freeze(cohort/'request.json',request); requests.append((request,value))
        for row,(request,value),checker in zip(cohorts,requests,(old,leaf)):
            execute_cohort(run,recipe,copied,row,request,value,checker,geometry[row['name']]['bodies'],caller)
        assert tuple(r['name'] for r in run.result['stages']) == STAGES
        run.result['sources_after']=run.freeze(a.raw/'sources-after.json',sources,cap=16*MIB)
        run.result['status']='LEAF_SET_WHOLE_NATIVE_LOCAL_COMPLETE'
    except BaseException as error:
        run.result['error']=type(error).__name__
    finally:
        run.budget.stopped()
        run.result.update(end_utc=dt.datetime.now(dt.timezone.utc).isoformat(),load_after=list(os.getloadavg()),
            custody_closed=run.safe,retained=dict(run.retained),tool_pins=dict(run.tool_pins),evidence_budget=run.budget.summary(),
            build_space_exclusions=[str(p) for p in run.build_scratch])
        seen={r['name']:r for r in run.result['stages']}
        run.result['planned_stages']=[seen.get(n,dict(name=n,status='UNRUN')) for n in STAGES]
        try:
            assert run.safe and not run.budget.exceeded
            run.closed_inventory(a.raw); assert run.budget.used <= recipe.EVIDENCE_LIMIT-recipe.FINAL_ALLOWANCE
            run.unchanged(); run.result['retention_verified']=True
        except BaseException as error:
            run.result.update(status='FAILED',retention_verified=False,final_error=type(error).__name__)
        # The projection reads retained memory only, never possibly live child files.
        try:
            run.result['public_projection']=run.freeze(a.raw/'public-result.json',public_projection(run.result),cap=16*MIB)
            run.unchanged()
        except BaseException as error:
            run.result.update(status='FAILED',retention_verified=False,projection_error=type(error).__name__)
        run.result.update(retained=dict(run.retained),evidence_budget=run.budget.summary())
        recipe.save(a.raw/'result.json',run.result,16*MIB)
    print(json.dumps(dict(status=run.result['status'],profile=PROFILE,
        cohorts=[dict(name=r['name'],status=r['status'],attempts=r['attempts'],observed_rows=len(r['observed'])) for r in cohorts],
        custody_closed=run.safe,external_owner_required=True,scope=SCOPE)))
    return 0 if run.result['status'] == 'LEAF_SET_WHOLE_NATIVE_LOCAL_COMPLETE' else 1


if __name__ == '__main__':
    if len(sys.argv) == 4 and sys.argv[1] == '--native-request':
        try:
            native_exec(Path(sys.argv[2]),sys.argv[3])
        except BaseException as error:
            print('LeafSet native exec FAILED: '+type(error).__name__,file=sys.stderr,flush=True)
            raise SystemExit(127)
    raise SystemExit(main())
