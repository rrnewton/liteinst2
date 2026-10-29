#!/usr/bin/env python3
"""Five fixed native/always-on pairs; descriptive elapsed time, no accuracy claim."""
import sys
if sys.flags.optimize:
    raise SystemExit('assertions required')
sys.dont_write_bytecode = True

import argparse
import csv
import datetime
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import traceback

MIB = 1048576
PROTOCOL = 'dc2925c6a562dcb444d824623fb2b5099621c23dc3280db757f3e81792b47671'
SCHEMA = '4715804d6e8965f91024cbcf64f16a936061722199f3a22a179b988f9eb75c3c'
PREFIX = 'normal::observer::throughput::tests::'
RUST = tuple(PREFIX+n for n in (
    'raw_clock_timespec_domains_and_u64_overflow',
    'timing_requires_all128_ordered_blocks_and_final_service_tail',
    'timing_preserves_zero_and_maximum_endpoints',
    'returns_require_each_ordered_value_and_helper_sum',
    'guard_and_request_mutations_refuse_before_checkpoint',
    'reused_batch_join_requires_full_identity_and_journal',
    'reused_report_join_requires_complete_population_and_history',
    'timing_appendix_has_exact_population_and_raw_sums'))
CHECKER = (
    'test_complete_modes_delegate_exact_prefix_and_retain_every_endpoint',
    'test_zero_and_maximal_endpoints_keep_unresolved_division',
    'test_exact_framing_order_literals_modes_and_cpu',
    'test_canonical_numbers_checked_arithmetic_and_enclosure_joins',
    'test_whole_old_prefix_corruption_remains_a_refusal',
    'test_source_local_import_and_optimization_guard')
CONTROLS = (
    'test_catalog_and_complete_requests_are_frozen_before_trial_one',
    'test_closure_joins_all_statuses_hashes_and_streams',
    'test_timer_identity_and_functional_join_are_required',
    'test_qualification_and_release_artifact_joins_are_exact',
    'test_completed_file_pins_never_refresh_drift',
    'test_closed_failure_continues_but_custody_failure_leaves_unrun',
    'test_pair_projection_keeps_zero_and_failed_members',
    'test_python_controls_require_exact_methods_and_counts',
    'test_projection_retains_all_outcomes_after_prerequisite_failure',
    'test_projection_retains_partial_evidence_without_custody_ratios')
TIMER_CONTROLS = (
    'test_actual_request_tail_record_budget_and_inner_clock_join',
    'test_exact_actual_arithmetic_zero_cpu_and_no_cpu_wall_filter',
    'test_pid_command_status_and_raw_derived_contradictions',
    'test_complete_canonical_grammar_and_integer_domains',
    'test_actual_nonzero_signal_exec_failure_and_excess_wall_never_pass')
STAGES = ('prerequisite', 'checker-controls', 'driver-controls', 'timer-controls',
          'rust-controls', 'timer-build')
TRIAL_FIELDS = ('trial','pair','position','mode','status','reason','cpu','pid','tid',
    'setup_ns','body_ns','service_ns','process_wall_ns','child_user_us','child_system_us',
    'child_cpu_us','stdout_sha256','stderr_sha256','result_sha256')
TIMING_FIELDS = ('trial','kind','index','start_ns','end_ns')
SCOPE = ('Fixed-work elapsed-wall observations; no warmup, retry, subtraction, '
    'outlier removal, performance threshold, confidence, accuracy or full-A5 claim. '
    'Segmented call-path spans include wrapper/loop work and 23 next-entry '
    'confirmations per block; 128 final confirmations/transfers remain in service. '
    'RAW collector clocks and MONOTONIC process clocks have different origins. '
    'The whole-process child includes taskset setup, initialization, output and exit. '
    'Prior strict 2 ms failures remain failures.')


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True, allow_nan=False)+'\n').encode('ascii')


def digest(path):
    h = hashlib.sha256(); count = 0
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(MIB), b''):
            count += len(block); h.update(block)
    return dict(bytes=count, sha256=h.hexdigest())


def stamp(path):
    s = path.lstat()
    assert stat.S_ISREG(s.st_mode) and not path.is_symlink()
    return (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)


class Pins:
    """Retain original hashes and file identities, including completed results."""
    def __init__(self):
        self.values = {}; self.identities = {}

    def retain(self, path, expected=None):
        value, identity = digest(path), stamp(path)
        if expected is not None: assert value == expected
        if path in self.values:
            assert value == self.values[path] and identity == self.identities[path]
        else:
            self.values[path] = value; self.identities[path] = identity
        return value

    def check(self):
        for path in self.values: self.retain(path)


def freeze(path, data, pins):
    with path.open('xb') as stream:
        stream.write(data); stream.flush(); os.fsync(stream.fileno())
    return pins.retain(path)


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def reservation_tag(value):
    assert type(value) is str and re.fullmatch('[a-z0-9-]{1,128}', value)
    return value


def catalog():
    modes = ('native', 'always-on', 'always-on', 'native', 'native',
             'always-on', 'always-on', 'native', 'native', 'always-on')
    return [dict(trial=i+1, pair=i//2+1, position=i%2+1, mode=mode)
            for i, mode in enumerate(modes)]


def request(argv, cwd, env, directory):
    return dict(argv=[str(v) for v in argv], cwd=str(cwd), env=dict(env, TMPDIR=str(directory/'tmp')),
        stdout=str(directory/'stdout.txt'), stderr=str(directory/'stderr.txt'),
        cpu_seconds=20, wall_seconds=30, file_bytes=MIB)


def check_request(value, expected):
    assert value == expected and set(value) == {'argv', 'cwd', 'env', 'stdout', 'stderr',
                                               'cpu_seconds', 'wall_seconds', 'file_bytes'}
    assert all(type(value[k]) is int for k in ('cpu_seconds', 'wall_seconds', 'file_bytes'))
    assert (value['cpu_seconds'], value['wall_seconds'], value['file_bytes']) == (20, 30, MIB)
    assert type(value['argv']) is list and value['argv'] and value['argv'][0].startswith('/')
    assert all(type(v) is str and '\0' not in v for v in value['argv'])


def timed_argv(taskset, timer, record, token, app, cpus):
    assert len(cpus) == 4 and cpus == sorted(set(cpus))
    assert all(type(c) is int and 0 <= c <= 1023 for c in cpus)
    inner = [str(taskset), '--cpu-list', str(cpus[1]), *map(str, app)]
    return [str(taskset), '--cpu-list', str(cpus[2]), str(timer), str(record),
            token(inner), '--', *inner], inner


def outer_closed(closed, expected):
    assert type(closed['exit_code']) is int and closed['exit_code'] == expected
    assert closed['termination'] is None and closed['cleanup_complete'] is True
    assert type(closed['reaped_descendants']) is int and closed['reaped_descendants'] == 0


def closed_request(closed, receipt, log, files, request_sha, helper_sha, cap):
    direct = receipt['exit']; assert type(direct) is int
    outer_closed(closed, 0 if direct == 0 else 1)
    assert closed['private_log_sha256'] == files['parent.log']['sha256']
    assert receipt['wall_timeout'] is False and receipt['inputs_unchanged'] is True
    assert receipt['absence_proof'] == 'ECHILD'
    assert receipt['unexpected_descendants'] == receipt['cleanup_events'] == []
    assert receipt['cleanup_error'] is receipt['aborted'] is None
    assert receipt['request_sha256'] == request_sha and receipt['helper_sha256'] == helper_sha
    assert log == dict(exit=direct, wall_timeout=False, absence_proof='ECHILD',
                       descendants=0, success=direct == 0)
    for name in ('stdout', 'stderr'):
        assert receipt[name+'_sha256'] == files[name+'.txt']['sha256']
        assert files[name+'.txt']['bytes'] <= cap
    return direct


def timer_status(timer, direct):
    # parse() already checks the complete raw wait4/status/token arithmetic.
    assert timer['exec_errno'] == 0 and 0 < timer['process_wall_ns'] <= 30_000_000_000
    ok = timer['exit'] == timer['signal'] == timer['core'] == timer['wait_status'] == 0
    assert direct == (0 if ok else 1)
    return ok


def observation_join(value, timer, mode, cpu):
    assert value['status'] == 'TIMING_COMPLETE' and value['mode'] == mode and value['cpu'] == cpu
    f = value['functional']
    assert f['status'] == 'FUNCTIONAL_PASS' and f['mode'] == mode
    assert f['pid'] == f['tid'] == timer['child_pid'] == timer['wait_pid']
    assert (f['calls'], f['helper_calls'], f['instructions'], len(f['rows'])) == (3072, 1536, 614400, 3072)
    assert (f['records'], f['batches']) == ((0, 0) if mode == 'native' else (3072, 128))
    assert value['clock'] == 'CLOCK_MONOTONIC_RAW' and value['units'] == 'ns'
    assert value['timing_rows'] == 130 and len(value['body']) == 128


def start_trial(rows, index):
    assert len(rows) == 10 and 0 <= index < 10
    for row, key in zip(rows, catalog()):
        assert all(row[k] == v for k, v in key.items())
    assert all(r['status'] in ('PASS', 'FAILED') and r.get('closed') is True for r in rows[:index])
    assert all(r['status'] == 'UNRUN' for r in rows[index:])
    rows[index]['status'] = 'FAILED'


def stop_remaining(rows, reason):
    for row in rows:
        if row['status'] == 'UNRUN': row['reason'] = reason


def pairs(rows):
    assert len(rows) == 10
    result = []
    for i in range(5):
        two = rows[2*i:2*i+2]
        assert all(all(r[k] == v for k, v in key.items()) for r, key in zip(two, catalog()[2*i:2*i+2]))
        row = dict(pair=i+1, status='UNRESOLVED_MEMBER', body=None, service=None)
        if all(r['status'] == 'PASS' and r.get('closed') is True for r in two):
            n = next(r for r in two if r['mode'] == 'native')
            a = next(r for r in two if r['mode'] == 'always-on')
            row['status'] = 'FUNCTIONALLY_VALID_PAIR'
            for kind in ('body', 'service'):
                numerator, denominator = a[kind+'_ns'], n[kind+'_ns']
                assert type(numerator) is type(denominator) is int and 0 <= numerator < 2**64 and 0 <= denominator < 2**64
                row[kind] = dict(status='EXACT_RATIO' if denominator else 'UNRESOLVED_ZERO',
                    numerator=numerator, denominator=denominator)
        result.append(row)
    return result


def projection(rows, result_pins, complete):
    """Project retained memory only; no file or native authority is acquired here."""
    assert type(complete) is bool and len(rows) == 10
    assert all(all(r[k] == v for k, v in key.items()) for r, key in zip(rows, catalog()))
    assert all(r['status'] in ('PASS', 'FAILED', 'UNRUN') for r in rows)
    assert all(type(i) is int and 1 <= i <= 10 for i in result_pins)
    for pin in result_pins.values():
        assert type(pin['bytes']) is int and pin['bytes'] >= 0
        assert re.fullmatch('[0-9a-f]{64}', pin['sha256'])
    if complete:
        assert all(r['status'] in ('PASS', 'FAILED') and r.get('closed') is True for r in rows)
        assert set(result_pins) == set(range(1, 11))
        for r in rows:
            assert all(k in r['timer'] for k in ('process_wall_ns','child_user_us','child_system_us','child_cpu_us'))
            assert all('sha256' in r['files'][k+'.txt'] for k in ('stdout','stderr'))
        outcomes = pairs(rows)
    else:
        outcomes = [dict(pair=i+1, status='UNQUALIFIED_CUSTODY' if all(
            r['status'] == 'PASS' and r.get('closed') is True for r in rows[2*i:2*i+2])
            else 'UNRESOLVED_MEMBER', body=None, service=None) for i in range(5)]
    trials = []
    for r in rows:
        row = {k:r.get(k) for k in TRIAL_FIELDS}
        row.update({k:r.get('timer', {}).get(k) for k in
            ('process_wall_ns','child_user_us','child_system_us','child_cpu_us')})
        row.update({k+'_sha256':r.get('files', {}).get(k+'.txt', {}).get('sha256')
                    for k in ('stdout', 'stderr')})
        row['result_sha256'] = result_pins.get(r['trial'], {}).get('sha256')
        trials.append(row)
    timing = [dict(trial=r['trial'], **{k:t[k] for k in TIMING_FIELDS[1:]})
              for r in rows for t in r.get('timing', [])]
    return dict(status='DESCRIPTIVE_PROJECTION' if complete else 'INCOMPLETE_UNQUALIFIED',
                trials=trials, timing=timing, pairs=outcomes)


def python_controls(stdout, stderr, names):
    assert stdout == b'' and len(names) == len(set(names))
    count = len(names)
    assert re.fullmatch(rb'\.{'+str(count).encode()+rb'}\n-+\nRan '+str(count).encode()+rb' tests in [0-9]+\.[0-9]+s\n\nOK\n', stderr)


def python_census(source, class_name, names):
    # Static inventory complements the unchanged default unittest transcript.
    import ast
    tree = ast.parse(source)
    classes = [n for n in tree.body if isinstance(n, ast.ClassDef)]
    methods = [(c.name, n.name) for c in classes for n in c.body
               if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name.startswith('test_')]
    assert len(methods) == len(names) and set(methods) == {(class_name, n) for n in names}


def qualification(value, revision, names):
    assert value['revision'] == revision and value['status'] == 'PASS' and value['stage'] == 'complete'
    assert len(names) == 34 and tuple(r['name'] for r in value['stages']) == tuple(names)
    assert all(r['status'] == 'PASS' for r in value['stages'])
    assert value['closure'] == dict(owned_stages=34, nested_normal_helpers=46, nested_outer_owners=48, rescues=0)
    offset = 10
    for label, count in (('reference_exact', 13), ('reference_work', 3), ('reference_leg', 4), ('observer_work', 4)):
        g = value[label]
        assert g['status'] == 'PASS' and len(g['stages']) == count and all(r['status'] == 'PASS' for r in g['stages'])
        assert tuple(r['name'] for r in g['stages']) == tuple(names[offset:offset+count]); offset += count
        assert g['closure'] == dict(owned_stages=count, normal_helpers=count, outer_owners=count, rescues=0)
    assert all(value['reference_exact'][n]['status'] == 'PASS' for n in ('old_exact', 'reference'))
    assert value['reference_work']['collector']['status'] == 'PASS'
    assert [(r['phase'], r['trial'], r['leg'], r['calls'], r['status']) for r in value['reference_leg']['legs']] == [
        ('qualification', 1, 'original', 24, 'PASS'), ('qualification', 1, 'installed', 24, 'PASS')]
    assert value['native']['pairs'] == 17 and value['native']['children'] == 34


def release_product(messages, repo, authority, actual):
    assert messages[-1] == dict(reason='build-finished', success=True)
    found = [m for m in messages if m.get('reason') == 'compiler-artifact'
             and m['target']['name'] == 'ordinary-interval' and m['profile']['test']]
    assert len(found) == 1
    p = found[0]; binary = Path(p['executable'])
    profile = dict(opt_level='3', debuginfo=0, test=True, debug_assertions=True, overflow_checks=True)
    assert p['profile'] == profile and type(p['fresh']) is bool
    assert p['manifest_path'] == str(repo/'tools/rapid-profiler/Cargo.toml')
    assert p['target']['src_path'] == str(repo/'tools/rapid-profiler/ordinary-interval/main.rs')
    assert p['target']['kind'] == ['bin'] and p['target']['crate_types'] == ['bin']
    assert binary.parent == repo/'target/release/deps' and re.fullmatch('ordinary_interval-[0-9a-f]+', binary.name)
    assert authority == dict(binary=actual, profile=profile, cargo_fresh=p['fresh'])
    return binary


def qualified_inputs(repo, qualified, revision, env, cpus, before, tools, pins,
                     prior, census, fixture, control_prefix, control_names):
    """Authenticate an already owned, closed prerequisite; never launch a process."""
    def retained_json(path):
        pins.retain(path); return json.loads(path.read_bytes())
    old = retained_json(qualified/'result.json')
    stages = prior.STAGES+prior.REFERENCE_STAGES+prior.REFERENCE_WORK_STAGES+prior.REFERENCE_LEG_STAGES+prior.OBSERVER_WORK_STAGES
    qualification(old, revision, stages)
    source_before = retained_json(qualified/'sources-before.json')
    assert source_before == retained_json(qualified/'sources-after.json')
    assert all(before[n] == h for n, h in source_before.items())
    assert old['sources'] == dict(count=len(source_before), manifest=pins.values[qualified/'sources-before.json'])
    nested = qualified/'strnlen-prerequisite'
    pins.retain(nested/'result.json', old['prerequisite']['result'])
    pins.retain(qualified/'prerequisite-command.json', old['prerequisite']['command'])
    pins.retain(qualified/'prerequisite-closed.json', old['prerequisite']['closed'])
    inherited_closed = retained_json(qualified/'prerequisite-closed.json'); outer_closed(inherited_closed, 0)
    assert pins.retain(qualified/'prerequisite.log')['sha256'] == inherited_closed['private_log_sha256']
    nested_result = retained_json(nested/'result.json')
    assert nested_result['revision'] == revision and nested_result['status'] == 'PASS'
    private = retained_json(nested/'private-environment.json')
    assert private['env'] == env and private['affinity'] == cpus
    for name, value in private['tools'].items():
        path = Path(value); assert path.resolve(strict=True) == path
        pins.retain(path, old['tools'][name])
        if name in tools: assert path == tools[name]
    # Authenticate every completed outer stage and the borrowed Cargo build/list.
    def old_stage(directory, record):
        fs = {n: pins.retain(directory/n) for n in ('request.json', 'receipt.json', 'parent-closed.json', 'parent.log', 'stdout.txt', 'stderr.txt')}
        for key, file in (('request','request.json'), ('receipt','receipt.json'), ('stdout','stdout.txt'), ('stderr','stderr.txt')):
            assert record[key] == fs[file]
        assert record.get('closed', record.get('parent_closed')) == fs['parent-closed.json']
        r = retained_json(directory/'request.json')
        assert r['cwd'] == str(repo) and r['env'] == dict(env, TMPDIR=str(directory/'tmp'))
        assert r['stdout'] == str(directory/'stdout.txt') and r['stderr'] == str(directory/'stderr.txt')
        assert (r['cpu_seconds'], r['wall_seconds'], r['file_bytes']) == (record['cpu_seconds'], record['wall_seconds'], record['file_bytes'])
        assert closed_request(retained_json(directory/'parent-closed.json'), retained_json(directory/'receipt.json'),
            json.loads((directory/'parent.log').read_bytes()), fs, fs['request.json']['sha256'],
            before['tools/unwind-oracle/bounded_command.py']['sha256'], r['file_bytes']) == 0
    for s in old['stages']: old_stage(qualified/s['name'], s)
    for suffix in ('build', 'list'):
        found = [s for s in nested_result['stages'] if s['name'] == 'work-validator-'+suffix]
        assert len(found) == 1 and found[0]['status'] == 'PASS'
        old_stage(nested/('work-validator-'+suffix), found[0])
    messages = [json.loads(line) for line in (nested/'work-validator-build/stdout.txt').read_bytes().splitlines()]
    products = [m for m in messages if m.get('reason') == 'compiler-artifact' and m['target']['name'] == 'ordinary-interval' and m['profile']['test']]
    assert len(products) == 1
    test_binary = Path(products[0]['executable']); assert test_binary.resolve(strict=True) == test_binary
    assert release_product(messages, repo, nested_result['artifacts']['work-validator'], pins.retain(test_binary)) == test_binary
    inventory = census.census((nested/'work-validator-list/stdout.txt').read_bytes(), (nested/'work-validator-list/stderr.txt').read_bytes())
    assert {n for n in inventory if n.startswith(control_prefix)} == set(control_names)
    binary = repo/'target/release/ordinary-interval'; pins.retain(binary, old['artifacts']['ordinary-interval'])
    subject, trusted = qualified/'reference-exact-candidate.so', qualified/'reference-exact-final.so'
    selection = qualified/'reference-exact-selection.json'; caller_candidate, caller = qualified/'caller-candidate.so', qualified/'caller.so'
    cohorts = old['observer_work']['modes']; assert [(c['mode'], c['status']) for c in cohorts] == [('native','PASS'), ('always-on','PASS')]
    authority = cohorts[0]
    for p, field in ((binary,'binary'), (trusted,'subject'), (selection,'selection'), (caller_candidate,'helper_candidate'), (caller,'helper')):
        pins.retain(p, authority[field])
    pins.retain(subject, old['reference_exact']['subject']['candidate'])
    for c in cohorts:
        assert c['calls'] == c['observation']['calls'] == 3072
        assert c['observation']['helper_calls'] == 1536 and c['observation']['instructions'] == 614400
        assert all(c[k] == authority[k] for k in ('binary','subject','selection','helper','helper_candidate'))
        assert (c['process_cpu_seconds'], c['process_wall_seconds'], c['file_bytes']) == (20,30,MIB)
    assert caller_candidate.read_bytes() == caller.read_bytes()
    assert stamp(caller_candidate)[:2] != stamp(caller)[:2] and pins.values[caller] == old['artifacts']['caller']
    details = retained_json(selection); assert details['revision'] == revision
    selected = fixture.authenticate(subject, trusted, details['elf_va'], 37, selection, pins.values[selection]['sha256'])
    assert selected == {k:v for k,v in details.items() if k != 'revision'}
    artifacts = {label:pins.values[p] for label,p in (
        ('binary',binary), ('subject',subject), ('trusted',trusted), ('selection',selection),
        ('caller_candidate',caller_candidate), ('caller',caller), ('libtest',test_binary))}
    prerequisite = dict(result=pins.values[qualified/'result.json'], closure=old['closure'], tools=old['tools'])
    return dict(binary=binary, test_binary=test_binary, inventory=inventory,
        subject=subject, trusted=trusted, selection=selection,
        caller_candidate=caller_candidate, caller=caller, details=details,
        selected=selected, artifacts=artifacts, prerequisite=prerequisite, old=old)


def csv_bytes(fields, rows):
    text = io.StringIO(newline=''); writer = csv.DictWriter(text, fieldnames=fields, lineterminator='\n')
    writer.writeheader(); writer.writerows(rows)
    return text.getvalue().encode('ascii')


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--revision', required=True); ap.add_argument('--reservation-tag', required=True)
    for name in ('raw', 'toolchain', 'user-home', 'cargo-home'): ap.add_argument('--'+name, type=Path, required=True)
    a = ap.parse_args(); repo = Path(__file__).resolve().parents[3]
    assert re.fullmatch('[0-9a-f]{40}', a.revision)
    reservation_tag(a.reservation_tag)
    for path in (repo, a.toolchain, a.user_home, a.cargo_home):
        assert path.is_absolute() and path.resolve(strict=True) == path and path.is_dir()
    assert a.raw.is_absolute() and a.raw.is_relative_to(repo/'ignored') and not a.raw.exists()
    assert a.raw.parent.resolve(strict=True) == a.raw.parent
    env = dict(HOME=str(a.user_home), CARGO_HOME=str(a.cargo_home),
        PATH=str(a.toolchain/'bin')+':/usr/bin:/bin', RUSTC=str(a.toolchain/'bin/rustc'),
        CC=str(Path('/usr/bin/gcc').resolve(strict=True)), CARGO_TARGET_DIR=str(repo/'target'),
        CARGO_INCREMENTAL='0', CARGO_BUILD_JOBS='4', CARGO_NET_OFFLINE='true',
        CARGO_PROFILE_RELEASE_OPT_LEVEL='3', CARGO_PROFILE_RELEASE_DEBUG='0',
        CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS='true', CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS='true',
        CARGO_TERM_COLOR='never', LC_ALL='C', PYTHONDONTWRITEBYTECODE='1', PYTHONNOUSERSITE='1')
    def git(*args):
        data = subprocess.check_output(['/usr/bin/git', '-C', str(repo), *args], env=env, timeout=15)
        assert len(data) <= 4*MIB
        return data
    assert git('rev-parse', '--show-toplevel').decode().strip() == str(repo)
    assert git('rev-parse', 'HEAD').decode().strip() == a.revision and git('status', '--porcelain', '--untracked-files=no') == b''
    required = {'evaluation/admission/processes.py', 'tools/unwind-oracle/bounded_command.py', 'tests/call_tree_truth.rs'}
    required.update('tools/rapid-profiler/'+p for p in (
        'verify_normal_interval.py', 'selected-work/check_output.py', 'selected-work/provenance.py',
        'ordinary-interval/normal/observer/throughput.rs', 'ordinary-interval/normal/observer/throughput/tests.rs',
        'normal-work/throughput_probe.py', 'normal-work/test_throughput_probe.py',
        'normal-work/throughput_work.py', 'normal-work/test_throughput_work.py',
        'normal-work/observer_work.py', 'normal-work/exact_fixture.py',
        'tree-work/process_timer.c', 'tree-work/process_timing.py', 'tree-work/test_process_timing.py'))
    names = git('ls-files', '-z', '--', 'src', 'tests/support', 'tools/rapid-profiler',
        'Cargo.toml', 'Cargo.lock', 'README.md', 'build.rs', ':(glob)**/Cargo.toml', *sorted(required)).decode().rstrip('\0').split('\0')
    assert all(names) and len(names) == len(set(names)) and required.issubset(names)
    pins = Pins(); before = {name: pins.retain(repo/name) for name in names}
    assert all((repo/n).read_bytes() == git('show', a.revision+':'+n) for n in names)
    tools = {name: path.resolve(strict=True) for name, path in (
        ('python', Path(sys.executable)), ('gcc', Path('/usr/bin/gcc')), ('taskset', Path('/usr/bin/taskset')),
        ('git', Path('/usr/bin/git')), ('cargo', a.toolchain/'bin/cargo'), ('rustc', a.toolchain/'bin/rustc'))}
    tool_pins = {name: pins.retain(p) for name, p in tools.items()}
    # Complete local source/tool authentication precedes every project import.
    processes = load('throughput_processes', repo/'evaluation/admission/processes.py')
    prior = load('throughput_prior', repo/'tools/rapid-profiler/verify_normal_interval.py')
    census = load('throughput_census', repo/'tools/rapid-profiler/selected-work/check_output.py')
    timing = load('throughput_timing', repo/'tools/rapid-profiler/tree-work/process_timing.py')
    checker = load('throughput_checker', repo/'tools/rapid-profiler/normal-work/throughput_work.py')
    fixture = load('throughput_fixture', repo/'tools/rapid-profiler/normal-work/exact_fixture.py')
    cpus = sorted(os.sched_getaffinity(0)); assert len(cpus) == 4
    assert all(0 <= c <= 1023 for c in cpus)
    expected_affinity = cpus[:]
    a.raw.mkdir(mode=0o700)
    logs_root = repo/'target/evaluation'; logs_root.mkdir(parents=True, exist_ok=True)
    assert logs_root.resolve(strict=True) == logs_root
    logs = Path(tempfile.mkdtemp(prefix='throughput-probe-', dir=logs_root))
    result = dict(schema=1, status='FAILED', revision=a.revision, protocol_sha256=PROTOCOL,
        schema_sha256=SCHEMA, scope=SCOPE, stage='setup',
        stages=[dict(name=n, status='UNRUN') for n in STAGES],
        trials=[dict(key, status='UNRUN') for key in catalog()],
        reservation=dict(tag=a.reservation_tag, inherited_cpus=cpus, producer_cpu=cpus[0],
            application_cpu=cpus[1], timer_cpu=cpus[2], verified=False,
            authority='Outer root wrapper must join exact command/tag, allocator transcript and hard AllowedCPUs. Tag/affinity do not establish reservation or quiet hardware.'),
        outer_owner_required=dict(wall_seconds=1200, log_bytes=8*MIB),
        sources=dict(count=len(before), manifest=freeze(a.raw/'sources-before.json', encoded(before), pins)),
        tools={n: dict(path=str(p), **tool_pins[n]) for n, p in tools.items()})
    result['pairs'] = pairs(result['trials'])
    def save():
        tmp = a.raw/'result.tmp'; tmp.write_bytes(encoded(result)); tmp.replace(a.raw/'result.json')
    def unchanged():
        assert git('rev-parse', 'HEAD').decode().strip() == a.revision and git('status', '--porcelain', '--untracked-files=no') == b''
        assert sorted(os.sched_getaffinity(0)) == expected_affinity
        pins.check()
    def observation():
        assert sorted(os.sched_getaffinity(0)) == expected_affinity
        return dict(utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            affinity=expected_affinity[:], reservation_tag=a.reservation_tag,
            load_average=list(os.getloadavg()))
    def retained_json(path):
        pins.retain(path); return json.loads(path.read_bytes())
    def bounded(directory, expected_request, row):
        unchanged(); check_request(retained_json(directory/'request.json'), expected_request)
        helper = repo/'tools/unwind-oracle/bounded_command.py'
        parent = [str(tools['python']), '-B', str(helper), '--request', str(directory/'request.json'), '--receipt', str(directory/'receipt.json')]
        expected_command = dict(argv=parent, env=env, wall_seconds=55, log_bytes=MIB,
            request=pins.values[directory/'request.json'])
        assert retained_json(directory/'command.json') == expected_command
        row['before'] = observation(); save()
        log = logs/(directory.name+'.log')
        closed = processes.run_command(parent, env, log, 55, MIB)
        freeze(directory/'parent-closed.json', encoded(closed), pins)
        freeze(directory/'parent.log', log.read_bytes(), pins)
        row['after'] = observation(); row['actual_parent_exit'] = closed['exit_code']; save()
        # Do not read possibly still-written child files when outer custody failed.
        outer_closed(closed, closed['exit_code'])
        files = {n: pins.retain(directory/n) for n in ('request.json', 'command.json', 'parent-closed.json', 'parent.log', 'receipt.json', 'stdout.txt', 'stderr.txt')}
        row['files'] = files; save()
        direct = closed_request(closed, retained_json(directory/'receipt.json'),
            json.loads((directory/'parent.log').read_bytes()), files,
            pins.values[directory/'request.json']['sha256'], before['tools/unwind-oracle/bounded_command.py']['sha256'], MIB)
        row['actual_exit'] = direct
        unchanged(); return direct
    def prepare(directory, argv):
        directory.mkdir(); (directory/'tmp').mkdir()
        r = request(argv, repo, env, directory); check_request(r, r)
        freeze(directory/'request.json', encoded(r), pins)
        parent = [str(tools['python']), '-B', str(repo/'tools/unwind-oracle/bounded_command.py'),
            '--request', str(directory/'request.json'), '--receipt', str(directory/'receipt.json')]
        freeze(directory/'command.json', encoded(dict(argv=parent, env=env, wall_seconds=55,
            log_bytes=MIB, request=pins.values[directory/'request.json'])), pins)
        return r
    def stage(name, argv, validate):
        row = result['stages'][STAGES.index(name)]; assert row['status'] == 'UNRUN'
        assert all(r['status'] == 'PASS' for r in result['stages'][:STAGES.index(name)])
        result['stage'] = name; row['status'] = 'FAILED'; save()
        d = a.raw/name
        try:
            r = prepare(d, argv); assert bounded(d, r, row) == 0
            validate(d); unchanged(); row['status'] = 'PASS'
        finally:
            freeze(d/'result.json', encoded(row), pins); save()
    def export_projection(directory, complete):
        # Failure finalization consults retained mappings, never possibly live files.
        result_pins = {r['trial']:pins.values[p] for r in result['trials']
            if (p := a.raw/('trial-%02d'%r['trial'])/'result.json') in pins.values}
        view = projection(result['trials'], result_pins, complete)
        directory.mkdir(); result['pairs'] = view['pairs']
        exports = dict(trials=freeze(directory/'trials.csv', csv_bytes(TRIAL_FIELDS,view['trials']), pins),
            timing=freeze(directory/'timing.csv', csv_bytes(TIMING_FIELDS,view['timing']), pins),
            pairs=freeze(directory/'pairs.json', encoded(view['pairs']), pins))
        result['exports'] = exports
        stage_results = {'prerequisite':pins.values.get(a.raw/'prerequisite-result.json')}
        stage_results.update({n:pins.values.get(a.raw/n/'result.json') for n in STAGES[1:]})
        if complete:
            assert all(pin is not None for pin in stage_results.values())
            assert all(k in result for k in ('prerequisite','artifacts','catalog'))
            assert all('before' in r and 'after' in r for r in result['trials'])
        receipt = dict(status=view['status'], trial_outcome=result['status'], revision=a.revision,
            protocol_sha256=PROTOCOL, schema_sha256=SCHEMA,
            scope=SCOPE, reservation=result['reservation'], outer_owner_required=result['outer_owner_required'],
            completion_authority='Require final private result plus root-authenticated final source and normal outer closure; this projection alone proves neither driver completion nor reservation.',
            prerequisite=result.get('prerequisite'), stage_results=stage_results,
            stage=result['stage'], stage_statuses=[dict(name=s['name'],status=s['status']) for s in result['stages']],
            failure=result.get('failure'), error_type=result.get('error_type'),
            sources=dict(result['sources'], after=result['sources'].get('after')), tools=tool_pins,
            artifacts=result.get('artifacts'), catalog=result.get('catalog'), exports=exports,
            trials=10, pairs=5, timing_rows=len(view['timing']),
            observations=[dict(trial=r['trial'],before=r.get('before'),after=r.get('after')) for r in result['trials']])
        result['public_receipt'] = freeze(directory/'receipt.json', encoded(receipt), pins)
    projection_pending = False
    active_trial = None
    try:
        row = result['stages'][0]; row['status'] = 'FAILED'; result['stage'] = 'prerequisite'; save()
        qualified = a.raw/'qualification'
        argv = [str(tools['python']), '-B', str(repo/'tools/rapid-profiler/verify_normal_interval.py'),
            '--revision', a.revision, '--raw', str(qualified), '--toolchain', str(a.toolchain),
            '--user-home', str(a.user_home), '--cargo-home', str(a.cargo_home),
            '--reference-exact', '--reference-work', '--reference-leg', '--observer-work']
        freeze(a.raw/'prerequisite-command.json', encoded(dict(argv=argv, env=env, wall_seconds=1200, log_bytes=8*MIB, affinity=cpus)), pins)
        closed = processes.run_command(argv, env, logs/'prerequisite.log', 1200, 8*MIB)
        freeze(a.raw/'prerequisite-closed.json', encoded(closed), pins)
        freeze(a.raw/'prerequisite.log', (logs/'prerequisite.log').read_bytes(), pins)
        row['actual_exit'] = closed['exit_code']; save()
        outer_closed(closed, closed['exit_code'])
        assert pins.values[a.raw/'prerequisite.log']['sha256'] == closed['private_log_sha256']
        row['files'] = {n:pins.values[a.raw/n] for n in ('prerequisite-command.json','prerequisite-closed.json','prerequisite.log')}
        if (qualified/'result.json').exists(): row['result'] = pins.retain(qualified/'result.json')
        save(); outer_closed(closed, 0)
        inputs = qualified_inputs(repo, qualified, a.revision, env, cpus, before, tools,
            pins, prior, census, fixture, PREFIX, RUST)
        binary, test_binary, inventory = (inputs[n] for n in ('binary', 'test_binary', 'inventory'))
        subject, trusted, selection = (inputs[n] for n in ('subject', 'trusted', 'selection'))
        caller_candidate, caller = (inputs[n] for n in ('caller_candidate', 'caller'))
        details, selected = inputs['details'], inputs['selected']
        result['artifacts'], result['prerequisite'] = inputs['artifacts'], inputs['prerequisite']
        unchanged(); row['status'] = 'PASS'; freeze(a.raw/'prerequisite-result.json', encoded(row), pins); save()
        tree = repo/'tools/rapid-profiler/tree-work'; work = repo/'tools/rapid-profiler/normal-work'
        for name, source, klass, methods in (
            ('checker-controls',work/'test_throughput_work.py','Controls',CHECKER),
            ('driver-controls',work/'test_throughput_probe.py','Controls',CONTROLS),
            ('timer-controls',tree/'test_process_timing.py','ProcessTiming',TIMER_CONTROLS)):
            python_census(source.read_bytes(), klass, methods)
            stage(name, [tools['python'],'-B',source], lambda d, methods=methods:
                python_controls((d/'stdout.txt').read_bytes(), (d/'stderr.txt').read_bytes(), methods))
        stage('rust-controls', [test_binary,*RUST,'--exact','--test-threads=1'], lambda d:
            census.controls((d/'stdout.txt').read_bytes(), (d/'stderr.txt').read_bytes(), RUST, inventory))
        timer = a.raw/'process-timer'
        def built(d):
            assert (d/'stdout.txt').read_bytes() == (d/'stderr.txt').read_bytes() == b''
            assert 0 < pins.retain(timer)['bytes'] <= MIB
        stage('timer-build', [tools['gcc'],'-O3','-std=c11','-Wall','-Wextra','-Werror',tree/'process_timer.c','-o',timer], built)
        result['artifacts']['timer'] = pins.values[timer]
        plans = []
        for key in catalog():
            d = a.raw/('trial-%02d'%key['trial'])
            app = [binary,'normal-observer-throughput',key['mode'],subject,trusted,str(details['elf_va']),'37',caller_candidate,caller]
            argv, inner = timed_argv(tools['taskset'], timer, d/'timing.txt', timing.token, app, cpus)
            r = prepare(d, argv)
            plans.append(dict(key, app_argv=inner, request=r, request_digest=pins.values[d/'request.json']))
        result['catalog'] = freeze(a.raw/'catalog.json', encoded(plans), pins)
        os.sched_setaffinity(0, {cpus[0]}); expected_affinity = [cpus[0]]; unchanged()
        for index, plan in enumerate(plans):
            unchanged(); assert retained_json(a.raw/'catalog.json') == plans
            assert fixture.authenticate(subject, trusted, details['elf_va'], 37, selection, pins.values[selection]['sha256']) == selected
            start_trial(result['trials'], index); row = result['trials'][index]
            active_trial = a.raw/('trial-%02d'%row['trial']); result['stage'] = active_trial.name; save()
            direct = bounded(active_trial, plan['request'], row)
            pins.retain(active_trial/'timing.txt')
            measured = timing.parse((active_trial/'timing.txt').read_bytes(), plan['app_argv'])
            normal_exit = timer_status(measured, direct)
            row['timer'] = measured
            try:
                parsed = checker.check((active_trial/'stdout.txt').read_bytes(), (active_trial/'stderr.txt').read_bytes(), row['mode'])
            except AssertionError as error:
                # A taskset child status alone does not prove APP exec/identity.
                raise AssertionError('APP_EXEC_UNCONFIRMED') from error
            observation_join(parsed, measured, row['mode'], cpus[1])
            row.update(status='PASS' if normal_exit else 'FAILED', closed=True,
                reason=None if normal_exit else 'FUNCTIONAL_EXIT',
                cpu=parsed['cpu'], pid=parsed['functional']['pid'], tid=parsed['functional']['tid'],
                setup_ns=parsed['setup_ns'], body_ns=parsed['body_ns'], service_ns=parsed['service_ns'],
                timing=[parsed['setup'],*parsed['body'],parsed['service']], division_status=parsed['division_status'])
            row['files']['timing.txt'] = pins.values[active_trial/'timing.txt']
            unchanged(); freeze(active_trial/'result.json', encoded(row), pins)
            active_trial = None; save()
        unchanged()
        result['sources']['after'] = freeze(a.raw/'sources-after.json', encoded({n:digest(repo/n) for n in names}), pins)
        unchanged()
        result['status'] = 'COMPLETE' if all(r['status'] == 'PASS' for r in result['trials']) else 'COMPLETE_WITH_FAILURES'
        result['stage'] = 'complete'
        projection_pending = True
        export_projection(a.raw/'public-pending', True)
        unchanged()
        assert not (a.raw/'public').exists()
        (a.raw/'public-pending').rename(a.raw/'public')
    except BaseException as error:
        result['status'] = 'FAILED'; result['error_type'] = type(error).__name__
        reason = 'APP_EXEC_UNCONFIRMED' if str(error) == 'APP_EXEC_UNCONFIRMED' else 'SHARED_AUTHORITY_OR_CUSTODY_FAILURE'
        stop_remaining(result['trials'], reason)
        result['failure'] = freeze(a.raw/'failure.txt', traceback.format_exc().encode('utf-8'), pins)
        if active_trial is not None and active_trial/'result.json' not in pins.values:
            failed = result['trials'][int(active_trial.name[-2:])-1]
            failed.update(status='FAILED', reason=reason)
            freeze(active_trial/'result.json', encoded(failed), pins)
        if projection_pending:
            result['withheld_projection'] = dict(directory='public-pending',
                exports=result.get('exports'), receipt=result.get('public_receipt'))
        export_projection(a.raw/'public', False)
    finally:
        save()
    print('throughput-probe '+result['status']+' stage='+result['stage'])
    return 0 if result['status'] == 'COMPLETE' else 1


if __name__ == '__main__':
    raise SystemExit(main())
