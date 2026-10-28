#!/usr/bin/env python3
"""Release-build and verify ordinary native state pairs, then functional raw ticks."""
import argparse
import csv
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import traceback

MIB = 1048576
LENGTHS = [1, 2, 17, 64, 3, 63, 7, 32]
SCOPE = '# raw callback-positioned RDTSCP ticks; uncalibrated, includes instrumentation/descheduling; no accuracy or nanosecond claim'
HEADER = 'ordinal,length,owner,generation,invocation,ret_offset,native_value,value,start_ticks,end_ticks,start_aux,end_aux,elapsed_ticks'
PASS = 'ordinary-interval PASS originals=8 calls=8 entries=8 returns=8 completed=6 unsampled=2 raw_rows=8 reports=4+2 short_ret_refused=true input_unchanged=true joined=true'
CFLAGS = ['-O2', '-fPIC', '-shared', '-nostdlib', '-fno-builtin', '-fno-stack-protector', '-fomit-frame-pointer',
    '-fno-tree-vectorize', '-fno-tree-slp-vectorize', '-fno-asynchronous-unwind-tables', '-fno-unwind-tables',
    '-fcf-protection=none', '-Wl,-z,now', '-Wl,-z,noexecstack']


def digest(path):
    owner = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), 'rb') as stream:
        before = os.fstat(stream.fileno()); assert stat.S_ISREG(before.st_mode)
        result = hashlib.sha256()
        for block in iter(lambda: stream.read(MIB), b''): result.update(block)
        assert owner(before) == owner(os.fstat(stream.fileno())) == owner(Path(path).lstat())
    return dict(sha256=result.hexdigest(), bytes=before.st_size)


def save(path, value):
    with path.open('x') as stream: json.dump(value, stream, indent=2, sort_keys=True, allow_nan=False); stream.write('\n')


def output(data):
    assert data.endswith(b'\n') and b'\r' not in data
    lines = data.decode('ascii').splitlines()
    assert len(lines) == 11 and lines[0] == SCOPE and lines[1] == HEADER and lines[-1] == PASS
    rows = list(csv.DictReader(lines[1:-1], strict=True)); assert len(rows) == 8
    for i, row in enumerate(rows):
        assert set(row) == set(HEADER.split(','))
        for key in row:
            if key not in ('owner', 'invocation'):
                assert re.fullmatch(r'0|[1-9][0-9]*', row[key]); row[key] = int(row[key]); assert row[key] < 2**64
        assert (row['ordinal'], row['length'], row['generation']) == (i+1, LENGTHS[i], 1 if i < 6 else 2)
        if i in (4, 5): assert row['owner'] == 'closed' and row['invocation'] == ''; row['invocation'] = None
        else:
            assert row['owner'] == 'sampled' and row['invocation'] == str(i if i < 4 else i-6)
            row['invocation'] = int(row['invocation'])
        expected = sum((((j*37+11) & 255) ^ 0x5a) for j in range(LENGTHS[i])) ^ 0x9e3779b97f4a7c15
        assert row['value'] == row['native_value'] == expected and 0 < row['ret_offset'] < 256
        assert row['start_aux'] == row['end_aux'] < 2**32 and row['end_ticks'] >= row['start_ticks']
        assert row['elapsed_ticks'] == row['end_ticks'] - row['start_ticks']
    return rows, '\n'.join(lines[1:-1])+'\n'


def native_output(directory, terminal):
    header = 'seed,length,status,children,comparisons,original_visits,original_steps,candidate_steps,value'
    table = (directory/'ordinary-pairs.csv').read_bytes(); assert 0 < len(table) <= MIB and table.endswith(b'\n') and b'\r' not in table
    lines = table.decode('ascii').splitlines(); assert len(lines) == 5 and lines[0] == header
    rows = list(csv.DictReader(lines, strict=True)); assert len(rows) == 4
    population = [(seed, length) for seed in (0x1234567887654320, 0xfedcba9801234567) for length in (1, 64)]
    for row, (seed, length) in zip(rows, population):
        assert set(row) == set(header.split(',')) and row['status'] == 'PASS'
        for key in set(row)-{'status'}:
            assert re.fullmatch(r'0|[1-9][0-9]*', row[key]); row[key] = int(row[key]); assert row[key] < 2**64
        assert (row['seed'], row['length'], row['children']) == (seed, length, 2)
        assert all(row[k] > 0 for k in ('comparisons', 'original_visits', 'original_steps', 'candidate_steps'))
        assert row['original_steps'] <= 20000 and row['candidate_steps'] <= 20000
        assert row['original_visits'] < row['comparisons'] <= min(row['original_steps'], row['candidate_steps'])
        expected = sum(((((128+j)*37+11+seed) & 255) ^ 0x5a) for j in range(length)) ^ 0x9e3779b97f4a7c15
        assert row['value'] == expected
    comparisons = sum(row['comparisons'] for row in rows)
    assert (directory/'ordinary-refusals.csv').read_bytes() == b'case,status,reason\nempty_capable_symbol,PASS,NoPatchWindow\n'
    assert terminal == f'native-ordinary:required=4:pairs=4:children=8:comparisons={comparisons}:short-ret-refusals=1:real-outer-ret=8:complete\n'.encode('ascii')
    return rows, table, comparisons


EXACT_SCHEDULES = ('short', 'long', 'alternating', 'late-long')
EXACT_SCOPE = '# exact original work from authenticated fixed assembly; uncalibrated raw RDTSCP endpoints, no timing accuracy or savings-from-K claim'
EXACT_HEADER = 'schedule,k,external_id,ordinal,length,owner,generation,invocation,instructions,branches,taken_branches,input_byte_reads,return_read_bytes,value,start_ticks,end_ticks,start_aux,end_aux'


def exact_table(data, header, count):
    assert 0 < len(data) <= MIB and data.endswith(b'\n') and b'\r' not in data
    lines = data.decode('ascii').splitlines(); assert len(lines) == count+1 and lines[0] == header
    rows = list(csv.DictReader(lines, strict=True)); assert len(rows) == count
    assert all(set(row) == set(header.split(',')) and all(isinstance(v, str) for v in row.values()) for row in rows)
    return rows


def exact_number(word):
    assert re.fullmatch(r'0|[1-9][0-9]*', word)
    value = int(word); assert value < 2**64
    return value


def exact_output(data, schedule, retained):
    assert schedule in EXACT_SCHEDULES and type(retained) is int and retained in (24, 1, 10)
    assert 0 < len(data) <= MIB and data.endswith(b'\n') and b'\r' not in data
    lines = data.decode('ascii').splitlines(); assert len(lines) == 27 and lines[0] == EXACT_SCOPE
    table = '\n'.join(lines[1:-1])+'\n'; rows = exact_table(table.encode('ascii'), EXACT_HEADER, 24)
    lengths = {'short': [1]*24, 'long': [64]*24, 'alternating': [1, 64]*12, 'late-long': [1]*10+[64]*14}[schedule]
    for i, (row, length) in enumerate(zip(rows, lengths)):
        assert row['schedule'] == schedule
        for key in set(row)-{'schedule', 'owner', 'invocation'}: row[key] = exact_number(row[key])
        assert (row['k'], row['external_id'], row['ordinal'], row['length'], row['generation']) == (
            retained, EXACT_SCHEDULES.index(schedule)*10000+retained*100+i, i+1, length, 1)
        if i < retained:
            assert row['owner'] == 'sampled' and row['invocation'] == str(i); row['invocation'] = i
        else:
            assert row['owner'] == 'closed' and row['invocation'] == ''; row['invocation'] = None
        assert (row['instructions'], row['branches'], row['taken_branches'], row['input_byte_reads'], row['return_read_bytes']) == (6*length+5, length, length-1, length, 8)
        assert row['value'] == sum((((j*37+11) & 255) ^ 0x5a) for j in range(length)) ^ 0x9e3779b97f4a7c15
        assert row['start_aux'] == row['end_aux'] < 2**32 and row['end_ticks'] >= row['start_ticks']
    population = sum(6*n+5 for n in lengths); selected = sum(6*n+5 for n in lengths[:retained])
    numerator, denominator = selected*24-population*retained, retained*24
    assert lines[-1] == (f'exact-work PASS calls=24 retained={retained} population_instructions={population} retained_instructions={selected} '
        f'selection_error_numerator={numerator} selection_error_denominator={denominator} originals=24 raw_rows=24 input_unchanged=true joined=true')
    return rows, table, dict(schedule=schedule, k=retained, calls=24, originals=24, raw_rows=24, sampled=retained, closed=24-retained,
        population_instructions=population, retained_instructions=selected, selection_error_numerator=numerator, selection_error_denominator=denominator)


def exact_native_output(directory, terminal, concurrent=False):
    assert type(concurrent) is bool
    header = 'seed,length,status,children,comparisons,original_visits,original_steps,candidate_steps,value'
    truth_header = 'seed,length,status,instructions,conditional_branches,taken_branches,input_reads,return_reads,value'
    table = (directory/'exact-pairs.csv').read_bytes(); rows = exact_table(table, header, 4)
    truth_table = (directory/'exact-truth.csv').read_bytes(); truth = exact_table(truth_table, truth_header, 4)
    population = [(seed, n) for seed in (0x1234567887654320, 0xfedcba9801234567) for n in (1, 64)]
    for row, observed, (seed, n) in zip(rows, truth, population):
        for item in (row, observed):
            assert item['status'] == 'PASS'
            for key in set(item)-{'status'}: item[key] = exact_number(item[key])
            assert (item['seed'], item['length']) == (seed, n)
        assert row['children'] == 2 and row['original_visits'] == 6*n+5
        assert 0 < row['original_steps'] <= 20000 and 0 < row['candidate_steps'] <= 20000
        assert row['original_visits'] < row['comparisons'] <= min(row['original_steps'], row['candidate_steps'])
        expected = sum(((((128+j)*37+11+seed) & 255) ^ 0x5a) for j in range(n)) ^ 0x9e3779b97f4a7c15
        assert row['value'] == observed['value'] == expected
        assert (observed['instructions'], observed['conditional_branches'], observed['taken_branches'], observed['input_reads'], observed['return_reads']) == (6*n+5, n, n-1, n, 1)
    comparisons = sum(row['comparisons'] for row in rows)
    assert (directory/'exact-refusals.csv').read_bytes() == b'case,status,reason\nempty_capable_symbol,PASS,NoPatchWindow\n'
    mode = 'exact-concurrent' if concurrent else 'exact'
    assert terminal == (f'native-{mode}:required=4:pairs=4:children=8:comparisons={comparisons}:truth-instructions=800:conditional=130:taken=126:'
        'input-reads=130:return-reads=4:short-ret-refusals=1:real-outer-ret=8:complete\n').encode('ascii')
    return rows, table, truth_table, comparisons


RETIREMENT_CASES = {
    'sixteen-epochs': (
        'frontend_native::always_on::tests::concurrent_native::retirement_native::ordinary_native_retirement_sixteen_epochs',
        'retirement-native PASS case=sixteen-epochs epochs=16 originals=16 calls=16 sampled=16 rows=16 events=32 actions=32 registrations=1 report_permit_refusals=16 joined=true'),
    'function-closed': (
        'frontend_native::always_on::tests::concurrent_native::retirement_native::ordinary_native_retirement_function_closed_receipt',
        'retirement-native PASS case=function-closed originals=2 calls=2 sampled=1 closed=1 rows=2 events=4 actions=2 report_ready_before_return=true receipt_permit_refusal=1 post_return_stage=true joined=true'),
}


def retirement_output(data, case):
    assert case in RETIREMENT_CASES
    assert 0 < len(data) <= MIB and data.endswith(b'\n') and b'\r' not in data
    test_name, terminal = RETIREMENT_CASES[case]
    protocol = '\nrunning 1 test\ntest '+test_name+' ... '+terminal+'\nok\n\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; '
    assert re.fullmatch(re.escape(protocol)+r'[0-9]+ filtered out; finished in [0-9]+\.[0-9]+s\n\n', data.decode('ascii'))
    fields = dict(word.split('=', 1) for word in terminal.split()[2:])
    return {key: int(value) if value.isdecimal() else True if value == 'true' else value for key, value in fields.items()}


DRAIN_TEST = 'frontend_native::always_on::tests::concurrent_native::drain_native::ordinary_native_two_completed_batches'
DRAIN_PASS = 'drain-native PASS originals=64 calls=64 sampled=64 batches=2 rows=64 events=128 actions=2 registrations=1 capacity_refusals=2 empty_drains=3 report_records=64 detached=true input_unchanged=true'


def drain_output(data):
    assert 0 < len(data) <= MIB and data.endswith(b'\n') and b'\r' not in data
    protocol = '\nrunning 1 test\ntest '+DRAIN_TEST+' ... '+DRAIN_PASS+'\nok\n\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; '
    assert re.fullmatch(re.escape(protocol)+r'[0-9]+ filtered out; finished in [0-9]+\.[0-9]+s\n\n', data.decode('ascii'))
    fields = dict(word.split('=', 1) for word in DRAIN_PASS.split()[2:])
    return {key: int(value) if value.isdecimal() else True if value == 'true' else value for key, value in fields.items()}


HISTORY_TEST = 'frontend_native::always_on::tests::concurrent_native::history_native::ordinary_native_history_stream_old_owner'
HISTORY_PASS = 'history-native PASS originals=2 calls=2 sampled=2 rows=2 events=4 actions=600 history_batches=77 max_resident=8 epochs=300 retired=300 replacements=298 interval_batches=2 registrations=1 old_prefix=1 new_prefix=599 history_full_refusals=1 not_drained_refusals=1 report_permit_refusals=1 stale_refusals=1 empty_drains=2 replay_refusals=4 joined=true'


def history_output(data, stderr):
    assert stderr == b''
    assert 0 < len(data) <= MIB and data.endswith(b'\n') and b'\r' not in data
    protocol = '\nrunning 1 test\ntest '+HISTORY_TEST+' ... '+HISTORY_PASS+'\nok\n\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; '
    assert re.fullmatch(re.escape(protocol)+r'[0-9]+ filtered out; finished in [0-9]+\.[0-9]+s\n\n', data.decode('ascii'))
    fields = dict(word.split('=', 1) for word in HISTORY_PASS.split()[2:])
    return {key: int(value) if value.isdecimal() else True if value == 'true' else value for key, value in fields.items()}


TREE_OWNER_TEST = 'frontend_native::always_on::tests::concurrent_native::tree_native::tree_native_root_child_keep_distinct_owners_until_actual_returns'
TREE_OWNER_PASS = ('tree-owner-native PASS originals=1 roots=1 entries=2 returns=2 sampled=2 rows=2 events=4 '
    'reports=1+1+0 root_owner=A child_owner=B rearmed_owner=C child_pending_before_ret=true '
    'root_pending_before_ret=true actual_outer_return=true input_unchanged=true joined=true')


def tree_owner_output(data, stderr):
    assert stderr == b'' and 0 < len(data) <= MIB and b'\r' not in data
    protocol = '\nrunning 1 test\ntest '+TREE_OWNER_TEST+' ... '+TREE_OWNER_PASS+'\nok\n\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; '
    assert re.fullmatch(re.escape(protocol)+r'[0-9]+ filtered out; finished in [0-9]+\.[0-9]+s\n\n', data.decode('ascii'))
    return dict(status='PASS', originals=1, roots=1, entries=2, returns=2, sampled=2,
        rows=2, events=4, reports=[1, 1, 0], helper_joined=True,
        source_attested='root A remains outstanding at root RET; child B remains outstanding before child RET and finishes only at its original continuation under C; root finishes after actual outer return/postflight; complete input, rows, journal, history, original-owner Reports and retirement joins')


def main():
    if sys.flags.optimize: raise SystemExit('assertions required')
    sys.dont_write_bytecode = True
    ap = argparse.ArgumentParser(description=__doc__); ap.add_argument('--revision', required=True)
    for name in ('raw', 'toolchain', 'user-home', 'cargo-home'): ap.add_argument('--'+name, type=Path, required=True)
    ap.add_argument('--cache-work', action='store_true', help='also require twelve loaded cache-model state pairs; requires --exact-work')
    ap.add_argument('--counter-probe', action='store_true', help='also require twelve raw whole-original-API counter observations; requires --cache-work')
    ap.add_argument('--call-tree', action='store_true', help='also require four loaded caller/child state pairs and actual A/B/C ownership control; requires --cache-work and --concurrent-epochs')
    ap.add_argument('--tree-population', action='store_true', help='also require three 24-root finite populations at K=1/10/24; requires --call-tree')
    ap.add_argument('--tree-throughput', action='store_true', help='also measure 52 frozen paired SDK-consumer trials; requires --tree-population')
    ap.add_argument('--exact-work', action='store_true', help='also require exact native work truth and all 12 fresh 24-call populations')
    ap.add_argument('--concurrent-epochs', action='store_true', help='also require concurrent-mode state, forced native contention and autonomous timed epochs; requires --exact-work')
    ap.add_argument('--retire-epochs', action='store_true', help='also require two fresh native epoch-retirement controls; requires --concurrent-epochs')
    ap.add_argument('--drain-completed', action='store_true', help='also require two full native completed-record batches; requires --retire-epochs')
    ap.add_argument('--streamed-epochs', action='store_true', help='also require a finite 160-call streamed epoch trial; requires --drain-completed')
    ap.add_argument('--stream-history', action='store_true', help='also require the finite native absolute-history/old-owner control; requires --streamed-epochs')
    ap.add_argument('--optional-frontend', action='store_true', help='also require real optional Fast/Slow state pairs and finite reuse; requires --stream-history')
    ap.add_argument('--optional-backoff-control', action='store_true', help='also require the deterministic real optional driver control; requires --optional-frontend')
    ap.add_argument('--reference-timing', action='store_true', help='also require reference-reader state pairs and one paired raw timing population; requires --optional-backoff-control')
    a = ap.parse_args(); repo = Path(__file__).resolve().parents[2]; raw = a.raw
    assert Path(__file__).resolve() == repo/'tools/rapid-profiler/verify_ordinary_interval.py'
    assert re.fullmatch('[0-9a-f]{40}', a.revision)
    for p in (repo, a.toolchain, a.user_home, a.cargo_home): assert p.is_absolute() and p.resolve(strict=True) == p and p.is_dir()
    assert raw.is_absolute() and raw.is_relative_to(repo/'ignored') and not raw.exists()
    assert raw.parent.resolve(strict=True) == raw.parent
    assert not a.cache_work or a.exact_work
    assert not a.counter_probe or a.cache_work
    assert not a.tree_population or a.call_tree
    assert not a.tree_throughput or a.tree_population
    assert not a.call_tree or a.cache_work
    assert not a.call_tree or a.concurrent_epochs
    assert not a.concurrent_epochs or a.exact_work
    assert not a.retire_epochs or a.concurrent_epochs
    assert not a.drain_completed or a.retire_epochs
    assert not a.streamed_epochs or a.drain_completed
    assert not a.stream_history or a.streamed_epochs
    assert not a.optional_frontend or a.stream_history
    assert not a.optional_backoff_control or a.optional_frontend
    assert not a.reference_timing or a.optional_backoff_control
    raw.mkdir(mode=0o700); result = dict(schema=1, status='FAILED', revision=a.revision, stage='preflight', exact_work_requested=a.exact_work, concurrent_epochs_requested=a.concurrent_epochs,
        native_setup='Required original owner validation and candidate publication/attachment precede readiness; continuous 20000 steps after readiness, absolute 15-second deadline includes setup. Earlier original-preflight step-budget failures remain failures; prelude accounting is not equivalent.',
        scope='uncalibrated functional raw-TSC observations; no timing accuracy or throughput claim', native_state_qualification='PENDING: gate entry through post-POP; real outer return after own harness-context restoration; no whole-64KiB stack or timing-accuracy claim')
    result['retire_epochs_requested'] = a.retire_epochs
    result['drain_completed_requested'] = a.drain_completed
    result['streamed_epochs_requested'] = a.streamed_epochs
    result['stream_history_requested'] = a.stream_history
    result['optional_frontend_requested'] = a.optional_frontend
    result['optional_backoff_control_requested'] = a.optional_backoff_control
    result['reference_timing_requested'] = a.reference_timing
    result['cache_work_requested'] = a.cache_work
    result['counter_probe_requested'] = a.counter_probe
    result['call_tree_requested'] = a.call_tree
    result['tree_population_requested'] = a.tree_population
    result['tree_throughput_requested'] = a.tree_throughput
    if a.tree_throughput:
        result['tree_throughput'] = dict(status='UNRUN', trials=[],
            scope='Release guarded SDK consumer cost against original SDK, including source/input checks and installed joins; no bare-native or timing-accuracy claim')
    if a.tree_population:
        result['tree_population'] = dict(status='UNRUN', trials=[],
            scope='finite same-thread root/child population with exact work attribution and first-K selection error; raw ticks uncalibrated, no cache-model, timing-accuracy or performance claim')
    if a.call_tree:
        result['call_tree'] = dict(status='UNRUN', stage='UNRUN',
            scope='fixed depth-two ordinary calls, physical transfer witnesses and one continuous architectural demand-cache model; no hardware-cache, calibrated-time or performance claim')
    if a.counter_probe:
        result['counter_probe'] = dict(status='UNRUN', stage='UNRUN',
            hardware_accuracy='unqualified', model11h_semantics='unqualified',
            scope='raw event availability and full-running reads around the whole original API; no cache-model equality')
    if a.cache_work:
        result['cache_work'] = dict(status='UNRUN', stage='UNRUN',
            scope='exact original architectural operand reads replayed through a declared virtual-address cache model; no hardware-cache, timing-accuracy or performance claim')
    if a.reference_timing:
        result['reference_timing'] = dict(status='UNRUN', native_state='UNRUN', untraced='UNRUN',
            scope='separate real-CALL enclosing TSC endpoints and inner callback endpoints, with exact invocation/work joins; no frequency, calibration, accuracy or performance claim')
    if a.optional_backoff_control:
        result['optional_backoff_control'] = dict(status='UNRUN',
            scope='one deterministic 13-call real driver-operation/queue control; not a timed scheduler trial, new full-state cohort or performance result',
            source_attested='actual stable post-disable Fast bracket, later sampled rearm and retained B owner across C rearm; whole input, full journals, reports and real worker join')
    if a.optional_frontend:
        result['optional_frontend'] = dict(status='UNRUN', state_modes={}, functional='UNRUN',
            scope='actual optional TLS gate with eight full-state pairs and a separate 96-call functional/accounting case; no joint full-state coverage, timing accuracy, cheap-off or performance claim',
            source_attested='whole input, frame, physical returns, complete journal/Report and retained-owner joins; emitted rows are compact projections')
    if a.stream_history:
        result['history_stream'] = dict(status='UNRUN', test=HISTORY_TEST,
            scope='one finite cfg(test) history/owner control; no new full-register-state, indefinite-service, timing-accuracy or performance qualification',
            source_attested='Rust checks complete 600-Action replay, carry-in/stream identity, two whole 512-word journals, original/installed CALL/RET, raw/report joins and retained-owner release; protocol exports only its literal fields')
    if a.streamed_epochs:
        result['streamed_epochs'] = dict(status='UNRUN',
            scope='finite 160-call, 20-epoch trial; mandatory entry/RET hooks remain active; no indefinite service, timing accuracy, throughput or new full-register-state qualification',
            source_attested='Rust checks whole guarded input, original calls, full 512-word journal pages, batch identity, complete Report/terminal payloads, owned retirement and real gate returns; CSV exports only the stated projections')
    if a.drain_completed:
        result['completed_drain'] = dict(status='UNRUN', test=DRAIN_TEST,
            scope='two finite 32-call batches in one thread/registration; source-attested actual returns, entire input/raw/journal/report joins and capacity refusals; no new full-register oracle, indefinite service, timing accuracy or performance credit')
    if a.retire_epochs:
        result['epoch_retirement'] = dict(status='UNRUN',
            scope='two finite cfg(test) lifecycle controls; source-attested actual CALL/RET, journal and report ownership; no new full-register oracle, buffer-drain, indefinite-service or performance credit',
            cases=[dict(case=case, test=test, status='UNRUN') for case, (test, _) in RETIREMENT_CASES.items()])
    try:
        cpus = sorted(os.sched_getaffinity(0))[:4]; assert len(cpus) == 4
        os.sched_setaffinity(0, cpus); assert set(os.sched_getaffinity(0)) == set(cpus)
        tools = {n: (a.toolchain/'bin'/n).resolve(strict=True) for n in ('cargo', 'rustc')}
        tools.update(python=Path(sys.executable).resolve(strict=True), git=Path('/usr/bin/git').resolve(strict=True), gcc=Path('/usr/bin/gcc').resolve(strict=True))
        env = dict(HOME=str(a.user_home), CARGO_HOME=str(a.cargo_home), PATH=str(a.toolchain/'bin')+':/usr/bin:/bin',
            RUSTC=str(tools['rustc']), CC=str(tools['gcc']), CARGO_TARGET_DIR=str(repo/'target'), CARGO_INCREMENTAL='0', CARGO_BUILD_JOBS='4',
            CARGO_NET_OFFLINE='true', CARGO_PROFILE_RELEASE_OPT_LEVEL='3', CARGO_PROFILE_RELEASE_DEBUG='0',
            CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS='true', CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS='true',
            CARGO_TERM_COLOR='never', LC_ALL='C', PYTHONDONTWRITEBYTECODE='1', PYTHONNOUSERSITE='1')
        def command(argv): return subprocess.check_output(argv, cwd=repo, env=env, timeout=15).decode('ascii')
        def git(*argv): return command([str(tools['git']), '-C', str(repo), *argv])
        names = ['Cargo.toml', 'Cargo.lock', 'tools/rapid-profiler/Cargo.toml', 'tools/rapid-profiler/ordinary-interval/main.rs',
            'tools/rapid-profiler/src/counter_probe.rs', 'tools/rapid-profiler/src/counter_probe/tests.rs',
            'tools/rapid-profiler/src/counter_reading.rs', 'tools/rapid-profiler/src/lib.rs',
            'tools/rapid-profiler/ordinary-interval/counter.rs',
            'tools/rapid-profiler/ordinary-interval/tree.rs',
            'tools/rapid-profiler/ordinary-interval/tree/check.rs',
            'tools/rapid-profiler/ordinary-interval/tree/check/tests.rs',
            'tools/rapid-profiler/ordinary-interval/tree/throughput.rs',
            'tools/rapid-profiler/ordinary-interval/tree/throughput/joins.rs',
            'tools/rapid-profiler/ordinary-interval/tree/throughput/joins/tests.rs',
            'tools/rapid-profiler/ordinary-interval/tree/throughput/clocks.rs',
            'tools/rapid-profiler/native-interval/main.rs', 'tools/rapid-profiler/native-interval/ordinary.rs',
            'tests/support/native_ordinary.rs', 'tests/support/native_interval_oracle.rs',
            'tests/support/native_cache.rs', 'tools/rapid-profiler/native-interval/cache.rs',
            'tools/rapid-profiler/cache-work/truth.rs', 'tools/rapid-profiler/cache-work/model.rs',
            'tools/rapid-profiler/cache-work/cache_work.S', 'tools/rapid-profiler/cache-work/README.md',
            'tools/rapid-profiler/cache-work/check_output.py', 'tools/rapid-profiler/cache-work/test_recipe.py',
            'tools/rapid-profiler/native-interval/ordinary_checksum.c', 'tools/rapid-profiler/src/generation.rs',
            'tools/rapid-profiler/src/frontend.rs', 'tools/rapid-profiler/src/frontend_native/ordinary/mod.rs',
            'tools/rapid-profiler/src/frontend_native/ordinary/cfg.rs',
            'tools/rapid-profiler/src/frontend_native/always_on.rs', 'tools/rapid-profiler/src/frontend_native/always_on/gate.rs',
            'tools/rapid-profiler/src/frontend_native/always_on/timing.rs', 'tools/rapid-profiler/src/frontend_native/always_on/site/ordinary.rs',
            'tools/rapid-profiler/verify_ordinary_interval.py', 'evaluation/admission/processes.py', 'tools/unwind-oracle/bounded_command.py',
            'tools/rapid-profiler/ordinary-interval/exact.rs', 'tools/rapid-profiler/exact-work/exact_work.S',
            'tools/rapid-profiler/exact-work/truth.rs', 'tools/rapid-profiler/exact-work/join.rs', 'tools/rapid-profiler/exact-work/join/tests.rs',
            'tools/rapid-profiler/exact-work/README.md', 'tools/rapid-profiler/exact-work/test_recipe.py',
            'tools/rapid-profiler/src/frontend/interval_entry.rs',
            'tools/rapid-profiler/src/frontend_native/always_on/tests/concurrent_native.rs',
            'tools/rapid-profiler/ordinary-interval/timed.rs',
            'tools/rapid-profiler/ordinary-interval/timed/check.rs',
            'tools/rapid-profiler/ordinary-interval/timed/check_tests.rs',
            'tools/rapid-profiler/timed-work/check_output.py', 'tools/rapid-profiler/timed-work/test_recipe.py',
            'tools/rapid-profiler/timed-work/README.md']
        if a.retire_epochs:
            names.append('tools/rapid-profiler/src/frontend_native/always_on/tests/concurrent_native/retirement_native.rs')
        names.extend(['tools/rapid-profiler/src/frontend_native/mod.rs',
            'tools/rapid-profiler/src/frontend_native/always_on/drain.rs',
            'tools/rapid-profiler/src/frontend_native/always_on/drain/tests.rs',
            'tools/rapid-profiler/src/frontend_native/always_on/gate/drain_tests.rs',
            'tools/rapid-profiler/src/frontend_native/always_on/timing/drain_tests.rs'])
        if a.drain_completed:
            names.append('tools/rapid-profiler/src/frontend_native/always_on/tests/concurrent_native/drain_native.rs')
        if a.streamed_epochs:
            names.extend(['tools/rapid-profiler/ordinary-interval/streamed.rs',
                'tools/rapid-profiler/ordinary-interval/streamed/check.rs',
                'tools/rapid-profiler/ordinary-interval/streamed/check_tests.rs',
                'tools/rapid-profiler/streamed-work/check_output.py', 'tools/rapid-profiler/streamed-work/test_recipe.py',
                'tools/rapid-profiler/streamed-work/README.md'])
        names.extend(['tools/rapid-profiler/src/frontend/history_stream.rs',
            'tools/rapid-profiler/src/frontend/history_stream/tests.rs',
            'tools/rapid-profiler/src/frontend_native/always_on/history.rs',
            'tools/rapid-profiler/src/frontend_native/always_on/history/tests.rs'])
        if a.stream_history:
            names.extend(['tools/rapid-profiler/src/frontend_native/always_on/tests/concurrent_native/history_native.rs',
                'tools/rapid-profiler/history-stream/README.md', 'tools/rapid-profiler/history-stream/test_recipe.py'])
        if a.optional_frontend:
            names.extend(['src/precontext.rs', 'src/quiescent.rs', 'src/trampoline.rs',
                'tests/support/native_precontext.rs', 'tests/support/native_optional_frontend.rs',
                'tools/rapid-profiler/native-interval/optional.rs',
                'tools/rapid-profiler/src/frontend_native/always_on/optional.rs',
                'tools/rapid-profiler/src/frontend_native/always_on/optional/gate.rs',
                'tools/rapid-profiler/src/frontend_native/always_on/optional/site.rs',
                'tools/rapid-profiler/src/frontend_native/always_on/optional/drain.rs',
                'tools/rapid-profiler/src/frontend_native/always_on/optional/tests.rs',
                'tools/rapid-profiler/src/frontend_native/always_on/optional/gate/tests.rs',
                'tools/rapid-profiler/src/frontend_native/always_on/optional/tests/native.rs',
                'tools/rapid-profiler/optional-work/check_output.py', 'tools/rapid-profiler/optional-work/test_recipe.py',
                'tools/rapid-profiler/optional-work/README.md'])
        if a.optional_backoff_control:
            names.extend(['tools/rapid-profiler/ordinary-interval/backoff.rs',
                'tools/rapid-profiler/ordinary-interval/backoff/optional.rs',
                'tools/rapid-profiler/src/frontend_native/backoff/mod.rs',
                'tools/rapid-profiler/src/frontend_native/backoff/driver.rs',
                'tools/rapid-profiler/src/frontend_native/backoff/worker.rs',
                'tools/rapid-profiler/src/frontend_native/backoff/tests.rs',
                'tools/rapid-profiler/src/frontend_native/backoff/driver/tests.rs',
                'tools/rapid-profiler/src/frontend_native/backoff/driver/backpressure_tests.rs',
                'tools/rapid-profiler/src/frontend_native/backoff/worker/tests.rs',
                'tools/rapid-profiler/src/frontend_native/backoff/optional.rs',
                'tools/rapid-profiler/src/frontend_native/backoff/optional/cursor.rs',
                'tools/rapid-profiler/src/frontend_native/backoff/optional/worker.rs',
                'tools/rapid-profiler/src/frontend_native/backoff/optional/tests.rs',
                'tools/rapid-profiler/src/frontend_native/backoff/optional/tests/native.rs',
                'tools/rapid-profiler/src/frontend_native/backoff/sink.rs',
                'tools/rapid-profiler/src/frontend_native/backoff/sink/tests.rs',
                'tools/rapid-profiler/src/frontend_native/backoff/driver/sink_tests.rs',
                'tools/rapid-profiler/src/frontend_native/backoff/optional/sink_tests.rs',
                'tools/rapid-profiler/src/frontend_native/always_on/optional/history.rs',
                'tools/rapid-profiler/src/frontend_native/always_on/optional/tests/history.rs',
                'tools/rapid-profiler/optional-backoff-work/check_output.py',
                'tools/rapid-profiler/optional-backoff-work/test_recipe.py',
                'tools/rapid-profiler/optional-backoff-work/README.md'])
        if a.reference_timing or a.cache_work:
            names.extend(['tools/rapid-profiler/src/frontend_native/always_on/gate/reference.rs',
                'tools/rapid-profiler/src/frontend_native/always_on/gate/reference/hardware.rs',
                'tools/rapid-profiler/src/frontend_native/always_on/gate/reference/tests.rs',
                'tools/rapid-profiler/native-interval/reference.rs',
                'tools/rapid-profiler/native-interval/calibrations.rs',
                'tests/support/native_reference.rs',
                'tests/support/native_reference/tests.rs',
                'tools/rapid-profiler/ordinary-interval/exact/reference.rs',
                'tools/rapid-profiler/ordinary-interval/exact/reference/join.rs',
                'tools/rapid-profiler/ordinary-interval/exact/reference/join/tests.rs',
                'tools/rapid-profiler/reference-work/check_output.py',
                'tools/rapid-profiler/reference-work/test_recipe.py',
                'tools/rapid-profiler/reference-work/README.md'])
        if a.counter_probe:
            names.extend(['tools/rapid-profiler/counter-work/check_output.py',
                'tools/rapid-profiler/counter-work/test_recipe.py', 'tools/rapid-profiler/counter-work/README.md'])
        # Tree code is compiled into the ordinary client even without its trial.
        names.extend(['tests/support/native_call_tree.rs', 'tests/support/native_call_tree/tests.rs', 'tests/support/native_call_tree/refusal.rs', 'tests/call_tree_truth.rs',
            'tools/rapid-profiler/native-interval/tree.rs',
            'tools/rapid-profiler/tree-work/tree_work.S', 'tools/rapid-profiler/tree-work/truth.rs',
            'tools/rapid-profiler/tree-work/model.rs', 'tools/rapid-profiler/tree-work/check_output.py',
            'tools/rapid-profiler/tree-work/test_recipe.py', 'tools/rapid-profiler/tree-work/README.md',
            'tools/rapid-profiler/src/frontend_native/ordinary/tree.rs',
            'tools/rapid-profiler/src/frontend_native/always_on/tests/concurrent_native/tree_native.rs',
            'tools/rapid-profiler/src/frontend_native/always_on/gate/tree.rs',
            'tools/rapid-profiler/src/frontend_native/always_on/tree/drain.rs',
            'tools/rapid-profiler/src/frontend_native/always_on/tree/mod.rs',
            'tools/rapid-profiler/src/frontend_native/always_on/tree/postflight.rs',
            'tools/rapid-profiler/src/frontend_native/always_on/tree/prepared.rs',
            'tools/rapid-profiler/src/frontend_native/always_on/tree/runtime.rs',
            'tools/rapid-profiler/src/frontend_native/always_on/tree/runtime/tests.rs',
            'tools/rapid-profiler/src/frontend_native/always_on/tree/site.rs',
            'src/frame_trace.rs', 'src/quiescent.rs', 'src/trampoline.rs'])
        if a.tree_population:
            names.extend(['tools/rapid-profiler/tree-work/check_population.py',
                'tools/rapid-profiler/tree-work/test_population.py'])
        if a.tree_throughput:
            names.extend(['tools/rapid-profiler/tree-work/check_throughput.py',
                'tools/rapid-profiler/tree-work/test_throughput.py',
                'tools/rapid-profiler/tree-work/throughput_stats.py',
                'tools/rapid-profiler/tree-work/test_throughput_stats.py'])
        def sources():
            assert git('rev-parse', '--show-toplevel').strip() == str(repo) and git('rev-parse', 'HEAD').strip() == a.revision
            assert git('status', '--porcelain', '--untracked-files=no') == ''
            assert set(git('ls-files', '-z', '--', *names).rstrip('\0').split('\0')) == set(names)
            return {n: digest(repo/n) for n in names}
        before = sources(); tool_hashes = {n: digest(p) for n, p in tools.items()}
        save(raw/'sources-before.json', before); save(raw/'tools.json', {n: dict(path=str(p), **tool_hashes[n]) for n, p in tools.items()})
        if a.tree_throughput:
            spec = importlib.util.spec_from_file_location('tree_throughput_stats', repo/'tools/rapid-profiler/tree-work/throughput_stats.py')
            throughput_stats = importlib.util.module_from_spec(spec); spec.loader.exec_module(throughput_stats)
            throughput_plan = throughput_stats.plan()
            save(raw/'tree-throughput-plan.json', dict(seed=throughput_stats.SEED, trials=throughput_plan,
                cpu_seconds=20, wall_seconds=30, file_bytes=MIB))
            result['tree_throughput'].update(plan_digest=digest(raw/'tree-throughput-plan.json'),
                trials=[dict(request, status='UNRUN') for request in throughput_plan])
        rust_text = command([str(tools['rustc']), '--version', '--verbose']); (raw/'rustc-version.txt').write_text(rust_text)
        rust = dict(line.split(': ', 1) for line in rust_text.splitlines() if ': ' in line)
        assert re.fullmatch('[0-9A-Za-z.+_-]+', rust['release']) and re.fullmatch('[0-9a-f]{40}', rust['commit-hash'])
        assert rust['host'] == 'x86_64-unknown-linux-gnu'
        gcc = command([str(tools['gcc']), '-dumpfullversion', '-dumpversion']).strip(); assert re.fullmatch(r'[0-9]+(?:\.[0-9]+)+', gcc)
        cargo = command([str(tools['cargo']), '--version']).strip(); assert re.fullmatch(r'cargo [0-9A-Za-z.+_-]+ \([0-9a-f]{7,40} [0-9-]+\)', cargo)
        git_version = git('--version').strip(); assert re.fullmatch(r'git version [0-9]+(?:\.[0-9]+)+', git_version)
        rows = [{k.strip(): v.strip() for k, v in (line.split(':', 1) for line in block.splitlines() if ':' in line)} for block in Path('/proc/cpuinfo').read_text().split('\n\n') if block.strip()]
        selected = [r for r in rows if int(r['processor']) in cpus]; assert {int(r['processor']) for r in selected} == set(cpus)
        hardware = {(r['vendor_id'], *(int(r[k]) for k in ('cpu family', 'model', 'stepping'))) for r in selected}
        assert len(hardware) == 1; vendor, family, model, stepping = hardware.pop(); assert vendor in ('GenuineIntel', 'AuthenticAMD')
        result.update(sources=before, tools=tool_hashes, versions=dict(rust={k: rust[k] for k in ('release', 'commit-hash', 'host')}, cargo=cargo, gcc=gcc, git=git_version, python=list(sys.version_info[:3])),
            hardware=dict(architecture='x86_64', vendor=vendor, family=family, model=model, stepping=stepping, build_affinity_cpus=4, native_affinity_cpus=1, native_state_affinity_cpus=4,
                native_affinity_scope='single-worker checksum/exact clients and forced native qualification; state-oracle and timed affinities are separate',
                owner_label='AMD EPYC Zen 5 dev host', owner_label_origin='owner-specified; not inferred from observed CPU fields'))
        if a.concurrent_epochs:
            result['hardware'].update(timed_worker_affinity_cpus=1, timed_controller_affinity_cpus=1, timed_total_active_cpus=2)
        if a.streamed_epochs:
            result['hardware'].update(streamed_worker_affinity_cpus=1, streamed_controller_affinity_cpus=1, streamed_total_active_cpus=2)
        spec = importlib.util.spec_from_file_location('ordinary_processes', repo/'evaluation/admission/processes.py')
        processes = importlib.util.module_from_spec(spec); spec.loader.exec_module(processes)
        log_root = repo/'target/evaluation'; log_root.mkdir(parents=True, exist_ok=True)
        logs = Path(tempfile.mkdtemp(prefix='ordinary-interval-', dir=log_root)); helper = repo/'tools/unwind-oracle/bounded_command.py'
        def stage(name, argv, cpu, wall, cap, extra_env=None):
            result['stage'] = name; directory = raw/name; directory.mkdir(); (directory/'tmp').mkdir()
            request = dict(argv=argv, cwd=str(repo), env=dict(env, **(extra_env or {}), TMPDIR=str(directory/'tmp')), stdout=str(directory/'stdout.txt'), stderr=str(directory/'stderr.txt'), cpu_seconds=cpu, wall_seconds=wall, file_bytes=cap)
            save(directory/'request.json', request)
            invocation = [str(tools['python']), '-B', str(helper), '--request', str(directory/'request.json'), '--receipt', str(directory/'receipt.json')]
            save(directory/'parent-command.json', dict(argv=invocation, env=env, affinity=cpus, wall_seconds=wall+25))
            closed = processes.run_command(invocation, env, logs/(name+'.log'), wall+25, MIB); save(directory/'parent-closed.json', closed)
            assert closed['exit_code'] == 0 and closed['termination'] is None and closed['cleanup_complete'] and closed['reaped_descendants'] == 0
            receipt = json.loads((directory/'receipt.json').read_text())
            assert receipt['exit'] == 0 and receipt['wall_timeout'] is False and receipt['inputs_unchanged'] is True
            assert receipt['request_sha256'] == digest(directory/'request.json')['sha256'] and receipt['helper_sha256'] == before['tools/unwind-oracle/bounded_command.py']['sha256']
            assert receipt['absence_proof'] == 'ECHILD' and receipt['unexpected_descendants'] == receipt['cleanup_events'] == []
            assert receipt['cleanup_error'] is receipt['aborted'] is None
            for stream in ('stdout', 'stderr'): assert receipt[stream+'_sha256'] == digest(directory/(stream+'.txt'))['sha256']
            assert json.loads((logs/(name+'.log')).read_text()) == dict(exit=0, wall_timeout=False, absence_proof='ECHILD', descendants=0, success=True)
            assert sources() == before and {n: digest(p) for n, p in tools.items()} == tool_hashes
            result[name] = dict(process_exit=0, cpu_seconds=cpu, wall_seconds=wall, file_bytes=cap, strict_cleanup=True)
            return directory
        source = repo/'tools/rapid-profiler/native-interval/ordinary_checksum.c'; trusted = raw/'trusted.so'; candidate = raw/'candidate.so'
        cargv = [str(tools['gcc']), *CFLAGS, str(source), '-o', str(trusted)]
        stage('c-build', cargv, 20, 30, MIB); trusted_hash = digest(trusted); assert 0 < trusted_hash['bytes'] <= MIB
        with trusted.open('rb') as inp, candidate.open('xb') as out: out.write(inp.read(MIB+1))
        assert trusted.read_bytes() == candidate.read_bytes() and digest(trusted) == digest(candidate) == trusted_hash
        assert (trusted.stat().st_dev, trusted.stat().st_ino) != (candidate.stat().st_dev, candidate.stat().st_ino)
        build_args = ['build', '--locked', '--offline', '--release', '--jobs', '4', '-p', 'rapid-profiler', '--bin', 'ordinary-interval', '--bin', 'frontend-native-oracle', '--message-format=json-render-diagnostics']
        build = stage('build', [str(tools['cargo']), *build_args], 120, 180, 128*MIB)
        messages = [json.loads(line) for line in (build/'stdout.txt').read_text().splitlines()]; assert messages[-1] == dict(reason='build-finished', success=True)
        artifacts = {}; binaries = {}
        for name, source_name in [('ordinary-interval', 'ordinary-interval/main.rs'), ('frontend-native-oracle', 'native-interval/main.rs')]:
            products = [m for m in messages if m.get('reason') == 'compiler-artifact' and m['target']['name'] == name]
            assert len(products) == 1; product = products[0]; binary = repo/'target/release'/name
            assert product['executable'] == str(binary) and product['target']['kind'] == ['bin'] and product['target']['crate_types'] == ['bin'] and type(product['fresh']) is bool
            assert product['manifest_path'] == str(repo/'tools/rapid-profiler/Cargo.toml') and product['target']['src_path'] == str(repo/'tools/rapid-profiler'/source_name)
            profile = product['profile']; assert set(profile) == {'opt_level', 'debuginfo', 'test', 'debug_assertions', 'overflow_checks'}
            assert type(profile['opt_level']) is str and profile['opt_level'] == '3'
            assert type(profile['debuginfo']) is int and profile['debuginfo'] == 0 and profile['test'] is False
            assert profile['debug_assertions'] is True and profile['overflow_checks'] is True
            artifacts[name] = dict(cargo_fresh=product['fresh'], profile=profile, binary=digest(binary)); binaries[name] = binary
        result['build']['artifacts'] = artifacts; binary = binaries['ordinary-interval']
        result['binary'] = artifacts['ordinary-interval']['binary']; result['dso'] = trusted_hash
        oracle_output = raw/'oracle-output'
        oracle = stage('oracle', [str(binaries['frontend-native-oracle']), 'ordinary-state', str(candidate), str(trusted), str(oracle_output)], 90, 90, MIB)
        assert (oracle/'stderr.txt').read_bytes() == b''
        pairs, pair_table, comparisons = native_output(oracle_output, (oracle/'stdout.txt').read_bytes())
        (raw/'state-pairs.csv').write_bytes(pair_table)
        result['oracle'].update(pairs=4, children=8, comparisons=comparisons, short_ret_refusals=1, real_outer_returns=8, rows=pairs)
        result['native_state_qualification'] = 'PASS: gate entry through post-POP; full inherited GPR/flags/XSAVE/data and exact [S-128, stack_end) comparisons; real outer return after own harness-context restoration; no whole-64KiB stack or timing-accuracy claim'
        assert {n: digest(p) for n, p in binaries.items()} == {n: a['binary'] for n, a in artifacts.items()}
        assert digest(trusted) == digest(candidate) == trusted_hash and trusted.read_bytes() == candidate.read_bytes()
        native = stage('native', [str(binary), str(candidate), str(trusted)], 20, 30, MIB)
        assert (native/'stderr.txt').read_bytes() == b''
        checked, table = output((native/'stdout.txt').read_bytes())
        assert {n: digest(p) for n, p in binaries.items()} == {n: a['binary'] for n, a in artifacts.items()} and digest(trusted) == digest(candidate) == trusted_hash
        assert trusted.read_bytes() == candidate.read_bytes()
        (raw/'rows.csv').write_text(table)
        result.update(checksum_status='PASS', rows=checked, originals=8, calls=8, entries=8, returns=8, completed=6, unsampled=2, reports=[4, 2],
            required_short_ret_refusal=True, whole_guarded_input_bytes=96, worker_joined=True,
            commands=[['$GCC', *CFLAGS, '$REPO/tools/rapid-profiler/native-interval/ordinary_checksum.c', '-o', '$RAW/trusted.so'], ['$CARGO', *build_args],
                ['$REPO/target/release/frontend-native-oracle', 'ordinary-state', '$RAW/candidate.so', '$RAW/trusted.so', '$RAW/oracle-output'],
                ['$REPO/target/release/ordinary-interval', '$RAW/candidate.so', '$RAW/trusted.so']])
        if a.exact_work:
            exact = dict(status='FAILED', stage='assembly-build', scope='exact original work and retention bias; uncalibrated callback ticks, no duration accuracy or savings-from-K claim',
                boundary_and_report_joins='source-attested: synchronous Rust Trial::begin/finish/validate checks complete entry/RET, raw prefix, stack, totals and retained Report; CSV does not export those complete objects',
                trials=[dict(schedule=name, k=k, status='UNRUN') for name in EXACT_SCHEDULES for k in (24, 1, 10)])
            result['exact_work'] = exact
            exact_trusted, exact_candidate = raw/'exact-trusted.so', raw/'exact-candidate.so'
            assembly = repo/'tools/rapid-profiler/exact-work/exact_work.S'
            # Keep the original short-RET refusal symbol in this separate DSO.
            result['commands'].append(['$GCC', *CFLAGS, '$REPO/tools/rapid-profiler/native-interval/ordinary_checksum.c',
                '$REPO/tools/rapid-profiler/exact-work/exact_work.S', '-o', '$RAW/exact-trusted.so'])
            stage('exact-build', [str(tools['gcc']), *CFLAGS, str(source), str(assembly), '-o', str(exact_trusted)], 20, 30, MIB)
            exact_hash = digest(exact_trusted); assert 0 < exact_hash['bytes'] <= MIB
            with exact_trusted.open('rb') as inp, exact_candidate.open('xb') as out: out.write(inp.read(MIB+1))
            assert (exact_trusted.stat().st_dev, exact_trusted.stat().st_ino) != (exact_candidate.stat().st_dev, exact_candidate.stat().st_ino)
            def exact_stable():
                assert {n: digest(p) for n, p in binaries.items()} == {n: a['binary'] for n, a in artifacts.items()}
                assert digest(trusted) == digest(candidate) == trusted_hash and trusted.read_bytes() == candidate.read_bytes()
                assert digest(exact_trusted) == digest(exact_candidate) == exact_hash and exact_trusted.read_bytes() == exact_candidate.read_bytes()
            exact_stable(); exact['dso'] = exact_hash; exact['stage'] = 'oracle'
            exact_dir = raw/'exact-oracle-output'
            result['commands'].append(['$REPO/target/release/frontend-native-oracle', 'exact-state', '$RAW/exact-candidate.so', '$RAW/exact-trusted.so', '$RAW/exact-oracle-output'])
            observed = stage('exact-oracle', [str(binaries['frontend-native-oracle']), 'exact-state', str(exact_candidate), str(exact_trusted), str(exact_dir)], 90, 90, MIB)
            assert (observed/'stderr.txt').read_bytes() == b''
            exact_pairs, exact_table_bytes, truth_table, count = exact_native_output(exact_dir, (observed/'stdout.txt').read_bytes())
            exact_stable(); (raw/'exact-state-pairs.csv').write_bytes(exact_table_bytes); (raw/'exact-truth.csv').write_bytes(truth_table)
            exact['oracle'] = dict(status='PASS', pairs=4, children=8, comparisons=count, short_ret_refusals=1, real_outer_returns=8,
                original_instructions=800, conditional_branches=130, taken_branches=126, input_reads=130, return_reads=4, rows=exact_pairs)
            for trial in exact['trials']:
                name, k = trial['schedule'], trial['k']; label = f'exact-{name}-k{k}'
                exact['stage'] = label; trial['status'] = 'FAILED'; exact_stable()
                result['commands'].append(['$REPO/target/release/ordinary-interval', 'exact-work', '$RAW/exact-candidate.so', '$RAW/exact-trusted.so', name, str(k)])
                observed = stage(label, [str(binary), 'exact-work', str(exact_candidate), str(exact_trusted), name, str(k)], 20, 30, MIB)
                assert (observed/'stderr.txt').read_bytes() == b''
                exact_rows, exact_csv, summary = exact_output((observed/'stdout.txt').read_bytes(), name, k)
                exact_stable(); csv_path = raw/(label+'.csv'); csv_path.write_text(exact_csv)
                trial.update(summary, status='PASS', csv=csv_path.name, csv_digest=digest(csv_path))
            assert len(exact['trials']) == 12 and all(t['status'] == 'PASS' for t in exact['trials'])
            assert sum(t['calls'] for t in exact['trials']) == 288 and sum(t['sampled'] for t in exact['trials']) == 140
            exact.update(status='PASS', stage='complete', fresh_processes=12, calls=288, originals=288, sampled=140, closed=148)
        if a.concurrent_epochs:
            concurrent = dict(status='FAILED', scope='bounded concurrent metadata admission and three timed epochs; mandatory hooks stay active; no timing accuracy, throughput, indefinite service or contested full-register-state claim')
            result['concurrent_epochs'] = concurrent
            concurrent_dir = raw/'concurrent-oracle-output'
            result['commands'].append(['$REPO/target/release/frontend-native-oracle', 'exact-concurrent-state', '$RAW/exact-candidate.so', '$RAW/exact-trusted.so', '$RAW/concurrent-oracle-output'])
            observed = stage('concurrent-oracle', [str(binaries['frontend-native-oracle']), 'exact-concurrent-state', str(exact_candidate), str(exact_trusted), str(concurrent_dir)], 90, 90, MIB)
            assert (observed/'stderr.txt').read_bytes() == b''
            pairs, pair_bytes, truth_bytes, count = exact_native_output(concurrent_dir, (observed/'stdout.txt').read_bytes(), concurrent=True)
            exact_stable(); (raw/'concurrent-state-pairs.csv').write_bytes(pair_bytes); (raw/'concurrent-truth.csv').write_bytes(truth_bytes)
            concurrent['oracle'] = dict(pairs=4, children=8, comparisons=count, rows=pairs,
                scope='concurrent activation without a competing controller; same complete original-state comparator and truth checks')
            test_args = ['test', '--locked', '--offline', '--release', '--jobs', '4', '-p', 'rapid-profiler', '--lib', '--no-run', '--message-format=json-render-diagnostics']
            result['commands'].append(['$CARGO', *test_args])
            built = stage('concurrent-test-build', [str(tools['cargo']), *test_args], 120, 180, 128*MIB)
            messages = [json.loads(line) for line in (built/'stdout.txt').read_text().splitlines()]
            assert messages[-1] == dict(reason='build-finished', success=True)
            products = [m for m in messages if m.get('reason') == 'compiler-artifact' and m['target']['name'] == 'rapid_profiler' and m['profile']['test']]
            assert len(products) == 1; product = products[0]
            test_binary = Path(product['executable']); assert test_binary.resolve(strict=True) == test_binary
            assert test_binary.parent == repo/'target/release/deps' and re.fullmatch('rapid_profiler-[0-9a-f]+', test_binary.name)
            assert product['manifest_path'] == str(repo/'tools/rapid-profiler/Cargo.toml')
            assert product['target']['src_path'] == str(repo/'tools/rapid-profiler/src/lib.rs')
            assert product['target']['kind'] == product['target']['crate_types'] == ['lib']
            assert product['profile'] == dict(opt_level='3', debuginfo=0, test=True, debug_assertions=True, overflow_checks=True)
            assert type(product['profile']['debuginfo']) is int and type(product['fresh']) is bool
            assert all(product['profile'][key] is True for key in ('test', 'debug_assertions', 'overflow_checks'))
            test_hash = digest(test_binary)
            concurrent['test_artifact'] = dict(binary=test_hash, profile=product['profile'], cargo_fresh=product['fresh'])
            test_name = 'frontend_native::always_on::tests::concurrent_native::ordinary_native_concurrent_arm_remove_and_old_owner'
            test_flags = ['--exact', test_name, '--ignored', '--nocapture', '--test-threads=1']
            result['commands'].append(['$RAPID_LIBTEST', *test_flags])
            observed = stage('concurrent-native', [str(test_binary), *test_flags], 10, 15, MIB,
                dict(RAPID_CONCURRENT_CANDIDATE=str(candidate), RAPID_CONCURRENT_EXPECTED=str(trusted)))
            assert (observed/'stderr.txt').read_bytes() == b''
            terminal = 'concurrent-native PASS originals=6 calls=6 entries=6 returns=6 sampled=4 closed=1 removed=1 reports=2+2 writer_contentions=2 registry_contentions=0 inflight_rearm=1 joined=true'
            protocol = '\nrunning 1 test\ntest '+test_name+' ... '+terminal+'\nok\n\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; '
            assert re.fullmatch(re.escape(protocol)+r'[0-9]+ filtered out; finished in [0-9]+\.[0-9]+s\n\n', (observed/'stdout.txt').read_text())
            assert digest(test_binary) == test_hash and digest(candidate) == digest(trusted) == trusted_hash
            concurrent['forced_native'] = dict(originals=6, calls=6, sampled=4, closed=1, removed=1, writer_contentions=2, registry_contentions=0, inflight_rearm=1,
                scope='cfg(test) atomic rendezvous; actual CALL/RET, raw rows, whole journal, input, stack and reports; no concurrent full-register comparator')
            result['commands'].append(['$REPO/target/release/ordinary-interval', 'timed-work', '$RAW/exact-candidate.so', '$RAW/exact-trusted.so'])
            observed = stage('timed-native', [str(binary), 'timed-work', str(exact_candidate), str(exact_trusted)], 20, 30, MIB)
            assert (observed/'stderr.txt').read_bytes() == b''
            spec = importlib.util.spec_from_file_location('timed_check', repo/'tools/rapid-profiler/timed-work/check_output.py')
            checker = importlib.util.module_from_spec(spec); spec.loader.exec_module(checker)
            timed = checker.parse((observed/'stdout.txt').read_bytes())
            assert {timed['worker_cpu'], timed['controller_cpu']} <= set(cpus)
            for label in ('transitions', 'calls', 'reports'):
                with (raw/('timed-'+label+'.csv')).open('x', newline='') as stream:
                    rows = timed[label]; writer = csv.DictWriter(stream, fieldnames=list(rows[0]), lineterminator='\n')
                    writer.writeheader(); writer.writerows(rows)
            concurrent['timed'] = {k: v for k, v in timed.items() if k not in ('transitions', 'calls', 'reports')}
            concurrent['timed'].update(originals=24, calls=24, epochs=3, actions=6, requested_active_ms=30, requested_inactive_ms=10)
            exact_stable(); assert digest(test_binary) == test_hash
            concurrent['status'] = 'PASS'
        if a.retire_epochs:
            retirement = result['epoch_retirement']; retirement['status'] = 'FAILED'
            for case in retirement['cases']:
                case['status'] = 'FAILED'
                exact_stable(); assert digest(test_binary) == test_hash
                label = 'retirement-'+case['case']
                test_flags = ['--exact', case['test'], '--ignored', '--nocapture', '--test-threads=1']
                result['commands'].append(['$RAPID_LIBTEST', *test_flags])
                observed = stage(label, [str(test_binary), *test_flags], 10, 15, MIB,
                    dict(RAPID_CONCURRENT_CANDIDATE=str(candidate), RAPID_CONCURRENT_EXPECTED=str(trusted)))
                assert (observed/'stderr.txt').read_bytes() == b''
                summary = retirement_output((observed/'stdout.txt').read_bytes(), case['case'])
                exact_stable(); assert digest(test_binary) == test_hash
                case.update(summary, status='PASS')
            assert len(retirement['cases']) == 2 and all(c['status'] == 'PASS' for c in retirement['cases'])
            retirement.update(status='PASS', fresh_processes=2)
        if a.drain_completed:
            drained = result['completed_drain']; drained['status'] = 'FAILED'
            exact_stable(); assert digest(test_binary) == test_hash
            test_flags = ['--exact', DRAIN_TEST, '--ignored', '--nocapture', '--test-threads=1']
            result['commands'].append(['$RAPID_LIBTEST', *test_flags])
            observed = stage('drain-native', [str(test_binary), *test_flags], 10, 15, MIB,
                dict(RAPID_CONCURRENT_CANDIDATE=str(candidate), RAPID_CONCURRENT_EXPECTED=str(trusted)))
            assert (observed/'stderr.txt').read_bytes() == b''
            summary = drain_output((observed/'stdout.txt').read_bytes())
            exact_stable(); assert digest(test_binary) == test_hash
            drained.update(summary, status='PASS', fresh_processes=1)
        if a.streamed_epochs:
            streamed = result['streamed_epochs']; streamed['status'] = 'FAILED'
            exact_stable(); assert digest(test_binary) == test_hash
            result['commands'].append(['$REPO/target/release/ordinary-interval', 'streamed-work', '$RAW/exact-candidate.so', '$RAW/exact-trusted.so'])
            observed = stage('streamed-native', [str(binary), 'streamed-work', str(exact_candidate), str(exact_trusted)], 20, 30, MIB)
            assert (observed/'stderr.txt').read_bytes() == b''
            spec = importlib.util.spec_from_file_location('streamed_check', repo/'tools/rapid-profiler/streamed-work/check_output.py')
            checker = importlib.util.module_from_spec(spec); spec.loader.exec_module(checker)
            parsed = checker.parse((observed/'stdout.txt').read_bytes())
            assert {parsed['worker_cpu'], parsed['controller_cpu']} <= set(cpus)
            tables = ('transitions', 'calls', 'batches', 'retirement', 'reports')
            exported = {}
            for label in tables:
                path = raw/('streamed-'+label+'.csv')
                with path.open('x', newline='') as stream:
                    rows = parsed[label]; writer = csv.DictWriter(stream, fieldnames=list(rows[0]), lineterminator='\n')
                    writer.writeheader(); writer.writerows(rows)
                exported[label] = dict(file=path.name, rows=len(rows), **digest(path))
            exact_stable(); assert digest(test_binary) == test_hash
            streamed.update({k: v for k, v in parsed.items() if k not in tables})
            streamed.update(status='PASS', originals=160, calls=160, entries=160, returns=160, epochs=20, slots=3, retired=20, replacements=17,
                batches=40, raw_rows=160, events=320, actions=40, reports=parsed['sampled'], active_coverage=20, off_coverage=20,
                requested_active_ms=30, requested_inactive_ms=10, nominal_window_ms=800, schedule_deadline_ms=2000,
                replacement_cutoff_before_arm_ms=10, calls_per_batch=4, channel_capacity=2, tables=exported, fresh_processes=1)
        if a.stream_history:
            history = result['history_stream']; history['status'] = 'FAILED'
            exact_stable(); assert digest(test_binary) == test_hash
            test_flags = ['--exact', HISTORY_TEST, '--ignored', '--nocapture', '--test-threads=1']
            result['commands'].append(['$RAPID_LIBTEST', *test_flags])
            observed = stage('history-native', [str(test_binary), *test_flags], 10, 15, MIB,
                dict(RAPID_CONCURRENT_CANDIDATE=str(candidate), RAPID_CONCURRENT_EXPECTED=str(trusted)))
            parsed = history_output((observed/'stdout.txt').read_bytes(), (observed/'stderr.txt').read_bytes())
            exact_stable(); assert digest(test_binary) == test_hash
            history.update(status='PASS', protocol=parsed, fresh_processes=1,
                source_assertions=dict(epoch_limit=2, retained_owner_release=[2, 1, 0], full_journal_pages=2, words_per_journal_page=512))
        if a.optional_frontend:
            optional = result['optional_frontend']; optional['status'] = 'FAILED'
            spec = importlib.util.spec_from_file_location('optional_check', repo/'tools/rapid-profiler/optional-work/check_output.py')
            checker = importlib.util.module_from_spec(spec); spec.loader.exec_module(checker)
            for mode in ('fast', 'slow'):
                optional['state_modes'][mode] = dict(status='FAILED')
                exact_stable(); assert digest(test_binary) == test_hash
                directory = raw/('optional-'+mode+'-output'); label = 'optional-'+mode+'-state'
                result['commands'].append(['$REPO/target/release/frontend-native-oracle', label, '$RAW/candidate.so', '$RAW/trusted.so', '$RAW/'+directory.name])
                observed = stage(label, [str(binaries['frontend-native-oracle']), label, str(candidate), str(trusted), str(directory)], 90, 90, MIB)
                assert (observed/'stderr.txt').read_bytes() == b''
                table = (directory/'optional-pairs.csv').read_bytes()
                pairs, count = checker.pairs(table, (directory/'optional-refusals.csv').read_bytes(), (observed/'stdout.txt').read_bytes(), mode == 'slow')
                exact_stable(); assert digest(test_binary) == test_hash
                (raw/('optional-'+mode+'-pairs.csv')).write_bytes(table)
                optional['state_modes'][mode] = dict(status='PASS', pairs=4, children=8, comparisons=count, rows=pairs,
                    helper_joins=4, observer_entries=8 if mode == 'slow' else 0, controller_transitions=4, short_ret_refusals=1,
                    scope='actual optional gate entry through post-POP with controller transition; real outer return after own harness restoration')
            optional['functional'] = dict(status='FAILED')
            exact_stable(); assert digest(test_binary) == test_hash
            flags = ['--exact', checker.TEST, '--ignored', '--nocapture', '--test-threads=1']
            result['commands'].append(['$RAPID_LIBTEST', *flags])
            observed = stage('optional-functional', [str(test_binary), *flags], 10, 15, MIB,
                dict(RAPID_CONCURRENT_CANDIDATE=str(candidate), RAPID_CONCURRENT_EXPECTED=str(trusted)))
            parsed = checker.functional((observed/'stdout.txt').read_bytes(), (observed/'stderr.txt').read_bytes())
            exact_stable(); assert digest(test_binary) == test_hash
            optional['functional'] = dict(parsed, status='PASS', fresh_processes=1,
                scope='96 originals plus 96 installed functional/accounting calls; no full-register oracle for this schedule')
            with (raw/'optional-functional.csv').open('x', newline='') as stream:
                writer = csv.DictWriter(stream, fieldnames=list(parsed), lineterminator='\n'); writer.writeheader(); writer.writerow(parsed)
            optional.update(status='PASS', state_pairs=8, state_children=16, state_helper_joins=8, functional_helper_joins=1)
        if a.optional_backoff_control:
            control = result['optional_backoff_control']; control['status'] = 'FAILED'
            spec = importlib.util.spec_from_file_location('optional_backoff_check', repo/'tools/rapid-profiler/optional-backoff-work/check_output.py')
            checker = importlib.util.module_from_spec(spec); spec.loader.exec_module(checker)
            exact_stable(); assert digest(test_binary) == test_hash
            flags = ['--exact', checker.TEST, '--ignored', '--nocapture', '--test-threads=1']
            result['commands'].append(['$RAPID_LIBTEST', *flags])
            observed = stage('optional-backoff-native', [str(test_binary), *flags], 10, 15, MIB,
                dict(RAPID_CONCURRENT_CANDIDATE=str(candidate), RAPID_CONCURRENT_EXPECTED=str(trusted)))
            parsed = checker.native_output((observed/'stdout.txt').read_bytes(), (observed/'stderr.txt').read_bytes())
            exact_stable(); assert digest(test_binary) == test_hash
            control.update(status='PASS', protocol=parsed, fresh_processes=1)
            with (raw/'optional-backoff-control.csv').open('x', newline='') as stream:
                writer = csv.DictWriter(stream, fieldnames=list(parsed), lineterminator='\n'); writer.writeheader(); writer.writerow(parsed)
        if a.reference_timing:
            reference = result['reference_timing']; reference['status'] = 'FAILED'
            exact_stable(); assert digest(test_binary) == test_hash
            spec = importlib.util.spec_from_file_location('reference_check', repo/'tools/rapid-profiler/reference-work/check_output.py')
            checker = importlib.util.module_from_spec(spec); spec.loader.exec_module(checker)
            calibration_args = ['test', '--locked', '--offline', '--release', '--jobs', '4', '-p', 'rapid-profiler',
                '--test', 'frontend-native-calibrations', '--no-run', '--message-format=json-render-diagnostics']
            result['commands'].append(['$CARGO', *calibration_args])
            built = stage('reference-calibration-build', [str(tools['cargo']), *calibration_args], 120, 180, 128*MIB)
            messages = [json.loads(line) for line in (built/'stdout.txt').read_text().splitlines()]
            assert messages[-1] == dict(reason='build-finished', success=True)
            products = [m for m in messages if m.get('reason') == 'compiler-artifact' and m['target']['name'] == 'frontend-native-calibrations']
            assert len(products) == 1; product = products[0]
            calibration_binary = Path(product['executable']); assert calibration_binary.resolve(strict=True) == calibration_binary
            assert calibration_binary.parent == repo/'target/release/deps' and re.fullmatch('frontend_native_calibrations-[0-9a-f]+', calibration_binary.name)
            assert product['manifest_path'] == str(repo/'tools/rapid-profiler/Cargo.toml')
            assert product['target']['src_path'] == str(repo/'tools/rapid-profiler/native-interval/calibrations.rs')
            assert product['target']['kind'] == ['test'] and product['target']['crate_types'] == ['bin']
            assert product['profile'] == dict(opt_level='3', debuginfo=0, test=True, debug_assertions=True, overflow_checks=True)
            assert type(product['profile']['debuginfo']) is int and type(product['fresh']) is bool
            assert all(product['profile'][key] is True for key in ('test', 'debug_assertions', 'overflow_checks'))
            calibration_hash = digest(calibration_binary)
            reference['calibration_artifact'] = dict(binary=calibration_hash, profile=product['profile'], cargo_fresh=product['fresh'])
            result['commands'].append(['$REFERENCE_CALIBRATIONS'])
            observed = stage('reference-calibrations', [str(calibration_binary)], 20, 30, MIB)
            checker.calibrations((observed/'stdout.txt').read_bytes(), (observed/'stderr.txt').read_bytes())
            assert digest(calibration_binary) == calibration_hash
            reference['calibrations'] = dict(status='PASS', passed=76, failed=0, ignored=0,
                scope='actual state-validator mutation controls, including all inherited controls; not clock calibration')
            exact_stable(); assert digest(test_binary) == test_hash
            directory = raw/'reference-oracle-output'; reference['native_state'] = dict(status='FAILED')
            result['commands'].append(['$REPO/target/release/frontend-native-oracle', 'exact-reference-state', '$RAW/exact-candidate.so', '$RAW/exact-trusted.so', '$RAW/reference-oracle-output'])
            observed = stage('reference-oracle', [str(binaries['frontend-native-oracle']), 'exact-reference-state', str(exact_candidate), str(exact_trusted), str(directory)], 90, 90, MIB)
            table = (directory/'reference-pairs.csv').read_bytes()
            pairs = checker.pairs(table, (observed/'stdout.txt').read_bytes(), (observed/'stderr.txt').read_bytes())
            exact_stable(); assert digest(test_binary) == test_hash and digest(calibration_binary) == calibration_hash
            (raw/'reference-state-pairs.csv').write_bytes(table)
            reference['native_state'] = dict(status='PASS', pairs=4, children=8, comparisons=872,
                reader_checks=16, timestamp_joins=16, returned_records=8, subject_returns=8, real_outer_returns=8,
                original_instructions=800, conditional_branches=130, taken_branches=126, input_reads=130, return_reads=4,
                rows=pairs, affinity_cpus=1,
                scope='unchanged full-state comparator over restored application/wrapper points and both same-child readers, expanded application stack, actual RDTSCP outputs joined to stores and postflight records; no timing-accuracy result')
            # This mode executes only after every required native reference pair.
            reference['untraced'] = dict(status='FAILED')
            result['commands'].append(['$REPO/target/release/ordinary-interval', 'exact-reference', '$RAW/exact-candidate.so', '$RAW/exact-trusted.so'])
            observed = stage('reference-native', [str(binary), 'exact-reference', str(exact_candidate), str(exact_trusted)], 20, 30, MIB)
            rows, table = checker.functional((observed/'stdout.txt').read_bytes(), (observed/'stderr.txt').read_bytes())
            exact_stable(); assert digest(test_binary) == test_hash and digest(calibration_binary) == calibration_hash
            (raw/'reference-rows.csv').write_bytes(table)
            reference['untraced'] = dict(status='PASS', originals=24, installed=24, raw_rows=24, sampled=24,
                report_records=24, original_instructions=4800, installed_instructions=4800, same_thread=True,
                detached=True, input_unchanged=True, affinity_cpus=1, csv='reference-rows.csv', csv_digest=digest(raw/'reference-rows.csv'),
                scope='48 serial real CALLs with distinct legs, exact IDs/work/Report joins and uncalibrated enclosing/inner TSC endpoints; no accuracy, frequency or performance claim')
            reference['status'] = 'PASS'
        if a.cache_work:
            cache = result['cache_work']; cache.update(status='FAILED', stage='calibration-build')
            exact_stable()
            spec = importlib.util.spec_from_file_location('cache_check', repo/'tools/rapid-profiler/cache-work/check_output.py')
            cache_checker = importlib.util.module_from_spec(spec); spec.loader.exec_module(cache_checker)
            spec = importlib.util.spec_from_file_location('cache_calibrations', repo/'tools/rapid-profiler/reference-work/check_output.py')
            calibration_checker = importlib.util.module_from_spec(spec); spec.loader.exec_module(calibration_checker)
            args = ['test', '--locked', '--offline', '--release', '--jobs', '4', '-p', 'rapid-profiler',
                '--test', 'frontend-native-calibrations', '--no-run', '--message-format=json-render-diagnostics']
            result['commands'].append(['$CARGO', *args])
            built = stage('cache-calibration-build', [str(tools['cargo']), *args], 120, 180, 128*MIB)
            messages = [json.loads(line) for line in (built/'stdout.txt').read_text().splitlines()]
            assert messages[-1] == dict(reason='build-finished', success=True)
            products = [m for m in messages if m.get('reason') == 'compiler-artifact' and m['target']['name'] == 'frontend-native-calibrations']
            assert len(products) == 1; product = products[0]
            cache_calibration = Path(product['executable']); assert cache_calibration.resolve(strict=True) == cache_calibration
            assert cache_calibration.parent == repo/'target/release/deps' and re.fullmatch('frontend_native_calibrations-[0-9a-f]+', cache_calibration.name)
            assert product['manifest_path'] == str(repo/'tools/rapid-profiler/Cargo.toml')
            assert product['target']['src_path'] == str(repo/'tools/rapid-profiler/native-interval/calibrations.rs')
            assert product['target']['kind'] == ['test'] and product['target']['crate_types'] == ['bin']
            assert product['profile'] == dict(opt_level='3', debuginfo=0, test=True, debug_assertions=True, overflow_checks=True)
            assert type(product['profile']['debuginfo']) is int and type(product['fresh']) is bool
            assert all(product['profile'][key] is True for key in ('test', 'debug_assertions', 'overflow_checks'))
            cache_calibration_hash = digest(cache_calibration)
            cache['calibration_artifact'] = dict(binary=cache_calibration_hash, profile=product['profile'], cargo_fresh=product['fresh'])
            cache['stage'] = 'calibrations'
            result['commands'].append(['$CACHE_CALIBRATIONS'])
            observed = stage('cache-calibrations', [str(cache_calibration)], 20, 30, MIB)
            calibration_checker.calibrations((observed/'stdout.txt').read_bytes(), (observed/'stderr.txt').read_bytes())
            assert digest(cache_calibration) == cache_calibration_hash
            cache['calibrations'] = dict(status='PASS', passed=76, failed=0, ignored=0,
                scope='complete inherited and new validator/model controls; no hardware-cache calibration')
            cache.update(stage='assembly-build')
            cache_trusted, cache_candidate = raw/'cache-trusted.so', raw/'cache-candidate.so'
            assembly = repo/'tools/rapid-profiler/cache-work/cache_work.S'
            result['commands'].append(['$GCC', *CFLAGS, '$REPO/tools/rapid-profiler/cache-work/cache_work.S', '-o', '$RAW/cache-trusted.so'])
            stage('cache-build', [str(tools['gcc']), *CFLAGS, str(assembly), '-o', str(cache_trusted)], 20, 30, MIB)
            cache_hash = digest(cache_trusted); assert 0 < cache_hash['bytes'] <= MIB
            with cache_trusted.open('rb') as inp, cache_candidate.open('xb') as out: out.write(inp.read(MIB+1))
            assert (cache_trusted.stat().st_dev, cache_trusted.stat().st_ino) != (cache_candidate.stat().st_dev, cache_candidate.stat().st_ino)
            def cache_stable():
                exact_stable()
                assert digest(cache_calibration) == cache_calibration_hash
                assert digest(cache_trusted) == digest(cache_candidate) == cache_hash and cache_trusted.read_bytes() == cache_candidate.read_bytes()
            cache_stable(); cache.update(dso=cache_hash, stage='oracle')
            directory = raw/'cache-oracle-output'
            result['commands'].append(['$REPO/target/release/frontend-native-oracle', 'cache-state', '$RAW/cache-candidate.so', '$RAW/cache-trusted.so', '$RAW/cache-oracle-output'])
            observed = stage('cache-oracle', [str(binaries['frontend-native-oracle']), 'cache-state', str(cache_candidate), str(cache_trusted), str(directory)], 90, 90, MIB)
            table = (directory/'cache-pairs.csv').read_bytes()
            rows = cache_checker.pairs(table, (observed/'stdout.txt').read_bytes(), (observed/'stderr.txt').read_bytes())
            cache_stable(); (raw/'cache-state-pairs.csv').write_bytes(table)
            cache.update(status='PASS', stage='complete', pairs=12, children=24, comparisons=3564,
                instructions=3432, conditional_branches=672, taken_branches=660, input_reads=1356, return_reads=12,
                model_events=1368, model_hits=1040, model_misses=328, real_outer_returns=24,
                rows=rows, csv='cache-state-pairs.csv', csv_digest=digest(raw/'cache-state-pairs.csv'),
                model=dict(line_bytes=64, sets=4, ways=2, replacement='true LRU', initial='all invalid per invocation',
                    addressing='actual virtual line number; set = floor(address/64) modulo 4',
                    events='all original subject demand operand reads including count and RET; no instruction fetch or observer accesses'),
                source_attested='exact whole input/source and ordered original PCs, actual load operands/results, DEC/JNZ and return/stack; shared full-state candidate comparison and exact gate/Report joins; simulator and independent reuse-distance agree per event')
        if a.counter_probe:
            probe = result['counter_probe']; probe.update(status='FAILED', stage='untraced')
            spec = importlib.util.spec_from_file_location('counter_check', repo/'tools/rapid-profiler/counter-work/check_output.py')
            counter_checker = importlib.util.module_from_spec(spec); spec.loader.exec_module(counter_checker)
            directory = raw/'counter-probe-output'
            result['commands'].append(['$REPO/target/release/ordinary-interval', 'counter-cache-probe', '$RAW/cache-candidate.so', '$RAW/cache-trusted.so', '$RAW/counter-probe-output'])
            try:
                observed = stage('counter-probe', [str(binary), 'counter-cache-probe', str(cache_candidate), str(cache_trusted), str(directory)], 20, 30, MIB)
            finally:
                # A refusal remains a failed required stage. Preserve its finite
                # raw export without changing stage's existing exit/closure gates.
                table_names = ('population.csv', 'counters.csv', 'operations.csv')
                if all((directory/name).is_file() for name in table_names):
                    terminal = raw/'counter-probe'
                    parsed = counter_checker.directory(directory, (terminal/'stdout.txt').read_bytes(), (terminal/'stderr.txt').read_bytes())
                    probe.update(parsed, tables={name: digest(directory/name) for name in table_names})
            assert probe['status'] == 'OBSERVED' and probe['observed_full_running'] == 12
            cache_stable(); probe['stage'] = 'complete'
        if a.call_tree:
            tree = result['call_tree']; tree.update(status='FAILED', stage='assembly-build')
            cache_stable()
            spec = importlib.util.spec_from_file_location('tree_check', repo/'tools/rapid-profiler/tree-work/check_output.py')
            tree_checker = importlib.util.module_from_spec(spec); spec.loader.exec_module(tree_checker)
            tree_trusted, tree_candidate = raw/'tree-trusted.so', raw/'tree-candidate.so'
            assembly = repo/'tools/rapid-profiler/tree-work/tree_work.S'
            result['commands'].append(['$GCC', *CFLAGS, '$REPO/tools/rapid-profiler/tree-work/tree_work.S', '-o', '$RAW/tree-trusted.so'])
            stage('tree-build', [str(tools['gcc']), *CFLAGS, str(assembly), '-o', str(tree_trusted)], 20, 30, MIB)
            tree_hash = digest(tree_trusted); assert 0 < tree_hash['bytes'] <= MIB
            with tree_trusted.open('rb') as inp, tree_candidate.open('xb') as out: out.write(inp.read(MIB+1))
            assert (tree_trusted.stat().st_dev, tree_trusted.stat().st_ino) != (tree_candidate.stat().st_dev, tree_candidate.stat().st_ino)
            def tree_stable():
                cache_stable()
                assert digest(tree_trusted) == digest(tree_candidate) == tree_hash and tree_trusted.read_bytes() == tree_candidate.read_bytes()
            tree_stable(); tree.update(dso=tree_hash, stage='oracle')
            directory = raw/'tree-oracle-output'
            result['commands'].append(['$REPO/target/release/frontend-native-oracle', 'tree-state', '$RAW/tree-candidate.so', '$RAW/tree-trusted.so', '$RAW/tree-oracle-output'])
            observed = stage('tree-oracle', [str(binaries['frontend-native-oracle']), 'tree-state', str(tree_candidate), str(tree_trusted), str(directory)], 90, 90, MIB)
            table = (directory/'tree-pairs.csv').read_bytes()
            rows = tree_checker.pairs(table, (observed/'stdout.txt').read_bytes(), (observed/'stderr.txt').read_bytes())
            tree_stable(); (raw/'tree-state-pairs.csv').write_bytes(table)
            tree.update(stage='owner-control', native_state='PASS', pairs=4, children=8, comparisons=1372,
                instructions=1328, root_instructions=24, child_instructions=1304,
                conditional_branches=256, taken_branches=252, input_reads=516, return_reads=8, call_stores=4,
                model_events=528, model_hits=392, model_misses=136, root_misses=4, child_misses=132,
                model_writebacks=0, transfers=24, real_outer_returns=8,
                rows=rows, csv='tree-state-pairs.csv', csv_digest=digest(raw/'tree-state-pairs.csv'),
                model=dict(line_bytes=64, sets=4, ways=2, replacement='true LRU', initial='all invalid once at root entry',
                    stores='write allocate, write back; this population never evicts its dirty stack line',
                    addressing='actual virtual line number; input base set2 and both return words in one set3 line',
                    events='original CALL store, count/payload/link reads and both RET reads; no instruction fetch or observer accesses'),
                source_attested='whole source/input, all ordered original heads, immediate physical E8/C3 successor and RSP/word witnesses, full unmasked stack/GPR/flags/XSAVE comparison, retained owners through child acknowledgement and root actual return/postflight; exact nested rows/journal/Reports')
            test_flags = [TREE_OWNER_TEST, '--exact', '--ignored', '--nocapture', '--test-threads=1']
            result['commands'].append(['$TEST_BINARY', *test_flags])
            observed = stage('tree-owner-native', [str(test_binary), *test_flags], 10, 15, MIB,
                extra_env=dict(RAPID_TREE_CANDIDATE=str(tree_candidate), RAPID_TREE_EXPECTED=str(tree_trusted)))
            tree['ownership'] = tree_owner_output((observed/'stdout.txt').read_bytes(), (observed/'stderr.txt').read_bytes())
            tree_stable(); assert digest(test_binary) == test_hash
            tree.update(stage='return-word-refusal')
            directory = raw/'tree-refusal-output'
            result['commands'].append(['$REPO/target/release/frontend-native-oracle', 'tree-return-word-refusal', '$RAW/tree-candidate.so', '$RAW/tree-trusted.so', '$RAW/tree-refusal-output'])
            observed = stage('tree-return-word-refusal', [str(binaries['frontend-native-oracle']), 'tree-return-word-refusal', str(tree_candidate), str(tree_trusted), str(directory)], 20, 30, MIB)
            table = (directory/'tree-refusal.csv').read_bytes()
            tree['return_word_refusal'] = tree_checker.refusal(table, (observed/'stdout.txt').read_bytes(), (observed/'stderr.txt').read_bytes())
            (raw/'tree-return-word-refusal.csv').write_bytes(table)
            tree.update(refusal_csv='tree-return-word-refusal.csv', refusal_csv_digest=digest(raw/'tree-return-word-refusal.csv'))
            tree_stable()
            tree.update(status='PASS', stage='complete')
        if a.tree_population:
            population = result['tree_population']; population['status'] = 'FAILED'
            assert result['call_tree']['status'] == 'PASS'
            spec = importlib.util.spec_from_file_location('tree_population_check', repo/'tools/rapid-profiler/tree-work/check_population.py')
            population_checker = importlib.util.module_from_spec(spec); spec.loader.exec_module(population_checker)
            for k in (1, 10, 24):
                label = f'tree-population-k{k}'
                trial = dict(k=k, status='FAILED'); population['trials'].append(trial)
                tree_stable()
                result['commands'].append(['$REPO/target/release/ordinary-interval', 'tree-population', '$RAW/tree-candidate.so', '$RAW/tree-trusted.so', str(k)])
                observed = stage(label, [str(binary), 'tree-population', str(tree_candidate), str(tree_trusted), str(k)], 20, 30, MIB)
                parsed = population_checker.parse((observed/'stdout.txt').read_bytes(), (observed/'stderr.txt').read_bytes(), k)
                tree_stable()
                path = raw/(label+'.csv')
                with path.open('x', newline='') as stream:
                    writer = csv.DictWriter(stream, fieldnames=list(parsed['rows'][0]), lineterminator='\n')
                    writer.writeheader(); writer.writerows(parsed['rows'])
                trial.update(parsed['summary'], status='PASS', csv=path.name, csv_digest=digest(path))
            assert [t['k'] for t in population['trials']] == [1, 10, 24]
            assert all(t['status'] == 'PASS' for t in population['trials'])
            population.update(status='PASS', fresh_processes=3, originals=72, roots=72, nodes=144,
                sampled=70, closed=74, batches=9, events=288, reports=70)
        if a.tree_throughput:
            throughput = result['tree_throughput']; throughput['status'] = 'FAILED'
            assert result['tree_population']['status'] == 'PASS'
            spec = importlib.util.spec_from_file_location('tree_throughput_check', repo/'tools/rapid-profiler/tree-work/check_throughput.py')
            throughput_checker = importlib.util.module_from_spec(spec); spec.loader.exec_module(throughput_checker)
            assert len(throughput['trials']) == 52
            for request, trial in zip(throughput_plan, throughput['trials']):
                assert trial == dict(request, status='UNRUN')
                mode = request['mode']; label = f'tree-throughput-{request["trial"]:02d}-{mode}'
                trial.update(status='FAILED', stage=label)
                tree_stable()
                result['commands'].append(['$REPO/target/release/ordinary-interval', 'tree-throughput', mode, '$RAW/tree-candidate.so', '$RAW/tree-trusted.so'])
                observed = stage(label, [str(binary), 'tree-throughput', mode, str(tree_candidate), str(tree_trusted)], 20, 30, MIB)
                parsed = throughput_checker.parse((observed/'stdout.txt').read_bytes(), (observed/'stderr.txt').read_bytes(), mode)
                tree_stable()
                assert not (set(parsed['summary']) & {'trial', 'phase', 'block', 'position', 'stage'})
                assert parsed['summary']['mode'] == mode and parsed['summary']['status'] == 'FUNCTIONAL_PASS'
                trial.update(parsed['summary'], stdout_digest=digest(observed/'stdout.txt'), stderr_digest=digest(observed/'stderr.txt'))
            statistics = throughput_stats.summarize(throughput['trials'])
            save(raw/'tree-throughput-statistics.json', statistics)
            throughput.update(status='OBSERVED', fresh_processes=52, statistics=statistics,
                statistics_digest=digest(raw/'tree-throughput-statistics.json'),
                source_attested=parsed['source_attested'],
                retention='All 52 trials retained. Twelve fixed warmups excluded only from the estimator; no retries, outlier discard or post-observation cohort changes.')
        after = sources(); save(raw/'sources-after.json', after); assert after == before and {n: digest(p) for n, p in tools.items()} == tool_hashes
        result.update(status='PASS', stage='complete')
    except BaseException:
        (raw/'failure.txt').write_text(traceback.format_exc())
    save(raw/'result.json', result); print(json.dumps(result, sort_keys=True))
    return 0 if result['status'] == 'PASS' else 1


if __name__ == '__main__': raise SystemExit(main())
