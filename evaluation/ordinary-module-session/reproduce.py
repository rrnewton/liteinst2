#!/usr/bin/env python3
"""Fixed module-session functional campaign; no retries or timing qualification.

An external owner supplies the hard three-CPU reservation and 7200-second wall.
Private raw evidence stays under ignored/. This script grants no reservation
credit from the caller's descriptive tag or from affinity alone.
"""
import sys
if sys.flags.optimize:
    raise SystemExit('assertions required')
sys.dont_write_bytecode = True

import argparse
import csv
import io
import datetime as dt
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import time

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
MIB = 1048576
CAP = 4 * MIB
OUTER_SECONDS = 7200
EVIDENCE_LIMIT = 2048 * MIB
FINAL_ALLOWANCE = 64 * MIB
NATIVE_GROWTH = 1152 * MIB
OWNER_SHA = '0dfc4f40943252950e122c9e9fffb837448cba12140d0614acfa9d3621f2e31f'
BOUNDED_SHA = 'c0d8d24d9538e2ffd9dee09f8b7efc8a68eb2bfd41b0744d47167d7932d8df44'
CORPUS_SHA = '6feddb81816cc509e1357edec646ab60ba433a4a857d094ddce4d09a0c3ee738'
MODULES = {
    'native': 'evaluation/ordinary-module-native/reproduce.py',
    'native_output': 'evaluation/ordinary-module-native/module_native.py',
    'module': 'evaluation/ordinary-module/reproduce.py',
    'csv': 'evaluation/ordinary-csv/reproduce.py',
    'owner': 'evaluation/admission/processes.py',
    'census': 'tools/rapid-profiler/selected-work/check_output.py',
    'single': 'tools/rapid-profiler/verify_normal_session.py',
    'output': 'evaluation/ordinary-module-session/output.py',
    'producer': 'evaluation/ordinary-module-session/produce.py',
    'corpus': 'evaluation/ordinary-module-session/corpus.py',
}
CONSUMER = (
    'normal::module::session::input::tests::grammar_preserves_literals_empty_fields_quotes_and_limits',
    'normal::module::session::input::tests::actual_frame_acceptance_distinguishes_eof_refusal_and_incomplete',
    'normal::module::session::input::tests::owned_record_checks_entire_guard_and_exact_input',
    'normal::module::session::check::tests::ordered_module_population_keeps_global_slots_and_function_ranks',
    'normal::module::session::check::tests::complete_population_identity_ack_stack_and_all_journal_words_refuse',
    'normal::module::session::check::tests::absolute_history_owner_prefix_and_independent_closed_budget_refuse',
    'normal::module::session::check::tests::report_payloads_keep_function_rank_sequence_and_raw_unavailability',
    'normal::module::session::tests::canonical_numeric_cli_never_normalizes_signs_spaces_or_overflow',
    'normal::module::session::tests::accepted_module_pending_owner_survives_full_queue_and_disconnect_before_stop',
    'normal::module::session::input::tests::accepted_snapshot_refuses_same_shape_in_range_payload_change',
    'normal::module::session::input::tests::typed_completion_keeps_all_refusals_incomplete_and_exact_stderr',
)
# CLOSED interface 3e614aee, independently approved by interface review 21ce8ad7.
OWNER_CONTROLS = tuple('normal::module::session::owner::tests::' + name for name in (
    'owner_phases_require_two_refusals_and_reclaim_before_checkpoint',
    'owner_population_preserves_hot_cold_slots_ranks_and_sequences',
    'owner_snapshot_refusals_keep_all_retained_state',
    'owner_completion_refuses_wrong_identity_missing_calls_and_renewed_deadline'))
REUSE_CONTROLS = tuple('normal::module::session::owner::reuse::tests::' + name for name in (
    'recycled_population_requires_new_generation_and_both_function_rank_zero',
    'recycled_transfer_checks_every_journal_word_and_final_four_acknowledgements',
    'old_report_copy_remains_exact_after_restage_and_new_completions',
    'reuse_phase_order_and_generation_bound_slot_state_are_exact',
    'reuse_deadline_and_channel_refusals_retain_owned_values'))
NATIVE_STAGES = tuple('tool-' + n for n in ('cc1', 'collect2', 'as', 'ld')) + (
    'python-controls', 'native-build', 'state-build', 'caller-build', 'state-list',
    'state-controls', 'caller-list', 'caller-controls', 'module-c-build', 'caller-c-build',
    'module-symbols', 'csv_fields-disassembly', 'strnlen-disassembly', 'caller-symbols', 'caller-disassembly')


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode('ascii')


def read(path, cap=16*MIB):
    identity = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as f:
        before = os.fstat(f.fileno())
        assert stat.S_ISREG(before.st_mode) and 0 <= before.st_size <= cap
        data = f.read(cap + 1)
        assert len(data) == before.st_size <= cap
        assert identity(before) == identity(os.fstat(f.fileno())) == identity(Path(path).lstat())
    return data


def pin(data):
    return dict(bytes=len(data), sha256=hashlib.sha256(data).hexdigest())


def save(path, value, cap=MIB):
    data = canonical(value)
    assert len(data) <= cap
    with path.open('xb') as f:
        f.write(data)


def load(name, path):
    spec = importlib.util.spec_from_file_location('_session_recipe_' + name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def catalog():
    originals = [dict(leg='original', attempt=0, k=None, case=i, status='UNRUN', attempts=0) for i in range(32)]
    installed = [dict(leg='installed', attempt=a, k=k, case=i, status='UNRUN', attempts=0)
                 for a in range(1, 6) for k in (10, 1000) for i in range(32)]
    return originals, installed


def frame(records):
    assert len(records) <= 2048
    data = bytearray(b'MODCSV1\0' + len(records).to_bytes(4, 'little'))
    for payload, fields in records:
        assert type(payload) is bytes and len(payload) <= 64
        assert all(32 <= b <= 126 for b in payload) and type(fields) is int and 1 <= fields <= 65
        data.append(len(payload)); data.extend(payload)
    return bytes(data)


def malformed_frames():
    prefix = b'MODCSV1\0'
    one = prefix + (1).to_bytes(4, 'little')
    return (
        ('bad_magic', b'X' + prefix[1:] + bytes(4)),
        ('count_over_2048', prefix + (2049).to_bytes(4, 'little')),
        ('truncated_length', one), ('truncated_payload', one + b'\x02a'),
        ('length_over_64', one + b'\x41' + b'x' * 65),
        ('non_ascii_payload', one + b'\x01\xff'),
        ('malformed_csv', one + b'\x01"'),
        ('trailing_input_byte', prefix + bytes(4) + b'x'),
    )


def normal_closed(closed):
    assert closed['cleanup_complete'] is True and closed['reaped_descendants'] == 0
    assert closed['termination'] is None and type(closed['exit_code']) is int
    assert closed['exit_code'] in (0, 1)


def bounded_join(receipt, closed, request_pin, helper_pin, stdout_pin, stderr_pin):
    normal_closed(closed)
    assert type(receipt['exit']) is int and receipt['exit'] in (0, 1, 2)
    assert closed['exit_code'] == (0 if receipt['exit'] == 0 else 1)
    assert receipt['absence_proof'] == 'ECHILD' and receipt['inputs_unchanged'] is True
    assert receipt['wall_timeout'] is False
    assert receipt['unexpected_descendants'] == receipt['cleanup_events'] == []
    assert receipt['aborted'] is receipt['cleanup_error'] is None
    assert receipt['request_sha256'] == request_pin['sha256']
    assert receipt['helper_sha256'] == helper_pin['sha256']
    assert receipt['stdout_sha256'] == stdout_pin['sha256'] and receipt['stderr_sha256'] == stderr_pin['sha256']
    return receipt['exit']


def producer_join(result, code, stdout, stderr, checked, expected_bytes):
    assert code == 0 and result['status'] == 'PASS'
    assert result['normal_reaps'] == 1 and result['rescue'] is False and result['cleanup_error'] is None
    assert result['sent_bytes'] == expected_bytes
    assert result['stdout_sha256'] == pin(stdout)['sha256'] and result['stderr_sha256'] == pin(stderr)['sha256']
    assert result['child_pid'] == checked['rows']['READY'][0]['pid']
    assert result['child_exit'] == (0 if checked['rows']['DONE'][0]['status'] == 'COMPLETE' else 1)
    assert result['totals'] == checked['totals'] and result['done'] == checked['rows']['DONE'][0]
    assert result['original_values'] == [[r['id'], r['length'], r['checksum'], r['csv_value'], r['length_value']]
                                          for r in checked['rows']['RESULT']]


def public_projection(result):
    columns = ('leg', 'attempt', 'k', 'case', 'name', 'expected_outcome', 'input_error', 'status', 'attempts', 'records', 'calls', 'sampled',
               'unsampled', 'epochs', 'batches', 'child_exit', 'normal_reaps', 'write_blocked')
    rows = [{key: row.get(key) for key in columns} for row in result['originals'] + result['installed']]
    assert len(rows) == 352
    attempts = [dict(attempt=a, passed=sum(r['status'] == 'PASS' for r in result['installed'] if r['attempt'] == a),
                     failed=sum(r['status'] == 'FAILED' for r in result['installed'] if r['attempt'] == a),
                     unrun=sum(r['status'] == 'UNRUN' for r in result['installed'] if r['attempt'] == a)) for a in range(1, 6)]
    return dict(status=result['status'], revision=result['revision'], rows=rows, attempts=attempts,
                campaign_complete=all(r['attempts'] == 1 for r in rows) and result.get('custody_closed', False) and result.get('retention_verified', False),
                all_qualified=result['status'] == 'FUNCTIONAL_CAMPAIGN_PASS', evidence_budget=result.get('evidence_budget'),
                prerequisites={name: dict(status=value['status'], attempts=value['attempts'],
                    owner_rows=[{key: row.get(key) for key in ('k','direction','status','attempts')} for row in value.get('rows',[])])
                    for name,value in result.get('prerequisites',{}).items()},
                malformed_controls=[{key: row[key] for key in ('name','status','attempts')} for row in result.get('controls',[])],
                scope='Scalar functional campaign only; native state and owner gates are separate; no timing or full-A5 claim.')


def ordinary_inventory(inventory, single, module, owner_controls):
    assert owner_controls is not None and len(owner_controls) == 4
    old = tuple(single.SESSION) + tuple(single.TRACE)
    assert len(old) == 21 and len(CONSUMER) == 11
    wanted = old + CONSUMER + tuple(module.MODULE_TESTS) + tuple(module.CSV_TESTS) + tuple(owner_controls) + REUSE_CONTROLS
    assert len(REUSE_CONTROLS) == 5
    assert len(wanted) == len(set(wanted)) == 52
    prefixes = ('normal::session::tests::', 'normal::session::check::tests::',
                'normal::session::epoch_storage::tests::', 'normal::session::io::tests::',
                'normal::session::io::csv_tests::', 'normal::session::io::history_tests::',
                'normal::session::loop_trace::tests::',
                'normal::session::protocol::tests::', 'normal::module::', 'normal::csv::')
    assert set(n for n in inventory if n.startswith(prefixes)) == set(wanted)
    return wanted


def native_summary(result, revision, session):
    status = 'NATIVE_SESSION_STATE_PASS' if session else 'NATIVE_STATE_PASS'
    assert result['status'] == status and result['revision'] == revision
    if session:
        assert result['profile'] == 'session-absolute-v1' and result['pending_owner_controls'] == 'UNRUN_SEPARATE_REQUIRED_GATE'
    else:
        assert 'profile' not in result and 'pending_owner_controls' not in result
    assert result['custody_closed'] is True and result['retention_verified'] is True
    assert [r['name'] for r in result['stages']] == list(NATIVE_STAGES)
    assert all(r['status'] == 'CLOSED_EXIT_ZERO' for r in result['stages'])
    assert [r['k'] for r in result['native']] == ([10, 1000] if session else [16, 1])
    for row in result['native']:
        assert row['status'] == status and row['attempts'] == 1
        assert (row['required_pairs'], row['required_normal_reaps'], row['required_target_calls']) == (32, 64, 256)
        assert (row['pairs'], row['normal_reaps'], row['target_calls'], row['target_returns'], row['outer_returns']) == (32, 64, 256, 256, 64)
        assert len(row['rows']) == 32 and len(row['coverage']) == 2
        normal_closed(row['closed']); assert row['closed']['exit_code'] == 0


class EvidenceBudget:
    """Prospective retained-file budget; no kernel quota or evidence deletion."""
    def __init__(self):
        self.used = 0
        self.held = 0
        self.active = False
        self.files = {}
        self.exceeded = False
    def room(self, maximum):
        assert type(maximum) is int and maximum > 0 and not self.active and self.held == 0
        assert not self.exceeded and self.used + maximum <= EVIDENCE_LIMIT - FINAL_ALLOWANCE, 'evidence budget'
    def reserve(self, maximum):
        self.room(maximum)
        self.held = maximum
        self.active = True
    def charge(self, path, size):
        assert type(size) is int and size >= 0
        cost = max(4096, ((size + 4095) // 4096) * 4096)
        if path in self.files:
            assert self.files[path] == cost
            return
        available = self.held if self.active else EVIDENCE_LIMIT - FINAL_ALLOWANCE - self.used
        self.files[path] = cost
        self.used += cost
        self.held = max(0, self.held - cost)
        if cost > available:
            self.exceeded = True
            raise AssertionError('evidence reservation exceeded; retain all files')
    def complete(self):
        assert not self.exceeded
        self.held = 0
        self.active = False
    def stopped(self):
        # Uninventoried/live output retains its complete outstanding reservation.
        self.used += self.held
        self.held = 0
        self.active = False
    def summary(self):
        return dict(limit=EVIDENCE_LIMIT, final_allowance=FINAL_ALLOWANCE,
                    charged_rounded_bytes=self.used, held_bytes=self.held, reservation_active=self.active, exceeded=self.exceeded,
                    scope='Retained evidence only; shared target build cache/artifacts are separate; no filesystem quota.')


def bounded_growth(request, generated=(), app_files=False):
    return 2*request['file_bytes'] + 10*MIB + sum(cap for _,cap in generated) + (3*CAP if app_files else 0)


def bounded_ready(run, request, app_files=False):
    assert time.monotonic() + request['wall_seconds'] + 28 < run.deadline
    run.budget.room(bounded_growth(request, app_files=app_files))


class Run:
    """One source-bound owner, immutable first pins, and no retry operation."""
    def __init__(self, args, raw, tools, env, sources, modules, started, tool_pins):
        self.a, self.raw, self.tools, self.env, self.sources, self.m = args, raw, tools, env, sources, modules
        self.deadline = started + OUTER_SECONDS
        self.retained = {}; self.tool_pins = dict(tool_pins); self.budget = EvidenceBudget()
        self.native_dirs = {label: raw/(raw.name+'-native-'+label) for label in ('finite','session')}
        self.build_scratch = (raw/'tmp', *(p/'tmp' for p in self.native_dirs.values()))
        modules['native'].pins_ok(self.tool_pins)
        self.safe = True; self.cpus = sorted(os.sched_getaffinity(0))
        assert len(self.cpus) == 3 and all(0 <= cpu < 1024 for cpu in self.cpus)
        self.logs = ROOT/'target/evaluation'/raw.name; self.logs.mkdir(parents=True, exist_ok=False)
        originals, installed = catalog()
        for row in originals + installed:
            case = modules['producer'].case_spec(modules['corpus'], row['case'])
            row.update(name=case['name'], expected_outcome='original_scalar' if row['leg'] == 'original' else case['outcome'],
                       input_error=None if row['leg'] == 'original' else case['input_error'])
        self.result = dict(status='FAILED', revision=args.revision, originals=originals, installed=installed,
                           stages=[], controls=[dict(name=name, status='UNRUN', attempts=0) for name, _ in malformed_frames()],
                           prerequisites={name: dict(status='UNRUN', attempts=0) for name in ('finite', 'session', 'owner')},
                           custody_closed=False, retention_verified=False,
                           affinity=self.cpus, cpu_roles=dict(controller=self.cpus[0], worker=self.cpus[1], producer=self.cpus[2]),
                           reservation_tag=args.reservation_tag, reservation_authority='external owner only',
                           start_utc=dt.datetime.now(dt.timezone.utc).isoformat(), load_before=list(os.getloadavg()))
    def remember(self, path, expected=None, cap=512*MIB):
        assert not any(path.is_relative_to(p) for p in self.build_scratch), 'evidence in excluded build scratch'
        value = self.m['native'].retain(self.retained, path, expected, cap)
        if path.is_relative_to(self.raw) or path.is_relative_to(ROOT/'target/evaluation'):
            self.budget.charge(str(path), value['bytes'])
        return value
    def freeze(self, path, value, cap=MIB):
        assert not any(path.is_relative_to(p) for p in self.build_scratch)
        data = canonical(value); assert len(data) <= cap
        self.budget.charge(str(path), len(data))
        with path.open('xb') as f: f.write(data)
        return self.remember(path)
    def closed_inventory(self, directory):
        assert self.safe
        for current, dirs, files in os.walk(directory, topdown=True, followlinks=False):
            for name in dirs:
                assert not (Path(current)/name).is_symlink()
            dirs[:] = [name for name in dirs if Path(current)/name not in self.build_scratch]
            for name in sorted(files): self.remember(Path(current)/name)
    def unchanged(self):
        assert time.monotonic() < self.deadline
        assert sorted(os.sched_getaffinity(0)) == self.cpus
        assert subprocess.check_output([self.tools['git'], '-C', ROOT, 'rev-parse', 'HEAD'], env=self.env, timeout=15).decode().strip() == self.a.revision
        assert subprocess.check_output([self.tools['git'], '-C', ROOT, 'status', '--porcelain', '--untracked-files=no'], env=self.env, timeout=15) == b''
        for pins in (self.sources, self.tool_pins, self.retained): self.m['native'].pins_ok(pins)
        assert time.monotonic() < self.deadline
    def command(self, name, argv, wall, cap=MIB):
        d = self.raw/name
        command = dict(argv=list(map(str, argv)), cwd=str(ROOT), env=self.env, wall_seconds=wall, log_bytes=cap)
        if d.exists():
            assert str(d/'command.json') in self.retained and json.loads(read(d/'command.json', MIB)) == command
        else:
            d.mkdir(); self.freeze(d/'command.json', command)
        return d, command
    def owned(self, name, argv, wall, cap=MIB, growth=None):
        self.unchanged(); assert time.monotonic() + wall + 3 < self.deadline
        d, command = self.command(name, argv, wall, cap)
        assert all(row['name'] != name for row in self.result['stages'])
        assert not (d/'closed.json').exists()
        self.budget.reserve(growth if growth is not None else 2*cap + 4*MIB)
        row = dict(name=name, status='FAILED'); self.result['stages'].append(row)
        self.safe = False
        closed = self.m['owner'].run_command(command['argv'], self.env, self.logs/(name+'.log'), wall, cap)
        self.freeze(d/'closed.json', closed); row['closed'] = closed
        self.safe = closed['cleanup_complete'] is True
        if self.safe:
            data = read(self.logs/(name+'.log'), cap)
            expected = dict(bytes=len(data), sha256=closed['private_log_sha256'])
            self.remember(self.logs/(name+'.log'), expected)
            with (d/'parent.log').open('xb') as stream: stream.write(data)
            self.remember(d/'parent.log', expected)
        normal_closed(closed)
        self.unchanged(); row['status'] = 'CLOSED_EXIT_' + str(closed['exit_code'])
        return d, closed
    def request(self, directory, argv, cpu=20, wall=30, cap=CAP):
        directory.mkdir()
        req = dict(argv=list(map(str, argv)), cwd=str(ROOT), env=self.env, stdout=str(directory/'stdout.txt'),
                   stderr=str(directory/'stderr.txt'), cpu_seconds=cpu, wall_seconds=wall, file_bytes=cap)
        self.freeze(directory/'request.json', req)
        return req
    def plan_bounded(self, name, directory, req):
        helper = ROOT/'tools/unwind-oracle/bounded_command.py'
        self.command(name, [self.tools['python'], '-B', helper, '--request', directory/'request.json',
                           '--receipt', directory/'receipt.json'], req['wall_seconds']+25)
    def bounded(self, name, directory, req, generated=(), app_files=False):
        assert json.loads(read(directory/'request.json', MIB)) == req
        helper = ROOT/'tools/unwind-oracle/bounded_command.py'
        d, closed = self.owned(name, [self.tools['python'], '-B', helper, '--request', directory/'request.json',
                                     '--receipt', directory/'receipt.json'], req['wall_seconds'] + 25,
            growth=bounded_growth(req, generated, app_files))
        self.safe = False
        for path in (directory/'receipt.json', directory/'stdout.txt', directory/'stderr.txt'): self.remember(path, cap=max(MIB, req['file_bytes']))
        receipt = json.loads(read(directory/'receipt.json', MIB))
        code = bounded_join(receipt, closed, self.retained[str(directory/'request.json')], self.sources[str(helper)],
                            self.retained[str(directory/'stdout.txt')], self.retained[str(directory/'stderr.txt')])
        parent = json.loads(read(d/'parent.log', MIB))
        assert parent == dict(exit=code, wall_timeout=False, absence_proof='ECHILD', descendants=0, success=code == 0)
        self.safe = True
        for path, cap in generated:
            if path.exists(): self.remember(path, cap=cap)
        self.closed_inventory(directory)
        self.unchanged()
        if not app_files: self.budget.complete()
        return code, read(directory/'stdout.txt', req['file_bytes']), read(directory/'stderr.txt', req['file_bytes'])
    def stage(self, name, argv, cpu=20, wall=30, cap=MIB, generated=()):
        d = self.raw/(name+'-io'); req = self.request(d, argv, cpu, wall, cap)
        code, out, err = self.bounded(name, d, req, generated=generated)
        assert code == 0
        return out, err


def accept_native(run, directory, session):
    n = run.m['native']; result = json.loads(read(directory/'result.json', 32*MIB))
    native_summary(result, run.a.revision, session)
    run.remember(directory/'result.json')
    assert result['affinity'] == [run.cpus[1]]
    for path, expected in result['retained'].items():
        p = Path(path); assert p.is_absolute() and p.resolve(strict=True) == p
        assert p.is_relative_to(directory) or p.is_relative_to(ROOT/'target')
        run.remember(p, expected)
    for label, filename in (('plan', 'plan.json'), ('sources_before', 'sources-before.json'), ('sources_after', 'sources-after.json'),
                            ('tools', 'tools.json'), ('catalog', 'catalog.json'), ('calibration_manifest', 'calibration-manifest.json')):
        assert run.retained[str(directory/filename)] == result[label]
    before = json.loads(read(directory/'sources-before.json', 16*MIB))
    assert before == json.loads(read(directory/'sources-after.json', 16*MIB))
    assert before and all(run.sources.get(path) == value for path, value in before.items())
    native_tools = json.loads(read(directory/'tools.json', MIB))
    native_env = dict(run.env, TMPDIR=str(directory/'tmp'))
    for path, expected in native_tools.items():
        assert n.digest(Path(path)) == expected
        if path in run.tool_pins: assert run.tool_pins[path] == expected
        else: run.tool_pins[path] = expected
    plan = json.loads(read(directory/'plan.json', MIB))
    assert plan['mode'] == ('normal-module-session-state' if session else 'normal-module-state')
    if session: assert plan['profile'] == 'session-absolute-v1'
    else: assert 'profile' not in plan
    assert plan['k_order'] == ([10, 1000] if session else [16, 1]) and plan['native_invocations'] == 2 and plan['retries'] == 0
    assert plan['pair_seconds'] == 15 and plan['steps_per_child'] == 20000 and plan['whole_wall_seconds'] == 510
    assert plan['revision'] == run.a.revision and plan['seeds'] == list(run.m['native_output'].SEEDS) and plan['cases'] == list(range(1,17))
    assert plan['native'] == [dict(k=k, status='UNRUN', attempts=0, required_pairs=32, required_normal_reaps=64, required_target_calls=256) for k in plan['k_order']]
    module = run.m['native_output']
    assert json.loads(read(directory/'catalog.json', MIB)) == [dict(k=k, seed=seed, case=i+1, csv_length=length, csv_value=value,
        length_case=i%8+1, length_bound=module.LENGTH_BOUNDS[i%8], length_value=module.LENGTH_VALUES[i%8])
        for k in plan['k_order'] for seed in module.SEEDS for i,(length,value) in enumerate(zip(module.CSV_LENGTHS,module.CSV_VALUES))]
    helper = ROOT/'tools/unwind-oracle/bounded_command.py'
    for stage in result['stages']:
        d = directory/stage['name']
        request = json.loads(read(d/'request.json', MIB))
        assert request['cwd'] == str(ROOT) and request['env'] == native_env
        assert request['stdout'] == str(d/'stdout.txt') and request['stderr'] == str(d/'stderr.txt')
        assert set(request) == {'argv', 'cwd', 'env', 'stdout', 'stderr', 'cpu_seconds', 'wall_seconds', 'file_bytes'}
        build = stage['name'] in ('native-build', 'state-build', 'caller-build')
        assert (request['cpu_seconds'], request['wall_seconds'], request['file_bytes']) == ((120, 180, 128*MIB) if build else (20, 30, MIB))
        command = json.loads(read(d/'command.json', MIB))
        assert command == dict(argv=[str(run.tools['python']), '-B', str(helper), '--request', str(d/'request.json'),
            '--receipt', str(d/'receipt.json')], env=native_env, wall_seconds=request['wall_seconds']+25, log_bytes=MIB)
        closed = json.loads(read(d/'closed.json', MIB)); assert closed == stage['closed']
        receipt = json.loads(read(d/'receipt.json', MIB))
        assert bounded_join(receipt, closed, run.retained[str(d/'request.json')], run.sources[str(helper)],
                            run.retained[str(d/'stdout.txt')], run.retained[str(d/'stderr.txt')]) == 0
        parent = read(d/'parent.log', MIB)
        assert pin(parent)['sha256'] == closed['private_log_sha256']
        assert json.loads(parent) == dict(exit=0, wall_timeout=False, absence_proof='ECHILD', descendants=0, success=True)
    # Exact existing parser/census functions consume the retained actual streams.
    n.python_output(read(directory/'python-controls/stdout.txt', MIB), read(directory/'python-controls/stderr.txt', MIB))
    manifest = json.loads(read(directory/'calibration-manifest.json', MIB))
    legacy = load('native_legacy', ROOT/n.MODULES['legacy'])
    normal = load('native_normal', ROOT/n.MODULES['normal'])
    whole = load('native_whole', ROOT/n.MODULES['whole'])
    expected = n.calibration_manifest(legacy, normal, whole)
    assert manifest == dict(expected=expected, ignored={n.IGNORED: n.IGNORE_REASON}) and len(expected) == 163
    inventory = run.m['census'].census(read(directory/'state-list/stdout.txt', MIB), read(directory/'state-list/stderr.txt', MIB))
    assert set(inventory) == set(expected) | {n.IGNORED}
    n.calibration_output(read(directory/'state-controls/stdout.txt', MIB), read(directory/'state-controls/stderr.txt', MIB), expected)
    expected_caller = tuple('normal::caller::tests::'+name for name in normal.CALLER)
    caller_inventory = run.m['census'].census(read(directory/'caller-list/stdout.txt', MIB), read(directory/'caller-list/stderr.txt', MIB))
    assert set(v for v in caller_inventory if v.startswith('normal::caller::tests::')) == set(expected_caller) and len(expected_caller) == 4
    run.m['census'].controls(read(directory/'caller-controls/stdout.txt', MIB), read(directory/'caller-controls/stderr.txt', MIB), expected_caller, caller_inventory)
    for label, target, source, kind, test in (('native', 'frontend-native-oracle', 'native-interval/main.rs', 'bin', False),
        ('state', 'frontend-native-calibrations', 'native-interval/calibrations.rs', 'test', True),
        ('caller', 'ordinary-interval', 'ordinary-interval/main.rs', 'bin', True)):
        binary, product = n.artifact(read(directory/(label+'-build/stdout.txt'), 128*MIB), target, source, kind, test)
        manifest = json.loads(read(directory/(label+'-artifact.json'), MIB))
        assert manifest == dict(product=product, binary=n.digest(binary))
        assert result['artifacts'][label] == run.retained[str(directory/(label+'-artifact.json'))]
    selection = json.loads(read(directory/'selection.json', MIB))
    assert selection['csv_index'] == 0  # This application's fixed CSV then length image order.
    symbols = read(directory/'module-symbols/stdout.txt', MIB)
    selections = [n.selection(symbols, name, ceiling) for name,ceiling in (('csv_fields',256),('strnlen',80))]
    assert selection['selections'] == [list(pair) for pair in selections]
    for index,(name,(va,extent)) in enumerate(zip(('csv_fields','strnlen'),selections)):
        data = read(directory/(name+'-disassembly/stdout.txt'), MIB)
        assert n.body_geometry(n.geometry(data,name,va,extent),va,extent,name=='strnlen') == selection['geometry'][index]
    assert n.caller_geometry(read(directory/'caller-disassembly/stdout.txt', MIB), read(directory/'caller-symbols/stdout.txt', MIB)) == selection['caller']
    for row in result['native']:
        d = directory/('k'+str(row['k']))
        request = json.loads(read(d/'request.json', 16*MIB))
        # The launch validator requires nonexistent outputs; here authenticate the completed request.
        assert set(request) == {'argv', 'cwd', 'env', 'stdout', 'stderr', 'pins'}
        assert request['argv'] == [str(ROOT/'target/release/frontend-native-oracle'), plan['mode'], str(row['k']),
            str(directory/'module-candidate.so'), str(directory/'module-trusted.so'),
            *[str(v) for pair in selection['selections'] for v in pair],
            str(directory/'caller-candidate.so'), str(directory/'caller-trusted.so'), str(d/'native-output')]
        assert request['cwd'] == str(ROOT) and request['env'] == native_env
        assert request['stdout'] == str(d/'stdout.txt') and request['stderr'] == str(d/'stderr.txt')
        for path, expected in request['pins'].items():
            assert (before | native_tools | result['retained']).get(path) == expected
            assert n.digest(Path(path)) == expected
        command = json.loads(read(d/'native-command.json', MIB))
        assert command == dict(argv=[str(run.tools['python']), '-B', str(ROOT/'evaluation/ordinary-module-native/reproduce.py'),
            '--native-session-request' if session else '--native-request', str(d/'request.json'), run.retained[str(d/'request.json')]['sha256']],
            env=native_env, wall_seconds=510, log_bytes=MIB, cpu_seconds_per_process=480, file_bytes=MIB, core_bytes=0, pair_seconds=15, steps_per_child=20000)
        assert json.loads(read(d/'native-closed.json', MIB)) == row['closed']
        assert read(d/'native-parent.log', MIB) == b'' and row['closed']['private_log_sha256'] == pin(b'')['sha256']
        stem = 'normal-module-session' if session else 'normal-module'
        checker = run.m['native_output'].check_session if session else run.m['native_output'].check
        parsed = checker(read(d/('native-output/'+stem+'-pairs.csv'), 65536 if session else 32768),
            read(d/('native-output/'+stem+'-coverage.csv'), 65536 if session else 1024), read(d/'stdout.txt', 1024),
            read(d/'stderr.txt', MIB), row['k'], selection['geometry'], selection['csv_index'])
        assert row['rows'] == parsed['rows'] and row['coverage'] == parsed['coverage']
        assert row['comparisons'] == parsed['comparisons']
    for name in ('module-candidate.so', 'module-trusted.so'):
        assert run.retained[str(directory/name)] == selection['candidate' if 'candidate' in name else 'final']
    assert selection['candidate'] == selection['final']
    product = json.loads(read(directory/'caller-artifact.json', MIB))
    binary = Path(product['product']['executable'])
    assert n.digest(binary) == product['binary'] == run.retained[str(binary)]
    run.unchanged()
    return selection, binary


def owner_gate(run, binary, geometry, candidate, trusted):
    gate = run.result['prerequisites']['owner']
    assert gate['status'] == 'UNRUN' and gate['attempts'] == 0
    rows = [dict(k=k, direction=direction, status='UNRUN', attempts=0)
            for k in (10, 1000) for direction in ('csv-length', 'length-csv')]
    for index, row in enumerate(rows, 1):
        d = run.raw/f'owner-{index}'
        row['request'] = run.request(d, [binary, 'normal-module-session-owner', candidate, trusted,
            geometry['csv_va'], geometry['csv_length'], geometry['length_va'], geometry['length_length'], row['k'], row['direction']], cap=MIB)
        row['directory'] = str(d)
        run.plan_bounded(f'owner-{index}-outer', d, row['request'])
    gate.update(status='FAILED', attempts=1, rows=rows)
    run.freeze(run.raw/'owner-plan.json', rows)
    for index, row in enumerate(rows, 1):
        run.unchanged(); assert row['attempts'] == 0
        bounded_ready(run, row['request'])
        row.update(status='FAILED', attempts=1)
        code, stdout, stderr = run.bounded(f'owner-{index}-outer', Path(row['directory']), row['request'])
        try:
            assert code == 0
            parsed = run.m['output'].owner_check(stdout, stderr, k=row['k'], direction=row['direction'], geometry=geometry, cpus=tuple(run.cpus[:2]))
            row.update(status='OWNER_FUNCTIONAL_PASS', totals=parsed['totals'], pid=parsed['pid'], worker_tid=parsed['worker_tid'])
        except (AssertionError, ValueError, KeyError, IndexError, UnicodeError) as error:
            row['error'] = type(error).__name__
        run.unchanged(); run.freeze(run.raw/f'owner-{index}-outcome.json', row)
    assert all(row['status'] == 'OWNER_FUNCTIONAL_PASS' for row in rows)
    gate['status'] = 'OWNER_FUNCTIONAL_PASS'



def caller_symbol_command(tools, binary):
    # Read the complete table, retaining every exact matching row. pipefail
    # preserves readelf failures even when the filter has already found a row.
    # Positional arguments keep paths out of shell source; both tools are pinned.
    return [tools['bash'], '-o', 'pipefail', '-c',
            '"$1" --wide --syms "$2" | "$3" -- " liteinst_csv_call_and_store$"',
            'module-session-caller-symbols', tools['readelf'], binary, tools['rg']]


def caller(run, label, binary):
    data, err = run.stage(label+'-disassembly', [run.tools['objdump'], '-d', '-M', 'intel', '--insn-width=16',
                                               '--disassemble=liteinst_csv_call_and_store', binary])
    assert err == b''
    shape = run.m['csv'].caller_geometry(data.decode('ascii'))
    symbols, err = run.stage(label+'-symbols', caller_symbol_command(run.tools, binary)); assert err == b''
    run.m['module'].caller_symbols(symbols.decode('ascii'), shape)
    return shape


def freeze_campaign(run, binary, original, geometry, candidate, trusted, original_dso):
    records = []
    for i in range(32):
        spec = run.m['producer'].case_spec(run.m['corpus'], i)
        records.append(tuple((r.payload, r.fields) for r in spec['records']))
    plans = run.raw/'plans'; plans.mkdir()
    static = run.sources | run.tool_pins | run.retained
    pin_map = {path: value['sha256'] for path, value in static.items()}
    for row in run.result['originals']:
        i = row['case']; input_path = plans/f'original-{i:02}.bin'
        input_bytes = frame(records[i]); run.budget.charge(str(input_path), len(input_bytes))
        with input_path.open('xb') as f: f.write(input_bytes)
        run.remember(input_path)
        directory = run.raw/f'original-{i:02}'
        argv = [original, original_dso, geometry['csv_va'], geometry['csv_length'], geometry['length_va'], geometry['length_length'], input_path, run.cpus[1]]
        row['request'] = run.request(directory, argv); row['directory'] = str(directory)
        run.plan_bounded(directory.name+'-owner', directory, row['request'])
    for row in run.result['installed']:
        i = row['case']; spec = run.m['producer'].case_spec(run.m['corpus'], i)
        label = f"attempt-{row['attempt']}-k{row['k']}-case-{i:02}"
        path = plans/(label+'.json'); child_raw = run.raw/(label+'-child')
        plan = dict(case=i, name=spec['name'], k=row['k'], cpus=run.cpus, geometry=geometry,
                    binary=str(binary), candidate=str(candidate), trusted=str(trusted), pins=pin_map,
                    argv=[str(binary), 'normal-module-session', str(candidate), str(trusted), str(geometry['csv_va']),
                          str(geometry['csv_length']), str(geometry['length_va']), str(geometry['length_length']), str(row['k']), '520'])
        plan_pin = run.freeze(path, plan)
        directory = run.raw/label
        row['request'] = run.request(directory, [run.tools['python'], '-B', HERE/'produce.py', '--plan', path,
                                                '--plan-sha', plan_pin['sha256'], '--raw', child_raw])
        row.update(directory=str(directory), child_raw=str(child_raw), plan=str(path))
        run.plan_bounded(directory.name+'-owner', directory, row['request'])
    run.freeze(run.raw/'campaign-plan.json', dict(revision=run.a.revision, originals=run.result['originals'], installed=run.result['installed'],
        original_count=32, installed_count=320, whole_attempts=5, retries=0, outer_wall_seconds=7200,
        cpu_seconds=20, inner_wall_seconds=30, owner_wall_seconds=55, producer_seconds=15, stream_bytes=CAP,
        accepted=[[dict(payload_hex=p.hex(), fields=f) for p, f in rows] for rows in records]), cap=16*MIB)
    run.unchanged()
    return records


def campaign(run, records, geometry):
    originals = {}
    for row in run.result['originals'] + run.result['installed']:
        run.unchanged(); assert row['status'] == 'UNRUN' and row['attempts'] == 0
        bounded_ready(run, row['request'], app_files=row['leg'] == 'installed')
        row.update(status='FAILED', attempts=1)
        label = Path(row['directory']).name
        code, stdout, stderr = run.bounded(label+'-owner', Path(row['directory']), row['request'], app_files=row['leg'] == 'installed')
        try:
            i = row['case']; actual = None
            if row['leg'] == 'original':
                assert code == 0
                actual = run.m['output'].original_check(stdout, stderr, records=records[i],
                    lengths=(geometry['csv_length'], geometry['length_length']), cpu=run.cpus[1])
                originals[i] = actual['results']
                row.update(records=len(records[i]), calls=2*len(records[i]), child_exit=0, normal_reaps=1)
            else:
                d = Path(row['child_raw'])
                # Wrapper closure does not establish the APP identity or normal reap.
                run.safe = False
                for name in ('result.json', 'stdout.txt', 'stderr.txt'): run.remember(d/name, cap=CAP)
                producer = json.loads(read(d/'result.json', CAP))
                assert producer['normal_reaps'] == 1 and producer['rescue'] is False and producer['cleanup_error'] is None
                assert type(producer['child_exit']) is int and producer['child_exit'] in (0, 1)
                app_out, app_err = read(d/'stdout.txt', CAP), read(d/'stderr.txt', CAP)
                spec = run.m['producer'].case_spec(run.m['corpus'], i)
                checked = run.m['output'].check(app_out, app_err, records=records[i], k=row['k'], epochs=520,
                    outcome=spec['outcome'], input_error=spec['input_error'], lengths=(geometry['csv_length'], geometry['length_length']),
                    returns=tuple(tuple(v) for v in geometry['returns']), continuation=geometry['continuation'], cpus=tuple(run.cpus[:2]))
                assert type(producer['child_pid']) is int and producer['child_pid'] == checked['rows']['READY'][0]['pid']
                run.safe = True; run.budget.complete()
                expected_bytes = len(run.m['corpus'].framed(spec['records'])) if i >= 30 else len(spec['data'])
                producer_join(producer, code, app_out, app_err, checked, expected_bytes)
                assert stderr == b'' and json.loads(stdout) == producer
                assert producer['case'] == i and producer['name'] == spec['name'] and producer['k'] == row['k']
                if i == 30:
                    assert checked['totals']['epochs'] == 520 and checked['rows']['DONE'][0]['history_end'] == 521
                    assert any(r['owner'] == 'sampled' and r['history_prefix'] >= 513 for r in checked['rows']['CALL'])
                if i == 31: assert checked['rows']['IO'][0]['write_blocked'] > 0
                assert i in originals and producer['original_values'] == originals[i]
                row.update(**checked['totals'], child_exit=producer['child_exit'], normal_reaps=producer['normal_reaps'],
                           write_blocked=producer['write_blocked'])
            run.unchanged(); row['status'] = 'PASS'
        except BaseException as error:
            row['error'] = type(error).__name__
            if not run.safe: raise
            run.unchanged()  # A closed functional failure never licenses source drift.
        run.freeze(run.raw/(label+'-outcome.json'), row)


def main():
    started = time.monotonic()
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--revision', required=True); ap.add_argument('--reservation-tag', required=True)
    for name in ('raw', 'toolchain', 'user-home', 'cargo-home'): ap.add_argument('--'+name, type=Path, required=True)
    a = ap.parse_args(); assert re.fullmatch('[0-9a-f]{40}', a.revision)
    assert re.fullmatch('[A-Za-z0-9_.-]{1,128}', a.reservation_tag)
    assert HERE == ROOT/'evaluation/ordinary-module-session'
    for p in (ROOT, a.toolchain, a.user_home, a.cargo_home): assert p.is_absolute() and p.resolve(strict=True) == p and p.is_dir()
    assert a.raw.is_absolute() and a.raw.parent.resolve(strict=True) == a.raw.parent
    assert a.raw.is_relative_to(ROOT/'ignored') and not a.raw.exists()
    os.chdir(ROOT)
    tools = {n: (a.toolchain/'bin'/n).resolve(strict=True) for n in ('cargo', 'rustc', 'rustdoc')}
    tools.update({n: Path('/usr/bin', n).resolve(strict=True) for n in ('git', 'gcc', 'readelf', 'objdump', 'taskset', 'bash', 'rg')})
    tools['python'] = Path(sys.executable).resolve(strict=True)
    env = dict(HOME=str(a.user_home), CARGO_HOME=str(a.cargo_home), PATH=str(a.toolchain/'bin')+':/usr/bin:/bin',
        RUSTC=str(tools['rustc']), RUSTDOC=str(tools['rustdoc']), CC=str(tools['gcc']), CARGO_TARGET_DIR=str(ROOT/'target'),
        CARGO_INCREMENTAL='0', CARGO_BUILD_JOBS='4', CARGO_NET_OFFLINE='true', CARGO_PROFILE_RELEASE_OPT_LEVEL='3',
        CARGO_PROFILE_RELEASE_DEBUG='0', CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS='true', CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS='true',
        CARGO_TERM_COLOR='never', LC_ALL='C', PYTHONDONTWRITEBYTECODE='1', PYTHONNOUSERSITE='1', LITEINST_EVALUATION='1', TMPDIR=str(a.raw/'tmp'))
    def git(*argv):
        data = subprocess.check_output([tools['git'], '-C', ROOT, *argv], env=env, timeout=15)
        assert len(data) <= 32*MIB; return data
    assert git('rev-parse', '--show-toplevel').decode().strip() == str(ROOT)
    assert git('rev-parse', 'HEAD').decode().strip() == a.revision and git('status', '--porcelain', '--untracked-files=no') == b''
    required = set(MODULES.values()) | {'tools/unwind-oracle/bounded_command.py', 'tests/call_tree_truth.rs',
        'evaluation/ordinary-module-session/reproduce.py', 'evaluation/ordinary-module-session/controls.py',
        'evaluation/ordinary-module-session/original.c', 'evaluation/ordinary-module-native/controls.py',
        'tools/rapid-profiler/strnlen-work/localize.map',
        'tools/rapid-profiler/ordinary-interval/normal/module/session/owner.rs',
        'tools/rapid-profiler/ordinary-interval/normal/module/session/owner/check.rs',
        'tools/rapid-profiler/ordinary-interval/normal/module/session/owner/tests.rs'}
    names = git('ls-files', '-z', '--', 'src', 'tests/support', 'tools/rapid-profiler', 'Cargo.toml', 'Cargo.lock', 'README.md',
                'build.rs', ':(glob)**/Cargo.toml', *sorted(required)).decode().rstrip('\0').split('\0')
    assert all(names) and len(names) == len(set(names)) and required <= set(names)
    sources = {}
    for name in names:
        data = read(ROOT/name); assert data == git('show', a.revision+':'+name)
        sources[str(ROOT/name)] = pin(data)
    for name, expected in (('evaluation/admission/processes.py', OWNER_SHA), ('tools/unwind-oracle/bounded_command.py', BOUNDED_SHA),
                           ('evaluation/ordinary-module-session/corpus.py', CORPUS_SHA)):
        assert sources[str(ROOT/name)]['sha256'] == expected
    tool_pins = {str(path): pin(read(path, 512*MIB)) for path in tools.values()}
    modules = {key: load(key, ROOT/path) for key, path in MODULES.items()}
    assert set(modules['native'].NATIVE_SOURCES) | set(modules['native'].MODULES.values()) <= set(names)
    a.raw.mkdir(mode=0o700); (a.raw/'tmp').mkdir()
    run = Run(a, a.raw, tools, env, sources, modules, started, tool_pins)
    run.freeze(a.raw/'sources-before.json', sources, cap=16*MIB)
    run.freeze(a.raw/'initial-plan.json', dict(revision=a.revision, originals=32, attempts=5, installed=320,
        native_profiles=[dict(name='finite', k=[16, 1]), dict(name='session', k=[10, 1000])], owner_controls=[dict(k=k, direction=d) for k in (10,1000) for d in ('csv-length','length-csv')], retries=0, outer_seconds=7200,
        affinity=run.cpus, reservation_tag=a.reservation_tag, reservation_authority='external owner only',
        evidence_limit=EVIDENCE_LIMIT, final_allowance=FINAL_ALLOWANCE, native_growth_reservation=NATIVE_GROWTH,
        build_space_exclusions=[str(p) for p in run.build_scratch], shared_build_space=str(ROOT/'target')))
    try:
        native_dir = run.native_dirs['session']
        native_commands = []
        for label, session in (('finite', False), ('session', True)):
            directory = run.native_dirs[label]
            argv = [tools['taskset'], '-c', run.cpus[1], tools['python'], '-B',
                    ROOT/'evaluation/ordinary-module-native/reproduce.py', '--revision', a.revision, '--toolchain', a.toolchain,
                    '--user-home', a.user_home, '--cargo-home', a.cargo_home, '--output', directory]
            if session: argv.append('--session-absolute')
            run.command('native-'+label+'-prerequisite', argv, 1200, 8*MIB)
            native_commands.append((label, session, directory, argv))
        for label, session, directory, argv in native_commands:
            gate = run.result['prerequisites'][label]
            assert gate['status'] == 'UNRUN' and gate['attempts'] == 0
            assert time.monotonic() + 1203 < run.deadline
            run.budget.room(NATIVE_GROWTH)
            gate.update(status='FAILED', attempts=1)
            _, closed = run.owned('native-'+label+'-prerequisite', argv, 1200, 8*MIB, growth=NATIVE_GROWTH)
            gate['closed'] = closed
            # A failed closed prerequisite remains visible; never borrow an earlier receipt.
            if (directory/'result.json').exists():
                run.remember(directory/'result.json', cap=32*MIB)
                observed = json.loads(read(directory/'result.json', 32*MIB))
                gate['observed_status'] = observed['status']
                if observed.get('custody_closed') is True:
                    for path, expected_pin in observed.get('retained', {}).items(): run.remember(Path(path), expected_pin)
            assert closed['exit_code'] == 0
            selected, test_artifact = accept_native(run, directory, session)
            run.closed_inventory(directory); run.budget.complete()
            gate['status'] = 'NATIVE_SESSION_STATE_PASS' if session else 'NATIVE_STATE_PASS'
            if session: selection, test_binary = selected, test_artifact
        candidate, trusted = native_dir/'module-candidate.so', native_dir/'module-trusted.so'
        data, _ = run.stage('application-build', [tools['cargo'], 'build', '--bin', 'ordinary-interval', '--locked', '--offline',
            '--release', '--jobs', '4', '-p', 'rapid-profiler', '--message-format=json-render-diagnostics'], 120, 180, 128*MIB)
        binary, product = modules['native'].artifact(data, 'ordinary-interval', 'ordinary-interval/main.rs', 'bin', False)
        run.remember(binary); run.freeze(a.raw/'application-artifact.json', dict(product=product, binary=run.retained[str(binary)]))
        shape = caller(run, 'application-caller', binary)
        (csv_va, csv_length), (length_va, length_length) = selection['selections']
        geometry = dict(csv_va=csv_va, csv_length=csv_length, length_va=length_va, length_length=length_length,
                        returns=[g['returns'] for g in selection['geometry']], continuation=shape['continuation_offset'])
        assert csv_va + csv_length <= length_va and csv_va//4096 == (length_va+length_length-1)//4096
        data, err = run.stage('ordinary-list', [test_binary, '--list'])
        inventory = modules['census'].census(data, err)
        expected = ordinary_inventory(inventory, modules['single'], modules['module'], OWNER_CONTROLS)
        data, err = run.stage('ordinary-controls', [test_binary, *expected, '--exact', '--test-threads=1'])
        modules['census'].controls(data, err, expected, inventory)
        owner_gate(run, binary, geometry, candidate, trusted)
        # Exact method identities and successful individual results are required.
        data, err = run.stage('python-controls', [tools['python'], '-B', HERE/'controls.py', '-v'])
        python_controls(data, err)
        original = a.raw/'original'
        data, err = run.stage('original-build', [tools['gcc'], '-O2', '-std=c11', '-Wall', '-Wextra', '-Werror',
            '-fno-stack-protector', '-fomit-frame-pointer', '-fcf-protection=none', '-fno-builtin', '-Wl,--build-id=none,-z,now,-z,noexecstack',
            HERE/'original.c', '-ldl', '-o', original], generated=((original, 512*MIB),))
        assert data == err == b''; run.remember(original)
        original_shape = caller(run, 'original-caller', original)
        original_dso = a.raw/'original-module.so'
        original_bytes = read(trusted, MIB)
        run.budget.charge(str(original_dso), len(original_bytes))
        with original_dso.open('xb') as f: f.write(original_bytes)
        assert (original_dso.stat().st_dev, original_dso.stat().st_ino) != (trusted.stat().st_dev, trusted.stat().st_ino)
        assert (original_dso.stat().st_dev, original_dso.stat().st_ino) != (candidate.stat().st_dev, candidate.stat().st_ino)
        run.remember(original_dso, run.retained[str(trusted)])
        run.freeze(a.raw/'geometry.json', dict(geometry=geometry, caller=shape, original_caller=original_shape,
                                             selection=selection, original_dso=run.retained[str(original_dso)]))
        controls = []
        for name, content in malformed_frames():
            d = a.raw/('malformed-'+name); input_path = a.raw/('malformed-'+name+'.bin')
            run.budget.charge(str(input_path), len(content))
            with input_path.open('xb') as f: f.write(content)
            run.remember(input_path)
            req = run.request(d, [original, original_dso, csv_va, csv_length, length_va, length_length, input_path, run.cpus[1]])
            controls.append(dict(name=name, directory=str(d), request=req, status='UNRUN', attempts=0))
            run.plan_bounded('malformed-'+name+'-owner', d, req)
        run.result['controls'] = controls; run.freeze(a.raw/'malformed-plan.json', controls)
        records = freeze_campaign(run, binary, original, geometry, candidate, trusted, original_dso)
        for row in controls:
            assert row['attempts'] == 0
            bounded_ready(run, row['request'])
            row.update(status='FAILED', attempts=1)
            code, out, err = run.bounded('malformed-'+row['name']+'-owner', Path(row['directory']), row['request'])
            try:
                modules['output'].original_refusal(out, err, code, row['name'])
                row['status'] = 'EXPECTED_INPUT_REFUSAL'
            except (AssertionError, ValueError, UnicodeError) as error:
                row['error'] = type(error).__name__
            run.unchanged(); run.freeze(a.raw/('malformed-'+row['name']+'-outcome.json'), row)
        assert all(row['status'] == 'EXPECTED_INPUT_REFUSAL' for row in controls)
        campaign(run, records, geometry)
        run.unchanged(); run.freeze(a.raw/'sources-after.json', sources, cap=16*MIB)
        if all(row['status'] == 'PASS' for row in run.result['originals'] + run.result['installed']):
            run.result['status'] = 'FUNCTIONAL_CAMPAIGN_PASS'
    except BaseException as error:
        run.result['error'] = type(error).__name__
    finally:
        # Do not read child files, repin old evidence, or grant acceptance on this path.
        run.budget.stopped()
        run.result.update(custody_closed=run.safe, retained=dict(run.retained), tool_pins=dict(run.tool_pins),
                          end_utc=dt.datetime.now(dt.timezone.utc).isoformat(), load_after=list(os.getloadavg()),
                          evidence_budget=run.budget.summary(), build_space_exclusions=[str(p) for p in run.build_scratch])
        try:
            if not run.safe: raise RuntimeError('custody not closed')
            assert not run.budget.exceeded and run.budget.used <= EVIDENCE_LIMIT - FINAL_ALLOWANCE
            run.unchanged(); run.result['retention_verified'] = True
        except BaseException as error:
            run.result.update(status='FAILED', final_error=type(error).__name__)
        projection = public_projection(run.result)
        save(a.raw/'result.json', run.result, 16*MIB); save(a.raw/'summary.json', projection, 8*MIB)
        table = io.StringIO(newline='')
        writer = csv.DictWriter(table, fieldnames=list(projection['rows'][0]), lineterminator='\n')
        writer.writeheader(); writer.writerows(projection['rows'])
        table_bytes = table.getvalue().encode('ascii'); assert len(table_bytes) <= 8*MIB
        with (a.raw/'results.csv').open('xb') as f: f.write(table_bytes)
        print(json.dumps({k: v for k, v in projection.items() if k != 'rows'}, sort_keys=True))
    return 0 if run.result['status'] == 'FUNCTIONAL_CAMPAIGN_PASS' else 1


PYTHON_CONTROLS = ('test_caller_symbol_filter_keeps_all_matches_failures_and_literal_paths', 'test_actual_stderr_requires_exact_finalized_outcome_and_no_hard_diagnostic', 'test_campaign_actual_producer_identity_and_all_failure_rows', 'test_campaign_closed_functional_failure_continues_but_unknown_custody_stops', 'test_campaign_commands_freeze_exact_argv_before_owner_and_never_refresh', 'test_campaign_exact_ordinary_namespaces_keep_unrelated_two_caller_inventory', 'test_campaign_exact_python_names_and_local_import_refusal', 'test_campaign_fixed_catalog_frames_and_owner_status_join', 'test_campaign_missing_app_identity_stops_and_budget_stop_keeps_unrun', 'test_campaign_native_profiles_census_and_complete_retained_counts', 'test_campaign_storage_reserves_complete_stage_and_never_refreshes_charge', 'test_complete_empty_closed_and_absolute_history_populations', 'test_eof_typed_refusal_and_incomplete_are_distinct', 'test_every_family_missing_duplicate_reorder_and_extra_refuses', 'test_fixed_catalog_has_exact_special_inputs_and_error_classes', 'test_global_slots_function_ranks_closed_budget_and_report_order', 'test_history_starts_at_one_and_preserves_multi_action_chunks', 'test_numeric_framing_actual_stderr_and_caps', 'test_optimization_refuses_before_production_checks', 'test_original_input_refusal_never_accepts_hard_failure', 'test_original_reference_uses_all_values_and_exact_population', 'test_owner_four_cases_keep_full_raw_zero_max_and_unavailable', 'test_owner_identity_phases_reports_raw_and_complete_order_refuse', 'test_scalar_input_fingerprint_and_complete_results_are_independent', 'test_stack_continuation_ack_and_batch_boundaries', 'test_zero_maximum_and_raw_unavailable_are_retained')


def python_controls(stdout, stderr):
    assert stdout == b'' and type(stderr) is bytes
    lines = stderr.decode('ascii').splitlines()
    assert len(lines) == len(PYTHON_CONTROLS)+5
    for name, line in zip(sorted(PYTHON_CONTROLS), lines):
        assert re.fullmatch(re.escape(name)+r' \(__main__\.Controls(?:\.'+re.escape(name)+r')?\) \.\.\. ok', line)
    tail = lines[len(PYTHON_CONTROLS):]
    assert tail[0] == tail[3] == '' and tail[4] == 'OK' and re.fullmatch('-+', tail[1])
    assert re.fullmatch(rf'Ran {len(PYTHON_CONTROLS)} tests in [0-9]+\.[0-9]+s', tail[2])


if __name__ == '__main__':
    raise SystemExit(main())
