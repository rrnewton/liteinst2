"""Fixed CallPair producer contract; no native or ownership authority from labels."""
import sys
if sys.flags.optimize:
    raise SystemExit('assertions required')
import hashlib
import json
from pathlib import Path
import re
from typing import NamedTuple

PREFIX = 'evaluation/ordinary-call-pair-session/'
SHARED = 'evaluation/ordinary-module-session/'
CORPUS = '6feddb81816cc509e1357edec646ab60ba433a4a857d094ddce4d09a0c3ee738'
SOURCES = tuple(PREFIX + n for n in ('produce.py', 'profile.py', 'output.py', 'producer_controls.py')) + tuple(
    SHARED + n for n in ('reproduce.py', 'produce.py', 'corpus.py', 'output.py'))
CONTROLS = (
    'test_fixed_call_pair_plan_and_all_case_bytes',
    'test_ready_requires_actual_profile_pid_roles_before_input',
    'test_closed_envelope_precedes_custody_release',
    'test_projection_failure_and_literal_default_lifecycle',
    'test_authenticated_imports_and_optimized_refusal',
)


def uint(text):
    assert type(text) is str and re.fullmatch(r'0|[1-9][0-9]{0,19}', text)
    value = int(text)
    assert value < 1 << 64
    return value


class CallPairBinding(NamedTuple):
    identity: str
    application_profile: str
    producer_path: str
    corpus_sha256: str
    checker_path: str

    def fields(self, plan):
        self.check_plan(plan)
        return {key: plan[key] for key in ('profile', 'application_profile', 'producer', 'corpus_sha256', 'attempt')}

    def check_plan(self, plan):
        assert type(self) is CallPairBinding and self == call_pair_binding()
        for key, value in (('profile', self.identity), ('application_profile', self.application_profile),
                           ('producer', self.producer_path), ('corpus_sha256', self.corpus_sha256)):
            assert type(plan[key]) is str and plan[key] == value
        assert type(plan['attempt']) is int and 1 <= plan['attempt'] <= 5
        assert type(plan['case']) is int and 0 <= plan['case'] < 32
        assert type(plan['k']) is int and plan['k'] in (10, 1000)
        assert type(plan['epochs']) is int and plan['epochs'] == 520
        assert type(plan['name']) is str and plan['name']
        assert type(plan['data_sha256']) is str and re.fullmatch('[0-9a-f]{64}', plan['data_sha256'])
        cpus = plan['cpus']
        assert type(cpus) is list and len(cpus) == 3 and cpus == sorted(set(cpus))
        assert all(type(c) is int and 0 <= c < 1024 for c in cpus)
        geometry = plan['geometry']
        assert type(geometry) is dict and set(geometry) == {'parent', 'child'}
        spans = []
        for name, limit in (('parent', 80), ('child', 256)):
            item = geometry[name]
            assert type(item) is dict
            va, length = item['elf_va'], item['length']
            assert type(va) is int and 0 < va < 1 << 64
            assert type(length) is int and (5 if name == 'parent' else 1) <= length <= limit
            assert va + length < 1 << 64
            returns = item['returns']
            assert type(returns) is list and returns and returns == sorted(set(returns))
            assert all(type(r) is int and 0 <= r < length for r in returns)
            spans.append((va, va + length))
        assert spans[0][1] <= spans[1][0] or spans[1][1] <= spans[0][0]
        assert len({v // 4096 for lo, hi in spans for v in (lo, hi - 1)}) <= 2
        caller = plan['caller']
        assert type(caller) is dict and type(caller['length']) is int and 5 <= caller['length'] <= 256
        assert type(caller['continuation_offset']) is int and 0 < caller['continuation_offset'] < caller['length']
        for key in ('binary', 'candidate', 'trusted'):
            assert type(plan[key]) is str and Path(plan[key]).is_absolute() and '\0' not in plan[key]
        assert plan['candidate'] != plan['trusted']
        parent, child = geometry['parent'], geometry['child']
        assert plan['argv'] == [plan['binary'], 'normal-call-pair-session', plan['candidate'], plan['trusted'],
                                str(plan['k']), '520', '501', str(parent['elf_va']), str(parent['length']),
                                '502', str(child['elf_va']), str(child['length'])]

    def check_sources(self, root, pins):
        assert type(self) is CallPairBinding and self == call_pair_binding()
        assert isinstance(root, Path) and root.is_absolute() and type(pins) is dict
        for relative in SOURCES:
            path = root / relative
            assert path.resolve(strict=True) == path and not path.is_symlink() and path.is_file()
            assert 0 < path.stat().st_size <= 1048576
            digest = pins[str(path)]
            assert type(digest) is str and re.fullmatch('[0-9a-f]{64}', digest)
            assert hashlib.sha256(path.read_bytes()).hexdigest() == digest
        assert pins[str(root / SHARED / 'corpus.py')] == CORPUS

    def arguments(self, plan, case, corpus):
        self.check_plan(plan)
        assert plan['name'] == case['name']
        data = corpus.framed(case['records']) if plan['case'] >= 30 else case['data']
        assert hashlib.sha256(data).hexdigest() == plan['data_sha256']

    def ready(self, raw, pid, plan):
        self.check_plan(plan)
        assert type(raw) is bytes and 0 < len(raw) + 1 <= 350
        row = raw.decode('ascii').split(',')
        assert len(row) == 17 and row[:2] == ['READY', self.application_profile]
        values = list(map(uint, row[2:]))
        assert values[:9] == [plan['k'], 520, 10, 2, 64, 2048, 4, 1, 0x63700001]
        assert type(pid) is int and 0 < pid < 1 << 31
        assert values[9] == values[10] == pid and 0 < values[11] < 1 << 31 and values[11] != pid
        assert values[12:14] == plan['cpus'][:2] and values[14] > 0

    def uint(self, text):
        return uint(text)

    def check(self, checker, stdout, stderr, plan, case):
        self.check_plan(plan)
        return checker.check(stdout, stderr,
            records=tuple(r.payload for r in case['records']),
            k=plan['k'], epochs=520, outcome=case['outcome'], input_error=case['input_error'],
            geometry=plan['geometry'], caller=plan['caller'], cpus=tuple(plan['cpus'][:2]))

    def history_complete(self, checked, phase):
        # CallPair DONE/totals expose arms; do not invent an epochs wire alias.
        assert phase == 2 and checked['totals']['arms'] == 520
        assert checked['rows']['DONE'][0]['history_end'] == 521
        assert any(row['owner'] == 'sampled' and row['history_prefix'] >= 513 for row in checked['rows']['CALL'])

    def project(self, checked):
        # The independent checker owns all nested generation/tree/Report joins.
        # Keep its direct results and coverage; never manufacture a flat transcript.
        return dict(status='PASS', totals=checked['totals'], done=checked['rows']['DONE'][0],
                    write_blocked=checked['rows']['IO'][0]['write_blocked_count'],
                    original_values=checked['results'], coverage=checked['coverage'])


def call_pair_binding():
    return CallPairBinding('call-pair-session-qualification-v1', 'normal-call-pair-session-v1',
                           PREFIX + 'produce.py', CORPUS, PREFIX + 'output.py')


def confirm_custody(run, plan, result, code, out, err, app_out, app_err, checked):
    """After Run.bounded and first-pin verification, authorize only identified closure."""
    assert run.safe is False and run.budget.active is True
    binding = call_pair_binding()
    binding.check_plan(plan)
    for key, value in binding.fields(plan).items():
        assert type(result[key]) is type(value) and result[key] == value
    assert type(code) is int and code in (0, 1)
    assert type(result['status']) is str and result['status'] in ('PASS', 'FAILED')
    assert type(result['normal_reaps']) is int and result['normal_reaps'] == 1
    assert result['rescue'] is False and result['cleanup_error'] is None
    assert type(result['child_pid']) is int and result['child_pid'] == checked['rows']['READY'][0]['pid']
    assert type(result['child_exit']) is int and result['child_exit'] in (0, 1)
    assert result['stdout_sha256'] == hashlib.sha256(app_out).hexdigest()
    assert result['stderr_sha256'] == hashlib.sha256(app_err).hexdigest()
    assert err == b'' and json.loads(out) == result
    for key in ('case', 'name', 'k'):
        assert type(result[key]) is type(plan[key]) and result[key] == plan[key]
    run.unchanged()
    run.budget.complete()
    run.safe = True


def join_pass(plan, result, code, checked, expected_bytes):
    """Functional acceptance remains separate from permission to run the next fixed slot."""
    binding = call_pair_binding()
    binding.check_plan(plan)
    assert type(code) is int and code == 0 and result['status'] == 'PASS'
    assert type(result['sent_bytes']) is int and result['sent_bytes'] == expected_bytes
    assert result['child_exit'] == checked['expected_exit']
    for key, value in binding.project(checked).items():
        assert result[key] == value
