"""Narrow child-envelope joins for the existing recipe.Run; never an executor.

Run.bounded has already authenticated the unchanged outer helper receipt/ECHILD
closure. This module joins the additional producer and actual child streams.
A failure to establish normal child closure must leave run.safe false.
"""
import sys
if sys.flags.optimize:
    raise SystemExit('assertions required')
import json
from pathlib import Path

CAP = 4 * 1024 * 1024
MIB = 1024 * 1024
IDENTITY = ('profile', 'revision', 'leg', 'variant', 'index', 'name', 'n', 'k')


def child_envelope(run, recipe, plan, directory, code, stdout, stderr):
    """Return a normally closed child, even when its functional result failed."""
    run.safe = False
    assert run.budget.active is True
    assert type(code) is int and code in (0, 1) and stderr == b''
    directory = Path(directory)
    for name, cap in (('result.json', MIB), ('stdout.txt', CAP), ('stderr.txt', CAP)):
        run.remember(directory / name, cap=cap)
    result = json.loads(recipe.read(directory / 'result.json', MIB))
    actual = recipe.read(directory / 'stdout.txt', CAP)
    errors = recipe.read(directory / 'stderr.txt', CAP)
    assert json.loads(stdout) == result
    assert all(type(result[key]) is type(plan[key]) and result[key] == plan[key] for key in IDENTITY)
    assert result['status'] in ('PASS', 'FAILED')
    assert result['normal_reaps'] == 1 and type(result['normal_reaps']) is int
    assert result['rescue'] is False and result['cleanup_error'] is None
    assert type(result['child_pid']) is int and result['child_pid'] > 0
    assert type(result['child_exit']) is int
    assert result['stdout_sha256'] == recipe.pin(actual)['sha256']
    assert result['stderr_sha256'] == recipe.pin(errors)['sha256']
    assert type(result['sent_bytes']) is int and result['sent_bytes'] >= 0
    if result['status'] == 'PASS':
        assert code == result['child_exit'] == 0
    else:
        assert code == 1
    # The caller must still join the exact immutable input, functional checks and
    # source pins, then complete the evidence reservation before safe=True.
    return result, actual, errors


def pass_observations(plan, case, result, actual, errors, oracle, checker, checker_args):
    assert result['status'] == 'PASS' and result['child_exit'] == 0
    assert result['sent_bytes'] == len(case['data'])
    expected = [[i, len(record), oracle.fnv(record), *oracle.values(record)]
                for i, record in enumerate(case['records'], 1)]
    assert result['original_values'] == expected
    if plan['leg'] == 'reference':
        assert errors == b''
        calls = oracle.compare(actual, plan['k'], True)
        assert result['records'] == len(case['records']) and result['calls'] == calls
        assert calls == 2 * len(case['records'])
        # No synthesized READY or opaque installed receipt exists in this leg.
        return dict(values=expected, records=len(case['records']), calls=calls,
                    child_pid=result['child_pid'], source='actual-original-stdout')
    assert plan['leg'] == 'installed'
    checked = checker.check(actual, errors, **checker_args)
    assert checked['status'] == 'SELECTED_SESSION_WIRE_PASS'
    assert checked['raw'] == actual and checked['stderr'] == errors
    assert checked['rows']['READY'][0]['pid'] == result['child_pid']
    assert result['totals'] == checked['totals']
    assert result['done'] == checked['rows']['DONE'][0]
    assert result['write_blocked'] == checked['rows']['IO'][0]['write_blocked']
    observed = [[row['record_id'], row['length'], row['checksum'], row['value_0'], row['value_1']]
                for row in checked['rows']['RESULT']]
    assert observed == expected
    return dict(values=observed, totals=checked['totals'], child_pid=result['child_pid'],
                source='actual-installed-wire', checked=checked)


def complete_closed_cell(run, recipe, producer, oracle, checker, plan, directory,
                         code, stdout, stderr):
    """Run's outer custody is necessary, never sufficient for a passing cell."""
    result, actual, errors = child_envelope(run, recipe, plan, directory, code, stdout, stderr)
    case, checker_args = producer.plan_arguments(plan, oracle, checker)
    assert result['sent_bytes'] <= len(case['data'])
    observations = None
    why = None
    if result['status'] == 'PASS':
        # A contradictory PASS manifest is not downgraded into a safe failure.
        observations = pass_observations(plan, case, result, actual, errors, oracle, checker, checker_args)
    else:
        assert type(result.get('error')) is str
        why = result['error']
    run.unchanged()
    run.budget.complete()
    run.safe = True
    return dict(status=result['status'], result=result, observations=observations, error=why)
