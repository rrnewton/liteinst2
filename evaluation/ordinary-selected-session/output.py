"""Fixed selected-session full numeric wire; no native, custody or clock authority.

The caller pins this module, the shared checker and the independent oracle before
loading them. Actual bytes are parsed directly; no observed field is projected.
"""
import sys
if not __debug__:
    raise SystemExit('assertions required')
sys.dont_write_bytecode = True
import importlib.util
from pathlib import Path


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_HERE = Path(__file__).resolve().parent
_shared = _load('_selected_session_shared_wire',
                _HERE.parent / 'ordinary-leaf-set-session/output.py')
_oracle = _load('_selected_session_wire_oracle', _HERE / 'oracle.py')
OPERATIONS = ('first_equal', 'uppercase_count')
FUNCTIONS = (101, 202)
PROFILE = 'selected-session-functional-v1'
WHOLE_PROFILE = 'selected-session-whole-functional-v1'
CAP = _shared.CAP
LINE = _shared.LINE
uint = _shared.uint


def geometry(table, caller, cpus, *, profile=PROFILE):
    assert type(profile) is str and profile in (PROFILE, WHOLE_PROFILE)
    assert type(table) is tuple and len(table) == 2
    _shared._geometry(table, caller, cpus, OPERATIONS)
    if profile == PROFILE:
        assert tuple((leaf['function_id'], leaf['operation'], leaf['policy']) for leaf in table) == (
            (101, 'first_equal', 'certified'), (202, 'uppercase_count', 'certified'))
    else:
        assert tuple((leaf['function_id'], leaf['operation'], leaf['policy']) for leaf in table) == (
            (101, 'first_equal', 'whole'), (202, 'uppercase_count', 'whole'))


def _semantic_rows(records):
    # Grammar and CSV field totals retain the old independent recognizer. Scalar
    # results come from separately authored byte operations, never native calls.
    rows = []
    for payload in records:
        grammar = _shared.truths(payload)
        first, upper = _oracle.values(payload)
        rows.append(dict(csv_fields=grammar['csv_fields'], first_equal=first,
                         uppercase_count=upper))
    return tuple(rows)


def check(stdout, stderr, *, records, table, caller, k, epochs, outcome, input_error, cpus,
          profile=PROFILE):
    geometry(table, caller, cpus, profile=profile)
    assert type(records) is tuple and records == _oracle.records(k)
    assert type(epochs) is int and epochs == 520
    assert outcome == 'eof' and input_error == 'none'
    return _shared._check(
        stdout, stderr, records=records, table=table, caller=caller, k=k,
        epochs=epochs, outcome=outcome, input_error=input_error, cpus=cpus,
        operations=OPERATIONS, version='selected-session-v1',
        semantic_rows=_semantic_rows(records), command='normal-selected-session',
        status='SELECTED_SESSION_WIRE_PASS')
