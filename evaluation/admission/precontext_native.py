"""Exact Cargo precontext-native scope using the unchanged core strict reader.

The custom main is not a libtest harness. Only its exact header and one validated
terminal JSON line are separated; every other harness byte stays unchanged.
These are bounded core state observations, not frontend or performance evidence.
"""
import copy
import hashlib
import importlib.util
from pathlib import Path
import re
import sys

from backing_cleanup_query import typed_equal
from parsing import require

ROOT = Path(__file__).resolve().parents[2]
VERIFY = ROOT / 'evaluation/precontext/verify.py'
VERIFY_SHA256 = '9336515811ee0a9867e5cfbb14336a87bba63874b3489e6cda8a62bc882599fe'
require(not sys.flags.optimize, 'precontext_assertions_disabled')
require(hashlib.sha256(VERIFY.read_bytes()).hexdigest() == VERIFY_SHA256, 'precontext_reader_differs')
_spec = importlib.util.spec_from_file_location('admission_precontext_core_verify', VERIFY)
_core = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_core)

TARGET = 'control/precontext_native'
HEADER = re.compile(r'\s*Running tests/precontext_native\.rs '
                    r'\(target/debug/deps/precontext_native-[a-f0-9]{16}\)')
CARGO_HEADER = re.compile(r'\s*(?:Running |Doc-tests )')


def specification():
    return {'id': TARGET, 'source': 'tests/precontext_native.rs', 'binary': 'precontext_native',
            'profile': 'precontext-v1', 'pairs': 8, 'malformed_children': 2,
            'reader_sha256': VERIFY_SHA256}


def require_inventory(corpus):
    require(typed_equal(corpus.get('precontext_native_harnesses'),
                        {'workspace_tests': [specification()]}), 'invalid_precontext_inventory')


def _view(seen, value, successful, error):
    return specification() | {'status': 'invalid' if error else 'complete' if value is not None else
                              'incomplete' if seen else 'not_observed',
                              'header_observed': seen, 'observations': copy.deepcopy(value),
                              'command_succeeded': successful, 'qualified_run': False}


def is_complete(row):
    if type(row) is not dict or type(row.get('qualified_run')) is not bool:
        return False
    try:
        _core.validate_terminal(row['observations'])
    except (AssertionError, ValueError, KeyError, TypeError, RecursionError):
        return False
    return typed_equal(row | {'qualified_run': False}, _view(True, row['observations'], True, None))


def separate(output, inventory, successful):
    require(type(output) is str and type(successful) is bool, 'invalid_precontext_input')
    require(typed_equal(inventory, [specification()]), 'invalid_precontext_inventory')
    remaining, value = [], None
    seen = active = False
    error = None

    def fail(code):
        nonlocal error
        if error is None:
            error = code

    for original in output.splitlines(keepends=True):
        line = original.rstrip('\r\n')
        if CARGO_HEADER.match(line):
            if active and value is None:
                fail('incomplete_precontext_protocol')
            active = False
            if HEADER.fullmatch(line):
                if seen:
                    fail('duplicate_precontext_harness')
                seen = active = True
                continue
            if 'precontext_native' in line:
                fail('invalid_precontext_header')
            remaining.append(original)
            continue
        if not active:
            if 'precontext-v1' in line:
                fail('precontext_record_outside_harness')
            remaining.append(original)
            continue
        if not line.strip():
            continue
        if error is not None:
            continue
        if value is not None:
            fail('extra_precontext_output')
            continue
        try:
            # Keep exact newline/CR behavior and all core field/type/bound checks.
            value = _core.read_terminal(original.encode('utf-8'))
        except (AssertionError, ValueError, KeyError, TypeError, RecursionError):
            fail('invalid_precontext_protocol')
    if not seen:
        fail('missing_precontext_harness')
    elif value is None:
        fail('incomplete_precontext_protocol')
    return ''.join(remaining), [_view(seen, value, successful, error)], error
