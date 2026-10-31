"""Exact prepared-phase source successor; all earlier catalogs remain separate."""
import copy
import hashlib
import json
from pathlib import Path
import re

from parsing import require
import core_d8d85_inventory as maind8d85

ROOT = Path(__file__).resolve().parents[2]
RAW = Path(__file__).with_suffix('.json').read_bytes()
require(hashlib.sha256(RAW).hexdigest() == 'f5f50c2729f23589e3c62b5b99bbaefa9685a386ee8e7103d6dc91d464938770',
        'main34c47_inventory_data_differs')
DATA = json.loads(RAW)
CURRENT = DATA['current_corpus_sha256']
PREVIOUS = DATA['previous_corpus_sha256']
PYTHON_CURRENT = DATA['python_current_sha256']
PYTHON_PREVIOUS = DATA['python_previous_sha256']
RECORDER_TESTS = 363
ADDED = 'test_main34c47_inventory.Main34c47InventoryTests.test_exact_prepared_sources_instances_and_causal_history_refusals'


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                     allow_nan=False).encode()).hexdigest()


def inverse(path, raw, rows, error):
    if path not in rows:
        return raw
    row = rows[path]
    require(type(raw) is bytes and hashlib.sha256(raw).hexdigest() == row['current_sha256'], error)
    last = len(raw)
    for first, end, old in reversed(row['edits']):
        require(type(first) is int and type(end) is int and type(old) is str
                and 0 <= first <= end <= last, error)
        raw = raw[:first] + old.encode() + raw[end:]
        last = first
    require(hashlib.sha256(raw).hexdigest() == row['previous_sha256'], error)
    return raw


def source_before_bf8b(path, raw, error):
    return inverse(path, raw, DATA['source_projections_bf8b'], error)


def source_before23d6(path, raw, error):
    return inverse(path, raw, DATA['source_projections_23d6'], error)


def source_before(path, raw, error):
    raw = maind8d85.source_before(path, raw, error)
    raw = source_before_bf8b(path, raw, error)
    raw = source_before23d6(path, raw, error)
    return inverse(path, raw, DATA['projections'], error)


def source_before_evaluation(path, raw, error):
    raw = maind8d85.source_before_evaluation(path, raw, error)
    return inverse(path, raw, DATA['evaluation_projections'], error)


def require_sources(error='main34c47_source_inventory_differs'):
    for path, expected in DATA['sources'].items():
        try:
            observed = (ROOT / path).read_bytes()
        except OSError:
            require(False, error)
        raw = maind8d85.source_before(path, observed, error)
        raw = maind8d85.source_before_evaluation(path, raw, error)
        raw = source_before_bf8b(path, raw, error)
        if path in DATA['source_projections_bf8b']:
            row = DATA['source_projections_bf8b'][path]
            require(expected == row['current_sha256'], error)
            expected = row['previous_sha256']
        if path in DATA['source_projections_23d6']:
            row = DATA['source_projections_23d6'][path]
            require(expected == row['current_sha256'], error)
            expected = row['previous_sha256']
        raw = source_before23d6(path, raw, error)
        require(hashlib.sha256(raw).hexdigest() == expected, error)
        if path in DATA['methods']:
            found = re.findall(r'#\[test\]\s*((?:#\[[^\n]*\]\s*)*)(?:unsafe\s+)?fn\s+(\w+)\s*\(', raw.decode())
            row = DATA['methods'][path]
            require([name for _, name in found] == row['all'] and
                    [name for attrs, name in found if re.search(r'#\[ignore(?:\]|\s*=)', attrs)] == row['ignored'] and
                    raw.count(b'#[test]') == len(found) + len(row['templates']), error)
            require(all(raw.decode().count(template) == 1 for template in row['templates']), error)
            for pattern, matches in row['macro_calls']:
                require([list(x) if isinstance(x, tuple) else x for x in re.findall(pattern, raw.decode())] == matches, error)
        if path in DATA['module_chains']:
            require(all(raw.decode().count(literal) == 1
                        for literal in DATA['module_chains'][path]), error)
        source_before(path, observed, error)
        source_before_evaluation(path, observed, error)


def before_current(declared, error='main34c47_inventory_differs',
                   source_error='main34c47_source_inventory_differs'):
    require(type(declared) is dict and digest(declared) == CURRENT, error)
    require_sources(source_error)
    old = copy.deepcopy(declared)
    require(type(old['recorder_tests']) is int and old['recorder_tests'] == RECORDER_TESTS, error)
    old['recorder_tests'] = 362
    rows = old['harness_test_counts']['workspace_tests']
    for name, change in DATA['workspace_changes'].items():
        require(digest(rows[name]) == digest(change['current']), error)
        if change['previous'] is None:
            del rows[name]
        else:
            rows[name] = copy.deepcopy(change['previous'])
    require(digest(old) == PREVIOUS, error)
    return old


def peel_current(declared, error, source_error):
    declared = maind8d85.peel_current(declared, error, source_error)
    return before_current(declared, error, source_error) if type(declared) is dict and digest(declared) == CURRENT else declared


def before_python(identities, error='main34c47_python_inventory_differs'):
    require(type(identities) is list and all(type(x) is str for x in identities) and
            len(identities) == len(set(identities)) == RECORDER_TESTS and
            digest(identities) == PYTHON_CURRENT, error)
    require(identities.count(ADDED) == 1, error)
    old = [name for name in identities if name != ADDED]
    require(len(old) == 362 and digest(old) == PYTHON_PREVIOUS, error)
    return old


def peel_python(identities, error='main34c47_python_inventory_differs'):
    identities = maind8d85.peel_python(identities, error)
    return before_python(identities, error) if type(identities) is list and digest(identities) == PYTHON_CURRENT else identities
