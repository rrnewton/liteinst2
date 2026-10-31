"""Exact native indexed-DSO source successor; all earlier catalogs remain separate."""
import copy
import hashlib
import json
from pathlib import Path
import re

from parsing import require

ROOT = Path(__file__).resolve().parents[2]
RAW = Path(__file__).with_suffix('.json').read_bytes()
require(hashlib.sha256(RAW).hexdigest() == 'eb1835712ca0907a1281ef0dc065dff893b2898acffff09457a8f158820886bf',
        'main97ab_inventory_data_differs')
DATA = json.loads(RAW)
CURRENT = DATA['current_corpus_sha256']
PREVIOUS = DATA['previous_corpus_sha256']
PYTHON_CURRENT = DATA['python_current_sha256']
PYTHON_PREVIOUS = DATA['python_previous_sha256']
RECORDER_TESTS = 366
ADDED = 'test_main97ab_inventory.Main97abInventoryTests.test_exact_native_indexed_sources_and_historical_refusals'


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


def source_before(path, raw, error):
    return inverse(path, raw, DATA['projections'], error)


def source_before_evaluation(path, raw, error):
    return inverse(path, raw, DATA['evaluation_projections'], error)


def require_sources(error='main97ab_source_inventory_differs'):
    for path, expected in DATA['sources'].items():
        try:
            raw = (ROOT / path).read_bytes()
        except OSError:
            require(False, error)
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
        source_before(path, raw, error)
        source_before_evaluation(path, raw, error)


def before_current(declared, error='main97ab_inventory_differs',
                   source_error='main97ab_source_inventory_differs'):
    require(type(declared) is dict and digest(declared) == CURRENT, error)
    require_sources(source_error)
    old = copy.deepcopy(declared)
    require(type(old['recorder_tests']) is int and old['recorder_tests'] == RECORDER_TESTS, error)
    old['recorder_tests'] = 365
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
    return before_current(declared, error, source_error) if type(declared) is dict and digest(declared) == CURRENT else declared


def before_python(identities, error='main97ab_python_inventory_differs'):
    require(type(identities) is list and all(type(x) is str for x in identities) and
            len(identities) == len(set(identities)) == RECORDER_TESTS and
            digest(identities) == PYTHON_CURRENT, error)
    require(identities.count(ADDED) == 1, error)
    old = [name for name in identities if name != ADDED]
    require(len(old) == 365 and digest(old) == PYTHON_PREVIOUS, error)
    return old


def peel_python(identities, error='main97ab_python_inventory_differs'):
    return before_python(identities, error) if type(identities) is list and digest(identities) == PYTHON_CURRENT else identities
