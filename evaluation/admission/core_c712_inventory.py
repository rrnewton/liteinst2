"""Exact SPSC software-preemption successor; all earlier catalogs remain separate."""
import copy
import hashlib
import json
from pathlib import Path
import re

from parsing import require
import core_0fb574_inventory as main0fb574

ROOT = Path(__file__).resolve().parents[2]
RAW = Path(__file__).with_suffix('.json').read_bytes()
require(hashlib.sha256(RAW).hexdigest() == '673d465bea3f91a5c974950bc404ca6d86f4f903d542c10c495b2cf393be2a45',
        'mainc712_inventory_data_differs')
DATA = json.loads(RAW)
CURRENT = DATA['current_corpus_sha256']
PREVIOUS = DATA['previous_corpus_sha256']
PYTHON_CURRENT = DATA['python_current_sha256']
PYTHON_PREVIOUS = DATA['python_previous_sha256']
RECORDER_TESTS = 356
ADDED = 'test_mainc712_inventory.MainC712InventoryTests.test_exact_software_preemption_sources_catalog_and_refusals'


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
    raw = main0fb574.source_before(path, raw, error)
    return inverse(path, raw, DATA['projections'], error)


def source_before_evaluation(path, raw, error):
    raw = main0fb574.source_before_evaluation(path, raw, error)
    return inverse(path, raw, DATA['evaluation_projections'], error)


def require_sources(error='mainc712_source_inventory_differs'):
    for path, expected in DATA['sources'].items():
        try:
            raw = (ROOT / path).read_bytes()
        except OSError:
            require(False, error)
        observed = raw
        raw = main0fb574.source_before(path, raw, error)
        raw = main0fb574.source_before_evaluation(path, raw, error)
        require(hashlib.sha256(raw).hexdigest() == expected, error)
        if path in DATA['methods']:
            found = re.findall(r'#\[test\]\s*((?:#\[[^\n]*\]\s*)*)(?:unsafe\s+)?fn\s+(\w+)\s*\(', raw.decode())
            row = DATA['methods'][path]
            require([name for _, name in found] == row['all'] and
                    [name for attrs, name in found if re.search(r'#\[ignore(?:\]|\s*=)', attrs)] == row['ignored'] and
                    raw.count(b'#[test]') == len(found), error)
        if path in DATA['module_chains']:
            require(all(raw.decode().count(literal) == 1
                        for literal in DATA['module_chains'][path]), error)
        source_before(path, observed, error)
        source_before_evaluation(path, observed, error)


def before_current(declared, error='mainc712_inventory_differs',
                   source_error='mainc712_source_inventory_differs'):
    require(type(declared) is dict and digest(declared) == CURRENT, error)
    require_sources(source_error)
    old = copy.deepcopy(declared)
    require(type(old['recorder_tests']) is int and old['recorder_tests'] == RECORDER_TESTS, error)
    old['recorder_tests'] = 355
    rows = old['harness_test_counts']['workspace_tests']
    for name, change in DATA['workspace_changes'].items():
        require(digest(rows[name]) == digest(change['current']), error)
        rows[name] = copy.deepcopy(change['previous'])
    require(digest(old) == PREVIOUS, error)
    return old


def peel_current(declared, error, source_error):
    declared = main0fb574.peel_current(declared, error, source_error)
    return before_current(declared, error, source_error) if type(declared) is dict and digest(declared) == CURRENT else declared


def before_python(identities, error='mainc712_python_inventory_differs'):
    require(type(identities) is list and all(type(x) is str for x in identities) and
            len(identities) == len(set(identities)) == RECORDER_TESTS and
            digest(identities) == PYTHON_CURRENT, error)
    require(identities.count(ADDED) == 1, error)
    old = [name for name in identities if name != ADDED]
    require(len(old) == 355 and digest(old) == PYTHON_PREVIOUS, error)
    return old


def peel_python(identities, error='mainc712_python_inventory_differs'):
    identities = main0fb574.peel_python(identities, error)
    return before_python(identities, error) if type(identities) is list and digest(identities) == PYTHON_CURRENT else identities
