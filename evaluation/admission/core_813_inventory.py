"""Exact main813 source/catalog successor; no execution credit from declarations."""
import copy
import hashlib
import json
from pathlib import Path
import re

from parsing import require

ROOT = Path(__file__).resolve().parents[2]
RAW = Path(__file__).with_suffix('.json').read_bytes()
require(hashlib.sha256(RAW).hexdigest() == '9ecef3e5bd508ebf227befe07f072e4f6fadfb2041029e20f98c6fe019431b8b', 'main813_inventory_data_differs')
DATA = json.loads(RAW)
CURRENT = DATA['current_corpus_sha256']
MAIN690 = DATA['main690']
CURRENT690 = MAIN690['current_corpus_sha256']
MAINC0 = DATA['mainc0']
CURRENTC0 = MAINC0['current_corpus_sha256']
MAINC1 = DATA['mainc1']
CURRENTC1 = MAINC1['current_corpus_sha256']
MAINE797 = DATA['maine797']
LATEST = MAINE797['current_corpus_sha256']
PREVIOUS = DATA['previous_corpus_sha256']
PYTHON_CURRENT = DATA['python_current_sha256']
PYTHON_PREVIOUS = DATA['python_previous_sha256']
RECORDER_TESTS = 350


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()


def source_before_e797(path, data, error):
    """Only the fixed e797 whole blob may reach its exact historical source."""
    if path not in MAINE797['projections']:
        return data
    row = MAINE797['projections'][path]
    require(type(data) is bytes and hashlib.sha256(data).hexdigest() == row['current_sha256'], error)
    last = len(data)
    for start, end, old in reversed(row['edits']):
        require(0 <= start <= end <= last, error)
        data = data[:start] + old.encode() + data[end:]
        last = start
    require(hashlib.sha256(data).hexdigest() == row['previous_sha256'], error)
    return data


def require_e797_sources(error='maine797_source_inventory_differs'):
    for path, expected in MAINE797['sources'].items():
        try:
            raw = (ROOT / path).read_bytes()
        except OSError:
            require(False, error)
        require(hashlib.sha256(raw).hexdigest() == expected, error)
        if path in MAINE797['methods']:
            found = re.findall(r'#\[test\]\s*((?:#\[[^\n]*\]\s*)*)(?:unsafe\s+)?fn\s+(\w+)\s*\(', raw.decode())
            row = MAINE797['methods'][path]
            require([name for _, name in found] == row['all'] and
                    [name for attrs, name in found if re.search(r'#\[ignore(?:\]|\s*=)', attrs)] == row['ignored'] and
                    raw.count(b'#[test]') == len(found), error)
    for path, rows in MAINE797['doctests'].items():
        lines = (ROOT / path).read_text().splitlines()
        for row in rows:
            require(lines[row['line'] - 1].strip() == row['marker'] + ' ```' + row['attributes'], error)


def before_e797(declared, error='maine797_inventory_differs', source_error='maine797_source_inventory_differs'):
    require(type(declared) is dict and digest(declared) == LATEST, error)
    require_e797_sources(source_error)
    old = copy.deepcopy(declared)
    rows = old['harness_test_counts']['workspace_tests']
    for name, change in MAINE797['workspace_changes'].items():
        require(rows[name] == change['current'], error)
        if change['previous'] is None:
            del rows[name]
        else:
            rows[name] = copy.deepcopy(change['previous'])
    require(digest(old) == MAINE797['previous_corpus_sha256'] == CURRENTC1, error)
    return old


def peel_e797(declared, error, source_error):
    return before_e797(declared, error, source_error) if type(declared) is dict and digest(declared) == LATEST else declared


def source_before_c1(path, data, error):
    """Only the fixed c1 whole blob may reach its exact historical source."""
    data = source_before_e797(path, data, error)
    if path not in MAINC1['projections']:
        return data
    row = MAINC1['projections'][path]
    require(type(data) is bytes and hashlib.sha256(data).hexdigest() == row['current_sha256'], error)
    last = len(data)
    for start, end, old in reversed(row['edits']):
        require(0 <= start <= end <= last, error)
        data = data[:start] + old.encode() + data[end:]
        last = start
    require(hashlib.sha256(data).hexdigest() == row['previous_sha256'], error)
    return data


def require_c1_sources(error='mainc1_source_inventory_differs'):
    require_e797_sources(error)
    for path, expected in MAINC1['sources'].items():
        try:
            raw = (ROOT / path).read_bytes()
        except OSError:
            require(False, error)
        raw = source_before_e797(path, raw, error)
        require(hashlib.sha256(raw).hexdigest() == expected, error)
        if path in MAINC1['methods']:
            found = re.findall(r'#\[test\]\s*((?:#\[[^\n]*\]\s*)*)(?:unsafe\s+)?fn\s+(\w+)\s*\(', raw.decode())
            row = MAINC1['methods'][path]
            require([name for _, name in found] == row['all'] and
                    [name for attrs, name in found if re.search(r'#\[ignore(?:\]|\s*=)', attrs)] == row['ignored'] and
                    raw.count(b'#[test]') == len(found), error)


def before_c1(declared, error='mainc1_inventory_differs', source_error='mainc1_source_inventory_differs'):
    declared = peel_e797(declared, error, source_error)
    require(type(declared) is dict and digest(declared) == CURRENTC1, error)
    require_c1_sources(source_error)
    old = copy.deepcopy(declared)
    rows = old['harness_test_counts']['workspace_tests']
    for name, change in MAINC1['workspace_changes'].items():
        require(rows[name] == change['current'], error)
        rows[name] = copy.deepcopy(change['previous'])
    require(digest(old) == MAINC1['previous_corpus_sha256'] == CURRENTC0, error)
    return old


def peel_c1(declared, error, source_error):
    declared = peel_e797(declared, error, source_error)
    return before_c1(declared, error, source_error) if type(declared) is dict and digest(declared) == CURRENTC1 else declared


def source_before_c0(path, data, error):
    """Only the fixed c0 whole blob may reach its exact historical source."""
    data = source_before_c1(path, data, error)
    if path not in MAINC0['projections']:
        return data
    row = MAINC0['projections'][path]
    require(type(data) is bytes and hashlib.sha256(data).hexdigest() == row['current_sha256'], error)
    last = len(data)
    for start, end, old in reversed(row['edits']):
        require(0 <= start <= end <= last, error)
        data = data[:start] + old.encode() + data[end:]
        last = start
    require(hashlib.sha256(data).hexdigest() == row['previous_sha256'], error)
    return data


def require_c0_sources(error='mainc0_source_inventory_differs'):
    require_c1_sources(error)
    for path, expected in MAINC0['sources'].items():
        try:
            raw = (ROOT / path).read_bytes()
        except OSError:
            require(False, error)
        raw = source_before_c1(path, raw, error)
        require(hashlib.sha256(raw).hexdigest() == expected, error)
        if path in MAINC0['methods']:
            found = re.findall(r'#\[test\]\s*((?:#\[[^\n]*\]\s*)*)(?:unsafe\s+)?fn\s+(\w+)\s*\(', raw.decode())
            row = MAINC0['methods'][path]
            require([name for _, name in found] == row['all'] and
                    [name for attrs, name in found if re.search(r'#\[ignore(?:\]|\s*=)', attrs)] == row['ignored'] and
                    raw.count(b'#[test]') == len(found), error)


def before_c0(declared, error='mainc0_inventory_differs', source_error='mainc0_source_inventory_differs'):
    declared = peel_c1(declared, error, source_error)
    require(type(declared) is dict and digest(declared) == CURRENTC0, error)
    require_c0_sources(source_error)
    old = copy.deepcopy(declared)
    rows = old['harness_test_counts']['workspace_tests']
    for name, change in MAINC0['workspace_changes'].items():
        require(rows[name] == change['current'], error)
        rows[name] = copy.deepcopy(change['previous'])
    require(digest(old) == MAINC0['previous_corpus_sha256'] == CURRENT690, error)
    return old


def peel_c0(declared, error, source_error):
    declared = peel_c1(declared, error, source_error)
    return before_c0(declared, error, source_error) if type(declared) is dict and digest(declared) == CURRENTC0 else declared


def source_before_690(path, data, error):
    """Only this whole main690 blob may reach its fixed historical source."""
    data = source_before_c0(path, data, error)
    if path not in MAIN690['projections']:
        return data
    row = MAIN690['projections'][path]
    require(type(data) is bytes and hashlib.sha256(data).hexdigest() == row['current_sha256'], error)
    last = len(data)
    for start, end, old in reversed(row['edits']):
        require(0 <= start <= end <= last, error)
        data = data[:start] + old.encode() + data[end:]
        last = start
    require(hashlib.sha256(data).hexdigest() == row['previous_sha256'], error)
    return data


def require_690_sources(error='main690_source_inventory_differs'):
    require_c0_sources(error)
    for path, expected in MAIN690['sources'].items():
        try:
            raw = (ROOT / path).read_bytes()
        except OSError:
            require(False, error)
        raw = source_before_c0(path, raw, error)
        require(hashlib.sha256(raw).hexdigest() == expected, error)
        if path in MAIN690['methods']:
            found = re.findall(r'#\[test\]\s*((?:#\[[^\n]*\]\s*)*)(?:unsafe\s+)?fn\s+(\w+)\s*\(', raw.decode())
            row = MAIN690['methods'][path]
            require([name for _, name in found] == row['all'] and
                    [name for attrs, name in found if re.search(r'#\[ignore(?:\]|\s*=)', attrs)] == row['ignored'] and
                    raw.count(b'#[test]') == len(found), error)


def before_690(declared, error='main690_inventory_differs', source_error='main690_source_inventory_differs'):
    declared = peel_c0(declared, error, source_error)
    require(type(declared) is dict and digest(declared) == CURRENT690, error)
    require_690_sources(source_error)
    old = copy.deepcopy(declared)
    change = MAIN690['workspace_change']
    rows = old['harness_test_counts']['workspace_tests']
    require(rows[change['identity']] == change['current'], error)
    rows[change['identity']] = copy.deepcopy(change['previous'])
    require(digest(old) == MAIN690['previous_corpus_sha256'] == CURRENT, error)
    return old


def peel_690(declared, error, source_error):
    declared = peel_c0(declared, error, source_error)
    return before_690(declared, error, source_error) if type(declared) is dict and digest(declared) == CURRENT690 else declared


def source_before(path, data, error):
    """Only the complete fixed successor can enter an older source guard."""
    data = source_before_690(path, data, error)
    if path not in DATA['projections']:
        return data
    row = DATA['projections'][path]
    require(type(data) is bytes and hashlib.sha256(data).hexdigest() == row['current_sha256'], error)
    last = len(data)
    for start, end, old in reversed(row['edits']):
        require(0 <= start <= end <= last, error)
        data = data[:start] + old.encode() + data[end:]
        last = start
    require(hashlib.sha256(data).hexdigest() == row['previous_sha256'], error)
    return data


def require_sources(error='main813_source_inventory_differs'):
    require_690_sources(error)
    for path, expected in DATA['sources'].items():
        try:
            raw = (ROOT / path).read_bytes()
        except OSError:
            require(False, error)
        raw = source_before_690(path, raw, error)
        require(hashlib.sha256(raw).hexdigest() == expected, error)
        if path in DATA['methods']:
            found = re.findall(r'#\[test\]\s*((?:#\[[^\n]*\]\s*)*)(?:unsafe\s+)?fn\s+(\w+)\s*\(', raw.decode())
            row = DATA['methods'][path]
            require([name for _, name in found] == row['all'] and
                    [name for attrs, name in found if re.search(r'#\[ignore(?:\]|\s*=)', attrs)] == row['ignored'] and
                    raw.count(b'#[test]') == len(found), error)
    for path, rows in DATA['doctests'].items():
        lines = source_before_690(path, (ROOT / path).read_bytes(), error).decode().splitlines()
        for row in rows:
            require(lines[row['line'] - 1].strip() == '/// ```' + row['attributes'], error)


def before_current(declared, error='main813_inventory_differs', source_error='main813_source_inventory_differs'):
    declared = peel_690(declared, error, source_error)
    require(type(declared) is dict and digest(declared) == CURRENT, error)
    require_sources(source_error)
    old = copy.deepcopy(declared)
    require(old['recorder_tests'] == RECORDER_TESTS, error)
    old['recorder_tests'] = 345
    require(old.pop('precontext_native_harnesses') == DATA['precontext_inventory'], error)
    rows = old['harness_test_counts']['workspace_tests']
    for name, change in DATA['workspace_changes'].items():
        require(rows[name] == change['current'], error)
        if change['previous'] is None:
            del rows[name]
        else:
            rows[name] = copy.deepcopy(change['previous'])
    # This recovers the exact historical declaration, including its erroneous
    # 15-doc denominator. The old failed receipt remains failed.
    require(digest(old) == PREVIOUS, error)
    return old


def peel_current(declared, error='main813_inventory_differs', source_error='main813_source_inventory_differs'):
    declared = peel_690(declared, error, source_error)
    return before_current(declared, error, source_error) if type(declared) is dict and digest(declared) == CURRENT else declared


def peel_python(identities):
    if type(identities) is list and digest(identities) == PYTHON_CURRENT:
        require(len(identities) == len(set(identities)) == RECORDER_TESTS, 'main813_python_inventory_differs')
        new = [x for x in identities if x.startswith('test_main813_inventory.')]
        old = [x for x in identities if not x.startswith('test_main813_inventory.')]
        require(new == DATA['python_added'] and len(old) == 345 and digest(old) == PYTHON_PREVIOUS,
                'main813_python_inventory_differs')
        return old
    return identities
