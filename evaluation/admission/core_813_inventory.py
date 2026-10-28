"""Exact main813 source/catalog successor; no execution credit from declarations."""
import ast
import copy
import hashlib
import json
from pathlib import Path
import re

from parsing import require

ROOT = Path(__file__).resolve().parents[2]
RAW = Path(__file__).with_suffix('.json').read_bytes()
require(hashlib.sha256(RAW).hexdigest() == '9491c0e57d4de0d295389dedb735e17a83c92ef5f92e8aba96082c6beb7d9fb4', 'main813_inventory_data_differs')
DATA = json.loads(RAW)
CURRENT = DATA['current_corpus_sha256']
MAIN690 = DATA['main690']
CURRENT690 = MAIN690['current_corpus_sha256']
MAINC0 = DATA['mainc0']
CURRENTC0 = MAINC0['current_corpus_sha256']
MAINC1 = DATA['mainc1']
CURRENTC1 = MAINC1['current_corpus_sha256']
MAINE797 = DATA['maine797']
CURRENTE797 = MAINE797['current_corpus_sha256']
MAINF0EF = DATA['mainf0ef']
CURRENTF0EF = MAINF0EF['current_corpus_sha256']
MAIN7CDC = DATA['main7cdc']
CURRENT7CDC = MAIN7CDC['current_corpus_sha256']
MAIN43D7 = DATA['main43d7']
CURRENT43D7 = MAIN43D7['current_corpus_sha256']
MAIN0DF8 = DATA['main0df8']
CURRENT0DF8 = MAIN0DF8['current_corpus_sha256']
MAIN0A8 = DATA['main0a8']
CURRENT0A8 = MAIN0A8['current_corpus_sha256']
MAIN09FE = DATA['main09fe']
LATEST = MAIN09FE['current_corpus_sha256']
PREVIOUS = DATA['previous_corpus_sha256']
PYTHON_CURRENT = DATA['python_current_sha256']
PYTHON_PREVIOUS = DATA['python_previous_sha256']
RECORDER_TESTS = 350


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()


def source_before_09fe(path, data, error):
    """Only the fixed 09fe whole blob may reach its exact historical source."""
    if path not in MAIN09FE['projections']:
        return data
    row = MAIN09FE['projections'][path]
    require(type(data) is bytes and hashlib.sha256(data).hexdigest() == row['current_sha256'], error)
    last = len(data)
    for start, end, old in reversed(row['edits']):
        require(0 <= start <= end <= last, error)
        data = data[:start] + old.encode() + data[end:]
        last = start
    require(hashlib.sha256(data).hexdigest() == row['previous_sha256'], error)
    return data


def require_09fe_sources(error='main09fe_source_inventory_differs'):
    for path, expected in MAIN09FE['sources'].items():
        try:
            raw = (ROOT / path).read_bytes()
        except OSError:
            require(False, error)
        require(hashlib.sha256(raw).hexdigest() == expected, error)
        if path in MAIN09FE['methods']:
            found = re.findall(r'#\[test\]\s*((?:#\[[^\n]*\]\s*)*)(?:unsafe\s+)?fn\s+(\w+)\s*\(', raw.decode())
            row = MAIN09FE['methods'][path]
            require([name for _, name in found] == row['all'] and
                    [name for attrs, name in found if re.search(r'#\[ignore(?:\]|\s*=)', attrs)] == row['ignored'] and
                    raw.count(b'#[test]') == len(found) + MAIN09FE['macros'].get(path, {}).get('test_attributes', 0), error)

    for path, row in MAIN09FE['macros'].items():
        require((ROOT / path).read_text().count(row['literal']) == 1, error)
    for path, rows in MAIN09FE['doctests'].items():
        lines = (ROOT / path).read_text().splitlines()
        for row in rows:
            require(lines[row['line'] - 1].strip() == row['marker'] + ' ```' + row['attributes'], error)
    metadata = MAIN09FE['python_metadata']
    tree = ast.parse((ROOT / metadata['path']).read_bytes())
    for name, expected in metadata['assignments'].items():
        values = [ast.literal_eval(node.value) for node in tree.body if isinstance(node, ast.Assign)
                  and any(isinstance(target, ast.Name) and target.id == name for target in node.targets)]
        if name in metadata['tuple_assignments']:
            expected = tuple(expected)
        require(values == [expected], error)
    for path, facts in metadata['qualification_facts'].items():
        raw = (ROOT / path).read_text()
        require(all(raw.count(literal) == 1 for literal in facts), error)


def before_09fe(declared, error='main09fe_inventory_differs', source_error='main09fe_source_inventory_differs'):
    require(type(declared) is dict and digest(declared) == LATEST, error)
    require_09fe_sources(source_error)
    old = copy.deepcopy(declared)
    rows = old['harness_test_counts']['workspace_tests']
    for name, change in MAIN09FE['workspace_changes'].items():
        require(rows[name] == change['current'], error)
        if change['previous'] is None:
            del rows[name]
        else:
            rows[name] = copy.deepcopy(change['previous'])
    require(digest(old) == MAIN09FE['previous_corpus_sha256'] == CURRENT0A8, error)
    return old


def peel_09fe(declared, error, source_error):
    return before_09fe(declared, error, source_error) if type(declared) is dict and digest(declared) == LATEST else declared


def source_before_0a8(path, data, error):
    """Only the fixed 0a8 whole blob may reach its exact historical source."""
    data = source_before_09fe(path, data, error)
    if path not in MAIN0A8['projections']:
        return data
    row = MAIN0A8['projections'][path]
    require(type(data) is bytes and hashlib.sha256(data).hexdigest() == row['current_sha256'], error)
    last = len(data)
    for start, end, old in reversed(row['edits']):
        require(0 <= start <= end <= last, error)
        data = data[:start] + old.encode() + data[end:]
        last = start
    require(hashlib.sha256(data).hexdigest() == row['previous_sha256'], error)
    return data


def require_0a8_sources(error='main0a8_source_inventory_differs'):
    require_09fe_sources(error)
    for path, expected in MAIN0A8['sources'].items():
        try:
            raw = (ROOT / path).read_bytes()
        except OSError:
            require(False, error)
        raw = source_before_09fe(path, raw, error)
        require(hashlib.sha256(raw).hexdigest() == expected, error)
        if path in MAIN0A8['methods']:
            found = re.findall(r'#\[test\]\s*((?:#\[[^\n]*\]\s*)*)(?:unsafe\s+)?fn\s+(\w+)\s*\(', raw.decode())
            row = MAIN0A8['methods'][path]
            require([name for _, name in found] == row['all'] and
                    [name for attrs, name in found if re.search(r'#\[ignore(?:\]|\s*=)', attrs)] == row['ignored'] and
                    raw.count(b'#[test]') == len(found) + MAIN0A8['macros'].get(path, {}).get('test_attributes', 0), error)

    for path, row in MAIN0A8['macros'].items():
        raw = source_before_09fe(path, (ROOT / path).read_bytes(), error)
        require(raw.decode().count(row['literal']) == 1, error)
    for path, rows in MAIN0A8['doctests'].items():
        lines = source_before_09fe(path, (ROOT / path).read_bytes(), error).decode().splitlines()
        for row in rows:
            require(lines[row['line'] - 1].strip() == row['marker'] + ' ```' + row['attributes'], error)
    metadata = MAIN0A8['python_metadata']
    tree = ast.parse(source_before_09fe(metadata['path'], (ROOT / metadata['path']).read_bytes(), error))
    for name, expected in metadata['assignments'].items():
        values = [ast.literal_eval(node.value) for node in tree.body if isinstance(node, ast.Assign)
                  and any(isinstance(target, ast.Name) and target.id == name for target in node.targets)]
        if name in metadata['tuple_assignments']:
            expected = tuple(expected)
        require(values == [expected], error)
    for path, facts in metadata['qualification_facts'].items():
        raw = source_before_09fe(path, (ROOT / path).read_bytes(), error).decode()
        require(all(raw.count(literal) == 1 for literal in facts), error)


def before_0a8(declared, error='main0a8_inventory_differs', source_error='main0a8_source_inventory_differs'):
    declared = peel_09fe(declared, error, source_error)
    require(type(declared) is dict and digest(declared) == CURRENT0A8, error)
    require_0a8_sources(source_error)
    old = copy.deepcopy(declared)
    rows = old['harness_test_counts']['workspace_tests']
    for name, change in MAIN0A8['workspace_changes'].items():
        require(rows[name] == change['current'], error)
        if change['previous'] is None:
            del rows[name]
        else:
            rows[name] = copy.deepcopy(change['previous'])
    require(digest(old) == MAIN0A8['previous_corpus_sha256'] == CURRENT0DF8, error)
    return old


def peel_0a8(declared, error, source_error):
    declared = peel_09fe(declared, error, source_error)
    return before_0a8(declared, error, source_error) if type(declared) is dict and digest(declared) == CURRENT0A8 else declared


def source_before_0df8(path, data, error):
    """Only the fixed 0df8 whole blob may reach its exact historical source."""
    data = source_before_0a8(path, data, error)
    if path not in MAIN0DF8['projections']:
        return data
    row = MAIN0DF8['projections'][path]
    require(type(data) is bytes and hashlib.sha256(data).hexdigest() == row['current_sha256'], error)
    last = len(data)
    for start, end, old in reversed(row['edits']):
        require(0 <= start <= end <= last, error)
        data = data[:start] + old.encode() + data[end:]
        last = start
    require(hashlib.sha256(data).hexdigest() == row['previous_sha256'], error)
    return data


def require_0df8_sources(error='main0df8_source_inventory_differs'):
    require_0a8_sources(error)
    for path, expected in MAIN0DF8['sources'].items():
        try:
            raw = (ROOT / path).read_bytes()
        except OSError:
            require(False, error)
        raw = source_before_0a8(path, raw, error)
        require(hashlib.sha256(raw).hexdigest() == expected, error)
        if path in MAIN0DF8['methods']:
            found = re.findall(r'#\[test\]\s*((?:#\[[^\n]*\]\s*)*)(?:unsafe\s+)?fn\s+(\w+)\s*\(', raw.decode())
            row = MAIN0DF8['methods'][path]
            require([name for _, name in found] == row['all'] and
                    [name for attrs, name in found if re.search(r'#\[ignore(?:\]|\s*=)', attrs)] == row['ignored'] and
                    raw.count(b'#[test]') == len(found) + MAIN0DF8['macros'].get(path, {}).get('test_attributes', 0), error)

    for path, row in MAIN0DF8['macros'].items():
        raw = source_before_0a8(path, (ROOT / path).read_bytes(), error)
        require(raw.decode().count(row['literal']) == 1, error)
    for path, rows in MAIN0DF8['doctests'].items():
        lines = source_before_0a8(path, (ROOT / path).read_bytes(), error).decode().splitlines()
        for row in rows:
            require(lines[row['line'] - 1].strip() == row['marker'] + ' ```' + row['attributes'], error)
    metadata = MAIN0DF8['python_metadata']
    tree = ast.parse(source_before_0a8(metadata['path'], (ROOT / metadata['path']).read_bytes(), error))
    for name, expected in metadata['assignments'].items():
        values = [ast.literal_eval(node.value) for node in tree.body if isinstance(node, ast.Assign)
                  and any(isinstance(target, ast.Name) and target.id == name for target in node.targets)]
        if name in metadata['tuple_assignments']:
            expected = tuple(expected)
        require(values == [expected], error)
    for path, facts in metadata['qualification_facts'].items():
        raw = source_before_0a8(path, (ROOT / path).read_bytes(), error).decode()
        require(all(raw.count(literal) == 1 for literal in facts), error)


def before_0df8(declared, error='main0df8_inventory_differs', source_error='main0df8_source_inventory_differs'):
    declared = peel_0a8(declared, error, source_error)
    require(type(declared) is dict and digest(declared) == CURRENT0DF8, error)
    require_0df8_sources(source_error)
    old = copy.deepcopy(declared)
    rows = old['harness_test_counts']['workspace_tests']
    for name, change in MAIN0DF8['workspace_changes'].items():
        require(rows[name] == change['current'], error)
        if change['previous'] is None:
            del rows[name]
        else:
            rows[name] = copy.deepcopy(change['previous'])
    require(digest(old) == MAIN0DF8['previous_corpus_sha256'] == CURRENT43D7, error)
    return old


def peel_0df8(declared, error, source_error):
    declared = peel_0a8(declared, error, source_error)
    return before_0df8(declared, error, source_error) if type(declared) is dict and digest(declared) == CURRENT0DF8 else declared


def source_before_43d7(path, data, error):
    """Only the fixed 43d7 whole blob may reach its exact historical source."""
    data = source_before_0df8(path, data, error)
    if path not in MAIN43D7['projections']:
        return data
    row = MAIN43D7['projections'][path]
    require(type(data) is bytes and hashlib.sha256(data).hexdigest() == row['current_sha256'], error)
    last = len(data)
    for start, end, old in reversed(row['edits']):
        require(0 <= start <= end <= last, error)
        data = data[:start] + old.encode() + data[end:]
        last = start
    require(hashlib.sha256(data).hexdigest() == row['previous_sha256'], error)
    return data


def require_43d7_sources(error='main43d7_source_inventory_differs'):
    require_0df8_sources(error)
    for path, expected in MAIN43D7['sources'].items():
        try:
            raw = (ROOT / path).read_bytes()
        except OSError:
            require(False, error)
        raw = source_before_0df8(path, raw, error)
        require(hashlib.sha256(raw).hexdigest() == expected, error)
        if path in MAIN43D7['methods']:
            found = re.findall(r'#\[test\]\s*((?:#\[[^\n]*\]\s*)*)(?:unsafe\s+)?fn\s+(\w+)\s*\(', raw.decode())
            row = MAIN43D7['methods'][path]
            require([name for _, name in found] == row['all'] and
                    [name for attrs, name in found if re.search(r'#\[ignore(?:\]|\s*=)', attrs)] == row['ignored'] and
                    raw.count(b'#[test]') == len(found) + MAIN43D7['macros'].get(path, {}).get('test_attributes', 0), error)

    for path, row in MAIN43D7['macros'].items():
        raw = source_before_0df8(path, (ROOT / path).read_bytes(), error)
        require(raw.decode().count(row['literal']) == 1, error)
    for path, rows in MAIN43D7['doctests'].items():
        lines = source_before_0df8(path, (ROOT / path).read_bytes(), error).decode().splitlines()
        for row in rows:
            require(lines[row['line'] - 1].strip() == row['marker'] + ' ```' + row['attributes'], error)
    metadata = MAIN43D7['python_metadata']
    tree = ast.parse(source_before_0df8(metadata['path'], (ROOT / metadata['path']).read_bytes(), error))
    for name, expected in metadata['assignments'].items():
        values = [ast.literal_eval(node.value) for node in tree.body if isinstance(node, ast.Assign)
                  and any(isinstance(target, ast.Name) and target.id == name for target in node.targets)]
        require(values == [expected], error)
    for path, facts in metadata['qualification_facts'].items():
        raw = source_before_0df8(path, (ROOT / path).read_bytes(), error).decode()
        require(all(raw.count(literal) == 1 for literal in facts), error)


def before_43d7(declared, error='main43d7_inventory_differs', source_error='main43d7_source_inventory_differs'):
    declared = peel_0df8(declared, error, source_error)
    require(type(declared) is dict and digest(declared) == CURRENT43D7, error)
    require_43d7_sources(source_error)
    old = copy.deepcopy(declared)
    rows = old['harness_test_counts']['workspace_tests']
    for name, change in MAIN43D7['workspace_changes'].items():
        require(rows[name] == change['current'], error)
        if change['previous'] is None:
            del rows[name]
        else:
            rows[name] = copy.deepcopy(change['previous'])
    require(digest(old) == MAIN43D7['previous_corpus_sha256'] == CURRENT7CDC, error)
    return old


def peel_43d7(declared, error, source_error):
    declared = peel_0df8(declared, error, source_error)
    return before_43d7(declared, error, source_error) if type(declared) is dict and digest(declared) == CURRENT43D7 else declared


def source_before_7cdc(path, data, error):
    """Only the fixed 7cdc whole blob may reach its exact historical source."""
    data = source_before_43d7(path, data, error)
    if path not in MAIN7CDC['projections']:
        return data
    row = MAIN7CDC['projections'][path]
    require(type(data) is bytes and hashlib.sha256(data).hexdigest() == row['current_sha256'], error)
    last = len(data)
    for start, end, old in reversed(row['edits']):
        require(0 <= start <= end <= last, error)
        data = data[:start] + old.encode() + data[end:]
        last = start
    require(hashlib.sha256(data).hexdigest() == row['previous_sha256'], error)
    return data


def require_7cdc_sources(error='main7cdc_source_inventory_differs'):
    require_43d7_sources(error)
    for path, expected in MAIN7CDC['sources'].items():
        try:
            raw = (ROOT / path).read_bytes()
        except OSError:
            require(False, error)
        raw = source_before_43d7(path, raw, error)
        require(hashlib.sha256(raw).hexdigest() == expected, error)
        if path in MAIN7CDC['methods']:
            found = re.findall(r'#\[test\]\s*((?:#\[[^\n]*\]\s*)*)(?:unsafe\s+)?fn\s+(\w+)\s*\(', raw.decode())
            row = MAIN7CDC['methods'][path]
            require([name for _, name in found] == row['all'] and
                    [name for attrs, name in found if re.search(r'#\[ignore(?:\]|\s*=)', attrs)] == row['ignored'] and
                    raw.count(b'#[test]') == len(found), error)


def before_7cdc(declared, error='main7cdc_inventory_differs', source_error='main7cdc_source_inventory_differs'):
    declared = peel_43d7(declared, error, source_error)
    require(type(declared) is dict and digest(declared) == CURRENT7CDC, error)
    require_7cdc_sources(source_error)
    old = copy.deepcopy(declared)
    rows = old['harness_test_counts']['workspace_tests']
    for name, change in MAIN7CDC['workspace_changes'].items():
        require(rows[name] == change['current'], error)
        if change['previous'] is None:
            del rows[name]
        else:
            rows[name] = copy.deepcopy(change['previous'])
    require(digest(old) == MAIN7CDC['previous_corpus_sha256'] == CURRENTF0EF, error)
    return old


def peel_7cdc(declared, error, source_error):
    declared = peel_43d7(declared, error, source_error)
    return before_7cdc(declared, error, source_error) if type(declared) is dict and digest(declared) == CURRENT7CDC else declared


def source_before_f0ef(path, data, error):
    """Only the fixed f0ef whole blob may reach its exact historical source."""
    data = source_before_7cdc(path, data, error)
    if path not in MAINF0EF['projections']:
        return data
    row = MAINF0EF['projections'][path]
    require(type(data) is bytes and hashlib.sha256(data).hexdigest() == row['current_sha256'], error)
    last = len(data)
    for start, end, old in reversed(row['edits']):
        require(0 <= start <= end <= last, error)
        data = data[:start] + old.encode() + data[end:]
        last = start
    require(hashlib.sha256(data).hexdigest() == row['previous_sha256'], error)
    return data


def require_f0ef_sources(error='mainf0ef_source_inventory_differs'):
    require_7cdc_sources(error)
    for path, expected in MAINF0EF['sources'].items():
        try:
            raw = (ROOT / path).read_bytes()
        except OSError:
            require(False, error)
        raw = source_before_7cdc(path, raw, error)
        require(hashlib.sha256(raw).hexdigest() == expected, error)
        if path in MAINF0EF['methods']:
            found = re.findall(r'#\[test\]\s*((?:#\[[^\n]*\]\s*)*)(?:unsafe\s+)?fn\s+(\w+)\s*\(', raw.decode())
            row = MAINF0EF['methods'][path]
            require([name for _, name in found] == row['all'] and
                    [name for attrs, name in found if re.search(r'#\[ignore(?:\]|\s*=)', attrs)] == row['ignored'] and
                    raw.count(b'#[test]') == len(found), error)


def before_f0ef(declared, error='mainf0ef_inventory_differs', source_error='mainf0ef_source_inventory_differs'):
    declared = peel_7cdc(declared, error, source_error)
    require(type(declared) is dict and digest(declared) == CURRENTF0EF, error)
    require_f0ef_sources(source_error)
    old = copy.deepcopy(declared)
    rows = old['harness_test_counts']['workspace_tests']
    for name, change in MAINF0EF['workspace_changes'].items():
        require(rows[name] == change['current'], error)
        if change['previous'] is None:
            del rows[name]
        else:
            rows[name] = copy.deepcopy(change['previous'])
    require(digest(old) == MAINF0EF['previous_corpus_sha256'] == CURRENTE797, error)
    return old


def peel_f0ef(declared, error, source_error):
    declared = peel_7cdc(declared, error, source_error)
    return before_f0ef(declared, error, source_error) if type(declared) is dict and digest(declared) == CURRENTF0EF else declared


def source_before_e797(path, data, error):
    """Only the fixed e797 whole blob may reach its exact historical source."""
    data = source_before_f0ef(path, data, error)
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
    require_f0ef_sources(error)
    for path, expected in MAINE797['sources'].items():
        try:
            raw = (ROOT / path).read_bytes()
        except OSError:
            require(False, error)
        raw = source_before_f0ef(path, raw, error)
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
    declared = peel_f0ef(declared, error, source_error)
    require(type(declared) is dict and digest(declared) == CURRENTE797, error)
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
    declared = peel_f0ef(declared, error, source_error)
    return before_e797(declared, error, source_error) if type(declared) is dict and digest(declared) == CURRENTE797 else declared


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
