"""Exact5cda source/catalog boundary; declarations and supplied records only."""
import ast
import copy
import hashlib
import json
from pathlib import Path
import re

from parsing import require
import core_813_inventory as main813

ROOT = Path(__file__).resolve().parents[2]
DATA_SHA256 = '5f622c9cb2600b35ddf93f587e5ba7198b90712d0c8bb139acd55381e552dd91'
RAW = Path(__file__).with_suffix('.json').read_bytes()
require(hashlib.sha256(RAW).hexdigest() == DATA_SHA256, 'main5c_inventory_data_differs')
DATA = json.loads(RAW)
CURRENT = DATA['current_corpus_sha256']
PREVIOUS = DATA['previous_corpus_sha256']
PYTHON_CURRENT = DATA['python_current_sha256']
PYTHON_PREVIOUS = DATA['python_previous_sha256']
RECORDER_TESTS = 345


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()


def source_before(path, data, error):
    """Authenticate whole successor before exact inverse; stale input refuses."""
    data = main813.source_before(path, data, error)
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


def require_sources(error='main5c_source_inventory_differs'):
    for path, expected in DATA['sources'].items():
        try:
            data = (ROOT / path).read_bytes()
        except OSError:
            require(False, error)
        data = main813.source_before(path, data, error)
        require(hashlib.sha256(data).hexdigest() == expected, error)
        if path in DATA['methods']:
            rows = re.findall(r'#\[test\]\s*((?:#\[[^\n]*\]\s*)*)(?:unsafe\s+)?fn\s+(\w+)\s*\(', data.decode())
            wanted = DATA['methods'][path]
            require([name for _, name in rows] == wanted['all'] and
                    [name for attrs, name in rows if re.search(r'#\[ignore(?:\]|\s*=)', attrs)] == wanted['ignored'] and
                    data.count(b'#[test]') == len(rows), error)


def before_current(declared, error='main5c_inventory_differs', source_error='main5c_source_inventory_differs'):
    declared = main813.peel_current(declared, error, source_error)
    require(type(declared) is dict and digest(declared) == CURRENT, error)
    require_sources(source_error)
    old = copy.deepcopy(declared)
    require(old['recorder_tests'] == RECORDER_TESTS, error)
    old['recorder_tests'] = 340
    for identity, row in DATA['workspace_changes'].items():
        require(old['harness_test_counts']['workspace_tests'][identity] == row['current'], error)
        old['harness_test_counts']['workspace_tests'][identity] = copy.deepcopy(row['previous'])
    require(digest(old) == PREVIOUS, error)
    return old


def peel_current(declared, error='main5c_inventory_differs', source_error='main5c_source_inventory_differs'):
    declared = main813.peel_current(declared, error, source_error)
    return before_current(declared, error, source_error) if type(declared) is dict and digest(declared) == CURRENT else declared


def peel_python(identities):
    identities = main813.peel_python(identities)
    if type(identities) is list and digest(identities) == PYTHON_CURRENT:
        require(len(identities) == RECORDER_TESTS and len(set(identities)) == RECORDER_TESTS,
                'main5c_python_inventory_differs')
        new = [x for x in identities if x.startswith('test_backing_singleton.')]
        old = [x for x in identities if not x.startswith('test_backing_singleton.')]
        require(new == DATA['python_added'] and len(old) == 340 and digest(old) == PYTHON_PREVIOUS,
                'main5c_python_inventory_differs')
        return old
    return identities


def python_identities(directory):
    identities = []
    for path in sorted(Path(directory).glob('test_*.py')):
        for cls in ast.parse(path.read_text()).body:
            if isinstance(cls, ast.ClassDef):
                identities.extend(path.stem + '.' + cls.name + '.' + method.name
                                  for method in cls.body if isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef))
                                  and method.name.startswith('test_'))
    return identities
