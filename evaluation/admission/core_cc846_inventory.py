"""Exact additive main-cc846 source/catalog boundary; never execution evidence."""
import ast
import copy
import hashlib
import json
from pathlib import Path
import re

from parsing import require

DATA_SHA256 = 'e1feb27983daf3950e884225d223a0a5802e937d14908e53b3443cf96d8e1d79'
ROOT = Path(__file__).resolve().parents[2]
RAW = Path(__file__).with_suffix('.json').read_bytes()
require(hashlib.sha256(RAW).hexdigest() == DATA_SHA256, 'cc846_inventory_data_differs')
DATA = json.loads(RAW)
CURRENT = DATA['current_corpus_sha256']
PREVIOUS = DATA['previous_corpus_sha256']
RECORDER_TESTS = 340
PYTHON_CURRENT = '462da94e73e635ac5c3b46192cba7b991de92b72ec871853204e45d529943b3f'
PYTHON_PREVIOUS = 'fb8adb475b7ecbafb984dfa99c674f8a60fdb59fbb5adeb5754482e1136bb3bc'
PYTHON_MODULE = 'test_main_query_inventory'
PYTHON_METHODS = ('test_main_query_inventory.MainQueryInventoryTests.test_exact_sources_catalog_and_historical_denominators', 'test_main_query_inventory.MainQueryInventoryTests.test_catalog_source_and_python_mutations_cannot_enter_history', 'test_main_query_inventory.MainQueryInventoryTests.test_new_harness_and_exact_242_child_shape', 'test_main_query_inventory.MainQueryInventoryTests.test_complete_new_protocol_keeps_all_four_old_trajectories', 'test_main_query_inventory.MainQueryInventoryTests.test_every_new_record_field_requires_exact_value_and_type', 'test_main_query_inventory.MainQueryInventoryTests.test_every_partial_duplicate_reordered_and_extra_protocol_refuses', 'test_main_query_inventory.MainQueryInventoryTests.test_old_descriptor_and_protocol_cannot_replace_live_new_inventory', 'test_main_query_inventory.MainQueryInventoryTests.test_header_duplicate_keys_and_nonfinite_values_cannot_hide_old_logs', 'test_main_query_inventory.MainQueryInventoryTests.test_command_failure_preserves_prefix_without_qualification', 'test_main_query_inventory.MainQueryInventoryTests.test_final_qualification_requires_new_rows_and_complete_unchanged_run')


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def source_before_cc846(path, data, error):
    """Whole-new-blob authentication, exact sparse inverse, whole-old-blob check."""
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


def require_sources():
    for path, expected in DATA['sources'].items():
        try:
            data = (ROOT / path).read_bytes()
        except OSError:
            require(False, 'cc846_source_inventory_differs')
        require(hashlib.sha256(data).hexdigest() == expected, 'cc846_source_inventory_differs')
        if path in DATA['methods']:
            text = data.decode()
            require(re.findall(r'#\[test\]\s*fn\s+(\w+)\s*\(', text) == DATA['methods'][path]['all']
                    and not re.search(r'#\[ignore(?:\]|\()', text), 'cc846_source_inventory_differs')
    path = 'tools/rapid-profiler/src/frontend_native/always_on/site/ordinary.rs'
    require((ROOT / path).read_bytes().count(b'```compile_fail') == 4, 'cc846_source_inventory_differs')


def before_exec_parser(declared):
    """Authenticate the whole live corpus before peeling exactly two parser rows."""
    require(type(declared) is dict and digest(declared) == CURRENT, 'cc846_inventory_differs')
    require_sources()
    old = copy.deepcopy(declared)
    rows = old['native_validation_fixtures']
    require(len(rows) == 110 and rows[108:] == DATA['exec_parser_controls'],
            'cc846_inventory_differs')
    old['native_validation_fixtures'] = rows[:108]
    require(digest(old) == DATA['before_exec_parser_corpus_sha256'], 'cc846_inventory_differs')
    return old


def before_cc846(declared):
    require(type(declared) is dict and digest(declared) == CURRENT, 'cc846_inventory_differs')
    require_sources()
    old = before_exec_parser(declared)
    for cohort, changes in DATA['changes'].items():
        for identity, (previous, current) in changes.items():
            require(old['harness_test_counts'][cohort][identity]['tests'] == current, 'cc846_inventory_differs')
            old['harness_test_counts'][cohort][identity]['tests'] = previous
    for identity, expected in DATA['added'].items():
        require(old['harness_test_counts']['workspace_tests'].pop(identity) == expected, 'cc846_inventory_differs')
    old['recorder_tests'] = 330
    old['backing_cleanup_harnesses'] = copy.deepcopy(DATA['old_cleanup'])
    require(digest(old) == PREVIOUS, 'cc846_inventory_differs')
    return old


def peel_current(declared):
    return before_cc846(declared) if type(declared) is dict and digest(declared) == CURRENT else declared


def peel_python(identities):
    if type(identities) is list and digest(identities) == PYTHON_CURRENT:
        require(len(identities) == RECORDER_TESTS and len(set(identities)) == RECORDER_TESTS,
                'cc846_python_inventory_differs')
        new = [x for x in identities if x.startswith(PYTHON_MODULE + '.')]
        old = [x for x in identities if not x.startswith(PYTHON_MODULE + '.')]
        require(new == list(PYTHON_METHODS) and len(old) == 330 and digest(old) == PYTHON_PREVIOUS,
                'cc846_python_inventory_differs')
        return old
    return identities


def require_current(declared):
    """Live preflight has no historical-catalog acceptance path."""
    before_cc846(declared)
    identities = []
    for path in sorted(Path(__file__).parent.glob('test_*.py')):
        for cls in ast.parse(path.read_text()).body:
            if isinstance(cls, ast.ClassDef):
                identities.extend(path.stem + '.' + cls.name + '.' + method.name
                                  for method in cls.body if isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef))
                                  and method.name.startswith('test_'))
    require(digest(identities) == PYTHON_CURRENT and len(identities) == RECORDER_TESTS,
            'cc846_python_inventory_differs')
