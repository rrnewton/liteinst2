"""Exact additive main-cc846 source/catalog boundary; never execution evidence."""
import ast
import copy
import hashlib
import json
from pathlib import Path
import re

from parsing import require
import inventory_syntax
import core_5cda_inventory as main5c
import core_813_inventory as main813

DATA_SHA256 = 'bdea03e1f24150ab46dfa196782fb4866378d8cf00f8291745d89de21593cf14'
ROOT = Path(__file__).resolve().parents[2]
RAW = Path(__file__).with_suffix('.json').read_bytes()
require(hashlib.sha256(RAW).hexdigest() == DATA_SHA256, 'cc846_inventory_data_differs')
DATA = json.loads(RAW)
CURRENT = DATA['current_corpus_sha256']
AC0963 = DATA['ac0963']
LIVE = AC0963['current_corpus_sha256']
PREVIOUS = DATA['previous_corpus_sha256']
RECORDER_TESTS = main813.RECORDER_TESTS
PYTHON_CURRENT = main813.PYTHON_CURRENT
PYTHON_PRE_5CDA = '462da94e73e635ac5c3b46192cba7b991de92b72ec871853204e45d529943b3f'
PYTHON_PREVIOUS = 'fb8adb475b7ecbafb984dfa99c674f8a60fdb59fbb5adeb5754482e1136bb3bc'
PYTHON_MODULE = 'test_main_query_inventory'
PYTHON_METHODS = ('test_main_query_inventory.MainQueryInventoryTests.test_exact_sources_catalog_and_historical_denominators', 'test_main_query_inventory.MainQueryInventoryTests.test_catalog_source_and_python_mutations_cannot_enter_history', 'test_main_query_inventory.MainQueryInventoryTests.test_new_harness_and_exact_242_child_shape', 'test_main_query_inventory.MainQueryInventoryTests.test_complete_new_protocol_keeps_all_four_old_trajectories', 'test_main_query_inventory.MainQueryInventoryTests.test_every_new_record_field_requires_exact_value_and_type', 'test_main_query_inventory.MainQueryInventoryTests.test_every_partial_duplicate_reordered_and_extra_protocol_refuses', 'test_main_query_inventory.MainQueryInventoryTests.test_old_descriptor_and_protocol_cannot_replace_live_new_inventory', 'test_main_query_inventory.MainQueryInventoryTests.test_header_duplicate_keys_and_nonfinite_values_cannot_hide_old_logs', 'test_main_query_inventory.MainQueryInventoryTests.test_command_failure_preserves_prefix_without_qualification', 'test_main_query_inventory.MainQueryInventoryTests.test_final_qualification_requires_new_rows_and_complete_unchanged_run')


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def source_before_ac0963(path, data, error):
    """Authenticate the complete new source before its exact historical inverse."""
    data = main5c.source_before(path, data, error)
    if path not in AC0963['projections']:
        return data
    row = AC0963['projections'][path]
    require(type(data) is bytes and hashlib.sha256(data).hexdigest() == row['current_sha256'], error)
    last = len(data)
    for start, end, old in reversed(row['edits']):
        require(0 <= start <= end <= last, error)
        data = data[:start] + old.encode() + data[end:]
        last = start
    require(hashlib.sha256(data).hexdigest() == row['previous_sha256'], error)
    return data


def require_ac0963_sources():
    for path, expected in AC0963['sources'].items():
        try:
            data = (ROOT / path).read_bytes()
        except OSError:
            require(False, 'ac0963_source_inventory_differs')
        data = main5c.source_before(path, data, 'ac0963_source_inventory_differs')
        require(hashlib.sha256(data).hexdigest() == expected, 'ac0963_source_inventory_differs')
        if path in AC0963['methods']:
            rows = re.findall(r'#\[test\]\s*((?:#\[[^\n]*\]\s*)*)(?:unsafe\s+)?fn\s+(\w+)\s*\(', data.decode())
            expected_methods = AC0963['methods'][path]
            require([name for _, name in rows] == expected_methods['all']
                    and [name for attrs, name in rows if re.search(r'#\[ignore(?:\]|\s*=)', attrs)]
                    == expected_methods['ignored'] and data.count(b'#[test]') == len(rows),
                    'ac0963_source_inventory_differs')


def before_ac0963(declared):
    """Peel only four exact live count rows; every other catalog byte is bound."""
    declared = main5c.peel_current(declared, 'ac0963_inventory_differs', 'ac0963_source_inventory_differs')
    require(type(declared) is dict and digest(declared) == LIVE, 'ac0963_inventory_differs')
    require_ac0963_sources()
    old = copy.deepcopy(declared)
    for cohort, changes in AC0963['changes'].items():
        for identity, (previous, current) in changes.items():
            require(old['harness_test_counts'][cohort][identity] == current, 'ac0963_inventory_differs')
            old['harness_test_counts'][cohort][identity] = copy.deepcopy(previous)
    require(digest(old) == AC0963['previous_corpus_sha256'] == CURRENT, 'ac0963_inventory_differs')
    return old


def peel_ac0963(declared):
    return before_ac0963(declared) if type(declared) is dict and digest(declared) in (LIVE, main5c.CURRENT, main813.CURRENT, main813.CURRENT690, main813.CURRENTC0, main813.CURRENTC1, main813.CURRENTE797, main813.CURRENTF0EF, main813.CURRENT7CDC, main813.CURRENT43D7, main813.CURRENT0DF8, main813.CURRENT0A8, main813.CURRENT09FE, main813.CURRENT727, main813.CURRENTABAB, main813.CURRENT83B, main813.CURRENT850, main813.CURRENT5A0, main813.CURRENT9950, main813.LATEST) else declared


def source_before_cc846(path, data, error):
    """Whole-new-blob authentication, exact sparse inverse, whole-old-blob check."""
    data = source_before_ac0963(path, data, error)
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
            data = source_before_ac0963(path, data, 'cc846_source_inventory_differs')
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
    declared = peel_ac0963(declared)
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
    declared = peel_ac0963(declared)
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
    declared = peel_ac0963(declared)
    return before_cc846(declared) if type(declared) is dict and digest(declared) == CURRENT else declared


def peel_python(identities):
    identities = main5c.peel_python(identities)
    if type(identities) is list and digest(identities) == PYTHON_PRE_5CDA:
        require(len(identities) == 340 and len(set(identities)) == 340,
                'cc846_python_inventory_differs')
        new = [x for x in identities if x.startswith(PYTHON_MODULE + '.')]
        old = [x for x in identities if not x.startswith(PYTHON_MODULE + '.')]
        require(new == list(PYTHON_METHODS) and len(old) == 330 and digest(old) == PYTHON_PREVIOUS,
                'cc846_python_inventory_differs')
        return old
    return identities


def require_current(declared):
    """Live preflight has no historical-catalog acceptance path."""
    require(type(declared) is dict and digest(declared) == main813.LATEST, 'ac0963_inventory_differs')
    before_cc846(declared)
    identities = []
    for path in sorted(Path(__file__).parent.glob('test_*.py')):
        identities.extend(path.stem + '.' + identity
                          for identity in inventory_syntax.identities(path.read_text()))
    require(digest(identities) == PYTHON_CURRENT and len(identities) == RECORDER_TESTS,
            'cc846_python_inventory_differs')
