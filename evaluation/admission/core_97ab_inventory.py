"""Exact native indexed-DSO source successor; all earlier catalogs remain separate."""
import copy
import hashlib
import json
from pathlib import Path
import re

from parsing import require

ROOT = Path(__file__).resolve().parents[2]
RAW = Path(__file__).with_suffix('.json').read_bytes()
require(hashlib.sha256(RAW).hexdigest() == 'b36618b96fde9b3269b7058852e6120f0760797a1a8f5189de155fa551d95af9',
        'main97ab_inventory_data_differs')
DATA = json.loads(RAW)
CURRENT = DATA['current_corpus_sha256']
EARLY_PREVIOUS = DATA['source_successor_667921']['previous_corpus_sha256']
ADMISSION_PREVIOUS = DATA['source_successor_c110']['previous_corpus_sha256']
CLOCK_PREVIOUS = DATA['source_successor_abe7']['previous_corpus_sha256']
OVERLAP_PREVIOUS = DATA['source_successor_124521']['previous_corpus_sha256']
RX_PREVIOUS = DATA['source_successor_b6fea']['previous_corpus_sha256']
ENTRY_PREVIOUS = DATA['source_successor_b0a30']['previous_corpus_sha256']
PLACEMENT_PREVIOUS = DATA['source_successor_fd4c6']['previous_corpus_sha256']
PHASE_CURRENT = DATA['source_successor_96378']['previous_corpus_sha256']
NATIVE_INDEXED_CURRENT = DATA['source_successor_29859']['previous_corpus_sha256']
PREVIOUS = DATA['previous_corpus_sha256']
PYTHON_CURRENT = DATA['python_current_sha256']
PYTHON_PREVIOUS = DATA['python_previous_sha256']
RECORDER_TESTS = 366
ADDED = 'test_main97ab_inventory.Main97abInventoryTests.test_exact_native_indexed_sources_and_historical_refusals'


def plain_catalog(value):
    """Only builtin object graphs have ordinary, non-publishing deepcopy semantics."""
    pending = [value]
    seen = set()
    while pending:
        item = pending.pop()
        kind = type(item)
        if kind in (str, int, bool, float, type(None)):
            continue
        if kind not in (dict, list, tuple):
            return False
        if id(item) in seen:
            continue
        seen.add(id(item))
        if kind is dict:
            pending.extend(item.keys())
            pending.extend(item.values())
        else:
            pending.extend(item)
    return True

def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                     allow_nan=False).encode()).hexdigest()


def inverse(path, raw, rows, error):
    if path not in rows:
        return raw
    row = rows[path]
    require(type(raw) is bytes and hashlib.sha256(raw).hexdigest() == row['current_sha256'], error)
    last = len(raw)
    pieces = []
    for first, end, old in reversed(row['edits']):
        require(type(first) is int and type(end) is int and type(old) is str
                and 0 <= first <= end <= last, error)
        pieces.append(raw[end:last])
        pieces.append(old.encode())
        last = first
    pieces.append(raw[:last])
    raw = b''.join(reversed(pieces))
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
        if path in DATA['doctests']:
            require(re.findall(r'(?ms)^/// ```[^\n]*\n.*?^/// ```$', raw.decode())
                    == DATA['doctests'][path], error)
        if path in DATA['source_successor_abe7']['doctest_sources']:
            require(re.findall(r'(?ms)^[ \t]*/// ```[^\n]*\n.*?^[ \t]*/// ```$', raw.decode())
                    == DATA['source_successor_abe7']['doctest_sources'][path], error)
        if path in DATA['module_chains']:
            require(all(raw.decode().count(literal) == 1
                        for literal in DATA['module_chains'][path]), error)
        source_before(path, raw, error)
        source_before_evaluation(path, raw, error)


def before_667921(declared, error='main97ab_inventory_differs'):
    """Bind all early-control tests, including both complete inherited oracles."""
    require(type(declared) is dict and digest(declared) == CURRENT, error)
    owned = plain_catalog((declared, DATA))
    old = copy.deepcopy(declared)
    rows = old['harness_test_counts']['workspace_tests']
    for name, change in DATA['source_successor_667921']['workspace_changes'].items():
        require(digest(rows[name]) == digest(change['current']), error)
        if change['previous'] is None:
            del rows[name]
        else:
            rows[name] = copy.deepcopy(change['previous'])
    require(digest(old) == EARLY_PREVIOUS, error)
    return old if owned else copy.deepcopy(old)


def before_c110(declared, error='main97ab_inventory_differs'):
    """Bind the three admission-comparison tests in the existing preempt harness."""
    owned = plain_catalog((declared, DATA))
    declared = before_667921(declared, error)
    require(type(declared) is dict and digest(declared) == EARLY_PREVIOUS, error)
    old = declared if owned else copy.deepcopy(declared)
    rows = old['harness_test_counts']['workspace_tests']
    for name, change in DATA['source_successor_c110']['workspace_changes'].items():
        require(digest(rows[name]) == digest(change['current']), error)
        rows[name] = copy.deepcopy(change['previous'])
    require(digest(old) == ADMISSION_PREVIOUS, error)
    return old if owned else copy.deepcopy(old)


def before_abe7(declared, error='main97ab_inventory_differs'):
    """Bind the exact region/batch methods, compile-fail docs and example target."""
    owned = plain_catalog((declared, DATA))
    declared = before_c110(declared, error)
    require(type(declared) is dict and digest(declared) == ADMISSION_PREVIOUS, error)
    old = declared if owned else copy.deepcopy(declared)
    rows = old['harness_test_counts']['workspace_tests']
    for name, change in DATA['source_successor_abe7']['workspace_changes'].items():
        require(digest(rows[name]) == digest(change['current']), error)
        if change['previous'] is None:
            del rows[name]
        else:
            rows[name] = copy.deepcopy(change['previous'])
    require(digest(old) == CLOCK_PREVIOUS, error)
    return old


def before_124521(declared, error='main97ab_inventory_differs'):
    """Bind every overlapping-relay test while retaining the whole prior catalog."""
    owned = plain_catalog((declared, DATA))
    declared = before_abe7(declared, error)
    require(type(declared) is dict and digest(declared) == CLOCK_PREVIOUS, error)
    old = declared if owned else copy.deepcopy(declared)
    rows = old['harness_test_counts']['workspace_tests']
    for name, change in DATA['source_successor_124521']['workspace_changes'].items():
        require(digest(rows[name]) == digest(change['current']), error)
        rows[name] = copy.deepcopy(change['previous'])
    require(digest(old) == OVERLAP_PREVIOUS, error)
    return old


def before_b6fea(declared, error='main97ab_inventory_differs'):
    """Bind the packed-RX catalog, including its mandatory Linux loader harness."""
    owned = plain_catalog((declared, DATA))
    declared = before_124521(declared, error)
    require(type(declared) is dict and digest(declared) == OVERLAP_PREVIOUS, error)
    old = declared if owned else copy.deepcopy(declared)
    rows = old['harness_test_counts']['workspace_tests']
    for name, change in DATA['source_successor_b6fea']['workspace_changes'].items():
        require(digest(rows[name]) == digest(change['current']), error)
        if change['previous'] is None:
            del rows[name]
        else:
            rows[name] = copy.deepcopy(change['previous'])
    require(digest(old) == RX_PREVIOUS, error)
    return old


def before_b0a30(declared, error='main97ab_inventory_differs'):
    """Bind the complete entry-veneer catalog, preserving its whole predecessor."""
    owned = plain_catalog((declared, DATA))
    declared = before_b6fea(declared, error)
    require(type(declared) is dict and digest(declared) == RX_PREVIOUS, error)
    old = declared if owned else copy.deepcopy(declared)
    rows = old['harness_test_counts']['workspace_tests']
    for name, change in DATA['source_successor_b0a30']['workspace_changes'].items():
        require(digest(rows[name]) == digest(change['current']), error)
        rows[name] = copy.deepcopy(change['previous'])
    require(digest(old) == ENTRY_PREVIOUS, error)
    return old


def before_fd4c6(declared, error='main97ab_inventory_differs'):
    """Preserve the entire pre-entry-veneer catalog before the placement inverse."""
    owned = plain_catalog((declared, DATA))
    declared = before_b0a30(declared, error)
    require(type(declared) is dict and digest(declared) == ENTRY_PREVIOUS, error)
    old = declared if owned else copy.deepcopy(declared)
    rows = old['harness_test_counts']['workspace_tests']
    for name, change in DATA['source_successor_fd4c6']['workspace_changes'].items():
        require(digest(rows[name]) == digest(change['current']), error)
        rows[name] = copy.deepcopy(change['previous'])
    require(digest(old) == PLACEMENT_PREVIOUS, error)
    return old


def before_96378(declared, error='main97ab_inventory_differs'):
    """Preserve the complete pre-placement catalog before the older projection."""
    owned = plain_catalog((declared, DATA))
    declared = before_fd4c6(declared, error)
    require(type(declared) is dict and digest(declared) == PLACEMENT_PREVIOUS, error)
    old = declared if owned else copy.deepcopy(declared)
    rows = old['harness_test_counts']['workspace_tests']
    for name, change in DATA['source_successor_96378']['workspace_changes'].items():
        require(digest(rows[name]) == digest(change['current']), error)
        if change['previous'] is None:
            del rows[name]
        else:
            rows[name] = copy.deepcopy(change['previous'])
    require(digest(old) == PHASE_CURRENT, error)
    return old


def before_29859(declared, error='main97ab_inventory_differs'):
    """Project only the exact new catalog; source validation remains mandatory below."""
    owned = plain_catalog((declared, DATA))
    declared = before_96378(declared, error)
    require(type(declared) is dict and digest(declared) == PHASE_CURRENT, error)
    old = declared if owned else copy.deepcopy(declared)
    change = DATA['source_successor_29859']['workspace_change']
    rows = old['harness_test_counts']['workspace_tests']
    require(digest(rows[change['identity']]) == digest(change['current']), error)
    rows[change['identity']] = copy.deepcopy(change['previous'])
    require(digest(old) == NATIVE_INDEXED_CURRENT, error)
    return old


def before_current(declared, error='main97ab_inventory_differs',
                   source_error='main97ab_source_inventory_differs'):
    owned = plain_catalog((declared, DATA))
    declared = before_29859(declared, error)
    require(type(declared) is dict and digest(declared) == NATIVE_INDEXED_CURRENT, error)
    require_sources(source_error)
    old = declared if owned else copy.deepcopy(declared)
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
