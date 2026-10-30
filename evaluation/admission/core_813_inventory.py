"""Exact main813 source/catalog successor; no execution credit from declarations."""
import ast
import copy
import hashlib
import json
from pathlib import Path
import re

from parsing import require
import inventory_syntax
import inventory_digest
import inventory_copy
import inventory_splice

ROOT = Path(__file__).resolve().parents[2]
RAW = Path(__file__).with_suffix('.json').read_bytes()
require(inventory_digest.hexdigest(RAW) == 'e25c57dd34959825b9589731ddb8356da87733280d7e97657f7100b5c3ec338e', 'main813_inventory_data_differs')
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
CURRENT09FE = MAIN09FE['current_corpus_sha256']
MAIN727 = DATA['main727']
CURRENT727 = MAIN727['current_corpus_sha256']
MAINABAB = DATA['mainabab']
CURRENTABAB = MAINABAB['current_corpus_sha256']
MAIN83B = DATA['main83b']
CURRENT83B = MAIN83B['current_corpus_sha256']
MAIN850 = DATA['main850']
CURRENT850 = MAIN850['current_corpus_sha256']
MAIN5A0 = DATA['main5a0']
CURRENT5A0 = MAIN5A0['current_corpus_sha256']
MAIN9950 = DATA['main9950']
CURRENT9950 = MAIN9950['current_corpus_sha256']
MAIN2754 = DATA['main2754']
CURRENT2754 = MAIN2754['current_corpus_sha256']
MAIN9C70 = DATA['main9c70']
CURRENT9C70 = MAIN9C70['current_corpus_sha256']
MAIN0A088 = DATA['main0a088']
CURRENT0A088 = MAIN0A088['current_corpus_sha256']
MAINE11 = DATA['maine11']
CURRENTE11 = MAINE11['current_corpus_sha256']
MAIN469 = DATA['main469']
CURRENT469 = MAIN469['current_corpus_sha256']
MAINB66 = DATA['mainb66']
MAIN8F622 = DATA['main8f622']
MAIN8F622_CURRENT = DATA['main8f622_current']
CURRENTB66 = MAINB66['current_corpus_sha256']
MAIN12E = DATA['main12e']
CURRENT12E = MAIN12E['current_corpus_sha256']
MAINC6F = DATA['mainc6f']
CURRENTC6F = MAINC6F['current_corpus_sha256']
MAINSHORT = DATA['neighbor_short']
CURRENTSHORT = MAINSHORT['current_corpus_sha256']
MAINSHORTNATIVE = DATA['neighbor_short_native']
CURRENTSHORTNATIVE = MAINSHORTNATIVE['current_corpus_sha256']
MAINSHORTENGINE = DATA['neighbor_short_engine']
CURRENTSHORTENGINE = MAINSHORTENGINE['current_corpus_sha256']
MAINSHORTOWNERSHIP = DATA['neighbor_short_ownership']
CURRENTSHORTOWNERSHIP = MAINSHORTOWNERSHIP['current_corpus_sha256']
MAINSHORTPENDING = DATA['neighbor_short_pending']
CURRENTSHORTPENDING = MAINSHORTPENDING['current_corpus_sha256']
MAINADJACENT = DATA['adjacent_b2']
CURRENTADJACENT = MAINADJACENT['current_corpus_sha256']
MAINFRONTEND = DATA['adjacent_b2_frontend']
CURRENTFRONTEND = MAINFRONTEND['current_corpus_sha256']
MAINROUTED = DATA['adjacent_routed_jmp']
CURRENTROUTED = MAINROUTED['current_corpus_sha256']
MAINROUTEDNATIVE = DATA['adjacent_routed_native']
CURRENTROUTEDNATIVE = MAINROUTEDNATIVE['current_corpus_sha256']
MAINSTARTUP = DATA['startup_carrier']
CURRENTSTARTUP = MAINSTARTUP['current_corpus_sha256']
MAIN091 = DATA['main091']
LATEST = MAIN091['current_corpus_sha256']
PREVIOUS = DATA['previous_corpus_sha256']
PYTHON_CURRENT = DATA['python_current_sha256']
PYTHON_PREVIOUS = DATA['python_previous_sha256']
RECORDER_TESTS = 350


def digest(value):
    return inventory_digest.hexdigest(json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode())


def precheck_current_sources(error):
    """Reject changed current blobs early; never replace historical validation."""
    layers = (DATA, MAIN690, MAINC0, MAINC1, MAINE797, MAINF0EF,
              MAIN7CDC, MAIN43D7, MAIN0DF8, MAIN0A8, MAIN09FE, MAIN727,
              MAINABAB, MAIN83B, MAIN850, MAIN5A0, MAIN9950, MAIN2754, MAIN9C70, MAIN0A088, MAINE11, MAIN469, MAINB66, MAIN8F622, MAIN12E, MAINC6F, MAINSHORT, MAINSHORTNATIVE, MAINSHORTENGINE, MAINSHORTOWNERSHIP, MAINSHORTPENDING, MAINADJACENT, MAINFRONTEND, MAINROUTED, MAINROUTEDNATIVE, MAINSTARTUP, MAIN091)
    expected = {}
    for layer in layers:
        # Non-plain metadata stays on the original path, without new callbacks
        # or file reads. This is eligibility for an extra rejection check only.
        if type(layer) is not dict or any(type(key) is not str for key in layer):
            return
        sources = layer.get('sources')
        if (type(sources) is not dict or
                any(type(path) is not str or type(value) is not str
                    for path, value in sources.items())):
            return
        expected.update(sources)
    for path, value in expected.items():
        try:
            raw = (ROOT / path).read_bytes()
        except OSError:
            require(False, error)
        require(inventory_digest.hexdigest(raw) == value, error)


def source_before_091(path, data, error):
    """Whole current source, exact sparse inverse, then whole historical source."""
    if path not in MAIN091['projections']:
        return data
    row = MAIN091['projections'][path]
    require(type(data) is bytes and inventory_digest.hexdigest(data) == row['current_sha256'], error)
    last = len(data)
    for start, end, old in reversed(row['edits']):
        require(0 <= start <= end <= last, error)
        data = inventory_splice.splice(data, start, end, old)
        last = start
    require(inventory_digest.hexdigest(data) == row['previous_sha256'], error)
    return data


def require_091_sources(error='091_source_inventory_differs'):
    for path, expected in MAIN091['sources'].items():
        try:
            raw = (ROOT / path).read_bytes()
        except OSError:
            require(False, error)
        require(inventory_digest.hexdigest(raw) == expected, error)
        if path in MAIN091['methods']:
            found = re.findall(r'#\[test\]\s*((?:#\[[^\n]*\]\s*)*)(?:unsafe\s+)?fn\s+(\w+)\s*\(', raw.decode())
            row = MAIN091['methods'][path]
            require([name for _, name in found] == row['all'] and
                    [name for attrs, name in found if re.search(r'#\[ignore(?:\]|\s*=)', attrs)] == row['ignored'] and
                    raw.count(b'#[test]') == len(found), error)
        if path in MAIN091['module_chains']:
            require(all(raw.decode().count(literal) == 1 for literal in MAIN091['module_chains'][path]), error)
        source_before_091(path, raw, error)
    for previous, row in MAIN091['relocations'].items():
        require(MAIN091['sources'][row['current_path']] == row['sha256'], error)
        if row['old_path_absent']:
            old = ROOT / previous
            require(not old.exists() and not old.is_symlink(), error)



def before_091(declared, error='091_inventory_differs', source_error='091_source_inventory_differs'):
    require(type(declared) is dict and digest(declared) == LATEST, error)
    require_091_sources(source_error)
    old = inventory_copy.deepcopy(declared)
    rows = old['harness_test_counts']['workspace_tests']
    for name, change in MAIN091['workspace_changes'].items():
        require(rows[name] == change['current'], error)
        if change['previous'] is None:
            del rows[name]
        else:
            rows[name] = inventory_copy.deepcopy(change['previous'])
    require(digest(old) == MAIN091['previous_corpus_sha256'] == CURRENTSTARTUP, error)
    return old


def peel_091(declared, error, source_error):
    return before_091(declared, error, source_error) if type(declared) is dict and digest(declared) == LATEST else declared


def source_before_startup(path, data, error):
    """Whole current source, exact sparse inverse, then whole historical source."""
    data = source_before_091(path, data, error)
    if path not in MAINSTARTUP['projections']:
        return data
    row = MAINSTARTUP['projections'][path]
    require(type(data) is bytes and inventory_digest.hexdigest(data) == row['current_sha256'], error)
    last = len(data)
    for start, end, old in reversed(row['edits']):
        require(0 <= start <= end <= last, error)
        data = inventory_splice.splice(data, start, end, old)
        last = start
    require(inventory_digest.hexdigest(data) == row['previous_sha256'], error)
    return data


def require_startup_sources(error='startup_source_inventory_differs'):
    for path, expected in MAINSTARTUP['sources'].items():
        try:
            raw = (ROOT / path).read_bytes()
        except OSError:
            require(False, error)
        observed = raw
        raw = source_before_091(path, raw, error)
        require(inventory_digest.hexdigest(raw) == expected, error)
        if path in MAINSTARTUP['methods']:
            found = re.findall(r'#\[test\]\s*((?:#\[[^\n]*\]\s*)*)(?:unsafe\s+)?fn\s+(\w+)\s*\(', raw.decode())
            row = MAINSTARTUP['methods'][path]
            require([name for _, name in found] == row['all'] and
                    [name for attrs, name in found if re.search(r'#\[ignore(?:\]|\s*=)', attrs)] == row['ignored'] and
                    raw.count(b'#[test]') == len(found), error)
        if path in MAINSTARTUP['module_chains']:
            require(all(raw.decode().count(literal) == 1 for literal in MAINSTARTUP['module_chains'][path]), error)
        source_before_startup(path, observed, error)


def before_startup(declared, error='startup_inventory_differs', source_error='startup_source_inventory_differs'):
    declared = peel_091(declared, error, source_error)
    require(type(declared) is dict and digest(declared) == CURRENTSTARTUP, error)
    require_startup_sources(source_error)
    old = inventory_copy.deepcopy(declared)
    rows = old['harness_test_counts']['workspace_tests']
    for name, change in MAINSTARTUP['workspace_changes'].items():
        require(rows[name] == change['current'], error)
        if change['previous'] is None:
            del rows[name]
        else:
            rows[name] = inventory_copy.deepcopy(change['previous'])
    require(digest(old) == MAINSTARTUP['previous_corpus_sha256'] == CURRENTROUTEDNATIVE, error)
    return old


def peel_startup(declared, error, source_error):
    declared = peel_091(declared, error, source_error)
    return before_startup(declared, error, source_error) if type(declared) is dict and digest(declared) == CURRENTSTARTUP else declared


def source_before_routed_native(path, data, error):
    """Whole current source, exact sparse inverse, then whole historical source."""
    data = source_before_startup(path, data, error)
    if path not in MAINROUTEDNATIVE['projections']:
        return data
    row = MAINROUTEDNATIVE['projections'][path]
    require(type(data) is bytes and inventory_digest.hexdigest(data) == row['current_sha256'], error)
    last = len(data)
    for start, end, old in reversed(row['edits']):
        require(0 <= start <= end <= last, error)
        data = inventory_splice.splice(data, start, end, old)
        last = start
    require(inventory_digest.hexdigest(data) == row['previous_sha256'], error)
    return data


def require_routed_native_sources(error='adjacent_routed_native_source_inventory_differs'):
    for path, expected in MAINROUTEDNATIVE['sources'].items():
        try:
            raw = (ROOT / path).read_bytes()
        except OSError:
            require(False, error)
        observed = raw
        raw = source_before_startup(path, raw, error)
        require(inventory_digest.hexdigest(raw) == expected, error)
        if path in MAINROUTEDNATIVE['methods']:
            found = re.findall(r'#\[test\]\s*((?:#\[[^\n]*\]\s*)*)(?:unsafe\s+)?fn\s+(\w+)\s*\(', raw.decode())
            row = MAINROUTEDNATIVE['methods'][path]
            require([name for _, name in found] == row['all'] and
                    [name for attrs, name in found if re.search(r'#\[ignore(?:\]|\s*=)', attrs)] == row['ignored'] and
                    raw.count(b'#[test]') == len(found) +
                    MAINROUTEDNATIVE['macro_tests'].get(path, {}).get('template_tests', 0), error)
        if path in MAINROUTEDNATIVE['macro_tests']:
            macro = MAINROUTEDNATIVE['macro_tests'][path]
            require(macro['template_tests'] == 1 and macro['definition'].count('#[test]') == 1 and
                    raw.decode().count(macro['definition']) == 1 and
                    [list(row) for row in re.findall(r'^row!\((\w+), (\d+)\);$', raw.decode(), re.M)] == macro['rows'] and
                    macro['rows'] == [[f'row_{i:02}', str(i)] for i in range(31)], error)
        if path in MAINROUTEDNATIVE['module_chains']:
            require(all(raw.decode().count(literal) == 1 for literal in MAINROUTEDNATIVE['module_chains'][path]), error)
        source_before_routed_native(path, observed, error)


def before_routed_native(declared, error='adjacent_routed_native_inventory_differs', source_error='adjacent_routed_native_source_inventory_differs'):
    declared = peel_startup(declared, error, source_error)
    require(type(declared) is dict and digest(declared) == CURRENTROUTEDNATIVE, error)
    require_routed_native_sources(source_error)
    old = inventory_copy.deepcopy(declared)
    rows = old['harness_test_counts']['workspace_tests']
    for name, change in MAINROUTEDNATIVE['workspace_changes'].items():
        require(rows[name] == change['current'], error)
        if change['previous'] is None:
            del rows[name]
        else:
            rows[name] = inventory_copy.deepcopy(change['previous'])
    require(digest(old) == MAINROUTEDNATIVE['previous_corpus_sha256'] == CURRENTROUTED, error)
    return old


def peel_routed_native(declared, error, source_error):
    declared = peel_startup(declared, error, source_error)
    return before_routed_native(declared, error, source_error) if type(declared) is dict and digest(declared) == CURRENTROUTEDNATIVE else declared


def source_before_routed(path, data, error):
    """Whole current source, exact sparse inverse, then whole historical source."""
    data = source_before_routed_native(path, data, error)
    if path not in MAINROUTED['projections']:
        return data
    row = MAINROUTED['projections'][path]
    require(type(data) is bytes and inventory_digest.hexdigest(data) == row['current_sha256'], error)
    last = len(data)
    for start, end, old in reversed(row['edits']):
        require(0 <= start <= end <= last, error)
        data = inventory_splice.splice(data, start, end, old)
        last = start
    require(inventory_digest.hexdigest(data) == row['previous_sha256'], error)
    return data


def require_routed_sources(error='adjacent_routed_source_inventory_differs'):
    for path, expected in MAINROUTED['sources'].items():
        try:
            raw = (ROOT / path).read_bytes()
        except OSError:
            require(False, error)
        observed = raw
        raw = source_before_routed_native(path, raw, error)
        require(inventory_digest.hexdigest(raw) == expected, error)
        if path in MAINROUTED['methods']:
            found = re.findall(r'#\[test\]\s*((?:#\[[^\n]*\]\s*)*)(?:unsafe\s+)?fn\s+(\w+)\s*\(', raw.decode())
            row = MAINROUTED['methods'][path]
            require([name for _, name in found] == row['all'] and
                    [name for attrs, name in found if re.search(r'#\[ignore(?:\]|\s*=)', attrs)] == row['ignored'] and
                    raw.count(b'#[test]') == len(found), error)
        if path in MAINROUTED['module_chains']:
            require(all(raw.decode().count(literal) == 1 for literal in MAINROUTED['module_chains'][path]), error)
        source_before_routed(path, observed, error)


def before_routed(declared, error='adjacent_routed_inventory_differs', source_error='adjacent_routed_source_inventory_differs'):
    declared = peel_routed_native(declared, error, source_error)
    require(type(declared) is dict and digest(declared) == CURRENTROUTED, error)
    require_routed_sources(source_error)
    old = inventory_copy.deepcopy(declared)
    rows = old['harness_test_counts']['workspace_tests']
    for name, change in MAINROUTED['workspace_changes'].items():
        require(rows[name] == change['current'], error)
        if change['previous'] is None:
            del rows[name]
        else:
            rows[name] = inventory_copy.deepcopy(change['previous'])
    require(digest(old) == MAINROUTED['previous_corpus_sha256'] == CURRENTFRONTEND, error)
    return old


def peel_routed(declared, error, source_error):
    declared = peel_routed_native(declared, error, source_error)
    return before_routed(declared, error, source_error) if type(declared) is dict and digest(declared) == CURRENTROUTED else declared


def source_before_frontend(path, data, error):
    """Whole current source, exact sparse inverse, then whole historical source."""
    data = source_before_routed(path, data, error)
    if path not in MAINFRONTEND['projections']:
        return data
    row = MAINFRONTEND['projections'][path]
    require(type(data) is bytes and inventory_digest.hexdigest(data) == row['current_sha256'], error)
    last = len(data)
    for start, end, old in reversed(row['edits']):
        require(0 <= start <= end <= last, error)
        data = inventory_splice.splice(data, start, end, old)
        last = start
    require(inventory_digest.hexdigest(data) == row['previous_sha256'], error)
    return data


def require_frontend_sources(error='adjacent_frontend_source_inventory_differs'):
    for path, expected in MAINFRONTEND['sources'].items():
        try:
            raw = (ROOT / path).read_bytes()
        except OSError:
            require(False, error)
        observed = raw
        raw = source_before_routed(path, raw, error)
        require(inventory_digest.hexdigest(raw) == expected, error)
        if path in MAINFRONTEND['methods']:
            found = re.findall(r'#\[test\]\s*((?:#\[[^\n]*\]\s*)*)(?:unsafe\s+)?fn\s+(\w+)\s*\(', raw.decode())
            row = MAINFRONTEND['methods'][path]
            require([name for _, name in found] == row['all'] and
                    [name for attrs, name in found if re.search(r'#\[ignore(?:\]|\s*=)', attrs)] == row['ignored'] and
                    raw.count(b'#[test]') == len(found), error)
        if path in MAINFRONTEND['module_chains']:
            require(all(raw.decode().count(literal) == 1 for literal in MAINFRONTEND['module_chains'][path]), error)
        source_before_frontend(path, observed, error)


def before_frontend(declared, error='adjacent_frontend_inventory_differs', source_error='adjacent_frontend_source_inventory_differs'):
    declared = peel_routed(declared, error, source_error)
    require(type(declared) is dict and digest(declared) == CURRENTFRONTEND, error)
    require_frontend_sources(source_error)
    old = inventory_copy.deepcopy(declared)
    rows = old['harness_test_counts']['workspace_tests']
    for name, change in MAINFRONTEND['workspace_changes'].items():
        require(rows[name] == change['current'], error)
        if change['previous'] is None:
            del rows[name]
        else:
            rows[name] = inventory_copy.deepcopy(change['previous'])
    require(digest(old) == MAINFRONTEND['previous_corpus_sha256'] == CURRENTADJACENT, error)
    return old


def peel_frontend(declared, error, source_error):
    declared = peel_routed(declared, error, source_error)
    return before_frontend(declared, error, source_error) if type(declared) is dict and digest(declared) == CURRENTFRONTEND else declared


def source_before_adjacent(path, data, error):
    """Authenticate the whole adjacent API module before the exact older image."""
    data = source_before_frontend(path, data, error)
    if path not in MAINADJACENT['projections']:
        return data
    row = MAINADJACENT['projections'][path]
    require(type(data) is bytes and inventory_digest.hexdigest(data) == row['current_sha256'], error)
    last = len(data)
    for start, end, old in reversed(row['edits']):
        require(0 <= start <= end <= last, error)
        data = inventory_splice.splice(data, start, end, old)
        last = start
    require(inventory_digest.hexdigest(data) == row['previous_sha256'], error)
    return data


def require_adjacent_sources(error='adjacent_b2_source_inventory_differs'):
    for path, expected in MAINADJACENT['sources'].items():
        try:
            raw = (ROOT / path).read_bytes()
        except OSError:
            require(False, error)
        raw = source_before_frontend(path, raw, error)
        require(inventory_digest.hexdigest(raw) == expected, error)
        if path in MAINADJACENT['methods']:
            found = re.findall(r'#\[test\]\s*((?:#\[[^\n]*\]\s*)*)(?:unsafe\s+)?fn\s+(\w+)\s*\(', raw.decode())
            row = MAINADJACENT['methods'][path]
            require([name for _, name in found] == row['all'] and
                    [name for attrs, name in found if re.search(r'#\[ignore(?:\]|\s*=)', attrs)] == row['ignored'] and
                    raw.count(b'#[test]') == len(found), error)
        if path in MAINADJACENT['module_chains']:
            require(all(raw.decode().count(literal) == 1 for literal in MAINADJACENT['module_chains'][path]), error)


def before_adjacent(declared, error='adjacent_b2_inventory_differs', source_error='adjacent_b2_source_inventory_differs'):
    declared = peel_frontend(declared, error, source_error)
    require(type(declared) is dict and digest(declared) == CURRENTADJACENT, error)
    require_adjacent_sources(source_error)
    old = inventory_copy.deepcopy(declared)
    rows = old['harness_test_counts']['workspace_tests']
    for name, change in MAINADJACENT['workspace_changes'].items():
        require(rows[name] == change['current'], error)
        rows[name] = inventory_copy.deepcopy(change['previous'])
    require(digest(old) == MAINADJACENT['previous_corpus_sha256'] == CURRENTSHORTPENDING, error)
    return old


def peel_adjacent(declared, error, source_error):
    declared = peel_frontend(declared, error, source_error)
    return before_adjacent(declared, error, source_error) if type(declared) is dict and digest(declared) == CURRENTADJACENT else declared


def source_before_short_pending(path, data, error):
    """Authenticate the complete pending image before its exact prior image."""
    data = source_before_adjacent(path, data, error)
    if path not in MAINSHORTPENDING['projections']:
        return data
    row = MAINSHORTPENDING['projections'][path]
    require(type(data) is bytes and inventory_digest.hexdigest(data) == row['current_sha256'], error)
    last = len(data)
    for start, end, old in reversed(row['edits']):
        require(0 <= start <= end <= last, error)
        data = inventory_splice.splice(data, start, end, old)
        last = start
    require(inventory_digest.hexdigest(data) == row['previous_sha256'], error)
    return data


def _require_short_pending_blob(path, raw, expected, error):
    require(inventory_digest.hexdigest(raw) == expected, error)
    if path in MAINSHORTPENDING['methods']:
        found = re.findall(r'#\[test\]\s*((?:#\[[^\n]*\]\s*)*)(?:unsafe\s+)?fn\s+(\w+)\s*\(', raw.decode())
        row = MAINSHORTPENDING['methods'][path]
        require([name for _, name in found] == row['all'] and
                [name for attrs, name in found if re.search(r'#\[ignore(?:\]|\s*=)', attrs)] == row['ignored'] and
                raw.count(b'#[test]') == len(found), error)
    if path in MAINSHORTPENDING['python_methods']:
        cached = inventory_syntax.cached_test_names(raw, ast, _SHORT_PENDING_SYNTAX_CONTEXT)
        if cached is None:
            tree = ast.parse(raw)
            found = [node.name for node in ast.walk(tree)
                     if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith('test_')]
        else:
            found = [name for name in cached]
        require(found == MAINSHORTPENDING['python_methods'][path], error)
    if path in MAINSHORTPENDING['module_chains']:
        require(all(raw.decode().count(literal) == 1 for literal in MAINSHORTPENDING['module_chains'][path]), error)


_SHORT_PENDING_SYNTAX_CONTEXT = (
    _require_short_pending_blob.__globals__,
    _require_short_pending_blob.__builtins__,
)


def require_short_pending_sources(error='neighbor_short_pending_source_inventory_differs'):
    for path, expected in MAINSHORTPENDING['sources'].items():
        try:
            raw = (ROOT / path).read_bytes()
        except OSError:
            require(False, error)
        raw = source_before_adjacent(path, raw, error)
        _require_short_pending_blob(path, raw, expected, error)


def before_short_pending(declared, error='neighbor_short_pending_inventory_differs', source_error='neighbor_short_pending_source_inventory_differs'):
    declared = peel_adjacent(declared, error, source_error)
    require(type(declared) is dict and digest(declared) == CURRENTSHORTPENDING, error)
    require_short_pending_sources(source_error)
    old = inventory_copy.deepcopy(declared)
    rows = old['harness_test_counts']['workspace_tests']
    for name, change in MAINSHORTPENDING['workspace_changes'].items():
        require(rows[name] == change['current'], error)
        rows[name] = inventory_copy.deepcopy(change['previous'])
    require(digest(old) == MAINSHORTPENDING['previous_corpus_sha256'] == CURRENTSHORTOWNERSHIP, error)
    return old


def peel_short_pending(declared, error, source_error):
    declared = peel_adjacent(declared, error, source_error)
    return before_short_pending(declared, error, source_error) if type(declared) is dict and digest(declared) == CURRENTSHORTPENDING else declared


def source_before_short_ownership(path, data, error):
    """Authenticate the complete ownership source before one exact inverse."""
    data = source_before_short_pending(path, data, error)
    if path not in MAINSHORTOWNERSHIP['projections']:
        return data
    row = MAINSHORTOWNERSHIP['projections'][path]
    require(type(data) is bytes and inventory_digest.hexdigest(data) == row['current_sha256'], error)
    last = len(data)
    for start, end, old in reversed(row['edits']):
        require(0 <= start <= end <= last, error)
        data = inventory_splice.splice(data, start, end, old)
        last = start
    require(inventory_digest.hexdigest(data) == row['previous_sha256'], error)
    return data


def _require_short_ownership_blob(path, raw, expected, error):
    require(inventory_digest.hexdigest(raw) == expected, error)
    if path in MAINSHORTOWNERSHIP['methods']:
        found = re.findall(r'#\[test\]\s*((?:#\[[^\n]*\]\s*)*)(?:unsafe\s+)?fn\s+(\w+)\s*\(', raw.decode())
        row = MAINSHORTOWNERSHIP['methods'][path]
        require([name for _, name in found] == row['all'] and
                [name for attrs, name in found if re.search(r'#\[ignore(?:\]|\s*=)', attrs)] == row['ignored'] and
                raw.count(b'#[test]') == len(found), error)
    if path in MAINSHORTOWNERSHIP['python_methods']:
        cached = inventory_syntax.cached_test_names(raw, ast, _SHORT_OWNERSHIP_SYNTAX_CONTEXT)
        if cached is None:
            tree = ast.parse(raw)
            found = [node.name for node in ast.walk(tree)
                     if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith('test_')]
        else:
            found = [name for name in cached]
        require(found == MAINSHORTOWNERSHIP['python_methods'][path], error)
    if path in MAINSHORTOWNERSHIP['module_chains']:
        require(all(raw.decode().count(literal) == 1 for literal in MAINSHORTOWNERSHIP['module_chains'][path]), error)


_SHORT_OWNERSHIP_SYNTAX_CONTEXT = (
    _require_short_ownership_blob.__globals__,
    _require_short_ownership_blob.__builtins__,
)


def require_short_ownership_sources(error='neighbor_short_ownership_source_inventory_differs'):
    require_short_pending_sources(error)
    for path, expected in MAINSHORTOWNERSHIP['sources'].items():
        try:
            raw = (ROOT / path).read_bytes()
        except OSError:
            require(False, error)
        raw = source_before_short_pending(path, raw, error)
        _require_short_ownership_blob(path, raw, expected, error)


def before_short_ownership(declared, error='neighbor_short_ownership_inventory_differs', source_error='neighbor_short_ownership_source_inventory_differs'):
    declared = peel_short_pending(declared, error, source_error)
    require(type(declared) is dict and digest(declared) == CURRENTSHORTOWNERSHIP, error)
    require_short_ownership_sources(source_error)
    old = inventory_copy.deepcopy(declared)
    rows = old['harness_test_counts']['workspace_tests']
    for name, change in MAINSHORTOWNERSHIP['workspace_changes'].items():
        require(rows[name] == change['current'], error)
        rows[name] = inventory_copy.deepcopy(change['previous'])
    require(digest(old) == MAINSHORTOWNERSHIP['previous_corpus_sha256'] == CURRENTSHORTENGINE, error)
    return old


def peel_short_ownership(declared, error, source_error):
    declared = peel_short_pending(declared, error, source_error)
    return before_short_ownership(declared, error, source_error) if type(declared) is dict and digest(declared) == CURRENTSHORTOWNERSHIP else declared


def source_before_short_engine(path, data, error):
    """Authenticate the whole explicit-engine blob before its exact inverse."""
    data = source_before_short_ownership(path, data, error)
    if path not in MAINSHORTENGINE['projections']:
        return data
    row = MAINSHORTENGINE['projections'][path]
    require(type(data) is bytes and inventory_digest.hexdigest(data) == row['current_sha256'], error)
    last = len(data)
    for start, end, old in reversed(row['edits']):
        require(0 <= start <= end <= last, error)
        data = inventory_splice.splice(data, start, end, old)
        last = start
    require(inventory_digest.hexdigest(data) == row['previous_sha256'], error)
    return data


def _require_short_engine_blob(path, raw, expected, error):
    require(inventory_digest.hexdigest(raw) == expected, error)
    if path in MAINSHORTENGINE['methods']:
        found = re.findall(r'#\[test\]\s*((?:#\[[^\n]*\]\s*)*)(?:unsafe\s+)?fn\s+(\w+)\s*\(', raw.decode())
        row = MAINSHORTENGINE['methods'][path]
        require([name for _, name in found] == row['all'] and
                [name for attrs, name in found if re.search(r'#\[ignore(?:\]|\s*=)', attrs)] == row['ignored'] and
                raw.count(b'#[test]') == len(found), error)
    if path in MAINSHORTENGINE['module_chains']:
        require(all(raw.decode().count(literal) == 1 for literal in MAINSHORTENGINE['module_chains'][path]), error)


def require_short_engine_sources(error='neighbor_short_engine_source_inventory_differs'):
    require_short_ownership_sources(error)
    for path, expected in MAINSHORTENGINE['sources'].items():
        try:
            raw = (ROOT / path).read_bytes()
        except OSError:
            require(False, error)
        raw = source_before_short_ownership(path, raw, error)
        _require_short_engine_blob(path, raw, expected, error)


def before_short_engine(declared, error='neighbor_short_engine_inventory_differs', source_error='neighbor_short_engine_source_inventory_differs'):
    declared = peel_short_ownership(declared, error, source_error)
    require(type(declared) is dict and digest(declared) == CURRENTSHORTENGINE, error)
    require_short_engine_sources(source_error)
    old = inventory_copy.deepcopy(declared)
    rows = old['harness_test_counts']['workspace_tests']
    for name, change in MAINSHORTENGINE['workspace_changes'].items():
        require(rows[name] == change['current'], error)
        if change['previous'] is None:
            del rows[name]
        else:
            rows[name] = inventory_copy.deepcopy(change['previous'])
    require(digest(old) == MAINSHORTENGINE['previous_corpus_sha256'] == CURRENTSHORTNATIVE, error)
    return old


def peel_short_engine(declared, error, source_error):
    declared = peel_short_ownership(declared, error, source_error)
    return before_short_engine(declared, error, source_error) if type(declared) is dict and digest(declared) == CURRENTSHORTENGINE else declared


def source_before_short_native(path, data, error):
    """Only the fixed short-native whole blob may reach its exact historical source."""
    data = source_before_short_engine(path, data, error)
    if path not in MAINSHORTNATIVE['projections']:
        return data
    row = MAINSHORTNATIVE['projections'][path]
    require(type(data) is bytes and inventory_digest.hexdigest(data) == row['current_sha256'], error)
    last = len(data)
    for start, end, old in reversed(row['edits']):
        require(0 <= start <= end <= last, error)
        data = inventory_splice.splice(data, start, end, old)
        last = start
    require(inventory_digest.hexdigest(data) == row['previous_sha256'], error)
    return data


def _require_short_native_blob(path, raw, expected, error):
    require(inventory_digest.hexdigest(raw) == expected, error)
    if path in MAINSHORTNATIVE['methods']:
        found = re.findall(r'#\[test\]\s*((?:#\[[^\n]*\]\s*)*)(?:unsafe\s+)?fn\s+(\w+)\s*\(', raw.decode())
        row = MAINSHORTNATIVE['methods'][path]
        require([name for _, name in found] == row['all'] and
                [name for attrs, name in found if re.search(r'#\[ignore(?:\]|\s*=)', attrs)] == row['ignored'] and
                raw.count(b'#[test]') == len(found), error)
    if path in MAINSHORTNATIVE['module_chains']:
        require(all(raw.decode().count(literal) == 1 for literal in MAINSHORTNATIVE['module_chains'][path]), error)


def require_short_native_sources(error='neighbor_short_native_source_inventory_differs'):
    require_short_engine_sources(error)
    for path, expected in MAINSHORTNATIVE['sources'].items():
        try:
            raw = (ROOT / path).read_bytes()
        except OSError:
            require(False, error)
        raw = source_before_short_engine(path, raw, error)
        _require_short_native_blob(path, raw, expected, error)


def before_short_native(declared, error='neighbor_short_native_inventory_differs', source_error='neighbor_short_native_source_inventory_differs'):
    declared = peel_short_engine(declared, error, source_error)
    require(type(declared) is dict and digest(declared) == CURRENTSHORTNATIVE, error)
    require_short_native_sources(source_error)
    old = inventory_copy.deepcopy(declared)
    rows = old['harness_test_counts']['workspace_tests']
    for name, change in MAINSHORTNATIVE['workspace_changes'].items():
        require(rows[name] == change['current'], error)
        rows[name] = inventory_copy.deepcopy(change['previous'])
    require(digest(old) == MAINSHORTNATIVE['previous_corpus_sha256'] == CURRENTSHORT, error)
    return old


def peel_short_native(declared, error, source_error):
    declared = peel_short_engine(declared, error, source_error)
    return before_short_native(declared, error, source_error) if type(declared) is dict and digest(declared) == CURRENTSHORTNATIVE else declared


def source_before_short(path, data, error):
    """Only the fixed short whole blob may reach its exact historical source."""
    data = source_before_short_native(path, data, error)
    if path not in MAINSHORT['projections']:
        return data
    row = MAINSHORT['projections'][path]
    require(type(data) is bytes and inventory_digest.hexdigest(data) == row['current_sha256'], error)
    last = len(data)
    for start, end, old in reversed(row['edits']):
        require(0 <= start <= end <= last, error)
        data = inventory_splice.splice(data, start, end, old)
        last = start
    require(inventory_digest.hexdigest(data) == row['previous_sha256'], error)
    return data


def require_short_sources(error='neighbor_short_source_inventory_differs'):
    require_short_native_sources(error)
    for path, expected in MAINSHORT['sources'].items():
        try:
            raw = (ROOT / path).read_bytes()
        except OSError:
            require(False, error)
        raw = source_before_short_native(path, raw, error)
        require(inventory_digest.hexdigest(raw) == expected, error)
        if path in MAINSHORT['methods']:
            found = re.findall(r'#\[test\]\s*((?:#\[[^\n]*\]\s*)*)(?:unsafe\s+)?fn\s+(\w+)\s*\(', raw.decode())
            row = MAINSHORT['methods'][path]
            require([name for _, name in found] == row['all'] and
                    [name for attrs, name in found if re.search(r'#\[ignore(?:\]|\s*=)', attrs)] == row['ignored'] and
                    raw.count(b'#[test]') == len(found), error)
        if path in MAINSHORT['module_chains']:
            require(all(raw.decode().count(literal) == 1 for literal in MAINSHORT['module_chains'][path]), error)


def before_short(declared, error='neighbor_short_inventory_differs', source_error='neighbor_short_source_inventory_differs'):
    declared = peel_short_native(declared, error, source_error)
    require(type(declared) is dict and digest(declared) == CURRENTSHORT, error)
    require_short_sources(source_error)
    old = inventory_copy.deepcopy(declared)
    rows = old['harness_test_counts']['workspace_tests']
    for name, change in MAINSHORT['workspace_changes'].items():
        require(rows[name] == change['current'], error)
        rows[name] = inventory_copy.deepcopy(change['previous'])
    require(digest(old) == MAINSHORT['previous_corpus_sha256'] == CURRENTC6F, error)
    return old


def peel_short(declared, error, source_error):
    declared = peel_short_native(declared, error, source_error)
    return before_short(declared, error, source_error) if type(declared) is dict and digest(declared) == CURRENTSHORT else declared


def source_at_8f622(path, data, error):
    """Authenticate only the two newer whole blobs before the retained 8f622 proof."""
    data = source_before_short_native(path, data, error)
    if path not in MAIN8F622_CURRENT:
        return data
    row = MAIN8F622_CURRENT[path]
    require(row['current_sha256'] == MAIN12E['sources'][path] and
            row['previous_sha256'] == MAIN8F622['sources'][path], error)
    require(type(data) is bytes and inventory_digest.hexdigest(data) == row['current_sha256'], error)
    last = len(data)
    for start, end, old in reversed(row['edits']):
        require(0 <= start <= end <= last, error)
        data = inventory_splice.splice(data, start, end, old)
        last = start
    require(inventory_digest.hexdigest(data) == row['previous_sha256'], error)
    return data


def source_before_8f622(path, data, error):
    """Only the fixed incoming whole blob can recover its historical bytes."""
    if path not in MAIN8F622['projections']:
        return data
    data = source_at_8f622(path, data, error)
    row = MAIN8F622['projections'][path]
    require(type(data) is bytes and inventory_digest.hexdigest(data) == row['current_sha256'], error)
    last = len(data)
    for start, end, old in reversed(row['edits']):
        require(0 <= start <= end <= last, error)
        data = inventory_splice.splice(data, start, end, old)
        last = start
    require(inventory_digest.hexdigest(data) == row['previous_sha256'], error)
    return data


def require_8f622_sources(error='main8f622_source_inventory_differs'):
    for path, expected in MAIN8F622['sources'].items():
        try:
            raw = (ROOT / path).read_bytes()
        except OSError:
            require(False, error)
        raw = source_at_8f622(path, raw, error)
        require(inventory_digest.hexdigest(raw) == expected, error)


def source_before_c6f(path, data, error):
    """Only the fixed c6f whole blob may reach its exact historical source."""
    data = source_before_short(path, data, error)
    if path not in MAINC6F['projections']:
        return data
    row = MAINC6F['projections'][path]
    require(type(data) is bytes and inventory_digest.hexdigest(data) == row['current_sha256'], error)
    last = len(data)
    for start, end, old in reversed(row['edits']):
        require(0 <= start <= end <= last, error)
        data = inventory_splice.splice(data, start, end, old)
        last = start
    require(inventory_digest.hexdigest(data) == row['previous_sha256'], error)
    return data


def _require_c6f_blob(path, raw, expected, error):
    require(inventory_digest.hexdigest(raw) == expected, error)
    if path in MAINC6F['methods']:
        found = re.findall(r'#\[test\]\s*((?:#\[[^\n]*\]\s*)*)(?:unsafe\s+)?fn\s+(\w+)\s*\(', raw.decode())
        row = MAINC6F['methods'][path]
        require([name for _, name in found] == row['all'] and
                [name for attrs, name in found if re.search(r'#\[ignore(?:\]|\s*=)', attrs)] == row['ignored'] and
                raw.count(b'#[test]') == len(found), error)
    if path in MAINC6F['module_chains']:
        require(all(raw.decode().count(literal) == 1 for literal in MAINC6F['module_chains'][path]), error)


def require_c6f_sources(error='mainc6f_source_inventory_differs'):
    require_short_sources(error)
    for path, expected in MAINC6F['sources'].items():
        try:
            raw = (ROOT / path).read_bytes()
        except OSError:
            require(False, error)
        raw = source_before_short(path, raw, error)
        _require_c6f_blob(path, raw, expected, error)


def before_c6f(declared, error='mainc6f_inventory_differs', source_error='mainc6f_source_inventory_differs'):
    declared = peel_short(declared, error, source_error)
    require(type(declared) is dict and digest(declared) == CURRENTC6F, error)
    require_c6f_sources(source_error)
    old = inventory_copy.deepcopy(declared)
    rows = old['harness_test_counts']['workspace_tests']
    for name, change in MAINC6F['workspace_changes'].items():
        require(rows[name] == change['current'], error)
        rows[name] = inventory_copy.deepcopy(change['previous'])
    require(digest(old) == MAINC6F['previous_corpus_sha256'] == CURRENT12E, error)
    return old


def peel_c6f(declared, error, source_error):
    declared = peel_short(declared, error, source_error)
    return before_c6f(declared, error, source_error) if type(declared) is dict and digest(declared) == CURRENTC6F else declared


def source_before_12e(path, data, error):
    """Only the fixed 12e whole blob may reach its exact historical source."""
    unprojected = data
    data = source_before_c6f(path, data, error)
    if path not in MAIN12E['projections']:
        return data
    historical8f = (source_before_8f622(path, unprojected, error)
                    if path in MAIN8F622['projections'] else None)
    row = MAIN12E['projections'][path]
    require(type(data) is bytes and inventory_digest.hexdigest(data) == row['current_sha256'], error)
    last = len(data)
    for start, end, old in reversed(row['edits']):
        require(0 <= start <= end <= last, error)
        data = inventory_splice.splice(data, start, end, old)
        last = start
    require(inventory_digest.hexdigest(data) == row['previous_sha256'], error)
    if historical8f is not None:
        require(data == historical8f, error)
    return data


def require_12e_sources(error='main12e_source_inventory_differs'):
    require_c6f_sources(error)
    require_8f622_sources(error)
    for path, expected in MAIN12E['sources'].items():
        try:
            raw = (ROOT / path).read_bytes()
        except OSError:
            require(False, error)
        raw = source_before_c6f(path, raw, error)
        require(inventory_digest.hexdigest(raw) == expected, error)
        if path in MAIN12E['methods']:
            found = re.findall(r'#\[test\]\s*((?:#\[[^\n]*\]\s*)*)(?:unsafe\s+)?fn\s+(\w+)\s*\(', raw.decode())
            row = MAIN12E['methods'][path]
            require([name for _, name in found] == row['all'] and
                    [name for attrs, name in found if re.search(r'#\[ignore(?:\]|\s*=)', attrs)] == row['ignored'] and
                    raw.count(b'#[test]') == len(found), error)
        if path in MAIN12E['module_chains']:
            require(all(raw.decode().count(literal) == 1 for literal in MAIN12E['module_chains'][path]), error)


def before_12e(declared, error='main12e_inventory_differs', source_error='main12e_source_inventory_differs'):
    declared = peel_c6f(declared, error, source_error)
    require(type(declared) is dict and digest(declared) == CURRENT12E, error)
    require_12e_sources(source_error)
    old = inventory_copy.deepcopy(declared)
    rows = old['harness_test_counts']['workspace_tests']
    for name, change in MAIN12E['workspace_changes'].items():
        require(rows[name] == change['current'], error)
        rows[name] = inventory_copy.deepcopy(change['previous'])
    require(digest(old) == MAIN12E['previous_corpus_sha256'] == CURRENTB66, error)
    return old


def peel_12e(declared, error, source_error):
    declared = peel_c6f(declared, error, source_error)
    return before_12e(declared, error, source_error) if type(declared) is dict and digest(declared) == CURRENT12E else declared


def source_before_b66(path, data, error):
    """Only the fixed b66 whole blob may reach its exact historical source."""
    data = source_before_12e(path, data, error)
    if path not in MAINB66['projections']:
        return data
    row = MAINB66['projections'][path]
    require(type(data) is bytes and inventory_digest.hexdigest(data) == row['current_sha256'], error)
    last = len(data)
    for start, end, old in reversed(row['edits']):
        require(0 <= start <= end <= last, error)
        data = inventory_splice.splice(data, start, end, old)
        last = start
    require(inventory_digest.hexdigest(data) == row['previous_sha256'], error)
    return data


def require_b66_sources(error='mainb66_source_inventory_differs'):
    require_12e_sources(error)
    for path, expected in MAINB66['sources'].items():
        try:
            raw = (ROOT / path).read_bytes()
        except OSError:
            require(False, error)
        raw = source_before_12e(path, raw, error)
        require(inventory_digest.hexdigest(raw) == expected, error)
        if path in MAINB66['methods']:
            found = re.findall(r'#\[test\]\s*((?:#\[[^\n]*\]\s*)*)(?:unsafe\s+)?fn\s+(\w+)\s*\(', raw.decode())
            row = MAINB66['methods'][path]
            require([name for _, name in found] == row['all'] and
                    [name for attrs, name in found if re.search(r'#\[ignore(?:\]|\s*=)', attrs)] == row['ignored'] and
                    raw.count(b'#[test]') == len(found), error)
        if path in MAINB66['module_chains']:
            require(all(raw.decode().count(literal) == 1 for literal in MAINB66['module_chains'][path]), error)
        if path in MAINB66['python_methods']:
            found = list(inventory_syntax.identities(raw.decode()))
            require(found == MAINB66['python_methods'][path], error)


def before_b66(declared, error='mainb66_inventory_differs', source_error='mainb66_source_inventory_differs'):
    declared = peel_12e(declared, error, source_error)
    require(type(declared) is dict and digest(declared) == CURRENTB66, error)
    require_b66_sources(source_error)
    old = inventory_copy.deepcopy(declared)
    rows = old['harness_test_counts']['workspace_tests']
    for name, change in MAINB66['workspace_changes'].items():
        require(rows[name] == change['current'], error)
        rows[name] = inventory_copy.deepcopy(change['previous'])
    require(digest(old) == MAINB66['previous_corpus_sha256'] == CURRENT469, error)
    return old


def peel_b66(declared, error, source_error):
    declared = peel_12e(declared, error, source_error)
    return before_b66(declared, error, source_error) if type(declared) is dict and digest(declared) == CURRENTB66 else declared


def source_before_469(path, data, error):
    """Only the fixed 469 whole blob may reach its exact historical source."""
    data = source_before_b66(path, data, error)
    if path not in MAIN469['projections']:
        return data
    row = MAIN469['projections'][path]
    require(type(data) is bytes and inventory_digest.hexdigest(data) == row['current_sha256'], error)
    last = len(data)
    for start, end, old in reversed(row['edits']):
        require(0 <= start <= end <= last, error)
        data = inventory_splice.splice(data, start, end, old)
        last = start
    require(inventory_digest.hexdigest(data) == row['previous_sha256'], error)
    return data


def require_469_sources(error='main469_source_inventory_differs'):
    require_b66_sources(error)
    for path, expected in MAIN469['sources'].items():
        try:
            raw = (ROOT / path).read_bytes()
        except OSError:
            require(False, error)
        raw = source_before_b66(path, raw, error)
        require(inventory_digest.hexdigest(raw) == expected, error)
        if path in MAIN469['methods']:
            found = re.findall(r'#\[test\]\s*((?:#\[[^\n]*\]\s*)*)(?:unsafe\s+)?fn\s+(\w+)\s*\(', raw.decode())
            row = MAIN469['methods'][path]
            require([name for _, name in found] == row['all'] and
                    [name for attrs, name in found if re.search(r'#\[ignore(?:\]|\s*=)', attrs)] == row['ignored'] and
                    raw.count(b'#[test]') == len(found), error)
        if path in MAIN469['module_chains']:
            require(all(raw.decode().count(literal) == 1 for literal in MAIN469['module_chains'][path]), error)
        if path in MAIN469['python_methods']:
            found = list(inventory_syntax.identities(raw.decode()))
            require(found == MAIN469['python_methods'][path], error)


def before_469(declared, error='main469_inventory_differs', source_error='main469_source_inventory_differs'):
    declared = peel_b66(declared, error, source_error)
    require(type(declared) is dict and digest(declared) == CURRENT469, error)
    require_469_sources(source_error)
    old = inventory_copy.deepcopy(declared)
    rows = old['harness_test_counts']['workspace_tests']
    for name, change in MAIN469['workspace_changes'].items():
        require(rows[name] == change['current'], error)
        rows[name] = inventory_copy.deepcopy(change['previous'])
    require(digest(old) == MAIN469['previous_corpus_sha256'] == CURRENTE11, error)
    return old


def peel_469(declared, error, source_error):
    declared = peel_b66(declared, error, source_error)
    return before_469(declared, error, source_error) if type(declared) is dict and digest(declared) == CURRENT469 else declared


def source_before_e11(path, data, error):
    """Only the fixed e11 whole blob may reach its exact historical source."""
    data = source_before_469(path, data, error)
    if path not in MAINE11['projections']:
        return data
    row = MAINE11['projections'][path]
    require(type(data) is bytes and inventory_digest.hexdigest(data) == row['current_sha256'], error)
    last = len(data)
    for start, end, old in reversed(row['edits']):
        require(0 <= start <= end <= last, error)
        data = inventory_splice.splice(data, start, end, old)
        last = start
    require(inventory_digest.hexdigest(data) == row['previous_sha256'], error)
    return data


def require_e11_sources(error='maine11_source_inventory_differs'):
    require_469_sources(error)
    for path, expected in MAINE11['sources'].items():
        try:
            raw = (ROOT / path).read_bytes()
        except OSError:
            require(False, error)
        raw = source_before_469(path, raw, error)
        require(inventory_digest.hexdigest(raw) == expected, error)
        if path in MAINE11['methods']:
            found = re.findall(r'#\[test\]\s*((?:#\[[^\n]*\]\s*)*)(?:unsafe\s+)?fn\s+(\w+)\s*\(', raw.decode())
            row = MAINE11['methods'][path]
            require([name for _, name in found] == row['all'] and
                    [name for attrs, name in found if re.search(r'#\[ignore(?:\]|\s*=)', attrs)] == row['ignored'] and
                    raw.count(b'#[test]') == len(found), error)
        if path in MAINE11['module_chains']:
            require(all(raw.decode().count(literal) == 1 for literal in MAINE11['module_chains'][path]), error)
        if path in MAINE11['python_methods']:
            found = list(inventory_syntax.identities(raw.decode()))
            require(found == MAINE11['python_methods'][path], error)


def before_e11(declared, error='maine11_inventory_differs', source_error='maine11_source_inventory_differs'):
    declared = peel_469(declared, error, source_error)
    require(type(declared) is dict and digest(declared) == CURRENTE11, error)
    require_e11_sources(source_error)
    old = inventory_copy.deepcopy(declared)
    rows = old['harness_test_counts']['workspace_tests']
    for name, change in MAINE11['workspace_changes'].items():
        require(rows[name] == change['current'], error)
        rows[name] = inventory_copy.deepcopy(change['previous'])
    require(digest(old) == MAINE11['previous_corpus_sha256'] == CURRENT0A088, error)
    return old


def peel_e11(declared, error, source_error):
    declared = peel_469(declared, error, source_error)
    return before_e11(declared, error, source_error) if type(declared) is dict and digest(declared) == CURRENTE11 else declared


def source_before_0a088(path, data, error):
    """Only the fixed 0a088 whole blob may reach its exact historical source."""
    data = source_before_e11(path, data, error)
    if path not in MAIN0A088['projections']:
        return data
    row = MAIN0A088['projections'][path]
    require(type(data) is bytes and inventory_digest.hexdigest(data) == row['current_sha256'], error)
    last = len(data)
    for start, end, old in reversed(row['edits']):
        require(0 <= start <= end <= last, error)
        data = inventory_splice.splice(data, start, end, old)
        last = start
    require(inventory_digest.hexdigest(data) == row['previous_sha256'], error)
    return data


def require_0a088_sources(error='main0a088_source_inventory_differs'):
    require_e11_sources(error)
    for path, expected in MAIN0A088['sources'].items():
        try:
            raw = (ROOT / path).read_bytes()
        except OSError:
            require(False, error)
        raw = source_before_e11(path, raw, error)
        require(inventory_digest.hexdigest(raw) == expected, error)
        if path in MAIN0A088['methods']:
            found = re.findall(r'#\[test\]\s*((?:#\[[^\n]*\]\s*)*)(?:unsafe\s+)?fn\s+(\w+)\s*\(', raw.decode())
            row = MAIN0A088['methods'][path]
            require([name for _, name in found] == row['all'] and
                    [name for attrs, name in found if re.search(r'#\[ignore(?:\]|\s*=)', attrs)] == row['ignored'] and
                    raw.count(b'#[test]') == len(found), error)
        if path in MAIN0A088['module_chains']:
            require(all(raw.decode().count(literal) == 1 for literal in MAIN0A088['module_chains'][path]), error)
        if path in MAIN0A088['python_methods']:
            found = list(inventory_syntax.identities(raw.decode()))
            require(found == MAIN0A088['python_methods'][path], error)


def before_0a088(declared, error='main0a088_inventory_differs', source_error='main0a088_source_inventory_differs'):
    declared = peel_e11(declared, error, source_error)
    require(type(declared) is dict and digest(declared) == CURRENT0A088, error)
    require_0a088_sources(source_error)
    old = inventory_copy.deepcopy(declared)
    rows = old['harness_test_counts']['workspace_tests']
    for name, change in MAIN0A088['workspace_changes'].items():
        require(rows[name] == change['current'], error)
        rows[name] = inventory_copy.deepcopy(change['previous'])
    require(digest(old) == MAIN0A088['previous_corpus_sha256'] == CURRENT9C70, error)
    return old


def peel_0a088(declared, error, source_error):
    declared = peel_e11(declared, error, source_error)
    return before_0a088(declared, error, source_error) if type(declared) is dict and digest(declared) == CURRENT0A088 else declared


def source_before_9c70(path, data, error):
    """Only the fixed 9c70 whole blob may reach its exact historical source."""
    data = source_before_0a088(path, data, error)
    if path not in MAIN9C70['projections']:
        return data
    row = MAIN9C70['projections'][path]
    require(type(data) is bytes and inventory_digest.hexdigest(data) == row['current_sha256'], error)
    last = len(data)
    for start, end, old in reversed(row['edits']):
        require(0 <= start <= end <= last, error)
        data = inventory_splice.splice(data, start, end, old)
        last = start
    require(inventory_digest.hexdigest(data) == row['previous_sha256'], error)
    return data


def require_9c70_sources(error='main9c70_source_inventory_differs'):
    require_0a088_sources(error)
    for path, expected in MAIN9C70['sources'].items():
        try:
            raw = (ROOT / path).read_bytes()
        except OSError:
            require(False, error)
        raw = source_before_0a088(path, raw, error)
        require(inventory_digest.hexdigest(raw) == expected, error)
        if path in MAIN9C70['methods']:
            found = re.findall(r'#\[test\]\s*((?:#\[[^\n]*\]\s*)*)(?:unsafe\s+)?fn\s+(\w+)\s*\(', raw.decode())
            row = MAIN9C70['methods'][path]
            require([name for _, name in found] == row['all'] and
                    [name for attrs, name in found if re.search(r'#\[ignore(?:\]|\s*=)', attrs)] == row['ignored'] and
                    raw.count(b'#[test]') == len(found), error)
        if path in MAIN9C70['module_chains']:
            require(all(raw.decode().count(literal) == 1 for literal in MAIN9C70['module_chains'][path]), error)
        if path in MAIN9C70['python_methods']:
            found = list(inventory_syntax.identities(raw.decode()))
            require(found == MAIN9C70['python_methods'][path], error)


def before_9c70(declared, error='main9c70_inventory_differs', source_error='main9c70_source_inventory_differs'):
    declared = peel_0a088(declared, error, source_error)
    require(type(declared) is dict and digest(declared) == CURRENT9C70, error)
    require_9c70_sources(source_error)
    old = inventory_copy.deepcopy(declared)
    rows = old['harness_test_counts']['workspace_tests']
    for name, change in MAIN9C70['workspace_changes'].items():
        require(rows[name] == change['current'], error)
        rows[name] = inventory_copy.deepcopy(change['previous'])
    require(digest(old) == MAIN9C70['previous_corpus_sha256'] == CURRENT2754, error)
    return old


def peel_9c70(declared, error, source_error):
    declared = peel_0a088(declared, error, source_error)
    return before_9c70(declared, error, source_error) if type(declared) is dict and digest(declared) == CURRENT9C70 else declared


def source_before_2754(path, data, error):
    """Only the fixed 2754 whole blob may reach its exact historical source."""
    data = source_before_9c70(path, data, error)
    if path not in MAIN2754['projections']:
        return data
    row = MAIN2754['projections'][path]
    require(type(data) is bytes and inventory_digest.hexdigest(data) == row['current_sha256'], error)
    last = len(data)
    for start, end, old in reversed(row['edits']):
        require(0 <= start <= end <= last, error)
        data = inventory_splice.splice(data, start, end, old)
        last = start
    require(inventory_digest.hexdigest(data) == row['previous_sha256'], error)
    return data


def require_2754_sources(error='main2754_source_inventory_differs'):
    require_9c70_sources(error)
    for path, expected in MAIN2754['sources'].items():
        try:
            raw = (ROOT / path).read_bytes()
        except OSError:
            require(False, error)
        raw = source_before_9c70(path, raw, error)
        require(inventory_digest.hexdigest(raw) == expected, error)
        if path in MAIN2754['methods']:
            found = re.findall(r'#\[test\]\s*((?:#\[[^\n]*\]\s*)*)(?:unsafe\s+)?fn\s+(\w+)\s*\(', raw.decode())
            row = MAIN2754['methods'][path]
            require([name for _, name in found] == row['all'] and
                    [name for attrs, name in found if re.search(r'#\[ignore(?:\]|\s*=)', attrs)] == row['ignored'] and
                    raw.count(b'#[test]') == len(found), error)
        if path in MAIN2754['module_chains']:
            require(all(raw.decode().count(literal) == 1 for literal in MAIN2754['module_chains'][path]), error)
        if path in MAIN2754['python_methods']:
            found = list(inventory_syntax.identities(raw.decode()))
            require(found == MAIN2754['python_methods'][path], error)


def before_2754(declared, error='main2754_inventory_differs', source_error='main2754_source_inventory_differs'):
    declared = peel_9c70(declared, error, source_error)
    require(type(declared) is dict and digest(declared) == CURRENT2754, error)
    require_2754_sources(source_error)
    old = inventory_copy.deepcopy(declared)
    rows = old['harness_test_counts']['workspace_tests']
    for name, change in MAIN2754['workspace_changes'].items():
        require(rows[name] == change['current'], error)
        rows[name] = inventory_copy.deepcopy(change['previous'])
    require(digest(old) == MAIN2754['previous_corpus_sha256'] == CURRENT9950, error)
    return old


def peel_2754(declared, error, source_error):
    declared = peel_9c70(declared, error, source_error)
    return before_2754(declared, error, source_error) if type(declared) is dict and digest(declared) == CURRENT2754 else declared


def source_before_9950(path, data, error):
    """Only the fixed 9950 whole blob may reach its exact historical source."""
    data = source_before_2754(path, data, error)
    if path not in MAIN9950['projections']:
        return data
    row = MAIN9950['projections'][path]
    require(type(data) is bytes and inventory_digest.hexdigest(data) == row['current_sha256'], error)
    last = len(data)
    for start, end, old in reversed(row['edits']):
        require(0 <= start <= end <= last, error)
        data = inventory_splice.splice(data, start, end, old)
        last = start
    require(inventory_digest.hexdigest(data) == row['previous_sha256'], error)
    return data


def require_9950_sources(error='main9950_source_inventory_differs'):
    require_2754_sources(error)
    for path, expected in MAIN9950['sources'].items():
        try:
            raw = (ROOT / path).read_bytes()
        except OSError:
            require(False, error)
        raw = source_before_2754(path, raw, error)
        require(inventory_digest.hexdigest(raw) == expected, error)
        if path in MAIN9950['methods']:
            found = re.findall(r'#\[test\]\s*((?:#\[[^\n]*\]\s*)*)(?:unsafe\s+)?fn\s+(\w+)\s*\(', raw.decode())
            row = MAIN9950['methods'][path]
            require([name for _, name in found] == row['all'] and
                    [name for attrs, name in found if re.search(r'#\[ignore(?:\]|\s*=)', attrs)] == row['ignored'] and
                    raw.count(b'#[test]') == len(found), error)
        if path in MAIN9950['module_chains']:
            require(all(raw.decode().count(literal) == 1 for literal in MAIN9950['module_chains'][path]), error)
        if path in MAIN9950['python_methods']:
            found = list(inventory_syntax.identities(raw.decode()))
            require(found == MAIN9950['python_methods'][path], error)


def before_9950(declared, error='main9950_inventory_differs', source_error='main9950_source_inventory_differs'):
    declared = peel_2754(declared, error, source_error)
    require(type(declared) is dict and digest(declared) == CURRENT9950, error)
    require_9950_sources(source_error)
    old = inventory_copy.deepcopy(declared)
    rows = old['harness_test_counts']['workspace_tests']
    for name, change in MAIN9950['workspace_changes'].items():
        require(rows[name] == change['current'], error)
        rows[name] = inventory_copy.deepcopy(change['previous'])
    require(digest(old) == MAIN9950['previous_corpus_sha256'] == CURRENT5A0, error)
    return old


def peel_9950(declared, error, source_error):
    declared = peel_2754(declared, error, source_error)
    return before_9950(declared, error, source_error) if type(declared) is dict and digest(declared) == CURRENT9950 else declared


def source_before_5a0(path, data, error):
    """Only the fixed 5a0 whole blob may reach its exact historical source."""
    data = source_before_9950(path, data, error)
    if path not in MAIN5A0['projections']:
        return data
    row = MAIN5A0['projections'][path]
    require(type(data) is bytes and inventory_digest.hexdigest(data) == row['current_sha256'], error)
    last = len(data)
    for start, end, old in reversed(row['edits']):
        require(0 <= start <= end <= last, error)
        data = inventory_splice.splice(data, start, end, old)
        last = start
    require(inventory_digest.hexdigest(data) == row['previous_sha256'], error)
    return data


def require_5a0_sources(error='main5a0_source_inventory_differs'):
    require_9950_sources(error)
    for path, expected in MAIN5A0['sources'].items():
        try:
            raw = (ROOT / path).read_bytes()
        except OSError:
            require(False, error)
        raw = source_before_9950(path, raw, error)
        require(inventory_digest.hexdigest(raw) == expected, error)
        if path in MAIN5A0['methods']:
            found = re.findall(r'#\[test\]\s*((?:#\[[^\n]*\]\s*)*)(?:unsafe\s+)?fn\s+(\w+)\s*\(', raw.decode())
            row = MAIN5A0['methods'][path]
            require([name for _, name in found] == row['all'] and
                    [name for attrs, name in found if re.search(r'#\[ignore(?:\]|\s*=)', attrs)] == row['ignored'] and
                    raw.count(b'#[test]') == len(found), error)
        if path in MAIN5A0['module_chains']:
            require(all(raw.decode().count(literal) == 1 for literal in MAIN5A0['module_chains'][path]), error)
        if path in MAIN5A0['python_methods']:
            found = list(inventory_syntax.identities(raw.decode()))
            require(found == MAIN5A0['python_methods'][path], error)


def before_5a0(declared, error='main5a0_inventory_differs', source_error='main5a0_source_inventory_differs'):
    declared = peel_9950(declared, error, source_error)
    require(type(declared) is dict and digest(declared) == CURRENT5A0, error)
    require_5a0_sources(source_error)
    old = inventory_copy.deepcopy(declared)
    rows = old['harness_test_counts']['workspace_tests']
    for name, change in MAIN5A0['workspace_changes'].items():
        require(rows[name] == change['current'], error)
        rows[name] = inventory_copy.deepcopy(change['previous'])
    require(digest(old) == MAIN5A0['previous_corpus_sha256'] == CURRENT850, error)
    return old


def peel_5a0(declared, error, source_error):
    declared = peel_9950(declared, error, source_error)
    return before_5a0(declared, error, source_error) if type(declared) is dict and digest(declared) == CURRENT5A0 else declared


def source_before_850(path, data, error):
    """Only the fixed 850 whole blob may reach its exact historical source."""
    data = source_before_5a0(path, data, error)
    if path not in MAIN850['projections']:
        return data
    row = MAIN850['projections'][path]
    require(type(data) is bytes and inventory_digest.hexdigest(data) == row['current_sha256'], error)
    last = len(data)
    for start, end, old in reversed(row['edits']):
        require(0 <= start <= end <= last, error)
        data = inventory_splice.splice(data, start, end, old)
        last = start
    require(inventory_digest.hexdigest(data) == row['previous_sha256'], error)
    return data


def require_850_sources(error='main850_source_inventory_differs'):
    require_5a0_sources(error)
    for path, expected in MAIN850['sources'].items():
        try:
            raw = (ROOT / path).read_bytes()
        except OSError:
            require(False, error)
        raw = source_before_5a0(path, raw, error)
        require(inventory_digest.hexdigest(raw) == expected, error)
        if path in MAIN850['methods']:
            found = re.findall(r'#\[test\]\s*((?:#\[[^\n]*\]\s*)*)(?:unsafe\s+)?fn\s+(\w+)\s*\(', raw.decode())
            row = MAIN850['methods'][path]
            require([name for _, name in found] == row['all'] and
                    [name for attrs, name in found if re.search(r'#\[ignore(?:\]|\s*=)', attrs)] == row['ignored'] and
                    raw.count(b'#[test]') == len(found), error)
        if path in MAIN850['module_chains']:
            require(all(raw.decode().count(literal) == 1 for literal in MAIN850['module_chains'][path]), error)
        if path in MAIN850['python_methods']:
            found = list(inventory_syntax.identities(raw.decode()))
            require(found == MAIN850['python_methods'][path], error)


def before_850(declared, error='main850_inventory_differs', source_error='main850_source_inventory_differs'):
    declared = peel_5a0(declared, error, source_error)
    require(type(declared) is dict and digest(declared) == CURRENT850, error)
    require_850_sources(source_error)
    old = inventory_copy.deepcopy(declared)
    rows = old['harness_test_counts']['workspace_tests']
    for name, change in MAIN850['workspace_changes'].items():
        require(rows[name] == change['current'], error)
        rows[name] = inventory_copy.deepcopy(change['previous'])
    require(digest(old) == MAIN850['previous_corpus_sha256'] == CURRENT83B, error)
    return old


def peel_850(declared, error, source_error):
    declared = peel_5a0(declared, error, source_error)
    return before_850(declared, error, source_error) if type(declared) is dict and digest(declared) == CURRENT850 else declared


def source_before_83b(path, data, error):
    """Only the fixed 83b whole blob may reach its exact historical source."""
    data = source_before_850(path, data, error)
    if path not in MAIN83B['projections']:
        return data
    row = MAIN83B['projections'][path]
    require(type(data) is bytes and inventory_digest.hexdigest(data) == row['current_sha256'], error)
    last = len(data)
    for start, end, old in reversed(row['edits']):
        require(0 <= start <= end <= last, error)
        data = inventory_splice.splice(data, start, end, old)
        last = start
    require(inventory_digest.hexdigest(data) == row['previous_sha256'], error)
    return data


def require_83b_sources(error='main83b_source_inventory_differs'):
    require_850_sources(error)
    for path, expected in MAIN83B['sources'].items():
        try:
            raw = (ROOT / path).read_bytes()
        except OSError:
            require(False, error)
        raw = source_before_850(path, raw, error)
        require(inventory_digest.hexdigest(raw) == expected, error)
        if path in MAIN83B['methods']:
            found = re.findall(r'#\[test\]\s*((?:#\[[^\n]*\]\s*)*)(?:unsafe\s+)?fn\s+(\w+)\s*\(', raw.decode())
            row = MAIN83B['methods'][path]
            require([name for _, name in found] == row['all'] and
                    [name for attrs, name in found if re.search(r'#\[ignore(?:\]|\s*=)', attrs)] == row['ignored'] and
                    raw.count(b'#[test]') == len(found) + MAIN83B['macros'].get(path, {}).get('test_attributes', 0), error)

    for path, row in MAIN83B['macros'].items():
        raw = source_before_850(path, (ROOT / path).read_bytes(), error)
        require(raw.decode().count(row['literal']) == 1, error)
    for path, rows in MAIN83B['doctests'].items():
        lines = source_before_850(path, (ROOT / path).read_bytes(), error).decode().splitlines()
        for row in rows:
            require(lines[row['line'] - 1].strip() == row['marker'] + ' ```' + row['attributes'], error)
    metadata = MAIN83B['python_metadata']
    raw = source_before_850(metadata['path'], (ROOT / metadata['path']).read_bytes(), error)
    require(inventory_digest.hexdigest(raw) == MAIN83B['sources'][metadata['path']], error)
    require(len(metadata['assignment_sources']) == len(metadata['assignments']) == 5, error)
    snippets = []
    for start, end, literal in metadata['assignment_sources']:
        require(0 <= start <= end <= len(raw) and raw[start:end] == literal.encode(), error)
        snippets.append(literal)
    tree = ast.parse('\n'.join(snippets))
    for name, expected in metadata['assignments'].items():
        values = [ast.literal_eval(node.value) for node in tree.body if isinstance(node, ast.Assign)
                  and any(isinstance(target, ast.Name) and target.id == name for target in node.targets)]
        if name in metadata['tuple_assignments']:
            expected = tuple(expected)
        require(values == [expected], error)
    for path, facts in metadata['qualification_facts'].items():
        raw = source_before_850(path, (ROOT / path).read_bytes(), error).decode()
        require(all(raw.count(literal) == 1 for literal in facts), error)


def before_83b(declared, error='main83b_inventory_differs', source_error='main83b_source_inventory_differs'):
    declared = peel_850(declared, error, source_error)
    require(type(declared) is dict and digest(declared) == CURRENT83B, error)
    require_83b_sources(source_error)
    old = inventory_copy.deepcopy(declared)
    rows = old['harness_test_counts']['workspace_tests']
    for name, change in MAIN83B['workspace_changes'].items():
        require(rows[name] == change['current'], error)
        if change['previous'] is None:
            del rows[name]
        else:
            rows[name] = inventory_copy.deepcopy(change['previous'])
    require(digest(old) == MAIN83B['previous_corpus_sha256'] == CURRENTABAB, error)
    return old


def peel_83b(declared, error, source_error):
    declared = peel_850(declared, error, source_error)
    return before_83b(declared, error, source_error) if type(declared) is dict and digest(declared) == CURRENT83B else declared


def source_before_abab(path, data, error):
    """Only the fixed abab whole blob may reach its exact historical source."""
    data = source_before_83b(path, data, error)
    if path not in MAINABAB['projections']:
        return data
    row = MAINABAB['projections'][path]
    require(type(data) is bytes and inventory_digest.hexdigest(data) == row['current_sha256'], error)
    last = len(data)
    for start, end, old in reversed(row['edits']):
        require(0 <= start <= end <= last, error)
        data = inventory_splice.splice(data, start, end, old)
        last = start
    require(inventory_digest.hexdigest(data) == row['previous_sha256'], error)
    return data


def require_abab_sources(error='mainabab_source_inventory_differs'):
    require_83b_sources(error)
    for path, expected in MAINABAB['sources'].items():
        try:
            raw = (ROOT / path).read_bytes()
        except OSError:
            require(False, error)
        raw = source_before_83b(path, raw, error)
        require(inventory_digest.hexdigest(raw) == expected, error)
        if path in MAINABAB['methods']:
            found = re.findall(r'#\[test\]\s*((?:#\[[^\n]*\]\s*)*)(?:unsafe\s+)?fn\s+(\w+)\s*\(', raw.decode())
            row = MAINABAB['methods'][path]
            require([name for _, name in found] == row['all'] and
                    [name for attrs, name in found if re.search(r'#\[ignore(?:\]|\s*=)', attrs)] == row['ignored'] and
                    raw.count(b'#[test]') == len(found) + MAINABAB['macros'].get(path, {}).get('test_attributes', 0), error)

    for path, row in MAINABAB['macros'].items():
        raw = source_before_83b(path, (ROOT / path).read_bytes(), error)
        require(raw.decode().count(row['literal']) == 1, error)
    for path, rows in MAINABAB['doctests'].items():
        lines = source_before_83b(path, (ROOT / path).read_bytes(), error).decode().splitlines()
        for row in rows:
            require(lines[row['line'] - 1].strip() == row['marker'] + ' ```' + row['attributes'], error)
    metadata = MAINABAB['python_metadata']
    raw = source_before_83b(metadata['path'], (ROOT / metadata['path']).read_bytes(), error)
    require(inventory_digest.hexdigest(raw) == MAINABAB['sources'][metadata['path']], error)
    require(len(metadata['assignment_sources']) == len(metadata['assignments']) == 5, error)
    snippets = []
    for start, end, literal in metadata['assignment_sources']:
        require(0 <= start <= end <= len(raw) and raw[start:end] == literal.encode(), error)
        snippets.append(literal)
    tree = ast.parse('\n'.join(snippets))
    for name, expected in metadata['assignments'].items():
        values = [ast.literal_eval(node.value) for node in tree.body if isinstance(node, ast.Assign)
                  and any(isinstance(target, ast.Name) and target.id == name for target in node.targets)]
        if name in metadata['tuple_assignments']:
            expected = tuple(expected)
        require(values == [expected], error)
    for path, facts in metadata['qualification_facts'].items():
        raw = source_before_83b(path, (ROOT / path).read_bytes(), error).decode()
        require(all(raw.count(literal) == 1 for literal in facts), error)


def before_abab(declared, error='mainabab_inventory_differs', source_error='mainabab_source_inventory_differs'):
    declared = peel_83b(declared, error, source_error)
    require(type(declared) is dict and digest(declared) == CURRENTABAB, error)
    require_abab_sources(source_error)
    old = inventory_copy.deepcopy(declared)
    rows = old['harness_test_counts']['workspace_tests']
    for name, change in MAINABAB['workspace_changes'].items():
        require(rows[name] == change['current'], error)
        if change['previous'] is None:
            del rows[name]
        else:
            rows[name] = inventory_copy.deepcopy(change['previous'])
    require(digest(old) == MAINABAB['previous_corpus_sha256'] == CURRENT727, error)
    return old


def peel_abab(declared, error, source_error):
    declared = peel_83b(declared, error, source_error)
    return before_abab(declared, error, source_error) if type(declared) is dict and digest(declared) == CURRENTABAB else declared


def source_before_727(path, data, error):
    """Only the fixed 727 whole blob may reach its exact historical source."""
    data = source_before_abab(path, data, error)
    if path not in MAIN727['projections']:
        return data
    row = MAIN727['projections'][path]
    require(type(data) is bytes and inventory_digest.hexdigest(data) == row['current_sha256'], error)
    last = len(data)
    for start, end, old in reversed(row['edits']):
        require(0 <= start <= end <= last, error)
        data = inventory_splice.splice(data, start, end, old)
        last = start
    require(inventory_digest.hexdigest(data) == row['previous_sha256'], error)
    return data


def require_727_sources(error='main727_source_inventory_differs'):
    require_abab_sources(error)
    for path, expected in MAIN727['sources'].items():
        try:
            raw = (ROOT / path).read_bytes()
        except OSError:
            require(False, error)
        raw = source_before_abab(path, raw, error)
        require(inventory_digest.hexdigest(raw) == expected, error)
        if path in MAIN727['methods']:
            found = re.findall(r'#\[test\]\s*((?:#\[[^\n]*\]\s*)*)(?:unsafe\s+)?fn\s+(\w+)\s*\(', raw.decode())
            row = MAIN727['methods'][path]
            require([name for _, name in found] == row['all'] and
                    [name for attrs, name in found if re.search(r'#\[ignore(?:\]|\s*=)', attrs)] == row['ignored'] and
                    raw.count(b'#[test]') == len(found) + MAIN727['macros'].get(path, {}).get('test_attributes', 0), error)

    for path, row in MAIN727['macros'].items():
        raw = source_before_abab(path, (ROOT / path).read_bytes(), error)
        require(raw.decode().count(row['literal']) == 1, error)
    for path, rows in MAIN727['doctests'].items():
        lines = source_before_abab(path, (ROOT / path).read_bytes(), error).decode().splitlines()
        for row in rows:
            require(lines[row['line'] - 1].strip() == row['marker'] + ' ```' + row['attributes'], error)
    metadata = MAIN727['python_metadata']
    raw = source_before_abab(metadata['path'], (ROOT / metadata['path']).read_bytes(), error)
    require(inventory_digest.hexdigest(raw) == MAIN727['sources'][metadata['path']], error)
    require(len(metadata['assignment_sources']) == len(metadata['assignments']) == 5, error)
    snippets = []
    for start, end, literal in metadata['assignment_sources']:
        require(0 <= start <= end <= len(raw) and raw[start:end] == literal.encode(), error)
        snippets.append(literal)
    tree = ast.parse('\n'.join(snippets))
    for name, expected in metadata['assignments'].items():
        values = [ast.literal_eval(node.value) for node in tree.body if isinstance(node, ast.Assign)
                  and any(isinstance(target, ast.Name) and target.id == name for target in node.targets)]
        if name in metadata['tuple_assignments']:
            expected = tuple(expected)
        require(values == [expected], error)
    for path, facts in metadata['qualification_facts'].items():
        raw = source_before_abab(path, (ROOT / path).read_bytes(), error).decode()
        require(all(raw.count(literal) == 1 for literal in facts), error)


def before_727(declared, error='main727_inventory_differs', source_error='main727_source_inventory_differs'):
    declared = peel_abab(declared, error, source_error)
    require(type(declared) is dict and digest(declared) == CURRENT727, error)
    require_727_sources(source_error)
    old = inventory_copy.deepcopy(declared)
    rows = old['harness_test_counts']['workspace_tests']
    for name, change in MAIN727['workspace_changes'].items():
        require(rows[name] == change['current'], error)
        if change['previous'] is None:
            del rows[name]
        else:
            rows[name] = inventory_copy.deepcopy(change['previous'])
    require(digest(old) == MAIN727['previous_corpus_sha256'] == CURRENT09FE, error)
    return old


def peel_727(declared, error, source_error):
    declared = peel_abab(declared, error, source_error)
    return before_727(declared, error, source_error) if type(declared) is dict and digest(declared) == CURRENT727 else declared


def source_before_09fe(path, data, error):
    """Only the fixed 09fe whole blob may reach its exact historical source."""
    data = source_before_727(path, data, error)
    if path not in MAIN09FE['projections']:
        return data
    row = MAIN09FE['projections'][path]
    require(type(data) is bytes and inventory_digest.hexdigest(data) == row['current_sha256'], error)
    last = len(data)
    for start, end, old in reversed(row['edits']):
        require(0 <= start <= end <= last, error)
        data = inventory_splice.splice(data, start, end, old)
        last = start
    require(inventory_digest.hexdigest(data) == row['previous_sha256'], error)
    return data


def require_09fe_sources(error='main09fe_source_inventory_differs'):
    require_727_sources(error)
    for path, expected in MAIN09FE['sources'].items():
        try:
            raw = (ROOT / path).read_bytes()
        except OSError:
            require(False, error)
        raw = source_before_727(path, raw, error)
        require(inventory_digest.hexdigest(raw) == expected, error)
        if path in MAIN09FE['methods']:
            found = re.findall(r'#\[test\]\s*((?:#\[[^\n]*\]\s*)*)(?:unsafe\s+)?fn\s+(\w+)\s*\(', raw.decode())
            row = MAIN09FE['methods'][path]
            require([name for _, name in found] == row['all'] and
                    [name for attrs, name in found if re.search(r'#\[ignore(?:\]|\s*=)', attrs)] == row['ignored'] and
                    raw.count(b'#[test]') == len(found) + MAIN09FE['macros'].get(path, {}).get('test_attributes', 0), error)

    for path, row in MAIN09FE['macros'].items():
        raw = source_before_727(path, (ROOT / path).read_bytes(), error)
        require(raw.decode().count(row['literal']) == 1, error)
    for path, rows in MAIN09FE['doctests'].items():
        lines = source_before_727(path, (ROOT / path).read_bytes(), error).decode().splitlines()
        for row in rows:
            require(lines[row['line'] - 1].strip() == row['marker'] + ' ```' + row['attributes'], error)
    metadata = MAIN09FE['python_metadata']
    assignment_sources = inventory_syntax.assignments(source_before_727(metadata['path'], (ROOT / metadata['path']).read_bytes(), error))
    for name, expected in metadata['assignments'].items():
        values = inventory_syntax.literal_values(assignment_sources, name)
        if name in metadata['tuple_assignments']:
            expected = tuple(expected)
        require(values == [expected], error)
    for path, facts in metadata['qualification_facts'].items():
        raw = source_before_727(path, (ROOT / path).read_bytes(), error).decode()
        require(all(raw.count(literal) == 1 for literal in facts), error)


def before_09fe(declared, error='main09fe_inventory_differs', source_error='main09fe_source_inventory_differs'):
    declared = peel_727(declared, error, source_error)
    require(type(declared) is dict and digest(declared) == CURRENT09FE, error)
    require_09fe_sources(source_error)
    old = inventory_copy.deepcopy(declared)
    rows = old['harness_test_counts']['workspace_tests']
    for name, change in MAIN09FE['workspace_changes'].items():
        require(rows[name] == change['current'], error)
        if change['previous'] is None:
            del rows[name]
        else:
            rows[name] = inventory_copy.deepcopy(change['previous'])
    require(digest(old) == MAIN09FE['previous_corpus_sha256'] == CURRENT0A8, error)
    return old


def peel_09fe(declared, error, source_error):
    declared = peel_727(declared, error, source_error)
    return before_09fe(declared, error, source_error) if type(declared) is dict and digest(declared) == CURRENT09FE else declared


def source_before_0a8(path, data, error):
    """Only the fixed 0a8 whole blob may reach its exact historical source."""
    data = source_before_09fe(path, data, error)
    if path not in MAIN0A8['projections']:
        return data
    row = MAIN0A8['projections'][path]
    require(type(data) is bytes and inventory_digest.hexdigest(data) == row['current_sha256'], error)
    last = len(data)
    for start, end, old in reversed(row['edits']):
        require(0 <= start <= end <= last, error)
        data = inventory_splice.splice(data, start, end, old)
        last = start
    require(inventory_digest.hexdigest(data) == row['previous_sha256'], error)
    return data


def require_0a8_sources(error='main0a8_source_inventory_differs'):
    require_09fe_sources(error)
    for path, expected in MAIN0A8['sources'].items():
        try:
            raw = (ROOT / path).read_bytes()
        except OSError:
            require(False, error)
        raw = source_before_09fe(path, raw, error)
        require(inventory_digest.hexdigest(raw) == expected, error)
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
    assignment_sources = inventory_syntax.assignments(source_before_09fe(metadata['path'], (ROOT / metadata['path']).read_bytes(), error))
    for name, expected in metadata['assignments'].items():
        values = inventory_syntax.literal_values(assignment_sources, name)
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
    old = inventory_copy.deepcopy(declared)
    rows = old['harness_test_counts']['workspace_tests']
    for name, change in MAIN0A8['workspace_changes'].items():
        require(rows[name] == change['current'], error)
        if change['previous'] is None:
            del rows[name]
        else:
            rows[name] = inventory_copy.deepcopy(change['previous'])
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
    require(type(data) is bytes and inventory_digest.hexdigest(data) == row['current_sha256'], error)
    last = len(data)
    for start, end, old in reversed(row['edits']):
        require(0 <= start <= end <= last, error)
        data = inventory_splice.splice(data, start, end, old)
        last = start
    require(inventory_digest.hexdigest(data) == row['previous_sha256'], error)
    return data


def require_0df8_sources(error='main0df8_source_inventory_differs'):
    require_0a8_sources(error)
    for path, expected in MAIN0DF8['sources'].items():
        try:
            raw = (ROOT / path).read_bytes()
        except OSError:
            require(False, error)
        raw = source_before_0a8(path, raw, error)
        require(inventory_digest.hexdigest(raw) == expected, error)
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
    assignment_sources = inventory_syntax.assignments(source_before_0a8(metadata['path'], (ROOT / metadata['path']).read_bytes(), error))
    for name, expected in metadata['assignments'].items():
        values = inventory_syntax.literal_values(assignment_sources, name)
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
    old = inventory_copy.deepcopy(declared)
    rows = old['harness_test_counts']['workspace_tests']
    for name, change in MAIN0DF8['workspace_changes'].items():
        require(rows[name] == change['current'], error)
        if change['previous'] is None:
            del rows[name]
        else:
            rows[name] = inventory_copy.deepcopy(change['previous'])
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
    require(type(data) is bytes and inventory_digest.hexdigest(data) == row['current_sha256'], error)
    last = len(data)
    for start, end, old in reversed(row['edits']):
        require(0 <= start <= end <= last, error)
        data = inventory_splice.splice(data, start, end, old)
        last = start
    require(inventory_digest.hexdigest(data) == row['previous_sha256'], error)
    return data


def require_43d7_sources(error='main43d7_source_inventory_differs'):
    require_0df8_sources(error)
    for path, expected in MAIN43D7['sources'].items():
        try:
            raw = (ROOT / path).read_bytes()
        except OSError:
            require(False, error)
        raw = source_before_0df8(path, raw, error)
        require(inventory_digest.hexdigest(raw) == expected, error)
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
    assignment_sources = inventory_syntax.assignments(source_before_0df8(metadata['path'], (ROOT / metadata['path']).read_bytes(), error))
    for name, expected in metadata['assignments'].items():
        values = inventory_syntax.literal_values(assignment_sources, name)
        require(values == [expected], error)
    for path, facts in metadata['qualification_facts'].items():
        raw = source_before_0df8(path, (ROOT / path).read_bytes(), error).decode()
        require(all(raw.count(literal) == 1 for literal in facts), error)


def before_43d7(declared, error='main43d7_inventory_differs', source_error='main43d7_source_inventory_differs'):
    declared = peel_0df8(declared, error, source_error)
    require(type(declared) is dict and digest(declared) == CURRENT43D7, error)
    require_43d7_sources(source_error)
    old = inventory_copy.deepcopy(declared)
    rows = old['harness_test_counts']['workspace_tests']
    for name, change in MAIN43D7['workspace_changes'].items():
        require(rows[name] == change['current'], error)
        if change['previous'] is None:
            del rows[name]
        else:
            rows[name] = inventory_copy.deepcopy(change['previous'])
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
    require(type(data) is bytes and inventory_digest.hexdigest(data) == row['current_sha256'], error)
    last = len(data)
    for start, end, old in reversed(row['edits']):
        require(0 <= start <= end <= last, error)
        data = inventory_splice.splice(data, start, end, old)
        last = start
    require(inventory_digest.hexdigest(data) == row['previous_sha256'], error)
    return data


def require_7cdc_sources(error='main7cdc_source_inventory_differs'):
    require_43d7_sources(error)
    for path, expected in MAIN7CDC['sources'].items():
        try:
            raw = (ROOT / path).read_bytes()
        except OSError:
            require(False, error)
        raw = source_before_43d7(path, raw, error)
        require(inventory_digest.hexdigest(raw) == expected, error)
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
    old = inventory_copy.deepcopy(declared)
    rows = old['harness_test_counts']['workspace_tests']
    for name, change in MAIN7CDC['workspace_changes'].items():
        require(rows[name] == change['current'], error)
        if change['previous'] is None:
            del rows[name]
        else:
            rows[name] = inventory_copy.deepcopy(change['previous'])
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
    require(type(data) is bytes and inventory_digest.hexdigest(data) == row['current_sha256'], error)
    last = len(data)
    for start, end, old in reversed(row['edits']):
        require(0 <= start <= end <= last, error)
        data = inventory_splice.splice(data, start, end, old)
        last = start
    require(inventory_digest.hexdigest(data) == row['previous_sha256'], error)
    return data


def require_f0ef_sources(error='mainf0ef_source_inventory_differs'):
    require_7cdc_sources(error)
    for path, expected in MAINF0EF['sources'].items():
        try:
            raw = (ROOT / path).read_bytes()
        except OSError:
            require(False, error)
        raw = source_before_7cdc(path, raw, error)
        require(inventory_digest.hexdigest(raw) == expected, error)
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
    old = inventory_copy.deepcopy(declared)
    rows = old['harness_test_counts']['workspace_tests']
    for name, change in MAINF0EF['workspace_changes'].items():
        require(rows[name] == change['current'], error)
        if change['previous'] is None:
            del rows[name]
        else:
            rows[name] = inventory_copy.deepcopy(change['previous'])
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
    require(type(data) is bytes and inventory_digest.hexdigest(data) == row['current_sha256'], error)
    last = len(data)
    for start, end, old in reversed(row['edits']):
        require(0 <= start <= end <= last, error)
        data = inventory_splice.splice(data, start, end, old)
        last = start
    require(inventory_digest.hexdigest(data) == row['previous_sha256'], error)
    return data


def require_e797_sources(error='maine797_source_inventory_differs'):
    require_f0ef_sources(error)
    for path, expected in MAINE797['sources'].items():
        try:
            raw = (ROOT / path).read_bytes()
        except OSError:
            require(False, error)
        raw = source_before_f0ef(path, raw, error)
        require(inventory_digest.hexdigest(raw) == expected, error)
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
    old = inventory_copy.deepcopy(declared)
    rows = old['harness_test_counts']['workspace_tests']
    for name, change in MAINE797['workspace_changes'].items():
        require(rows[name] == change['current'], error)
        if change['previous'] is None:
            del rows[name]
        else:
            rows[name] = inventory_copy.deepcopy(change['previous'])
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
    require(type(data) is bytes and inventory_digest.hexdigest(data) == row['current_sha256'], error)
    last = len(data)
    for start, end, old in reversed(row['edits']):
        require(0 <= start <= end <= last, error)
        data = inventory_splice.splice(data, start, end, old)
        last = start
    require(inventory_digest.hexdigest(data) == row['previous_sha256'], error)
    return data


def require_c1_sources(error='mainc1_source_inventory_differs'):
    require_e797_sources(error)
    for path, expected in MAINC1['sources'].items():
        try:
            raw = (ROOT / path).read_bytes()
        except OSError:
            require(False, error)
        raw = source_before_e797(path, raw, error)
        require(inventory_digest.hexdigest(raw) == expected, error)
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
    old = inventory_copy.deepcopy(declared)
    rows = old['harness_test_counts']['workspace_tests']
    for name, change in MAINC1['workspace_changes'].items():
        require(rows[name] == change['current'], error)
        rows[name] = inventory_copy.deepcopy(change['previous'])
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
    require(type(data) is bytes and inventory_digest.hexdigest(data) == row['current_sha256'], error)
    last = len(data)
    for start, end, old in reversed(row['edits']):
        require(0 <= start <= end <= last, error)
        data = inventory_splice.splice(data, start, end, old)
        last = start
    require(inventory_digest.hexdigest(data) == row['previous_sha256'], error)
    return data


def require_c0_sources(error='mainc0_source_inventory_differs'):
    require_c1_sources(error)
    for path, expected in MAINC0['sources'].items():
        try:
            raw = (ROOT / path).read_bytes()
        except OSError:
            require(False, error)
        raw = source_before_c1(path, raw, error)
        require(inventory_digest.hexdigest(raw) == expected, error)
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
    old = inventory_copy.deepcopy(declared)
    rows = old['harness_test_counts']['workspace_tests']
    for name, change in MAINC0['workspace_changes'].items():
        require(rows[name] == change['current'], error)
        rows[name] = inventory_copy.deepcopy(change['previous'])
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
    require(type(data) is bytes and inventory_digest.hexdigest(data) == row['current_sha256'], error)
    last = len(data)
    for start, end, old in reversed(row['edits']):
        require(0 <= start <= end <= last, error)
        data = inventory_splice.splice(data, start, end, old)
        last = start
    require(inventory_digest.hexdigest(data) == row['previous_sha256'], error)
    return data


def require_690_sources(error='main690_source_inventory_differs'):
    require_c0_sources(error)
    for path, expected in MAIN690['sources'].items():
        try:
            raw = (ROOT / path).read_bytes()
        except OSError:
            require(False, error)
        raw = source_before_c0(path, raw, error)
        require(inventory_digest.hexdigest(raw) == expected, error)
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
    old = inventory_copy.deepcopy(declared)
    change = MAIN690['workspace_change']
    rows = old['harness_test_counts']['workspace_tests']
    require(rows[change['identity']] == change['current'], error)
    rows[change['identity']] = inventory_copy.deepcopy(change['previous'])
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
    require(type(data) is bytes and inventory_digest.hexdigest(data) == row['current_sha256'], error)
    last = len(data)
    for start, end, old in reversed(row['edits']):
        require(0 <= start <= end <= last, error)
        data = inventory_splice.splice(data, start, end, old)
        last = start
    require(inventory_digest.hexdigest(data) == row['previous_sha256'], error)
    return data


def require_sources(error='main813_source_inventory_differs'):
    require_690_sources(error)
    for path, expected in DATA['sources'].items():
        try:
            raw = (ROOT / path).read_bytes()
        except OSError:
            require(False, error)
        raw = source_before_690(path, raw, error)
        require(inventory_digest.hexdigest(raw) == expected, error)
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
    old = inventory_copy.deepcopy(declared)
    require(old['recorder_tests'] == RECORDER_TESTS, error)
    old['recorder_tests'] = 345
    require(old.pop('precontext_native_harnesses') == DATA['precontext_inventory'], error)
    rows = old['harness_test_counts']['workspace_tests']
    for name, change in DATA['workspace_changes'].items():
        require(rows[name] == change['current'], error)
        if change['previous'] is None:
            del rows[name]
        else:
            rows[name] = inventory_copy.deepcopy(change['previous'])
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
