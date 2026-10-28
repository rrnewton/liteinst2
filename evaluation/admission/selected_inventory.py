"""Authenticate the four added selected-instruction tests before old projections.

The live validator consumes all ten in-process tests. Historical inventory tests
receive their exact six-test predecessor only after the new whole catalog and
source additions have been authenticated. No execution result is manufactured.
"""
import copy
import hashlib
import json
from pathlib import Path
import re

from parsing import require
from core_cc846_inventory import source_before_cc846
from inline_clock_inventory import peel_current as peel_inline, source_before_inline

PREVIOUS = 'f748315064e4590ee4a2721c97f3b05717d271405d03271f9429bdaf5cc55d25'
CURRENT = '5722a63804e587b2bc6c9b9330e9a610feeedc5838916409d652fc5ea0b76668'
TEST_PATH = 'crates/liteinst-inprocess/src/selected/tests.rs'
METHODS = ('selected_all_decode_width_destination_and_rsp_refusal',
           'selected_all_prefix_legality_and_exact_old_profile',
           'selected_all_supplied_outcomes_preserve_unaffected_state',
           'selected_all_counter_prefix_is_actual_and_never_reset')
# Finalized from the actual formatted sources and Cargo-generated lockfile.
SOURCES = {'Cargo.lock': '5fd8ffbfedaa58242734525342062c5c2dc7924377ae62d6d91408453cfe1f7e',
 'crates/liteinst-inprocess/Cargo.toml': '3e4f957ead1df113d59de515947e86bdbca902e620ab269d713356afc749843b',
 'crates/liteinst-inprocess/src/selected/tests.rs': '7b2f4641929f2ea7ce3ff2848bde98e8e1de59e9db8df0e941218b17b1ba850f'}
PROJECTIONS = {'Cargo.lock': {'current_sha256': '5fd8ffbfedaa58242734525342062c5c2dc7924377ae62d6d91408453cfe1f7e',
                'inverse': [('name = "liteinst-inprocess"\n'
                             'version = "0.1.0"\n'
                             'dependencies = [\n'
                             ' "iced-x86",\n',
                             'name = "liteinst-inprocess"\n'
                             'version = "0.1.0"\n'
                             'dependencies = [\n')],
                'previous_sha256': 'e3a920f1f54ddf4cf91f484e1b795848c7303340964bb62229e299029412afe3'},
 'crates/liteinst-inprocess/Cargo.toml': {'current_sha256': '3e4f957ead1df113d59de515947e86bdbca902e620ab269d713356afc749843b',
                                          'inverse': [('iced-x86 = { version = '
                                                       '"1.21.0", '
                                                       'default-features = '
                                                       'false, features = '
                                                       '["std", "decoder"] }\n',
                                                       ''),
                                                      ('\n'
                                                       '[[example]]\n'
                                                       'name = '
                                                       '"selected_probe"\n'
                                                       'path = '
                                                       '"examples/selected_probe.rs"\n'
                                                       'test = false\n'
                                                       'bench = false\n'
                                                       'doc = false\n',
                                                       '')],
                                          'previous_sha256': '4394a131aee87a1a7885d76f25648c506c26fb668cad7723ca2be6ebbd9863c6'}}


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def source_before_selected(path, data, error):
    data = source_before_inline(path, data, error)
    if path not in PROJECTIONS:
        return data
    row = PROJECTIONS[path]
    require(type(data) is bytes and hashlib.sha256(data).hexdigest() == row['current_sha256'], error)
    for current, previous in row['inverse']:
        require(data.count(current.encode()) == 1, error)
        data = data.replace(current.encode(), previous.encode(), 1)
    require(hashlib.sha256(data).hexdigest() == row['previous_sha256'], error)
    return data


def before_selected(declared):
    declared = peel_inline(declared)
    require(type(declared) is dict and digest(declared) == CURRENT, 'selected_inventory_differs')
    previous = copy.deepcopy(declared)
    rows = previous['harness_test_counts']['workspace_tests']
    require(rows['unit/liteinst_inprocess/lib'] == {'tests': 10, 'ignored': 0}, 'selected_inventory_differs')
    rows['unit/liteinst_inprocess/lib'] = {'tests': 6, 'ignored': 0}
    require(digest(previous) == PREVIOUS, 'selected_inventory_differs')
    root = Path(__file__).resolve().parents[2]
    require(TEST_PATH in SOURCES and len(PROJECTIONS) == 2, 'selected_source_inventory_differs')
    for path, expected in SOURCES.items():
        try:
            data = (root / path).read_bytes()
            data = source_before_cc846(path, data, "selected_source_inventory_differs")
        except OSError:
            require(False, 'selected_source_inventory_differs')
        require(hashlib.sha256(data).hexdigest() == expected, 'selected_source_inventory_differs')
        if path == TEST_PATH:
            source = data.decode()
            require(re.findall(r'#\[test\]\s*fn\s+(\w+)\(', source) == list(METHODS)
                    and not re.search(r'#\[ignore(?:\]|\()', source), 'selected_source_inventory_differs')
    return previous


def peel_current(declared):
    """Permit only this exact new layer; corrupt catalogs hit the old strict gate."""
    declared = peel_inline(declared)
    return before_selected(declared) if type(declared) is dict and digest(declared) == CURRENT else declared
