"""Authenticate the eleven additive inline-clock tests before historical readers.

Current validators consume all 2,354 tests. Exact inverse source/catalog
projections preserve previous assertions without fabricating execution evidence.
"""
import copy
import hashlib
import json
from pathlib import Path
import re

from parsing import require
from core223_inventory import peel_current as peel_core223, source_before_core223

PREVIOUS = '5722a63804e587b2bc6c9b9330e9a610feeedc5838916409d652fc5ea0b76668'
CURRENT = '3de828ebb4d057e7fad20da36e59a90ea9ab09dedf5a2cb6ff7cf66068118f61'
METHODS = ('inline_clock_owns_exact_geometry_and_canaries',
 'inline_clock_duplicate_reentrant_and_wrong_process_leases_refuse',
 'inline_clock_caught_panic_does_not_release_an_existing_lease',
 'inline_clock_requires_exact_managed_writer_and_keeps_enable_immutable',
 'inline_clock_complete_source_and_site_mutations_refuse',
 'inline_clock_emits_only_exact_flag_neutral_gate_and_original_branch',
 'inline_clock_final_rip_reach_and_frame_emission_refuse',
 'inline_clock_image_retains_the_actual_data_owner_after_plan_drop')
SOURCES = {'src/controls.rs': '16867d6f968ca01c3a35ebc5ff24f6b603fce4f2f69b2a7c83a1ac2460f6a264',
 'src/lib.rs': '1addbff518f27cd29c506583d850a288e40ddf7f75efbb373288f43352820ce6',
 'src/trampoline.rs': '2120c60ad6c512b5b1058814ef3cc5dd28824c0980d69b4b3852e7f06fb8dc7d',
 'tools/software-preemption/main.rs': 'f3455aba09e0bebb1455bc8561bd0568f306949cc44671472a622d71623453ff',
 'src/backedge_clock.rs': 'c6f0e37cecf09c5e68a40f5036eee262abdf70607394d8a0500c83f93ede5425',
 'src/backedge_clock/tests.rs': '53ce9f320f1842020bbc8572cb82df1b993557e86edbba9b8db3acd02d3749ff',
 'src/trampoline/backedge_clock.rs': '1a4b4b062e50d1aad21ceef5293caf79706fd97a98ad83aedae4e904c17a1dde',
 'src/quiescent.rs': '01239d61eb7b30a32a8501ad43e792b48babb715d2180834c6b06cb1ab78f3cf',
 'tools/software-preemption/inline_clock.rs': '38ccbdda849fa86d96c262782bcbbdf6bc409e16d6519b16bd7ce63546849f0e',
 'tools/software-preemption/inline_gate.rs': '1b36ecee6a353636914abbf8c28a1930e57a96b394c2060bed2a8e9faaef0454'}
PROJECTIONS = {'src/controls.rs': {'current_sha256': '16867d6f968ca01c3a35ebc5ff24f6b603fce4f2f69b2a7c83a1ac2460f6a264',
                     'previous_sha256': 'e7fa95d7fb2fe6e3bc6b4fc998ca20fb9d44f01ed918d407329133c6d5d5857b',
                     'edits': [(3968, 4090, ''), (7693, 7818, '')]},
 'src/lib.rs': {'current_sha256': '1addbff518f27cd29c506583d850a288e40ddf7f75efbb373288f43352820ce6',
                'previous_sha256': '2e4cb57fb7be6c78d58a5582c5ab4e6408f373c1840243a30d71e49438db363a',
                'edits': [(345, 369, '')]},
 'src/trampoline.rs': {'current_sha256': '2120c60ad6c512b5b1058814ef3cc5dd28824c0980d69b4b3852e7f06fb8dc7d',
                       'previous_sha256': '7abbe3d70ebb0d4e3dfb7e6ac22e2ae54332a47704a0184326b21dc4d40a2a1f',
                       'edits': [(25857, 25934, ''),
                                 (28592, 28713, ''),
                                 (29653,
                                  29763,
                                  '    /// control for the entire executable-code lifetime. The provided '
                                  'private\n'),
                                 (30181, 30545, ''),
                                 (31333, 31486, ''),
                                 (42637, 42705, ''),
                                 (46654, 46679, ''),
                                 (50181, 50206, ''),
                                 (53782, 53807, ''),
                                 (56133, 56158, ''),
                                 (57681, 57706, ''),
                                 (61010, 62824, ''),
                                 (64781, 64908, ''),
                                 (76622, 76685, ''),
                                 (77838, 77878, ''),
                                 (78614, 78847, ''),
                                 (81191, 81265, ''),
                                 (81686, 82547, ''),
                                 (83868, 83905, '                    entry_index,\n'),
                                 (85044, 85183, '            body.set_ip(identity()?);\n'),
                                 (86608,
                                  87717,
                                  '        let block = encode_relocated_block_with_metadata(\n'
                                  '            &encoded_instructions,\n'
                                  '            address,\n'
                                  '            None,\n'
                                  '            artifact.is_some(),\n'
                                  '        )?;\n'),
                                 (88316, 88820, ''),
                                 (90669, 90892, ''),
                                 (97416, 97515, ''),
                                 (144696, 144747, ''),
                                 (146564, 146635, ''),
                                 (148399, 148462, ''),
                                 (158226, 158379, ''),
                                 (182452, 182511, ''),
                                 (260344, 260399, '')]},
 'tools/software-preemption/main.rs': {'current_sha256': 'f3455aba09e0bebb1455bc8561bd0568f306949cc44671472a622d71623453ff',
                                       'previous_sha256': 'a43cb418030350aa6051acfb8d9706525ba3c5f16de26039dbf64cfeb9083a76',
                                       'edits': [(158, 193, ''), (19217, 24546, ''), (25064, 25307, '')]}}


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def source_before_inline(path, data, error):
    data = source_before_core223(path, data, error)
    if path not in PROJECTIONS:
        return data
    row = PROJECTIONS[path]
    require(type(data) is bytes and hashlib.sha256(data).hexdigest() == row['current_sha256'], error)
    # Fixed byte ranges are meaningful only after the complete current blob hash.
    last = len(data)
    for first, end, original in reversed(row['edits']):
        require(0 <= first <= end <= last, error)
        data = data[:first] + original.encode() + data[end:]
        last = first
    require(hashlib.sha256(data).hexdigest() == row['previous_sha256'], error)
    return data


def before_inline(declared):
    declared = peel_core223(declared)
    require(type(declared) is dict and digest(declared) == CURRENT, 'inline_inventory_differs')
    previous = copy.deepcopy(declared)
    rows = previous['harness_test_counts']['workspace_tests']
    require(rows['unit/liteinst2/lib'] == {'tests': 227, 'ignored': 1}
            and rows['doc/liteinst2'] == {'tests': 6, 'ignored': 0}, 'inline_inventory_differs')
    rows['unit/liteinst2/lib'] = {'tests': 219, 'ignored': 1}
    rows['doc/liteinst2'] = {'tests': 3, 'ignored': 0}
    require(digest(previous) == PREVIOUS, 'inline_inventory_differs')
    root = Path(__file__).resolve().parents[2]
    for path, expected in SOURCES.items():
        try:
            data = (root / path).read_bytes()
        except OSError:
            require(False, 'inline_source_inventory_differs')
        require(hashlib.sha256(data).hexdigest() == expected, 'inline_source_inventory_differs')
        if path == 'src/backedge_clock/tests.rs':
            text = data.decode()
            require(re.findall(r'#\[test\]\s*fn\s+(\w+)\(', text) == list(METHODS)
                    and not re.search(r'#\[ignore(?:\]|\()', text), 'inline_source_inventory_differs')
        if path == 'src/backedge_clock.rs':
            require(data.count(b'```compile_fail') == 3, 'inline_source_inventory_differs')
    return previous


def peel_current(declared):
    declared = peel_core223(declared)
    return before_inline(declared) if type(declared) is dict and digest(declared) == CURRENT else declared
