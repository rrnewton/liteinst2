"""Strict explicit source-batch8 consumer grammar; historical modes delegate unchanged."""
import sys

if sys.flags.optimize:
    raise SystemExit('assertions required')
sys.dont_write_bytecode = True

import importlib.util
from pathlib import Path

SPEC = importlib.util.spec_from_file_location('tree_batch_legacy_check', Path(__file__).with_name('check_comparison.py'))
LEGACY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LEGACY)

BATCH_MODES = {'original-sdk-batch8': 'original-sdk', 'k1-batch8': 'k1',
    'k10-batch8': 'k10', 'k24-batch8': 'k24'}
MODES = LEGACY.MODES + tuple(BATCH_MODES)
POLICY_FIELDS = ('source_batch_calls', 'source_batch_finishes', 'provenance_policy')
TERMINAL_FIELDS = LEGACY.TERMINAL_FIELDS[:21] + POLICY_FIELDS + LEGACY.TERMINAL_FIELDS[21:]


def parse(stdout, stderr, requested_mode):
    """Complete transcript only; actual finishes and object joins remain source-attested."""
    assert type(requested_mode) is str and requested_mode in MODES
    if requested_mode in LEGACY.MODES:
        return LEGACY.parse(stdout, stderr, requested_mode)
    assert type(stdout) is bytes and type(stderr) is bytes and stderr == b''
    assert 0 < len(stdout) <= 1048576 and stdout.endswith(b'\n')
    assert all(byte == 10 or 32 <= byte <= 126 for byte in stdout)
    lines = stdout.decode('ascii').split('\n')[:-1]
    assert len(lines) == 66 and lines[0] == LEGACY.HEADER
    rows = [line.split(',') for line in lines[1:65]]
    assert all(len(row) == 25 and row[0] == requested_mode for row in rows)
    words = lines[-1].split(' ')
    assert words[:2] == ['tree-comparison-batch', 'FUNCTIONAL_PASS']
    assert len(words) == 46 and len(TERMINAL_FIELDS) == 44
    values = {}
    for name, word in zip(TERMINAL_FIELDS, words[2:]):
        key, separator, value = word.partition('=')
        assert key == name and separator == '='
        values[name] = value
    assert values['mode'] == requested_mode
    assert LEGACY.uint(values['source_batch_calls']) == 8
    assert LEGACY.uint(values['source_batch_finishes']) == 192
    assert values['provenance_policy'] == 'source-batch8'

    # Authenticate every new identity/marker before projecting only those fields.
    # All other row, count, checksum, numeric and clock predicates execute literally
    # in the unchanged legacy parser. No suffix-wide textual replacement occurs.
    mapped_mode = BATCH_MODES[requested_mode]
    mapped_rows = [','.join([mapped_mode] + row[1:]) for row in rows]
    mapped_terminal = 'tree-comparison FUNCTIONAL_PASS ' + ' '.join(
        name+'='+(mapped_mode if name == 'mode' else values[name])
        for name in LEGACY.TERMINAL_FIELDS)
    mapped = ('\n'.join([lines[0]] + mapped_rows + [mapped_terminal])+'\n').encode('ascii')
    result = LEGACY.parse(mapped, stderr, mapped_mode)
    result['summary'].update(mode=requested_mode, source_batch_calls=8,
        source_batch_finishes=192, provenance_policy='source-batch8')
    for row in result['rows']:
        row['mode'] = requested_mode
    result['source_attested'] = LEGACY.SOURCE_ATTESTED + (
        ' The consumer counts 192 consumed successful SDK finish verifications, each for eight calls; '
        'this parser authenticates the exported count, not independent finish receipts. Source-batch8 '
        'checks full file/mapping provenance at begin/finish and live source/images/input per call, '
        'under continuous unsafe immutability and exclusion obligations.')
    result['scope'] = ('Finite complete source-batch8 checked consumer and exact clock arithmetic; '
        'primary internal wall spans are upper enclosures. Original mode has no exported node, '
        'gate or model observations. Native qualification, process closure/timing and statistical '
        'comparison are separate. No performance result, isolated hook cost, equal invalid-client '
        'detection, hardware-cache or calibrated accuracy claim.')
    return result
