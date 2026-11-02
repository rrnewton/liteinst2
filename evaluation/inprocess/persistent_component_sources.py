"""Authenticate current production for unchanged original component oracles.

This grants source identity only. The caller still compiles these actual current
paths and requires every original assertion, control, bound and whole output.
Historical source is reconstructed for custody, never compiled as a substitute.
"""
import hashlib
import json
from pathlib import Path

from page_selected import fact, need

DATA = Path(__file__).with_suffix('.json')
DATA_FACT = dict(bytes=5480, sha256='bec4b3724cffe2a6047babab5d199d12e66347b82bc8344c673a006c712c96ba')
GROUP = frozenset(('persistent_group_compact.c', 'persistent_group_compact.h',
                   'persistent_group_plan.c', 'persistent_group_plan.h'))
RETAINED = frozenset(('persistent_retained_two.inc',))
PROFILES = {'group': GROUP, 'resident': GROUP, 'retained': RETAINED}


def byte_fact(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def original(raw, row):
    """Complete exact current-to-historical inverse, with no ignored bytes."""
    need(byte_fact(raw) == row['current'], 'exact current component source')
    lines = raw.decode('utf-8').splitlines(keepends=True)
    cursor = 0
    pieces = []
    need(type(row['inverse']) is list and row['inverse'], 'nonempty explicit component inverse')
    for span in row['inverse']:
        need(type(span) is list and len(span) == 3, 'one exact inverse span')
        first, end, replacement = span
        need(type(first) is int and type(end) is int and type(replacement) is str and
             cursor <= first <= end <= len(lines), 'ordered bounded complete inverse spans')
        need(''.join(lines[first:end]) != replacement, 'inverse span changes actual bytes')
        pieces.extend(lines[cursor:first])
        pieces.append(replacement)
        cursor = end
    pieces.extend(lines[cursor:])
    result = ''.join(pieces).encode('utf-8')
    need(byte_fact(result) == row['historical'], 'exact original pinned whole component source')
    return result


def qualify(expected, selected, pin, receipt, profile):
    """Select only the whole historical roster or its one explicit successor."""
    need(profile in PROFILES and 'component_source' not in receipt,
         'one named component source qualification')
    pin(Path(__file__))
    data_path = pin(DATA)
    need(fact(data_path) == DATA_FACT, 'exact source-owned component inverse table')
    data = json.loads(data_path.read_bytes())
    need(set(data) == {'schema', 'profile', 'sources'} and data['schema'] == 1 and
         data['profile'] == 'current-legacy-components-v1' and
         set(data['sources']) == GROUP | RETAINED, 'complete five-source successor table')
    changed = PROFILES[profile]
    need(set(expected) & (GROUP | RETAINED) == changed, 'exact original component roster')
    paths = {name: pin(selected / name) for name in expected}
    actual = {name: fact(path) for name, path in paths.items()}
    for name in changed:
        need(expected[name] == data['sources'][name]['historical'],
             'original caller source target remains byte-exact: ' + name)
    if actual == expected:
        selected_profile = 'historical-legacy-components-v1'
        resolved = dict(expected)
        reconstructed = {}
    else:
        selected_profile = data['profile']
        resolved = {name: data['sources'][name]['current'] if name in changed else value
                    for name, value in expected.items()}
        need(actual == resolved, 'whole exact current component roster; no mixed or unknown source')
        reconstructed = {name: byte_fact(original(paths[name].read_bytes(), data['sources'][name]))
                         for name in sorted(changed)}
        need(reconstructed == {name: expected[name] for name in changed},
             'every changed source reconstructs its original whole target')
    receipt['component_source'] = dict(
        profile=selected_profile, component=profile, status='source_authenticated',
        inverse_table=DATA_FACT, compiled_inputs=actual,
        historical_targets=dict(expected), reconstructed=reconstructed,
        component_execution_credit=False)
    return resolved
