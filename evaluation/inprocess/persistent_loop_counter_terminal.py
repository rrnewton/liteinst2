"""Typed LOOP row and ABI3 joins before the unchanged PF terminal gates.

A post-reap prefix is nine independent event cells, not a completion snapshot.
Only completed_terminal() applies successful-outcome predicates.
"""
import hashlib
import json

from page_selected import need
from persistent_loop_counter import LOOP_NAMES
import persistent_fused_counter_terminal as prior

PREFIX = b'LI2_LOOP_RUNTIME '
KEYS = ('version', 'status', 'failure_code', 'route', 'scope', 'choice_complete') + LOOP_NAMES
CONTROL_COUNT = 51


def decode(line):
    def pairs(items):
        need(len(items) == len(dict(items)), 'no duplicate LOOP terminal fields')
        return dict(items)
    need(type(line) is bytes and line.startswith(PREFIX) and len(line) <= 4096 and b'\r' not in line,
         'bounded actual LOOP terminal row')
    value = json.loads(line[len(PREFIX):], object_pairs_hook=pairs)
    need(type(value) is dict and tuple(value) == KEYS and
         all(type(v) is int and 0 <= v < 1 << 64 for v in value.values()) and
         value['version'] == 1 and value['route'] in (0, 11, 12) and
         value['scope'] in (0, 1, 2, 3) and value['choice_complete'] in (0, 1) and
         PREFIX + json.dumps(value, separators=(',', ':'), allow_nan=False).encode() == line,
         'whole canonical LOOP schema1 and exact policy/scope domains')
    return value


def split(stderr):
    need(type(stderr) is bytes and stderr.endswith(b'\n'), 'complete LOOP terminal stream')
    lines = stderr[:-1].split(b'\n')
    need(len(lines) > 5 and lines[-1].startswith(b'LI2_PERSISTENT_UNREGISTERED ') and
         lines[-2].startswith(b'LI2_PERSISTENT_SUBENTRY ') and
         lines[-3].startswith(b'LI2_PF_REFUSALS ') and lines[-4].startswith(PREFIX) and
         lines[-5].startswith(b'LI2_LINKED_NATIVE_PROBE ') and
         sum(line.startswith(PREFIX) for line in lines) == 1,
         'one actual probe/LOOP/PF/subentry/unregistered terminal order')
    row = decode(lines[-4])
    # Remove only the fully authenticated new row; the entire old byte stream
    # and all old predicates are then passed unchanged to the PF reader.
    original = b'\n'.join(lines[:-4] + lines[-3:]) + b'\n'
    return row, original


def observed(stderr):
    """Optional real rows on failure, with no completion or cross-cell equations."""
    need(type(stderr) is bytes, 'actual child stderr bytes')
    if not any(line.startswith(PREFIX) for line in stderr.splitlines()):
        return None, prior.optional_pf(stderr)
    row, original = split(stderr)
    pf = prior.optional_pf(original)
    need(pf is not None and (row['status'], row['failure_code']) == (pf['status'], pf['failure_code']),
         'actual LOOP and PF rows share the same reported outcome')
    return row, pf


def joined(stderr, prefix):
    row, original = split(stderr)
    need(type(prefix) is dict and type(prefix.get('version')) is int and prefix['version'] == 3 and
         type(prefix.get('logical_bytes')) is int and prefix['logical_bytes'] == 824 and
         type(prefix.get('loop')) is dict and tuple(prefix['loop']) == LOOP_NAMES and
         all(type(v) is int and 0 <= v < 1 << 64 for v in prefix['loop'].values()),
         'exact typed ABI3 nine-cell prefix before any successful terminal arithmetic')
    need(all(row[name] == prefix['loop'][name] for name in LOOP_NAMES),
         'every actual LOOP terminal counter equals its actual post-reap ABI3 cell')
    need(row['status'] == row['failure_code'] == row['scope'] == 0 and
         (row['route'], row['choice_complete']) in ((0, 0), (11, 1), (12, 1)),
         'successful LOOP terminal has no decoder scope or unfinished cold choice')
    return row, original


def completed_terminal(stderr, prefix):
    loop, original = joined(stderr, prefix)
    terminal = prior.completed_terminal(original, prefix)
    return dict(**terminal, loop_runtime=loop)


def counters(stderr):
    loop, original = split(stderr)
    result = prior.counters(original)
    result['LI2_LOOP_RUNTIME'] = loop
    return result


def controls(stderr, prefix):
    """Additive parser/join refusals on an actual completed child, no new child."""
    completed_terminal(stderr, prefix)
    value, _ = split(stderr)
    lines = stderr[:-1].split(b'\n'); index = len(lines) - 4
    refused = []

    def encoded(row):
        changed = list(lines)
        changed[index] = PREFIX + json.dumps(row, separators=(',', ':'), allow_nan=False).encode()
        return b'\n'.join(changed) + b'\n'

    def reject(name, mutant, cells=None):
        candidate = prefix if cells is None else cells
        need(mutant != stderr or json.dumps(candidate, sort_keys=True) != json.dumps(prefix, sort_keys=True),
             'causal LOOP terminal stimulus ' + name)
        try:
            completed_terminal(mutant, candidate)
        except ValueError:
            refused.append(name)
        else:
            raise ValueError('accepted supplied LOOP terminal mutation ' + name)

    for name in KEYS:
        changed = dict(value); changed[name] ^= 1
        reject('changed_' + name, encoded(changed))
    for name in KEYS:
        changed = dict(value); del changed[name]
        reject('missing_' + name, encoded(changed))
    for name in LOOP_NAMES:
        changed = dict(value); changed[name] = bool(changed[name])
        reject('boolean_' + name, encoded(changed))
    reject('missing_row', b'\n'.join(lines[:index] + lines[index+1:]) + b'\n')
    reject('duplicate_row', b'\n'.join(lines[:index] + [lines[index]] + lines[index:]) + b'\n')
    changed = list(lines); changed[index-1], changed[index] = changed[index], changed[index-1]
    reject('wrong_position', b'\n'.join(changed) + b'\n')
    reject('truncated', stderr[:-1])
    changed = dict(value); changed['extra'] = 0
    reject('extra_field', encoded(changed))
    changed = list(lines); changed[index] = lines[index][:-1] + b',"version":1}'
    reject('duplicate_field', b'\n'.join(changed) + b'\n')
    changed = list(lines); changed[index] = lines[index].replace(b'{', b'{ ', 1)
    reject('noncanonical', b'\n'.join(changed) + b'\n')
    changed = dict(value); changed['route'] = 13
    reject('unknown_route', encoded(changed))
    changed = dict(value); changed['choice_complete'] = 2
    reject('invalid_choice', encoded(changed))
    for name, number in (('version', 2), ('logical_bytes', 752)):
        changed = dict(prefix); changed[name] = number
        reject('prefix_' + ('version' if name == 'version' else 'bytes'), stderr, changed)
    changed = dict(prefix); changed['loop'] = dict(prefix['loop'])
    changed['loop'][LOOP_NAMES[0]] = bool(changed['loop'][LOOP_NAMES[0]])
    reject('prefix_bool', stderr, changed)
    need(len(refused) == len(set(refused)) == CONTROL_COUNT, 'all51 additive LOOP terminal refusals')
    return dict(refusals=refused, native_operations=0,
                original_stderr_sha256=hashlib.sha256(stderr).hexdigest())
