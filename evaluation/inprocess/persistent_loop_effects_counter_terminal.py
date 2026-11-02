"""Actual mixed11/12/13 terminal rows joined to the distinct ABI4 counter page.

Failure prefixes remain per-cell observations. Only completed_terminal() applies
successful-outcome predicates; the original PF reader receives its full stream.
"""
import hashlib
import json
from page_selected import need
from persistent_loop_effects_counter import LOOP_NAMES, EFFECTS_NAMES
from persistent_loop_effects_terminal import PREFIX, KEYS, EFFECTS_PREFIX, EFFECTS_KEYS, split
import persistent_fused_counter_terminal as prior

CONTROL_COUNT = 130


def observed(stderr):
    """Real optional rows only; no completion or cross-cell arithmetic on failure."""
    need(type(stderr) is bytes, 'actual child stderr bytes')
    if not any(line.startswith((PREFIX, EFFECTS_PREFIX)) for line in stderr.splitlines()):
        return None, None, prior.optional_pf(stderr)
    loop, effects, original = split(stderr)
    pf = prior.optional_pf(original)
    need(pf is not None and (loop['status'], loop['failure_code']) == (pf['status'], pf['failure_code']),
         'actual LOOP/effects/PF rows share the same reported outcome')
    return loop, effects, pf


def joined(stderr, prefix):
    loop, effects, original = split(stderr)
    need(type(prefix) is dict and type(prefix.get('version')) is int and prefix['version'] == 4 and
         type(prefix.get('logical_bytes')) is int and prefix['logical_bytes'] == 896 and
         type(prefix.get('loop')) is dict and tuple(prefix['loop']) == LOOP_NAMES and
         all(type(v) is int and 0 <= v < 1 << 64 for v in prefix['loop'].values()),
         'exact typed ABI4 with all original nine LOOP cells before successful arithmetic')
    need(type(prefix.get('effects')) is dict and tuple(prefix['effects']) == EFFECTS_NAMES and
         all(type(v) is int and 0 <= v < 1 << 64 for v in prefix['effects'].values()),
         'exact typed ABI4 with all nine separately appended effects cells')
    need(all(loop[name] == prefix['loop'][name] for name in LOOP_NAMES),
         'every actual LOOP terminal counter equals its actual post-reap ABI4 cell')
    need(all(effects[name] == prefix['effects'][name] for name in EFFECTS_NAMES),
         'every actual effects terminal counter equals its actual post-reap ABI4 cell')
    need(loop['status'] == loop['failure_code'] == loop['scope'] == 0,
         'successful LOOP terminal has no decoder scope or failed outcome')
    return loop, effects, original



def completed_choice(loop, effects, terminal):
    """Actual final selection, after unchanged PF completion/permit predicates.

    Reset clears both choice bits. Warm binding keeps the immutable earlier
    build serial; cold publication sets it to the current offer serial. Neither
    a counter increase alone nor a cleared choice bit proves a completed hit.
    """
    route, choice = loop['route'], loop['choice_complete']
    added = effects['choice_complete']
    d, sub = terminal['persistent'], terminal['subentry']
    if route == 0:
        need(choice == added == 0, 'idle/reset route has no completed cold chooser')
    elif choice == 0:
        need(added == 0 and d['phase'] == 13 and d['generation'] > 0 and
             0 < d['build_serial'] < d['serial'] and d['hits'] + sub['hits'] > 0,
             'completed warm choice binds an older selected generation and actual hit')
    else:
        need(choice == 1 and added == (0 if route == 12 else 1),
             'completed cold choice retains exact old-first effects selector bits')
        need(d['phase'] == 14 or
             d['phase'] == 13 and d['generation'] > 0 and d['build_serial'] == d['serial'],
             'completed cold choice is a current publication or genuine PF cancellation')


def completed_terminal(stderr, prefix):
    loop, effects, original = joined(stderr, prefix)
    terminal = prior.completed_terminal(original, prefix)
    completed_choice(loop, effects, terminal)
    return dict(**terminal, loop_runtime=loop, loop_effects=effects)


def counters(stderr):
    loop, effects, original = split(stderr)
    result = prior.counters(original)
    result['LI2_LOOP_RUNTIME'] = loop
    result['LI2_LOOP_EFFECTS'] = effects
    return result


def controls(stderr, prefix):
    """Additive parser/join refusals on an actual completed child, no new child."""
    completed_terminal(stderr, prefix)
    value, effects, _ = split(stderr)
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
    changed = dict(value); changed['route'] = 14
    reject('unknown_route', encoded(changed))
    changed = dict(value); changed['choice_complete'] = 2
    reject('invalid_choice', encoded(changed))
    for name, number in (('version', 2), ('logical_bytes', 752)):
        changed = dict(prefix); changed[name] = number
        reject('prefix_' + ('version' if name == 'version' else 'bytes'), stderr, changed)
    changed = dict(prefix); changed['loop'] = dict(prefix['loop'])
    changed['loop'][LOOP_NAMES[0]] = bool(changed['loop'][LOOP_NAMES[0]])
    reject('prefix_bool', stderr, changed)
    effects_index = len(lines) - 5
    def effects_encoded(row):
        changed = list(lines)
        changed[effects_index] = EFFECTS_PREFIX + json.dumps(row, separators=(',', ':'), allow_nan=False).encode()
        return b'\n'.join(changed) + b'\n'
    for name in EFFECTS_KEYS:
        changed = dict(effects); changed[name] ^= 1
        reject('effects_changed_' + name, effects_encoded(changed))
    for name in EFFECTS_KEYS:
        changed = dict(effects); del changed[name]
        reject('effects_missing_' + name, effects_encoded(changed))
    for name in EFFECTS_NAMES:
        changed = dict(effects); changed[name] = bool(changed[name])
        reject('effects_boolean_' + name, effects_encoded(changed))
    reject('effects_missing_row', b'\n'.join(lines[:effects_index] + lines[effects_index+1:]) + b'\n')
    reject('effects_duplicate_row', b'\n'.join(lines[:effects_index] + [lines[effects_index]] + lines[effects_index:]) + b'\n')
    changed = list(lines); changed[effects_index-1], changed[effects_index] = changed[effects_index], changed[effects_index-1]
    reject('effects_wrong_position', b'\n'.join(changed) + b'\n')
    changed = dict(effects); changed['extra'] = 0
    reject('effects_extra_field', effects_encoded(changed))
    changed = list(lines); changed[effects_index] = lines[effects_index][:-1] + b',"version":1}'
    reject('effects_duplicate_field', b'\n'.join(changed) + b'\n')
    changed = list(lines); changed[effects_index] = lines[effects_index].replace(b'{', b'{ ', 1)
    reject('effects_noncanonical', b'\n'.join(changed) + b'\n')
    changed = dict(prefix); changed['version'] = 3
    reject('effects_abi3_prefix', stderr, changed)
    changed = dict(prefix); del changed['effects']
    reject('effects_missing_bank', stderr, changed)
    changed = dict(prefix); changed['effects'] = dict(prefix['effects'], extra=0)
    reject('effects_extra_cell', stderr, changed)
    changed = dict(prefix); changed['effects'] = list(prefix['effects'].values())
    reject('effects_untyped_bank', stderr, changed)
    changed = dict(prefix); changed['effects'] = dict(prefix['effects'])
    changed['effects'][EFFECTS_NAMES[0]] = bool(changed['effects'][EFFECTS_NAMES[0]])
    reject('effects_prefix_bool', stderr, changed)
    for name in EFFECTS_NAMES:
        changed = dict(prefix); changed['effects'] = dict(prefix['effects']); changed['effects'][name] ^= 1
        reject('effects_prefix_cell_' + name, stderr, changed)
    # Isolate each new selection guard after the complete actual baseline has
    # passed. These are invalid supplied argument mutations, never synthetic
    # successful terminals or evidence that a warm guest actually ran.
    actual_terminal = prior.completed_terminal(split(stderr)[2], prefix)
    def choice_reject(name, route, choice, added, **fields):
        l = dict(value, route=route, choice_complete=choice)
        e = dict(effects, route=route, choice_complete=added)
        d = dict(actual_terminal['persistent'], phase=13, generation=1,
                 serial=2, build_serial=1 if choice == 0 else 2, hits=1)
        sub = dict(actual_terminal['subentry'], hits=0)
        if 'subentry_hits' in fields:sub['hits'] = fields.pop('subentry_hits')
        d.update(fields)
        terminal = dict(actual_terminal, persistent=d, subentry=sub)
        need((l,e,terminal)!=(value,effects,actual_terminal),
             'nonidentity supplied choice-guard control ' + name)
        try:completed_choice(l,e,terminal)
        except ValueError:refused.append('choice_guard_' + name)
        else:raise ValueError('accepted supplied choice-guard mutation ' + name)
    choice_reject('warm_phase',13,0,0,phase=14)
    choice_reject('warm_generation',13,0,0,generation=0)
    choice_reject('warm_build_zero',13,0,0,build_serial=0)
    choice_reject('warm_same_build',13,0,0,build_serial=2)
    choice_reject('warm_future_build',13,0,0,build_serial=3)
    choice_reject('warm_no_hits',13,0,0,hits=0,subentry_hits=0)
    choice_reject('warm_effects_choice',13,0,1)
    choice_reject('cold_effects_choice',13,1,0)
    choice_reject('cold_phase',13,1,1,phase=0)
    choice_reject('cold_old_build',13,1,1,build_serial=1)
    choice_reject('cold_generation',13,1,1,generation=0)
    choice_reject('cold12_effects_choice',12,1,1)
    choice_reject('idle_effects_choice',0,0,1)
    choice_reject('idle_old_choice',0,1,0)
    need(len(refused) == len(set(refused)) == CONTROL_COUNT,
         'all51 original LOOP,65 effects and14 source-bound choice-guard refusals')
    return dict(refusals=refused, native_operations=0,
                original_stderr_sha256=hashlib.sha256(stderr).hexdigest())
