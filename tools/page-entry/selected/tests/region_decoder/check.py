"""Bounded numeric result reader; actual C assertions own descriptor comparison."""
import json

def need(value, why):
    if not value:
        raise ValueError(why)

def decode(data):
    def pairs(values):
        result = {}
        for key, value in values:
            need(key not in result, 'duplicate key')
            result[key] = value
        return result
    need(isinstance(data, bytes) and 0 < len(data) <= 2048 and data.endswith(b'\n'), 'one bounded output')
    try:
        result = json.loads(data, object_pairs_hook=pairs)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError('JSON') from exc
    need(isinstance(result, dict) and all(type(v) is int and 0 <= v < 1 << 64 for v in result.values()), 'integer object')
    need(json.dumps(result, separators=(',', ':')).encode()+b'\n' == data, 'canonical one-line output')
    return result

def check(stdout, stderr, status, row):
    need(type(status) is int and type(row) is int and 0 <= row < 8, 'exact case and exit types')
    if row in (1, 2, 7):
        reason = {1: 102, 2: 106, 7: 101}[row]
        need(status == 125 and stdout == b'' and stderr == f'LI2_DECODER_FATAL {reason}\n'.encode(), 'exact real fatal operation')
        return {'fatal_reason': reason}
    need(status == 0 and stderr == b'', 'successful actual process')
    v = decode(stdout)
    stats = {'phase', 'first_fatal_reason', 'arena_bytes', 'retained_high_water', 'allocation_calls', 'deallocation_calls'}
    need(v['phase'] == 2 and v['first_fatal_reason'] == 0 and
         0 < v['retained_high_water'] <= v['arena_bytes'] == 16 << 20 and
         v['allocation_calls'] > 0, 'sealed allocator statistics')
    if row == 0:
        need(set(v) == stats | {'forms'} and v['forms'] == 112, 'unchanged 112 controls')
    elif row == 3:
        need(set(v) == stats | {'schema_version', 'decoded_classes', 'scan_starts'} and
             (v['schema_version'], v['decoded_classes'], v['scan_starts']) == (1, 7, 4110), 'unchanged freestanding checks')
    else:
        expected = {
            4: dict(version=1, mode=0, forms=47, accepted_rows=3898, accepted_calls=7796,
                    refusals=34, truncations=124, api_checks=6, guard_checks=0, busy=0, stats_equal=1),
            5: dict(version=1, mode=1, forms=47, accepted_rows=0, accepted_calls=47,
                    refusals=0, truncations=124, api_checks=0, guard_checks=171, busy=0, stats_equal=1),
            6: dict(version=1, mode=2, forms=0, accepted_rows=0, accepted_calls=0,
                    refusals=0, truncations=0, api_checks=0, guard_checks=0, busy=1, stats_equal=1),
        }[row]
        need(set(v) == stats | set(expected) and all(v[k] == x for k, x in expected.items()), 'complete fixed new population')
    return v

def controls(stdout, stderr, status, row):
    """Only copies of a previously accepted actual result, no replacement run."""
    check(stdout, stderr, status, row)
    trials = [('wrong_exit', stdout, stderr, 0 if status else 125),
              ('extra_stdout', stdout+b'\n', stderr, status),
              ('extra_stderr', stdout, stderr+b'x', status)]
    if row in (1, 2, 7):
        trials += [('wrong_reason', stdout, b'LI2_DECODER_FATAL 999\n', status)]
    else:
        value = decode(stdout)
        for key in value:
            altered = dict(value);altered[key] = True
            trials.append(('bool_'+key, json.dumps(altered, separators=(',', ':')).encode()+b'\n', stderr, status))
        key = 'forms' if row == 0 else 'scan_starts' if row == 3 else 'stats_equal'
        altered = dict(value);altered[key] += 1
        trials.append(('count', json.dumps(altered, separators=(',', ':')).encode()+b'\n', stderr, status))
        trials += [('duplicate', stdout[:-2]+b',"phase":2}\n', stderr, status)]
    names = []
    for name, out, err, code in trials:
        refused = False
        try:
            check(out, err, code, row)
        except (ValueError, KeyError):
            refused = True
        need(refused, 'accepted supplied corruption '+name);names.append(name)
    need(len(names) == len(set(names)), 'unique control names')
    return names
