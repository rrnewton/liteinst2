"""Additive terminal checks for the explicit RO LOOP experiment.

Certificate differential mode is separate from maps differential mode. All
ordinary application, source, permissions and chronology checks stay in the
unchanged LOOP13 reader. This module supplies no full-profile qualification.
"""
import json

from page_selected import need
import persistent_loop_effects_performance_reports as prior

PREFIXES = (b'LI2_SEALED_BYTE_CERTIFICATE ', b'LI2_LOOP_RO_CERTIFICATE ',
            b'LI2_LOOP_HISTORY ')
FIELDS = (
    ('version', 'status', 'failure_code', 'differential',
     'bytes_per_complete_scan', 'decisions', 'hits', 'misses', 'full_scans',
     'full_scan_errors', 'disagreements', 'full_scan_bytes', 'postseal_bytes',
     'issues', 'invalidations', 'abort_invalidations', 'live_queries',
     'live_query_errors', 'last_failure', 'last_full_result'),
    ('version', 'status', 'failure_code', 'initialized', 'readonly_calls',
     'query_attempts', 'requested_pages', 'query_errors', 'mirror_opens',
     'mirror_seals'),
    ('version', 'status', 'failure_code', 'differential', 'decisions', 'hits',
     'misses', 'full_calls', 'differential_checks', 'disagreements', 'issues',
     'invalidations', 'abort_invalidations', 'errors', 'restored_bytes'))


def split(stderr, mode):
    need(type(stderr) is bytes and stderr.endswith(b'\n') and
         mode in ('release', 'differential'), 'exact RO stream and certificate mode')
    lines = stderr[:-1].split(b'\n')
    positions = []
    rows = []
    for prefix, fields in zip(PREFIXES, FIELDS, strict=True):
        indices = [i for i, line in enumerate(lines) if line.startswith(prefix)]
        need(len(indices) == 1, 'one exact RO terminal row ' + prefix.decode())
        position = indices[0]
        need(len(lines[position]) < 4096, 'actual bounded C writer row')
        try:
            pairs = json.loads(lines[position][len(prefix):], object_pairs_hook=list)
        except (ValueError, UnicodeError) as error:
            raise ValueError('malformed RO terminal row') from error
        need(type(pairs) is list and all(type(p) is tuple and len(p) == 2 for p in pairs)
             and tuple(p[0] for p in pairs) == fields,
             'whole ordered distinct RO terminal fields ' + prefix.decode())
        value = dict(pairs)
        need(all(type(v) is int and 0 <= v < 1 << 64 for v in value.values()) and
             value['version'] == 1 and value['status'] == value['failure_code'] == 0,
             'successful finite unsigned RO terminal values ' + prefix.decode())
        need(lines[position] == prefix + json.dumps(value, separators=(',', ':'),
             allow_nan=False).encode(), 'whole canonical C terminal encoding')
        positions.append(position)
        rows.append(value)
    first = positions[0]
    need(positions == list(range(first, first + 3)) and first > 0 and
         first + 3 < len(lines) and lines[first - 1].startswith(b'LI2_PF_REFUSALS ') and
         lines[first + 3].startswith(b'LI2_PERSISTENT_SUBENTRY '),
         'actual ordered certificate rows at the existing producer boundary')
    byte, ro, history = rows
    diff = int(mode == 'differential')
    need(byte['differential'] == history['differential'] == diff and
         byte['bytes_per_complete_scan'] == 106 * 4096 and
         byte['decisions'] == byte['hits'] + byte['misses'] and
         byte['full_scans'] == (byte['decisions'] if diff else byte['misses']) and
         byte['full_scan_bytes'] == byte['full_scans'] * byte['bytes_per_complete_scan'] and
         byte['postseal_bytes'] == byte['issues'] * byte['bytes_per_complete_scan'] and
         byte['live_queries'] == 3 * (byte['issues'] + byte['hits']) and
         byte['invalidations'] == byte['issues'] == ro['mirror_opens'] == ro['mirror_seals'],
         'actual byte decisions, complete scans and sealed publication arithmetic')
    need(all(byte[k] == 0 for k in ('full_scan_errors', 'disagreements',
         'abort_invalidations', 'live_query_errors', 'last_failure', 'last_full_result')) and
         ro['initialized'] == 1 and ro['query_errors'] == 0 and
         0 < ro['readonly_calls'] <= ro['query_attempts'] <= ro['requested_pages'],
         'actual successful byte and private mapping query outcomes')
    need(history['decisions'] == history['hits'] + history['misses'] and
         history['full_calls'] == history['misses'] + diff * history['hits'] and
         history['differential_checks'] == diff * history['hits'] and
         history['invalidations'] == history['issues'] and
         history['misses'] >= history['issues'] and
         all(history[k] == 0 for k in ('disagreements', 'abort_invalidations', 'errors')) and
         (history['restored_bytes'] > 0) == (history['hits'] > 0),
         'actual historical proof work and every-hit comparison arithmetic')
    remaining = b'\n'.join(lines[:first] + lines[first + 3:]) + b'\n'
    return dict(byte_certificate=byte, readonly_queries=ro, history_certificate=history), remaining


def check(stdout, stderr, args, kind, mode):
    certificate, original = split(stderr, mode)
    # Both certificate modes use the actual maintained maps recipe. No row is
    # relabelled as a maps-DIFF observation or as an old capture-layout record.
    result = prior.check(stdout, original, args, kind, 'release')
    byte = certificate['byte_certificate']
    history = certificate['history_certificate']
    persistent = result['persistent']
    need(byte['issues'] == persistent['publications'] and
         history['issues'] == persistent['completed'],
         'actual publication and completed-activation identity joins')
    # Cold publication performs both complete verification loops before SBC
    # issuance. Release can then have zero decision-time scans if every call
    # hits; postseal_bytes records those actual first proofs separately.
    need(byte['issues'] > 0 and byte['hits'] > 0 and byte['postseal_bytes'] > 0 and
         byte['live_queries'] > 0 and history['issues'] > 0 and history['hits'] > 0 and
         history['full_calls'] > 0,
         'real program exercised first proofs and both issued certificate hit paths')
    result.update(certificate=certificate, certificate_mode=mode,
                  profile='persistent-loop-ro-certificate-v1', qualification_credit=False)
    return result


def controls(stdout, stderr, args, kind, mode):
    check(stdout, stderr, args, kind, mode)
    _, original = split(stderr, mode)
    inherited = prior.controls(stdout, original, args, kind, 'release')
    need(len(inherited['refusals']) == len(set(inherited['refusals'])) == prior.CONTROL_COUNTS[kind],
         'all unchanged LOOP13 real-program reader controls')
    lines = stderr[:-1].split(b'\n')
    refusals = []

    def reject(label, changed):
        need(type(changed) is bytes and changed != stderr, 'actual RO row mutation')
        try:
            check(stdout, changed, args, kind, mode)
        except ValueError:
            refusals.append(label)
        else:
            raise ValueError('accepted supplied RO row mutation ' + label)

    for number, (prefix, fields) in enumerate(zip(PREFIXES, FIELDS, strict=True)):
        index = next(i for i, line in enumerate(lines) if line.startswith(prefix))
        row = json.loads(lines[index][len(prefix):])
        label = ('byte', 'ro', 'history')[number]

        def replace(value, suffix):
            changed = list(lines)
            changed[index] = prefix + json.dumps(value, separators=(',', ':')).encode()
            reject(label + '.' + suffix, b'\n'.join(changed) + b'\n')

        for key in fields:
            changed = dict(row); del changed[key]
            replace(changed, 'missing_' + key)
            changed = dict(row); changed[key] = bool(changed[key])
            replace(changed, 'boolean_' + key)
        changed = dict(row); changed['extra'] = 0
        replace(changed, 'extra')
        replace(dict(reversed(list(row.items()))), 'key_order')
        changed = list(lines); changed[index] = lines[index][:-1] + b',"version":1}'
        reject(label + '.duplicate_key', b'\n'.join(changed) + b'\n')
        reject(label + '.missing_row', b'\n'.join(lines[:index] + lines[index+1:]) + b'\n')
        reject(label + '.duplicate_row', b'\n'.join(lines[:index] + [lines[index]] + lines[index:]) + b'\n')
        changed = list(lines); changed[index], changed[index-1] = changed[index-1], changed[index]
        reject(label + '.row_order', b'\n'.join(changed) + b'\n')
        for key in ('version', 'status', 'failure_code'):
            changed = dict(row); changed[key] += 1
            replace(changed, 'changed_' + key)
    need(len(refusals) == len(set(refusals)) == 2 * sum(map(len, FIELDS)) + 27,
         'complete distinct additive RO terminal schema and outcome controls')
    schema_count = len(refusals)
    actual, _ = split(stderr, mode)
    row_names = ('byte_certificate', 'readonly_queries', 'history_certificate')
    indices = [next(i for i, line in enumerate(lines) if line.startswith(p)) for p in PREFIXES]

    def semantic(label, changes):
        changed = list(lines)
        for number, fields in changes.items():
            row = dict(actual[row_names[number]])
            row.update(fields)
            changed[indices[number]] = PREFIXES[number] + json.dumps(
                row, separators=(',', ':'), allow_nan=False).encode()
        reject('semantic.' + label, b'\n'.join(changed) + b'\n')

    # Every arithmetic/outcome cell receives a causal, typed value mutation.
    # Inequality-only cells use their forbidden boundary rather than an
    # arbitrary increment that might still describe a possible observation.
    for number, fields in enumerate(FIELDS):
        row = actual[row_names[number]]
        for name in fields[3:]:
            value = row[name] ^ 1
            if number == 1:
                if name in ('initialized', 'readonly_calls'):value = 0
                elif name == 'query_attempts':value = row['readonly_calls'] - 1
                elif name == 'requested_pages':value = row['query_attempts'] - 1
            elif number == 2 and name == 'restored_bytes':value = 0
            semantic(row_names[number] + '.' + name, {number: {name: value}})

    # Preserve all within-certificate equations while breaking only the
    # actual publication/completion join or the required exercise path.
    byte = actual['byte_certificate']; history = actual['history_certificate']
    issues = byte['issues'] + 1
    semantic('publication_join', {
        0: dict(issues=issues, invalidations=issues,
                postseal_bytes=issues * byte['bytes_per_complete_scan'],
                live_queries=3 * (issues + byte['hits'])),
        1: dict(mirror_opens=issues, mirror_seals=issues)})
    issues = history['issues'] - 1
    semantic('completion_join', {2: dict(issues=issues, invalidations=issues)})
    semantic('byte_hit_exercise', {0: dict(hits=0, misses=byte['decisions'],
        full_scans=byte['decisions'],
        full_scan_bytes=byte['decisions'] * byte['bytes_per_complete_scan'],
        live_queries=3 * byte['issues'])})
    semantic('history_hit_exercise', {2: dict(hits=0, misses=history['decisions'],
        full_calls=history['decisions'], differential_checks=0, restored_bytes=0)})
    for number, prefix in enumerate(PREFIXES):
        index = indices[number]
        changed = list(lines); changed[index] = lines[index].replace(b'{', b'{ ', 1)
        reject('encoding.' + str(number) + '.whitespace', b'\n'.join(changed) + b'\n')
        changed = list(lines); changed[index] = lines[index].replace(b'"status":0', b'"status":-0', 1)
        reject('encoding.' + str(number) + '.negative_zero', b'\n'.join(changed) + b'\n')
        changed = list(lines); changed[index] = lines[index] + b' ' * 4096
        reject('encoding.' + str(number) + '.writer_bound', b'\n'.join(changed) + b'\n')
    reject('encoding.terminal_newline', stderr[:-1])
    need(len(refusals) == len(set(refusals)) == schema_count + 50,
         'all original schema controls plus36 semantic cells,4 joins/exercise and10 encoding controls')
    return dict(inherited=inherited, refusals=refusals)
