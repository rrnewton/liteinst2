"""Strict actual causal-test terminals; original success readers stay unchanged."""
import json

from page_selected import need
from loop_ro_certificate_reports import PREFIXES, FIELDS
from persistent_loop_effects_counter_terminal import counters

CONTROL_PREFIX = b'LI2_LOOP_RO_CONTROL '
ORACLE_PREFIX = b'LI2_LOOP_RO_ORACLE '
CONTROL_FIELDS = ('version', 'control', 'index', 'kind', 'expected', 'actual', 'restored')
ORACLE_FIELDS = ('version', 'control', 'status', 'failure_code', 'initialized',
    'started', 'complete', 'failure', 'checks', 'restorations', 'passed',
    'root_serial', 'generation', 'epoch', 'source_entry', 'byte_warm',
    'byte_phase', 'byte_build_serial')
ROSTERS = {
    'byte': ((1, 3303),) * 6 + ((2, 0),) * 11 + ((1, 3303),) +
        ((3, 14),) * 2 + ((4, 1), (5, 3303)),
    'history': ((1, 0),) * 29 + ((3, 14),) * 3 + ((4, 1), (1, 0), (5, 0)),
}


def row(line, prefix, fields, *, version=1):
    need(type(line) is bytes and line.startswith(prefix) and len(line) < 4096,
         'bounded actual causal-test terminal row')
    values = json.loads(line[len(prefix):], object_pairs_hook=list)
    need(type(values) is list and all(type(v) is tuple and len(v) == 2 for v in values)
         and tuple(v[0] for v in values) == fields,
         'whole ordered unique causal-test fields')
    value = dict(values)
    need(all(type(v) is int and 0 <= v < 1 << 64 for v in value.values())
         and value['version'] == version and line == prefix +
         json.dumps(value, separators=(',', ':'), allow_nan=False).encode(),
         'canonical unsigned actual causal-test values')
    return value


def check(stderr, mode):
    need(type(stderr) is bytes and stderr.endswith(b'\n') and mode in ROSTERS,
         'whole actual causal-test stream and explicit suite')
    lines = stderr[:-1].split(b'\n')
    positions = []
    certificate = []
    for prefix, fields in zip(PREFIXES, FIELDS, strict=True):
        found = [i for i, line in enumerate(lines) if line.startswith(prefix)]
        need(len(found) == 1, 'one actual byte/RO/history row')
        positions.append(found[0]); certificate.append(row(lines[found[0]], prefix, fields))
    control = 1 if mode == 'byte' else 2
    roster = ROSTERS[mode]
    count = 22 if control == 1 else 35
    need(len(roster) == count, 'fixed complete actual mutation population')
    controls_at = [i for i, line in enumerate(lines) if line.startswith(CONTROL_PREFIX)]
    oracle_at = [i for i, line in enumerate(lines) if line.startswith(ORACLE_PREFIX)]
    first = positions[0]
    need(positions == list(range(first, first + 3)) and
         controls_at == list(range(first + 3, first + 3 + count)) and
         oracle_at == [first + 3 + count] and first > 0 and
         first + 4 + count < len(lines) and
         lines[first - 1].startswith(b'LI2_PF_REFUSALS ') and
         lines[first + 4 + count].startswith(b'LI2_PERSISTENT_SUBENTRY '),
         'exact certificate/control/oracle insertion at the original report boundary')
    controls = []
    for index, (at, (kind, expected)) in enumerate(zip(controls_at, roster, strict=True)):
        value = row(lines[at], CONTROL_PREFIX, CONTROL_FIELDS)
        need(value == dict(version=1, control=control, index=index, kind=kind,
             expected=expected, actual=expected, restored=1),
             'actual control result and whole restoration before advancing')
        controls.append(value)
    oracle = row(lines[oracle_at[0]], ORACLE_PREFIX, ORACLE_FIELDS)
    need(oracle['control'] == control and oracle['initialized'] == oracle['started'] ==
         oracle['complete'] == 1 and oracle['failure'] == 0 and
         oracle['checks'] == count and oracle['restorations'] == count + 1 and
         oracle['passed'] == (1 << count) - 1 and oracle['root_serial'] > 0 and
         oracle['generation'] > 0 and oracle['epoch'] > 0 and
         oracle['source_entry'] == 0x4000200,
         'complete exact focal suite, actual issued identity and all restored baselines')
    if control == 1:
        need(oracle['byte_warm'] in (0, 1) and oracle['byte_phase'] in (4, 5, 6, 7, 8, 11)
             and oracle['byte_build_serial'] > 0,
             'record actual byte-decision context without inferring warm execution')
    else:
        need(oracle['byte_warm'] == oracle['byte_phase'] == oracle['byte_build_serial'] == 0,
             'history suite makes no byte-context observation')
    need(all(v['status'] == 125 and v['failure_code'] == 3303
             for v in (*certificate, oracle)),
         'literal deliberate terminal failure after the complete restored suite')
    byte, ro, history = certificate
    scan = 106 * 4096
    need(byte['differential'] == history['differential'] == 1 and
         byte['bytes_per_complete_scan'] == scan and
         byte['decisions'] == byte['hits'] + byte['misses'] == byte['full_scans'] and
         byte['full_scan_errors'] == byte['disagreements'] == (control == 1) and
         byte['full_scan_bytes'] == (byte['full_scans'] - byte['full_scan_errors']) * scan and
         byte['postseal_bytes'] == byte['issues'] * scan and byte['issues'] > 0 and
         byte['last_failure'] == byte['last_full_result'] == 0 and
         byte['abort_invalidations'] == history['abort_invalidations'] == 1 and
         byte['invalidations'] == byte['issues'] == ro['mirror_opens'] == ro['mirror_seals'],
         'real byte checks, exact deliberate disagreement, restored last baseline and terminal invalidation')
    need(ro['initialized'] == 1 and 0 < ro['readonly_calls'] <= ro['query_attempts'] <= ro['requested_pages']
         and history['issues'] == history['invalidations'] and
         history['full_calls'] == history['misses'] + history['hits'] and
         history['differential_checks'] == history['hits'],
         'actual shared queries and every-hit uncached history work remain counted')
    if control == 1:
        need(byte['decisions'] >= 42 and byte['hits'] >= 24 and byte['misses'] >= 18 and
             byte['live_query_errors'] == 1 and ro['query_errors'] == 5 and
             history['decisions'] == history['hits'] + history['misses'] and
             history['errors'] == history['disagreements'] == 0,
             'all byte-suite calls, one actual alias-query failure and five RO-query failures')
    else:
        need(byte['live_query_errors'] == 0 and ro['query_errors'] == 7 and
             history['decisions'] >= 65 and history['hits'] >= 38 and
             history['errors'] == 20 and history['disagreements'] == 1 and
             history['decisions'] == history['hits'] + history['misses'] + history['errors'] + 7 and
             history['restored_bytes'] > 0,
             'all history outcomes, six root refusals and the interrupted outer decision')
    original = b'\n'.join(lines[:first] + lines[first + count + 4:]) + b'\n'
    raw = counters(original)
    need(all(v['status'] == 125 and v['failure_code'] == 3303 for v in raw.values()
             if 'status' in v and 'failure_code' in v),
         'all original typed terminal rows retain the same failed outcome')
    domain = raw['LI2_PERSISTENT_UNREGISTERED']
    need(domain['detail_abs'] == 8800 + control and domain['detail_negative'] == 0 and
         domain['first_error'] == 3303 and domain['phase'] == 15 and domain['busy'] == 1 and
         raw['LI2_LOOP_RUNTIME']['scope'] == raw['LI2_LOOP_EFFECTS']['scope'] == 0,
         'ordinary terminal abort with exact suite detail, no resumed execution or decoder scope')
    return dict(profile='loop-ro-causal-oracle-v1', suite=mode, controls=controls, oracle=oracle,
        byte_certificate=byte, readonly_queries=ro, history_certificate=history,
        terminal_counters=raw, expected_process_exit=125, application_completed=False,
        warm_generated_admission_proven=False, owner_credit=False,
        qualification_credit=False, performance_credit=False)
