"""Exact custody scope adapter; original complete ls checks remain authoritative.

Only a source-defined report/profile spelling is adapted. Raw stderr remains
retained by the runner; no custody-work counters are inferred from lease work.
"""
import sys
sys.dont_write_bytecode = True
import json
import page_default_ls_release_lease_reports as lease

PROFILE = 'page-default-ls-sealed-custody-release-performance-v1'
SCOPE = 'partial_selected_sealed_page_custody'
def need(ok, message):
    if not ok: raise ValueError(message)

def check(stderr, pid, exit_code, parent, old, base):
    need(type(stderr) is bytes and stderr.endswith(b'\n'), 'complete actual custody application reports')
    rows, changed = [], 0
    for line in stderr[:-1].split(b'\n'):
        prefix, sep, raw = line.partition(b' ')
        if prefix == b'LI2_LOADER':
            need(sep == b' ', 'actual custody loader separator')
            value = json.loads(raw, object_pairs_hook=base.unique,
                               parse_constant=lambda x: need(False, 'nonfinite report constant'))
            need(type(value) is dict and value['scope'] == SCOPE, 'exact custody application loader scope')
            value['scope'] = 'partial_selected_same_page_tf_lease'
            line = prefix + b' ' + json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
            changed += 1
        rows.append(line)
    need(changed == 1, 'exactly one genuine custody application loader row')
    return lease.check(b'\n'.join(rows) + b'\n', pid, exit_code, parent, old, base)

counters = lease.counters

def project(value, receipt):
    need(receipt['profile'] == PROFILE, 'explicit custody application performance profile')
    # The old projection rechecks every accepted sample's actual lease counters.
    # Adapt only its exact profile discriminator, preserving all other fields.
    lease.project(value, dict(receipt, profile=lease.PROFILE))
    value['profile'] = PROFILE
    interval = receipt.get('interval_qualification')
    if interval is not None:
        need(interval['commands'] == 45 and interval['actual_children'] == 17 and
             interval['normal_children'] == 8 and interval['full_state_pairs'] == 2 and
             interval['required_protocol_failures'] == 5 and interval['required_pre_exec_refusals'] == 4,
             'complete authenticated custody interval qualification')
        value['custody_interval_qualification'] = {k: interval['receipt'][k] for k in ('bytes', 'sha256')}
    else:
        need(not value['performance_credit'], 'no custody application performance without complete finite authority')
        value['custody_interval_qualification'] = None
    value['custody_scope'] = ('Successful real ls with the exactly qualified unobserved custody artifact; '
        'global lease counters retain their original meanings. No application-specific retained-proof '
        'count is observed. Process-path latency and admission-work intervals remain distinct; '
        'interval microfixture results and historical runs do not establish ls speedup.')
