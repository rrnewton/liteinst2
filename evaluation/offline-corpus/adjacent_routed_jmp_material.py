#!/usr/bin/env python3
"""Prospective v6 union materials only. No importer, planner or native authority."""
import hashlib
from pathlib import Path
import sys
import types

assert not sys.flags.optimize, 'assertions required'
CAP = 1048576
ADAPTER_SHA = '0ae4995cccbeeb3d414849962b9b946b5e9c3fa3b391cdfd403ea5405730e374'
path = Path(__file__).resolve().with_name('disassembly.py')
with path.open('rb') as stream:
    raw = stream.read(CAP + 1)
assert len(raw) <= CAP and hashlib.sha256(raw).hexdigest() == ADAPTER_SHA
D = types.ModuleType('authenticated_pending_material'); D.__file__ = str(path)
exec(compile(raw, str(path), 'exec'), D.__dict__)
PROFILE = 'offline-whole-authored-adjacent-routed-jmp-short-t3-pending-2g-v1'
FAMILY = 'original-geometry-jcc-or-routed-jmp-v1'
COUNTS = D.COUNTS


def attempt_adjacent_routed_jmp(program, inputs, expected, *, upper, lower, joint):
    """One fixed material transformation; every old input/failure remains visible."""
    assert program in COUNTS
    labels = dict(profile=PROFILE, adjacent_pairs=FAMILY,
                  adjacent_upper=upper, adjacent_lower=lower, adjacent_joint=joint,
                  neighbor_victims='short-only', neighbor_ownership='inherited-t3',
                  pending_selected='full-instruction-ownership', qualification_complete=False)
    if (any(type(n) is not int or not 0 <= n <= 256 for n in (upper, lower, joint))
            or joint > upper):
        return dict(labels, program=program, status='MATERIALS_REFUSED', files={},
                    source_expected_heads=COUNTS[program][0],
                    source_expected_jumps=COUNTS[program][1],
                    roster_checked_heads=None, roster_checked_jumps=None,
                    importer_verified=False,
                    failure=dict(stage='adjacent-budgets', error='ValueError'))
    result = D.attempt(program, inputs, expected, profile=D.SHORT_T3_PENDING_PROFILE)
    result.update(labels)
    if result['status'] == 'MATERIALS_READY':
        rows = result['files']['policy.txt'].decode('ascii').splitlines()
        assert rows[0] == 'LI2DISASM-POLICY 4'
        assert rows[3:6] == ['neighbor-victims short-only', 'neighbor-ownership inherited-t3',
                            'pending-selected full-instruction-ownership']
        rows[0] = 'LI2DISASM-POLICY 6'
        rows[6:6] = ['adjacent-pairs ' + FAMILY,
                     f'adjacent-pair-budgets {upper} {lower} {joint}']
        policy = ('\n'.join(rows) + '\n').encode('ascii')
        if len(policy) > CAP:
            result['status'] = 'MATERIALS_REFUSED'
            result['failure'] = dict(stage='adjacent-policy-bound', error='ValueError')
        result['files']['policy.txt'] = policy
    return result
