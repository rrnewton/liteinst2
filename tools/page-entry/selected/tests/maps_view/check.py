"""Finite actual-TU component only; no runtime/entry or performance credit."""
import json

KEYS = ('version mode cases partial_errno alias_refusals nested_updates stack_growth syscall_stack_growth stack_split_retired '
        'mismatch_refusal poison_refusal cleanup_maps cleanup_fds disabled_refusal '
        'anchor_fallback persona_calls stats').split()
ROWS = (
    [12, 12, 2, 1, 1, 1, 1, 0, 0, 3, 1, 0, 0, 0],
    [2, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0],
    [2, 0, 0, 0, 0, 0, 0, 1, 1, 2, 0, 0, 0, 0],
    [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0],
    [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1],
    [1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0],
)
# queries,hits,refreshes,updates,comparisons,mismatches,unexplained,
# stack_probes,enabled,differential,poisoned,reserved. Invalidations is retained.
STATS = (
    [25, 9, 16, 5, 9, 0, 4, 5, 1, 1, 0, 0],
    [5, 1, 3, 0, 2, 1, 0, 0, 1, 1, 1, 0],
    [5, 1, 3, 0, 2, 1, 0, 0, 1, 1, 1, 0],
    [1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [4, 0, 4, 0, 0, 0, 0, 0, 1, 1, 0, 0],
)

INVALIDATIONS = (21, 2, 2, 0, 0, 2)

def check(stdout, stderr, exit_status, mode):
    def need(v):
        if not v:
            raise ValueError('exact maps-view component result')
    need(type(mode) is int and 0 <= mode < 6 and stderr == b'')
    need(type(exit_status) is int and exit_status == (0 if mode in (0, 5) else 125))
    need(type(stdout) is bytes and 0 < len(stdout) <= 2048)
    def unique(pairs):
        need(len(pairs) == len({k for k, _ in pairs}))
        return dict(pairs)
    value = json.loads(stdout, object_pairs_hook=unique)
    need(json.dumps(value, separators=(',', ':')).encode() + b'\n' == stdout)
    need(type(value) is dict and list(value) == KEYS)
    need(all(type(value[k]) is int and 0 <= value[k] < 2**32 for k in KEYS[:-1]))
    need([value[k] for k in KEYS[:-1]] == [1, mode] + ROWS[mode])
    s = value['stats']
    need(type(s) is list and len(s) == 13)
    need(all(type(x) is int and 0 <= x < 2**(64 if i < 9 else 32) for i, x in enumerate(s)))
    need(s[:4] + s[5:] == STATS[mode])
    need(s[4] == INVALIDATIONS[mode] and s[4] >= s[3])
    return value
