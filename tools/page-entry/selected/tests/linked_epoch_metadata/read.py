"""Exact two actual metadata rows; no instruction execution credit."""
import json

EXPECTED = (
    dict(schema=1, code_forms=131, accepted=1283, old_accepts=53, refusals=26,
         plan_controls=49, none_checks=1283, max_register_rows=4, postseal_equal=1),
    dict(schema=1, linked_code_forms=131, independent_calls=1283, varied_register_calls=5132,
         independent_refusals=27, graph_checks=23, max_heads=64, max_frontiers=8,
         selected_bytes=320, postseal_equal=1),
)

def check(stdout, stderr, exit_code):
    if type(exit_code) is not int or exit_code != 0 or stderr:
        raise ValueError('metadata process must complete without stderr')
    expected = b''.join((json.dumps(x, separators=(',', ':'))+'\n').encode() for x in EXPECTED)
    if stdout != expected:
        raise ValueError('both complete exact original and linked metadata rows required')
    return EXPECTED[1].copy()
