#!/usr/bin/env python3
"""Strict component-row predicate; no imports or runs of the component."""
import json


def read(stdout, stderr, returncode):
    if (type(stdout) is not bytes or len(stdout) > 4096 or type(stderr) is not bytes or
            stderr != b'' or type(returncode) is not int or returncode != 0):
        raise ValueError('exact successful bounded component capture')
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError('duplicate component field')
            value[key] = item
        return value
    value = json.loads(stdout, object_pairs_hook=unique)
    fixed = dict(profile='cached_direct_context_component', plans=2, no_envelopes=4,
                 heads=[3, 5], exits=[1, 2], links=[0, 0], directory_rows=10,
                 proof_bytes=364544, key_offset=296, plan_offset=9056,
                 image_mutations=5568, bundle_mutations=11056, tail_refusals=23,
                 owner_refusals=24, lease_refusals=58, models=960,
                 runtime_authority=False, native_credit=False)
    if type(value) is not dict or set(value) != set(fixed) | {'steps', 'aux_steps', 'aux_recoveries'}:
        raise ValueError('exact complete component schema')
    for key, expected in fixed.items():
        actual = value[key]
        if type(actual) is not type(expected) or actual != expected:
            raise ValueError('exact component field: '+key)
        if type(expected) is list and any(type(item) is not int for item in actual):
            raise ValueError('exact component array scalars: '+key)
    for key in ('steps', 'aux_steps', 'aux_recoveries'):
        if type(value[key]) is not int:
            raise ValueError('exact model count type: '+key)
    if not (960 < value['steps'] <= 960*2048 and
            384 < value['aux_steps'] <= 384*2048 and
            value['aux_steps'] < value['steps'] and
            value['aux_recoveries'] == 2*value['aux_steps']):
        raise ValueError('all model steps and two actual auxiliary recoveries per boundary')
    return value
