"""Explicit private authority for a reviewed, committed startup source profile.

The root freezes this JSON after the combined source commit. Its SHA is supplied
independently on the command line and bound into the prospective producer plan;
no self-declared receipt map, future hash, or tracked self-reference is accepted.
"""
import hashlib
import json
from pathlib import Path
import re
import types

PROFILE = 'startup-main-independent-verifier-source-v1'


def load(ctx, path, expected):
    path = Path(path)
    if (not path.is_absolute() or path.resolve(strict=True) != path or
            not path.is_relative_to(ctx.ROOT/'ignored') or
            type(expected) is not str or re.fullmatch('[0-9a-f]{64}',expected) is None):
        raise ValueError('explicit canonical private source profile')
    raw = ctx.read(path,cap=1048576)
    if hashlib.sha256(raw).hexdigest() != expected:
        raise ValueError('externally frozen source profile SHA')
    def pairs(items):
        result = {}
        for key,value in items:
            if key in result:
                raise ValueError('duplicate source profile key')
            result[key] = value
        return result
    value = json.loads(raw,object_pairs_hook=pairs)
    if (set(value) != {'schema','profile','source_revision','sources','producer_lock_sha256','verifier_lock_sha256'} or
            value['schema'] != 'LI2STARTUP-SOURCE-PROFILE-1' or value['profile'] != PROFILE or
            type(value['source_revision']) is not str or re.fullmatch('[0-9a-f]{40}',value['source_revision']) is None or
            type(value['sources']) is not dict or not value['sources']):
        raise ValueError('explicit complete source profile shape')
    for digest in [*value['sources'].values(),value['producer_lock_sha256'],value['verifier_lock_sha256']]:
        if type(digest) is not str or re.fullmatch('[0-9a-f]{64}',digest) is None:
            raise ValueError('source profile canonical digest')
    return types.SimpleNamespace(SOURCE_REVISION=value['source_revision'],SOURCE_PINS=value['sources'],
        PRODUCER_LOCK_SHA256=value['producer_lock_sha256'],VERIFIER_LOCK_SHA256=value['verifier_lock_sha256'])
