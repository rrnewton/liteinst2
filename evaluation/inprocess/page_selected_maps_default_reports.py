"""Strict additive maps row; the original generic/REP report stays whole."""
import copy
import hashlib
import json

from page_selected import need
import page_selected_generic_compare as generic
import page_selected_repeat_compare as original

PREFIX = b'LI2_MAPS_VIEW '
KEYS = ('version queries hits refreshes updates invalidations comparisons mismatches unexplained '
        'stack_probes enabled differential poisoned reserved').split()
ACTIVITY = ('hits', 'refreshes', 'stack_probes', 'updates')
PROFILES = ('default', 'differential')


def fields(view, profile):
    need(profile in PROFILES and type(view) is dict and list(view) == KEYS,
         'exact maps profile and complete ordered maps-view schema')
    need(all(type(view[k]) is int and 0 <= view[k] < (1 << (64 if k in KEYS[1:10] else 32))
             for k in KEYS), 'exact unsigned maps counters and flags, without bool or float')
    need(view['version'] == view['enabled'] == 1 and
         view['differential'] == int(profile == 'differential') and
         view['poisoned'] == view['reserved'] == view['mismatches'] == 0,
         'successful exact enabled maps mode, including expected guest refusals')
    need(view['queries'] == view['hits'] + view['refreshes'] and
         view['comparisons'] == (view['hits'] if profile == 'differential' else 0),
         'every query and differential hit accounted')


def parse(stderr, profile):
    need(type(stderr) is bytes and stderr.endswith(b'\n'), 'complete actual report bytes')
    rows = stderr[:-1].split(b'\n')
    need(sum(line.startswith(PREFIX) for line in rows) == 1 and rows[0].startswith(PREFIX) and
         len(rows[0]) <= 2048 and b'\r' not in rows[0],
         'one bounded first maps row, with the complete original report suffix')
    view = json.loads(rows[0][len(PREFIX):], object_pairs_hook=generic.unique,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite maps value')))
    fields(view, profile)
    suffix = b'\n'.join(rows[1:]) + b'\n'
    loader, repeat = original.parse(suffix)
    return loader, repeat, view


def controls(stderr, profile):
    _, _, view = parse(stderr, profile)
    line, suffix = stderr.split(b'\n', 1)
    trials = []
    for key, value in (('version', 2), ('enabled', 0), ('differential', 1-view['differential']),
                       ('poisoned', 1), ('reserved', 1), ('mismatches', 1),
                       ('queries', view['queries']+1), ('comparisons', view['comparisons']+1),
                       ('hits', -1), ('refreshes', 1 << 64), ('unexplained', False),
                       ('stack_probes', 1.0)):
        changed = dict(view); changed[key] = value
        trials.append((key, PREFIX + json.dumps(changed, separators=(',', ':')).encode() + b'\n' + suffix))
    short = dict(view); short.pop('reserved')
    extra = dict(view, unexpected=0)
    trials.extend((('missing', suffix), ('duplicate', line+b'\n'+stderr),
                   ('late', suffix+line+b'\n'), ('truncated', stderr[:-1]),
                   ('short_schema', PREFIX+json.dumps(short).encode()+b'\n'+suffix),
                   ('duplicate_key', line[:-1]+b',"version":1}\n'+suffix),
                   ('wrong_order', PREFIX+json.dumps(dict(reversed(list(view.items())))).encode()+b'\n'+suffix),
                   ('extra_field', PREFIX+json.dumps(extra).encode()+b'\n'+suffix),
                   ('wrong_tag', b'LI2_MAPS_UNKNOWN '+line[len(PREFIX):]+b'\n'+suffix)))
    refused = []
    for name, changed in trials:
        need(changed != stderr, 'actual distinct maps control')
        try:
            parse(changed, profile)
        except ValueError:
            refused.append(name)
        else:
            raise ValueError('accepted maps control: '+name)
    need(len(refused) == len(set(refused)) == 21, 'complete additive maps row controls')
    return dict(refusals=refused, whole_stderr_sha256=hashlib.sha256(stderr).hexdigest(),
                original_suffix_sha256=hashlib.sha256(suffix).hexdigest())


def aggregate(cases, profile):
    need(len(cases) == 20 and all(case['accepted'] is True for case in cases),
         'every original finite case must pass before maps qualification')
    for case in cases:
        fields(case['maps_view'], profile)
    totals = {key: sum(case['maps_view'][key] for case in cases) for key in KEYS[1:10]}
    need(all(totals[key] > 0 for key in ACTIVITY),
         'fixed original cohort demonstrates reuse, refresh, stack probing and protection updates')
    return totals


def aggregate_controls(cases, profile):
    aggregate(cases, profile)
    refused = []
    for key in ACTIVITY:
        changed = copy.deepcopy(cases)
        for case in changed:
            row = case['maps_view']; row[key] = 0
            row['queries'] = row['hits'] + row['refreshes']
            row['comparisons'] = row['hits'] if profile == 'differential' else 0
        try:
            aggregate(changed, profile)
        except ValueError:
            refused.append(key)
        else:
            raise ValueError('accepted absent maps activity: '+key)
    need(tuple(refused) == ACTIVITY, 'all four meaningful cohort activity controls')
    return refused
