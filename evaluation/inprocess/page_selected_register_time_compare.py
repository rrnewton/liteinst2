"""Strict timing-only suffix. Original LOADER/REP/RUN readers remain unchanged."""
import hashlib
import json
import struct
from page_selected import need
from page_selected_register_real import reports as original_reports, completed
from page_selected_register_connected_compare import generic

SCALARS = set(('version status failure_code detail_abs detail_negative mode initialized finalized qualified '
    'observer_error observer_detail_abs observer_detail_negative completed publications hits full_misses '
    'clock_calls clock_id sites samples').split())
ARRAYS = dict(image_hash=4, resolution=4, pending=8, current=15)
PREFIXES = (b'LI2_RUN_TIME_SITE ', b'LI2_RUN_TIME_SAMPLE ', b'LI2_RUN_TIME ')


def decode(data):
    return json.loads(data, object_pairs_hook=generic.unique,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite timing value')))


def integers(values, size):
    need(type(values) is list and len(values) == size and
         all(type(x) is int and 0 <= x < 1 << 64 for x in values), 'exact unsigned timing array')


def parse(data):
    need(type(data) is bytes and 0 < len(data) <= 65536 and data.endswith(b'\n'), 'bounded complete reports')
    lines = data.splitlines()
    first = next((i for i, line in enumerate(lines) if any(line.startswith(p) for p in PREFIXES)), len(lines))
    need(first in (2, 3) and first < len(lines) and all(len(x)+1 <= 4096 for x in lines), 'explicit report suffix')
    loader, repeat, run = original_reports(b'\n'.join(lines[:first])+b'\n')
    sites, samples = [], []
    for line in lines[first:-1]:
        if line.startswith(PREFIXES[0]):
            need(not samples and len(sites) < 64 and len(line)+1 <= 352, 'ordered bounded site rows')
            row = decode(line[len(PREFIXES[0]):]);integers(row, 13);sites.append(row)
        else:
            need(line.startswith(PREFIXES[1]) and len(samples) < 11 and len(line)+1 <= 352,
                 'ordered bounded sample rows')
            row = decode(line[len(PREFIXES[1]):]);integers(row, 15);samples.append(row)
    need(lines[-1].startswith(PREFIXES[2]), 'one final timing summary')
    summary = decode(lines[-1][len(PREFIXES[2]):])
    need(type(summary) is dict and set(summary) == SCALARS | set(ARRAYS), 'exact timing summary schema')
    for name in SCALARS:
        need(type(summary[name]) is int and 0 <= summary[name] < 1 << 64, 'unsigned timing scalar '+name)
    for name, size in ARRAYS.items():integers(summary[name], size)
    need(summary['version'] == 1 and summary['mode'] in (0, 1, 2) and summary['clock_id'] == 4 and
         summary['sites'] == len(sites) and summary['samples'] == len(samples) and
         all(summary[k] == loader[k] == run[k] for k in ('status', 'failure_code', 'detail_abs', 'detail_negative')),
         'same actual terminal outcome and complete rows')
    need(all(row[0] == 1 and row[1] < 64 and (not i or sites[i-1][1] < row[1]) for i, row in enumerate(sites)),
         'unique ordered actual slots')
    for row in sites:
        _, slot, offset, extent, run_length, count, guard, code, lo, hi, generation, done, hits = row
        source = struct.pack('<QQ', lo, hi)
        need(2 <= run_length < extent <= 15 and 2 <= count <= 14 and 1 <= guard <= 15 and
             run_length+guard <= extent and code > 0 and source[extent:] == bytes(16-extent) and
             generation == slot+1 and done >= hits, 'closed literal site identity and counts')
    return dict(loader=loader, repeat=repeat, run=run, summary=summary, sites=sites, samples=samples)


def key(row):
    return dict(offset=row[2], source_length=row[3], run_length=row[4], instructions=row[5],
                guard_length=row[6], guard_code=row[7], source_hex=struct.pack('<QQ', row[8], row[9]).hex())


def qualify(report, image_sha256, mode, selected=None):
    """Call only after actual exit zero and byte-exact native output equality."""
    completed(report['loader'], report['repeat'], report['run'])
    s, sites, samples = report['summary'], report['sites'], report['samples']
    need(mode in (1, 2) and s['mode'] == mode and s['initialized'] == s['finalized'] == s['qualified'] == 1 and
         s['observer_error'] == s['observer_detail_abs'] == s['observer_detail_negative'] == 0 and not s['pending'][0] and
         struct.pack('<4Q', *s['image_hash']).hex() == image_sha256 and s['resolution'][:2] == [0, 0] and
         s['resolution'][2] * 1000000000 + s['resolution'][3] > 0 and s['resolution'][3] < 1000000000,
         'completed actual observer/image/clock resolution')
    need(s['completed'] == sum(x[11] for x in sites) and s['hits'] == sum(x[12] for x in sites) and
         s['publications'] == len(sites) and all(x[11] == x[12]+1 for x in sites) and
         s['completed'] == s['publications']+s['hits'], 'same-site completion accounting')
    if mode == 1:
        need(s['samples'] == s['clock_calls'] == 0 and not samples, 'discovery has no timed intervals')
        eligible = [row for row in sites if row[12] >= 10]
        need(eligible, 'completed discovery contains an eligible interpreter site')
        offset = min(row[2] for row in eligible)
        matches = [row for row in eligible if row[2] == offset]
        need(len(matches) == 1, 'one unambiguous lowest-offset identity')
        return dict(interpreter_sha256=image_sha256, key=key(matches[0]),
                    rule='lowest interpreter ELF offset with at least ten completed same-site hits',
                    discovery_completed=matches[0][11], discovery_hits=matches[0][12])
    need(type(selected) is dict and selected['interpreter_sha256'] == image_sha256 and
         len(sites) == 1 and key(sites[0]) == selected['key'] and s['publications'] == 1 and
         s['hits'] >= 10 and s['full_misses'] == 0 and len(samples) == 11 and s['clock_calls'] == 33,
         'preselected identical site, one publication, all ten measured hits')
    previous_end = previous_ordinal = previous_borrow = 0
    publish_ns, service_ns = [], []
    for index, row in enumerate(samples):
        version, idx, ordinal, borrow, slot, hit, started, published, complete, attempted, clocks, clock_id, t0, t1, t2 = row
        need(version == 1 and idx == index and ordinal > previous_ordinal and borrow > previous_borrow and
             slot == sites[0][1] and hit == int(index != 0) and started == published == complete == 1 and
             attempted == clocks == 3 and clock_id == 4 and previous_end <= t0 <= t1 <= t2,
             'every sequential actual timestamp retained without normalization')
        publish_ns.append(t1-t0);service_ns.append(t2-t0)
        previous_end, previous_ordinal, previous_borrow = t2, ordinal, borrow
    return dict(clock='CLOCK_MONOTONIC_RAW', clock_id=4, resolution_seconds=s['resolution'][2],
        resolution_nanoseconds=s['resolution'][3], interpreter_sha256=image_sha256, site=selected['key'],
        first_publication_api_ns=publish_ns[0], steady_hit_api_ns=publish_ns[1:],
        first_service_ns=service_ns[0], steady_service_ns=service_ns[1:], samples=11,
        total_completed_hits=s['hits'], dropped_samples=0,
        scope='Service starts after source fetch/plan, immediately before publish; ends after genuine NX exit/reset and before guard dispatch. API subinterval ends before arm. No per-site native baseline.')


def configuration(image_sha256, selected=None):
    image = bytes.fromhex(image_sha256)
    need(len(image) == 32 and any(image), 'exact interpreter SHA-256')
    mode = 1 if selected is None else 2
    fields = ''
    if selected is not None:
        need(selected['interpreter_sha256'] == image_sha256 and set(selected['key']) ==
             {'offset', 'source_length', 'run_length', 'instructions', 'guard_length', 'guard_code', 'source_hex'},
             'frozen discovery identity')
        k = selected['key'];source = bytes.fromhex(k['source_hex'])
        need(len(source) == 16 and 2 <= k['run_length'] < k['source_length'] <= 15 and
             2 <= k['instructions'] <= 14 and 1 <= k['guard_length'] <= 15 and
             k['run_length']+k['guard_length'] <= k['source_length'] and k['guard_code'] > 0 and
             source[k['source_length']:] == bytes(16-k['source_length']), 'literal complete frozen plan')
        for name in ('offset', 'source_length', 'run_length', 'instructions', 'guard_length', 'guard_code'):
            need(type(k[name]) is int and 0 <= k[name] < 1 << 64, 'unsigned frozen field')
            fields += '.'+name+'=UINT64_C('+str(k[name])+'),'
        fields += '.source={'+','.join(str(x) for x in source)+'}'
    return ('/* Exact completed discovery output; no environment override. */\n'
        'static const struct li2_time_config li2_time_configuration={.mode='+str(mode)+
        ',.image_hash={'+','.join(str(x) for x in image)+'},.key={'+(fields or '0')+'}};\n').encode()
