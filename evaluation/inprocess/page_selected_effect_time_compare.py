"""Strict effect/TRACE timing composition; publication and block round trips.

The old timing parser and public APIs remain unchanged. The enclosing evaluator
must establish actual process/output, source, build, namespace and image custody.
"""
import struct
from page_selected import need
import page_selected_effect_ls_reports as effect_reports
from page_selected_register_time_compare import (
    SCALARS, ARRAYS, PREFIXES, decode, integers, key, configuration,
)


def _timing_rows(lines, loader, run):
    """Original timing suffix arithmetic, after the complete effect checker."""
    sites, samples = [], []
    for line in lines[:-1]:
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
    return dict(summary=summary, sites=sites, samples=samples)


def _recurring(report, image_sha256, mode, selected=None):
    """Called only after full current effect completion and new timing rows join."""
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
    publish_ns, roundtrip_ns = [], []
    for index, row in enumerate(samples):
        version, idx, ordinal, borrow, slot, hit, started, published, complete, attempted, clocks, clock_id, t0, t1, t2 = row
        need(version == 1 and idx == index and ordinal > previous_ordinal and borrow > previous_borrow and
             slot == sites[0][1] and hit == int(index != 0) and started == published == complete == 1 and
             attempted == clocks == 3 and clock_id == 4 and previous_end <= t0 <= t1 <= t2,
             'every sequential actual timestamp retained without normalization')
        publish_ns.append(t1-t0);roundtrip_ns.append(t2-t0)
        previous_end, previous_ordinal, previous_borrow = t2, ordinal, borrow
    return dict(clock='CLOCK_MONOTONIC_RAW', clock_id=4, resolution_seconds=s['resolution'][2],
        resolution_nanoseconds=s['resolution'][3], interpreter_sha256=image_sha256, site=selected['key'],
        first_publication_api_ns=publish_ns[0], hit_publication_api_ns=publish_ns[1:],
        first_block_roundtrip_ns=roundtrip_ns[0], hit_block_roundtrip_ns=roundtrip_ns[1:], samples=11,
        copied_instructions_per_roundtrip=selected['key']['instructions'],
        total_completed_hits=s['hits'], dropped_samples=0,
        scope='Block round trip starts after source fetch/plan, immediately before publication; ends after genuine generated-block exit/reset and before guard dispatch. Publication API subinterval ends before arm. NX and TRACE origins remain separately observed. No native per-site baseline or whole-application steady-state throughput.')


ORIGIN_PREFIX = b'LI2_RUN_TIME_ORIGIN '
ENTRY_PREFIX = b'LI2_ENTRY_TIME '


def _origins(lines, samples):
    need(len(lines) == len(samples) <= 11, 'one retained actual origin for every sample')
    origins = []
    for index, (line, sample) in enumerate(zip(lines, samples, strict=True)):
        need(line.startswith(ORIGIN_PREFIX) and len(line)+1 <= 352,
             'ordered bounded actual origin rows')
        row = decode(line[len(ORIGIN_PREFIX):]);integers(row, 7)
        version, idx, ordinal, borrow, slot, signal, code = row
        need(version == 1 and idx == index == sample[1] and
             (ordinal, borrow, slot) == (sample[2], sample[3], sample[4]) and
             (signal, code) in ((11, 2), (5, 2)),
             'exact sample identity and genuine NX or TRACE ingress')
        origins.append(row)
    return origins


def parse(data, pid, exit_code, parent):
    """First validate every current effect/TRACE row; then the exact timing suffix."""
    need(type(data) is bytes and 0 < len(data) <= 16 << 20 and data.endswith(b'\n'),
         'bounded complete effect timing reports')
    lines = data[:-1].split(b'\n')
    need(all(0 < len(line)+1 <= 4096 and b'\r' not in line for line in lines),
         'complete bounded source-emitted report lines')
    prefixes = PREFIXES+(ORIGIN_PREFIX, ENTRY_PREFIX)
    first = next((i for i, line in enumerate(lines)
                  if any(line.startswith(prefix) for prefix in prefixes)), len(lines))
    need(0 < first < len(lines), 'separate complete effect prefix and timing suffix')
    prefix = b'\n'.join(lines[:first])+b'\n'
    effect, effect_summary = effect_reports.check(prefix, pid, exit_code, parent)
    suffix = lines[first:]
    need(len(suffix) >= 2 and suffix[-2].startswith(PREFIXES[2]) and
         suffix[-1].startswith(ENTRY_PREFIX), 'exact final run and entry timing rows')
    body = suffix[:-2]
    first_origin = next((i for i, line in enumerate(body)
                         if line.startswith(ORIGIN_PREFIX)), len(body))
    timing = _timing_rows(body[:first_origin]+[suffix[-2]], effect['loader'], effect['run'])
    origins = _origins(body[first_origin:], timing['samples'])
    entry = decode(suffix[-1][len(ENTRY_PREFIX):])
    _entry(entry, effect, timing)
    return dict(raw=data, pid=pid, exit_code=exit_code, parent=parent,
                effect=effect, effect_summary=effect_summary, origins=origins,
                entry=entry, **timing)


def qualify(report, image_sha256, mode, selected=None, *, interpreter_entry_offset, entry_bytes):
    """Requires actual exit/output custody from the enclosing evaluator."""
    need(type(report) is dict, 'complete parsed effect timing report')
    current = parse(report['raw'], report['pid'], report['exit_code'], report['parent'])
    need(current == report, 'all parsed timing and effect values retain the actual report bytes')
    result = _recurring(current, image_sha256, mode, selected)
    entry = _entry_qualify(current, image_sha256, mode, interpreter_entry_offset, entry_bytes)
    if mode == 1:
        return result
    result['entry_to_first_closed_unit'] = entry
    result['sample_origins'] = [
        dict(index=row[1], ordinal=row[2], borrow=row[3], slot=row[4],
             signal=row[5], code=row[6], origin='NX' if row[5] == 11 else 'TRACE')
        for row in current['origins']]
    return result


ENTRY_SCALARS = set(('version status failure_code detail_abs detail_negative mode initialized '
    'started ingress armed complete qualified observer_error observer_detail_abs '
    'observer_detail_negative clock_attempted clock_complete clock_id route instructions_known '
    'instructions repeat_iterations native_pages native_refaults').split())
ENTRY_ARRAYS = dict(identity=9, closure=5, ns=2, clock_results=4,
                    maps_start_before=10, maps_start_after=10,
                    maps_end_before=10, maps_end_after=10)
ENTRY_ROUTES = {4:'original_step'}
ENTRY_OFFSET = 0x1f010
ENTRY_BYTES = bytes.fromhex('4889e7e8680d0000')


def _entry(entry, effect, timing):
    need(type(entry) is dict and set(entry) == ENTRY_SCALARS | set(ENTRY_ARRAYS),
         'exact entry-to-first-closed-unit schema')
    for name in ENTRY_SCALARS:
        need(type(entry[name]) is int and 0 <= entry[name] < 1 << 64,
             'unsigned entry timing scalar '+name)
    for name, size in ENTRY_ARRAYS.items():integers(entry[name], size)
    need(entry['version'] == 1 and entry['mode'] in (1, 2) and
         entry['mode'] == timing['summary']['mode'] and entry['clock_id'] == 4 and
         all(entry[k] == effect['loader'][k] == timing['summary'][k]
             for k in ('status', 'failure_code', 'detail_abs', 'detail_negative')),
         'same actual successful effect outcome and explicit timing mode')
    need(entry['initialized'] == entry['qualified'] == 1 and
         entry['observer_error'] == entry['observer_detail_abs'] == entry['observer_detail_negative'] == 0,
         'actual initialized and qualified first-window observer')
    if entry['mode'] == 1:
        fixed = {'version', 'mode', 'initialized', 'qualified', 'clock_id'}
        need(all(entry[k] == 0 for k in ENTRY_SCALARS-fixed) and
             all(not any(entry[k]) for k in ENTRY_ARRAYS),
             'discovery has no entry clocks, route or fabricated state observations')
        return
    need(all(entry[k] == 1 for k in ('started', 'ingress', 'armed', 'complete')) and
         entry['clock_attempted'] == entry['clock_complete'] == 2 and
         entry['clock_results'] == [0, 0, 0, 0] and entry['ns'][0] <= entry['ns'][1],
         'both separate RAW entry clocks and actual closed-unit completion')
    need(entry['route'] == 4 and entry['instructions_known'] == entry['instructions'] == 1 and
         entry['repeat_iterations'] == entry['native_pages'] == entry['native_refaults'] == 0,
         'only the authenticated first interpreter MOV completes through original step')
    pc, offset, page, allocation, generation, file_offset, backing, handler, event = entry['identity']
    start_sequence, finish_sequence, post_pc, finish_event, effect_kind = entry['closure']
    need(0 < pc <= (1 << 64)-4 and offset <= pc and page == (pc & ~4095) and file_offset % 4096 == 0 and
         allocation > 0 and generation > 0 and backing == 1 and handler > 0 and event > 0,
         'actual original interpreter entry and sealed allocated source page')
    need(start_sequence > 0 and finish_sequence == start_sequence and post_pc == pc+3 and
         finish_event > event and effect_kind == 0,
         'same first step owner completes at the unexecuted CALL on a later genuine event')
    for point in ('start', 'end'):
        before, after = entry['maps_'+point+'_before'], entry['maps_'+point+'_after']
        need(before == after and before[6] in (0, 1) and before[7] in (0, 1) and
             before[8:] == [0, 0], 'whole maps state unchanged across each private clock')
    need(entry['maps_start_before'][6] == 0, 'entry stamp precedes an active application handler')
    need(entry['maps_end_before'][4] > handler and entry['maps_end_before'][6] == 1,
         'completed original step uses its later active maps handler')


def _entry_qualify(report, image_sha256, mode, interpreter_entry_offset, entry_bytes):
    entry = report['entry']
    need(type(interpreter_entry_offset) is int and interpreter_entry_offset == ENTRY_OFFSET and
         type(entry_bytes) is bytes and entry_bytes == ENTRY_BYTES and
         entry['mode'] == mode and struct.pack('<4Q', *report['summary']['image_hash']).hex() == image_sha256,
         'same authenticated interpreter ELF has exact scoped e_entry and mapped MOV/CALL bytes')
    if mode == 1:
        return None
    need(entry['identity'][1] == interpreter_entry_offset,
         'original entry equals e_entry from the exact independently authenticated interpreter ELF')
    return dict(clock='CLOCK_MONOTONIC_RAW', clock_id=4,
        entry_to_first_closed_unit_ns=entry['ns'][1]-entry['ns'][0],
        route=ENTRY_ROUTES[entry['route']], instructions_known=bool(entry['instructions_known']),
        instructions=entry['instructions'] if entry['instructions_known'] else None,
        repeat_iterations=entry['repeat_iterations'], native_pages=entry['native_pages'],
        native_refaults=entry['native_refaults'], effect_kind=entry['closure'][4],
        interpreter_sha256=image_sha256, interpreter_elf_offset=entry['identity'][1],
        source_file_offset=entry['identity'][5], clocks=2,
        scope='Starts after li2_boot and before original interpreter state restoration/transfer; ends after the exact first MOV RSP to RDI completes through genuine original-step TRACE, revoke and release, before the following CALL executes. Includes instrumentation, signal and scheduling work. No process-launch, pure page-fault or whole-application steady-state interval.')
