#!/usr/bin/env python3
"""Finite actual register-run publication, cache-hit and full-capacity oracle."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import struct
import subprocess
import sys

sys.dont_write_bytecode = True
from checks import source
from run import hardware
from page_selected import ENV, fact, need, save, elf
from page_selected_components import plain_executable
from page_selected_generic_build import Build, PROFILES as BUILD_PROFILES
from page_selected_process import invoke

REPO = Path(__file__).resolve().parents[2]
FIXTURE = REPO/'tools/page-entry/selected/tests/register_run'
PROFILES = dict(BUILD_PROFILES, fixture_link=[5, 512 << 20, 16 << 20, 15],
                native=[5, 512 << 20, 16 << 20, 15])


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()


def executable_layout(path, symbols):
    """Sizes come from the actual retained ELF's symbols, not the record header."""
    names = {'header', 'samples', 'li2_register_records', 'capacities', 'tail'}
    found = {}
    _, _, segments = elf(path)
    for line in symbols.decode('ascii').splitlines():
        fields = line.split()
        if len(fields) != 4 or fields[3] not in names:
            continue
        address, size, kind, name = fields
        need(name not in found and re.fullmatch('[0-9a-fA-F]+', address) and
             re.fullmatch('[0-9a-fA-F]+', size) and kind in ('b', 'B'),
             'unique actual fixture BSS symbol')
        address, size = int(address, 16), int(size, 16)
        need(size > 0 and sum(p[0] == 1 and p[1] == 6 and
             p[3] <= address < address+size <= p[3]+p[6] for p in segments) == 1,
             'whole symbol within one real writable NX load segment')
        found[name] = {'address': address, 'bytes': size}
    need(set(found) == names, 'all actual retained record symbols')
    intervals = sorted((v['address'], v['address']+v['bytes']) for v in found.values())
    need(all(a[1] <= b[0] for a, b in zip(intervals, intervals[1:])), 'disjoint ELF record objects')
    size = {k: v['bytes'] for k, v in found.items()}
    need(size['header'] == 216 and size['samples'] % 21 == 0 and
         size['li2_register_records'] % 6 == 0 and size['capacities'] == 64*192,
         'actual closed C object extents')
    layout = {'header_bytes': size['header'], 'startup_bytes': size['samples']//21,
              'record_bytes': size['li2_register_records']//6, 'records_kept': 6,
              'capacity_row_bytes': size['capacities']//64, 'capacity_rows': 64,
              'tail_bytes': size['tail']}
    total = layout['header_bytes']+layout['startup_bytes']+size['li2_register_records']+size['capacities']+size['tail']
    need(0 < layout['startup_bytes'] < layout['record_bytes'] and total < 16 << 20,
         'actual finite complete record bound')
    return {'symbols': found, 'sizes': layout, 'total_bytes': total}


def record_sections(data, header, layout, capacity):
    need(all(header[k] == v for k, v in layout['sizes'].items()) and
         len(data) == layout['total_bytes'], 'record sizes exactly match retained executable')
    at = header['header_bytes']
    startup = data[at:at+header['startup_bytes']]; at += header['startup_bytes']
    records = [data[at+i*header['record_bytes']:at+(i+1)*header['record_bytes']] for i in range(6)]
    at += 6*header['record_bytes']
    rows = data[at:at+64*header['capacity_row_bytes']]; at += 64*header['capacity_row_bytes']
    tail = data[at:]
    need(any(startup) and any(tail), 'retain actual startup and final owner/cache prefix')
    fields = ('ordinal pc stop source_allocation source_generation slot publication_allocation '
              'publication_generation entry slots_used complete_slots attempts hits full_misses '
              'completed_runs native_generation checked reset_complete nx_entries nx_exits').split()
    if not capacity:
        need(all(any(r) for r in records) and not any(rows), 'six full semantic records and no capacity rows')
        return {'full_records': 6, 'capacity_rows': 0, 'capacity_full_hashes_checked': 0}
    need(all(any(r) for r in records[:5]) and not any(records[5]), 'five retained capacity/fallback/hit records')
    parsed, hashes = [], []
    for i in range(64):
        start = i*192
        row = dict(zip(fields, struct.unpack_from('<20Q', rows, start)))
        stamp = rows[start+160:start+192]
        need(row['ordinal'] == row['slot'] == i and
             row['slots_used'] == row['complete_slots'] == row['attempts'] == row['completed_runs'] == i+1 and
             row['hits'] == row['full_misses'] == 0 and
             row['checked'] == row['reset_complete'] == row['nx_entries'] == row['nx_exits'] == 1 and
             row['source_allocation'] > 0 and row['source_generation'] > 0 and row['native_generation'] > 0 and
             row['source_generation'] != row['native_generation'] and row['stop'] == row['pc']+2 and
             row['publication_allocation'] == 1 and row['publication_generation'] == i+1 and
             row['entry'] > 0 and row['entry'] % 4096 == 0 and any(stamp),
             'actual completed capacity cycle and distinct source/publication identities')
        parsed.append(row); hashes.append(stamp)
    need(all(r['entry'] == parsed[0]['entry']+i*4096 for i, r in enumerate(parsed)),
         '64 distinct consecutive immutable publication pages')
    for cycle, slot in ((0, 0), (62, 2), (63, 1)):
        need(hashlib.sha256(records[slot]).digest() == hashes[cycle], 'retained complete capacity record digest')
    # Only these three full capacity cycles, plus fallback and hit-after-full,
    # are retained. The other 61 cycle digests are not a full-state replay.
    return {'full_records': 5, 'capacity_rows': 64, 'capacity_full_hashes_checked': 3,
            'capacity_rows_sha256': digest(parsed), 'intermediate_full_records_retained': False}


def publish(path, record, receipt):
    # Small numeric/hash projection. Complete command rows, raw state records,
    # actual ELF/DWARF, tool pins and cleanup outcomes remain private and bound.
    build = record.get('build', {})
    public = {key: record.get(key) for key in (
        'schema_version', 'profile', 'status', 'scope', 'expected_revision', 'started_utc',
        'cpu', 'source', 'source_unchanged', 'hardware', 'totals', 'reproduce', 'bounds')}
    public.update(environment=ENV, private_receipt=fact(receipt),
        command_count=len(record['commands']), commands_sha256=digest(record['commands']),
        case_count=len(record['cases']), cases_sha256=digest(record['cases']),
        inputs_sha256=digest(record.get('inputs_before', {})),
        binaries_sha256=digest(record.get('binaries_before', {})),
        elf_sha256=digest(record.get('elf', {})),
        catalogue=record.get('catalogue'),
        tool_versions=build.get('numeric_versions', {}),
        tool_hashes={name: {k: value[k] for k in ('bytes', 'sha256')}
                     for name, value in build.get('tools', {}).items()},
        build_artifacts_sha256=digest(build.get('artifacts', {})),
        build_status=build.get('status', 'not_started'),
        failure_type=(record.get('error') or '').split(':')[0] or None,
        final_error_count=len(record['final_errors']))
    text = json.dumps(public, sort_keys=True, indent=2, allow_nan=False)+'\n'
    markers = (str(Path.home()), str(REPO), platform.node(), '/home/')
    need(not any(x and len(x) > 1 and x in text for x in markers), 'public private-location guard')
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('x') as output:
        output.write(text)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expect-revision', required=True)
    args = parser.parse_args()
    need(sys.flags.optimize == 0, 'Python assertions must remain enabled')
    need(len(args.expect_revision) == 40 and all(c in '0123456789abcdef' for c in args.expect_revision), 'exact revision')
    need(len(os.sched_getaffinity(0)) == 1, 'one externally reserved CPU')
    cpu = next(iter(os.sched_getaffinity(0)))
    os.chdir(REPO)
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    name = stamp+'-page-selected-register-'+args.expect_revision[:12]
    private = REPO/'target/evaluation/inprocess'/name
    private.mkdir(parents=True, exist_ok=False)
    public = REPO/'evaluation/inprocess/results'/(name+'.json')
    record = {'schema_version': 1, 'profile': 'page-selected-register-oracle-v1', 'status': 'failed',
        'scope': 'Finite actual register-run publication: nine inputs twice, 18 complete native/cache records, 64 real capacity publications, one genuine two-NOP fallback and one hit after full. Intermediate capacity full state is checked by the C fixture but only selected full records and all cycle hashes are retained. No negative publisher-control, connected application, performance or full-B2 claim.',
        'expected_revision': args.expect_revision, 'started_utc': stamp, 'cpu': cpu,
        'source': None, 'source_unchanged': False, 'commands': [], 'cases': [],
        'error': None, 'final_errors': [], 'bounds': PROFILES,
        'totals': {'semantic_pairs': 0, 'semantic_misses': 0, 'semantic_hits': 0,
                   'capacity_publications': 0, 'capacity_hit_after_full': 0, 'capacity_fallbacks': 0,
                   'fallback_trace_events': 0, 'generated_trace_events': 0,
                   'native_references': 0, 'startup_pairs': 0, 'refusal_encodings': 0,
                   'executed_refusal_checks': 0, 'full_semantic_records': 0,
                   'full_capacity_records': 0, 'capacity_rows': 0, 'capacity_record_hashes_checked': 0},
        'reproduce': ['python3', 'evaluation/inprocess/page_selected_register.py',
                      '--expect-revision', args.expect_revision]}
    pins, binaries = {}, {}
    fixtures = {name: private/name for name in ('register-run-0', 'register-run-1', 'register-run-2', 'register-run-3')}
    support = private/'run_support.inc'
    build = None

    def pin(path):
        path = Path(path).resolve()
        value = fact(path)
        need(str(path) not in pins or pins[str(path)] == value, 'pinned input changed')
        pins[str(path)] = value
        return path

    def binary(path):
        path = Path(path).resolve()
        value = fact(path)
        need(str(path) not in binaries or binaries[str(path)] == value, 'artifact changed')
        binaries[str(path)] = value
        return path

    def run(label, argv, expected=0, profile='native', env=None):
        need(all(fact(p) == v for p, v in pins.items()), 'input changed before command')
        need(all(fact(p) == v for p, v in binaries.items()), 'artifact changed before command')
        native = profile == 'native'
        row = {'name': label, 'argv': list(map(str, argv)), 'bounds': PROFILES[profile],
               'expected_exit': expected, 'profile': profile,
               'capture_limit': 8192 if native else 1024*1024,
               'environment': dict(ENV, **(env or {}))}
        record['commands'].append(row)
        out, err = invoke(row, private, cpu, record=native, step=native)
        need(row['exit'] == expected, 'exact process exit: '+label)
        return row, out, err

    try:
        record['source'] = source()
        need(record['source']['revision'] == args.expect_revision, 'revision differs')
        record['hardware'] = hardware(cpu)
        paths = subprocess.check_output(['git', 'ls-files', '-z', 'tools/page-entry', 'evaluation/inprocess'],
                                        cwd=REPO, timeout=5).split(b'\0')
        for value in paths:
            if value and not os.fsdecode(value).startswith('evaluation/inprocess/results/'):
                pin(REPO/os.fsdecode(value))
        build = Build(record, private, pin, binary, run)
        products = build.prepare()
        _, out, err = run('fixture-support', [build.tools['python'], FIXTURE/'prepare.py',
            REPO/'tools/page-entry/selected/tests/generic/fixture.c', support],
            profile='fixture_link', env=build.environment)
        need(not err and json.loads(out) == {
            'source_sha256': 'b0c758cb466ef3f8a35442f7cecbda77eb58c269a7ac90270d769c53440b2910',
            'generated_sha256': 'ecf5a0a0ad92a5ab88ba46c2b11eaff5bba0ff07fb0dfd466c237bc9324f833c',
            'source_bytes': 34870, 'generated_bytes': 34605}, 'exact one-file support generation')
        need(fact(support) == {'bytes': 34605,
            'sha256': 'ecf5a0a0ad92a5ab88ba46c2b11eaff5bba0ff07fb0dfd466c237bc9324f833c'},
            'actual generated support bytes')
        pin(support); record['generated_support'] = fact(support)
        run('fixture-build', [build.tools['sh'], FIXTURE/'build.sh', products['archive'], private, REPO/'tools/page-entry/selected'],
            profile='fixture_link', env=build.environment)
        record['fixtures'], record['elf'], record['layouts'] = {}, {}, {}
        for fixture_name, fixture in fixtures.items():
            binary(fixture)
            record['fixtures'][fixture_name] = fact(fixture)
            record['elf'][fixture_name] = plain_executable(fixture)
            _, out, err = run(fixture_name+'-undefined', [build.tools['nm'], '-u', fixture],
                              profile='inspect', env=build.environment)
            need(not out and not err, 'no undefined fixture symbols')
            _, out, err = run(fixture_name+'-layout', [build.tools['nm'], '-S', '--defined-only', fixture],
                              profile='inspect', env=build.environment)
            need(not err, 'actual ELF symbol inspection stderr')
            record['layouts'][fixture_name] = executable_layout(fixture, out)
        layouts = list(record['layouts'].values())
        need(all(v['sizes'] == layouts[0]['sizes'] and v['total_bytes'] == layouts[0]['total_bytes']
                 for v in layouts), 'same real C layout across four groups')
        need(fact(FIXTURE/'cases.h')['sha256'] ==
             '3a1e2e3564d106e509d83a5b814810716b5d4ed05bf9cf509af11b4b8b5e6e8f',
             'exact nine reviewed literal semantic inputs')
        record['catalogue'] = {'source': fact(FIXTURE/'cases.h'), 'semantic_inputs': 9,
                               'semantic_pairs': 18, 'capacity_pages': 64}
        need(fact(FIXTURE/'OUTCOMES.json')['sha256'] ==
             '3175ba3724a47b94e60eecd1233fb80bc863b9636234823ac383432228408836',
             'exact reviewed four-command outcomes')
        outcomes = json.loads((FIXTURE/'OUTCOMES.json').read_bytes())
        names = outcomes['record']['header_u64_fields']
        need(names == ('magic version header_bytes group record_bytes records_kept startup_bytes '
            'capacity_row_bytes capacity_rows tail_bytes completed_records completed_capacity native_references '
            'published_runs hit_runs fallback_runs source_restorations generated_trace_events fallback_trace_events '
            'refusals xcr0 xsave_bytes fixture_failure owner_failure owner_detail_abs owner_detail_negative complete').split() and
            [c['name'] for c in outcomes['commands']] == list(fixtures) and
            [c['argv'] for c in outcomes['commands']] == [[x] for x in fixtures] and
            [c['exit_code'] for c in outcomes['commands']] == [0]*4 and
            [c['environment_delta'] for c in outcomes['commands']] == [{}]*4 and
            outcomes['native_bounds'] == dict(cpu_seconds=5, address_space_bytes=512 << 20,
                file_bytes=16 << 20, wall_seconds=15, external_cpus=1),
            'exact finite process catalogue/header schema/native bounds')
        for group, case in enumerate(outcomes['commands']):
            name = case['name']; capacity = group == 3
            result = {'name': name, 'accepted': False, 'actual_exit': None,
                      'scope': 'capacity with genuine fallback' if capacity else 'full semantic native/cache pairs'}
            record['cases'].append(result)
            row, out, err = run(name, [fixtures[name]], case['exit_code'], env=case['environment_delta'])
            result['actual_exit'] = row['exit']
            need(out == case['stdout'].encode() and err == case['stderr'].encode(), 'exact fixture output: '+name)
            data = (private/(name+'.record')).read_bytes()
            need(len(data) >= 216, 'retained complete header')
            header = dict(zip(names, struct.unpack_from('<27Q', data)))
            result.update(header=header, record=fact(private/(name+'.record')))
            need(header['magic'] == outcomes['record']['magic'] and header['version'] == 1 and
                 header['group'] == group and all(header[key] == value for key, value in case['expected_header'].items()),
                 'exact completed actual fixture outcome: '+name)
            need(576 <= header['xsave_bytes'] <= 65536 and header['xcr0'] & 3 == 3, 'qualified XSAVE extent')
            result['sections'] = record_sections(data, header, record['layouts'][name], capacity)
            # The unchanged source-authenticated C comparator checks every
            # native/cache GPR/flags/FP/live-selector/stack/data endpoint. Full
            # raw records and the exact ELF/DWARF are retained for later replay.
            result['accepted'] = True
            total = record['totals']
            total['startup_pairs'] += 1
            total['native_references'] += header['native_references']
            total['refusal_encodings'] = header['refusals']
            total['executed_refusal_checks'] += header['refusals']
            total['generated_trace_events'] += header['generated_trace_events']
            total['fallback_trace_events'] += header['fallback_trace_events']
            if capacity:
                total['capacity_publications'] += header['completed_capacity']
                total['capacity_hit_after_full'] += header['hit_runs']
                total['capacity_fallbacks'] += header['fallback_runs']
                total['full_capacity_records'] += result['sections']['full_records']
                total['capacity_rows'] += result['sections']['capacity_rows']
                total['capacity_record_hashes_checked'] += result['sections']['capacity_full_hashes_checked']
            else:
                total['semantic_pairs'] += header['completed_records']
                total['semantic_hits'] += header['hit_runs']
                total['semantic_misses'] += header['published_runs']-header['hit_runs']
                total['full_semantic_records'] += result['sections']['full_records']
        need(record['totals'] == dict(semantic_pairs=18, semantic_misses=9, semantic_hits=9,
            capacity_publications=64, capacity_hit_after_full=1, capacity_fallbacks=1,
            fallback_trace_events=2, generated_trace_events=0, native_references=83,
            startup_pairs=4, refusal_encodings=47, executed_refusal_checks=188,
            full_semantic_records=18, full_capacity_records=5, capacity_rows=64,
            capacity_record_hashes_checked=3) and len(record['cases']) == 4 and
            all(c['accepted'] for c in record['cases']), 'complete semantic and capacity cohort')
        record['status'] = 'passed'
    except BaseException as exc:
        record['error'] = type(exc).__name__+': '+str(exc)
    finally:
        if build is not None:
            try:
                record['final_errors'].extend(build.finish())
                if record['status'] == 'passed':
                    need(record['build']['status'] == 'passed', 'build closure did not pass')
            except BaseException as exc:
                record['final_errors'].append('build closure: '+repr(exc))
        try:
            if support.is_file():
                record['generated_support_after'] = fact(support)
                pin(support)
        except BaseException as exc:
            record['final_errors'].append('generated support retention: '+repr(exc))
        for fixture_name, fixture in fixtures.items():
            try:
                if fixture.is_file():
                    value = fact(fixture)
                    record.setdefault('fixtures_after', {})[fixture_name] = value
                    record.setdefault('fixtures', {}).setdefault(fixture_name, value)
                    binary(fixture)
            except BaseException as exc:
                record['final_errors'].append('fixture retention '+fixture_name+': '+repr(exc))
        record['inputs_before'], record['binaries_before'] = pins, binaries
        for key, before in (('inputs_after', pins), ('binaries_after', binaries)):
            after = record[key] = {}
            for path, expected in before.items():
                try:
                    after[path] = fact(path)
                    need(after[path] == expected, 'final byte identity')
                except BaseException as exc:
                    record['final_errors'].append(path+': '+repr(exc))
        try:
            record['source_unchanged'] = source() == record['source']
            need(record['source_unchanged'], 'source changed')
        except BaseException as exc:
            record['final_errors'].append('source: '+repr(exc))
        if record['final_errors']:
            record['status'] = 'failed'
            if record['error'] is None:
                record['error'] = 'FinalObservationError: input/source/artifact closure failed'
        receipt = private/'receipt.json'
        save(receipt, record)
        publish(public, record, receipt)
    print(json.dumps({'status': record['status'], 'totals': record['totals'],
                      'failure_type': (record['error'] or '').split(':')[0] or None}))
    return 0 if record['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
