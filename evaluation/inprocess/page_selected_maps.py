#!/usr/bin/env python3
"""Handler-local maps acquisition oracle plus unchanged cache regression cohorts."""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import platform
import re
import shutil
import struct
import subprocess
import sys

sys.dont_write_bytecode = True
from checks import source
from run import hardware
from page_selected import ENV, fact, need, save, elf, bridge_check
from page_selected_components import plain_executable
from page_selected_generic_build import Build, PROFILES as BUILD_PROFILES
from page_selected_process import invoke
from page_selected_register import digest, executable_layout
from page_selected_register_controls import control_layout
from page_selected_maps_cohorts import positive, negative
from page_selected_maps_record import check
from page_selected_maps_headers import observe as observe_headers

REPO = Path(__file__).resolve().parents[2]
SELECTED = REPO/'tools/page-entry/selected'
FIXTURE = SELECTED/'tests/maps_phase'
PROFILES = dict(BUILD_PROFILES, fixture_link=[5, 512 << 20, 16 << 20, 15], native=[5, 512 << 20, 16 << 20, 15])
WRAPPER = b'#!/bin/sh\nexec "$LI2_MAPS_CC" -DLI2_MAPS_PHASE_REUSE=1 "$@"\n'


def publish(path, record, receipt):
    build = record.get('build', {})
    public = {k: record.get(k) for k in ('schema_version', 'profile', 'status', 'scope', 'expected_revision',
        'started_utc', 'cpu', 'hardware', 'source', 'source_unchanged', 'bounds', 'totals', 'reproduce')}
    public.update(private_receipt=fact(receipt), environment=ENV,
        command_count=len(record['commands']), commands_sha256=digest(record['commands']),
        input_sha256=digest(record.get('inputs_before', {})), artifact_sha256=digest(record.get('binaries_before', {})),
        cases_sha256=digest(record['cohorts']), tool_versions=build.get('numeric_versions', {}),
        tool_hashes={k: {n: v[n] for n in ('bytes', 'sha256')} for k, v in build.get('tools', {}).items()},
        build_status=build.get('status'), failure_type=(record.get('error') or '').split(':')[0] or None,
        final_error_count=len(record['final_errors']),
        maps_cases=record['cohorts'].get('maps', {}).get('cases', []),
        old_negative_operations_completed=record['cohorts'].get('negative', {}).get('totals', {}).get('completed_operations'),
        old_negative_cases=[{'name': c['name'], 'accepted': c['accepted'], 'actual_exit': c.get('actual_exit'),
            'operation_completed': False if c['accepted'] else None,
            'operation_status': 'failed' if c['accepted'] else 'unverified'}
            for c in record['cohorts'].get('negative', {}).get('cases', [])])
    text = json.dumps(public, sort_keys=True, indent=2, allow_nan=False)+'\n'
    need(not any(x and len(x)>1 and x in text for x in (str(Path.home()), str(REPO), platform.node(), '/home/')),
         'public numeric/hash projection excludes private locations')
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('x') as output: output.write(text)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expect-revision', required=True)
    args = parser.parse_args()
    need(sys.flags.optimize == 0 and re.fullmatch('[0-9a-f]{40}', args.expect_revision) and
         len(os.sched_getaffinity(0)) == 1, 'assertions, exact revision and one reserved CPU')
    cpu = next(iter(os.sched_getaffinity(0)));os.chdir(REPO)
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    name = stamp+'-page-selected-maps-'+args.expect_revision[:12]
    private = REPO/'target/evaluation/inprocess'/name;private.mkdir(parents=True, exist_ok=False)
    public = REPO/'evaluation/inprocess/results'/(name+'.json')
    record = dict(schema_version=1, profile='page-selected-maps-v1', status='failed',
        scope='Nine actual component-handler maps cases plus unchanged four cache-positive/capacity and fourteen failed-operation controls. Macro enabled; all complete private state retained. Component NOP/JMP is source execution, not a direct product-handler/generated-cache phase oracle. Connected and performance qualification remain separate.',
        expected_revision=args.expect_revision, started_utc=stamp, cpu=cpu, source=None, source_unchanged=False,
        commands=[], cohorts={}, error=None, final_errors=[], bounds=PROFILES, totals={},
        reproduce=['python3', 'evaluation/inprocess/page_selected_maps.py', '--expect-revision', args.expect_revision])
    pins, binaries, pending, header_aliases = {}, {}, set(), {}
    build = None
    register_build = record['register_build'] = dict(started=False, command_completed=False, output_before={}, retained={})
    shared = REPO/'target/page-entry/register-run'
    register_names = ('decoder.a', 'decoder.d', 'decoder-rustc.txt', 'decoder-cargo.txt',
                      'cc-version.txt', 'bridge-register-run.so', 'observe')

    def pin(path):
        path = Path(path).resolve();value = fact(path)
        need(str(path) not in pins or pins[str(path)] == value, 'input changed')
        pins[str(path)] = value;return path

    def binary(path):
        path = Path(path).resolve();value = fact(path)
        need(str(path) not in binaries or binaries[str(path)] == value, 'artifact changed')
        binaries[str(path)] = value;return path

    def run(label, argv, expected=0, profile='native', env=None):
        need(all(str(Path(p).resolve(strict=True)) == v for p, v in header_aliases.items()), 'header alias changed before command')
        need(all(fact(p) == v for p, v in pins.items()), 'input changed before command')
        need(all(fact(p) == v for p, v in binaries.items()), 'artifact changed before command')
        row = dict(name=label, argv=list(map(str, argv)), bounds=PROFILES[profile], expected_exit=expected,
            profile=profile, capture_limit=8192 if profile == 'native' else 1024*1024, environment=dict(ENV, **(env or {})))
        record['commands'].append(row)
        out, err = invoke(row, private, cpu, record=profile == 'native', step=profile == 'native')
        need(row['exit'] == expected, 'exact process exit: '+label)
        return row, out, err

    def inspect(name, path, kind):
        binary(path);record.setdefault('elf', {})[name] = plain_executable(path)
        _, out, err = run(name+'-undefined', [build.tools['nm'], '-u', path], profile='inspect', env=build.environment)
        need(out == err == b'', 'no unresolved fixture symbols')
        _, out, err = run(name+'-layout', [build.tools['nm'], '-S', '--defined-only', path], profile='inspect', env=build.environment)
        need(not err, 'actual ELF symbol inspection stderr')
        if kind == 'positive': return executable_layout(path, out)
        if kind == 'negative': return control_layout(path, out)
        rows = [l.split() for l in out.decode('ascii').splitlines() if l.split()[-1:] == ['li2_maps_record']]
        need(len(rows) == 1 and len(rows[0]) == 4 and rows[0][2] in ('b', 'B'), 'unique maps BSS record')
        address, size = int(rows[0][0], 16), int(rows[0][1], 16)
        _, _, segments = elf(path)
        need(0 < size < 16 << 20 and sum(s[0] == 1 and s[1] == 6 and
            s[3] <= address < address+size <= s[3]+s[6] for s in segments) == 1, 'whole actual maps record in writable NX segment')
        return dict(address=address, bytes=size)

    try:
        record['source'] = source();need(record['source']['revision'] == args.expect_revision, 'exact committed revision')
        record['hardware'] = hardware(cpu)
        for value in subprocess.check_output(['git', 'ls-files', '-z', 'tools/page-entry', 'evaluation/inprocess'], timeout=5).split(b'\0'):
            if value and not os.fsdecode(value).startswith('evaluation/inprocess/results/'):pin(REPO/os.fsdecode(value))
        inputs = json.loads((REPO/'evaluation/inprocess/page_selected_maps_inputs.json').read_bytes())
        for item in inputs['bindings']:
            need(fact(pin(REPO/item['path'])) == {k: item[k] for k in ('bytes', 'sha256')}, 'reviewed implementation/helper binding')
        record['reviewed_inputs'] = inputs
        build = Build(record, private, pin, binary, run);products = build.prepare()
        gdb = pin(shutil.which('gdb', path=ENV['PATH']));build.tools['gdb'] = gdb
        record['build']['tools']['gdb'] = dict(path=str(gdb), **fact(gdb))
        # Retain and inspect the actual opt-in production bridge as well as the
        # default reference bridge/archive retained by unchanged Build.
        substitutions = {'$cc_bin': build.tools['cc'], '$source_dir': SELECTED,
            '$parent_dir': SELECTED.parent, '$output_dir': shared}
        observe_headers(SELECTED/'build-register-run.sh', substitutions, [], 'register-headers',
                        build, pin, run, record, header_aliases)
        register_build['output_before'] = {n: fact(shared/n) for n in register_names if (shared/n).is_file()}
        register_build['started'] = True
        run('register-build', [build.tools['sh'], SELECTED/'build-register-run.sh'], profile='build', env=build.environment)
        register_build['command_completed'] = True
        for n in register_names:
            retained = build.retain('register-'+n, shared/n)
            register_build['retained'][n] = dict(path=str(retained), **fact(retained))
        for n in ('decoder.a', 'decoder.d', 'decoder-rustc.txt', 'decoder-cargo.txt', 'cc-version.txt'):
            need(fact(shared/n) == fact(build.retained/n), 'same actual current decoder/tool product')
        bridge = Path(register_build['retained']['bridge-register-run.so']['path'])
        _, out, err = run('register-undefined', [build.tools['nm'], '-u', bridge], profile='inspect', env=build.environment)
        need(out == err == b'', 'no unresolved opt-in bridge imports')
        _, out, err = run('register-maps-symbols', [build.tools['nm'], '--defined-only', bridge], profile='inspect', env=build.environment)
        symbols = [l.split()[-1] for l in out.splitlines() if l.split()]
        need(not err and all(symbols.count(s.encode()) == 1 for s in ('li2_maps_phase_begin', 'li2_maps_before_raw', 'li2_maps_after_raw')) and
             b'li2_maps_test_saturate' not in symbols, 'real production hooks with no test injection API')
        record['register_elf'] = bridge_check(bridge)
        # Preserve old generated bytes, then authenticate both exact inverses.
        positive_dir, negative_dir = private/'positive', private/'negative'
        positive_dir.mkdir();negative_dir.mkdir()
        original = private/'old-support';original.mkdir()
        pending.update(original/n for n in ('positive.inc', 'run_support.inc', 'control_support.inc'))
        _, out, err = run('positive-support', [build.tools['python'], SELECTED/'tests/register_run/prepare.py',
            SELECTED/'tests/generic/fixture.c', original/'positive.inc'], profile='fixture_link', env=build.environment)
        need(not err and json.loads(out) == {
            'source_sha256': 'b0c758cb466ef3f8a35442f7cecbda77eb58c269a7ac90270d769c53440b2910',
            'generated_sha256': 'ecf5a0a0ad92a5ab88ba46c2b11eaff5bba0ff07fb0dfd466c237bc9324f833c',
            'source_bytes': 34870, 'generated_bytes': 34605}, 'exact one-file support generation')
        _, out, err = run('negative-support', [build.tools['python'], SELECTED/'tests/register_run_controls/prepare.py',
            SELECTED/'tests/generic/fixture.c', SELECTED/'tests/register_run/fixture.c', original], profile='fixture_link', env=build.environment)
        expected = {'positive.inc': {'bytes': 34605, 'sha256': 'ecf5a0a0ad92a5ab88ba46c2b11eaff5bba0ff07fb0dfd466c237bc9324f833c'},
            'run_support.inc': {'bytes': 34613, 'sha256': '49f738fab848dc56e64f4d3e52cc9f0e1320d4c968953dfdeaca474c3138f31d'},
            'control_support.inc': {'bytes': 30510, 'sha256': 'bae491633d24aaeb03c59e533d2cb3eae77100d801341d97eb04585309748d7f'}}
        need(not err and json.loads(out) == {n: expected[n] for n in ('run_support.inc', 'control_support.inc')},
             'exact three reviewed adapters')
        for n, value in expected.items():need(fact(pin(original/n)) == value, 'exact old generated support')
        record['support_adapters'] = []
        for scope, src, directory in [('positive', original/'positive.inc', positive_dir), ('controls', original/'run_support.inc', negative_dir)]:
            target = directory/'run_support.inc';pending.add(target)
            _, out, err = run(scope+'-maps-adapter', [build.tools['python'], FIXTURE/'adapt_support.py', src, target], profile='fixture_link', env=build.environment)
            value = json.loads(out);pin(target)
            need(not err and value['scope'] == scope and value['before_sha256'] == fact(src)['sha256'] and
                 value['after_sha256'] == fact(target)['sha256'] and value['bytes'] == fact(target)['bytes'], 'exact generated raw-boundary adapter receipt')
            record['support_adapters'].append(value)
        pending.add(negative_dir/'control_support.inc')
        with (negative_dir/'control_support.inc').open('xb') as f:f.write((original/'control_support.inc').read_bytes())
        need(fact(pin(negative_dir/'control_support.inc')) == expected['control_support.inc'], 'control bodies byte-exact')
        wrapper = private/'cc-maps';pending.add(wrapper);wrapper.write_bytes(WRAPPER);wrapper.chmod(0o700);pin(wrapper)
        wrapped = dict(build.environment, LI2_CC=str(wrapper), LI2_MAPS_CC=str(build.tools['cc']))
        fixtures = {f'register-run-{i}': positive_dir/f'register-run-{i}' for i in range(4)}
        control = negative_dir/'register-run-controls';maps = private/'maps-phase'
        pending.update([*fixtures.values(), control, negative_dir/'publisher-controls.o', maps])
        common = {'$cc_bin': build.tools['cc'], '$decoder_archive': products['archive'],
            '$selected_dir': SELECTED, '$parent_dir': SELECTED.parent}
        for group in range(4):
            observe_headers(SELECTED/'tests/register_run/build.sh', dict(common, **{'$group': group,
                '$fixture_dir': SELECTED/'tests/register_run', '$output_dir': positive_dir}),
                ['-DLI2_MAPS_PHASE_REUSE=1'], 'positive-headers-'+str(group), build, pin, run, record, header_aliases)
        observe_headers(SELECTED/'tests/register_run_controls/build.sh', dict(common, **{
            '$fixture_dir': SELECTED/'tests/register_run_controls', '$output_dir': negative_dir}),
            ['-DLI2_MAPS_PHASE_REUSE=1'], 'negative-headers', build, pin, run, record, header_aliases)
        observe_headers(FIXTURE/'build.sh', dict(common, **{'$fixture_dir': FIXTURE, '$output_dir': private}),
                        [], 'maps-headers', build, pin, run, record, header_aliases)
        run('positive-link', [build.tools['sh'], SELECTED/'tests/register_run/build.sh', products['archive'], positive_dir, SELECTED], profile='fixture_link', env=wrapped)
        run('negative-link', [build.tools['sh'], SELECTED/'tests/register_run_controls/build.sh', products['archive'], negative_dir, SELECTED], profile='fixture_link', env=wrapped)
        run('maps-link', [build.tools['sh'], FIXTURE/'build.sh', SELECTED, private], profile='fixture_link', env=build.environment)
        obj = binary(negative_dir/'publisher-controls.o')
        _, out, err = run('publisher-adapter-import', [build.tools['nm'], '-u', obj], profile='inspect', env=build.environment)
        imports = [l.split()[-1] for l in out.splitlines() if l.split()]
        need(not err and imports.count(b'li2_control_raw') == 1 and b'li2_step_raw' not in imports, 'only publisher object binds named raw-control adapter')
        layouts = {n: inspect(n, p, 'positive') for n, p in fixtures.items()}
        first = next(iter(layouts.values()))
        need(all(x['sizes'] == first['sizes'] and x['total_bytes'] == first['total_bytes'] for x in layouts.values()), 'same actual positive layouts')
        control_shape = inspect('controls', control, 'negative');maps_symbol = inspect('maps', maps, 'maps')
        _, out, err = run('maps-dwarf', [gdb, '-q', '-nx', '-batch', '-iex', 'set auto-load off',
            '-iex', 'set debuginfod enabled off', '-iex', 'maintenance set worker-threads 1',
            '--readnow', '--se='+str(maps), '-x', REPO/'evaluation/inprocess/page_selected_maps_dwarf.py'],
            profile='metadata', env=build.environment)
        need(not err, 'file-only DWARF stderr');layout = json.loads(out)
        need(layout['kind'] == 'struct' and layout['bytes'] == maps_symbol['bytes'], 'DWARF and actual ELF symbol agree')
        record['maps_layout'] = layout;record['maps_symbol'] = maps_symbol
        # Exact old cohort bodies/parsers, unchanged semantic errors and totals.
        pos = record['cohorts']['positive'] = dict(cases=[], totals={k: 0 for k in (
            'semantic_pairs semantic_misses semantic_hits capacity_publications capacity_hit_after_full capacity_fallbacks '
            'fallback_trace_events generated_trace_events native_references startup_pairs refusal_encodings executed_refusal_checks '
            'full_semantic_records full_capacity_records capacity_rows capacity_record_hashes_checked').split()}, layouts=layouts)
        positive(SELECTED/'tests/register_run', pos, private, fixtures, run)
        neg = record['cohorts']['negative'] = dict(cases=[], totals={k: 0 for k in (
            'verified_failure_controls failed_operations completed_operations generated_executions native_reference_captures '
            'startup_pairs refusal_encodings executed_refusal_checks explicit_raw_failure_injections actual_injected_signals').split()}, layout=control_shape)
        negative(SELECTED/'tests/register_run_controls', neg, private, control, run)
        new = record['cohorts']['maps'] = dict(cases=[])
        outcomes = json.loads((FIXTURE/'OUTCOMES.json').read_bytes())
        need(outcomes['bounds'] == dict(external_cpus=1, cpu_seconds=5, address_space_bytes=512 << 20,
             file_bytes=16 << 20, wall_seconds=15, core_bytes=0), 'unchanged nine-mode native bounds')
        need([x['mode'] for x in outcomes['commands']] == list(range(9)) and
             [x['exit_code'] for x in outcomes['commands']] == [0,125,125,0,125,125,125,125,125], 'complete nine-mode outcome catalogue')
        for case in outcomes['commands']:
            result = {'name': case['name'], 'accepted': False, 'actual_exit': None};new['cases'].append(result)
            label = 'maps-'+str(case['mode'])
            row, out, err = run(label, [maps, str(case['mode'])], case['exit_code'])
            result['actual_exit'] = row['exit']
            need(out == case['stdout'].encode() and err == case['stderr'].encode(), 'exact maps output')
            result['record'] = fact(private/(label+'.record'))
            result.update(check((private/(label+'.record')).read_bytes(), layout, case))
        need(len(record['commands']) >= 27 and sum(r['profile'] == 'native' for r in record['commands']) == 27 and
             len(new['cases']) == 9 and all(x['accepted'] for x in new['cases']), 'all 27 native commands, no skipped cases')
        record['totals'] = dict(positive=pos['totals'], negative=neg['totals'], maps_cases=9,
            maps_successes=2, maps_failed_operations=7, new_actual_partial_errors=1, new_actual_nested_signals=1,
            new_actual_source_corruptions=1, new_nonissued_raw_errors=1, new_supplied_counter_saturations=2)
        record['status'] = 'passed'
    except BaseException as exc:
        record['error'] = type(exc).__name__+': '+str(exc)
    finally:
        if build is not None and register_build['started']:
            for n in register_names:
                try:
                    if (shared/n).is_file() and n not in register_build['retained']:
                        retained = build.retain('register-'+n, shared/n)
                        register_build['retained'][n] = dict(path=str(retained), **fact(retained))
                except BaseException as exc:record['final_errors'].append('register partial '+n+': '+repr(exc))
        if build is not None:
            try:
                record['final_errors'].extend(build.finish())
                if record['status'] == 'passed':need(record['build']['status'] == 'passed', 'build closure')
            except BaseException as exc:record['final_errors'].append('build: '+repr(exc))
        for p in sorted(pending):
            try:
                if p.is_file():binary(p)
            except BaseException as exc:record['final_errors'].append('partial artifact '+str(p)+': '+repr(exc))
        record['header_aliases'] = header_aliases
        for name, resolved in header_aliases.items():
            try:need(str(Path(name).resolve(strict=True)) == resolved, 'final header path identity')
            except BaseException as exc:record['final_errors'].append('header alias '+name+': '+repr(exc))
        record['inputs_before'], record['binaries_before'] = pins, binaries
        for label, before in (('inputs_after', pins), ('binaries_after', binaries)):
            after = record[label] = {}
            for path, expected in before.items():
                try:
                    after[path] = fact(path);need(after[path] == expected, 'final byte identity')
                except BaseException as exc:record['final_errors'].append(path+': '+repr(exc))
        try:
            record['source_unchanged'] = source() == record['source'];need(record['source_unchanged'], 'source changed')
        except BaseException as exc:record['final_errors'].append('source: '+repr(exc))
        if record['final_errors']:
            record['status'] = 'failed'
            if record['error'] is None:record['error'] = 'FinalObservationError: source/tool/artifact closure'
        receipt = private/'receipt.json';save(receipt, record);publish(public, record, receipt)
    print(json.dumps(dict(status=record['status'], totals=record['totals'], failure_type=(record['error'] or '').split(':')[0] or None)))
    return 0 if record['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
