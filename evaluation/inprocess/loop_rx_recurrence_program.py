#!/usr/bin/env python3
"""One bounded LS recurrence diagnostic; an intentional cutoff is a failed program.

Reuse the installed RX build, native prerequisite, namespace and process owner.
This is a startup-prefix observation, not a timing or admission qualification.
"""
import argparse
import csv
import json
import os
from pathlib import Path
import platform
import re
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
from checks import source
from run import hardware
from page_selected import ENV, fact, need, save
from page_selected_process import invoke
from page_cost_compare import PROGRAM_ENV
from persistent_dynamic import BOUNDS, imported_sources
from loop_ro_current_archive import current_archive
from loop_resident_rx_build import build_rx
from loop_resident_rx_benchmark import prerequisite
from page_native_pair_performance import prepare_workload
from page_selected_effect_ls import finalize
from loop_rx_recurrence_process import program_invoke, namespace_join
import loop_rx_recurrence as counter
import namespace

TARGET = [30, 512 << 20, 16 << 20, 60]
SCHEDULE = (('build', 'release_build'), ('headers', 'metadata'),
            ('undefined', 'inspect'), ('symbols', 'inspect'),
            ('ls-native-libraries', 'metadata'), ('ls-carrier', 'program'),
            ('ls-recurrence', 'program'))


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--expect-revision', required=True)
    ap.add_argument('--current-build', type=Path, required=True)
    ap.add_argument('--current-build-sha256', required=True)
    ap.add_argument('--native-receipt', type=Path, required=True)
    ap.add_argument('--native-sha256', required=True)
    ap.add_argument('--output', type=Path, required=True)
    a = ap.parse_args(); os.chdir(ROOT)
    need(sys.version_info[:2] == (3, 12) and not sys.flags.optimize and
         re.fullmatch('[0-9a-f]{40}', a.expect_revision) and len(os.sched_getaffinity(0)) == 1,
         'exact revision, Python3.12 assertions and externally reserved singleton')
    need(all(re.fullmatch('[0-9a-f]{64}', value) for value in
             (a.current_build_sha256, a.native_sha256)) and
         all(path.resolve().is_relative_to(ROOT/'target/evaluation/inprocess') for path in
             (a.current_build, a.native_receipt)), 'contained prerequisite paths and exact hashes')
    private = a.output.resolve()
    need(private.parent == ROOT/'target/evaluation/inprocess' and not private.exists(), 'fresh diagnostic directory')
    need(BOUNDS['program'] == BOUNDS['release_build'] == TARGET, 'unchanged target/compiler bounds')
    private.mkdir(mode=0o700); cpu = next(iter(os.sched_getaffinity(0)))
    r = dict(schema=1, profile='loop-rx-recurrence-program-v1', revision=a.expect_revision,
        source=None, status='failed', program_status='not_run', cpu=cpu, hardware=hardware(cpu),
        bounds=BOUNDS, commands=[], namespace_aliases={}, source_unchanged=False,
        inputs_unchanged=False, cleanup_complete=False, error=None, final_errors=[],
        qualification_credit=False, performance_credit=False, successful_target_credit=False,
        scope='One LS startup prefix after existing coarse/negative gates; no whole-program time prediction.')
    inputs = {}; artifacts = {}; aliases = {}; presence = {}

    def pin(path):
        lexical = Path(os.path.abspath(path)); p = lexical.resolve(strict=True); v = fact(p)
        need(str(p) not in inputs or inputs[str(p)] == v, 'unchanged input bytes')
        need(str(lexical) not in aliases or aliases[str(lexical)] == str(p), 'unchanged input alias')
        inputs[str(p)] = v; aliases[str(lexical)] = str(p); return p

    def binary(path):
        p = pin(path); v = dict(fact(p), mode=p.stat().st_mode & 0o777)
        need(str(p) not in artifacts or artifacts[str(p)] == v, 'unchanged artifact mode/bytes')
        artifacts[str(p)] = v; return p

    def stable():
        need(source() == r['source'] and os.sched_getaffinity(0) == {cpu}, 'unchanged source/CPU')
        need(all(fact(p) == v for p, v in inputs.items()), 'whole unchanged inputs')
        need(all(dict(fact(p), mode=Path(p).stat().st_mode & 0o777) == v
                 for p, v in artifacts.items()), 'whole unchanged artifacts')
        need(all(str(Path(p).resolve(strict=True)) == v for p, v in aliases.items()), 'unchanged aliases')
        need(all(os.path.lexists(p) == v for p, v in presence.items()), 'unchanged loader configuration')
        finalize(r)

    def run(name, argv, profile='metadata', expected=0, env=None):
        stable(); index = len(r['commands'])
        need(index < len(SCHEDULE) and (name, profile) == SCHEDULE[index], 'fixed seven-command schedule')
        target = name == 'ls-recurrence'
        need(expected == (125 if target else 0), 'literal original outcome or distinct diagnostic refusal')
        row = dict(name=name, argv=list(map(str, argv)), profile=profile, bounds=BOUNDS[profile],
            capture_limit=16 << 20, environment=dict(ENV if env is None else env), expected_exit=expected)
        if target:
            need(row['environment'] == PROGRAM_ENV and row['bounds'] == TARGET,
                 'original LS environment and process limits')
        r['commands'].append(row)
        try:
            out, err = (program_invoke if target else invoke)(row, private, cpu)
            need(type(row['exit']) is int and row['reaped'] is True and row['cleanup_errors'] == [] and
                 all(d['closed'] is True for d in row['descriptors']), 'complete actual process cleanup')
            if not target:
                need(row['exit'] == expected and row['timed_out'] is False and row['error'] is None,
                     'successful bounded setup command')
            return row, out, err
        finally:
            for stream, capture in row.get('captures', {}).items():
                need(capture['file'] == name+'.'+stream, 'contained actual capture name')
                need(fact(binary(private/capture['file'])) == {k: capture[k] for k in ('bytes', 'sha256')},
                     'whole saved capture bytes')
            saved = private/(name+'.json')
            if saved.exists():
                need(json.loads(binary(saved).read_bytes()) == row, 'whole actual saved command')

    try:
        r['source'] = source(); need(r['source']['revision'] == a.expect_revision, 'clean installed revision')
        pin(__file__); imported_sources(pin)
        for name in ('/etc/ld.so.cache', '/etc/ld.so.preload'):
            presence[name] = os.path.lexists(name)
            if presence[name]: pin(name)
        need(not presence['/etc/ld.so.preload'], 'no global preload')
        r['native_prerequisite'] = prerequisite(a.native_receipt, a.native_sha256, 'native', r, pin)
        builder, archive, r['archive_provider'] = current_archive(
            a.current_build, a.current_build_sha256, ROOT, pin, binary, aliases)
        r['archive'] = fact(archive)
        need(r['native_prerequisite']['archive'] == r['archive'], 'same actual native-qualified archive')
        original = pin('/bin/ls'); directory = private/'ls-build'; directory.mkdir()
        r['release_build'] = {}
        bridge = build_rx(builder, archive, original, directory, pin, binary, aliases, run,
                          r['release_build'], 'release', recurrence=True)
        (private/'external-inputs').mkdir()
        state = prepare_workload('ls', original, ('-d', '.'), bridge, builder,
                                 private, pin, binary, run, r, namespace)
        r['counter_transport'] = counter.prepare_counter_carrier(state, pin)
        ns = private/'ls-recurrence-namespace'
        argv = [builder.tools['python'], '-B', state['carrier_tool'], 'exec-loader',
                '--library-root', '/usr/lib64', '--namespace', ns,
                '--counter-fd', '{counter_fd}', '--counter-nonce', '{counter_nonce}',
                state['carrier'], state['original'], '--', *state['argv']]
        r['program_status'] = 'failed'
        row, out, err = run('ls-recurrence', argv, profile='program', expected=125, env=PROGRAM_ENV)
        namespace_join(state, ns, binary, r, namespace, row['counter_input'])
        r['observation'] = counter.final_prefix(row, private, binary)
        capture = binary(private/row['captures']['counters']['file'])
        c = row['counter_input']
        initial = (counter.MAGIC, counter.VERSION, counter.BYTES, counter.STORAGE,
                   c['nonce'], c['parent'], c['device'], c['inode'])
        r['controls'] = counter.controls(capture.read_bytes(), initial, row['pid'],
                                         row['counter_observation']['final_seals'])
        records = counter.records(capture.read_bytes())
        columns = list(dict.fromkeys(k for value in records for k in value if k not in ('before', 'after')))
        columns += [side+'_'+key for side in ('before', 'after') for key in counter.COUNTERS]
        with (private/'attempts.csv').open('x', newline='') as stream:
            writer = csv.DictWriter(stream, fieldnames=columns, lineterminator='\n')
            writer.writeheader()
            for value in records:
                flat = {k: v for k, v in value.items() if k not in ('before', 'after')}
                flat.update({side+'_'+k: v for side in ('before', 'after') for k, v in value.get(side, {}).items()})
                writer.writerow(flat)
        r['records'] = dict(rows=len(records), csv=fact(binary(private/'attempts.csv')))
        need(len(r['commands']) == 7, 'whole declared diagnostic schedule')
        # An actual abort gets its separate strict cleanup join. Killed prefixes
        # carry no terminal-cleanup inference, even if their rows are valid.
        need(row['exit'] in (125, -9), 'only an actual refusal or SIGKILL under the original bounds')
        if row['exit'] == 125:
            r['terminal'] = counter.terminal(err, r['observation']['prefix'], row['exit'])
        else:
            r['terminal'] = None
        r['status'] = 'observed_failed_program_prefix'
    except BaseException as error:
        r['error'] = type(error).__name__+': '+str(error)
    finally:
        try:
            imported_sources(pin)
            for path in sorted(private.rglob('*')):
                if path.is_file() and not path.is_symlink(): binary(path)
            stable()
            if 'native_prerequisite' in r:
                need(prerequisite(a.native_receipt, a.native_sha256, 'native', r, pin) == r['native_prerequisite'],
                     'complete native prerequisite unchanged after diagnostic')
            r['source_unchanged'] = r['inputs_unchanged'] = True
        except BaseException as error:
            r['final_errors'].append(type(error).__name__+': '+str(error))
        r['cleanup_complete'] = bool(r['commands']) and all(type(c.get('exit')) is int and
            c.get('reaped') is True and c.get('cleanup_errors') == [] and
            all(d.get('closed') is True for d in c.get('descriptors', [])) for c in r['commands'])
        if r['error'] or r['final_errors'] or not r['cleanup_complete']: r['status'] = 'failed'
        r.update(inputs=inputs, artifacts=artifacts, aliases=aliases, presence=presence)
        save(private/'receipt.json', r)
        summary = {k: r[k] for k in ('schema', 'profile', 'revision', 'source', 'status',
            'program_status', 'cpu', 'hardware', 'bounds', 'source_unchanged', 'inputs_unchanged',
            'cleanup_complete', 'qualification_credit', 'performance_credit', 'successful_target_credit', 'scope')}
        summary.update(receipt=fact(private/'receipt.json'), observation=r.get('observation'),
            terminal=r.get('terminal'), records=r.get('records'), command_count=len(r['commands']),
            error_type=(r['error'] or '').split(':', 1)[0] or None, final_error_count=len(r['final_errors']),
            reader_controls=r.get('controls'), driver=fact(__file__))
        if r['commands'] and r['commands'][-1]['name'] == 'ls-recurrence':
            row = r['commands'][-1]
            summary['failed_process'] = {k: row.get(k) for k in ('exit', 'process_ns', 'duration_ns',
                'user_cpu_ns', 'system_cpu_ns', 'timed_out', 'reaped', 'minor_faults', 'major_faults')}
        summary['reproduce'] = ['python3.12', '-B', 'evaluation/inprocess/loop_rx_recurrence_program.py',
            '--expect-revision', a.expect_revision, '--current-build', str(a.current_build.resolve().relative_to(ROOT)),
            '--current-build-sha256', a.current_build_sha256,
            '--native-receipt', str(a.native_receipt.resolve().relative_to(ROOT)),
            '--native-sha256', a.native_sha256, '--output', 'target/evaluation/inprocess/loop-rx-recurrence-NEW']
        text = json.dumps(summary, sort_keys=True)
        need(len(text.encode()) < 32 << 10 and '/home/' not in text and platform.node() not in text,
             'compact portable summary without host paths or raw logs')
        save(private/'summary.json', summary)
        print(json.dumps(dict(status=r['status'], program_status=r['program_status'],
                              receipt=str(private/'receipt.json'))), flush=True)
    return int(r['status'] != 'observed_failed_program_prefix')


if __name__ == '__main__':
    raise SystemExit(main())
