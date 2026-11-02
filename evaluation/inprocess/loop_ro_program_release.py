#!/usr/bin/env python3
"""Two real programs through the actual RO release, with all original readers.

This separate development observation has no native/DR comparison, repeated
samples, full machine-state qualification or full-profile prerequisite credit.
"""
import argparse
import csv
import io
import json
import os
from pathlib import Path
import re
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
from checks import source
from run import hardware
from page_selected import ENV, fact, need, save
from persistent_dynamic import BOUNDS, digest, imported_sources
from persistent_loop_effects_archive import Build
from persistent_loop_effects_build_default import before_loop_effects_default
from persistent_loop_effects_build import FEATURES
from loop_ro_native_positive import build_ro
from page_selected_process import invoke
from page_cost_compare import PROGRAM_ENV, program_invoke
from page_native_pair_performance import prepare_workload, namespace_join
from page_selected_effect_ls import finalize
import loop_ro_certificate_reports as reports
import namespace

TARGET = [30, 512 << 20, 16 << 20, 60]
PROGRAMS = (('ls', '/bin/ls', ('-d', '.'), b'.\n'),
            ('true', '/bin/true', (), b''))
ORDER = tuple((kind, 'release') for kind, _, _, _ in PROGRAMS)
NAMES = tuple(kind+'-'+lane for kind, lane in ORDER)
CONTROL_COUNTS = {'ls': 447, 'true': 480}
RO_CONTROL_COUNT = 167
SETUP = (('tracked-input-list', 'metadata'),) + tuple((name, 'metadata') for name in (
    'resolve-cargo', 'resolve-rustc', 'resolve-cc1', 'resolve-collect2', 'resolve-as', 'resolve-ld',
    'version-cc', 'version-cargo', 'version-rustc', 'version-python', 'cargo-metadata',
    'default-headers-0', 'default-headers-1')) + (
    ('selected-build', 'build'), ('archive-text-exports', 'inspect'),
    ('bridge-undefined', 'inspect'), ('bridge-elf', 'inspect'),
    ('generic-observer-headers', 'metadata'), ('generic-observer-link', 'metadata'))
SCHEDULE = SETUP + tuple((kind+'-'+name, profile) for kind, _, _, _ in PROGRAMS
    for name, profile in (('build', 'release_build'), ('headers', 'metadata'),
        ('undefined', 'inspect'), ('symbols', 'inspect'), ('native-libraries', 'metadata'),
        ('carrier', 'program'))) + tuple((name, 'program') for name in NAMES)


def cohort(builder, products, private, pin, binary, aliases, run, r):
    states = {}; builds = r['release_builds'] = {}
    archive = pin(products['archive']); owned = builder.record['artifacts']['decoder.a']
    need(archive == builder.paths['archive'] == builder.retained/'decoder.a' and
         str(archive) == owned['path'] and fact(archive) == r['archive'] ==
         {k: owned[k] for k in ('bytes', 'sha256')},
         'this fresh13-source Build owns the exact archive used for both release links')
    (private/'external-inputs').mkdir()
    for kind, program, args, expected in PROGRAMS:
        original = pin(program)
        directory = private/(kind+'-build'); directory.mkdir()
        holder = builds[kind] = {}
        def labelled(name, argv, **kwargs):
            return run(kind+'-'+name, argv, **kwargs)
        bridge = build_ro(builder, archive, original, directory, pin, binary, aliases,
                          labelled, holder, 'release')
        need(holder['status'] == 'compiled_diagnostic_only' and
             holder['binding']['profile'] == 'persistent-loop-ro-certificate-release-v1' and
             holder['binding']['mode'] == 'release' and
             holder['binding']['archive'] == r['archive'] and
             holder['binding']['capture_version'] is None and
             holder['binding']['byte_certificate']['every_hit_full_scan'] is False and
             holder['binding']['history_certificate']['every_hit_reconstruction'] is False,
             'actual separately bound RO release with no test/capture/counter profile')
        states[kind] = prepare_workload(kind, original, args, bridge, builder,
                                       private, pin, binary, run, r, namespace)
    need(reports.prior.CONTROL_COUNTS == CONTROL_COUNTS and len(r['cases']) == 2,
         'fixed two release subjects and every unchanged real-program reader control')
    expected_output = {kind: out for kind, _, _, out in PROGRAMS}
    for ordinal, (kind, lane) in enumerate(ORDER):
        name = NAMES[ordinal]; state = states[kind]; case = r['cases'][ordinal]
        case['status'] = 'failed'; ns = private/(name+'-namespace')
        argv = [builder.tools['python'], '-B', state['carrier_tool'], 'exec-loader',
                '--library-root', '/usr/lib64', '--namespace', ns,
                state['carrier'], state['original'], '--', *state['argv']]
        start = len(r['commands'])
        try:
            row, out, err = run(name, argv, profile='program', env=PROGRAM_ENV)
            need(out == expected_output[kind], 'whole exact real-program stdout')
            namespace_join(state, ns, binary, r, namespace)
            args = (row['pid'], row['exit'], row['stdout_provenance_before'],
                    state['images'], state['image_bytes'], fact(state['carrier']), state['carrier_bytes'])
            observed = reports.check(out, err, args, kind, 'release')
            case['observed'] = observed  # Retain validated counts even if later reader controls fail.
            controls = reports.controls(out, err, args, kind, 'release')
            need(len(controls['inherited']['refusals']) ==
                 len(set(controls['inherited']['refusals'])) == CONTROL_COUNTS[kind] and
                 len(controls['refusals']) == len(set(controls['refusals'])) == RO_CONTROL_COUNT,
                 'all original447/480 reader controls plus each of167 certificate controls')
            case.update(observed=observed, controls=controls, namespace_complete=True,
                        status='passed', completed_program_measurement=True)
        except Exception as error:
            case['error'] = type(error).__name__+': '+str(error)
            if r['error'] is None: r['error'] = case['error']
            actual = r['commands'][start:]
            need(len(actual) == 1 and actual[0]['name'] == name and
                 type(actual[0].get('exit')) is int and actual[0].get('reaped') is True and
                 actual[0].get('cleanup_errors') == [] and
                 all(d.get('closed') is True for d in actual[0].get('descriptors', [])),
                 'continue the fixed schedule only after actual complete child cleanup')
        finally:
            attempted = [c for c in r['commands'][start:] if c['name'] == name]
            if attempted:
                row = attempted[-1]
                case.update({k: row.get(k) for k in ('exit', 'process_ns', 'duration_ns',
                    'process_start_ns', 'process_reaped_ns', 'timed_out', 'reaped',
                    'user_cpu_ns', 'system_cpu_ns', 'minor_faults', 'major_faults',
                    'voluntary_switches', 'involuntary_switches')})
                case['captures'] = {k: {f: v[f] for f in ('bytes', 'sha256')}
                                    for k, v in row.get('captures', {}).items()}
            print(json.dumps({k: case.get(k) for k in
                  ('ordinal', 'workload', 'lane', 'status', 'exit', 'process_ns', 'error')}), flush=True)
    need(len(r['commands']) == len(SCHEDULE) == 34 and len(r['cases']) == 2 and
         all(c['status'] == 'passed' for c in r['cases']) and r['error'] is None,
         'both fixed diagnostic attempts and all34 source-owned commands, no replacement or discarded failure')


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--expect-revision', required=True)
    ap.add_argument('--output', type=Path, required=True)
    a = ap.parse_args(); os.chdir(ROOT)
    need(sys.version_info[:2] == (3, 12) and not sys.flags.optimize and re.fullmatch('[0-9a-f]{40}', a.expect_revision) and
         len(os.sched_getaffinity(0)) == 1,
         'Python3.12, exact revision, enabled assertions and externally reserved singleton CPU')
    private = a.output.resolve()
    need(private.is_relative_to(ROOT/'target/evaluation/inprocess') and
         not private.exists(), 'fresh private diagnostic output')
    private.mkdir(mode=0o700)
    cpu = next(iter(os.sched_getaffinity(0))); bounds = dict(BOUNDS)
    need(bounds['program'] == bounds['release_build'] == TARGET,
         'unchanged original subject and release compiler bounds')
    r = dict(schema=1, profile='loop-ro-program-release-v1', status='failed',
        revision=a.expect_revision, source=None, source_unchanged=False, inputs_unchanged=False, cleanup_complete=False,
        cpu=cpu, hardware=hardware(cpu), bounds=bounds, commands=[], namespace_aliases={},
        cases=[dict(ordinal=i, workload=k, lane=lane, status='not_run', expected_exit=0,
                    completed_program_measurement=False) for i, (k, lane) in enumerate(ORDER)],
        error=None, final_errors=[], qualification_credit=False, full_state_credit=False,
        whole_profile_qualified=False, performance_credit=False,
        scope='Two RO release programs only, with original complete application/namespace/terminal readers plus167 certificate controls each. No fresh native comparison, full machine-state or qualification prerequisite credit. Full19 and lifecycle remain required.',
        timing_scope='Single whole-process observations including carrier/namespace/terminal output. Failed elapsed values describe failure cost only. No median, IQR, speedup, DR parity or first-touch/steady claim.',
        count_scope='Actual fully checked terminal rows. Linked ingress is not every kernel trap; policy redirects are not internal iterations. No counter bank or invented absent events.',
        reproduce=[sys.executable, '-B', str(Path(__file__).resolve()),
                   '--expect-revision', a.expect_revision, '--output', str(private)])
    pins = {}; aliases = {}; artifacts = {}; presence = {}
    def pin(path, want=None):
        alias=Path(os.path.abspath(path)); p=alias.resolve(strict=True); value=fact(p)
        need(want is None or value=={k:want[k] for k in ('bytes','sha256')},'whole requested input')
        need(str(alias) not in aliases or aliases[str(alias)]==str(p),'stable input alias')
        need(str(p) not in pins or pins[str(p)]==value,'stable input bytes')
        aliases[str(alias)]=str(p); pins[str(p)]=value; return p
    def binary(path):
        p=Path(path).resolve(strict=True); value=dict(fact(p),mode=p.stat().st_mode&0o777)
        need(str(p) not in artifacts or artifacts[str(p)]==value,'stable artifact bytes/mode')
        artifacts[str(p)]=value; return p
    def closure():
        need(os.sched_getaffinity(0)=={cpu},'same reserved CPU')
        need(all(fact(p)==v for p,v in pins.items()),'whole unchanged inputs')
        need(all(dict(fact(p),mode=Path(p).stat().st_mode&0o777)==v for p,v in artifacts.items()),'whole unchanged artifacts/modes')
        need(all(str(Path(p).resolve(strict=True))==v for p,v in aliases.items()),'whole unchanged aliases')
        need(all(os.path.lexists(p)==v for p,v in presence.items()),'unchanged loader configuration presence')
        finalize(r)
    def run(name, argv, profile='metadata', expected=0, env=None, record=False, step=False):
        closure(); need(not r['final_errors'] and not any(c['name']==name for c in r['commands']),'clean unique command')
        need(record is False and step is False,'RO release has no protected capture or step instrumentation')
        need(len(r['commands']) < len(SCHEDULE) and
             (name, profile) == SCHEDULE[len(r['commands'])] and type(expected) is int and expected == 0,
             'fixed34 source-owned setup/build/subject schedule and expected zero outcomes')
        row=dict(name=name,argv=list(map(str,argv)),profile=profile,bounds=bounds[profile],capture_limit=16<<20,
                 environment=dict(ENV if env is None else env),expected_exit=expected)
        r['commands'].append(row)
        try:
            if name in NAMES:
                need(profile == 'program' and row['bounds'] == TARGET and
                     row['environment'] == PROGRAM_ENV and type(expected) is int and expected == 0,
                     'exact two subject environments, positive outcomes and original bounds')
            out,err=(program_invoke if name in NAMES else invoke)(row,private,cpu,record=record,step=step)
            need(type(row['exit']) is int and (expected is None or row['exit']==expected),'actual command outcome '+name)
            return row,out,err
        finally:
            for stream in ('stdout','stderr','record','preparation'):
                path=private/(name+'.'+stream); observed=row.get('captures',{}).get(stream)
                try:
                    if path.exists() or path.is_symlink():
                        value=fact(binary(path))
                        if observed is not None:
                            need(observed['file']==path.name and value=={k:observed[k] for k in ('bytes','sha256')},'actual retained capture')
                    else: need(observed is None,'missing actual capture')
                except BaseException as error: r['final_errors'].append('capture '+name+': '+repr(error))
            try:
                path=private/(name+'.json')
                if path.exists(): need(json.loads(binary(path).read_bytes())==row,'whole retained command JSON')
            except BaseException as error: r['final_errors'].append('command '+name+': '+repr(error))
    def build_run(name,argv,profile='metadata',env=None,expected=0):
        before_loop_effects_default(name,argv,builder,pin,aliases,run,r)
        return run(name,argv,profile=profile,env=env,expected=expected)
    builder = Build(r, private, pin, binary, build_run, ('region.rs',),
                    scalar_span=True, linked_epoch=True, mov_guard=True)
    try:
        r['source'] = source()
        need(r['source']['revision'] == a.expect_revision, 'exact current clean source')
        _, names, err = run('tracked-input-list', ['git', '-C', ROOT, 'ls-files', '-z',
                                                  'tools/page-entry', 'evaluation/inprocess'])
        need(not err and str(Path(__file__).resolve().relative_to(ROOT)).encode() in names.split(b'\0'),
             'this diagnostic source is installed and tracked before execution')
        for name in names.split(b'\0'):
            if name and not name.startswith(b'evaluation/inprocess/results/'): pin(ROOT/os.fsdecode(name))
        for name in ('/etc/ld.so.cache', '/etc/ld.so.preload'):
            presence[name] = os.path.lexists(name)
            if presence[name]: pin(name)
        need(not presence['/etc/ld.so.preload'], 'no global preload')
        imported_sources(pin)
        products = builder.prepare()
        need(builder.decoder_features == FEATURES and builder.extra_decoder_sources ==
             ('region.rs', 'mov_guard.rs', 'scalar_read.rs', 'loop_scalar.rs', 'byte_mov_guard.rs') and
             builder.record['status'] == 'passed' and builder.record['command_completed'] is True and
             builder.environment['CARGO_BUILD_JOBS'] == '1' and
             builder.environment['CARGO_INCREMENTAL'] == '0', 'fresh exact archive with one Cargo job')
        r['archive'] = fact(products['archive'])
        cohort(builder, products, private, pin, binary, aliases, run, r)
        need(not r['final_errors'], 'complete retained command custody')
        r['status'] = 'completed_diagnostic'
    except BaseException as error:
        if r['error'] is None: r['error'] = type(error).__name__+': '+str(error)
    finally:
        try: r['final_errors'].extend(builder.finish())
        except BaseException as error: r['final_errors'].append('build finalization: '+repr(error))
        try: imported_sources(pin)
        except BaseException as error: r['final_errors'].append('imported closure: '+repr(error))
        for path in sorted(private.rglob('*')):
            if path.is_file() and not path.is_symlink():
                try: binary(path)
                except BaseException as error: r['final_errors'].append('artifact closure: '+repr(error))
        r.update(inputs=pins, artifacts=artifacts, aliases=aliases, presence=presence)
        try:
            closure(); need(source() == r['source'], 'exact source unchanged after every child')
            r['source_unchanged'] = r['inputs_unchanged'] = True
        except BaseException as error: r['final_errors'].append('final closure: '+repr(error))
        r['cleanup_complete'] = bool(r['commands']) and all(type(c.get('exit')) is int and
            c.get('reaped') is True and c.get('timed_out') is False and not c.get('error') and
            c.get('cleanup_errors') == [] and all(d.get('closed') is True for d in c.get('descriptors', []))
            for c in r['commands'])
        if r['error'] or r['final_errors'] or not r['source_unchanged'] or not r['cleanup_complete']:
            r['status'] = 'failed'
        save(private/'receipt.json', r)
        summary = {key: r[key] for key in ('schema', 'profile', 'status', 'revision', 'cpu',
            'hardware', 'bounds', 'scope', 'timing_scope', 'count_scope', 'source_unchanged',
            'inputs_unchanged', 'cleanup_complete', 'qualification_credit', 'full_state_credit',
            'whole_profile_qualified', 'performance_credit')}
        cases = []
        for case in r['cases']:
            observed = {k: v for k, v in case.items() if k not in ('controls', 'error')}
            observed['error_type'] = case.get('error', '').split(':', 1)[0] or None
            controls = case.get('controls', {})
            observed.update(inherited_reader_controls=len(controls.get('inherited', {}).get('refusals', [])),
                certificate_reader_controls=len(controls.get('refusals', [])),
                controls_sha256=digest(controls) if controls else None,
                validated_terminal_available='observed' in case)
            cases.append(observed)
        summary.update(receipt=fact(private/'receipt.json'), commands=len(r['commands']), cases=cases,
            error_type=(r['error'] or '').split(':', 1)[0] or None,
            final_error_count=len(r['final_errors']),
            errors_sha256=digest(dict(error=r['error'], final_errors=r['final_errors'])),
            reproduce=['python3.12', '-B', 'evaluation/inprocess/loop_ro_program_release.py',
                       '--expect-revision', a.expect_revision, '--output',
                       'target/evaluation/inprocess/loop-ro-program-release-NEW'])
        text = json.dumps(summary, sort_keys=True, indent=2)+'\n'
        need(len(text.encode()) < 32 << 10 and '/home/' not in text and str(ROOT) not in text,
             'bounded public actual observations without host paths or raw errors')
        save(private/'summary.json', summary)
        fields = ('ordinal', 'workload', 'lane', 'status', 'expected_exit', 'exit',
            'process_start_ns', 'process_reaped_ns', 'process_ns', 'duration_ns',
            'user_cpu_ns', 'system_cpu_ns', 'timed_out', 'reaped',
            'inherited_reader_controls', 'certificate_reader_controls', 'validated_terminal_available')
        csv_text = io.StringIO(); writer = csv.DictWriter(csv_text, fieldnames=fields, lineterminator='\n')
        writer.writeheader()
        for case in cases: writer.writerow({k: case.get(k) for k in fields})
        with (private/'timeline.csv').open('x') as stream: stream.write(csv_text.getvalue())
        print(json.dumps(dict(status=r['status'], receipt=str(private/'receipt.json'))), flush=True)
    return int(r['status'] != 'completed_diagnostic')


if __name__ == '__main__':
    raise SystemExit(main())
