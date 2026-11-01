#!/usr/bin/env python3
"""Fresh two-lane PF diagnostic; no native-state or qualification result."""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import sys

sys.dont_write_bytecode = True
from checks import source
from run import hardware
from page_selected import ENV, fact, need, save
from page_selected_generic_build import Build
from page_selected_process import invoke
from page_selected_effect_ls import program_invoke
from page_selected_oneshot_build import before_default
from persistent_dynamic import BOUNDS, imported_sources, raw_emission
from persistent_fused_build import build_bridge
from bounded_fused_owner_build import compile_subject
from bounded_fused_owner_helpers import BASE_COMMAND_SCHEDULE, observed_layout
from direct_frontier_loop_helpers import prepare_inputs, preparation

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT/'tools/page-entry/selected/tests/persistent_fused_app'
# This diagnostic does not run semantic readers, their native-policy/seed
# support, or a native reference. The full finite evaluator is unchanged.
OMITTED = (('policy-headers', 'metadata'), ('policy-link', 'release_build'),
           ('seed-headers', 'metadata'), ('seed-link', 'release_build'),
           ('seed-libraries', 'inspect'), ('seed-prerequisite', 'seed'),
           ('subject-native-0-0', 'program'))
SCHEDULE = tuple(row for row in BASE_COMMAND_SCHEDULE if row not in OMITTED)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--expect-revision', required=True)
    ap.add_argument('--expect-decoder-sha256', required=True)
    ap.add_argument('--cpu', type=int, required=True)
    ap.add_argument('--output', type=Path, required=True)
    args = ap.parse_args()
    need(re.fullmatch('[0-9a-f]{40}', args.expect_revision) and
         re.fullmatch('[0-9a-f]{64}', args.expect_decoder_sha256), 'explicit exact source and decoder identities')
    need(not sys.flags.optimize and sorted(os.sched_getaffinity(0)) == [args.cpu], 'assertions and one externally reserved CPU')
    need(len(BASE_COMMAND_SCHEDULE) == 101 and len(SCHEDULE) == 94 and
         tuple(row for row in BASE_COMMAND_SCHEDULE if row in OMITTED) == OMITTED,
         'exact diagnostic subset of the unchanged finite command schedule')
    os.chdir(ROOT)
    private = args.output.absolute()
    need(private.parent == ROOT/'target/evaluation/inprocess' and not private.exists(), 'fresh direct-child diagnostic output')
    private.mkdir(parents=True, exist_ok=False)
    r = dict(schema=1, profile='bounded-fused-fresh-smoke-v1', status='failed',
        revision=args.expect_revision, expected_decoder_sha256=args.expect_decoder_sha256,
        cpu=args.cpu, hardware=hardware(args.cpu), source=None, source_unchanged=False,
        inputs_unchanged=False, cleanup_complete=False, commands=[], bounds=dict(BOUNDS),
        error=None, final_errors=[], namespace_aliases={}, lanes={},
        qualification_credit=False, native_state_equality=False, performance_credit=False,
        scope='fresh current-source diagnostic; original expected-zero mode0 subjects only; no historical replay or finite qualification',
        cases=[dict(label='subject-'+lane+'-0-0', lane=lane, mode=0, control=0,
                    expected_exit=0, status='unexecuted', launched=False)
               for lane in ('maintained', 'differential')])
    pins, artifacts, aliases, presence = {}, {}, {}, {}

    def pin(path):
        alias = Path(os.path.abspath(path)); p = alias.resolve(strict=True); value = fact(p)
        need(str(alias) not in aliases or aliases[str(alias)] == str(p), 'stable input alias')
        need(str(p) not in pins or pins[str(p)] == value, 'stable input bytes')
        pins[str(p)] = value; aliases[str(alias)] = str(p)
        return p

    def binary(path):
        p = Path(path).resolve(strict=True)
        value = dict(fact(p), mode=p.stat().st_mode & 0o777)
        need(str(p) not in artifacts or artifacts[str(p)] == value, 'stable artifact')
        artifacts[str(p)] = value
        return p

    def closure():
        need(all(fact(p) == v for p, v in pins.items()), 'input bytes unchanged')
        need(all(dict(fact(p), mode=Path(p).stat().st_mode & 0o777) == v
                 for p, v in artifacts.items()), 'artifact bytes and modes unchanged')
        need(all(str(Path(p).resolve(strict=True)) == v for p, v in aliases.items()), 'input aliases unchanged')
        need(all(os.path.lexists(p) == v for p, v in presence.items()), 'loader configuration presence')
        need(all(Path(p).is_symlink() and os.readlink(p) == v
                 for p, v in r['namespace_aliases'].items()), 'sealed namespace aliases unchanged')

    def run(name, argv, profile='metadata', expected=0, env=None, record=False):
        closure()
        need(sorted(os.sched_getaffinity(0)) == [args.cpu], 'same reserved CPU before every command')
        need(expected == 0 and len(r['commands']) < len(SCHEDULE) and
             (name, profile) == SCHEDULE[len(r['commands'])], 'fixed diagnostic order, original bounds and expected-zero outcomes')
        row = dict(name=name, argv=list(map(str, argv)), environment=dict(ENV if env is None else env),
            profile=profile, bounds=BOUNDS[profile], capture_limit=16 << 20, expected_exit=0)
        r['commands'].append(row)
        try:
            out, err = (program_invoke if name.startswith('subject-') else invoke)(row, private, args.cpu, record=record)
            need(row['exit'] == 0 and not row['timed_out'], 'actual expected-zero command: '+name)
            return row, out, err
        finally:
            for item in row.get('captures', {}).values():
                try:
                    need(fact(binary(private/item['file'])) == {k: item[k] for k in ('bytes', 'sha256')}, 'whole actual capture bytes')
                except BaseException as error:
                    r['final_errors'].append('capture '+name+': '+repr(error))
            try:
                p = private/(name+'.json')
                if p.exists():
                    need(json.loads(binary(p).read_bytes()) == row, 'retained actual command row')
            except BaseException as error:
                r['final_errors'].append('command record '+name+': '+repr(error))

    def build_run(name, argv, profile='metadata', env=None, expected=0):
        before_default(name, argv, builder, pin, aliases, run, r)
        return run(name, argv, profile=profile, expected=expected, env=env)

    builder = Build(r, private, pin, binary, build_run, ('region.rs',),
                    scalar_span=True, linked_epoch=True, mov_guard=True)
    try:
        r['source'] = source()
        need(r['source']['revision'] == args.expect_revision, 'exact clean tracked source')
        imported_sources(pin)
        git = pin(shutil.which('git', path=ENV['PATH']))
        _, names, err = run('tracked-input-list', [git, '-C', ROOT, 'ls-files', '-z', 'tools/page-entry', 'evaluation/inprocess'])
        need(names and not err, 'complete nonempty tracked input list from the repository')
        for raw in names.split(b'\0'):
            if raw and not os.fsdecode(raw).startswith('evaluation/inprocess/results/'):
                pin(ROOT/os.fsdecode(raw))
        for name in ('/etc/ld.so.cache', '/etc/ld.so.preload'):
            presence[name] = os.path.lexists(name)
            if presence[name]: pin(name)
        need(not presence['/etc/ld.so.preload'], 'no global preload')
        products = builder.prepare()
        need(fact(products['archive'])['sha256'] == args.expect_decoder_sha256, 'fresh source-authenticated decoder has the explicit expected identity')
        original = compile_subject(builder, private, pin, binary, aliases, run, r)
        subjects = {}
        for lane in ('maintained', 'differential'):
            directory = private/(lane+'-build'); directory.mkdir(); holder = r['lanes'][lane] = {}
            def lane_run(name, argv, profile='metadata', expected=0, env=None, record=False):
                return run(lane+'-'+name, argv, profile=profile, expected=expected, env=env, record=record)
            bridge = build_bridge(builder, products, directory, pin, binary, aliases, lane_run,
                                  holder, original, capture=True, differential=lane == 'differential')
            raw_emission(builder, bridge, pin, lane_run, holder)
            layout = observed_layout(builder, bridge, directory, pin, binary, lane_run, holder)
            inputs = prepare_inputs(original, bridge, builder, directory, pin, binary, lane_run, holder, r['application_build'])
            state = holder['release_build']
            need(state['status'] == 'passed' and
                 state['profile'] == 'persistent-fused-'+('differential' if lane == 'differential' else 'capture')+'-v1' and
                 state['active_domain']['differential'] == (lane == 'differential') and
                 state['persistent_binding']['bounded_fused'] is True and state['persistent_binding']['policy_version'] == 11 and
                 state['pf_refusals'] == state['persistent_binding']['pf_refusals'] == dict(version=1, reason=256, shared_reasons=18, abi2=False),
                 'current exact PF11 maintained/differential capture builds')
            need(holder['subject_artifacts']['original'] == fact(original), 'one unchanged fresh application across both lanes')
            subjects[lane] = (layout, inputs)
        launcher = pin(FIXTURE/'launch.py')
        imported_sources(pin)
        for case in r['cases']:
            lane, label = case['lane'], case['label']; case['status'] = 'failed'
            directory = private/label; directory.mkdir()
            layout, (interp, roots, objects, description, images, raws, carrier) = subjects[lane]
            argv = [builder.tools['python'], '-B', launcher, '--root', ROOT, '--role', 'gated', '--mode', '0', '--control', '0',
                    '--original', original, '--preparation', directory/'preparation.json']
            for path in roots: argv += ['--library-root', path]
            argv += ['--carrier', carrier, '--namespace', directory/'namespace', '--record-fd', '{record_fd}']
            errors = []
            try:
                run(label, argv, profile='program', record=True)
            except Exception as error:
                errors.append(type(error).__name__+': '+str(error))
            if r['commands'][-1]['name'] == label:
                row = r['commands'][-1]
                case.update(exit=row.get('exit'), whole_process_ns=row.get('duration_ns'),
                    timed_out=row.get('timed_out'), launched=type(row.get('pid')) is int,
                    captures={k: {j: v[j] for j in ('bytes', 'sha256')} for k, v in row.get('captures', {}).items()})
                try:
                    preparation(case, row, directory, original, roots, objects, description, carrier, private, binary, r)
                    capture = row['captures']['record']
                    need(128 < capture['bytes'] < 4 << 20 and layout['types']['pdo_wire']['bytes'] == 5421440,
                         'whole encoded schema13 diagnostic capture within the unchanged strict4MiB limit')
                except Exception as error:
                    errors.append(type(error).__name__+': '+str(error))
            if errors: case['errors'] = errors
            else: case['status'] = 'observed_exit_zero_only'
            last = r['commands'][-1] if r['commands'] else {}
            need(last.get('name') == label and last.get('reaped') is True and
                 last.get('cleanup_errors') == [] and isinstance(last.get('descriptors'), list) and
                 all(d.get('closed') is True for d in last['descriptors']),
                 'completed current-subject cleanup before advancing to another lane')
        need(tuple((c['name'], c['profile']) for c in r['commands']) == SCHEDULE, 'complete fixed94-command diagnostic schedule')
        need(all(c['status'] == 'observed_exit_zero_only' for c in r['cases']), 'both actual expected-zero subjects; every failure stays failed')
        r['status'] = 'observed_smoke_exit_zero'
    except BaseException as error:
        r['error'] = type(error).__name__+': '+str(error)
    finally:
        r['final_errors'].extend(builder.finish())
        try:
            imported_sources(pin)
            closure()
            need(source() == r['source'], 'exact source unchanged')
            need(sorted(os.sched_getaffinity(0)) == [args.cpu], 'same reserved CPU at closure')
            r['source_unchanged'] = r['inputs_unchanged'] = True
        except BaseException as error:
            r['final_errors'].append(type(error).__name__+': '+str(error))
        r['cleanup_complete'] = all(c.get('reaped') and not c.get('cleanup_errors') and
            all(d['closed'] for d in c.get('descriptors', [])) for c in r['commands'])
        if r['error'] or r['final_errors'] or not r['source_unchanged'] or not r['cleanup_complete']:
            r['status'] = 'failed'
        r.update(inputs=pins, artifacts=artifacts, aliases=aliases, presence=presence)
        save(private/'receipt.json', r)
    print(json.dumps(dict(status=r['status'], receipt=str((private/'receipt.json').relative_to(ROOT)))))
    return int(r['status'] != 'observed_smoke_exit_zero')


if __name__ == '__main__':
    raise SystemExit(main())
