#!/usr/bin/env python3
"""Two current mode6/placement3 lanes against one retained same-CPU native reference.

Run from the clean repository on the reference's reserved CPU192. The historical
archive is reused only after exact current decoder/fixture input joins. Both
current capture builds retain every original build/ELF/DWARF/byte-oracle check.
The unchanged full evaluate() runs without mutation controls. This is a scoped
diagnostic, not a replacement for native28, owner56 or any qualification stage.
"""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import sys
from types import SimpleNamespace

sys.dont_write_bytecode = True
ROOT = Path.cwd().resolve()
sys.path.insert(0, str(ROOT/'evaluation/inprocess'))
from checks import source
from run import hardware
from page_selected import ENV, fact, need, save
from page_selected_process import invoke
from page_selected_effect_ls import program_invoke
from persistent_dynamic import (BOUNDS, digest, imported_sources, load,
    raw_emission, seed_prerequisite, image_inventory)
from persistent_loop_effects_build import build_bridge, FEATURES
from persistent_loop_effects_native import SCHEDULE as NATIVE_SCHEDULE, summary
from persistent_loop_effects_native_prerequisite import require_seed_record, SOURCES
from persistent_loop_native_build import (FIXTURE, application, reader_support,
    native_namespace, native_preparation, preparation)
from persistent_loop_effects_owner_helpers import (OWNER, LANE_SCHEDULE,
    observed_layout, case_argv, evaluate, expected_status)
from direct_frontier_loop_helpers import prepare_inputs

SELECTED = ROOT/'tools/page-entry/selected'
REFERENCE_REVISION = '1b2028e795bac3b308114d73681311b67cf2da1a'
REFERENCE_SHA = '63ffcec24921e93d9ef9682e04feb411a1684f21c1ed93939701a5a0e4f4fbf1'
LANES = ('maintained', 'differential')
SCHEDULE = tuple((lane+'-'+name, profile) for lane in LANES for name, profile in LANE_SCHEDULE) + tuple(
    ('subject-'+lane+'-6-3', 'program') for lane in LANES)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--expect-revision', required=True)
    ap.add_argument('--native-receipt', type=Path, required=True)
    ap.add_argument('--native-receipt-sha256', required=True)
    ap.add_argument('--output', type=Path, required=True)
    args = ap.parse_args()
    need(sys.version_info[:2] == (3, 12) and not sys.flags.optimize and
         re.fullmatch('[0-9a-f]{40}', args.expect_revision) and
         os.sched_getaffinity(0) == {192}, 'exact current revision, Python3.12/assertions and reserved reference CPU192')
    private = args.output.absolute()
    need(private.parent == ROOT/'target/evaluation/inprocess' and not private.exists(), 'fresh private direct-child output')
    private.mkdir()
    pins, artifacts, aliases, presence = {}, {}, {}, {}
    r = dict(schema=1, profile='effects-predecessor-pair-diagnostic-v1', status='failed',
        revision=args.expect_revision, cpu=192, hardware=hardware(192), source=None,
        argv=[sys.executable, '-B', *sys.argv], commands=[], lanes={}, namespace_aliases={},
        bounds=dict(BOUNDS), error=None, final_errors=[], source_unchanged=False,
        inputs_unchanged=False, cleanup_complete=False, diagnostic_only=True,
        current_native_credit=False, owner_credit=False, mutation_controls_run=False,
        qualification_credit=False, performance_credit=False,
        cases=[dict(label='subject-'+lane+'-6-3', build_lane=lane, lane=1, mode=6,
            placement=3, control=0, cpu=192, expected_exit=125, status='unexecuted', launched=False)
            for lane in LANES])

    def pin(path):
        lexical = Path(os.path.abspath(path)); p = lexical.resolve(strict=True); value = fact(p)
        need(str(p) not in pins or pins[str(p)] == value, 'stable whole input')
        need(str(lexical) not in aliases or aliases[str(lexical)] == str(p), 'stable input alias')
        pins[str(p)] = value; aliases[str(lexical)] = str(p); return p

    def binary(path):
        p = pin(path); value = dict(fact(p), mode=p.stat().st_mode & 0o777)
        need(str(p) not in artifacts or artifacts[str(p)] == value, 'stable whole artifact and mode')
        artifacts[str(p)] = value; return p

    def closure():
        need(source() == r['source'] and os.sched_getaffinity(0) == {192}, 'same clean source and reserved CPU')
        need(all(fact(p) == v for p, v in pins.items()), 'whole input closure')
        need(all(dict(fact(p), mode=Path(p).stat().st_mode & 0o777) == v for p, v in artifacts.items()), 'whole artifact closure')
        need(all(str(Path(p).resolve(strict=True)) == v for p, v in aliases.items()), 'input alias closure')
        need(all(os.path.lexists(p) == v for p, v in presence.items()), 'loader configuration presence closure')
        need(all(Path(p).is_symlink() and os.readlink(p) == v for p, v in r['namespace_aliases'].items()), 'namespace alias closure')

    def complete(row):
        need(type(row['exit']) is int and row['exit'] == row['expected_exit'] and
             row['timed_out'] is False and row['error'] is None and row['reaped'] is True and
             row['cleanup_errors'] == [] and type(row['descriptors']) is list and
             all(d.get('closed') is True for d in row['descriptors']) and
             row['bounds'] == BOUNDS[row['profile']] and row['capture_limit'] == 16 << 20,
             'exact bounded outcome, timeout, process and descriptor closure')

    def run(name, argv, profile='metadata', expected=0, env=None, record=False):
        closure()
        need(len(r['commands']) < len(SCHEDULE) and (name, profile) == SCHEDULE[len(r['commands'])], 'fixed 50-setup/two-subject schedule')
        subject = name.startswith('subject-')
        need(record is subject and expected == (125 if subject else 0), 'actual required-read fault125, never unexpected termination acceptance')
        row = dict(name=name, argv=list(map(str, argv)), environment=dict(ENV if env is None else env),
            profile=profile, bounds=BOUNDS[profile], capture_limit=16 << 20, expected_exit=expected)
        r['commands'].append(row)
        try:
            out, err = (program_invoke if record else invoke)(row, private, 192, record=record)
            complete(row)
            return row, out, err
        finally:
            for value in row.get('captures', {}).values():
                try: need(fact(binary(private/value['file'])) == {k:value[k] for k in ('bytes', 'sha256')}, 'whole fresh command capture')
                except BaseException as error: r['final_errors'].append(repr(error))
            path = private/(name+'.json')
            if path.exists():
                try: need(json.loads(binary(path).read_bytes()) == row, 'whole fresh command row')
                except BaseException as error: r['final_errors'].append(repr(error))
            save(private/'receipt.json', r)
            print(json.dumps(dict(command=name, exit=row.get('exit'), duration_ns=row.get('duration_ns'))), flush=True)

    try:
        r['source'] = source(); need(r['source']['revision'] == args.expect_revision, 'exact clean current source')
        pin(__file__); imported_sources(pin)
        path = pin(args.native_receipt)
        need(path.name == 'receipt.json' and path.parent.parent == ROOT/'target/evaluation/inprocess' and
             args.native_receipt_sha256 == REFERENCE_SHA == fact(path)['sha256'], 'one exact retained reference receipt')
        n = json.loads(path.read_bytes()); directory = path.parent
        need(n['profile'] == 'persistent-loop-effects-native-v1' and n['status'] == 'observed_native_references' and
             n['revision'] == n['source']['revision'] == REFERENCE_REVISION and n['cpu'] == r['cpu'] and
             n['hardware'] == r['hardware'] and n['bounds'] == BOUNDS and n['error'] is None and n['final_errors'] == [] and
             all(n[k] is True for k in ('source_unchanged', 'inputs_unchanged', 'cleanup_complete')) and
             all(n[k] is False for k in ('owner_validated', 'mixed_policy_validated', 'qualification_credit', 'performance_credit')),
             'closed historical native source, exact CPU/hardware and no owner credit')
        need(tuple((x['name'], x['profile']) for x in n['commands']) == NATIVE_SCHEDULE and len(n['commands']) == 82,
             'original native82 schedule remains complete in historical receipt')
        for row in n['commands']: complete(row)
        rows = {x['name']:x for x in n['commands']}; used = []

        def retained(path):
            p = pin(path); key = str(p); value = fact(p)
            need(key in n['inputs'] or key in n['artifacts'], 'historical receipt owns every reused input/artifact')
            if key in n['inputs']: need(value == n['inputs'][key], 'whole current bytes equal historical input')
            if key in n['artifacts']:
                need(dict(fact(binary(p)), mode=p.stat().st_mode & 0o777) == n['artifacts'][key], 'whole historical artifact and mode')
            return p

        def capture(row, stream):
            value = row['captures'][stream]; p = retained(directory/value['file'])
            need(p.parent == directory and fact(p) == {k:value[k] for k in ('bytes', 'sha256')} and
                 0 <= value['bytes'] <= row['capture_limit'], 'whole bounded retained capture')
            return p.read_bytes()

        def recorded(name, argv, profile='metadata', expected=0, env=None, record=False):
            need(name in rows and name not in used and record is False, 'one closed-row replay, never a new subject')
            row = rows[name]
            need(row['argv'] == list(map(str, argv)) and row['environment'] == dict(ENV if env is None else env) and
                 row['profile'] == profile and row['expected_exit'] == expected == 0 and
                 json.loads(retained(directory/(name+'.json')).read_bytes()) == row,
                 'whole exact historical command argv/environment/profile/outcome')
            used.append(name); return row, capture(row, 'stdout'), capture(row, 'stderr')

        b = n['build']; tools = {name:retained(value['path']) for name, value in b['tools'].items()}
        need(all(fact(tools[name]) == {k:value[k] for k in ('bytes', 'sha256')} for name, value in b['tools'].items()) and
             Path(sys.executable).resolve() == tools['python'], 'whole original tool identities and actual Python')
        need(b['status'] == 'passed' and b['command_completed'] is True and b['final_errors'] == [] and
             b['configuration_unchanged'] is True and b['registry_before'] == b['registry_after'] and
             b['decoder_features'] == list(FEATURES), 'closed original effects archive build')
        archive = retained(b['artifacts']['decoder.a']['path'])
        need(archive == directory/'artifacts/decoder.a' and fact(archive) == n['archive'] and
             fact(archive) == {k:b['artifacts']['decoder.a'][k] for k in ('bytes', 'sha256')} and
             archive.read_bytes()[:8] == b'!<arch>\n', 'exact retained archive path and whole bytes')
        need(set(b['dep_info']) == {'tools/page-entry/selected/decoder/src/'+name for name in SOURCES}, 'exact thirteen-source archive domain')
        for name, value in b['dep_info'].items(): need(fact(retained(ROOT/name)) == value, 'current Rust source equals actual retained compiler input')
        for name in ('decoder/Cargo.toml', 'decoder/Cargo.lock', 'build-loop-effects-decoder.sh'): retained(SELECTED/name)
        for name in ('/etc/ld.so.cache', '/etc/ld.so.preload'):
            presence[name] = os.path.lexists(name)
            need(presence[name] == n['presence'][name], 'original loader configuration presence')
            if presence[name]: retained(name)
        need(presence['/etc/ld.so.preload'] is False, 'no global preload')
        builder = SimpleNamespace(tools=tools, environment=b['environment'], record=b,
            retained=directory/'artifacts', paths=dict(archive=archive), mov_guard=True, linked_epoch=True,
            scalar_span=True, extra_decoder_sources=('region.rs', 'mov_guard.rs', 'scalar_read.rs', 'loop_scalar.rs', 'byte_mov_guard.rs'),
            decoder_features=FEATURES)
        # These unchanged constructors only consume recorded rows here. They do
        # not compile, launch, or rewrite any historical evidence.
        holder = {}; original = application(builder, directory, retained, retained, aliases, recorded, holder)
        need(holder['application_build'] == n['application_build'], 'whole original fixture recipe/headers/ELF/helper facts')
        reader, controls, policy = reader_support(builder, directory, retained, retained, recorded, holder)
        need(holder['reader_support'] == n['reader_support'], 'whole retained native-policy build')
        gdb = retained(shutil.which('gdb', path=ENV['PATH'])); layout_script = retained(FIXTURE/'layout.py')
        _, out, err = recorded('layout-gdb-version', [gdb, '--version'], env=builder.environment)
        need(out and not err, 'actual native layout tool identity')
        _, out, err = recorded('native-layout', [gdb, '-q', '-nx', '-nh', '-batch', '-iex', 'set auto-load off',
            '-iex', 'set debuginfod enabled off', '-iex', 'set index-cache enabled off', '-iex', 'maintenance set worker-threads 1',
            '--readnow', '--se='+str(original), '-x', layout_script], profile='inspect', env=dict(builder.environment, MALLOC_ARENA_MAX='1'))
        layout_path = retained(directory/'native-dwarf-layout.json'); layout = json.loads(out)
        need(not err and out.endswith(b'\n') and out.count(b'\n') == 1 and layout_path.read_bytes() == out and
             n['native_layout'] == dict(path=str(layout_path), artifact=fact(layout_path), application=fact(original), observer=fact(layout_script)),
             'whole original native DWARF observation')
        image = reader.elf(original.read_bytes(), policy, layout, holder['application_build']['headers'])
        native_namespace(original, holder['application_build'], retained, holder)
        need(holder['native_namespace'] == n['native_namespace'], 'whole original empty native namespace')
        holder.update(cpu=192, commands=n['commands'][:54], seed_prerequisite=dict(planned=1, status='unexecuted', launched=False,
            expected_exit=0, bounds=BOUNDS['seed'], completed_applications=0, owner_subjects=0, performance_credit=False))
        seed = seed_prerequisite(builder, directory, retained, retained, recorded, holder)
        require_seed_record(holder['seed_prerequisite'], n['seed_prerequisite'])
        seed = (*seed, capture(rows['seed-prerequisite'], 'stdout'))
        name = 'subject-native-6-3'; prep = directory/name/'preparation.json'
        row, out, err = recorded(name, [tools['python'], '-B', retained(FIXTURE/'launch.py'), '--root', ROOT,
            '--role', 'native', '--case', 6, '--placement', 3, '--control', '0', '--original', original,
            '--library-root', original.parent, '--preparation', prep], profile='program')
        need(not err and set(row['captures']) == {'stdout', 'stderr'}, 'original native subject has full stdout and empty stderr')
        native_preparation(prep, row, original, 6, 3, 192, retained)
        native = reader.read(out, 0, 6, 3, 0, image, row['pid'], 192, seed)
        case = next(c for c in n['cases'] if (c['mode'], c['placement']) == (6, 3))
        need(case['label'] == name and case['status'] == 'observed_native_reference' and case['launched'] is True and
             case['exit'] == case['expected_exit'] == 0 and case['timed_out'] is False and 'errors' not in case and
             case['whole_process_ns'] == row['duration_ns'] and summary(native, 6, 3) == case['native'] and
             case['captures'] == {k:{j:v[j] for j in ('bytes', 'sha256')} for k, v in row['captures'].items()},
             'actual complete historical mode6/placement3 native reference')
        need(tuple(used) == tuple(name for name, _ in NATIVE_SCHEDULE[20:54]) + ('subject-native-6-3',), 'complete selected historical setup/reference replay')
        r['historical_reference'] = dict(receipt=fact(path), revision=n['revision'], source=n['source'], cpu=n['cpu'],
            hardware=n['hardware'], archive=fact(archive), original=fact(original), native=case['native'],
            recorded_commands=used, current_source_input_equal=True, current_native_credit=False,
            mutation_controls_replayed=False)
        support = dict(original=original, reader=reader, controls=controls, image=image, seed_reference=seed,
            application_build=holder['application_build'])
        subjects = {}; owner_reader = load('current_effects_pair_owner', OWNER/'read.py', pin)
        for lane in LANES:
            directory = private/(lane+'-build'); directory.mkdir(); state = r['lanes'][lane] = {}
            def lane_run(name, argv, profile='metadata', expected=0, env=None, record=False):
                return run(lane+'-'+name, argv, profile, expected, env, record)
            bridge = build_bridge(builder, dict(archive=archive), directory, pin, binary, aliases, lane_run, state,
                original, capture=True, differential=lane == 'differential')
            raw_emission(builder, bridge, pin, lane_run, state)
            layout = observed_layout(builder, bridge, directory, pin, binary, lane_run, state)
            subjects[lane] = (bridge, layout, *prepare_inputs(original, bridge, builder, directory, pin, binary,
                lane_run, state, support['application_build']))
        imported_sources(pin)
        for case in r['cases']:
            lane, label = case['build_lane'], case['label']; case['status'] = 'failed'
            directory = private/label; directory.mkdir()
            bridge, layout, interp, roots, objects, description, images, raws, carrier = subjects[lane]
            try:
                row, stdout, stderr = run(label, case_argv(builder, original, case, directory, roots, carrier, pin),
                    profile='program', expected=125, record=True)
                manifest = preparation(case, row, directory, original, roots, objects, description, carrier, private, binary, r)
                cap = row['captures']['record']; record = binary(private/cap['file'])
                need(128 < cap['bytes'] < 4 << 20 and fact(record) == {k:cap[k] for k in ('bytes', 'sha256')}, 'whole unchanged strict4MiB encoded record bound')
                inventory = image_inventory(original, interp, carrier, objects, manifest)
                inventory.update(bridge=bridge.read_bytes(), persistent_binding=r['lanes'][lane]['release_build']['persistent_binding'],
                    headers=r['lanes'][lane]['release_build']['headers'], app_symbols=image['symbols'])
                case.update(evaluate(case, row, stdout, stderr, record.read_bytes(), layout, inventory, support,
                    native, owner_reader, images, raws, carrier, run_controls=False, progress=case))
                case['status'] = expected_status(6)
            except Exception as error: case['error'] = type(error).__name__+': '+str(error)
            finally:
                last = r['commands'][-1]
                if last.get('name') == label:
                    case.update(exit=last.get('exit'), whole_process_ns=last.get('duration_ns'), timed_out=last.get('timed_out'),
                        launched=type(last.get('pid')) is int,
                        captures={k:{j:v[j] for j in ('bytes', 'sha256')} for k, v in last.get('captures', {}).items()})
                need(last.get('name') == label and last.get('reaped') is True and last.get('cleanup_errors') == [] and
                     type(last.get('descriptors')) is list and all(d.get('closed') is True for d in last['descriptors']),
                     'entire subject cleanup before any next lane')
                save(private/'receipt.json', r)
                print(json.dumps(dict(case=label, status=case['status'], error=case.get('error'))), flush=True)
        need(len(r['commands']) == 52 and tuple((x['name'], x['profile']) for x in r['commands']) == SCHEDULE and
             all(c['status'] == expected_status(6) for c in r['cases']), 'both required-read125 full reader/pair/terminal diagnostics pass')
        r['status'] = 'observed_two_focal_pairs_diagnostic_only'
    except BaseException as error: r['error'] = type(error).__name__+': '+str(error)
    finally:
        try:
            imported_sources(pin); closure(); r['source_unchanged'] = r['inputs_unchanged'] = True
            for row in r['commands']:
                need(json.loads(binary(private/(row['name']+'.json')).read_bytes()) == row, 'whole final command row')
                for value in row.get('captures', {}).values():
                    need(fact(binary(private/value['file'])) == {k:value[k] for k in ('bytes', 'sha256')}, 'whole final capture')
        except BaseException as error: r['final_errors'].append(type(error).__name__+': '+str(error))
        r['cleanup_complete'] = all(x.get('reaped') is True and x.get('cleanup_errors') == [] and
            type(x.get('descriptors')) is list and all(d.get('closed') is True for d in x['descriptors']) for x in r['commands'])
        if r['error'] or r['final_errors'] or not r['cleanup_complete']: r['status'] = 'failed'
        r.update(inputs=pins, artifacts=artifacts, aliases=aliases, presence=presence)
        save(private/'receipt.json', r)
        print(json.dumps(dict(status=r['status'], error=r['error'], final_errors=r['final_errors'],
            receipt=str(private/'receipt.json'), fact=fact(private/'receipt.json'))), flush=True)
    return int(r['status'] != 'observed_two_focal_pairs_diagnostic_only')


if __name__ == '__main__': raise SystemExit(main())
