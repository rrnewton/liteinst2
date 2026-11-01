#!/usr/bin/env python3
"""One bounded native/counted LS and true schedule after native41, PB and PF proof.

This diagnostic never grants whole-profile or performance qualification. Original
392/522 qualification and the ten-run native/DR comparison remain mandatory.
"""
import argparse
import csv
from datetime import datetime, timezone
import io
import json
import os
from pathlib import Path
import platform
import re
import sys

sys.dont_write_bytecode = True
from checks import source
from run import hardware
from page_selected import ENV, fact, need, save
from page_selected_generic_build import Build
from page_selected_process import invoke
from page_selected_oneshot_build import before_default
from persistent_dynamic import BOUNDS, digest, imported_sources
from persistent_epoch_build import FEATURES
from persistent_fused_build import build_bridge
from bounded_block_prerequisite import block_prerequisite
from bounded_fused_prerequisite import fused_prerequisite
from page_native_pair_performance import PROGRAM_ENV, prepare_workload, program_invoke
from startup_counter import protocol
from startup_counter_terminal import completed_terminal, counters
import persistent_group_counter_process as counter_process
from direct_frontier_program import direct_prerequisite, final_prefix
import namespace

ROOT = Path(__file__).resolve().parents[2]
PROFILES = dict(BOUNDS)
TARGET = [30, 512 << 20, 16 << 20, 60]
PROGRAMS = (('ls', '/bin/ls', ('-d', '.'), b'.\n'), ('true', '/bin/true', (), b''))
ORDER = tuple((kind, lane) for kind, *_ in PROGRAMS for lane in ('native', 'counted'))
REQUIRED = ('same-revision original392 and cross-pair522 qualification with their original prerequisites',
            'ten-run same-host native and DR comparison')


def cohort(builder, products, private, pin, binary, aliases, run, r):
    states = {}
    for kind, program, args, expected_stdout in PROGRAMS:
        original = pin(program); directory = private/(kind+'-build'); directory.mkdir()
        (directory/'external-inputs').mkdir()
        holder = r['program_builds'][kind] = {}
        def lane_run(name, argv, profile='metadata', expected=0, env=None, record=False):
            return run(kind+'-'+name, argv, profile=profile, expected=expected, env=env, record=record)
        bridge = build_bridge(builder, products, directory, pin, binary, aliases, lane_run, holder, original,
                              capture=False, retained_counters=True, differential=False)
        rb = holder['release_build']
        need(rb['status'] == 'passed' and rb['profile'] == 'persistent-fused-counters-v1' and
             rb['capture'] is False and rb['counters'] is True and rb['retained_counters'] is True and
             rb['archive'] == fact(products['archive']) and rb['counter_schema'] ==
             dict(version=2, bytes=752, page=4096, initial_seals=6, final_seals=23) and
             rb['active_domain']['slots'] == rb['active_domain']['source_pairs_max'] == 2 and
             rb['active_domain']['differential'] is False and rb['dispatch']['shared_boundaries'] == 8 and
             rb['direct_frontier'] == dict(version=1, policy_version=11, conditions=16, shared_boundaries=8,
                typed_external_arms=True, unknown_target='original branch-before full drain',
                partition='direction-fused', all_arms_directory=False) and
             rb['bounded_fused'] == dict(version=1, policy_version=11, heads_max=128,
                shared_boundaries=8, active_members_max=2, call_ret=False) and
             rb['persistent_binding']['mode'] == 'counters' and
             rb['persistent_binding']['profile'] == 'persistent-fused-counters-v1' and
             rb['persistent_binding']['bounded_fused'] is True and rb['persistent_binding']['policy_version'] == 11 and
             all(rb['active_domain'][k] is True and rb['persistent_binding'][k] is True for k in
                 ('unregistered', 'subentry', 'cross_pair', 'direct_frontier', 'native_probe', 'parse_memo')),
             'exact per-original bounded-fused counter profile, full build gates and unchanged ABI2')
        state = prepare_workload(kind, original, args, bridge, builder, directory, pin, binary, lane_run, r, namespace)
        holder.update(original=fact(original), bridge=fact(bridge), carrier=fact(state['carrier']))
        states[kind] = state
    imported_sources(pin)
    need([(c['program'], c['lane']) for c in r['cases']] == list(ORDER), 'one fixed four-subject schedule')
    references = {}
    for case in r['cases']:
        kind, lane = case['program'], case['lane']; state = states[kind]
        expected_stdout = next(x[3] for x in PROGRAMS if x[0] == kind)
        ns = private/(case['label']+'-namespace')
        argv = state['argv'] if lane == 'native' else [builder.tools['python'], '-B', state['carrier_tool'],
            'exec-loader', '--counter-fd', '{counter_fd}', '--counter-nonce', '{counter_nonce}',
            '--library-root', '/usr/lib64', '--namespace', ns, state['carrier'], state['original'], '--', *state['argv']]
        case['status'] = 'failed'; row = None
        try:
            try:
                row, stdout, stderr = run(case['label'], argv, profile='program', expected=None,
                                         env=PROGRAM_ENV, counter=lane == 'counted', subject=True)
            finally:
                if r['commands'] and r['commands'][-1]['name'] == case['label']:
                    row = r['commands'][-1]
                    case.update(exit=row.get('exit'), process_ns=row.get('process_ns'),
                        wrapper_interval_ns=row.get('duration_ns'), timed_out=row.get('timed_out'),
                        launched=type(row.get('pid')) is int,
                        captures={k: {n: v[n] for n in ('bytes', 'sha256')} for k, v in row.get('captures', {}).items()})
                    if lane == 'counted' and row.get('reaped'):
                        # Prefix validation has no completed-transaction arithmetic.
                        case['counts'] = final_prefix(row, private, binary)
                        case['counter_collection'] = 'closed_usable_prefix'
                        counter_process.namespace_join(state, ns, binary, r, namespace, row['counter_input'])
                        case['namespace_complete'] = True
            need(row['exit'] == 0 and row['reaped'] is True and row['timed_out'] is False and
                 row['error'] is None and row['cleanup_errors'] == [], 'actual completed program before acceptance')
            need(type(row['process_ns']) is int and 0 < row['process_ns'] <= row['duration_ns'],
                 'actual Popen-to-reap interval within the complete wrapper interval')
            if lane == 'native':
                need(stdout == expected_stdout and stderr == b'', 'exact real native program output and empty stderr')
                references[kind] = (row['exit'], stdout)
                case.update(status='completed_native_reference', stdout_equal=True)
            else:
                need(kind in references and (row['exit'], stdout) == references[kind] and stdout == expected_stdout,
                     'complete counted stdout and exit equal the exact successful native reference')
                terminal = completed_terminal(stderr, case['counts'])
                actual = counters(stderr)
                case.update(status='completed_unqualified', stdout_equal=True, terminal=terminal,
                    terminal_counters={k: actual[k] for k in ('LI2_CHAIN', 'LI2_LINKED_NATIVE_PROBE', 'LI2_NATIVE_PAIR')})
        except Exception as exc:
            case['error'] = type(exc).__name__+': '+str(exc)
            # An unsuccessful subject never acquires a completed-terminal label.
            case['terminal'] = case['terminal_counters'] = None
        need(row is not None and row.get('reaped') is True and row.get('cleanup_errors') == [] and
             all(d['closed'] for d in row.get('descriptors', [])) and not r['final_errors'],
             'finish each child and every descriptor before the next fixed subject')
    need(all(c['status'] == ('completed_native_reference' if c['lane'] == 'native' else 'completed_unqualified')
             for c in r['cases']), 'all four original bounded subjects must complete; prefixes remain failures')


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--expect-revision', required=True)
    ap.add_argument('--direct-receipt', type=Path, required=True)
    ap.add_argument('--block-receipt', type=Path, required=True)
    ap.add_argument('--block-receipt-sha256', required=True)
    ap.add_argument('--fused-receipt', type=Path, required=True)
    ap.add_argument('--fused-receipt-sha256', required=True)
    args = ap.parse_args()
    need(not sys.flags.optimize and len(os.sched_getaffinity(0)) == 1, 'assertions and one reserved CPU')
    need(re.fullmatch('[0-9a-f]{40}', args.expect_revision), 'exact committed revision')
    os.chdir(ROOT); cpu = next(iter(os.sched_getaffinity(0)))
    args.direct_receipt = args.direct_receipt.resolve(strict=True)
    args.block_receipt = args.block_receipt.resolve(strict=True)
    args.fused_receipt = args.fused_receipt.resolve(strict=True)
    need(args.direct_receipt.parent == ROOT/'evaluation/inprocess/results' and args.direct_receipt.suffix == '.json',
         'portable canonical public native41 prerequisite')
    name = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')+'-bounded-fused-program-'+args.expect_revision[:12]
    private = ROOT/'target/evaluation/inprocess'/name; private.mkdir(parents=True, exist_ok=False)
    public = ROOT/'evaluation/inprocess/results'/(name+'.json'); public.parent.mkdir(parents=True, exist_ok=True)
    need(not public.exists() and not public.with_suffix('.csv').exists(), 'fresh public result identity')
    receipt = private/'receipt.json'
    r = dict(schema=1, profile='bounded-fused-program-probe-v1', status='failed', revision=args.expect_revision,
        source=None, source_unchanged=False, cleanup_complete=False, commands=[], cases=[], error=None, final_errors=[],
        cpu=cpu, hardware=hardware(cpu), bounds=PROFILES, namespace_aliases={}, program_builds={},
        qualification_credit=False, whole_profile_qualified=False, performance_credit=False,
        required_unmet=list(REQUIRED), scope='One fixed real LS/true native and counted schedule; no throughput or whole-profile claim.',
        counter_scope='Post-reap per-cell prefix. Events/signals count linked ingress, not all kernel traps; direct hits and stage timings unavailable.')
    for kind, lane in ORDER:
        r['cases'].append(dict(label='subject-'+kind+'-'+lane, program=kind, lane=lane, expected_exit=0,
            status='unexecuted', launched=False, stdout_equal=False, counts=None, terminal=None, terminal_counters=None,
            namespace_complete=None if lane == 'native' else False, counter_collection='not_applicable' if lane == 'native' else 'unavailable'))
    pins, artifacts, aliases, presence = {}, {}, {}, {}

    def pin(path):
        alias=Path(os.path.abspath(path));p=alias.resolve(strict=True);value=fact(p)
        need(str(alias) not in aliases or aliases[str(alias)]==str(p),'stable input alias')
        need(str(p) not in pins or pins[str(p)]==value,'stable input bytes')
        pins[str(p)]=value;aliases[str(alias)]=str(p)
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
        need(all(os.path.lexists(p)==v for p,v in presence.items()),'loader configuration presence')
        need(all(Path(p).is_symlink() and os.readlink(p)==v for p,v in r['namespace_aliases'].items()),'sealed namespace aliases unchanged')

    def run(name, argv, profile='metadata', expected=0, env=None, record=False, counter=False, subject=False):
        closure()
        need(not r['final_errors'] and not any(c['name'] == name for c in r['commands']), 'clean unique command/capture name')
        need(record is False and (not counter or subject) and
             (not subject or profile == 'program' and PROFILES[profile] == TARGET and env == PROGRAM_ENV),
             'only original whole-program bounds/environment and separate counter owner')
        row = dict(name=name, argv=list(map(str, argv)), environment=dict(ENV if env is None else env),
                   profile=profile, bounds=PROFILES[profile], capture_limit=16 << 20, expected_exit=expected)
        r['commands'].append(row)
        try:
            function = counter_process.program_invoke if counter else program_invoke if subject else invoke
            out, err = function(row, private, cpu, record=record)
            need(expected is None or row['exit'] == expected, 'actual command exit: ' + name)
            return row, out, err
        finally:
            for item in row.get('captures', {}).values():
                try:
                    p = private / item['file']
                    need(fact(binary(p)) == {k: item[k] for k in ('bytes', 'sha256')}, 'actual capture bytes')
                except BaseException as error:
                    r['final_errors'].append('capture ' + name + ': ' + repr(error))
            try:
                p = private / (name + '.json')
                if p.exists():
                    need(json.loads(binary(p).read_bytes()) == row, 'retained actual command row')
            except BaseException as error:
                r['final_errors'].append('command record ' + name + ': ' + repr(error))

    def build_run(name, argv, profile='metadata', env=None, expected=0):
        before_default(name, argv, builder, pin, aliases, run, r)
        return run(name, argv, profile=profile, expected=expected, env=env)

    builder = Build(r, private, pin, binary, build_run, ('region.rs',),
                    scalar_span=True, linked_epoch=True, mov_guard=True)
    try:
        r['source'] = source()
        need(r['source']['revision'] == args.expect_revision and PROFILES['program'] == TARGET, 'exact clean source and original target bounds')
        _, names, err = run('tracked-input-list', ['git', 'ls-files', '-z', 'tools/page-entry', 'evaluation/inprocess'])
        need(not err, 'complete tracked input list')
        for raw in names.split(b'\0'):
            if raw:
                path = os.fsdecode(raw)
                if not path.startswith('evaluation/inprocess/results/'): pin(ROOT/path)
        for path in ('/etc/ld.so.cache', '/etc/ld.so.preload'):
            presence[path] = os.path.lexists(path)
            if presence[path]: pin(path)
        need(not presence['/etc/ld.so.preload'], 'no global preload')
        imported_sources(pin)
        products = builder.prepare()
        need(builder.decoder_features == FEATURES and builder.extra_decoder_sources == ('region.rs', 'mov_guard.rs') and
             builder.record['decoder_features'] == list(FEATURES) and builder.record['status'] == 'passed' and
             builder.record['command_completed'] is True, 'fresh actual current region/span/linked/MOV decoder')
        r['archive'] = fact(products['archive'])
        r['direct_prerequisite'] = direct_prerequisite(args.direct_receipt, r, pin, binary, products['archive'])
        r['block_prerequisite'] = block_prerequisite(args.block_receipt, args.block_receipt_sha256, r, pin, binary, products['archive'])
        r['fused_prerequisite'] = fused_prerequisite(args.fused_receipt, args.fused_receipt_sha256, r, pin, binary, products['archive'])
        protocol(builder, run, r)
        cohort(builder, products, private, pin, binary, aliases, run, r)
        r['status'] = 'completed_unqualified'
    except BaseException as exc:
        r['error'] = type(exc).__name__+': '+str(exc)
    finally:
        r['final_errors'].extend(builder.finish())
        try:
            imported_sources(pin); closure()
            need(source() == r['source'], 'exact source unchanged')
            r['source_unchanged'] = True
        except BaseException as exc:
            r['final_errors'].append(type(exc).__name__+': '+str(exc))
        r['cleanup_complete'] = bool(r['commands']) and all(c.get('reaped') is True and c.get('cleanup_errors') == [] and
            all(d['closed'] for d in c.get('descriptors', [])) for c in r['commands'])
        if r['error'] or r['final_errors'] or not r['source_unchanged'] or not r['cleanup_complete']:
            r['status'] = 'failed'
        r.update(inputs=pins, artifacts=artifacts, aliases=aliases, presence=presence)
        save(receipt, r)
        hw = dict(r['hardware']); flags = hw.pop('isa_flags')
        hw.update(isa_flags_count=len(flags), isa_flags_sha256=digest(flags))
        summary = {k: r[k] for k in ('schema', 'profile', 'status', 'revision', 'source', 'source_unchanged',
            'cleanup_complete', 'cpu', 'bounds', 'scope', 'counter_scope', 'qualification_credit',
            'whole_profile_qualified', 'performance_credit', 'required_unmet')}
        summary.update(hardware=hw, receipt=fact(receipt), direct_prerequisite=r.get('direct_prerequisite'),
            block_prerequisite=r.get('block_prerequisite'),
            fused_prerequisite=r.get('fused_prerequisite'),
            archive=r.get('archive'), command_count=len(r['commands']), commands_sha256=digest(r['commands']),
            program_environment=PROGRAM_ENV,
            error_type=r['error'].split(':', 1)[0] if r['error'] else None, final_error_count=len(r['final_errors']),
            tool_versions=builder.record.get('numeric_versions'),
            reproduce=['cpuset-alloc', 'run', '--cores', '1', '--', 'python3', '-B',
                'evaluation/inprocess/bounded_fused_program.py', '--expect-revision', args.expect_revision,
                '--direct-receipt', str(args.direct_receipt.relative_to(ROOT)),
                '--block-receipt', str(args.block_receipt.relative_to(ROOT)),
                '--block-receipt-sha256', args.block_receipt_sha256,
                '--fused-receipt', str(args.fused_receipt.relative_to(ROOT)),
                '--fused-receipt-sha256', args.fused_receipt_sha256],
            counter_protocol={k: r.get('counter_protocol', {}).get(k) for k in ('scope', 'guest_executions', 'refusal_count')},
            closure=dict(inputs=len(pins), artifacts=len(artifacts), commands=len(r['commands']),
                         captures=sum(len(c.get('captures', {})) for c in r['commands'])))
        summary['programs'] = {}
        for kind, program, args_, _ in PROGRAMS:
            build = r['program_builds'].get(kind, {}); binding = build.get('release_build', {}).get('persistent_binding')
            summary['programs'][kind] = dict(argv=[program, *args_], external=r.get('system_inputs', {}).get(kind),
                bridge=build.get('bridge'), carrier=build.get('carrier'),
                binding_sha256=digest(binding) if binding else None,
                policy_sha256=binding.get('policy_sha256') if binding else None)
        summary['cases'] = [{k: c[k] for k in ('program', 'lane', 'status', 'expected_exit', 'exit', 'process_ns',
            'wrapper_interval_ns', 'timed_out', 'launched', 'captures', 'stdout_equal', 'namespace_complete',
            'counter_collection', 'counts', 'terminal', 'terminal_counters') if k in c} |
            dict(error_type=c['error'].split(':', 1)[0] if c.get('error') else None) for c in r['cases']]
        payload = (json.dumps(summary, sort_keys=True, separators=(',', ':'), allow_nan=False)+'\n').encode()
        table = io.StringIO(); writer = csv.writer(table, lineterminator='\n')
        writer.writerow(('revision', 'program', 'lane', 'status', 'exit', 'process_ns', 'wrapper_interval_ns',
                         'counter_scope', 'counter', 'value'))
        for case in summary['cases']:
            stem = (r['revision'], case['program'], case['lane'], case['status'], case.get('exit'),
                    case.get('process_ns'), case.get('wrapper_interval_ns'))
            writer.writerow((*stem, '', '', ''))
            if case['counts'] is not None:
                for name in ('events', 'signals', 'group', 'misses', 'maps', 'view', 'native'):
                    value = case['counts'][name]
                    cells = value.items() if type(value) is dict else enumerate(value) if type(value) is list else [('', value)]
                    for key, number in cells:
                        label = ('linked_events' if name == 'events' else 'linked_signals' if name == 'signals' else name)
                        writer.writerow((*stem, 'post_reap_per_cell_prefix', label+('.'+str(key) if key != '' else ''), number))
        csv_bytes = table.getvalue().encode()
        need(len(payload) <= 32 << 10 and len(csv_bytes) <= 32 << 10 and
             all(x.encode() not in payload+csv_bytes for x in (str(ROOT), str(Path.home()), '/home/', platform.node()) if len(x) > 1),
             'compact public JSON/CSV without host paths or raw logs')
        with public.open('xb') as f: f.write(payload)
        with public.with_suffix('.csv').open('xb') as f: f.write(csv_bytes)
    print(json.dumps(dict(status=r['status'], receipt=str(public.relative_to(ROOT)))))
    return int(r['status'] != 'completed_unqualified')


if __name__ == '__main__':
    raise SystemExit(main())
