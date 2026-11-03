#!/usr/bin/env python3
"""Two real programs through plain LCX; execution diagnostic, not qualification.

Use a closed current RO archive without changing its program outcomes. Every
subject still requires exit zero and its exact stdout. Partial terminal values
are schema-checked observations, never successful-owner or full-state proof.
"""
import argparse
import json
import os
from pathlib import Path
import re
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
from checks import source
from run import hardware
from page_selected import ENV, fact, need, save
from persistent_dynamic import BOUNDS, imported_sources
from loop_ro_current_archive import current_archive
from loop_resident_rx_build import build_rx
from loop_resident_rx_program import TARGET, PROGRAMS, ORDER, NAMES, SETUP, SCHEDULE
from page_selected_process import invoke
from page_cost_compare import PROGRAM_ENV, program_invoke
from page_native_pair_performance import prepare_workload, namespace_join
from page_selected_effect_ls import finalize
from loop_ro_oracle_reports import row as scalar_row
import page_native_pair_reports as original
import namespace

PROFILE = 'loop-cached-direct-context-program-execution-v1'
FRESH = SCHEDULE[len(SETUP):]
PREFIX = b'LI2_LOOP_CACHED_DIRECT_PROGRAM '
FIELDS = tuple(('version status failure_code detail_negative detail_abs initialized poisoned '
    'builds opens closes entries recoveries retirements invalidations serial built published '
    'opened closed recovery_owned recovery_result').split())
CANDIDATE_PREFIX = b'LI2_LOOP_CACHED_DIRECT_CANDIDATE '
CANDIDATE_IMAGE_FIELDS = tuple(('aux_version aux_ready aux_result inner_version inner_ready '
    'inner_result original_pc generated miss_offset image_bytes boundaries').split())
CANDIDATE_FIELDS = ('version', 'status', 'failure_code', 'detail_negative', 'detail_abs',
    'members', 'count', 'image_present') + CANDIDATE_IMAGE_FIELDS
PAIR_COUNTS = ('events', 'seeds', 'extensions', 'epochs_closed', 'one_page_closes',
    'two_page_closes', 'policy_closes', 'capacity_closes', 'refaults', 'refault_completed')
OUTCOME = ('status', 'failure_code', 'detail_negative', 'detail_abs')


def terminal(stderr, exit_status):
    """Original scalar/array schemas only; no completed-owner theorem on failure."""
    if not stderr:
        need(exit_status != 0, 'successful execution requires actual terminal reports')
        return None
    need(type(stderr) is bytes and stderr.endswith(b'\n'), 'whole actual terminal stderr')
    lines = stderr[:-1].split(b'\n')
    parts = [line.partition(b' ') for line in lines]
    need(all(sep == b' ' and name.startswith(b'LI2_') and 0 < len(line)+1 <= 4096 and
             b'\r' not in line for (name, sep, _), line in zip(parts, lines, strict=True)) and
         len({name for name, _, _ in parts}) == len(parts),
         'bounded complete terminal rows with unique actual names')
    values = {name: original.rseq.decode(raw) for name, _, raw in parts}
    required = (b'LI2_LOADER', b'LI2_NATIVE_PAIR', b'LI2_NATIVE', PREFIX[:-1], CANDIDATE_PREFIX[:-1])
    need(all(name in values for name in required), 'actual loader, pair, native, plain LCX and candidate rows')
    loader, pair, native = (values[name] for name in required[:3])
    original._unsigned(loader, original.generic.KEYS-{'scope'}, scope='partial_selected_reusable_effects')
    need(loader['version'] == loader['selected_profile'] == loader['generic_tf_profile'] == 1,
         'actual selected reusable loader profile')
    original.pair_schema(pair)
    need(type(native) is dict and type(native.get('revisit_count')) is int and
         0 <= native['revisit_count'] <= 16, 'actual native_counts.revisit_ns[16] dimension')
    original._unsigned(native, original.NATIVE_KEYS-{'revisit_ns'}, {'revisit_ns': native['revisit_count']})
    need(native['version'] == 1, 'original native counter version')
    at = [i for i, line in enumerate(lines) if line.startswith(PREFIX)]
    need(len(at) == 1 and at[0]+2 < len(lines) and
         lines[at[0]+1].startswith(CANDIDATE_PREFIX) and
         lines[at[0]+2].startswith(b'LI2_LOOP_EFFECTS '), 'exact plain LCX, candidate and original report boundary')
    context = scalar_row(lines[at[0]], PREFIX, FIELDS)
    candidate = scalar_row(lines[at[0]+1], CANDIDATE_PREFIX, CANDIDATE_FIELDS)
    need(all(candidate[k] < 1 << 32 for k in ('members', 'count', 'image_present',
             'aux_version', 'aux_ready', 'aux_result', 'inner_version', 'inner_ready',
             'inner_result', 'miss_offset', 'image_bytes', 'boundaries')) and
         candidate['image_present'] == int(1 <= candidate['count'] <= 8),
         'actual uint32 candidate fields and exact bounded image-presence selector')
    need(candidate['aux_ready'] in (0, 1) and candidate['inner_ready'] in (0, 1) and
         (candidate['image_present'] or all(candidate[k] == 0 for k in CANDIDATE_IMAGE_FIELDS)),
         'actual ready flags and whole zero absent-image projection; no success-plan theorem')
    need(all(context[k] in (0, 1) for k in ('initialized', 'poisoned', 'built', 'published',
             'opened', 'closed', 'recovery_owned')), 'actual binary LCX state fields')
    need(all(tuple(v[k] for k in OUTCOME) == tuple(loader[k] for k in OUTCOME)
             for v in (pair, context, candidate)) and
         (native['status'], native['failure_code']) == (loader['status'], loader['failure_code']) and
         loader['status'] == exit_status,
         'every observed terminal outcome equals the actual process exit')
    if exit_status == 0:
        need(all(loader[k] == 0 for k in OUTCOME), 'successful execution has no reported failure')
    return dict(loader=loader, native=native, native_pair=pair, lcx=context, lcx_candidate=candidate,
        native_pair_counts=dict(zip(PAIR_COUNTS, pair['counts'], strict=True)),
        other_rows=[name.decode() for name in values if name not in required],
        validation_scope='Five schema-checked terminal rows and exact outcome joins; other rows retained raw.',
        owner_proof_validated=False, edge_traversals=None, qualification_credit=False)


def prepare(builder, archive, private, pin, binary, aliases, run, r):
    owned = builder.record['artifacts']['decoder.a']
    need(archive == builder.paths['archive'] == builder.retained/'decoder.a' and
         str(archive) == owned['path'] and fact(archive) == r['archive'] ==
         {k: owned[k] for k in ('bytes', 'sha256')}, 'current14-source owner of the exact release archive')
    (private/'external-inputs').mkdir()
    states = {}; r['release_builds'] = {}
    for kind, program, args, _ in PROGRAMS:
        original_image = pin(program); directory = private/(kind+'-build'); directory.mkdir()
        holder = r['release_builds'][kind] = {}
        def labelled(name, argv, **kwargs):
            return run(kind+'-'+name, argv, **kwargs)
        bridge = build_rx(builder, archive, original_image, directory, pin, binary, aliases,
            labelled, holder, 'release', cache8=True, group_descriptor=True, arena=True,
            cached_direct_context=True)
        binding = holder['binding']
        need(holder['status'] == 'compiled_diagnostic_only' and
             binding['profile'] == 'persistent-loop-cached-direct-context-release-v1' and
             binding['mode'] == 'release' and binding['archive'] == r['archive'] and
             binding['capture_version'] is None and binding['arena']['nodes'] == 12 and
             not any(k in binding for k in ('cached_direct_observer', 'arena_program',
                 'arena_observer', 'cache8_program', 'group_descriptor_observer')),
             'actual plain twelve-node LCX release; no finite observer or all-node program identity')
        states[kind] = prepare_workload(kind, original_image, args, bridge, builder,
            private, pin, binary, run, r, namespace)
    return states


def cohort(builder, states, private, binary, run, r):
    expected = {kind: out for kind, _, _, out in PROGRAMS}
    for ordinal, (kind, lane) in enumerate(ORDER):
        name = NAMES[ordinal]; state = states[kind]; case = r['cases'][ordinal]
        case['status'] = 'failed'; ns = private/(name+'-namespace'); start = len(r['commands'])
        argv = [builder.tools['python'], '-B', state['carrier_tool'], 'exec-loader',
            '--library-root', '/usr/lib64', '--namespace', ns,
            state['carrier'], state['original'], '--', *state['argv']]
        try:
            row, out, err = run(name, argv, profile='program', env=PROGRAM_ENV)
            namespace_join(state, ns, binary, r, namespace); case['namespace_complete'] = True
            case['stdout_matches'] = out == expected[kind]
            case['terminal'] = terminal(err, row['exit'])
            need(row['exit'] == row['expected_exit'] == 0 and case['stdout_matches'],
                 'actual required exit zero and whole exact real-program stdout')
            case['status'] = 'completed_execution_diagnostic'
            case['application_completed'] = True
        except Exception as error:
            case['error'] = type(error).__name__+': '+str(error)
            if r['error'] is None: r['error'] = case['error']
            actual = r['commands'][start:]
            need(len(actual) == 1 and actual[0]['name'] == name and
                 type(actual[0].get('exit')) is int and actual[0].get('reaped') is True and
                 actual[0].get('cleanup_errors') == [] and
                 all(d.get('closed') is True for d in actual[0].get('descriptors', [])),
                 'continue the fixed two subjects only after complete actual child cleanup')
        finally:
            attempted = r['commands'][start:]
            if attempted:
                row = attempted[-1]
                case.update({k: row.get(k) for k in ('exit', 'process_ns', 'duration_ns',
                    'process_start_ns', 'process_reaped_ns', 'timed_out', 'reaped',
                    'user_cpu_ns', 'system_cpu_ns', 'minor_faults', 'major_faults',
                    'voluntary_switches', 'involuntary_switches')})
                case['captures'] = {k: {f: v[f] for f in ('bytes', 'sha256')}
                    for k, v in row.get('captures', {}).items()}
            print(json.dumps({k: case.get(k) for k in ('ordinal', 'workload', 'status', 'exit', 'error')}), flush=True)
    need(len(r['commands']) == 14 and len(r['cases']) == 2 and
         all(c['application_completed'] for c in r['cases']) and r['error'] is None,
         'both required executions and all fourteen fresh commands, no discarded failure')


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    for name in ('expect-revision', 'current-build', 'current-build-sha256'):
        ap.add_argument('--'+name, required=True)
    ap.add_argument('--output', type=Path, required=True)
    a = ap.parse_args(); os.chdir(ROOT)
    need(sys.version_info[:2] == (3, 12) and not sys.flags.optimize and
         re.fullmatch('[0-9a-f]{40}', a.expect_revision) and
         re.fullmatch('[0-9a-f]{64}', a.current_build_sha256) and len(os.sched_getaffinity(0)) == 1,
         'Python3.12, exact revision/provider, assertions and reserved singleton CPU')
    need(len(SETUP) == 20 and len(SCHEDULE) == 34 and len(FRESH) == 14 and
         BOUNDS['program'] == BOUNDS['release_build'] == TARGET == [30, 512 << 20, 16 << 20, 60],
         'original twenty recorded provider rows and fourteen fresh commands under unchanged bounds')
    private = a.output.resolve()
    need(private.parent == ROOT/'target/evaluation/inprocess' and not private.exists(), 'fresh confined diagnostic output')
    private.mkdir(mode=0o700); cpu = next(iter(os.sched_getaffinity(0)))
    pins = {}; aliases = {}; artifacts = {}; presence = {}
    r = dict(schema=1, profile=PROFILE, status='failed', revision=a.expect_revision,
        source=None, source_unchanged=False, inputs_unchanged=False, cleanup_complete=False,
        cpu=cpu, hardware=hardware(cpu), bounds=dict(BOUNDS), commands=[], namespace_aliases={},
        cases=[dict(ordinal=i, workload=k, lane=lane, status='not_run', expected_exit=0,
            application_completed=False, qualification_credit=False) for i, (k, lane) in enumerate(ORDER)],
        error=None, final_errors=[], qualification_credit=False, full_state_credit=False,
        whole_profile_qualified=False, performance_credit=False,
        scope='Separate plain LCX ls/true execution diagnostic; exact stdout/exit and namespace custody. '
              'No all-node,633-control,causal,full-state or full-profile qualification.',
        count_scope='Terminal values follow the original terminal revoke. LCX entries count groups containing '
                    'auxiliary images, not observed edge traversals. Native-pair capacity closes precede '
                    'third-page eligibility and do not establish a clean candidate.',
        timing_scope='Single bounded process observations; failed elapsed values are failure cost only.',
        private_memory_scope='Native-page execution retains its existing private-RW-memory limitation.')

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
        need(record is False and step is False,'plain release has no protected capture or step instrumentation')
        need(len(r['commands']) < len(FRESH) and (name, profile) == FRESH[len(r['commands'])] and
             type(expected) is int and expected == 0, 'fixed fourteen-command schedule with required zero outcomes')
        row=dict(name=name,argv=list(map(str,argv)),profile=profile,bounds=BOUNDS[profile],capture_limit=16<<20,
                 environment=dict(ENV if env is None else env),expected_exit=expected)
        r['commands'].append(row)
        try:
            if name in NAMES:
                need(profile == 'program' and row['bounds'] == TARGET and row['environment'] == PROGRAM_ENV,
                     'exact two subject environments and original bounds')
            out,err=(program_invoke if name in NAMES else invoke)(row,private,cpu,record=record,step=step)
            need(type(row['exit']) is int, 'actual command outcome '+name)
            if name not in NAMES:
                need(row['exit'] == expected, 'actual setup command must succeed '+name)
            # The subject's required-zero assertion remains in cohort after its
            # raw failure counters and exact namespace have been retained.
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

    try:
        r['source'] = source()
        need(r['source']['revision'] == a.expect_revision, 'exact current clean installed source')
        pin(__file__); imported_sources(pin)
        for name in ('/etc/ld.so.cache', '/etc/ld.so.preload'):
            presence[name] = os.path.lexists(name)
            if presence[name]: pin(name)
        need(not presence['/etc/ld.so.preload'], 'no global preload')
        builder, archive, r['archive_build'] = current_archive(a.current_build,
            a.current_build_sha256, ROOT, pin, binary, aliases)
        need(r['archive_build']['current_compiler_inputs_equal'] is True and
             len(r['archive_build']['compiled_sources']) == 14 and
             r['archive_build']['archive_rebuilt_by_consumer'] is False,
             'all actual current compiler inputs joined; producer program failures remain failed')
        r['archive'] = fact(archive)
        states = prepare(builder, archive, private, pin, binary, aliases, run, r)
        cohort(builder, states, private, binary, run, r)
        need(not r['final_errors'], 'complete retained command custody')
        r['status'] = 'completed_execution_diagnostic'
    except BaseException as error:
        if r['error'] is None: r['error'] = type(error).__name__+': '+str(error)
    finally:
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
        print(json.dumps(dict(status=r['status'], receipt=str(private/'receipt.json'))), flush=True)
    return int(r['status'] != 'completed_execution_diagnostic')


if __name__ == '__main__':
    raise SystemExit(main())
