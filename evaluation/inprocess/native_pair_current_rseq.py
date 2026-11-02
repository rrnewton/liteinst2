#!/usr/bin/env python3
"""Current lifecycle/native-pair rseq mapping component, on one reserved CPU.

Two current C builds and five fixed cases each. The supplied native receipt
authenticates the retained Rust archive/tools through the existing setup replay;
no old C closure, subject, registration, application or owner credit is reused.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys

sys.dont_write_bytecode = True
ROOT = Path.cwd().resolve()
sys.path[:0] = [str(ROOT/'evaluation/inprocess'), str(ROOT/'tools/page-entry')]
from checks import source
from run import hardware
from page_selected import ENV, elf, fact, interpreter, need, save
from page_selected_process import invoke
from page_selected_effect_ls import PROGRAM_ENV
from page_selected_register_time_build import recipe, expand, headers
from persistent_dynamic import BOUNDS, imported_sources
from scalar_span_trace_build import resolved_libraries
from loop_ro_native_positive import retained_support
import namespace

SELECTED = ROOT/'tools/page-entry/selected'
FIXTURE = SELECTED/'tests/rseq_pair_current'
MODES = ('projected', 'verified')
SCHEDULE = (('historical-decoder-recipe', 'metadata'),) + tuple(
    (mode+'-'+name, profile) for mode in MODES for name, profile in (
        ('build', 'release_build'), ('headers', 'metadata'), ('libraries', 'inspect'))
) + tuple((mode+'-case-'+str(case), 'finite') for mode in MODES for case in range(5))
SCRIPT_SHA = 'f90ce64ee70c7bffa0839dfa467346f16f67fd69a4b87584c266820726a9bb42'
H = lambda data: hashlib.sha256(data).hexdigest()


def extracted(path, name):
    """Independently join each generated body to the actual production source."""
    text = path.read_text(); token = 'static int '+name+'('
    need(text.count(token) == 1, 'one actual production function '+name)
    start = text.index(token); end = text.index('{', start)+1; depth = 1
    while depth:
        need(end < len(text), 'complete production function '+name)
        depth += (text[end] == '{')-(text[end] == '}'); end += 1
    return text[start:end]+'\n'


def result(raw, mode, case):
    value = json.loads(raw)
    need(type(value) is dict and type(value.get('io')) is list and len(value['io']) == 3
         and all(type(n) is int and 0 < n < 1 << 64 for n in value['io'])
         and value['io'][0] == value['io'][1] == value['io'][2],
         'actual maps opens/closes/EOFs are complete and conserved')
    expected = dict(version=1, mode=case, differential=int(mode == 'verified'), component_only=1,
        compared=(3, 2, 1, 0, 0)[case], identity_refusals=9 if case == 0 else 0,
        argument_refusals=2 if case == 0 else 0, mapping_refusals=int(case == 1),
        generation_changes=int(case == 1), physical_fallbacks=int(case == 2),
        no_io_refusals=int(case >= 3), maps_unchanged_data=1, cleanup=[2, 2, 1], io=value['io'])
    need(raw == (json.dumps(expected, separators=(',', ':'))+'\n').encode(),
         'whole canonical fixed component row, including exact typed counters and cleanup')
    return value


def build(builder, archive, directory, mode, pin, binary, aliases, run, state):
    script = pin(FIXTURE/'build.sh'); generator = pin(FIXTURE/'prepare.py')
    need(fact(script)['sha256'] == SCRIPT_SHA,
         'exact source-owned projected/verified shell grammar and compiler expansion')
    output = directory/('rseq-pair-'+mode)
    sources = {name: pin(SELECTED/name) for name in (
        'rseq_native_pair.inc', 'rseq_guard.c', 'lifecycle_loader.c',
        'rseq_current_data.inc', 'maps_current_ticket.inc',
        'tests/maps_current_custody/oracle.c', 'tests/rseq_pair_current/oracle.c')}
    state.update(status='failed', recipe=fact(script), generator=fact(generator),
        extracted_sources={name: fact(path) for name, path in sources.items()}, archive=fact(archive))
    env = dict(builder.environment, LI2_CC=str(builder.tools['cc']), LI2_PYTHON=str(builder.tools['python']))
    _, out, err = run(mode+'-build', [builder.tools['sh'], script, SELECTED, archive, output, mode],
                      profile='release_build', env=env)
    need(out == err == b'', 'actual component shell build without diagnostics')
    unit = binary(str(output)+'.c')
    expected = ('#define main original_current_custody_main\n'
        '#include "tests/maps_current_custody/oracle.c"\n#undef main\n'
        '#include "rseq_current_data.h"\n'+
        extracted(sources['rseq_native_pair.inc'], 'np_rseq_data')+
        extracted(sources['rseq_guard.c'], 'same_data')+
        '#include "tests/rseq_pair_current/oracle.c"\n').encode()
    need(unit.read_bytes() == expected, 'whole generated TU with actual adapter and unchanged identity predicate')
    lines = recipe(script, '"$cc_bin"'); need(len(lines) == 1, 'one actual compiler command')
    argv = expand(lines[0], {'$cc_bin': builder.tools['cc'], '$selected': SELECTED,
        '$output': output, '$archive': archive}, ['-DLI2_MAPS_DIFFERENTIAL=1'] if mode == 'verified' else [])
    state.update(argv=argv, generated=fact(unit))
    need(argv[-2:] == ['-o', str(output)] and argv.count('-DLI2_MAPS_DIFFERENTIAL=1') == int(mode == 'verified'),
         'literal mode-specific compiler argv')
    headers(mode+'-headers', argv, [str(unit)], archive, builder, pin, aliases, run, state)
    need({str(unit), *(str(p) for name, p in sources.items() if name not in
         ('rseq_native_pair.inc', 'rseq_guard.c'))} <= set(state['headers']),
         'actual conditional lifecycle/current-data/oracle include closure')
    executable = binary(output); data, head, segments = elf(executable)
    need(head[1] in (2, 3) and executable.stat().st_mode & 0o111
         and any(p[0] == 1 and p[1] == 5 and p[3] <= head[4] < p[3]+p[6] for p in segments)
         and all(not (p[1]&1 and p[1]&2) for p in segments if p[0] in (1, 0x6474e551)),
         'actual executable ELF entry and no writable executable load/stack')
    loader = pin(interpreter(executable))
    need(pin(namespace.parse(data)['interpreter']) == loader, 'exact ELF interpreter alias')
    objects, description = namespace.plan(executable, [Path('/usr/lib64')], bytes.fromhex(H(data)),
                                          bytes.fromhex(fact(loader)['sha256']))
    expected_libraries = {loader: set()}
    for obj in objects:
        path = pin(obj['path']); need(fact(path)['sha256'] == H(obj['bytes']), 'whole actual runtime library')
        expected_libraries.setdefault(path, set()).update(obj['names'])
    _, out, err = run(mode+'-libraries', [loader, '--list', executable], profile='inspect', env=PROGRAM_ENV)
    need(not err, 'actual component loader listing stderr')
    resolved_libraries(out, expected_libraries, loader, pin)
    state.update(status='compiled_component', executable=dict(path=str(executable), **fact(executable)),
        runtime_inputs=dict(interpreter=fact(loader), dependencies=[dict(names=o['names'], **fact(o['path'])) for o in objects]),
        namespace_plan=description)
    return executable


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--expect-revision', required=True)
    ap.add_argument('--native-receipt', type=Path, required=True)
    ap.add_argument('--native-receipt-sha256', required=True)
    ap.add_argument('--output', type=Path, required=True)
    a = ap.parse_args(); affinity = os.sched_getaffinity(0)
    need(sys.version_info[:2] == (3, 12) and not sys.flags.optimize and len(affinity) == 1
         and re.fullmatch('[0-9a-f]{40}', a.expect_revision)
         and re.fullmatch('[0-9a-f]{64}', a.native_receipt_sha256),
         'Python3.12/assertions, reserved singleton and exact identities')
    cpu = next(iter(affinity)); private = a.output.absolute()
    need(cpu == 148 and private.parent == ROOT/'target/evaluation/inprocess' and not private.exists(),
         'historical setup CPU148 and fresh direct-child output')
    private.mkdir(); pins, artifacts, aliases = {}, {}, {}
    r = dict(schema=1, profile='native-pair-current-rseq-component-v1', status='failed',
        revision=a.expect_revision, cpu=cpu, hardware=hardware(cpu), source=None,
        argv=[sys.executable, '-B', *sys.argv], bounds=dict(BOUNDS), commands=[], builds={},
        presence={}, namespace_aliases={}, error=None, final_errors=[], source_unchanged=False,
        inputs_unchanged=False, cleanup_complete=False, application_executed=False,
        rseq_registration_executed=False, native_pair_owner_credit=False,
        qualification_credit=False, performance_credit=False,
        original_custody14_suite='unchanged_separate_requirement_not_run_here',
        cases=[dict(label=mode+'-case-'+str(case), mode=mode, case=case,
                    status='unexecuted', launched=False) for mode in MODES for case in range(5)])

    def pin(path):
        lexical = Path(os.path.abspath(path)); p = lexical.resolve(strict=True); value = fact(p)
        need(str(p) not in pins or pins[str(p)] == value, 'stable whole input')
        need(str(lexical) not in aliases or aliases[str(lexical)] == str(p), 'stable input alias')
        pins[str(p)] = value; aliases[str(lexical)] = str(p); return p

    def binary(path):
        p = pin(path); value = dict(fact(p), mode=p.stat().st_mode & 0o777)
        need(str(p) not in artifacts or artifacts[str(p)] == value, 'stable artifact bytes/mode')
        artifacts[str(p)] = value; return p

    def closure():
        need(source() == r['source'] and os.sched_getaffinity(0) == {cpu}, 'same clean source and reserved CPU')
        need(all(fact(p) == v for p, v in pins.items()), 'whole input closure')
        need(all(dict(fact(p), mode=Path(p).stat().st_mode & 0o777) == v for p, v in artifacts.items()), 'whole artifact closure')
        need(all(str(Path(p).resolve(strict=True)) == v for p, v in aliases.items()), 'input alias closure')
        need(all(os.path.lexists(p) == v for p, v in r['presence'].items()), 'loader configuration presence')
        need(all(Path(p).is_symlink() and os.readlink(p) == v for p, v in r['namespace_aliases'].items()), 'namespace alias closure')

    def complete(row):
        need(type(row['exit']) is int and row['exit'] == row['expected_exit']
             and row['timed_out'] is False and row['error'] is None and row['reaped'] is True
             and row['cleanup_errors'] == [] and type(row['descriptors']) is list
             and all(d.get('closed') is True for d in row['descriptors'])
             and row['bounds'] == BOUNDS[row['profile']] and row['capture_limit'] == 16 << 20,
             'exact bounded outcome and process/descriptor closure')

    def run(name, argv, profile='metadata', expected=0, env=None, record=False):
        closure()
        need(len(r['commands']) < len(SCHEDULE) and (name, profile) == SCHEDULE[len(r['commands'])]
             and expected == 0 and record is False, 'fixed17 schedule, expected zero exits and no observer FD')
        row = dict(name=name, argv=list(map(str, argv)), environment=dict(ENV if env is None else env),
            profile=profile, bounds=BOUNDS[profile], capture_limit=16 << 20, expected_exit=0)
        r['commands'].append(row)
        try:
            out, err = invoke(row, private, cpu)
            complete(row); return row, out, err
        finally:
            for value in row.get('captures', {}).values():
                try: need(fact(binary(private/value['file'])) == {k: value[k] for k in ('bytes', 'sha256')}, 'whole fresh capture')
                except BaseException as error: r['final_errors'].append(repr(error))
            p = private/(name+'.json')
            if p.exists():
                try: need(json.loads(binary(p).read_bytes()) == row, 'whole fresh command row')
                except BaseException as error: r['final_errors'].append(repr(error))
            save(private/'receipt.json', r)
            print(json.dumps(dict(command=name, exit=row.get('exit'), duration_ns=row.get('duration_ns'))), flush=True)

    try:
        r['source'] = source(); need(r['source']['revision'] == a.expect_revision, 'exact clean current source')
        pin(__file__); imported_sources(pin)
        builder, archive, _, _, _, _, _ = retained_support(a.native_receipt, a.native_receipt_sha256,
            r, pin, binary, aliases, complete, run)
        executables = {}
        for mode in MODES:
            state = r['builds'][mode] = {}
            executables[mode] = build(builder, archive, private, mode, pin, binary, aliases, run, state)
        imported_sources(pin)
        for case in r['cases']:
            case.update(status='failed')
            try:
                _, out, err = run(case['label'], [executables[case['mode']], case['case']],
                                  profile='finite', env=PROGRAM_ENV)
                need(not err, 'component stderr empty')
                case.update(status='observed_mapping_component', result=result(out, case['mode'], case['case']))
            except Exception as error:
                case['error'] = type(error).__name__+': '+str(error)
                last = r['commands'][-1]
                need(last['name'] == case['label'] and last.get('reaped') is True
                     and last.get('cleanup_errors') == [], 'failed component closed before next fixed case')
        need(len(r['commands']) == 17 and all(c['status'] == 'observed_mapping_component' for c in r['cases']),
             'both complete builds and all ten fixed component outcomes required')
        r['status'] = 'observed_mapping_components'
    except BaseException as error: r['error'] = type(error).__name__+': '+str(error)
    finally:
        for case in r['cases']:
            rows = [x for x in r['commands'] if x['name'] == case['label']]
            if rows:
                row = rows[0]; case.update(launched=type(row.get('pid')) is int,
                    exit=row.get('exit'), timed_out=row.get('timed_out'),
                    duration_ns_validation_only=row.get('duration_ns'),
                    captures={k: {j: v[j] for j in ('bytes', 'sha256')} for k, v in row.get('captures', {}).items()})
        try:
            for mode in MODES:
                for suffix in ('', '.c'):
                    path = private/('rseq-pair-'+mode+suffix)
                    if path.exists(): binary(path)
            imported_sources(pin); closure(); r['source_unchanged'] = r['inputs_unchanged'] = True
            for row in r['commands']:
                need(json.loads(binary(private/(row['name']+'.json')).read_bytes()) == row, 'final whole command row')
                for value in row.get('captures', {}).values():
                    need(fact(binary(private/value['file'])) == {k: value[k] for k in ('bytes', 'sha256')}, 'final whole capture')
        except BaseException as error: r['final_errors'].append(type(error).__name__+': '+str(error))
        r['cleanup_complete'] = bool(r['commands']) and all(x.get('reaped') is True and x.get('cleanup_errors') == []
            and type(x.get('descriptors')) is list and all(d.get('closed') is True for d in x['descriptors']) for x in r['commands'])
        if r['error'] or r['final_errors'] or not r['cleanup_complete']: r['status'] = 'failed'
        r.update(inputs=pins, artifacts=artifacts, aliases=aliases); save(private/'receipt.json', r)
    print(json.dumps(dict(status=r['status'], receipt=str((private/'receipt.json').relative_to(ROOT)))), flush=True)
    return int(r['status'] != 'observed_mapping_components')


if __name__ == '__main__': raise SystemExit(main())
