#!/usr/bin/env python3
"""Qualify the clock observer, then measure one completed real program's frozen site."""
import argparse
from datetime import datetime, timezone
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import shutil
import sys

sys.dont_write_bytecode = True
from checks import source
from run import hardware
from page_selected import ENV as BASE_ENV, fact, interpreter, need, save
from page_selected_generic import digest
from page_selected_generic_build import Build, PROFILES as BUILD_PROFILES
from page_selected_process import invoke
from page_selected_register_time_compare import configuration, decode
from page_selected_register_time_record import check
import page_selected_register_time_build as link
from page_selected_register_time_program import execute

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
ENV = dict(BASE_ENV, LD_BIND_NOW='1')
PROFILES = dict(BUILD_PROFILES, native=[3, 512 << 20, 16 << 20, 15],
                finite=[5, 512 << 20, 16 << 20, 15], program=[30, 512 << 20, 16 << 20, 60])


def publish(path, r, private):
    build = r.get('build', {})
    result = {k: r.get(k) for k in ('schema', 'profile', 'status', 'scope', 'expected_revision',
        'started_utc', 'cpu', 'hardware', 'source', 'source_unchanged', 'bounds', 'reproduce', 'workload')}
    result.update(timing=r.get('timing') if r['status'] == 'passed' else None,
        selection=r.get('selection'), selected_configuration=r.get('selected_configuration'),
        qualification=[dict(name=x['name'], exit=x.get('exit'), status=x['status'],
            outcome=x.get('outcome'), record=x.get('record')) for x in r['qualification']],
        programs=[dict(name=x['name'], status=x['status'], native_exit=x.get('native_exit'),
            gated_exit=x.get('gated_exit'), whole_process_ns=(x.get('whole_process_ns')
                if r['status'] == 'passed' and x['status'] == 'completed' else None),
            original=x['original'], interpreter=x['interpreter'], bridge=x['bridge'],
            report_sha256=digest(x.get('report')), namespace=x.get('namespace'),
            actual_environment_sha256=x.get('launch_environment_sha256'),
            counters={k: x.get('report', {}).get('loader', {}).get(k) for k in
                ('status', 'failure_code', 'nx_faults', 'source_syscalls', 'forwarded')}) for x in r['programs']],
        command_count=len(r['commands']), command_rows_sha256=digest(r['commands']),
        private_receipt=fact(private/'receipt.json'), inputs_sha256=digest(r['inputs_before']),
        artifacts_sha256=digest(r['artifacts_before']), header_aliases_sha256=digest(r['header_aliases']),
        tool_versions=build.get('numeric_versions'),
        tool_hashes={k: {a: v[a] for a in ('bytes', 'sha256')} for k,v in build.get('tools', {}).items()},
        build_status=build.get('status'), build_evidence_sha256=digest(build),
        finite_build_sha256=digest(r.get('finite_build')), timing_builds_sha256=digest(r.get('timing_builds')),
        configuration_sha256=digest(r.get('configuration')), cleanup_complete=r.get('cleanup_complete', False),
        failure_type=r['error'].split(':', 1)[0] if r['error'] else None, final_error_count=len(r['final_errors']),
        whole_process_scope='Separate original native baseline and instrumented fresh exec for each phase. Gated duration includes namespace preparation; neither is a same-site steady interval.',
        interval_scope='All 22 CLOCK_MONOTONIC_RAW interval values from one frozen interpreter site. Service begins after source fetch/plan and ends after genuine generated NX exit/reset, before guard dispatch. API interval ends before arm. No per-site native baseline or frequency conversion.')
    text = json.dumps(result, sort_keys=True, indent=2, allow_nan=False)+'\n'
    need(not any(x and len(x) > 1 and x in text for x in
         (str(ROOT), str(Path.home()), platform.node(), '/home/')), 'public private-location guard')
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('x') as f:f.write(text)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--expect-revision', required=True)
    ap.add_argument('--program', choices=('true', 'ls'), default='ls')
    ap.add_argument('--disable-rseq', action='store_true')
    args = ap.parse_args()
    need(not sys.flags.optimize and len(os.sched_getaffinity(0)) == 1 and
         re.fullmatch('[0-9a-f]{40}', args.expect_revision), 'exact source, assertions and one reserved CPU')
    cpu = next(iter(os.sched_getaffinity(0)));os.chdir(ROOT)
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    stem = stamp+'-page-selected-register-time-'+args.expect_revision[:12]
    private = ROOT/'target/evaluation/inprocess'/stem;private.mkdir(parents=True, exist_ok=False)
    public = HERE/'results'/(stem+'.json');need(not public.exists(), 'unique public receipt')
    reproduce = ['python3', 'evaluation/inprocess/page_selected_register_time.py',
                 '--expect-revision', args.expect_revision, '--program', args.program]
    if args.disable_rseq:reproduce.append('--disable-rseq')
    r = dict(schema=1, profile='page-selected-register-time-v1', status='failed',
        scope='Finite observer qualification followed by completed discovery and one completed real-program timed run; lowest eligible interpreter offset fixed before measurement. No full B2/B3 or transparent-namespace claim.',
        expected_revision=args.expect_revision, started_utc=stamp, cpu=cpu, source=None, source_unchanged=False,
        bounds=PROFILES, reproduce=reproduce, workload=dict(program=args.program, rseq_disabled=args.disable_rseq),
        commands=[], qualification=[], programs=[], timing=None, error=None, final_errors=[])
    pins, binaries, aliases, optional = {}, {}, {}, {}
    def pin(path):
        lexical = str(Path(path).absolute());p = Path(path).resolve(strict=True);value = fact(p)
        need(lexical not in aliases or aliases[lexical] == str(p), 'input resolution changed')
        aliases[lexical] = str(p)
        need(str(p) not in pins or pins[str(p)] == value, 'input changed')
        pins[str(p)] = value;return p
    def artifact(path):
        p = Path(path);return dict(fact(p), mode=p.stat().st_mode & 0o777)
    def binary(path):
        p = Path(path).resolve(strict=True);value = artifact(p)
        need(str(p) not in binaries or binaries[str(p)] == value, 'artifact changed')
        binaries[str(p)] = value;return p
    def closure():
        need(all(fact(p) == v for p,v in pins.items()) and all(artifact(p) == v for p,v in binaries.items()),
             'input/artifact changed before command')
        need(all(str(Path(p).resolve(strict=True)) == v for p,v in aliases.items()), 'input alias changed')
        need(all(Path(p).exists() == v for p,v in optional.items()), 'native loader configuration presence changed')
    stage = 'build'
    def run(label, argv, expected=0, profile='native', env=None, record=False, step=False):
        closure()
        row = dict(name=label, stage=stage, profile=profile, argv=list(map(str, argv)), bounds=PROFILES[profile],
            capture_limit=65536 if profile in ('native','finite','program') else 4 << 20,
            expected_exit=expected, environment=dict(ENV if env is None else env), record_requested=record,
            standalone_signal_preparation=step)
        r['commands'].append(row)
        out, err = invoke(row, private, cpu, record=record, step=step)
        need(type(row['exit']) is int and (expected is None or row['exit'] == expected), 'actual process outcome')
        return row, out, err
    builder = Build(r, private, pin, binary, run)
    try:
        r['source'] = source();need(r['source']['revision'] == args.expect_revision, 'exact committed source')
        r['hardware'] = hardware(cpu)
        inputs_path = pin(HERE/'page_selected_register_time_inputs.json')
        inputs = decode(inputs_path.read_bytes());r['configuration'] = inputs
        need(inputs['schema'] == 1 and inputs['mechanism_manifest_sha256'] ==
             '3842a4be98e666ffdca9053d77aa9d875092111083b86d3b5ddc03a1ebf819ae', 'reviewed observer V2')
        for row in inputs['sources']:
            path = pin(ROOT/row['path']);need(fact(path) == {k: row[k] for k in ('bytes','sha256')}, 'exact timing recipe/context input')
        git = pin(shutil.which('git', path=ENV['PATH']))
        _, out, err = run('source-paths', [git, '-C', ROOT, 'ls-files', '-z', 'tools/page-entry', 'evaluation/inprocess'], profile='metadata')
        need(not err, 'source enumeration stderr')
        for value in out.split(b'\0'):
            if value and not os.fsdecode(value).startswith('evaluation/inprocess/results/'):pin(ROOT/os.fsdecode(value))
        for p in ('/etc/ld.so.cache', '/etc/ld.so.preload'):
            optional[p] = Path(p).exists()
            if optional[p]:pin(p)
        spec = importlib.util.spec_from_file_location('li2_timing_namespace', pin(ROOT/'tools/page-entry/namespace.py'))
        namespace_api = importlib.util.module_from_spec(spec);spec.loader.exec_module(namespace_api)
        for module in tuple(sys.modules.values()):
            p = getattr(module, '__file__', None)
            if p and Path(p).resolve().is_relative_to(ROOT):pin(p)
        products = builder.prepare()
        builder.tools['gdb'] = pin(shutil.which('gdb', path=ENV['PATH']))
        _, out, err = run('version-gdb', [builder.tools['gdb'], '--version'], profile='metadata', env=builder.environment)
        need(not err and out, 'actual file-only GDB identity')
        r['build']['versions']['gdb'] = out.decode().strip()
        r['build']['tools']['gdb'] = dict(path=str(builder.tools['gdb']), **fact(builder.tools['gdb']))
        fixtures = link.fixtures(builder, products, ROOT, private, pin, binary, aliases, run, r, inputs)
        outcomes = decode(pin(ROOT/'tools/page-entry/selected/tests/register_timing/OUTCOMES.json').read_bytes())
        need(len(outcomes['commands']) == len(fixtures) == 3 and outcomes['bounds'] ==
             dict(external_cpus=1, cpu_seconds=5, address_space_bytes=512 << 20, file_bytes=16 << 20, wall_seconds=15),
             'three unchanged finite commands and exact bounds')
        stage = 'qualification'
        for mode, ((path, layout), expected) in enumerate(zip(fixtures, outcomes['commands'])):
            item = dict(name=expected['name'], status='failed');r['qualification'].append(item)
            command, out, err = run(expected['name']+'-native', [path], expected=expected['exit_code'],
                                    profile='finite', env=builder.environment, record=True, step=True)
            item['exit'] = command['exit']
            need(out == expected['stdout'].encode() and err == expected['stderr'].encode(), 'exact finite stdout/stderr')
            capture = command['captures']['record'];record_path = binary(private/capture['file'])
            need(fact(record_path) == {k: capture[k] for k in ('bytes','sha256')}, 'complete retained actual state record')
            item['record'] = fact(record_path);value = check(record_path.read_bytes(), layout, mode)
            for k in ('operation','completed','retained_full_records','native_references','clock_calls'):
                need(value[k] == expected[k], 'actual finite operation count '+k)
            item.update(status='accepted_observation', outcome=value)
        need(len(r['qualification']) == 3 and all(x['status'] == 'accepted_observation' for x in r['qualification']),
             'all observer qualifications precede real timing')
        original = pin('/bin/'+args.program);interp = pin(interpreter(original))
        extra, expected_stdout = (['-d', '.'], b'.\n') if args.program == 'ls' else ([], b'')
        env = dict(ENV, **({'GLIBC_TUNABLES':'glibc.pthread.rseq=0'} if args.disable_rseq else {}))
        stage = 'discovery'
        bridge = link.interpreter('discovery', configuration(fact(interp)['sha256']),
            builder, products, ROOT, private, pin, binary, aliases, run, r)
        selected = execute('discovery', 1, None, bridge, original, interp, extra, expected_stdout,
            args.disable_rseq, namespace_api, builder, ROOT, private, pin, binary, run, r, env, digest)
        selection = private/'selection.json'
        with selection.open('x') as f:json.dump(selected, f, sort_keys=True, indent=2, allow_nan=False);f.write('\n')
        binary(selection);r['selection'] = selected;r['selection_file'] = fact(selection)
        stage = 'measurement'
        need(decode(selection.read_bytes()) == selected, 'frozen discovery identity before timed link')
        config = configuration(fact(interp)['sha256'], selected)
        bridge = link.interpreter('measurement', config, builder, products, ROOT, private, pin, binary, aliases, run, r)
        r['selected_configuration'] = fact(private/'measurement/register_timing_config.h')
        r['timing'] = execute('measurement', 2, selected, bridge, original, interp, extra, expected_stdout,
            args.disable_rseq, namespace_api, builder, ROOT, private, pin, binary, run, r, env, digest)
        need(len(r['programs']) == 2 and all(x['status'] == 'completed' for x in r['programs']), 'both real programs completed')
        r['status'] = 'passed'
    except BaseException as exc:
        r['error'] = type(exc).__name__+': '+str(exc)
    finally:
        try:r['final_errors'] += builder.finish()
        except BaseException as exc:r['final_errors'].append('build finalization: '+repr(exc))
        for command in r['commands']:
            for capture in command.get('captures', {}).values():
                try:
                    path = private/capture['file']
                    need(path.parent == private and fact(path) == {k: capture[k] for k in ('bytes','sha256')},
                         'actual retained capture closure')
                    binary(path)
                except BaseException as exc:r['final_errors'].append('capture closure: '+repr(exc))
        r['inputs_before'], r['artifacts_before'], r['header_aliases'] = pins, binaries, aliases
        r['optional_loader_configuration'] = optional
        for name, before, observe in (('inputs_after', pins, fact), ('artifacts_after', binaries, artifact)):
            after = r[name] = {}
            for p, value in before.items():
                try:after[p] = observe(p);need(after[p] == value, 'final exact byte/mode identity')
                except BaseException as exc:r['final_errors'].append(p+': '+repr(exc))
        try:closure()
        except BaseException as exc:r['final_errors'].append('input/alias closure: '+repr(exc))
        try:r['source_unchanged'] = source() == r['source'];need(r['source_unchanged'], 'source closure')
        except BaseException as exc:r['final_errors'].append('source closure: '+repr(exc))
        r['cleanup_complete'] = all(x.get('reaped') and not x.get('timed_out') and not x.get('error') and
            not x.get('cleanup_errors') and all(d['closed'] for d in x.get('descriptors', [])) for x in r['commands'])
        if r['error'] or r['final_errors'] or not r['cleanup_complete'] or r['build']['status'] != 'passed':
            r['status'] = 'failed';r['timing'] = None
        save(private/'receipt.json', r);publish(public, r, private)
    print(json.dumps(dict(status=r['status'], receipt=str(public.relative_to(ROOT)))))
    return 0 if r['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
