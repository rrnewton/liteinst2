#!/usr/bin/env python3
"""Within-process first-publication and steady-hit source-clock experiment."""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import platform
import re
import shutil
import sys

sys.dont_write_bytecode = True
import page_selected_generic as base
from page_selected_generic_build import Build
from page_selected_process import invoke
import page_selected_register_connected_build as link
import page_selected_register_perf_compare as compare
from page_selected_register_perf_images import NAMES

ROOT, HERE, ENV, PROFILES = base.ROOT, base.HERE, base.ENV, dict(base.PROFILES)
need, fact, save, digest = base.need, base.fact, base.save, base.digest


def publish(path, receipt, private):
    """Publish checked numbers and hashes; keep ordered commands/raw owners private."""
    build = receipt.get('build', {})
    register = receipt.get('register_build', {})
    commands = receipt['commands']
    fields = ('status', 'failure_code', 'nx_faults', 'main_faults', 'interpreter_faults',
              'selected_steps', 'generic_tf_attempts', 'generic_tf_steps', 'cpuid', 'rdtscp',
              'source_syscalls', 'syscalls', 'forwarded', 'admissions', 'sync_core')
    qualified = receipt['status'] == 'passed_finite_cohort' and receipt['source_unchanged'] is True
    def outcome(case):
        value = case.get('outcome')
        if value is None:
            return None
        result = {k: value[k] for k in ('mode', 'samples', 'steady_iterations', 'expected_values',
            'publications', 'hits', 'completed_runs', 'copied_instructions', 'loop_publications', 'tail_publications')}
        result['timing_qualified'] = qualified
        result['timing'] = ({lane: value[lane] for lane in ('native', 'gated')} if qualified else None)
        result['raw_samples_sha256'] = digest({lane: value[lane+'_samples'] for lane in ('native', 'gated')})
        return result
    cases = [dict(name=c['name'], accepted=c['accepted'],
        classification='completed' if c['accepted'] else 'incomplete',
        native_exit=c.get('native_exit'), gated_exit=c.get('gated_exit'),
        counters={k: c.get('loader', {})[k] for k in fields if k in c.get('loader', {})},
        outcome=outcome(c), loader_sha256=digest(c.get('loader')),
        register_report_sha256=digest(c.get('register')), namespace=c.get('namespace')) for c in receipt['cases']]
    public = {k: receipt.get(k) for k in ('schema', 'profile', 'status', 'scope', 'expected_revision',
        'started_utc', 'cpu', 'hardware', 'source', 'source_unchanged', 'environment', 'bounds',
        'reproduce', 'cohort_command_count', 'hardware_observer')}
    public.update(required_cases=6, required_cohort_commands=38, timing_qualified=qualified, timing_unit='TSC ticks',
        timing_scope='Same-process serialized source intervals; clock/CPUID/gating overhead included. Bracket-only controls are separate; no subtraction, ns conversion or speed threshold.', cases=cases,
        accepted_cases=sum(c['accepted'] is True for c in cases),
        commands=dict(attempted=len(commands), reaped=sum(c.get('reaped') is True for c in commands),
            timeouts=sum(c.get('timed_out') is True for c in commands),
            errors=sum(bool(c.get('error')) for c in commands),
            cleanup_errors=sum(len(c.get('cleanup_errors', [])) for c in commands),
            nonzero_exits=sum(type(c.get('exit')) is int and c['exit'] != 0 for c in commands),
            observed_duration_ns=sum(c['duration_ns'] for c in commands if type(c.get('duration_ns')) is int)),
        private_receipt=fact(private/'receipt.json'), command_rows_sha256=digest(commands),
        case_rows_sha256=digest(receipt['cases']), input_manifest_sha256=digest(receipt['inputs_before']),
        artifact_manifest_sha256=digest(receipt['artifacts_before']),
        build_status=build.get('status'), register_build_status=register.get('status'),
        configuration_unchanged=build.get('configuration_unchanged'),
        tool_versions=build.get('numeric_versions'), tool_bindings_sha256=digest(build.get('tools', {})),
        build_evidence_sha256=digest(build), register_build_sha256=digest(register),
        reference_artifacts={n: {k: v[k] for k in ('bytes', 'sha256', 'mode')}
                             for n, v in build.get('artifacts', {}).items()},
        opt_in_bridge=register.get('artifact'), opt_in_bridge_elf=register.get('elf'),
        failure_type=receipt['error'].split(':', 1)[0] if receipt['error'] else None,
        final_error_count=len(receipt['final_errors']),
        command_recipe=dict(reference_build=['sh', 'tools/page-entry/selected/build.sh'],
            opt_in_link='Exact C link command from tools/page-entry/selected/build-register-run.sh, using the freshly retained archive; no second Cargo build.',
            images=['python3', 'evaluation/inprocess/page_selected_register_perf_images.py', '${RUN}/images'],
            observer=['generic-observe'],
            each_case=['make-carrier', 'before-clock', 'native-original', 'gated-carrier', 'after-clock', 'decode-last-generic'],
            gated=['python3', 'tools/page-entry/carrier.py', 'exec-loader', '--library-root', '${CASE}',
                '--namespace', '${RUN}/namespace-${CASE_NAME}', '${CASE}/carrier', '${CASE}/original', '--', '${CASE}/original'],
            evidence='Private ordered rows retain exact argv, environments, bounds, cleanup, captures, namespace and owner reports.'))
    text = json.dumps(public, sort_keys=True, indent=2, allow_nan=False)+'\n'
    need(not any(x and len(x) > 1 and x in text for x in
                 (str(ROOT), str(Path.home()), platform.node(), '/home/')), 'private publication data')
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('x') as output:
        output.write(text)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--expect-revision', required=True)
    args = ap.parse_args()
    need(not sys.flags.optimize and len(os.sched_getaffinity(0)) == 1, 'assertions and one reserved CPU')
    need(re.fullmatch('[0-9a-f]{40}', args.expect_revision), 'exact revision')
    cpu = next(iter(os.sched_getaffinity(0)))
    os.chdir(ROOT)
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    name = stamp+'-page-selected-register-perf-'+args.expect_revision[:12]
    private = ROOT/'target/evaluation/inprocess'/name
    private.mkdir(parents=True, exist_ok=False)
    public = HERE/'results'/(name+'.json')
    need(not public.exists(), 'unique public receipt')
    pins, binaries = {}, {}
    receipt = dict(schema=1, profile='page-selected-register-perf-v1', status='failed',
        scope='Within-process first-publication and steady-hit timing of one finite two-MOV/CPUID-guard source run, plus bracket-only controls. Raw TSC intervals include clock/guard/source-gate costs. No isolated-cache, general application or full B2/B3 claim; existing full-state/negative suites remain separate requirements.',
        started_utc=stamp, expected_revision=args.expect_revision, source=None, source_unchanged=False,
        cpu=cpu, environment=ENV, bounds=PROFILES, commands=[], cases=[], error=None, final_errors=[],
        cohort_command_count=0, reproduce=['python3', 'evaluation/inprocess/page_selected_register_perf.py',
                                         '--expect-revision', args.expect_revision])

    def pin(path):
        path = Path(path).resolve(strict=True)
        value = fact(path)
        need(str(path) not in pins or pins[str(path)] == value, 'input changed')
        pins[str(path)] = value
        return path

    def artifact(path):
        path = Path(path)
        return dict(fact(path), mode=path.stat().st_mode & 0o777)

    def binary(path):
        path = Path(path).resolve(strict=True)
        value = artifact(path)
        need(str(path) not in binaries or binaries[str(path)] == value, 'artifact changed')
        binaries[str(path)] = value
        return path

    stage = 'build'

    def run(label, argv, expected=0, profile='native', env=None):
        need(all(fact(p) == v for p, v in pins.items()) and
             all(artifact(p) == v for p, v in binaries.items()), 'input/artifact changed before command')
        row = dict(name=label, stage=stage, profile=profile, argv=list(map(str, argv)), bounds=PROFILES[profile],
            capture_limit=65536 if profile == 'native' else 4 << 20,
            expected_exit=expected, environment=dict(ENV if env is None else env))
        receipt['commands'].append(row)
        out, err = invoke(row, private, cpu)
        need(row['exit'] == expected, 'exact process outcome: '+label)
        return row, out, err

    builder = Build(receipt, private, pin, binary, run)
    cohort_start = None
    bridge_path = private/'bridge-register-run.so'
    try:
        receipt['source'] = base.source()
        need(receipt['source']['revision'] == args.expect_revision, 'revision differs')
        receipt['hardware'] = base.hardware(cpu)
        git = pin(shutil.which('git', path=ENV['PATH']))
        _, paths, err = run('source-paths', [git, '-C', ROOT, 'ls-files', '-z', 'tools/page-entry', 'evaluation/inprocess'],
                            profile='metadata')
        need(not err, 'source path enumeration stderr')
        for value in paths.split(b'\0'):
            if value and not os.fsdecode(value).startswith('evaluation/inprocess/results/'):
                pin(ROOT/os.fsdecode(value))
        for module in tuple(sys.modules.values()):
            path = getattr(module, '__file__', None)
            if path and Path(path).resolve().is_relative_to(ROOT):
                pin(path)
        built = builder.prepare()
        bridge = link.build(builder, built, ROOT, private, pin, binary, run, receipt)
        python, observe = builder.tools['python'], built['observe']
        stage = 'cohort'
        cohort_start = len(receipt['commands'])
        _, out, err = run('hardware', [observe])
        need(not err, 'native hardware observer stderr')
        hw = json.loads(out)
        need(hw['cpu'] == cpu, 'actual CPU')
        receipt['hardware_observer'] = hw
        images = private/'images'
        _, out, err = run('images', [python, HERE/'page_selected_register_perf_images.py', images])
        need(out == err == b'', 'literal generator output')
        specs = json.loads(binary(images/'images.json').read_bytes())
        need(len(specs) == 6 and [s['name'] for s in specs] == NAMES, 'exact six cache/bracket programs')
        for spec in specs:
            name = spec['name']
            case = dict(name=name, accepted=False)
            receipt['cases'].append(case)
            original, interp = binary(spec['original']), binary(spec['interpreter'])
            need(fact(original)['sha256'] == spec['original_sha256'] and
                 fact(interp)['sha256'] == spec['interpreter_sha256'] and base.interpreter(original) == interp,
                 'actual source/interpreter binding')
            code, head, ph = base.elf(interp)
            stream = bytes.fromhex(spec['exact_stream_hex'])
            need(head[1] == 3 and head[4] == spec['entry_vaddr'] and not any(p[0] == 3 for p in ph) and
                 code[spec['entry_file_offset']:spec['entry_file_offset']+len(stream)] == stream,
                 'actual first interpreter bytes')
            soname = binary(Path(spec['library_root'])/'li2-stream.so')
            need(fact(soname)['sha256'] == spec['soname_sha256'] == fact(interp)['sha256'], 'exact dependency copy')
            carrier = original.parent/'carrier'
            run('make-'+name, [python, ROOT/'tools/page-entry/carrier.py', 'make', original, bridge, carrier])
            binary(carrier)
            need(base.interpreter(carrier) == bridge, 'actual opt-in PT_INTERP binding')
            _, out, err = run('before-'+name, [observe, 'clock'])
            need(not err, 'clock observer stderr')
            before = compare.generic.clock(out, cpu)
            command, out, err = run('native-'+name, [original])
            case['native_exit'] = command['exit']
            need(not err, 'native original stderr')
            native = dict(exit=command['exit'], stdout=out)
            namespace = private/('namespace-'+name)
            command, out, err = run('gated-'+name, [python, ROOT/'tools/page-entry/carrier.py', 'exec-loader',
                '--library-root', spec['library_root'], '--namespace', namespace, carrier, original, '--', original])
            case['gated_exit'] = command['exit']
            loader, register = compare.parse(err)
            case.update(loader=loader, register=register)
            _, after_out, after_err = run('after-'+name, [observe, 'clock'])
            need(not after_err, 'clock observer stderr')
            after = compare.generic.clock(after_out, cpu)
            last = {r['name']: r for r in spec['rows']}['store_r12']
            _, decoded_out, decoded_err = run('decode-last-'+name, [observe, 'decode', str(last['pc']), last['bytes']])
            need(not decoded_err, 'actual decoder observer stderr')
            decoded = json.loads(decoded_out)
            case['outcome'] = compare.check(spec, loader, register, command, out, native, before, after, decoded,
                                            original.read_bytes())
            ns = json.loads(binary(namespace/'namespace.json').read_bytes())
            binary(namespace/'launch.json')
            need(len(ns['objects']) == 1 and ns['objects'][0]['sha256'] == spec['interpreter_sha256'] and
                 ns['objects'][0]['seals'] == 15 and
                 fact(pin(ns['objects'][0]['source']))['sha256'] == spec['interpreter_sha256'],
                 'actual immutable interpreter dependency')
            case.update(accepted=True, namespace={n: fact(namespace/n) for n in ('namespace.json', 'launch.json')})
        need(len(receipt['cases']) == 6 and all(c['accepted'] for c in receipt['cases']) and
             len(receipt['commands'])-cohort_start == 38, 'complete exact six-case command cohort')
        receipt['status'] = 'passed_finite_cohort'
    except BaseException as exc:
        receipt['error'] = type(exc).__name__+': '+str(exc)
    finally:
        if cohort_start is not None:
            receipt['cohort_command_count'] = len(receipt['commands'])-cohort_start
        try:
            receipt['final_errors'] += builder.finish()
        except BaseException as exc:
            receipt['final_errors'].append('build finalization: '+repr(exc))
        try:
            if bridge_path.is_file():
                binary(bridge_path)
        except BaseException as exc:
            receipt['final_errors'].append('opt-in bridge retention: '+repr(exc))
        receipt['inputs_before'], receipt['artifacts_before'] = pins, binaries
        for name, before, observe in (('inputs_after', pins, fact), ('artifacts_after', binaries, artifact)):
            after = receipt[name] = {}
            for path, value in before.items():
                try:
                    after[path] = observe(path)
                    need(after[path] == value, 'final byte/mode identity')
                except BaseException as exc:
                    receipt['final_errors'].append(path+': '+repr(exc))
        try:
            receipt['source_unchanged'] = base.source() == receipt['source']
            need(receipt['source_unchanged'], 'committed source changed')
        except BaseException as exc:
            receipt['final_errors'].append('source closure: '+repr(exc))
        if (receipt['error'] or receipt['final_errors'] or receipt['build']['status'] != 'passed' or
                receipt.get('register_build', {}).get('status') != 'passed'):
            receipt['status'] = 'failed'
        save(private/'receipt.json', receipt)
        publish(public, receipt, private)
    print(json.dumps(dict(status=receipt['status'], cases=len(receipt['cases']),
        commands=len(receipt['commands']), receipt=str(public.relative_to(ROOT)))))
    return 0 if receipt['status'] == 'passed_finite_cohort' else 1


if __name__ == '__main__':
    raise SystemExit(main())
