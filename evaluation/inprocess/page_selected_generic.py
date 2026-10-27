#!/usr/bin/env python3
"""Build the committed generic controller; validate twenty finite streams and report real-ls progress separately."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import struct
import sys

sys.dont_write_bytecode = True
from checks import source
from page_selected import ENV, fact, need, save, interpreter, elf
from page_selected_process import invoke
from page_selected_generic_build import Build, PROFILES as BUILD_PROFILES
from run import hardware
import page_selected_generic_compare as compare

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
PROFILES = dict(BUILD_PROFILES, native=[3, 512 << 20, 16 << 20, 15])


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()


def publish(path, receipt, private, aliases):
    build = receipt.get('build', {})
    tools = build.get('tools', {})
    substitutions = [(str(private), '${RUN}'), (str(ROOT), '${REPO_ROOT}')]
    substitutions += [(v['path'], '${TOOL_'+k.upper()+'}') for k, v in tools.items()]
    substitutions += aliases
    substitutions.sort(key=lambda x: len(x[0]), reverse=True)

    def argv(values):
        result = []
        for value in values:
            for original, replacement in substitutions:
                value = value.replace(original, replacement)
            # Unanticipated external paths are authenticated privately, not
            # copied into publication. They cannot silently acquire a recipe.
            if value.startswith('/') or '/home/' in value:
                value = '${PRIVATE_ARGUMENT_SHA256:'+hashlib.sha256(value.encode()).hexdigest()+'}'
            result.append(value)
        return result

    def error_type(value):
        return value.split(':', 1)[0] if value else None

    def counts(row):
        keys = ('status failure_code detail_abs detail_negative dependency_objects first_target_is_interpreter_entry '
                'nx_faults main_faults interpreter_faults dependency_faults selected_selftests selected_steps '
                'generic_tf_attempts generic_tf_steps rdrand rdseed rdpid cpuid rdtsc rdtscp '
                'source_syscalls syscalls forwarded admissions sync_core generations retired live_pages '
                'step_route tf_phase tf_error tf_flow tf_family tf_code tf_length tf_release_complete').split()
        return {k: row[k] for k in keys if k in row}

    cases = []
    for case in receipt['cases']:
        row = case.get('result', {})
        item = dict(name=case['name'], accepted=case['accepted'], native_exit=case.get('native_exit'),
                    outcome_class=('expected_refusal' if row.get('status') == 125 else
                                   'completed' if case['accepted'] else 'incomplete'),
                    counters=counts(row), exact_report_sha256=digest(row))
        if case.get('outcome') is not None:
            item['outcome'] = case['outcome']
        if row.get('selected_last_kind'):
            item['selected_outcome'] = {k.removeprefix('selected_last_'): v for k, v in row.items()
                                        if k.startswith('selected_last_')}
        if row.get('builtin_kind'):
            item['builtin_outcome'] = {k.removeprefix('builtin_'): v for k, v in row.items() if k.startswith('builtin_')}
        if case.get('namespace'):
            item['namespace'] = case['namespace']
        cases.append(item)
    diagnostic = receipt.get('ls_diagnostic')
    if diagnostic is not None:
        diagnostic = {k: diagnostic[k] for k in ('status', 'original', 'interpreter', 'bytes') if k in diagnostic} | {
            'counters': counts(receipt['ls_diagnostic']['result']),
            'exact_report_sha256': digest(receipt['ls_diagnostic']['result']),
            'namespace': receipt['ls_diagnostic'].get('namespace')}
    commands = []
    for command in receipt['commands']:
        commands.append(dict(name=command['name'], stage=command['stage'], profile=command['profile'],
            argv=argv(command['argv']), actual_argv_sha256=digest(command['argv']),
            expected_exit=command['expected_exit'], exit=command.get('exit'),
            duration_ns=command.get('duration_ns'), timed_out=command.get('timed_out'), reaped=command.get('reaped'),
            error_type=error_type(command.get('error')), cleanup_error_count=len(command.get('cleanup_errors', [])),
            captures={k: {a: v[a] for a in ('bytes', 'sha256')} for k, v in command.get('captures', {}).items()}))
    public = {k: receipt.get(k) for k in ('schema', 'profile', 'status', 'scope', 'expected_revision',
        'started_utc', 'cpu', 'hardware', 'source', 'source_unchanged', 'environment', 'bounds', 'reproduce',
        'cohort_command_count', 'hardware_observer')}
    public.update(cases=cases, ls_diagnostic=diagnostic, commands=commands, command_count=len(commands),
        command_rows_sha256=digest(receipt['commands']), private_receipt=fact(private/'receipt.json'),
        input_manifest_sha256=digest(receipt['inputs_before']), artifact_manifest_sha256=digest(receipt['artifacts_before']),
        tools={k: {x: v[x] for x in ('bytes', 'sha256')} for k, v in tools.items()},
        tool_versions=build.get('numeric_versions'), configuration_unchanged=build.get('configuration_unchanged'),
        build_status=build.get('status'), build_command_completed=build.get('command_completed'),
        registry_sources=[{k: v for k, v in p.items() if k != 'root'} for p in build.get('registry_before', [])],
        archive_text_exports=build.get('archive_text_exports'), dep_info=build.get('dep_info'),
        bridge_elf=build.get('bridge_elf'),
        artifacts={n: {k: p[k] for k in ('bytes', 'sha256', 'mode')} for n, p in build.get('artifacts', {}).items()},
        failure_type=error_type(receipt.get('error')), final_error_count=len(receipt['final_errors']),
        command_recipe={'build': ['sh', 'tools/page-entry/selected/build.sh'],
            'observer': ['generic-observe', '<empty|clock|decode PC HEX>'],
            'images': ['python3', 'evaluation/inprocess/page_selected_generic_images.py', '${RUN}/images'],
            'native': ['${RUN}/images/<case>/original'],
            'gated': ['python3', 'tools/page-entry/carrier.py', 'exec-loader', '--library-root', '<sealed source root>',
                '--namespace', '${RUN}/namespace-<case>', '<carrier>', '<original>', '--', '<original>'],
            'ls_native': ['/bin/ls', '-d', '.'],
            'actual_commands': 'Normalized argv above; private ordered rows retain exact argv, environment and captured bytes.'})
    text = json.dumps(public, indent=2, sort_keys=True, allow_nan=False)+'\n'
    need(not any(x and len(x)>1 and x in text for x in (str(Path.home()), str(ROOT), platform.node(), '/home/')),
         'private location in public receipt')
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('x') as output:
        output.write(text)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--expect-revision', required=True)
    ap.add_argument('--library-root', action='append', type=Path)
    args = ap.parse_args()
    need(sys.flags.optimize == 0 and len(os.sched_getaffinity(0)) == 1, 'assertions and one reserved CPU')
    need(re.fullmatch('[0-9a-f]{40}', args.expect_revision), 'exact revision')
    cpu = next(iter(os.sched_getaffinity(0)))
    os.chdir(ROOT)
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    name = stamp+'-page-selected-generic-'+args.expect_revision[:12]
    output = ROOT/'target/evaluation/inprocess'/name
    output.mkdir(parents=True, exist_ok=False)
    public = HERE/'results'/(name+'.json')
    need(not public.exists(), 'unique public receipt')
    pins, binaries, aliases = {}, {}, []
    receipt = dict(schema=1, profile='page-selected-generic-v1', status='failed',
        scope='20 finite streams; separate real-ls diagnostic; no full ABI/B2/B3/performance claim',
        started_utc=stamp, expected_revision=args.expect_revision, source=None, source_unchanged=False,
        cpu=cpu, environment=ENV, commands=[], cases=[], error=None, final_errors=[], ls_diagnostic=None,
        bounds=PROFILES, cohort_command_count=0, reproduce=['python3', 'evaluation/inprocess/page_selected_generic.py',
                                                          '--expect-revision', args.expect_revision])
    for i, path in enumerate(args.library_root or [Path('/usr/lib64')]):
        aliases.append((str(path.resolve()), '${LIBRARY_ROOT_'+str(i)+'}'))
        if args.library_root:
            receipt['reproduce'] += ['--library-root', '${LIBRARY_ROOT_'+str(i)+'}']

    def pin(path):
        path = Path(path).resolve(strict=True)
        value = fact(path)
        need(str(path) not in pins or pins[str(path)] == value, 'input changed')
        pins[str(path)] = value
        return path

    def binary(path):
        path = Path(path).resolve(strict=True)
        value = fact(path)
        need(str(path) not in binaries or binaries[str(path)] == value, 'artifact changed')
        binaries[str(path)] = value
        return path

    stage = 'build'

    def run(label, argv, expected=0, profile='native', env=None):
        need(all(fact(p) == v for p, v in pins.items()) and all(fact(p) == v for p, v in binaries.items()),
             'source/artifact changed before command')
        row = dict(name=label, stage=stage, profile=profile, argv=list(map(str, argv)), bounds=PROFILES[profile],
            capture_limit=65536 if profile == 'native' else 4 << 20,
            expected_exit=expected, environment=dict(ENV if env is None else env))
        receipt['commands'].append(row)
        out, err = invoke(row, output, cpu)
        need(row['exit'] == expected if expected is not None else type(row['exit']) is int and 0 <= row['exit'] <= 255,
             'exact process outcome: '+label)
        return row, out, err

    builder = Build(receipt, output, pin, binary, run)
    cohort_start = None
    try:
        receipt['source'] = source()
        need(receipt['source']['revision'] == args.expect_revision, 'revision differs')
        receipt['hardware'] = hardware(cpu)
        git = pin(shutil.which('git', path=ENV['PATH']))
        _, paths, err = run('source-paths', [git, '-C', ROOT, 'ls-files', '-z', 'tools/page-entry', 'evaluation/inprocess'],
                            profile='metadata')
        need(not err, 'source path enumeration stderr')
        for value in paths.split(b'\0'):
            if value and not os.fsdecode(value).startswith('evaluation/inprocess/results/'):
                pin(ROOT/os.fsdecode(value))
        for module in tuple(sys.modules.values()):
            file = getattr(module, '__file__', None)
            if file and Path(file).resolve().is_relative_to(ROOT):
                pin(file)
        built = builder.prepare()
        bridge, observe = built['bridge'], built['observe']
        python = builder.tools['python']
        stage = 'cohort'
        cohort_start = len(receipt['commands'])
        _, out, err = run('hardware', [observe])
        need(not err, 'native hardware observer stderr')
        hw = json.loads(out)
        need(hw['cpu'] == cpu, 'actual CPU')
        receipt['hardware_observer'] = hw
        images = output/'images'
        run('images', [python, HERE/'page_selected_generic_images.py', images])
        specs = json.loads(binary(images/'images.json').read_bytes())
        need(len(specs) == 20 and [s['name'] for s in specs[:15]] ==
             ['rdrand16', 'rdrand32', 'rdrand64', 'rdseed16', 'rdseed32', 'rdseed64', 'rdpid64', 'mov_exit',
              'prefix_random', 'cross_mov', 'cross_selected', 'rsp_refusal', 'query_trap', 'query_trap_highbits', 'query_usr1'] and
             [s['name'] for s in specs[-5:]] ==
             ['branch_memory_stack', 'boundary_call_ret', 'cpuid0', 'rdtsc', 'rdtscp'], 'closed 15+5 cohort')
        for i, spec in enumerate(specs):
            name = spec['name']
            case = dict(name=name, accepted=False)
            receipt['cases'].append(case)
            original, interp = binary(spec['original']), binary(spec['interpreter'])
            need(fact(original)['sha256'] == spec['original_sha256'] and
                 fact(interp)['sha256'] == spec['interpreter_sha256'] and interpreter(original) == interp, 'actual ELF interpreter binding')
            code, head, ph = elf(interp)
            stream = bytes.fromhex(spec['exact_stream_hex'])
            need(head[1] == 3 and head[4] == spec['entry_vaddr'] and not any(p[0] == 3 for p in ph) and
                 code[spec['entry_file_offset']:spec['entry_file_offset']+len(stream)] == stream, 'actual first interpreter bytes')
            binary(Path(spec['library_root'])/'li2-stream.so')
            carrier = original.parent/'carrier'
            run('make-'+name, [python, ROOT/'tools/page-entry/carrier.py', 'make', original, bridge, carrier])
            binary(carrier)
            before = after = decoded = None
            if i >= 15:
                _, out, err = run('before-'+name, [observe, 'clock'])
                need(not err, 'clock observer stderr')
                before = compare.clock(out, cpu)
            native = None
            if name != 'rsp_refusal':
                command, out, err = run('native-'+name, [original], None)
                need(not err, 'native stderr')
                native = dict(exit=command['exit'], stdout=out)
            namespace = output/('namespace-'+name)
            command, out, err = run('gated-'+name, [python, ROOT/'tools/page-entry/carrier.py', 'exec-loader',
                '--library-root', spec['library_root'], '--namespace', namespace, carrier, original, '--', original], None)
            row = compare.parse(err)
            if i < 15:
                compare.check_legacy(spec, row, command, out, native, hw)
            else:
                _, clock_out, clock_err = run('after-'+name, [observe, 'clock'])
                need(not clock_err, 'clock observer stderr')
                after = compare.clock(clock_out, cpu)
                by_name = {r['name']: r for r in spec['rows']}
                last = [by_name[n] for n in spec['executed'] if by_name[n]['route'] == 'generic'][-1]
                _, decoded_out, decoded_err = run('decode-last-'+name, [observe, 'decode', str(last['pc']), last['bytes']])
                need(not decoded_err, 'exact native decoder observer stderr')
                decoded = json.loads(decoded_out)
                case['outcome'] = compare.check_connected(spec, row, command, out, native, before, after, decoded)
            ns = json.loads(binary(namespace/'namespace.json').read_bytes())
            binary(namespace/'launch.json')
            need(len(ns['objects']) == 1 and ns['objects'][0]['sha256'] == spec['interpreter_sha256'] and
                 ns['objects'][0]['seals'] == 15, 'actual immutable interpreter dependency')
            case.update(accepted=True, result=row, native_exit=None if native is None else native['exit'],
                        namespace={n: fact(namespace/n) for n in ('namespace.json', 'launch.json')})
        need(len(receipt['cases']) == 20 and all(x['accepted'] for x in receipt['cases']) and
             len(receipt['commands'])-cohort_start == 76, 'all finite cases and exact command cohort')

        # Optional-progress workload is still a real native/gated pair. Its
        # first unsupported request is retained exactly; it is never ls success.
        ls = pin('/bin/ls')
        aliases.append((str(ls), '${SYSTEM_LS}'))
        loader = pin(interpreter(ls))
        carrier = output/'ls-carrier'
        run('make-ls', [python, ROOT/'tools/page-entry/carrier.py', 'make', ls, bridge, carrier])
        binary(carrier)
        _, expected_out, err = run('native-ls', [ls, '-d', '.'])
        need(expected_out == b'.\n' and not err, 'native ls reference')
        namespace = output/'namespace-ls'
        argv = [python, ROOT/'tools/page-entry/carrier.py', 'exec-loader']
        for path in args.library_root or [Path('/usr/lib64')]:
            argv += ['--library-root', path.resolve()]
        argv += ['--namespace', namespace, carrier, ls, '--', ls, '-d', '.']
        command, out, err = run('gated-ls-diagnostic', argv, None)
        row = compare.parse(err)
        diagnostic = dict(status='failed', result=row, original=fact(ls), interpreter=fact(loader))
        receipt['ls_diagnostic'] = diagnostic
        if command['exit'] == 0:
            need(out == expected_out and row['status'] == row['failure_code'] == row['detail_abs'] == row['detail_negative'] == 0 and
                 row['step_route'] == 0 and row['generic_tf_attempts'] == row['generic_tf_steps'] and
                 row['source_syscalls'] == row['syscalls'] == row['forwarded'], 'actual scoped ls completion')
            compare.check_completed_owner(row)
            diagnostic['status'] = 'completed_actual_ls'
        else:
            need(command['exit'] == row['status'] == 125 and out == b'' and row['failure_code'] == row['tf_error'] == 100 and
                 row['tf_phase'] == 6 and row['step_route'] == 2 and row['tf_detail_abs'] == row['tf_detail_negative'] == 0 and
                 row['generic_tf_attempts'] == row['generic_tf_steps']+1 and
                 row['tf_sync_started'] == 1 and row['tf_sync_abs'] == row['tf_sync_negative'] == 0 and
                 all(row[k] == 0 for k in ('tf_trace', 'tf_open_started', 'tf_opened', 'tf_revoke_started', 'tf_revoked',
                     'tf_continuation_started', 'tf_query_attempted', 'tf_release_started')),
                 'exact pre-effect classifier refusal, not arbitrary failure')
            need(all(row[k] == 0 for k in ('tf_actual_flags', 'tf_flow', 'tf_family', 'tf_continuation_complete',
                 'tf_continuation_result_abs', 'tf_continuation_result_negative', 'tf_query_complete',
                 'tf_release_complete', 'tf_release_result_abs', 'tf_release_result_negative', 'tf_unexpected_frame')),
                 'exact unstarted classifier-refusal suffix')
            n = row['tf_length']
            packed = struct.pack('<QQ', row['tf_bytes_lo'], row['tf_bytes_hi'])
            need(1 <= n <= 15 and packed[n:] == bytes(16-n), 'retained exact failed original request')
            _, decoded_out, decoded_err = run('decode-ls-refusal', [observe, 'decode', str(row['tf_pc']), packed[:n].hex()])
            need(not decoded_err, 'refusal decoder stderr')
            decoded = json.loads(decoded_out)
            need(decoded['pc'] == row['tf_pc'] and decoded['length'] == n and decoded['decode_status'] == 0 and
                 decoded['kind'] == 0 and decoded['code'] == row['tf_code'], 'actual failed opcode identity')
            diagnostic.update(status='unsupported_actual_opcode', bytes=packed[:n].hex(), decoded=decoded)
        ns = json.loads(binary(namespace/'namespace.json').read_bytes())
        binary(namespace/'launch.json')
        for item in ns['objects']:
            need(item['seals'] == 15 and fact(pin(item['source']))['sha256'] == item['sha256'], 'immutable actual ls dependency')
        need(len(receipt['commands'])-cohort_start == (79 if diagnostic['status'] == 'completed_actual_ls' else 80),
             'complete exact diagnostic command cohort')
        diagnostic['namespace'] = {n: fact(namespace/n) for n in ('namespace.json', 'launch.json')}
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
        receipt['inputs_before'], receipt['artifacts_before'] = pins, binaries
        for name, before in (('inputs_after', pins), ('artifacts_after', binaries)):
            after = receipt[name] = {}
            for path, value in before.items():
                try:
                    after[path] = fact(path)
                    need(after[path] == value, 'final byte identity')
                except BaseException as exc:
                    receipt['final_errors'].append(path+': '+repr(exc))
        try:
            receipt['source_unchanged'] = source() == receipt['source']
            need(receipt['source_unchanged'], 'committed source changed')
        except BaseException as exc:
            receipt['final_errors'].append('source closure: '+repr(exc))
        if receipt['error'] or receipt['final_errors'] or receipt['build']['status'] != 'passed':
            receipt['status'] = 'failed'
        save(output/'receipt.json', receipt)
        publish(public, receipt, output, aliases)
    print(json.dumps(dict(status=receipt['status'], cases=len(receipt['cases']), commands=len(receipt['commands']),
                          receipt=str(public.relative_to(ROOT)))))
    return 0 if receipt['status'] == 'passed_finite_cohort' else 1


if __name__ == '__main__':
    raise SystemExit(main())
