#!/usr/bin/env python3
"""Bounded release validation of unchanged-page admission on real ELF programs.

Run pinned to one CPU. Raw process output stays under target; the public receipt
contains numeric summaries, exact source/program identities and output hashes.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import resource
import signal
import shutil
import sys
sys.dont_write_bytecode = True
import native_pages_compare as compare
from page_selected_fast_memset import body_check
import subprocess
import time

ROOT = Path(__file__).resolve().parents[2]


def sha(data):
    return hashlib.sha256(data).hexdigest()


def limits():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_CPU, (30, 30))
    resource.setrlimit(resource.RLIMIT_AS, (512 << 20, 512 << 20))
    resource.setrlimit(resource.RLIMIT_FSIZE, (16 << 20, 16 << 20))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expect-revision', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--library-root', default='/usr/lib64')
    parser.add_argument('--cpuid-nx', action='store_true', help='explicit raw CPUID NX-only release profile')
    args = parser.parse_args()
    if args.output.is_absolute():
        raise ValueError('public output must be repository-relative')
    os.chdir(ROOT)
    revision = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
    if revision != args.expect_revision or len(os.sched_getaffinity(0)) != 1:
        raise RuntimeError('exact revision and one reserved CPU required')
    nx_compare = None
    if args.cpuid_nx:
        spec = importlib.util.spec_from_file_location('native_page_cpuid_nx_reports',
            ROOT/'tools/page-entry/selected/tests/cpuid_nx/reports.py')
        nx_compare = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = nx_compare
        spec.loader.exec_module(nx_compare)
    # Bind the actual local import closure, including the unchanged completion
    # predicates reached through the old comparators. The schema is data rather
    # than a Python module, so it is named separately.
    imported_sources = set()
    for module in tuple(sys.modules.values()):
        name = getattr(module, '__file__', None)
        if not name:
            continue
        path = Path(name).resolve()
        if path.is_relative_to(ROOT) and path.suffix == '.py':
            imported_sources.add(str(path.relative_to(ROOT)))
    imported_sources.add('evaluation/inprocess/page_selected_rseq_schema.json')
    relevant = ['tools/page-entry', *sorted(imported_sources)]
    subprocess.run(['git', 'diff', '--exit-code', 'HEAD', '--', *relevant], check=True,
                   stdout=subprocess.DEVNULL)
    def source_facts():
        names = subprocess.check_output(['git', 'ls-files', '-z', '--', *relevant]).split(b'\0')
        facts = {os.fsdecode(name): sha(Path(os.fsdecode(name)).read_bytes()) for name in names if name}
        if not imported_sources <= facts.keys():
            raise RuntimeError('untracked evaluator or imported source')
        return facts
    def no_untracked_build_inputs():
        names = subprocess.check_output(['git', 'ls-files', '--others', '--exclude-standard', '-z',
                                         '--', 'tools/page-entry']).split(b'\0')
        return not any(name and Path(os.fsdecode(name)).suffix in ('.c', '.h', '.inc', '.rs', '.S', '.sh')
                       for name in names)
    if not no_untracked_build_inputs():
        raise RuntimeError('untracked build input')
    sources_before = source_facts()
    artifacts, dependencies = {}, {}
    stamp = time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())
    private = Path('target/native-pages') / stamp
    private.mkdir(parents=True, exist_ok=False)
    env = {'PATH': os.environ['PATH'], 'LANG': 'C', 'LC_ALL': 'C', 'LD_BIND_NOW': '1',
           'CARGO_INCREMENTAL': '0', 'CARGO_BUILD_JOBS': '1'}
    # Cargo/rustup require the existing toolchain home, never published below.
    for key in ('HOME', 'RUSTUP_HOME', 'CARGO_HOME'):
        if key in os.environ:
            env[key] = os.environ[key]
    receipt = dict(schema=1, revision=revision, started_utc=stamp,
                   hardware=dict(machine=platform.machine(), kernel=platform.release(),
                                 model=next(line.split(':', 1)[1].strip() for line in
                                            Path('/proc/cpuinfo').read_text().splitlines()
                                            if line.startswith('model name')),
                                 reserved_cpu_count=1),
                   reproduce=['python3', 'evaluation/inprocess/native_pages.py',
                              '--expect-revision', revision, '--output', str(args.output),
                              '--library-root', args.library_root],
                   cases=[], passed=False)
    if args.cpuid_nx:
        receipt['cpuid_profile'] = 'nx-only-raw'
        receipt['reproduce'].append('--cpuid-nx')
    commands = []
    tool_paths, tool_aliases, tool_hashes = {}, {}, {}
    receipt['tool_sha256'] = tool_hashes
    app_env = {'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C', 'TZ': 'UTC', 'LD_BIND_NOW': '1'}

    def pin_tool(name, value):
        if not value or not Path(value).is_absolute():
            raise RuntimeError('missing absolute tool: ' + name)
        alias = Path(value)
        path = alias.resolve(strict=True)
        if not path.is_file():
            raise RuntimeError('non-file tool: ' + name)
        tool_aliases[name], tool_paths[name] = alias, path
        tool_hashes[name] = sha(path.read_bytes())
        return path

    def run(name, command, timeout=60, bounded=False):
        start = time.monotonic_ns()
        out_path, err_path = private / (name + '.stdout'), private / (name + '.stderr')
        with out_path.open('wb') as out_file, err_path.open('wb') as err_file:
            process = subprocess.Popen(command, env=app_env if bounded else env,
                stdout=out_file, stderr=err_file, start_new_session=True,
                preexec_fn=limits if bounded else None)
            try:
                status = process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=5)
                status = 124
        elapsed = time.monotonic_ns() - start
        if out_path.stat().st_size + err_path.stat().st_size > 32 << 20:
            raise RuntimeError('capture exceeded bound')
        out, err = out_path.read_bytes(), err_path.read_bytes()
        commands.append(dict(name=name, command=command, pid=process.pid, exit=status, elapsed_ns=elapsed,
                             stdout_sha256=sha(out), stderr_sha256=sha(err)))
        return status, out, err, elapsed, process.pid

    try:
        for name in ('cc', 'python3', 'sh', 'rustup', 'git', 'cp', 'mkdir', 'dirname', 'nm', 'objdump'):
            pin_tool(name, shutil.which(name, path=env['PATH']))
        pin_tool('evaluator_python', sys.executable)
        pin_tool('app_python', shutil.which('python3', path=app_env['PATH']))
        # rustc/cargo in PATH can be rustup proxies. Resolve and pin the actual
        # selected toolchain, then make the build use those precise backends.
        for name in ('cargo', 'rustc'):
            status, out, err, _, _ = run('resolve-' + name, ['rustup', 'which', name])
            if status or err or not out.strip():
                raise RuntimeError('actual Rust tool resolution failed: ' + name)
            pin_tool(name, out.decode().strip())
        env.update(LI2_CC=str(tool_paths['cc']), LI2_CARGO=str(tool_paths['cargo']),
                   RUSTC=str(tool_paths['rustc']))
        for name in ('cc1', 'collect2', 'as', 'ld'):
            status, out, err, _, _ = run('resolve-' + name, ['cc', '-print-prog-name=' + name])
            if status or err or not out.strip():
                raise RuntimeError('actual C subtool resolution failed: ' + name)
            value = out.decode().strip()
            pin_tool(name, value if Path(value).is_absolute() else shutil.which(value, path=env['PATH']))
        recipe = 'tools/page-entry/selected/build-cpuid-nx.sh' if args.cpuid_nx else 'tools/page-entry/selected/build-native-pages.sh'
        status, _, _, _, _ = run('build', ['sh', recipe])
        if status:
            raise RuntimeError('release build failed')
        bridge = Path('target/page-entry/cpuid-nx/bridge-cpuid-nx.so' if args.cpuid_nx else 'target/page-entry/native-pages/bridge-native-pages.so')
        receipt['bridge_sha256'] = sha(bridge.read_bytes())
        artifacts[str(bridge)] = receipt['bridge_sha256']
        status, symbols, err, _, _ = run('runtime-memset-symbols', ['nm', '-S', '-n', str(bridge)])
        if status or err:
            raise RuntimeError('runtime reset symbol inspection failed')
        status, assembly, err, _, _ = run('runtime-memset-body', ['objdump', '-d', '--disassemble=memset', str(bridge)])
        if status or err:
            raise RuntimeError('runtime reset instruction inspection failed')
        receipt['runtime_memset'] = body_check(bridge, symbols, assembly, 'fast', symbol_name='memset')
        status, out, err, _, _ = run('compiler-version', ['cc', '-dumpfullversion'])
        if status or err or not out.strip():
            raise RuntimeError('compiler version observation failed')
        receipt['compiler'] = out.decode().strip()
        spec = importlib.util.spec_from_file_location('native_page_namespace', 'tools/page-entry/namespace.py')
        namespace_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(namespace_module)
        interpreter = namespace_module.parse(Path('/bin/true').read_bytes())['interpreter']
        boundary = private / 'boundary'
        boundary_command = ['cc', '-nostdlib', '-pie', '-Wl,--dynamic-linker,' + str(interpreter),
            '-Wl,-T,tools/page-entry/selected/tests/native_pages/linker.ld,-z,max-page-size=4096,--build-id=none,--no-as-needed',
            '-L' + args.library_root, '-l:' + Path(interpreter).name,
            'tools/page-entry/selected/tests/native_pages/boundary.S', '-o', str(boundary)]
        status, _, _, _, _ = run('build-boundary', boundary_command)
        if status:
            raise RuntimeError('boundary fixture build failed')
        artifacts[str(boundary)] = sha(boundary.read_bytes())
        for program in ('true', 'ls', 'boundary'):
            original = str(boundary) if program == 'boundary' else '/bin/' + program
            carrier = private / (program + '-carrier')
            status, out, _, _, _ = run('carrier-' + program,
                                   ['python3', 'tools/page-entry/carrier.py', 'make', original,
                                    str(bridge), str(carrier)])
            if status:
                raise RuntimeError('carrier preparation failed')
            identities = json.loads(out)
            artifacts[str(carrier)] = sha(carrier.read_bytes())
            dependencies[original] = identities['original_sha256']
            for rseq in (('disabled',) if program == 'boundary' else ('default', 'disabled')):
                name = program + '-' + rseq
                argv = [original] + (['-d', '.'] if program == 'ls' else [])
                if rseq == 'disabled':
                    app_env['GLIBC_TUNABLES'] = 'glibc.pthread.rseq=0'
                else:
                    app_env.pop('GLIBC_TUNABLES', None)
                native = run(name + '-native', argv, bounded=True)
                command = ['python3', 'tools/page-entry/carrier.py', 'exec-loader',
                           '--library-root', args.library_root, '--namespace', str(private / (name + '-ns'))]
                if rseq == 'disabled':
                    command += ['--disable-rseq']
                command += [str(carrier), original, '--', *argv]
                gated = run(name + '-gated', command, bounded=True)
                namespace = json.loads((private / (name + '-ns') / 'namespace.json').read_bytes())
                dependency_rows = []
                for item in namespace['objects']:
                    dependencies[item['source']] = item['sha256']
                    dependency_rows.append(dict(names=item['names'], sha256=item['sha256'], size=item['size']))
                dependencies[namespace['interpreter']] = identities['interpreter_sha256']
                loader, pages, report_error = {}, {}, None
                nx_public = None
                try:
                    if args.cpuid_nx:
                        parsed = nx_compare.reports(gated[2], True, False)
                        nx_compare.completed(parsed, gated[4])
                        nx = parsed['cpuid_nx']
                        if not (nx['status'] == nx['failure_code'] == 0 and
                                nx['hardware_entered'] == nx['hardware_returned'] == 1 and nx['phase'] == 3 and
                                nx['attempts'] == nx['samples'] == nx['commits'] == parsed['loader']['cpuid'] > 0 and
                                2 <= nx['next_pc']-nx['pc'] <= 15 and nx['raw'] == nx['result']):
                            raise ValueError('complete real NX raw sampling/commit; no fabricated fault/rearm')
                        nx_public = {k: nx[k] for k in ('hardware_entered', 'hardware_returned', 'phase', 'attempts', 'samples', 'commits')}
                    else:
                        parsed = compare.reports(gated[2])
                        compare.completed(parsed, gated[4])
                    loader, pages = parsed['loader'], parsed['native']
                except (ValueError, KeyError, TypeError) as error:
                    report_error = type(error).__name__ + ': ' + str(error)
                passed = (native[0] == gated[0] == 0 and native[1] == gated[1] and not native[2]
                          and report_error is None)
                if program == 'boundary':
                    passed = (passed and len(gated[1]) == 128 and pages.get('main_admissions') == 4
                              and pages.get('main_refaults') == 1)
                receipt['cases'].append(dict(name=name, passed=passed, report_error=report_error, dependencies=dependency_rows,
                    input_sha256=identities['original_sha256'], interpreter_sha256=identities['interpreter_sha256'],
                    native_exit=native[0], gated_exit=gated[0], output_equal=native[1] == gated[1],
                    output_sha256=sha(gated[1]), native_whole_process_ns=native[3], gated_whole_process_ns=gated[3],
                    loader={k: loader.get(k) for k in ('status', 'failure_code', 'nx_faults', 'admissions',
                                                      'source_syscalls', 'cpuid', 'rdtsc', 'rdtscp')},
                    pages=pages, **({'cpuid_nx': nx_public} if args.cpuid_nx else {})))
        receipt['passed'] = len(receipt['cases']) == 5 and all(c['passed'] for c in receipt['cases'])
    except Exception as error:
        receipt['error'] = type(error).__name__ + ': ' + str(error)
    # Closure errors must disqualify and remain in the receipt, including a
    # deleted/unreadable source or tool. They cannot erase an earlier failure.
    final_errors = receipt['final_errors'] = []
    def final_check(label, check):
        try:
            result = bool(check())
            if not result:
                final_errors.append(label + ': changed or missing')
            return result
        except Exception as error:
            final_errors.append(label + ': ' + type(error).__name__ + ': ' + str(error))
            return False
    receipt['source_unchanged'] = final_check('source', lambda: sources_before == source_facts() and revision ==
        subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip() and
        subprocess.run(['git', 'diff', '--quiet', 'HEAD', '--', *relevant]).returncode == 0 and
        no_untracked_build_inputs())
    receipt['source_manifest_sha256'] = sha(json.dumps(sources_before, sort_keys=True).encode())
    (private / 'source-manifest.json').write_text(json.dumps(sources_before, sort_keys=True))
    receipt['artifacts_unchanged'] = final_check('artifacts', lambda: all(
        Path(path).is_file() and sha(Path(path).read_bytes()) == expected for path, expected in artifacts.items()))
    receipt['inputs_unchanged'] = final_check('inputs', lambda: all(
        Path(path).is_file() and sha(Path(path).read_bytes()) == expected for path, expected in dependencies.items()))
    receipt['tools_unchanged'] = final_check('tools', lambda: all(tool_aliases[name].resolve() == path and
                                     path.is_file() and sha(path.read_bytes()) == tool_hashes[name]
                                     for name, path in tool_paths.items()))
    (private / 'tool-manifest.json').write_text(json.dumps({name: dict(
        path=str(path), alias=str(tool_aliases[name]), sha256=tool_hashes[name])
        for name, path in tool_paths.items()}, sort_keys=True))
    receipt['passed'] = (receipt['passed'] and not final_errors and receipt['tools_unchanged'] and
                         receipt['source_unchanged'] and receipt['artifacts_unchanged'] and receipt['inputs_unchanged'])
    receipt['bounds'] = dict(cpu_seconds=30, memory_bytes=512 << 20, file_bytes=16 << 20, wall_seconds=60)
    receipt['commands'] = commands
    receipt['timing_scope'] = ('CLOCK_MONOTONIC_RAW admission service from owner entry through live byte, backing, '
        'halo, permission and post-publication verification; first admitted page and at most16 revisits to '
        'that exact address/allocation/generation. Excludes signal delivery. Whole-process gated time includes '
        'namespace preparation. Single observations on a shared host; no instrumentation-only overhead claim.')
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(receipt, indent=2, sort_keys=True) + '\n')
    print(json.dumps({'passed': receipt['passed'], 'cases': len(receipt['cases']), 'output': str(args.output)}))
    return 0 if receipt['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
