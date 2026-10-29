#!/usr/bin/env python3
"""Twenty fixed release workload intervals after genuine finite qualification."""
import argparse
import csv
import functools
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from checks import admission, source
from page_selected import ENV, fact, need, save
from page_default_ls_release_performance import decode, HARDWARE_KEYS
from run import hardware
from page_tf_interval_samples import ORDER, PROFILE, command_name, digest, summarize
from page_tf_interval_qualified import authenticate

SEMANTIC = ('generic_tf_attempts', 'generic_tf_steps', 'source_syscalls', 'cpuid', 'rdtsc', 'selected_steps')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expect-revision', required=True)
    parser.add_argument('--qualification-receipt', type=Path, required=True)
    parser.add_argument('--qualification-sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    os.chdir(ROOT)
    need(not sys.flags.optimize and re.fullmatch('[0-9a-f]{40}', args.expect_revision) and
         re.fullmatch('[0-9a-f]{64}', args.qualification_sha256) and
         len(os.sched_getaffinity(0)) == 1, 'exact revision/hash, assertions and one reserved CPU')
    private = args.output.resolve()
    need(private.is_relative_to(ROOT / 'target') and not private.exists(), 'fresh private output')
    private.mkdir(parents=True, mode=0o700)
    cpu = next(iter(os.sched_getaffinity(0)))
    receipt = dict(schema=1, profile='page-tf-interval-release-performance-v1',
                   expected_revision=args.expect_revision, source=None, source_unchanged=False,
                   qualification_verified=False, cpu=cpu, hardware=hardware(cpu),
                   status='failed', error=None, final_errors=[], commands=[], samples=[])
    receipt['requested_qualification'] = dict(sha256=args.qualification_sha256, bytes=None)
    receipt['reproduce'] = ['python3', '-B', 'evaluation/inprocess/page_tf_interval_performance.py',
                            '--expect-revision', args.expect_revision, '--qualification-receipt',
                            '${SAME_REVISION_INTERVAL_RECEIPT}', '--qualification-sha256',
                            args.qualification_sha256, '--output', '${FRESH_PRIVATE_OUTPUT}']
    pins, aliases, artifacts, presence, namespace_links = {}, {}, {}, {}, {}
    namespaces = []

    def pin(path):
        alias = str(Path(path).absolute())
        resolved = Path(alias).resolve(strict=True)
        observed = fact(resolved)
        need(alias not in aliases or aliases[alias] == str(resolved), 'unchanged input alias')
        need(str(resolved) not in pins or pins[str(resolved)] == observed, 'unchanged input bytes')
        aliases[alias], pins[str(resolved)] = str(resolved), observed
        return resolved

    def binary(path):
        path = Path(path)
        need(path.is_file() and not path.is_symlink(), 'regular retained artifact')
        observed = dict(fact(path), mode=path.stat().st_mode & 0o777)
        need(str(path) not in artifacts or artifacts[str(path)] == observed, 'unchanged artifact')
        artifacts[str(path)] = observed
        return path

    def closure():
        if 'prerequisite_configuration' in receipt:
            config = receipt['prerequisite_configuration']
            need(admission.cargo_configuration(config['environment']) == config['cargo_configuration'],
                 'qualified compiler configuration unchanged')
        for name in ('qualified_namespace_aliases', 'interval_namespace_aliases'):
            need(all(Path(p).is_symlink() and os.readlink(p) == target
                     for p, target in receipt.get(name, {}).items()), 'qualified namespace unchanged')
        need(all(Path(p).is_symlink() and os.readlink(p) == target
                 for p, target in namespace_links.items()), 'timing namespace unchanged')
        need(all(os.path.lexists(p) == exists for p, exists in presence.items()), 'loader configuration presence')
        need(all(str(Path(p).resolve(strict=True)) == target for p, target in aliases.items()), 'all lexical aliases')
        need(all(fact(p) == expected for p, expected in pins.items()), 'all source/tool/input bytes')
        need(all(dict(fact(p), mode=Path(p).stat().st_mode & 0o777) == expected
                 for p, expected in artifacts.items()), 'all artifact bytes and modes')

    def load(name, path):
        spec = importlib.util.spec_from_file_location(name, pin(path))
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
        return module

    def capture(row):
        for stream in ('stdout', 'stderr', 'record', 'preparation'):
            path = private / (row['name'] + '.' + stream)
            observed = row.get('captures', {}).get(stream)
            if path.exists() or path.is_symlink():
                actual = fact(binary(path))
                need(observed is not None and observed.get('file') == path.name and
                     actual == {k: observed[k] for k in ('bytes', 'sha256')}, 'complete actual capture binding')
            elif observed is not None:
                need(observed == {'missing': True}, 'actual partial capture absence')
        path = private / (row['name'] + '.json')
        binary(path)
        need(decode(path.read_bytes()) == row, 'exact saved command row')

    def namespace_check(directory, asset, preparation, row):
        original, carrier, interpreter = asset['original'], asset['carrier'], asset['interpreter']
        mode = 'gated' if row['profile'] == 'gated-timing' else 'native'
        env = {k: v for k, v in ENV.items() if k != 'PYTHONDONTWRITEBYTECODE'}
        need(preparation['mode'] == mode and preparation['control'] == 0 and
             preparation['environment'] == env and preparation['argv'] ==
             [str(original), mode, str(preparation['pipes'][0]['fd']), str(preparation['pipes'][1]['fd']), '0'],
             'same original, fixed arguments and default environment')
        if mode == 'native':
            need(directory is None, 'native process has no carrier namespace')
            return
        manifest = binary(directory / 'namespace.json')
        launch = binary(directory / 'launch.json')
        sealed, started = decode(manifest.read_bytes()), decode(launch.read_bytes())
        need(sealed['schema_version'] == 1 and sealed['status'] == 'prepared_not_executed' and
             sealed['scope'] == 'explicit_sealed_dependency_namespace' and sealed['directory'] == str(directory) and
             sealed['original'] == str(original) and sealed['original_sha256'] == fact(original)['sha256'] and
             sealed['interpreter_sha256'] == fact(interpreter)['sha256'] and
             len(sealed['objects']) == len(asset['objects']), 'complete fresh namespace for qualified original')
        expected_names = {'namespace.json', 'launch.json'}
        fds = []
        for actual, expected in zip(sealed['objects'], asset['objects']):
            need(actual['names'] == expected['names'] and actual['sha256'] == hashlib.sha256(expected['bytes']).hexdigest() and
                 actual['size'] == len(expected['bytes']) and actual['seals'] == namespace.SEALS and
                 type(actual['fd']) is int and actual['fd'] > 2 and actual['fd'] not in fds and
                 type(actual['device']) is int and actual['device'] > 0 and
                 type(actual['inode']) is int and actual['inode'] > 0, 'actual immutable qualified dependency')
            fds.append(actual['fd'])
            for name in actual['names']:
                path, target = directory / name, '/proc/self/fd/' + str(actual['fd'])
                need(path.is_symlink() and os.readlink(path) == target, 'actual sealed dependency alias')
                namespace_links[str(path)] = target
                expected_names.add(name)
        need({p.name for p in directory.iterdir()} == expected_names, 'complete private namespace entry set')
        env.update(LD_LIBRARY_PATH=str(directory), LD_BIND_NOW='1', LI2_DEPENDENCY_FDS=','.join(map(str, fds)))
        need(started['schema_version'] == 1 and started['status'] == 'prepared_not_executed' and
             started['scope'] == 'first_entry_loader_candidate' and started['argv'] == preparation['argv'] and
             started['environment'] == env and started['dependency_fds'] == fds and
             started['carrier_sha256'] == fact(carrier)['sha256'] and
             started['carrier_size'] == carrier.stat().st_size, 'exact qualified unobserved carrier and launch')
        receipt.setdefault('namespace_facts', {})[row['name']] = dict(manifest=fact(manifest), launch=fact(launch))

    try:
        receipt['source'] = source()
        need(receipt['source']['revision'] == args.expect_revision, 'exact clean current source')
        names = subprocess.check_output(['git', 'ls-files', '-z', '--', 'tools/page-entry', 'evaluation/inprocess'])
        receipt['required_source_inputs'] = {str(pin(ROOT / os.fsdecode(n))): fact(ROOT / os.fsdecode(n))
            for n in names.split(b'\0') if n and not n.startswith(b'evaluation/inprocess/results/')}
        assets = authenticate(args.qualification_receipt, args.qualification_sha256,
                              receipt['source'], pin, binary, receipt)
        receipt['requested_qualification'] = fact(pin(args.qualification_receipt))
        need(receipt['requested_qualification']['sha256'] == args.qualification_sha256,
             'requested finite receipt bytes remain exact')
        need(set(assets['programs']) == {1, 256} and pin(sys.executable) == assets['tools']['python'],
             'both qualified programs and exact Python tool')
        receipt['measured_artifacts'] = {
            str(n): {name: fact(asset[name]) for name in ('original', 'interpreter', 'carrier')}
            for n, asset in assets['programs'].items()}
        fixture = ROOT / 'tools/page-entry/selected/tests/tf_interval'
        pipe = load('interval_perf_pipe', fixture / 'pipe_run.py')
        check = load('interval_perf_check', fixture / 'check.py')
        namespace = load('interval_perf_namespace', ROOT / 'tools/page-entry/namespace.py')
        reports = load('interval_perf_reports', ROOT / 'tools/page-entry/selected/tests/tf_same_page/reports.py')
        need(pipe.BOUNDS == [5, 512 << 20, 16 << 20, 15], 'unchanged finite-qualified child limits')
        for module in tuple(sys.modules.values()):
            path = getattr(module, '__file__', None)
            if path and Path(path).resolve().is_relative_to(ROOT) and Path(path).suffix == '.py':
                pin(path)
        for path in ('/etc/ld.so.cache', '/etc/ld.so.preload'):
            presence[path] = os.path.lexists(path)
            if presence[path]:
                pin(path)
        need(not presence['/etc/ld.so.preload'], 'no global preload')
        closure()
        receipt['qualification_verified'] = True
        for order, (n, pair, lane) in enumerate(ORDER):
            closure()
            asset = assets['programs'][n]
            name = command_name(n, pair, lane)
            directory = private / (name + '-namespace') if lane == 'gated' else None
            if directory is not None:
                namespaces.append(directory)
            command = tuple(pipe.command(assets['tools']['python'], asset['original'], lane,
                                         asset['interpreter'].parent,
                                         asset['carrier'] if lane == 'gated' else None, directory))
            image = asset['gated_image'] if lane == 'gated' else asset['image']
            callback = functools.partial(check.terminal, image=image, layout=None,
                                         cpu=cpu, profile=PROFILE[lane], expected_command=command)
            sample = dict(operations=n, pair=pair, lane=lane, order=order, accepted=False)
            row = dict(name=name, argv=list(command), profile=PROFILE[lane], control='normal',
                       bounds=list(pipe.BOUNDS), environment=dict(ENV), capture_limit=16 << 20, expected_exit=0)
            receipt['samples'].append(sample)
            receipt['commands'].append(row)
            try:
                pipe.invoke(row, private, cpu, callback)
            finally:
                # Invocation can fail while saving an already accepted child.
                # Retain that observation even when later capture, namespace or
                # custody checks fail; the whole batch still fails without an
                # aggregate. Never promote a rejected child to an accepted one.
                try:
                    if row.get('accepted') is True:
                        sample.update(pid=row['pid'], interval_ns=row['interval_ns'],
                                      terminal_sha256=digest(row['terminal_validation']), accepted=True)
                except BaseException as exc:
                    receipt['final_errors'].append('sample retention: ' + type(exc).__name__ + ': ' + str(exc))
                try:
                    capture(row)
                except BaseException as exc:
                    receipt['final_errors'].append('capture: ' + type(exc).__name__ + ': ' + str(exc))
            need(row.get('accepted') is True, 'actual fixed timing child passed every terminal check')
            need(not receipt['final_errors'], 'current captures retained without error')
            preparation = decode((private / (name + '.preparation')).read_bytes())
            namespace_check(directory, asset, preparation, row)
            if lane == 'gated':
                actual = reports.reports((private / (name + '.stderr')).read_bytes())
                reports.completed(actual, row['pid'])
                need(set(asset['semantic']['loader']) == set(SEMANTIC) and
                     actual['lease'] == asset['semantic']['lease'] and
                     {k: actual['loader'][k] for k in asset['semantic']['loader']} == asset['semantic']['loader'],
                     'same complete global lease and fixed six loader counters as qualified execution')
        receipt['status'] = 'passed'
    except BaseException as exc:
        receipt['error'] = type(exc).__name__ + ': ' + str(exc)
    finally:
        for directory in namespaces:
            for name in ('namespace.json', 'launch.json'):
                path = directory / name
                try:
                    if path.exists() or path.is_symlink():
                        binary(path)
                except BaseException as exc:
                    receipt['final_errors'].append('namespace retention: ' + type(exc).__name__ + ': ' + str(exc))
        try:
            closure()
            receipt['source_after'] = source()
            need(receipt['source_after'] == receipt['source'], 'entire committed source unchanged')
            receipt['source_unchanged'] = True
        except BaseException as exc:
            receipt['final_errors'].append('final custody: ' + type(exc).__name__ + ': ' + str(exc))
        if receipt['error'] or receipt['final_errors'] or not receipt['source_unchanged']:
            receipt['status'] = 'failed'
        receipt.update(inputs=pins, aliases=aliases, artifacts=artifacts,
                       configuration_presence=presence, namespace_links=namespace_links)
        save(private / 'receipt.json', receipt)
    public = summarize(receipt)
    columns = ('operations', 'pair', 'lane', 'order', 'accepted', 'pid', 'interval_ns', 'terminal_sha256')
    with (private / 'samples.csv').open('x', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=columns)
        writer.writeheader()
        writer.writerows({k: sample.get(k) for k in columns} for sample in receipt['samples'])
    public.update(schema=1, profile=receipt['profile'], revision=args.expect_revision, status=receipt['status'],
                  hardware={k: receipt['hardware'][k] for k in (*HARDWARE_KEYS, 'model name')}, reserved_cpu_count=1,
                  bounds=[5, 512 << 20, 16 << 20, 15], qualification=receipt['requested_qualification'],
                  reproduce=receipt['reproduce'],
                  acceptance_scope='A sample records strict child terminal and protocol acceptance. Performance credit also requires the complete fixed batch, namespace and semantic joins, and final source and artifact custody.',
                  source_unchanged=receipt['source_unchanged'], inputs_sha256=digest(pins), artifacts_sha256=digest(artifacts),
                  measured_artifacts=receipt.get('measured_artifacts'),
                  private_receipt=fact(private / 'receipt.json'), samples_csv=fact(private / 'samples.csv'),
                  error_type=receipt['error'].split(':', 1)[0] if receipt['error'] else None,
                  final_error_count=len(receipt['final_errors']), full_b2_complete=False, full_b3_complete=False)
    text = json.dumps(public, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n'
    need(len(text.encode()) < 64 << 10 and not any(v and len(v) > 1 and v in text
         for v in (str(ROOT), str(Path.home()), platform.node(), '/home/')), 'compact public numeric results')
    with (private / 'public.json').open('x') as stream:
        stream.write(text)
    print(json.dumps(dict(status=receipt['status'], accepted_subjects=public['accepted_subjects'],
                          receipt=str(private / 'receipt.json'), public=str(private / 'public.json'))))
    return 0 if receipt['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
