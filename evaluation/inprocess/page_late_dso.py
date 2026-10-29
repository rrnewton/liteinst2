#!/usr/bin/env python3
"""Bounded native and in-process late dlopen/dlclose/reload application cohort."""
import argparse
import ctypes
import hashlib
import importlib.util
import json
import os
import platform
import re
import shlex
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
SELECTED = ROOT / 'tools/page-entry/selected'
FIXTURE = SELECTED / 'tests/late_dso'
sys.path[:0] = [str(HERE), str(SELECTED.parent)]
from checks import source
from run import hardware
from page_selected import ENV, elf, fact, interpreter, need, save
from page_selected_generic_build import Build, PROFILES
from page_selected_process import invoke
from page_selected_effect_ls import program_invoke
from page_selected_repeat_lease_ls import build_bridge
from page_selected_oneshot_build import before_default
from page_selected_register_time_build import expand, recipe
import namespace
import page_late_dso_reports as reports

BOUNDS = dict(PROFILES, release_build=[30, 512 << 20, 16 << 20, 60],
              program=[30, 512 << 20, 16 << 20, 60])
H = lambda b: hashlib.sha256(b).hexdigest()
MASK = ((1 << 64) - 1) ^ sum(1 << (s - 1) for s in (4, 5, 9, 11, 19, 31))


def digest(value):
    return H(json.dumps(value, sort_keys=True, separators=(',', ':')).encode())


def reader_support(builder, private, pin, binary, run, receipt):
    def load(name, path):
        spec = importlib.util.spec_from_file_location(name, pin(path))
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    reader = load('late_dso_reader', FIXTURE / 'read.py')
    xstate = load('late_dso_xstate', SELECTED / 'tests/b2_reference/xstate.py')
    policy = private / 'native-policy.so'
    unit = pin(SELECTED / 'native_policy.c')
    flags = ['-std=gnu11', '-O2', '-g', '-Wall', '-Wextra', '-Werror', '-fPIC', '-shared']
    _, out, err = run('policy-headers', [builder.tools['cc'], *flags, '-M', '-MT', 'li2_policy', unit],
                      env=builder.environment)
    lines = out.decode().replace('\\\n', ' ').splitlines()
    need(not err and len(lines) == 1 and lines[0].startswith('li2_policy: '), 'complete policy include rule')
    headers = {str(pin(path)): fact(pin(path)) for path in shlex.split(lines[0].split(':', 1)[1])}
    need(str(unit) in headers and str(SELECTED / 'native_policy.h') in headers, 'actual policy sources')
    run('policy-link', [builder.tools['cc'], *flags, '-Wl,-z,noexecstack,--build-id=none', unit, '-o', policy],
        profile='release_build', env=builder.environment)
    receipt['reader_support'] = dict(headers=headers, native_policy=fact(binary(policy)))
    lib = ctypes.CDLL(str(policy))
    lib.li2_native_policy.argtypes = (ctypes.c_void_p, ctypes.c_size_t)
    lib.li2_native_policy.restype = ctypes.c_uint
    return reader, xstate, lambda data: lib.li2_native_policy(data, len(data))


def compile_subject(builder, private, pin, binary, aliases, run, receipt):
    """Execute the committed three-object release recipe with actual include closure."""
    script = pin(FIXTURE / 'build.sh')
    matches = re.findall(r'^common=\(([^\n]*)\)$', script.read_text(), re.M)
    rows = recipe(script, '"$cc"')
    need(len(matches) == 1 and len(rows) == 3, 'one complete three-object recipe')
    common = shlex.split(matches[0])
    output = private / 'application'
    output.mkdir()
    values = {'$cc': builder.tools['cc'], '$source_dir': FIXTURE,
              '$provider_dir': SELECTED / 'tests/provider_app', '$output': output}
    records = receipt['application_build'] = []
    names = ('libli2-late-leaf.so', 'libli2-late.so', 'late-dso')
    for index, (words, name) in enumerate(zip(rows, names, strict=True)):
        argv = expand([part for word in words for part in
                       (common if word == '${common[@]}' else [word])], values)
        path = output / name
        sources = [x for x in argv if x.endswith(('.c', '.S'))]
        need(argv[0] == str(builder.tools['cc']) and argv[-2:] == ['-o', str(path)] and
             len(sources) == (1 if index == 0 else 4) and
             all(x in argv for x in ('-O2', '-g', '-Wall', '-Wextra', '-Werror')),
             'actual release subject command')
        row = dict(name=name, argv=argv, status='failed')
        records.append(row)
        flags = [x for x in argv[1:-2] if x not in sources and
                 not x.startswith(('-Wl,', '-L', '-l'))]
        _, data, err = run('subject-' + str(index) + '-headers',
                          [builder.tools['cc'], *flags, '-M', '-MT', 'li2_late', *sources],
                          env=builder.environment)
        rules = data.decode().replace('\\\n', ' ').splitlines()
        need(not err and len(rules) == len(sources) and
             all(x.startswith('li2_late: ') for x in rules), 'complete subject include rules')
        includes = {}
        for rule in rules:
            for token in shlex.split(rule.split(':', 1)[1]):
                p = pin(token)
                includes[str(p)] = fact(p)
        need(set(sources) <= set(includes), 'all subject translation units observed')
        row['headers'] = includes
        run('subject-' + str(index) + '-link', argv, profile='release_build', env=builder.environment)
        row['artifact'] = fact(binary(path))
        _, head, segments = elf(path)
        need(head[2] == 62 and not any(p[0] == 1 and p[1] & 3 == 3 for p in segments),
             'actual x86-64 subject without writable executable segment')
        row['status'] = 'passed'
    return output / names[2], output / names[1], output / names[0]


def cohort(builder, products, private, pin, binary, aliases, run, r):
    original, late, leaf = compile_subject(builder, private, pin, binary, aliases, run, r)
    bridge = build_bridge(builder, products, private, pin, binary, aliases, run, r)
    reader, xstate, native_policy = reader_support(builder, private, pin, binary, run, r)
    reader_args = dict(native_policy=native_policy, xstate=xstate)
    original_bytes, late_bytes = original.read_bytes(), late.read_bytes()
    interp = pin(interpreter(original))
    main_info = namespace.parse(original.read_bytes())
    late_info = namespace.parse(late.read_bytes())
    need(not {'libli2-late.so', 'libli2-late-leaf.so'} & set(main_info['needed']) and
         'libli2-late-leaf.so' in late_info['needed'], 'real late dependency, absent from main DT_NEEDED')
    roots = [original.parent, Path('/usr/lib64')]
    objects, description = namespace.plan(original, roots, bytes.fromhex(fact(original)['sha256']),
                                          bytes.fromhex(fact(interp)['sha256']),
                                          late_sonames=('libli2-late.so',))
    for name, path in (('libli2-late.so', late), ('libli2-late-leaf.so', leaf)):
        matches = [item for item in objects if name in item['names']]
        need(len(matches) == 1 and matches[0]['path'] == path and matches[0]['bytes'] == path.read_bytes(),
             'fresh built late object is the exact preauthorized input')
    r['namespace_plan'] = description
    for item in objects:
        need(fact(pin(item['path']))['sha256'] == H(item['bytes']), 'exact sealed source plan')
    images, image_bytes, by_hash = [], [], {}
    inputs = private / 'external-inputs'
    inputs.mkdir()
    for role, path in [('original', original), ('interpreter', interp)] + [
            ('dependency-' + str(i), item['path']) for i, item in enumerate(objects)]:
        data = pin(path).read_bytes()
        identity = dict(bytes=len(data), sha256=H(data))
        need(fact(path) == identity, 'complete independent external ELF bytes')
        if identity['sha256'] in by_hash:
            i = by_hash[identity['sha256']]
            need(data == image_bytes[i], 'duplicate identity has identical external bytes')
            images[i]['roles'].append(role)
            continue
        copy = inputs / (str(len(images)) + '.elf')
        with copy.open('xb') as f:
            f.write(data)
        need(fact(binary(copy)) == identity, 'retained external input copy')
        by_hash[identity['sha256']] = len(images)
        images.append(dict(identity, roles=[role]))
        image_bytes.append(data)
    r['external_inputs'] = images
    r['subject_artifacts'] = {name: fact(path) for name, path in
                              (('original', original), ('late', late), ('leaf', leaf), ('bridge', bridge))}
    carrier = private / 'carrier'
    _, out, err = run('carrier', [builder.tools['python'], '-B', pin(SELECTED.parent / 'carrier.py'),
                                  'make', original, bridge, carrier], profile='program')
    need(not err, 'actual carrier construction stderr')
    binary(carrier)
    identities = json.loads(out)
    need(all(identities[k + '_sha256'] == fact(p)['sha256'] for k, p in
             (('original', original), ('interpreter', interp), ('bridge', bridge), ('carrier', carrier))) and
         interpreter(carrier) == bridge,
         'actual carrier identities')
    carrier_bytes = carrier.read_bytes()
    launcher = pin(FIXTURE / 'launch.py')
    parsed = []
    for role in ('native', 'gated'):
        directory = private / role
        directory.mkdir()
        case = dict(lane=role, status='failed')
        r['cases'].append(case)
        argv = [builder.tools['python'], '-B', launcher, '--root', ROOT, '--role', role,
                '--original', original, '--preparation', directory / 'preparation.json']
        for path in roots:
            argv += ['--library-root', path]
        if role == 'gated':
            argv += ['--carrier', carrier, '--namespace', directory / 'namespace', '--record-fd', '{record_fd}']
        try:
            row, out, err = run(role, argv, profile='program', record=role == 'gated')
        finally:
            command = r['commands'][-1]
            case.update(exit=command.get('exit'), whole_process_ns=command.get('duration_ns'),
                        captures=command.get('captures', {}))
        if role == 'native':
            need(not err, 'actual native subject completion stderr')
        prep = json.loads(binary(directory / 'preparation.json').read_bytes())
        need(prep['schema_version'] == 1 and prep['status'] == 'prepared_not_executed' and prep['role'] == role and
             prep['pid'] == row['pid'] and prep['cpu'] == [r['cpu']] and prep['reset_mask'] == 0 and
             prep['launch_mask'] == (MASK if role == 'native' else 0) and
             prep['argv'] == [str(original), 'native'] and prep['default_rseq'] is True and
             [x['signal'] for x in prep['dispositions']] == [n for n in range(1, 65) if n not in (9, 19)] and
             all(x['after'] == 0 for x in prep['dispositions']), 'actual original launch and signal preparation')
        if role == 'gated':
            ns = directory / 'namespace'
            manifest = json.loads(binary(ns / 'namespace.json').read_bytes())
            launch = json.loads(binary(ns / 'launch.json').read_bytes())
            need(all(manifest[k] == v for k, v in description.items()) and
                 len(manifest['objects']) == len(objects) and manifest['schema_version'] == 1 and
                 manifest['scope'] == 'explicit_sealed_dependency_namespace' and
                 manifest['status'] == 'prepared_not_executed' and manifest['directory'] == str(ns) and
                 manifest['search_policy'] == 'explicit roots; no RPATH/RUNPATH/cache emulation' and
                 manifest['identity_policy'] == 'sealed copies and private paths; not filesystem transparency',
                 'actual namespace matches independent late plan')
            fds = []
            for observed, item in zip(manifest['objects'], objects, strict=True):
                need(observed['names'] == item['names'] and observed['needed'] == item['info']['needed'] and
                     observed['source'] == str(item['path']) and
                     observed['descriptive_pt_interp'] == (str(item['info']['interpreter']) if item['info']['interpreter'] else None) and
                     observed['sha256'] == H(item['bytes']) and observed['size'] == len(item['bytes']) and
                     observed['seals'] == namespace.SEALS and type(observed['fd']) is int and
                     observed['fd'] > 3 and observed['fd'] not in fds and
                     type(observed['device']) is int and observed['device'] > 0 and
                     type(observed['inode']) is int and observed['inode'] > 0,
                     'actual sealed late dependency identity')
                fds.append(observed['fd'])
                for name in item['names']:
                    path = ns / name
                    value = '/proc/self/fd/' + str(observed['fd'])
                    need(path.is_symlink() and os.readlink(path) == value, 'actual sealed dependency alias')
                    r['namespace_aliases'][str(path)] = value
            need(launch == dict(schema_version=1, scope='first_entry_loader_candidate', status='prepared_not_executed',
                 argv=prep['argv'], dependency_fds=fds, carrier_sha256=fact(carrier)['sha256'],
                 carrier_size=fact(carrier)['bytes'], environment=dict(PATH='/usr/bin:/bin', LANG='C', LC_ALL='C', TZ='UTC',
                     LD_BIND_NOW='1', LD_LIBRARY_PATH=str(ns), LI2_DEPENDENCY_FDS=','.join(map(str, fds)))) and
                 prep['late_sonames'] == ['libli2-late.so'] and prep['environment_source'] == str(ns / 'launch.json'),
                 'actual closed gated exec environment')
            record = (private / 'gated.record').stat()
            need(record.st_size == 0 and prep['observer'] == dict(fd=3, device=record.st_dev, inode=record.st_ino),
                 'actual unused record descriptor in unobserved release bridge')
        else:
            need(prep['observer'] is None and prep['environment'] == dict(PATH='/usr/bin:/bin', LANG='C',
                 LC_ALL='C', TZ='UTC', LD_BIND_NOW='1', LD_LIBRARY_PATH=':'.join(map(str, roots))),
                 'actual closed native environment')
        state = reader.read(out, row['pid'], r['cpu'], original_bytes, late_bytes, **reader_args)
        case['application'] = state['summary']
        case['reader_controls'] = reader.controls(out, row['pid'], r['cpu'], original_bytes, late_bytes, **reader_args)
        if role == 'gated':
            r['pair'] = reader.pair(parsed[0][0], out, native_pid=parsed[0][1], gated_pid=row['pid'],
                                   cpu=r['cpu'], original_elf=original_bytes, late_elf=late_bytes, **reader_args)
            terminal_args = (err, row['pid'], row['exit'], row['stdout_provenance_before'],
                             images, image_bytes, fact(carrier), carrier_bytes)
            terminal, case['terminal'] = reports.check(*terminal_args)
            r['terminal_reports'] = terminal
            case['terminal_controls'] = reports.supplied_controls(*terminal_args)
        parsed.append((out, row['pid']))
        case['status'] = 'passed'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expect-revision', required=True)
    args = parser.parse_args()
    need(not sys.flags.optimize and re.fullmatch('[0-9a-f]{40}', args.expect_revision) and
         len(os.sched_getaffinity(0)) == 1, 'exact revision, assertions and one reserved CPU')
    os.chdir(ROOT)
    cpu = next(iter(os.sched_getaffinity(0)))
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    stem = stamp + '-late-dso-' + args.expect_revision[:12]
    private = ROOT / 'target/evaluation/inprocess' / stem
    private.mkdir(mode=0o700)
    pins, aliases, artifacts, presence = {}, {}, {}, {}
    r = dict(schema=1, scope='two real late-load cycles under native and in-process Native policy; '
             'application live state only, no full XSAVE/publication/kernel-unmap qualification',
             status='failed', expected_revision=args.expect_revision, started_utc=stamp,
             cpu=cpu, hardware=hardware(cpu), commands=[], cases=[], namespace_aliases={},
             bounds=BOUNDS, error=None, final_errors=[])

    def pin(path):
        alias = Path(os.path.abspath(path))
        p = alias.resolve(strict=True)
        value = fact(p)
        need(str(alias) not in aliases or aliases[str(alias)] == str(p), 'stable input alias')
        need(str(p) not in pins or pins[str(p)] == value, 'stable input bytes')
        aliases[str(alias)], pins[str(p)] = str(p), value
        return p

    def binary(path):
        p = Path(path).resolve(strict=True)
        value = dict(fact(p), mode=p.stat().st_mode & 0o777)
        need(str(p) not in artifacts or artifacts[str(p)] == value, 'stable retained artifact')
        artifacts[str(p)] = value
        return p

    def stable():
        need(all(fact(p) == value for p, value in pins.items()), 'all input bytes unchanged')
        need(all(str(Path(p).resolve(strict=True)) == value for p, value in aliases.items()), 'all input aliases unchanged')
        need(all(dict(fact(p), mode=Path(p).stat().st_mode & 0o777) == value
                 for p, value in artifacts.items()), 'all artifact bytes unchanged')
        need(all(os.path.lexists(p) == value for p, value in presence.items()), 'loader configuration presence')
        need(all(Path(p).is_symlink() and os.readlink(p) == value for p, value in r['namespace_aliases'].items()),
             'sealed namespace aliases unchanged')

    def run(name, argv, profile='metadata', expected=0, env=None, record=False):
        stable()
        need(not any(c['name'] == name for c in r['commands']), 'unique command/capture name')
        row = dict(name=name, argv=list(map(str, argv)), environment=dict(ENV if env is None else env),
                   profile=profile, bounds=BOUNDS[profile], capture_limit=16 << 20, expected_exit=expected)
        r['commands'].append(row)
        try:
            out, err = (program_invoke if name in ('native', 'gated') else invoke)(row, private, cpu, record=record)
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

    builder = Build(r, private, pin, binary, build_run)
    try:
        r['source'] = source()
        need(r['source']['revision'] == args.expect_revision, 'exact clean committed source')
        git = pin(shutil.which('git', path=ENV['PATH']))
        _, names, err = run('source-paths', [git, '-C', ROOT, 'ls-files', '-z', 'tools/page-entry', 'evaluation/inprocess'])
        need(not err, 'source enumeration stderr')
        for name in names.split(b'\0'):
            if name and not name.startswith(b'evaluation/inprocess/results/'):
                pin(ROOT / os.fsdecode(name))
        for name in ('/etc/ld.so.cache', '/etc/ld.so.preload'):
            presence[name] = os.path.lexists(name)
            if presence[name]:
                pin(name)
        need(not presence['/etc/ld.so.preload'], 'no global preload')
        temporary = private / 'tmp'
        temporary.mkdir()
        _, out, err = run('namespace-controls', [pin(sys.executable), '-B', '-m', 'unittest', 'discover',
             '-s', SELECTED.parent, '-p', 'namespace*_tests.py', '-v'], profile='program',
             env=dict(ENV, TMPDIR=str(temporary)))
        need(not out and re.search(rb'\nRan 12 tests in [0-9.]+s\n\nOK\n\Z', err) is not None,
             'all five existing and seven additive namespace controls pass')
        r['namespace_controls'] = dict(status='passed', tests=12, existing=5, added=7)
        products = builder.prepare()
        for module in tuple(sys.modules.values()):
            path = getattr(module, '__file__', None)
            if path and Path(path).is_file():
                pin(path)
        cohort(builder, products, private, pin, binary, aliases, run, r)
        need(len(r['cases']) == 2 and all(c['status'] == 'passed' for c in r['cases']), 'both complete functional lanes')
        r['status'] = 'passed'
    except BaseException as error:
        r['error'] = type(error).__name__ + ': ' + str(error)
    finally:
        for p in sorted(private.rglob('*')):
            if p.is_file() and not p.is_symlink():
                try:
                    binary(p)
                except BaseException as error:
                    r['final_errors'].append('partial artifact: ' + repr(error))
        for label, fn in (('build', builder.finish), ('closure', stable)):
            try:
                errors = fn()
                if errors:
                    r['final_errors'].extend(errors)
            except BaseException as error:
                r['final_errors'].append(label + ': ' + repr(error))
        try:
            r['source_after'] = source()
            need(r['source_after'] == r.get('source'), 'committed source unchanged')
        except BaseException as error:
            r['final_errors'].append('source: ' + repr(error))
        r['inputs'], r['aliases'], r['artifacts'] = pins, aliases, artifacts
        r['source_unchanged'] = r.get('source') is not None and r.get('source_after') == r['source'] and not r['final_errors']
        r['cleanup_complete'] = all(c.get('reaped') is True and not c.get('timed_out') and
            not c.get('error') and not c.get('cleanup_errors') and all(d['closed'] for d in c.get('descriptors', []))
            for c in r['commands'])
        if r['error'] or r['final_errors'] or not r['source_unchanged'] or not r['cleanup_complete']:
            r['status'] = 'failed'
        save(private / 'receipt.json', r)
        hw = dict(r['hardware'])
        flags = hw.pop('isa_flags')
        hw.update(isa_flags_count=len(flags), isa_flags_sha256=digest(flags))
        public = {k: r.get(k) for k in ('schema', 'scope', 'status', 'expected_revision', 'started_utc',
                   'source', 'source_unchanged', 'cleanup_complete', 'bounds', 'cases', 'pair', 'namespace_controls')}
        public.update(hardware=hw, private_receipt=fact(private / 'receipt.json'),
            reproduce=['python3', '-B', 'evaluation/inprocess/page_late_dso.py', '--expect-revision', args.expect_revision],
            input_manifest_sha256=digest(pins), artifact_manifest_sha256=digest(artifacts),
            command_count=len(r['commands']), command_rows_sha256=digest(r['commands']),
            failure_type=r['error'].split(':', 1)[0] if r['error'] else None, final_error_count=len(r['final_errors']),
            full_b2_qualification=False, full_b3_qualification=False, performance_credit=False)
        text = json.dumps(public, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n'
        need(len(text) < 16384 and '/home/' not in text and platform.node() not in text,
             'compact public result without private paths/host names')
        public_path = HERE / 'results' / (stem + '.json')
        with public_path.open('x') as f:
            f.write(text)
        print(json.dumps(dict(status=r['status'], result=str(public_path.relative_to(ROOT)),
                              commands=len(r['commands']), failure_type=public['failure_type']), sort_keys=True))
    return 0 if r['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
