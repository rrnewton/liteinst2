#!/usr/bin/env python3
"""Bounded D1 HLE raw-policy and decoder components; no admission/performance credit."""
import argparse
from datetime import datetime, timezone
import hashlib, json, os, platform, re, shlex, sys, tomllib
from pathlib import Path
sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from checks import source
from run import hardware
from page_selected import ENV, elf, fact, need, save
from page_selected_generic_build import Build, PROFILES as BUILD_PROFILES
from page_selected_process import invoke
from page_selected_oneshot_build import before_default
from page_selected_register_time_build import recipe, expand
from native_policy import expected as original_expected

SELECTED = ROOT/'tools/page-entry/selected'
FIXTURE = SELECTED/'tests/native_hle_d1'
BOUNDS = dict(BUILD_PROFILES, c_compile=[5, 512 << 20, 16 << 20, 15],
              component=[30, 256 << 20, 1 << 20, 45])
FLAGS = ['-O2', '-g', '-std=gnu11', '-Wall', '-Wextra', '-Werror']
D1_COUNTS = [40960, 20590, 1082, 1147]
MODES = dict(version=1, modes=[16, 32, 64], vendor_options=2, opcode_forms=24,
             canonical=3584, lock_invalid=14336, offset_decodes=3102930, actual_hle_decodes=42)

def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()

def line(value):
    return (json.dumps(value, separators=(',', ':'))+'\n').encode()

def publish(path, r, private):
    commands = r['commands']; captures = [(c['name'], k, v) for c in commands for k, v in c.get('captures', {}).items()]
    hw = dict(r['hardware']); flags = hw.pop('isa_flags')
    hw.update(isa_flags_count=len(flags), isa_flags_sha256=digest(flags))
    value = {k: r.get(k) for k in ('schema', 'profile', 'scope', 'status', 'expected_revision', 'source',
        'started_utc', 'source_unchanged', 'cleanup_complete', 'bounds', 'reproduce', 'cases')}
    value.update(hardware=hw, private_receipt=fact(private/'receipt.json'), command_count=len(commands),
        command_rows_sha256=digest(commands), capture_count=len(captures),
        capture_bytes=sum(v['bytes'] for _, _, v in captures), capture_manifest_sha256=digest(captures),
        command_outcomes=dict(exited_zero=sum(c.get('exit') == 0 for c in commands),
            reaped=sum(c.get('reaped') is True for c in commands),
            timeouts=sum(c.get('timed_out') is True for c in commands),
            cleanup_errors=sum(len(c.get('cleanup_errors', [])) for c in commands)),
        failed_commands=[{k: c.get(k) for k in ('name', 'profile', 'expected_exit', 'exit', 'duration_ns', 'timed_out', 'reaped')}
            for c in commands if c.get('exit') != 0 or c.get('error') or c.get('cleanup_errors') or c.get('timed_out') or not c.get('reaped')],
        build_status=r.get('build', {}).get('status'), component_build_status=r.get('component_build_status'),
        configuration_unchanged=r.get('build', {}).get('configuration_unchanged', False),
        numeric_versions=r.get('build', {}).get('numeric_versions'),
        tool_facts={k: {z: v[z] for z in ('bytes', 'sha256')} for k, v in r.get('build', {}).get('tools', {}).items()},
        input_manifest_sha256=digest(r['inputs_before']), alias_manifest_sha256=digest(r['aliases_before']),
        artifact_manifest_sha256=digest(r['artifacts_before']), component_build_sha256=digest(r.get('component_build', {})),
        failure_type=r['error'].split(':', 1)[0] if r.get('error') else None, final_error_count=len(r['final_errors']),
        runtime_admission_credit=False, hardware_16_32_mode_credit=False, application_performance_credit=False,
        recipe=dict(source='tools/page-entry/selected/tests/native_hle_d1/build.sh', cargo_target='target',
            components=['hle-d1-policy', 'hle-d1-modes'], old_raw_population='complete first policy output line',
            followup='six BMI1 cohorts, complete 6/49/17 prerequisites, registered-native 16+4, unchanged 20-subject performance'))
    text = json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)+'\n'
    need(len(text.encode()) < 8192 and not any(x and len(x) > 1 and x in text for x in
        (str(ROOT), str(Path.home()), platform.node(), '/home/')), 'compact public receipt without private paths')
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('x') as stream: stream.write(text)


def main():
    ap = argparse.ArgumentParser(description=__doc__); ap.add_argument('--expect-revision', required=True); args = ap.parse_args()
    need(not sys.flags.optimize and re.fullmatch('[0-9a-f]{40}', args.expect_revision) and len(os.sched_getaffinity(0)) == 1,
         'exact revision, enabled assertions and one externally reserved CPU')
    os.chdir(ROOT); cpu = next(iter(os.sched_getaffinity(0))); stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    stem = stamp+'-page-native-hle-d1-'+args.expect_revision[:12]
    private = ROOT/'target/evaluation/inprocess'/stem; private.mkdir(parents=True, mode=0o700)
    public = HERE/'results'/(stem+'.json'); need(not public.exists(), 'unique public receipt')
    r = dict(schema=1, profile='page-native-hle-d1-v1', status='failed', expected_revision=args.expect_revision,
        scope='Complete original raw policy population plus D1 all-ModRM/prefix/boundary policy checks and iced decode/metadata corroboration. No runtime admission, processor-mode or application/performance qualification.',
        source=None, source_unchanged=False, hardware=hardware(cpu), started_utc=stamp, bounds=BOUNDS,
        commands=[], cases=[dict(name=n, status='unexecuted', actual_exit=None) for n in ('policy', 'modes')],
        component_build_status='not_started', error=None, final_errors=[],
        reproduce=['python3', 'evaluation/inprocess/page_native_hle_d1.py', '--expect-revision', args.expect_revision])
    pins, aliases, artifacts, presence = {}, {}, {}, {}
    commands = r['commands']
    def pin(path, want=None):
        alias = Path(os.path.abspath(path)); p = alias.resolve(strict=True); value = fact(p)
        need(want is None or value == {k: want[k] for k in ('bytes', 'sha256')}, 'exact requested input bytes')
        need(str(alias) not in aliases or aliases[str(alias)] == str(p), 'input alias changed')
        need(str(p) not in pins or pins[str(p)] == value, 'input bytes changed')
        aliases[str(alias)] = str(p); pins[str(p)] = value; return p
    def binary(path):
        p = Path(path).resolve(strict=True); value = dict(fact(p), mode=p.stat().st_mode & 0o777)
        need(str(p) not in artifacts or artifacts[str(p)] == value, 'retained artifact changed')
        artifacts[str(p)] = value; return p
    def stable():
        need(all(Path(p).resolve(strict=True) == Path(v) for p, v in aliases.items()), 'all lexical input aliases unchanged')
        need(all(fact(p) == v for p, v in pins.items()), 'all input bytes unchanged')
        need(all(dict(fact(p), mode=Path(p).stat().st_mode & 0o777) == v for p, v in artifacts.items()), 'all artifact bytes/modes unchanged')
        need(all(os.path.lexists(p) == v for p, v in presence.items()), 'loader configuration presence unchanged')
    def run(name, argv, profile='metadata', expected=0, env=None):
        stable(); need(not any(x['name'] == name for x in commands), 'unique command/capture names')
        row = dict(name=name, argv=list(map(str, argv)), profile=profile, bounds=BOUNDS[profile],
            capture_limit=(1 << 20) if profile == 'component' else (16 << 20),
            environment=dict(ENV if env is None else env), expected_exit=expected); commands.append(row)
        try:
            out, err = invoke(row, private, cpu)
            need(type(row['exit']) is int and row['exit'] == expected, 'actual command exit '+name)
            return row, out, err
        finally:
            for stream in ('stdout', 'stderr'):
                path = private/(name+'.'+stream)
                try:
                    observed = row.get('captures', {}).get(stream)
                    if path.exists() or path.is_symlink():
                        actual = fact(binary(path))
                        if observed is not None: need(observed['file'] == path.name and actual == {k: observed[k] for k in ('bytes', 'sha256')}, 'actual command capture binding')
                    else: need(observed is None, 'retained command capture missing')
                except BaseException as error: r['final_errors'].append('capture '+name+'.'+stream+': '+type(error).__name__+': '+str(error))
            path = private/(name+'.json')
            try:
                if path.exists() or path.is_symlink(): binary(path); need(digest(json.loads(path.read_bytes())) == digest(row), 'actual retained command row')
            except BaseException as error: r['final_errors'].append('command row '+name+': '+type(error).__name__+': '+str(error))
    def build_run(name, argv, profile='metadata', env=None, expected=0):
        before_default(name, argv, builder, pin, aliases, run, r)
        return run(name, argv, profile=profile, env=env, expected=expected)
    builder = Build(r, private, pin, binary, build_run)
    output = private/'components'; output.mkdir()
    try:
        r['source'] = source(); need(r['source']['revision'] == args.expect_revision, 'exact clean committed source')
        git = pin('/usr/bin/git')
        _, out, err = run('source-paths', [git, '-C', ROOT, 'ls-files', '-z', 'tools/page-entry', 'evaluation/inprocess'])
        need(not err, 'source enumeration stderr')
        for name in out.split(b'\0'):
            if name and not name.startswith(b'evaluation/inprocess/results/'): pin(ROOT/os.fsdecode(name))
        for module in tuple(sys.modules.values()):
            path = getattr(module, '__file__', None)
            if path and Path(path).resolve().is_relative_to(ROOT) and Path(path).suffix == '.py': pin(path)
        for name in ('/etc/ld.so.cache', '/etc/ld.so.preload'):
            presence[name] = os.path.lexists(name)
            if presence[name]: pin(name)
        need(not presence['/etc/ld.so.preload'], 'no global preload')
        builder.prepare()
        r['component_build_status'] = 'started'
        state = r['component_build'] = dict(recipe=fact(pin(FIXTURE/'build.sh')), headers={}, metadata=None, outputs={})
        cc_rows = recipe(FIXTURE/'build.sh', '"$cc_bin"'); cargo_rows = recipe(FIXTURE/'build.sh', '"$cargo_bin"')
        rel = 'tools/page-entry/selected/tests/native_hle_d1/'
        need(cc_rows == [['$cc_bin', *FLAGS, '-Itools/page-entry/selected', rel+'probe.c',
                         'tools/page-entry/selected/native_policy.c', '-o', '$out/hle-d1-policy']] and
             cargo_rows == [['$cargo_bin', 'build', '--offline', '--locked', '--release', '--manifest-path',
                             rel+'Cargo.toml', '--target-dir', '$root/target']] and
             recipe(FIXTURE/'build.sh', 'cp ') == [['cp', '$root/target/release/hle-d1-modes', '$out/hle-d1-modes'],
                 ['cp', '$root/target/release/hle-d1-modes.d', '$out/hle-d1-modes.d']], 'exact two compile commands and immediate shared-target copies')
        units = [FIXTURE/'probe.c', SELECTED/'native_policy.c']; flags = [*FLAGS, '-I'+str(SELECTED)]
        for i, unit in enumerate(units):
            _, out, err = run('policy-headers-'+str(i), [builder.tools['cc'], *flags, '-M', '-MT', 'hle_d1', unit], env=builder.environment)
            rules = out.decode().replace('\\\n', ' ').splitlines()
            need(not err and len(rules) == 1 and rules[0].startswith('hle_d1: '), 'one complete C include rule')
            found = {str(pin(p)): fact(p) for p in shlex.split(rules[0].split(':', 1)[1])}
            need(str(unit) in found, 'actual C translation unit in include closure'); state['headers'][str(unit)] = found
        run('policy-link', [builder.tools['cc'], *flags, *units, '-o', output/'hle-d1-policy'], profile='c_compile', env=builder.environment)
        paths = {'policy': binary(output/'hle-d1-policy')}
        _, out, err = run('modes-metadata', [builder.tools['cargo'], 'metadata', '--manifest-path', FIXTURE/'Cargo.toml',
                                          '--format-version', '1', '--locked', '--offline'], env=builder.environment)
        need(not err, 'mode metadata stderr'); metadata = json.loads(out); state['metadata'] = metadata
        need(Path(metadata['target_directory']).resolve() == ROOT/'target', 'same single repository Cargo target')
        locked = tomllib.loads(pin(FIXTURE/'Cargo.lock').read_text())['package']
        expected = {(p['name'], p['version']): p for p in locked}
        need(len(expected) == len(locked) == 3 and {(p['name'], p['version']) for p in metadata['packages']} == set(expected), 'exact separate mode package closure')
        authenticated = {(p['name'], p['version'], p['checksum']): p for p in builder.packages}
        ids = {}
        for package in metadata['packages']:
            lock = expected[(package['name'], package['version'])]; manifest = pin(package['manifest_path']); ids[package['id']] = package['name']
            if 'checksum' in lock:
                key = (package['name'], package['version'], lock['checksum'])
                need(key in authenticated and manifest.parent == Path(authenticated[key]['root']) and package['source'] == lock['source'], 'same fully authenticated locked registry source')
            else:
                need(package['name'] == 'li2-native-hle-d1-modes' and package['version'] == '0.0.0' and package['source'] is None and manifest == FIXTURE/'Cargo.toml', 'exact local modes crate')
                targets = package['targets']; need(len(targets) == 1 and targets[0]['name'] == 'hle-d1-modes' and targets[0]['kind'] == ['bin'] and Path(targets[0]['src_path']) == FIXTURE/'modes.rs', 'exact mode entry source')
        nodes = metadata['resolve']['nodes']; need(len(nodes) == 3 and {ids[n['id']] for n in nodes} == set(ids.values()), 'complete resolved mode nodes')
        features = {ids[n['id']]: sorted(n['features']) for n in nodes}
        need(features == {'li2-native-hle-d1-modes': [], 'iced-x86': ['decoder', 'encoder', 'lazy_static', 'op_code_info', 'std'], 'lazy_static': []}, 'closed mode decoder/opcode feature composition')
        values = {'$cargo_bin': builder.tools['cargo'], '$root': ROOT}; argv = expand(cargo_rows[0], values)
        argv[argv.index('--manifest-path')+1] = str(FIXTURE/'Cargo.toml')
        run('modes-build', argv, profile='build', env=builder.environment)
        paths['modes'] = builder.retain('hle-d1-modes', ROOT/'target/release/hle-d1-modes')
        dep = builder.retain('hle-d1-modes.d', ROOT/'target/release/hle-d1-modes.d')
        text = dep.read_text().strip(); prefix = str(ROOT/'target/release/hle-d1-modes')+': '
        need(text.startswith(prefix) and '\n' not in text and shlex.split(text[len(prefix):]) == [str(FIXTURE/'modes.rs')], 'exact emitted mode binary dep-info source')
        state['mode_dep_info'] = dict(artifact=fact(dep), source=fact(pin(FIXTURE/'modes.rs')))
        for name, path in paths.items():
            need(path.stat().st_mode & 0o111, 'actual component executable mode')
            _, _, err = run(name+'-elf', [builder.tools['readelf'], '-h', '-l', '-d', '-r', '-W', path], profile='inspect', env=builder.environment)
            need(not err, 'actual component ELF stderr'); data, header, ph = elf(path)
            need(header[1] in (2, 3) and all(not (p[0] == 1 and p[1] & 3 == 3) for p in ph), 'executable without writable executable LOAD')
            rows = [p for p in ph if p[0] == 3]; need(len(rows) == 1, 'one component interpreter')
            p = rows[0]; raw = data[p[2]:p[2]+p[5]]
            need(raw.startswith(b'/') and raw.endswith(b'\0') and b'\0' not in raw[:-1], 'actual interpreter path')
            loader = pin(os.fsdecode(raw[:-1])); _, out, err = run(name+'-libraries', [loader, '--list', path])
            need(not err, 'actual component loader listing stderr'); libraries = {}; vdso = 0
            for text in out.decode().splitlines():
                if re.fullmatch(r'\s*linux-vdso\.so\.1 \(0x[0-9a-f]+\)', text): vdso += 1; continue
                match = re.fullmatch(r'\s*(?:(\S+) => )?(/\S+) \(0x[0-9a-f]+\)', text); need(match is not None, 'complete actual loader row')
                key = match[1] or 'interpreter'
                if match[1] and match[1].startswith('/'):
                    need(pin(match[1]) == pin(match[2]) == loader, 'actual interpreter aliases'); key = 'interpreter'
                need(key not in libraries, 'unique actual dependency'); libraries[key] = dict(path=str(pin(match[2])), **fact(match[2]))
            allowed = {'libc.so.6', 'interpreter'} if name == 'policy' else {'libc.so.6', 'libgcc_s.so.1', 'libm.so.6', 'interpreter'}
            need(vdso == 1 and {'libc.so.6', 'interpreter'} <= set(libraries) <= allowed and libraries['interpreter']['path'] == str(loader), 'closed actual component system dependencies')
            state['outputs'][name] = dict(artifact=fact(path), elf_type=header[1], libraries=libraries)
        _, out, err = run('policy-symbols', [builder.tools['nm'], '-S', '--defined-only', paths['policy']], profile='inspect', env=builder.environment)
        need(not err, 'policy symbols stderr')
        for symbol in ('main', 'li2_native_policy', 'legacy_policy_main'):
            found = [x.split() for x in out.decode().splitlines() if x.split()[-1:] == [symbol]]
            need(len(found) == 1 and len(found[0]) == 4 and found[0][2] == 'T' and int(found[0][1], 16) > 0, 'actual linked '+symbol)
        r['component_build_status'] = 'passed'
        expected_outputs = {'policy': line(original_expected())+line(dict(version=1, d1_checks=D1_COUNTS)), 'modes': line(MODES)}
        for case in r['cases']:
            name = case['name']; case['status'] = 'failed'; case['artifact'] = fact(paths[name])
            try: row, out, err = run(name, [paths[name]], profile='component')
            finally:
                rows = [c for c in commands if c['name'] == name]
                if rows: case.update(actual_exit=rows[0].get('exit'), reaped=rows[0].get('reaped'), timed_out=rows[0].get('timed_out'))
            need(not err and out == expected_outputs[name], 'complete exact '+name+' output')
            case.update(status='passed', output=fact(private/(name+'.stdout')),
                result=[original_expected(), dict(version=1, d1_checks=D1_COUNTS)] if name == 'policy' else MODES)
        need(all(c['status'] == 'passed' for c in r['cases']) and not r['final_errors'], 'both complete component populations')
        r['status'] = 'passed'
    except BaseException as error: r['error'] = type(error).__name__+': '+str(error)
    finally:
        try: r['final_errors'].extend(builder.finish())
        except BaseException as error: r['final_errors'].append('build finalization: '+type(error).__name__+': '+str(error))
        for p in sorted(private.rglob('*')):
            if p.is_file() and not p.is_symlink():
                try: binary(p)
                except BaseException as error: r['final_errors'].append('retain '+str(p)+': '+type(error).__name__+': '+str(error))
        r['inputs_before'] = dict(pins); r['aliases_before'] = dict(aliases); r['artifacts_before'] = dict(artifacts)
        try: stable()
        except BaseException as error: r['final_errors'].append('closure: '+type(error).__name__+': '+str(error))
        try: r['source_after'] = source(); need(r['source_after'] == r['source'], 'exact committed source unchanged')
        except BaseException as error: r['final_errors'].append('source: '+type(error).__name__+': '+str(error))
        r['inputs_after'] = {}; r['artifacts_after'] = {}; r['aliases_after'] = {}
        for table, observed, fn in (('inputs_after', pins, fact), ('artifacts_after', artifacts, lambda p: dict(fact(p), mode=Path(p).stat().st_mode & 0o777)),
                                   ('aliases_after', aliases, lambda p: str(Path(p).resolve(strict=True)))):
            for p in observed:
                try: r[table][p] = fn(p)
                except BaseException as error: r['final_errors'].append(table+' '+p+': '+type(error).__name__)
        r['source_unchanged'] = r['source'] is not None and r.get('source_after') == r['source'] and r['inputs_before'] == r['inputs_after'] and r['aliases_before'] == r['aliases_after']
        r['cleanup_complete'] = all(type(c.get('exit')) is int and c.get('reaped') is True and
            c.get('timed_out') is False and not c.get('error') and c.get('cleanup_errors') == [] and
            all(d['closed'] for d in c.get('descriptors', [])) for c in commands)
        if r['error'] or r['final_errors'] or not r['source_unchanged'] or r['artifacts_before'] != r['artifacts_after'] or not r['cleanup_complete']: r['status'] = 'failed'
        save(private/'receipt.json', r)
        try: publish(public, r, private)
        except BaseException as error:
            r['final_errors'].append('projection: '+type(error).__name__+': '+str(error)); r['status'] = 'failed'; save(private/'receipt.json', r)
    print(json.dumps(dict(status=r['status'], receipt=str((private/'receipt.json').relative_to(ROOT)), public=str(public.relative_to(ROOT)), commands=len(commands))))
    return int(r['status'] != 'passed')

if __name__ == '__main__': raise SystemExit(main())
