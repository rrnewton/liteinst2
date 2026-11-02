#!/usr/bin/env python3
"""One bounded seven-chunk CALL/PUSH native diagnostic; no qualification."""
import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import stat
import struct
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = next(p for p in HERE.parents if (p/'evaluation/inprocess/page_selected_process.py').is_file())
BOUNDS = {'build': [30, 512 << 20, 16 << 20, 60], 'native': [5, 512 << 20, 16 << 20, 15]}


def need(ok, message):
    if not ok:
        raise ValueError(message)


def fact(path):
    path = Path(path)
    need(path.is_file() and not path.is_symlink(), 'regular whole file: '+str(path))
    data = path.read_bytes()
    return {'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest(),
            'mode': format(stat.S_IMODE(path.stat().st_mode), '04o')}


def unique(pairs):
    result = dict(pairs)
    need(len(result) == len(pairs), 'no duplicate JSON fields')
    return result


def load(path):
    return json.loads(Path(path).read_bytes(), object_pairs_hook=unique)


def dynamic(path):
    """Read actual ELF strings for dependency-closure joins; no loading."""
    b = Path(path).read_bytes()
    need(b[:7] == b'\x7fELF\2\1\1' and struct.unpack_from('<H', b, 18)[0] == 62, 'actual ELF64')
    off = struct.unpack_from('<Q', b, 32)[0]
    size, count = struct.unpack_from('<HH', b, 54)
    need(size == 56 and 0 < count <= 64 and off+size*count <= len(b), 'bounded ELF headers')
    rows = [struct.unpack_from('<IIQQQQQQ', b, off+i*size) for i in range(count)]
    tables = [p for p in rows if p[0] == 2]
    need(len(tables) == 1, 'one actual dynamic table')
    p = tables[0]
    need(p[5] % 16 == 0 and p[2]+p[5] <= len(b), 'whole dynamic table')
    tags = []
    for offset in range(p[2], p[2]+p[5], 16):
        tag, value = struct.unpack_from('<QQ', b, offset)
        if not tag:
            break
        tags.append((tag, value))
    else:
        raise ValueError('terminated dynamic table')
    def one(tag):
        values = [v for t, v in tags if t == tag]
        need(len(values) == 1, 'one string-table field')
        return values[0]
    address, length = one(5), one(10)
    segments = [p for p in rows if p[0] == 1 and p[3] <= address and address+length <= p[3]+p[5]]
    need(len(segments) == 1, 'whole LOAD-owned dynamic strings')
    p = segments[0]
    offset = p[2]+address-p[3]
    strings = b[offset:offset+length]
    need(len(strings) == length, 'whole dynamic strings')
    def name(value):
        need(value < len(strings) and b'\0' in strings[value:], 'bounded dynamic name')
        return strings[value:strings.index(b'\0', value)].decode('ascii')
    needed = [name(v) for t, v in tags if t == 1]
    sonames = [name(v) for t, v in tags if t == 14]
    need(len(sonames) <= 1 and len(set(needed)) == len(needed), 'unambiguous dynamic dependencies')
    need(not any(t in (15, 29, 0x7FFFFFFD, 0x7FFFFFFF, 0x6FFFFEFC, 0x6FFFFEFB) for t, v in tags),
         'no search/filter/audit overrides')
    return {'needed': needed, 'soname': sonames[0] if sonames else None}


def compact(observation):
    need(observation['status'] == 'observed_unqualified' and observation['matrix_pairs'] == 217 and
         observation['native_lanes'] == 434 and observation['call_push_equivalence'] is None and
         all(observation[k] is False for k in ('production_admission_credit', 'owner_credit',
                                              'qualification_credit', 'performance_credit')),
         'observation-only reader result')
    pairs = observation['pairs']
    need(len(pairs) == 217 and [p['id'] for p in pairs] == list(range(217)), 'all ordered pairs')
    groups = []
    for group, count in enumerate((16, 128, 16, 35, 16, 6)):
        rows = [p for p in pairs if p['call']['group'] == group]
        need(len(rows) == count and all(p['push']['group'] == group for p in rows), 'complete fixed group')
        result = {'group': group, 'pairs': count,
                  'after_greg_difference_pairs': sum(bool(p['after_greg_differences']) for p in rows)}
        for key in ('call', 'push'):
            lanes = [p[key] for p in rows]
            result[key] = {
                'signals': dict(sorted(Counter(str(p['signal'])+':'+str(p['si_code']) for p in lanes).items())),
                'stack_changed_bytes_distribution': dict(sorted(Counter(str(p['stack_changed_bytes']) for p in lanes).items())),
                'fp_storage_changed': sum(not p['fp_storage_unchanged'] for p in lanes),
                'fs_gs_changed': sum(not p['fs_gs_unchanged'] for p in lanes)}
        groups.append(result)
    return {'status': 'observed_unqualified', 'matrix_pairs': 217, 'native_lanes': 434,
            'groups': groups, 'call_push_equivalence': None,
            'production_admission_credit': False, 'owner_credit': False,
            'qualification_credit': False, 'performance_credit': False,
            'scope': 'Complete actual native observations; differences are not general equivalence or production admission.'}


def main():
    sys.path.insert(0,str(ROOT/'evaluation/inprocess'))
    from page_selected_maps_sources import historical, bind as bind_maps_sources
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expect-revision', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    manifest = load(HERE/'SOURCE.json')
    need(sys.version_info >= (3, 11) and not sys.flags.optimize and len(os.sched_getaffinity(0)) == 1,
         'pinned Python3.11+, assertions and exactly one independently reserved CPU')
    need(re.fullmatch(r'[0-9a-f]{40}', args.expect_revision) is not None,
         'explicit complete source revision; all pinned inputs remain mandatory')
    for name, wanted in manifest['artifacts'].items():
        need(historical(HERE/name,wanted,fact(HERE/name)) == wanted, 'frozen collector file: '+name)
    for name, wanted in manifest['inputs'].items():
        need(historical(ROOT/name,wanted,fact(ROOT/name)) == wanted, 'frozen whole input: '+name)
    private = args.output.resolve()
    need(private.is_relative_to((ROOT/'target/evaluation/inprocess').resolve(strict=True)) and not private.exists(),
         'fresh private attempt')
    cpu = next(iter(os.sched_getaffinity(0)))
    sys.path.insert(0, str(ROOT/'evaluation/inprocess'))
    from checks import source
    from run import hardware
    from page_selected import ENV, save
    from page_selected_process import invoke
    os.chdir(ROOT)
    private.mkdir()
    receipt = private/'receipt.json'
    pins, aliases, artifacts, presence = {}, {}, {}, {}
    r = dict(schema=1, profile='call-push-native-diagnostic-v1', status='failed',
             revision=args.expect_revision, cpu=cpu, hardware=hardware(cpu), source=None,
             bounds=BOUNDS, commands=[], result=None, error=None, final_errors=[],
             source_unchanged=False, inputs_unchanged=False, cleanup_complete=False,
             call_push_equivalence=None, production_admission_credit=False, owner_credit=False,
             qualification_credit=False, performance_credit=False)

    def pin(path):
        need(path is not None, 'required input path')
        alias = Path(path).absolute()
        resolved = alias.resolve(strict=True)
        value = fact(resolved)
        need(str(alias) not in aliases or aliases[str(alias)] == str(resolved), 'stable input alias')
        need(str(resolved) not in pins or pins[str(resolved)] == value, 'stable complete input')
        aliases[str(alias)], pins[str(resolved)] = str(resolved), value
        return resolved

    def artifact(path):
        path = Path(path)
        need(path.is_relative_to(private), 'artifact stays in this attempt')
        value = fact(path)
        need(str(path) not in artifacts or artifacts[str(path)] == value, 'stable whole artifact')
        artifacts[str(path)] = value

    def closure():
        need(all(fact(p) == f for p, f in pins.items()), 'whole inputs unchanged')
        need(all(str(Path(p).resolve(strict=True)) == v for p, v in aliases.items()), 'aliases unchanged')
        need(all(fact(p) == f for p, f in artifacts.items()), 'whole artifacts unchanged')
        need(all(Path(p).exists() == v for p, v in presence.items()), 'loader configuration presence')
        need(sorted(os.sched_getaffinity(0)) == [cpu], 'same reserved CPU')

    def run(name, argv, profile='build'):
        closure()
        need(not any(c['name'] == name for c in r['commands']), 'unique command; no retry')
        row = dict(name=name, argv=list(map(str, argv)), bounds=BOUNDS[profile],
                   capture_limit=16 << 20, environment=dict(ENV), expected_exit=0)
        r['commands'].append(row)
        save(receipt, r)
        try:
            out, err = invoke(row, private, cpu)
        finally:
            for stream, f in row.get('captures', {}).items():
                path = private/f['file']
                need({k: fact(path)[k] for k in ('bytes', 'sha256')} ==
                     {k: f[k] for k in ('bytes', 'sha256')}, 'post-reap complete capture')
                artifact(path)
            path = private/(name+'.json')
            if path.is_file():
                artifact(path)
            save(receipt, r)
        need(row['exit'] == 0, 'exact command exit: '+name)
        return out, err

    output = private/'call-push-native-probe'
    try:
        r['source'] = source()
        need(r['source']['revision'] == args.expect_revision, 'exact current clean source')
        bind_maps_sources(pin)
        for name in ('SOURCE.json', *manifest['artifacts']):
            pin(HERE/name)
        for name in manifest['inputs']:
            pin(ROOT/name)
        for module in tuple(sys.modules.values()):
            name = getattr(module, '__file__', None)
            if name and Path(name).resolve().is_relative_to(ROOT):
                pin(name)
        python = pin(sys.executable)
        r['collector_python'] = str(python)
        fixture = (ROOT/manifest['fixture']).resolve(strict=True)
        probe = manifest
        need(probe['matrix']['pairs'] == 217 and probe['matrix']['native_lanes'] == 434 and
             probe['matrix']['chunks'] == [32, 32, 32, 32, 32, 32, 25] and
             probe['raw']['record'] == 175544 and probe['call_push_equivalence'] is None,
             'whole frozen diagnostic population')
        tools = {'cc': pin(shutil.which('cc', path=ENV['PATH']))}
        for name in ('/etc/ld.so.cache', '/etc/ld.so.preload'):
            presence[name] = Path(name).exists()
            if presence[name]:
                pin(name)
        need(not presence['/etc/ld.so.preload'], 'no global preload')
        for name in ('cc1', 'collect2', 'as', 'ld'):
            out, err = run('resolve-'+name, [tools['cc'], '-print-prog-name='+name])
            value = out.decode().strip()
            need(value and not err, 'actual compiler subtool')
            tools[name] = pin(value if Path(value).is_absolute() else shutil.which(value, path=ENV['PATH']))
        for name in ('cc', 'as', 'ld'):
            out, err = run('version-'+name, [tools[name], '--version'])
            need(out and not err, 'actual tool version')
        for name in ('crt1.o', 'Scrt1.o', 'crti.o', 'crtn.o', 'crtbegin.o', 'crtbeginS.o',
                     'crtend.o', 'crtendS.o', 'libgcc.a', 'libgcc_s.so', 'libc.so',
                     'libc_nonshared.a', 'libc.so.6', 'libgcc_s.so.1'):
            out, err = run('link-input-'+name, [tools['cc'], '-print-file-name='+name])
            value = out.decode().strip()
            need(not err and Path(value).is_absolute(), 'actual selected link input')
            pin(value)
        _, err = run('compiler-specs', [tools['cc'], '-dumpspecs'])
        need(not err, 'whole compiler specs')
        r['tools'] = {k: str(v) for k, v in tools.items()}
        recipe = (fixture/'build.sh').read_text().replace('\\\n', ' ')
        lines = [line.strip() for line in recipe.splitlines() if line.strip().startswith('"$cc" ')]
        need(len(lines) == 1, 'one closed literal build recipe')
        substitutions = {'$cc': tools['cc'], '$source_dir': fixture, '$output': output}
        argv = []
        for word in shlex.split(lines[0]):
            for key, value in substitutions.items():
                word = word.replace(key, str(value))
            need('$' not in word and '`' not in word, 'literal compiler argv')
            argv.append(word)
        sources = [str(fixture/'probe.c'), str(fixture/'probe.S')]
        need([x for x in argv if x.endswith(('.c', '.S'))] == sources and
             argv[-2:] == ['-o', str(output)] and '-Werror' in argv and '-no-pie' in argv,
             'exact two-source strict recipe')
        r['recipe'] = {'file': fact(fixture/'build.sh'), 'argv': argv}
        flags = [x for x in argv[1:-2] if x not in sources and not x.startswith('-Wl,')]
        all_headers = set()
        for index, source_path in enumerate(sources):
            out, err = run('headers-'+str(index), [tools['cc'], *flags, '-M', '-MT', 'probe', source_path])
            rule = out.decode().replace('\\\n', ' ')
            need(not err and len(rule.splitlines()) == 1 and rule.startswith('probe: '), 'whole actual compiler-M rule')
            actual = {str(pin(x)) for x in shlex.split(rule.split(':', 1)[1])}
            need(str(Path(source_path).resolve()) in actual, 'actual source included')
            all_headers |= actual
        r['headers'] = sorted(all_headers)
        out, err = run('build', argv)
        need(not out and not err, 'strict compiler captures empty')
        artifact(output)
        need(int(fact(output)['mode'], 8) & 0o111, 'fresh executable')
        out, err = run('emitted-inspection', [python, '-I', '-S', '-B', HERE/'inspect.py', output], 'native')
        need(not err, 'emitted inspection stderr empty')
        inspected = json.loads(out, object_pairs_hook=unique)
        need(inspected['status'] == 'source_bytes_inspected' and
             inspected['elf_sha256'] == fact(output)['sha256'] and inspected['native_execution'] is False and
             inspected['qualification_credit'] is False, 'whole emitted code inspected before subjects')
        r['emitted_inspection'] = inspected
        interpreter = pin(inspected['interpreter'])
        out, err = run('runtime-dependencies', [interpreter, '--list', output])
        need(not err, 'actual loader dependency inspection')
        objects = {str(output): dynamic(output)}
        for line in out.decode().splitlines():
            if line.strip().startswith('linux-vdso.so.'):
                continue
            match = re.fullmatch(r'\s*(?:(\S+) => )?(/\S+) \(0x[0-9a-f]+\)', line)
            need(match is not None, 'complete actual loader dependency line')
            resolved = pin(match.group(2))
            value = dynamic(resolved)
            requested = match.group(1)
            if requested is not None and requested.startswith('/'):
                need(requested == inspected['interpreter'] and pin(requested) == resolved == interpreter,
                     'exact actual PT_INTERP alias join')
            else:
                need(requested is None or value['soname'] == requested, 'actual SONAME dependency join')
            objects[str(resolved)] = value
        need(str(interpreter) in objects, 'actual interpreter in loader closure')
        sonames = [v['soname'] for v in objects.values() if v['soname'] is not None]
        need(len(sonames) == len(set(sonames)) and
             all(name in sonames for v in objects.values() for name in v['needed']), 'closed exact DT_NEEDED roster')
        r['runtime_objects'] = objects
        chunks = []
        chunk_rows = []
        for chunk in range(7):
            name = 'native-'+str(chunk)
            out, err = run(name, [output, str(chunk)], 'native')
            row = r['commands'][-1]
            need(not err and len(out) >= 256, 'whole native diagnostic capture')
            h = struct.unpack_from('<32Q', out)
            count = min(32, 217-32*chunk)
            need(h[:4] == (0x315242504332494C, 1, 256, 175544) and
                 h[10:17] == (217, chunk, 32*chunk, count, 2*count, row['pid'], cpu) and
                 h[28:30] == (inspected['reload_address'], inspected['scratch_end_address']),
                 'actual collector PID/CPU/ELF-bootstrap and fixed chunk joins')
            chunks.append(private/row['captures']['stdout']['file'])
            chunk_rows.append({'chunk': chunk, 'pid': row['pid'], 'cpu': cpu,
                               'duration_ns': row['duration_ns'], 'capture': row['captures']['stdout']})
        r['native_chunks'] = chunk_rows
        out, err = run('read-all-chunks', [python, '-I', '-S', '-B', fixture/'read.py',
                                        '--expect-cpu', str(cpu), *chunks], 'native')
        need(not err, 'whole independent reader stderr empty')
        observed = json.loads(out, object_pairs_hook=unique)
        need(observed['cpu'] == cpu and len(observed['sources']) == 7, 'complete reader source roster')
        for source_row, child in zip(observed['sources'], chunk_rows):
            need(source_row == {'chunk': child['chunk'], 'pid': child['pid'],
                                'bytes': child['capture']['bytes'], 'sha256': child['capture']['sha256']},
                 'whole reader inputs join actual child captures and PID')
        r['result'] = compact(observed)
        r['result']['raw_sources'] = observed['sources']
        r['status'] = 'observed_unqualified'
    except BaseException as error:
        r['error'] = type(error).__name__+': '+str(error)
    finally:
        try:
            if output.exists():
                artifact(output)
        except BaseException as error:
            r['final_errors'].append('partial-artifact: '+type(error).__name__+': '+str(error))
        try:
            closure()
            r['inputs_unchanged'] = True
        except BaseException as error:
            r['final_errors'].append('input-closure: '+type(error).__name__+': '+str(error))
        try:
            need(source() == r['source'], 'whole current source closure')
            r['source_unchanged'] = True
        except BaseException as error:
            r['final_errors'].append('source-closure: '+type(error).__name__+': '+str(error))
        r['cleanup_complete'] = all(c.get('reaped') and not c.get('cleanup_errors') and
             all(d['closed'] for d in c.get('descriptors', [])) for c in r['commands'])
        if r['error'] or r['final_errors'] or not all(r[k] for k in
                ('source_unchanged', 'inputs_unchanged', 'cleanup_complete')):
            r['status'] = 'failed'
            r['result'] = None
        r.update(inputs=pins, aliases=aliases, artifacts=artifacts, loader_presence=presence)
        save(receipt, r)
    print(json.dumps({'status': r['status'], 'receipt': str(receipt), 'error': r['error'],
                      'qualification_credit': False, 'performance_credit': False}, sort_keys=True))
    return 0 if r['status'] == 'observed_unqualified' else 1


if __name__ == '__main__':
    raise SystemExit(main())
