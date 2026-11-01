#!/usr/bin/env python3
"""Run the bounded-block planner and byte model; no emitted-code or owner execution."""
import argparse
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
ROOT = Path(__file__).resolve().parents[3]
SELECTED = ROOT/'tools/page-entry/selected'
BOUNDS = {'build': [30, 512 << 20, 16 << 20, 60],
          'component': [5, 512 << 20, 16 << 20, 15]}
LINK_NAMES = ('crt1.o Scrt1.o crti.o crtn.o crtbegin.o crtbeginS.o crtend.o crtendS.o '
              'libgcc.a libgcc_eh.a libgcc_s.so libgcc_s.so.1 libc.so libc_nonshared.a '
              'libc.so.6 libdl.a libpthread.a libm.so libm.so.6 libmvec.so.1').split()
CASES = {
    'bounded_block_plan': {
        'recipe_sha256': '1d4f2c1c3458d355766b7831ac635d91f119175049ef7d21292fd9bb5e9c50eb',
        'units': ['tests/bounded_block_plan/oracle.c', 'tests/persistent_direct_frontier/model.c',
                  'persistent_group_plan.c', 'persistent_group_compact.c',
                  'linked_direct_dispatch.c', 'linked_jmp_dispatch.c', 'linked_mov_guard.c',
                  'tests/decoder/support.c'],
        'headers': ['persistent_block_plan.h', 'persistent_block_plan.inc', 'persistent_block_compact.inc',
                    'persistent_group_plan.h', 'persistent_group_compact.h',
                    'tests/persistent_direct_frontier/model.h'],
    },
}


def need(ok, message):
    if not ok:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def fact(path):
    path = Path(path)
    need(path.is_file() and not path.is_symlink(), 'regular whole file: '+str(path))
    data = path.read_bytes()
    return dict(bytes=len(data), sha256=digest(data), mode=format(stat.S_IMODE(path.stat().st_mode), '04o'))


def elf(path):
    """Read the actual ELF interpreter, SONAME and every DT_NEEDED entry."""
    data = Path(path).read_bytes()
    def take(at, count):
        need(0 <= at <= len(data) and 0 <= count <= len(data)-at, 'whole bounded ELF range')
        return data[at:at+count]
    h = struct.unpack('<16sHHIQQQIHHHHHH', take(0, 64))
    need(h[0][:7] == b'\x7fELF\2\1\1' and h[1] in (2, 3) and h[2:4] == (62, 1)
         and h[8:10] == (64, 56) and 0 < h[10] <= 128, 'actual bounded x86-64 ELF')
    ph = [struct.unpack('<IIQQQQQQ', take(h[5]+56*i, 56)) for i in range(h[10])]
    for p in ph:
        take(p[2], p[5])
        need(p[5] <= p[6], 'file-backed program extent')
    interpreter = [take(p[2], p[5]) for p in ph if p[0] == 3]
    need(len(interpreter) <= 1, 'at most one actual interpreter')
    if interpreter:
        name = interpreter[0]
        need(name.startswith(b'/') and name.endswith(b'\0') and b'\0' not in name[:-1], 'whole interpreter spelling')
        interpreter = os.fsdecode(name[:-1])
    else:
        interpreter = None
    dynamic = [p for p in ph if p[0] == 2]
    need(len(dynamic) == 1 and dynamic[0][5] % 16 == 0, 'one complete dynamic table')
    tags = []
    for at in range(dynamic[0][2], dynamic[0][2]+dynamic[0][5], 16):
        tag, value = struct.unpack('<QQ', take(at, 16))
        if tag == 0:
            break
        tags.append((tag, value))
    else:
        raise ValueError('unterminated dynamic table')
    addresses, sizes = ([v for t, v in tags if t == key] for key in (5, 10))
    need(len(addresses) == len(sizes) == 1, 'one actual dynamic string table')
    loads = [p for p in ph if p[0] == 1 and p[3] <= addresses[0]
             and sizes[0] <= p[3]+p[5]-addresses[0]]
    need(len(loads) == 1, 'whole strings in one file-backed LOAD')
    names = take(loads[0][2]+addresses[0]-loads[0][3], sizes[0])
    def string(at):
        need(at < len(names) and b'\0' in names[at:], 'bounded dynamic name')
        name = names[at:names.index(b'\0', at)].decode('ascii')
        need(name and '/' not in name, 'plain runtime SONAME')
        return name
    sonames = [string(v) for t, v in tags if t == 14]
    needed = [string(v) for t, v in tags if t == 1]
    need(len(sonames) <= 1 and len(set(needed)) == len(needed), 'unique SONAME/dependency identities')
    return dict(interpreter=interpreter, soname=sonames[0] if sonames else None, needed=needed)


def component_result(stdout, stderr):
    """Keep the independent fixed populations and typed recovery accounting."""
    need(type(stdout) is bytes and 0 < len(stdout) <= 2048 and stderr == b'',
         'complete bounded component output without diagnostics')
    def unique(pairs):
        result = dict(pairs)
        need(len(result) == len(pairs), 'no duplicate component fields')
        return result
    result = json.loads(stdout, object_pairs_hook=unique)
    fixed = dict(version=10, plans=45, models=8064, selectors=8064, misses=11,
                 corruptions=21, old_checks=6, capacity_links=2, copied_boundaries=580,
                 interiors=19848, emitted_execution=0, owner_credit=0)
    need(type(result) is dict and set(result) == set(fixed) | {'typed_recoveries', 'steps'}
         and all(type(value) is int for value in result.values()), 'exact integer component schema')
    need(all(result[key] == value for key, value in fixed.items()),
         'all fixed plans, model selectors, refusals, corruptions and old-policy populations')
    need(result['steps'] > result['models'] and result['typed_recoveries'] == 2 * result['steps'],
         'both complete typed recovery calls for every actual model step')
    need(json.dumps(result, separators=(',', ':')).encode() + b'\n' == stdout,
         'one canonical complete component row')
    return result


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--expect-revision', required=True)
    ap.add_argument('--archive', required=True, type=Path)
    ap.add_argument('--archive-sha256', required=True)
    ap.add_argument('--cpu', required=True, type=int)
    ap.add_argument('--output', required=True, type=Path)
    args = ap.parse_args()
    need(sys.version_info >= (3, 11) and not sys.flags.optimize, 'Python3.11+ with assertions enabled')
    need(sorted(os.sched_getaffinity(0)) == [args.cpu], 'one externally reserved CPU matching --cpu')
    need(re.fullmatch('[0-9a-f]{40}', args.expect_revision) and
         re.fullmatch('[0-9a-f]{64}', args.archive_sha256), 'explicit full source and archive identities')
    private = args.output.resolve()
    need(private.is_relative_to((ROOT/'target/evaluation/inprocess').resolve(strict=True)) and not private.exists(),
         'fresh private attempt below target/evaluation/inprocess')
    sys.path.insert(0, str(ROOT/'evaluation/inprocess'))
    from checks import source
    from run import hardware
    from page_selected import ENV, save
    from page_selected_process import invoke
    os.chdir(ROOT)
    private.mkdir()
    receipt = private/'receipt.json'
    pins, aliases, artifacts, presence = {}, {}, {}, {}
    r = dict(schema=1, profile='experimental-bounded-block-component-v1', status='failed',
             revision=args.expect_revision, source=None, cpu=args.cpu, hardware=hardware(args.cpu), bounds=BOUNDS,
             commands=[], components={}, source_unchanged=False, inputs_unchanged=False,
             cleanup_complete=False, archive_builds=0, archive_source_provenance_verified=False,
             generated_execution=0, native_execution=0, owner_credit=False, qualification_credit=False,
             performance_credit=False, error=None, final_errors=[])
    stage = 'preflight'

    def pin(path):
        need(path is not None, 'required input/tool')
        alias = Path(path).absolute(); resolved = alias.resolve(strict=True); value = fact(resolved)
        need(str(alias) not in aliases or aliases[str(alias)] == str(resolved), 'stable input alias')
        need(str(resolved) not in pins or pins[str(resolved)] == value, 'stable whole input')
        aliases[str(alias)] = str(resolved); pins[str(resolved)] = value
        return resolved

    def artifact(path):
        path = Path(path)
        need(path.is_relative_to(private), 'private artifact containment')
        value = fact(path)
        need(str(path) not in artifacts or artifacts[str(path)] == value, 'immutable completed artifact')
        artifacts[str(path)] = value
        return value

    def closure():
        need(all(fact(p) == v for p, v in pins.items()), 'all whole inputs unchanged')
        need(all(str(Path(p).resolve(strict=True)) == v for p, v in aliases.items()), 'all aliases unchanged')
        need(all(fact(p) == v for p, v in artifacts.items()), 'all completed artifacts unchanged')
        need(all(Path(p).exists() == v for p, v in presence.items()), 'loader configuration presence unchanged')
        need(sorted(os.sched_getaffinity(0)) == [args.cpu], 'same reserved CPU')

    def run(name, argv, kind='build'):
        nonlocal stage
        stage = name; closure()
        need(not any(c['name'] == name for c in r['commands']), 'unique stage, no retry')
        row = dict(name=name, argv=list(map(str, argv)), environment=dict(ENV), bounds=BOUNDS[kind],
                   capture_limit=16 << 20, expected_exit=0)
        r['commands'].append(row); save(receipt, r)
        try:
            out, err = invoke(row, private, args.cpu)
        finally:
            for v in row.get('captures', {}).values():
                actual = artifact(private/v['file'])
                need(all(actual[k] == v[k] for k in ('bytes', 'sha256')), 'whole post-reap capture')
            if (private/(name+'.json')).is_file():
                artifact(private/(name+'.json'))
            save(receipt, r)
        need(row['exit'] == 0, 'exact successful command: '+name)
        return out, err

    def runtime(label, program, allowed=None):
        image = elf(program); spelling = image['interpreter']
        need(spelling is not None, 'one actual executable interpreter')
        loader = pin(spelling)
        if allowed is not None:
            need(str(loader) in allowed, 'actual interpreter was bound before link')
        out, err = run(label+'-dependencies', [loader, '--list', program])
        need(not err, 'whole loader dependency listing stderr')
        dependencies = set()
        for line in out.decode().splitlines():
            line = line.strip()
            if re.fullmatch(r'linux-vdso\.so\.1 \(0x[0-9a-f]+\)', line): continue
            alias = re.fullmatch(r'(/[^ ]+) => (/[^ ]+) \(0x[0-9a-f]+\)', line)
            if alias:
                need(alias[1] == spelling and alias[2] == str(loader) and pin(alias[1]) == pin(alias[2]) == loader,
                     'only the exact actual interpreter alias/target')
                path = loader
            else:
                match = re.fullmatch(r'(?:[^ /]+ => )?(/[^ ]+) \(0x[0-9a-f]+\)', line)
                need(match is not None, 'complete resolved runtime dependency grammar'); path = pin(match[1])
            if allowed is not None:
                need(str(path) in allowed, 'runtime dependency bound before link')
            dependencies.add(str(path))
        need(str(loader) in dependencies, 'complete actual loader closure')
        dynamic = {p: elf(p) for p in sorted(dependencies)}; sonames = {}
        for p, info in dynamic.items():
            if info['soname']:
                need(info['soname'] not in sonames, 'one actual file per runtime SONAME'); sonames[info['soname']] = p
        need('libc.so.6' in sonames and all(n in sonames for info in [image, *dynamic.values()] for n in info['needed']),
             'every actual DT_NEEDED edge closes over the bound runtime objects')
        return image, dynamic

    try:
        pin('/usr/bin/git')
        r['source'] = source()
        need(r['source']['revision'] == args.expect_revision, 'clean exact expected source revision')
        pin(__file__); pin(Path(__file__).with_name('README.md')); pin(sys.executable)
        for module in tuple(sys.modules.values()):
            name = getattr(module, '__file__', None)
            if name and Path(name).is_file():
                pin(name)
        maps = Path('/proc/self/maps').read_bytes()
        (private/'python-maps.txt').write_bytes(maps); artifact(private/'python-maps.txt')
        mapped = set()
        for line in maps.decode().splitlines():
            fields = line.split(None, 5)
            if len(fields) == 6 and fields[5].startswith('/'):
                need(not fields[5].endswith(' (deleted)'), 'live Python mapped input')
                mapped.add(str(pin(fields[5])))
        r['python_mapped_inputs'] = sorted(mapped)
        archive = pin(args.archive)
        need(fact(archive)['sha256'] == args.archive_sha256 and archive.read_bytes().startswith(b'!<arch>\n'),
             'explicit supplied static archive identity')
        r['archive'] = fact(archive)
        tools = {name: pin(shutil.which(name, path=ENV['PATH'])) for name in ('cc', 'nm')}
        tools['python'] = pin(sys.executable)
        tools['git'] = pin('/usr/bin/git')
        for name in ('/etc/ld.so.cache', '/etc/ld.so.preload'):
            presence[name] = Path(name).exists()
            if presence[name]: pin(name)
        need(not presence['/etc/ld.so.preload'], 'no global preload')
        r['tool_runtime'] = {name: runtime('tool-'+name, tools[name])[1] for name in ('cc', 'nm', 'python', 'git')}
        for name in ('cc1', 'collect2', 'as', 'ld'):
            out, err = run('resolve-'+name, [tools['cc'], '-print-prog-name='+name]); value = out.decode().strip()
            need(value and not err, 'actual compiler subtool')
            tools[name] = pin(value if Path(value).is_absolute() else shutil.which(value, path=ENV['PATH']))
            r['tool_runtime'][name] = runtime('tool-'+name, tools[name])[1]
        for name in ('cc', 'as', 'ld', 'nm', 'python', 'git'):
            out, err = run('version-'+name, [tools[name], '--version'])
            need(out and not err, 'actual tool version')
        r['tools'] = {name: str(p) for name, p in tools.items()}
        link_inputs = {str(archive)}
        for name in LINK_NAMES:
            out, err = run('link-'+name, [tools['cc'], '-print-file-name='+name]); value = out.decode().strip()
            need(not err and Path(value).is_absolute(), 'prebound compiler-selected link input')
            link_inputs.add(str(pin(value)))
        pending = list(link_inputs)
        while pending:
            path = Path(pending.pop()); data = path.read_bytes()
            if data.startswith((b'\x7fELF', b'!<arch>')): continue
            need(len(data) < 4096 and b'GNU ld script' in data, 'bounded recognized GNU linker script')
            for name in re.findall(r'/[^\s()]+', re.sub(r'/\*.*?\*/', '', data.decode(), flags=re.S)):
                name = str(pin(name))
                if name not in link_inputs: link_inputs.add(name); pending.append(name)
        _, err = run('compiler-specs', [tools['cc'], '-dumpspecs']); need(not err, 'compiler specifications stderr')
        out, err = run('archive-exports', [tools['nm'], '-g', '--defined-only', archive]); need(not err, 'whole archive census stderr')
        required = ('li2_decoder_decode', 'li2_decoder_tf_classify', 'li2_decoder_write_footprint',
                    'li2_decoder_span_describe', 'li2_decoder_region_describe', 'li2_decoder_link_none', 'li2_decoder_mov_store')
        names = [m[1] for line in out.decode().splitlines()
                 if (m := re.fullmatch(r'[0-9a-fA-F]+ T (\S+)', line))]
        need(all(names.count(name) == 1 for name in required), 'all exact decoder component providers')

        for name, case in CASES.items():
            fixture = SELECTED/'tests'/name; recipe = pin(fixture/'build.sh')
            need(fact(recipe)['sha256'] == case['recipe_sha256'], 'unchanged complete component recipe')
            output_dir = private/name; output_dir.mkdir(); output = output_dir/'component'
            units = [str(SELECTED/x) for x in case['units']]
            for p in units: pin(p)
            text = recipe.read_text().replace('\\\n', ' ')
            lines = [line.strip() for line in text.splitlines() if line.strip().startswith('"$cc_bin" ')]
            need(len(lines) == 1, 'one exact compiler recipe')
            replacements = {'$cc_bin': tools['cc'], '$fixture': fixture, '$selected': SELECTED,
                            '$archive': archive, '$output': output}
            argv = []
            for word in shlex.split(lines[0]):
                for key, value in replacements.items(): word = word.replace(key, str(value))
                need('$' not in word and '`' not in word, 'closed literal compiler argument'); argv.append(word)
            need([x for x in argv if x.endswith(('.c', '.S'))] == units and
                 [x for x in argv if x.endswith('.a')] == [str(archive)] and argv[-2:] == ['-o', str(output)],
                 'all component translation units, single archive and exact output')
            flags = [x for x in argv[1:-2] if x not in units and x != str(archive) and not x.startswith(('-Wl,', '-l'))]
            out, err = run(name+'-headers', [tools['cc'], *flags, '-M', '-MT', 'call_component', *units])
            rules = out.decode().replace('\\\n', ' ').splitlines()
            need(not err and len(rules) == len(units) and all(x.startswith('call_component: ') for x in rules),
                 'every complete actual compiler-M rule')
            headers = {str(pin(x)) for line in rules for x in shlex.split(line.split(':', 1)[1])}
            need({str(Path(x).resolve()) for x in units} |
                 {str((SELECTED/x).resolve()) for x in case['headers']} <= headers, 'complete typed component header closure')
            additions = ['-save-temps=obj', '-Wl,--trace']
            out, err = run(name+'-build', argv[:-2]+additions+argv[-2:])
            need(not err, 'strict original -Werror compiler/linker stderr')
            objects = {str(output_dir/('component-'+Path(p).stem+'.o')) for p in units}
            for p in units:
                for suffix in ('.i', '.s', '.o', '.su'):
                    artifact(output_dir/('component-'+Path(p).stem+suffix))
            trace = out.decode().splitlines()
            need(trace and all(Path(x).is_absolute() for x in trace), 'whole absolute actual linker trace')
            linked = {str(Path(x).resolve(strict=True)) for x in trace}
            need(objects | {str(archive)} <= linked <= link_inputs | objects, 'all generated objects and only prebound link inputs')
            binary = artifact(output); need(int(binary['mode'], 8) & 0o111, 'actual executable component')
            image, dynamic = runtime(name, output, link_inputs)
            r['components'][name] = dict(status='not_run', recipe=fact(recipe), original_argv=argv,
                diagnostic_only_additions=additions, headers=sorted(headers), link_inputs=sorted(linked),
                runtime_objects=dynamic, elf=image, binary=binary, result=None)
            out, err = run(name+'-component', [output], 'component')
            r['components'][name].update(status='passed', result=component_result(out, err))
        need(list(r['components']) == list(CASES) and all(v['status'] == 'passed' for v in r['components'].values()),
             'the complete bounded-block component passed')
        r['status'] = 'components_passed'
    except BaseException as error:
        r['error'] = type(error).__name__+': '+str(error)
    finally:
        for name in CASES:
            directory = private/name
            if directory.is_dir():
                for p in directory.iterdir():
                    if p.is_file() and not p.is_symlink():
                        try: artifact(p)
                        except BaseException as error: r['final_errors'].append('partial-artifact: '+repr(error))
        try: closure(); r['inputs_unchanged'] = True
        except BaseException as error: r['final_errors'].append('inputs: '+repr(error))
        try:
            need(source() == r['source'], 'whole tracked source before/after equality'); r['source_unchanged'] = True
        except BaseException as error: r['final_errors'].append('source: '+repr(error))
        r['cleanup_complete'] = all(c.get('reaped') and not c.get('cleanup_errors') and
            all(d['closed'] for d in c.get('descriptors', [])) for c in r['commands'])
        if r['error'] or r['final_errors'] or not all(r[k] for k in ('source_unchanged', 'inputs_unchanged', 'cleanup_complete')):
            r['status'] = 'failed'
        r.update(inputs=pins, aliases=aliases, artifacts=artifacts, loader_presence=presence)
        save(receipt, r)

    # A shareable projection, never raw command lines, loader paths or failure text.
    host = dict(r['hardware']); flags = host.pop('isa_flags')
    host['isa_flags_count'] = len(flags); host['isa_flags_sha256'] = digest(canonical(flags))
    summary = dict(schema=1, profile=r['profile'], status=r['status'], source=r['source'], cpu=args.cpu,
        hardware=host, bounds=BOUNDS, archive=r.get('archive'), archive_builds=0,
        archive_source_provenance_verified=False, generated_execution=0, native_execution=0,
        owner_credit=False, qualification_credit=False, performance_credit=False,
        pending=['actual composed owner execution', 'whole392/522 qualification', 'real-program completion and performance'],
        source_unchanged=r['source_unchanged'], inputs_unchanged=r['inputs_unchanged'], cleanup_complete=r['cleanup_complete'],
        failed_stage=stage if r['status'] == 'failed' else None, final_error_count=len(r['final_errors']), receipt=fact(receipt),
        tools={n: pins[p] for n, p in r.get('tools', {}).items()},
        inventories={n: dict(count=len(v), sha256=digest(canonical(v))) for n, v in
            (('inputs', pins), ('aliases', aliases), ('artifacts', artifacts), ('tool_runtime', r.get('tool_runtime', {})),
             ('python_mapped_inputs', r.get('python_mapped_inputs', [])))},
        components={n: dict(status=v['status'], result=v['result'], binary=v['binary'], recipe=v['recipe'],
            headers=dict(count=len(v['headers']), sha256=digest(canonical(v['headers']))),
            link_inputs=dict(count=len(v['link_inputs']), sha256=digest(canonical(v['link_inputs']))),
            runtime_objects=dict(count=len(v['runtime_objects']), sha256=digest(canonical(v['runtime_objects']))))
            for n, v in r['components'].items()},
        commands=[dict(name=c['name'], exit=c.get('exit'), duration_ns=c.get('duration_ns'), bounds=c['bounds'],
            reaped=c.get('reaped', False), timed_out=c.get('timed_out', False), cleanup_errors=len(c.get('cleanup_errors', [])),
            argv_sha256=digest(canonical(c['argv'])), captures={n: {k: v[k] for k in ('bytes', 'sha256')}
                for n, v in c.get('captures', {}).items()}) for c in r['commands']])
    payload = json.dumps(summary, indent=2, sort_keys=True)+'\n'
    need(str(ROOT) not in payload and str(private) not in payload and '/home/' not in payload, 'public projection excludes private paths')
    (private/'summary.json').write_text(payload)
    print(json.dumps(dict(status=r['status'], components={n: v['result'] for n, v in r['components'].items()},
                         qualification_credit=False, summary=str((private/'summary.json').relative_to(ROOT))), sort_keys=True))
    return int(r['status'] != 'components_passed')


if __name__ == '__main__':
    raise SystemExit(main())
