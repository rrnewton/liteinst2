#!/usr/bin/env python3
"""Six actual emitted-CALL chunks after whole current-source component/CALL217 custody."""
import argparse
from collections import Counter
import hashlib
import json
import os
import re
from pathlib import Path
import shlex
import shutil
import stat
import struct
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
SELECTED = ROOT/'tools/page-entry/selected'
BOUNDS = {'build': [30, 512 << 20, 16 << 20, 60],
          'native': [5, 512 << 20, 16 << 20, 15]}


def need(ok, message):
    if not ok:
        raise ValueError(message)


def fact(path):
    path = Path(path)
    need(path.is_file() and not path.is_symlink(), 'regular input: '+str(path))
    data = path.read_bytes()
    return {'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest(),
            'mode': format(stat.S_IMODE(path.stat().st_mode), '04o')}


def unique(pairs):
    result = dict(pairs)
    need(len(result) == len(pairs), 'duplicate manifest field')
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



def retained(path, wanted, current, pin, environment):
    """Authenticate a closed prerequisite; never execute or substitute its result."""
    prior = load(pin(path))
    need(prior['status'] == wanted['status'] and prior['profile'] == wanted['profile'] and
         prior['revision'] == current['revision'] and prior['source'] == current['source'] and
         prior['cpu'] == current['cpu'] and prior['hardware'] == current['hardware'],
         'exact prerequisite source, CPU, hardware and outcome')
    need(prior['source_unchanged'] is True and prior['inputs_unchanged'] is True and
         prior['cleanup_complete'] is True and prior['error'] is None and prior['final_errors'] == [] and
         prior['owner_credit'] in (0, False) and prior['qualification_credit'] is False and
         prior['performance_credit'] is False, 'complete closed unqualified prerequisite')
    need([row['name'] for row in prior['commands']] == wanted['commands'] and
         prior['bounds'] == wanted['bounds'], 'whole original prerequisite schedule and bounds')
    for group in ('inputs', 'artifacts'):
        for name, value in prior[group].items():
            need(fact(pin(name)) == value, 'retained whole prerequisite '+group+': '+name)
    for name, target in prior['aliases'].items():
        need(str(pin(name)) == target, 'exact retained prerequisite alias')
    for name, target in prior.get('context_links', {}).items():
        need(Path(name).is_symlink() and os.readlink(name) == target and
             str(pin(name)) == str(Path(target).resolve(strict=True)), 'exact prerequisite context link')
    for name, exists in prior['loader_presence'].items():
        need(Path(name).exists() == exists, 'same prerequisite loader configuration presence')
    directory = Path(path).parent.resolve(strict=True)
    for row in prior['commands']:
        need(row['exit'] == row['expected_exit'] == 0 and row['error'] is None and
             row['timed_out'] is False and row['reaped'] is True and row['cleanup_errors'] == [] and
             all(d['closed'] for d in row['descriptors']) and row['environment'] == environment and
             row['capture_limit'] == 16 << 20 and row['bounds'] in wanted['bounds'].values(),
             'actual prerequisite process success, environment, original bounds and closure')
        need(set(row['captures']) == {'stdout', 'stderr'}, 'both whole prerequisite captures')
        for stream, value in row['captures'].items():
            capture = directory/value['file']
            need(capture.parent == directory and
                 {k: fact(pin(capture))[k] for k in ('bytes','sha256')} ==
                 {k: value[k] for k in ('bytes','sha256')} and
                 fact(capture) == prior['artifacts'][str(capture)], 'whole post-reap prerequisite capture')
    return prior


def native_compact(observed):
    need(observed['status'] == 'finite_native_comparisons_passed' and
         observed['native_pairs'] == 136 and observed['native_lanes'] == 272 and
         all(observed[k] is False for k in ('old217_cases_replaced', 'owner_credit',
              'production_admission_credit', 'qualification_credit', 'performance_credit')),
         'complete finite comparison without broader credit')
    pairs = observed['pairs']
    need(len(pairs) == 136 and [p['id'] for p in pairs] == list(range(136)) and
         [sum(p['group'] == group for p in pairs) for group in range(5)] == [32,64,16,8,16],
         'all original/generated pairs in every fixed group')
    return dict(status=observed['status'], native_pairs=136, native_lanes=272,
         groups=[dict(group=g, pairs=sum(p['group'] == g for p in pairs)) for g in range(5)],
         committed_once=sum(p['committed_once'] for p in pairs),
         no_effect_misses=sum(p['no_effect_miss'] for p in pairs),
         injected_stack_faults=sum(p['injected_stack_fault'] for p in pairs),
         post_push_traces=sum(p['post_push_trace'] for p in pairs),
         actual_generated_trace_boundaries=sum(p['actual_generated_trace_boundaries'] for p in pairs),
         raw_sources=observed['sources'], old217_cases_replaced=False,
         owner_credit=False, production_admission_credit=False,
         qualification_credit=False, performance_credit=False)


CALL217 = {'bounds': {'build': [30, 536870912, 16777216, 60], 'native': [5, 536870912, 16777216, 15]}, 'commands': ['resolve-cc1', 'resolve-collect2', 'resolve-as', 'resolve-ld', 'version-cc', 'version-as', 'version-ld', 'link-input-crt1.o', 'link-input-Scrt1.o', 'link-input-crti.o', 'link-input-crtn.o', 'link-input-crtbegin.o', 'link-input-crtbeginS.o', 'link-input-crtend.o', 'link-input-crtendS.o', 'link-input-libgcc.a', 'link-input-libgcc_s.so', 'link-input-libc.so', 'link-input-libc_nonshared.a', 'link-input-libc.so.6', 'link-input-libgcc_s.so.1', 'compiler-specs', 'headers-0', 'headers-1', 'build', 'emitted-inspection', 'runtime-dependencies', 'native-0', 'native-1', 'native-2', 'native-3', 'native-4', 'native-5', 'native-6', 'read-all-chunks'], 'profile': 'call-push-native-diagnostic-v1', 'status': 'observed_unqualified'}


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--expect-revision', required=True)
    ap.add_argument('--cpu', required=True, type=int)
    ap.add_argument('--archive-receipt', required=True, type=Path)
    ap.add_argument('--archive-receipt-sha256', required=True)
    ap.add_argument('--components-receipt', required=True, type=Path)
    ap.add_argument('--components-receipt-sha256', required=True)
    ap.add_argument('--call217-receipt', required=True, type=Path)
    ap.add_argument('--call217-receipt-sha256', required=True)
    ap.add_argument('--output', type=Path, required=True)
    args = ap.parse_args()
    need(sys.version_info >= (3, 11) and not sys.flags.optimize and
         sorted(os.sched_getaffinity(0)) == [args.cpu],
         'Python3.11+, assertions and exactly the independently reserved prerequisite CPU')
    need(re.fullmatch('[0-9a-f]{40}', args.expect_revision) and
         all(re.fullmatch('[0-9a-f]{64}', x) for x in (args.archive_receipt_sha256,
             args.components_receipt_sha256, args.call217_receipt_sha256)),
         'explicit complete revision and prerequisite receipt identities')
    cpu = args.cpu
    private = args.output.resolve()
    need(private.is_relative_to((ROOT/'target/evaluation/inprocess').resolve(strict=True))
         and not private.exists(), 'fresh private output below target/evaluation/inprocess')

    sys.path.insert(0, str(ROOT/'evaluation/inprocess'))
    from checks import source
    from run import hardware
    from page_selected import ENV, save
    from page_selected_process import invoke
    os.chdir(ROOT)
    private.mkdir()
    receipt = private/'receipt.json'
    pins, aliases, artifacts, links, presence = {}, {}, {}, {}, {}
    r = dict(schema=1, profile='public-call-dispatch-native-v1',
             status='failed', revision=args.expect_revision, source=None,
             source_unchanged=False, inputs_unchanged=False, cleanup_complete=False,
             cpu=cpu, hardware=hardware(cpu), bounds=BOUNDS, commands=[], result=None,
             scope='136 original/generated native pairs with supplied numeric bindings; retained model and old217 are separate mandatory observations',
             emitted_execution=0, owner_credit=0, qualification_credit=False,
             performance_credit=False, archive_builds=0, error=None, final_errors=[])
    stage = 'preflight'

    def pin(path):
        need(path is not None, 'required tool or source path')
        alias = Path(path).absolute()
        resolved = alias.resolve(strict=True)
        value = fact(resolved)
        need(str(alias) not in aliases or aliases[str(alias)] == str(resolved), 'stable alias')
        need(str(resolved) not in pins or pins[str(resolved)] == value, 'stable whole input')
        aliases[str(alias)] = str(resolved)
        pins[str(resolved)] = value
        return resolved

    def artifact(path):
        path = Path(path)
        need(path.is_relative_to(private), 'artifact remains in this private attempt')
        value = fact(path)
        need(str(path) not in artifacts or artifacts[str(path)] == value, 'stable complete artifact')
        artifacts[str(path)] = value

    def closure():
        need(all(fact(p) == value for p, value in pins.items()), 'all inputs unchanged')
        need(all(str(Path(p).resolve(strict=True)) == value for p, value in aliases.items()),
             'all resolved aliases unchanged')
        need(all(fact(p) == value for p, value in artifacts.items()), 'all artifacts unchanged')
        need(all(Path(p).is_symlink() and os.readlink(p) == value for p, value in links.items()),
             'all private context links unchanged')
        need(all(Path(p).exists() == value for p, value in presence.items()), 'loader configuration presence')
        need(sorted(os.sched_getaffinity(0)) == [cpu], 'reserved CPU unchanged')

    def run(name, argv, profile='build'):
        nonlocal stage
        stage = name
        closure()
        need(not any(row['name'] == name for row in r['commands']), 'unique command, no retry')
        row = dict(name=name, argv=list(map(str, argv)), bounds=BOUNDS[profile],
                   capture_limit=16 << 20, environment=dict(ENV), expected_exit=0)
        r['commands'].append(row)
        save(receipt, r)
        try:
            out, err = invoke(row, private, cpu)
        finally:
            for stream, value in row.get('captures', {}).items():
                path = private/value['file']
                need({k: fact(path)[k] for k in ('bytes', 'sha256')} ==
                     {k: value[k] for k in ('bytes', 'sha256')}, 'post-reap whole capture')
                artifact(path)
            record = private/(name+'.json')
            if record.is_file():
                artifact(record)
            save(receipt, r)
        need(row['exit'] == 0 and row['error'] is None and row['timed_out'] is False and
             row['reaped'] is True and row['cleanup_errors'] == [] and
             all(d['closed'] for d in row['descriptors']), 'exact successful reaped command: '+name)
        return out, err

    try:
        r['source'] = source()
        need(r['source']['revision'] == args.expect_revision, 'current clean source equals reviewed revision')
        pin('/usr/bin/git')
        pin(__file__); pin(HERE/'README.md')
        manifest = load(pin(HERE/'SOURCE.json'))
        for name, wanted in manifest['files'].items():
            need(fact(pin(ROOT/name)) == wanted, 'whole public source leaf: '+name)
        from call_owner.custody import check_archive, check_components
        for module in tuple(sys.modules.values()):
            name = getattr(module, '__file__', None)
            if name and Path(name).is_file(): pin(name)
        python = pin(sys.executable)
        r['collector_python'] = str(python)
        maps = Path('/proc/self/maps').read_bytes()
        (private/'python-maps.txt').write_bytes(maps); artifact(private/'python-maps.txt')
        mapped = set()
        for line in maps.decode().splitlines():
            fields = line.split(None, 5)
            if len(fields) == 6 and fields[5].startswith('/'):
                need(not fields[5].endswith(' (deleted)'), 'live Python mapped input')
                mapped.add(str(pin(fields[5])))
        r['python_mapped_inputs'] = sorted(mapped)
        archive, build, archive_environment, exports, archive_prior = check_archive(
            args.archive_receipt, args.archive_receipt_sha256, r, pin)
        model = check_components(args.components_receipt, args.components_receipt_sha256, r, pin, archive)
        old_path = pin(args.call217_receipt)
        need(fact(old_path)['sha256'] == args.call217_receipt_sha256,
             'explicit whole public CALL217 prerequisite identity')
        old_native = retained(old_path, CALL217, r, pin, ENV)
        need(str(python) == old_native['collector_python'] == model['tools']['python'],
             'same actual prerequisite/native Python interpreter')
        r['archive_reuse'] = dict(receipt=fact(pin(args.archive_receipt)),
            archive=fact(archive), release_build=build, environment=archive_environment,
            fresh_build=False, source_tools_features_verified=True, qualification_credit=False)
        selected = SELECTED
        fixture = selected/'tests/call_dispatch_native'
        old_read = old_native['commands'][-1]
        need(old_read['name'] == 'read-all-chunks' and old_read['captures']['stderr']['bytes'] == 0,
             'actual old217 whole reader completed')
        old_observed = load(old_path.parent/old_read['captures']['stdout']['file'])
        old_result = compact(old_observed)
        old_result['raw_sources'] = old_observed['sources']
        need(old_native['result'] == old_result and old_native['call_push_equivalence'] is None and
             old_native['production_admission_credit'] is False, 'unchanged old217 complete observation')
        old_chunks = [row for row in old_native['commands'] if re.fullmatch(r'native-[0-6]', row['name'])]
        need(len(old_chunks) == 7 and len(old_observed['sources']) == 7 and
             old_observed['cpu'] == cpu, 'all seven actual old217 chunks')
        for i, (row, observed) in enumerate(zip(old_chunks, old_observed['sources'])):
            capture = row['captures']['stdout']
            need(observed == dict(chunk=i, pid=row['pid'], bytes=capture['bytes'], sha256=capture['sha256']) and
                 row['bounds'] == BOUNDS['native'] and row['captures']['stderr']['bytes'] == 0,
                 'whole old217 reader inputs join actual original process rows')
        r['prerequisites'] = dict(model=dict(receipt=fact(pin(args.components_receipt)),
            status=model['status'], counts={k:v['result'] for k,v in model['components'].items()}, executed_here=False),
            old217=dict(receipt=fact(old_path), status=old_native['status'],
            pairs=217, lanes=434, executed_here=False, call_push_equivalence=None))
        tools = {name: pin(shutil.which(name, path=ENV['PATH'])) for name in ('cc', 'nm')}
        for name in ('/etc/ld.so.cache', '/etc/ld.so.preload'):
            presence[name] = Path(name).exists()
            if presence[name]:
                pin(name)
        need(not presence['/etc/ld.so.preload'], 'no global preload')
        for name in ('cc1', 'collect2', 'as', 'ld'):
            out, err = run('resolve-'+name, [tools['cc'], '-print-prog-name='+name])
            value = out.decode().strip()
            need(value and not err, 'actual compiler subtool resolution')
            tools[name] = pin(value if Path(value).is_absolute() else shutil.which(value, path=ENV['PATH']))
        for name in ('cc', 'as', 'ld', 'nm'):
            out, err = run('version-'+name, [tools[name], '--version'])
            need(out and not err, 'actual tool version')
        r['tools'] = {name: str(path) for name, path in tools.items()}
        for name in ('cc','cc1','collect2','as','ld','nm'):
            need(str(tools[name]) == model['tools'][name] and
                 fact(tools[name]) == model['inputs'][str(tools[name])], 'same actual model/native tool inputs')
        for name in ('cc','cc1','collect2','as','ld','nm'):
            wanted = build['tools'][name]
            need({k: fact(tools[name])[k] for k in ('bytes','sha256')} ==
                 {k: wanted[k] for k in ('bytes','sha256')}, 'same actual retained compiler/tool input')
        link_inputs = {str(archive)}
        for name in manifest['link_names']:
            out, err = run('link-input-'+name, [tools['cc'], '-print-file-name='+name])
            value = out.decode().strip()
            need(not err and Path(value).is_absolute(), 'actual compiler-selected link/runtime input')
            link_inputs.add(str(pin(value)))
        # Resolve every absolute GROUP/INPUT dependency of these actual GNU scripts before linking.
        pending = list(link_inputs)
        while pending:
            path = Path(pending.pop())
            data = path.read_bytes()
            if data.startswith((b'\x7fELF', b'!<arch>')):
                continue
            need(len(data) < 4096 and b'GNU ld script' in data, 'bounded recognized link script')
            for token in re.findall(r'/[^\s()]+', re.sub(r'/\*.*?\*/', '', data.decode(), flags=re.S)):
                resolved = str(pin(token))
                if resolved not in link_inputs:
                    link_inputs.add(resolved)
                    pending.append(resolved)
        _, err = run('compiler-specs', [tools['cc'], '-dumpspecs'])
        need(not err, 'compiler specifications stderr')
        out, err = run('retained-archive-exports', [tools['nm'], '-g', '--defined-only', archive])
        need(not err and out == exports, 'whole actual retained archive symbol census')
        r['archive_reuse']['exports'] = dict(bytes=len(exports), sha256=hashlib.sha256(exports).hexdigest())
        r['link_inputs'] = sorted(link_inputs)
        output = private/'call-dispatch-native'
        recipe = (fixture/'build.sh').read_text().replace('\\\n', ' ')
        replacements = {'$cc_bin': tools['cc'], '$fixture': fixture, '$selected': selected,
                        '$archive': archive, '$output': output}
        lines = [line.strip() for line in recipe.splitlines() if line.strip().startswith('"$cc_bin" ')]
        need(len(lines) == 1, 'one exact native compiler recipe')
        compile_argv = []
        for word in shlex.split(lines[0]):
            for key, value in replacements.items():
                word = word.replace(key, str(value))
            need('$' not in word and '`' not in word, 'closed literal native recipe argument')
            compile_argv.append(word)
        tus = list(map(str, [fixture/'probe.c', fixture/'probe.S',
                            selected/'linked_call_dispatch.c', selected/'tests/decoder/support.c']))
        need([x for x in compile_argv if x.endswith(('.c','.S'))] == tus and
             compile_argv[-2:] == ['-o',str(output)] and
             [x for x in compile_argv if x.endswith('.a')] == [str(archive)] and
             '-Werror' in compile_argv and '-no-pie' in compile_argv,
             'exact four native TUs, strict original recipe and one retained archive')
        r['recipe'] = dict(file=fact(fixture/'build.sh'), argv=compile_argv,
                          diagnostic_only_additions=[])
        flags = [x for x in compile_argv[1:-2] if x not in tus and x != str(archive)
                 and not x.startswith(('-Wl,','-l'))]
        all_headers = set()
        for index, source_path in enumerate(tus):
            out, err = run('headers-'+str(index), [tools['cc'], *flags, '-M', '-MT', 'probe', source_path])
            rule = out.decode().replace('\\\n', ' ')
            need(not err and len(rule.splitlines()) == 1 and rule.startswith('probe: '),
                 'whole actual compiler-M rule')
            actual = {str(pin(x)) for x in shlex.split(rule.split(':',1)[1])}
            need(str(Path(source_path).resolve()) in actual, 'actual native translation unit included')
            all_headers |= actual
        need({str((selected/name).resolve()) for name in
              ('linked_call_dispatch.h','linked_jmp_domain.h','decoder.h')} <= all_headers,
             'actual typed CALL/domain/decoder headers')
        r['headers'] = sorted(all_headers)
        out, err = run('build', compile_argv)
        need(not out and not err, 'strict exact native recipe captures empty')
        artifact(output)
        r['binary'] = fact(output)
        need(int(fact(output)['mode'], 8) & 0o111, 'fresh executable output')
        out, err = run('emitted-inspection', [python, '-I', '-S', '-B',
                       ROOT/'evaluation/inprocess/call_push_native/inspect.py', output], 'native')
        need(not err, 'emitted inspection stderr empty')
        inspected = json.loads(out, object_pairs_hook=unique)
        need(inspected['status'] == 'source_bytes_inspected' and
             inspected['elf_sha256'] == fact(output)['sha256'] and inspected['native_execution'] is False and
             inspected['qualification_credit'] is False, 'whole bootstrap/epilogue inspected before subjects')
        r['emitted_inspection'] = inspected
        interpreter = pin(inspected['interpreter'])
        need(str(interpreter) in link_inputs, 'actual native interpreter prebound before link')
        out, err = run('runtime-dependencies', [interpreter, '--list', output])
        need(not err, 'actual native loader dependency inspection')
        objects = {str(output): dynamic(output)}
        for line in out.decode().splitlines():
            if re.fullmatch(r'\s*linux-vdso\.so\.1 \(0x[0-9a-f]+\)', line):
                continue
            match = re.fullmatch(r'\s*(?:(\S+) => )?(/\S+) \(0x[0-9a-f]+\)', line)
            need(match is not None, 'complete actual native loader dependency line')
            resolved = pin(match.group(2))
            need(str(resolved) in link_inputs, 'runtime object belongs to prebound link closure')
            value = dynamic(resolved)
            requested = match.group(1)
            if requested is not None and requested.startswith('/'):
                need(requested == inspected['interpreter'] and pin(requested) == resolved == interpreter,
                     'exact actual native PT_INTERP alias join')
            else:
                need(requested is None or value['soname'] == requested, 'actual native SONAME dependency join')
            objects[str(resolved)] = value
        need(str(interpreter) in objects, 'actual native interpreter in loader closure')
        sonames = [v['soname'] for v in objects.values() if v['soname'] is not None]
        need(len(sonames) == len(set(sonames)) and
             all(name in sonames for v in objects.values() for name in v['needed']), 'closed exact native DT_NEEDED roster')
        r['runtime_objects'] = objects
        chunks, chunk_rows = [], []
        for chunk in range(6):
            name = 'native-'+str(chunk)
            out, err = run(name, [output, str(chunk)], 'native')
            row = r['commands'][-1]
            need(not err and 576 <= len(out) < 16 << 20, 'whole bounded native comparison capture')
            h = struct.unpack_from('<64Q', out)
            count = min(24, 136-24*chunk)
            need(h[:4] == (0x314e434432494c,1,512,295792) and
                 h[10:17] == (136,chunk,24*chunk,count,2*count,row['pid'],cpu) and
                 h[28:30] == (inspected['reload_address'],inspected['scratch_end_address']) and
                 len(out) == 512+2*count*295792+64,
                 'actual collector PID/CPU/ELF-bootstrap and exact native chunk joins')
            chunks.append(private/row['captures']['stdout']['file'])
            chunk_rows.append(dict(chunk=chunk,pid=row['pid'],cpu=cpu,
                 duration_ns=row['duration_ns'],capture=row['captures']['stdout']))
        r['native_chunks'] = chunk_rows
        out, err = run('read-all-chunks', [python,'-I','-S','-B',fixture/'read.py',
             '--expect-cpu',str(cpu),'--expect-pids',*[str(row['pid']) for row in chunk_rows],*chunks], 'native')
        need(not err, 'complete independent native reader stderr empty')
        observed = json.loads(out, object_pairs_hook=unique)
        need(observed['cpu'] == cpu and len(observed['sources']) == 6, 'complete native reader source roster')
        for source_row, child in zip(observed['sources'], chunk_rows):
            need(source_row == dict(chunk=child['chunk'],pid=child['pid'],
                 bytes=child['capture']['bytes'],sha256=child['capture']['sha256']),
                 'all independent reader inputs join actual process PID and whole captures')
        r['result'] = native_compact(observed)
        r['emitted_execution'] = 136
        r['status'] = 'passed'
    except BaseException as error:
        r['error'] = type(error).__name__+': '+str(error)
    finally:
        try:
            for path in (private/'call-dispatch-native', *private.glob('call-dispatch-native-*')):
                if path.exists():
                    artifact(path)
        except BaseException as error:
            r['final_errors'].append('partial-artifact: '+type(error).__name__+': '+str(error))
        try:
            closure()
            r['inputs_unchanged'] = True
        except BaseException as error:
            r['final_errors'].append('inputs: '+type(error).__name__+': '+str(error))
        try:
            need(source() == r['source'], 'whole current source closure')
            r['source_unchanged'] = True
        except BaseException as error:
            r['final_errors'].append('source: '+type(error).__name__+': '+str(error))
        r['cleanup_complete'] = all(row.get('reaped') and not row.get('cleanup_errors') and
             all(d['closed'] for d in row.get('descriptors', [])) for row in r['commands'])
        if r['error'] or r['final_errors'] or not r['source_unchanged'] or not r['inputs_unchanged'] or not r['cleanup_complete']:
            r['status'] = 'failed'
            r['result'] = None
        r.update(inputs=pins, aliases=aliases, artifacts=artifacts, context_links=links,
                 loader_presence=presence)
        save(receipt, r)
    # Public metadata retains outcomes and custody digests, never raw state or paths.
    def canonical(value):
        return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()
    def digest(value):
        return hashlib.sha256(canonical(value)).hexdigest()
    host = dict(r['hardware']); host.pop('runner_euid', None); flags = host.pop('isa_flags')
    host['isa_flags_count'] = len(flags); host['isa_flags_sha256'] = digest(flags)
    summary = dict(schema=1, profile=r['profile'], status=r['status'], source=r['source'], cpu=cpu,
        hardware=host, bounds=BOUNDS, result=r['result'], prerequisites=r.get('prerequisites'),
        archive=r.get('archive_reuse', {}).get('archive'), archive_builds=0,
        emitted_execution=r['emitted_execution'], owner_credit=False,
        production_admission_credit=False, qualification_credit=False, performance_credit=False,
        pending=['actual authenticated production owner', 'whole392/522 qualification',
                 'warm reuse and real-program completion/performance'],
        source_unchanged=r['source_unchanged'], inputs_unchanged=r['inputs_unchanged'],
        cleanup_complete=r['cleanup_complete'], failed_stage=stage if r['status']=='failed' else None,
        final_error_count=len(r['final_errors']), receipt=fact(receipt), binary=r.get('binary'),
        tools={n:pins[p] for n,p in r.get('tools', {}).items()},
        inventories={name:dict(count=len(value),sha256=digest(value)) for name,value in
            (('inputs',pins),('aliases',aliases),('artifacts',artifacts),
             ('runtime_objects',r.get('runtime_objects',{})),('python_mapped_inputs',r.get('python_mapped_inputs',[])))},
        commands=[dict(name=c['name'], exit=c.get('exit'), duration_ns=c.get('duration_ns'),
            bounds=c['bounds'], reaped=c.get('reaped',False), timed_out=c.get('timed_out',False),
            cleanup_errors=len(c.get('cleanup_errors',[])), argv_sha256=digest(c['argv']),
            captures={n:{k:v[k] for k in ('bytes','sha256')} for n,v in c.get('captures',{}).items()})
            for c in r['commands']])
    payload = json.dumps(summary,indent=2,sort_keys=True)+'\n'
    need(str(ROOT) not in payload and str(private) not in payload and '/home/' not in payload,
         'public summary contains no host paths or raw captures')
    (private/'summary.json').write_text(payload)
    print(json.dumps(dict(status=r['status'], result=r['result'], qualification_credit=False,
        summary=str((private/'summary.json').relative_to(ROOT))), sort_keys=True))
    return int(r['status'] != 'passed')


if __name__ == '__main__':
    raise SystemExit(main())
