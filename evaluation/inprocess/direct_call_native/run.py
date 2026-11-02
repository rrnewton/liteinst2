#!/usr/bin/env python3
"""Fifteen complete components and two additive direct-E8 native chunks; no owner execution."""
import argparse
import importlib.util
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
from types import SimpleNamespace

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = next(p for p in HERE.parents if (p/'evaluation/inprocess/page_selected_process.py').is_file())
BOUNDS = {'build': [30, 512 << 20, 16 << 20, 60],
          'native': [5, 512 << 20, 16 << 20, 15],
          'release_build': [30, 512 << 20, 16 << 20, 60],
          'finite': [5, 512 << 20, 16 << 20, 15]}


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


def native_compact(observed):
    need(observed['status']=='finite_native_comparisons_passed' and
         observed['native_pairs']==24 and observed['native_lanes']==48 and
         all(observed[k] is False for k in ('old217_cases_replaced','old136_cases_replaced',
             'owner_credit','production_admission_credit','qualification_credit','performance_credit')),
         'complete additive E8 native comparison with all original gates separate')
    pairs=observed['pairs']
    need(len(pairs)==24 and [p['id'] for p in pairs]==list(range(24)) and
         [sum(p['group']==g for p in pairs) for g in range(12)]==[2]*12 and
         sum(p['actual_generated_trace_boundaries'] for p in pairs)==140 and
         sum(p['pre_push_full_frame_sha256'] is not None for p in pairs)==4 and
         sum(p['return_page_observed_unmapped'] for p in pairs)==4,
         'all exact low/high signed/fault/full-frame/page-end observations')
    return dict(status=observed['status'],native_pairs=24,native_lanes=48,
        groups=[dict(group=g,pairs=2) for g in range(12)],full_frames=100,
        pre_push_full_frames=4,actual_generated_trace_boundaries=140,
        committed_once=sum(p['committed_once'] for p in pairs),
        no_effect_misses=sum(p['no_effect_miss'] for p in pairs),
        injected_stack_faults=sum(p['injected_stack_fault'] for p in pairs),
        return_page_observed_unmapped=4,raw_sources=observed['sources'],
        old217_cases_replaced=False,old136_cases_replaced=False,
        owner_credit=False,production_admission_credit=False,
        qualification_credit=False,performance_credit=False)


def main():
    sys.path.insert(0,str(ROOT/'evaluation/inprocess'))
    from page_selected_maps_sources import historical, bind as bind_maps_sources
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--expect-revision', required=True)
    ap.add_argument('--cpu', required=True, type=int)
    ap.add_argument('--archive-receipt', required=True, type=Path)
    ap.add_argument('--archive-receipt-sha256', required=True)
    for label in ('ret-owner','return-heads'):
        ap.add_argument('--'+label+'-receipt',required=True,type=Path)
        ap.add_argument('--'+label+'-receipt-sha256',required=True)
    ap.add_argument('--output', type=Path, required=True)
    args = ap.parse_args()
    need(sys.version_info >= (3, 11) and not sys.flags.optimize and
         args.cpu == 3 and sorted(os.sched_getaffinity(0)) == [args.cpu],
         'Python3.11+, assertions and exactly the independently reserved prerequisite CPU')
    need(re.fullmatch('[0-9a-f]{40}', args.expect_revision) and
         all(re.fullmatch('[0-9a-f]{64}', x) for x in (args.archive_receipt_sha256,
             args.ret_owner_receipt_sha256, args.return_heads_receipt_sha256)),
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
    r = dict(schema=1, profile='public-direct-call-components-native-v1',
             status='failed', revision=args.expect_revision, source=None,
             source_unchanged=False, inputs_unchanged=False, cleanup_complete=False,
             cpu=cpu, hardware=hardware(cpu), bounds=BOUNDS, commands=[], result=None,
             scope='Fifteen full components plus24 additive native E8 pairs; original-nine and return-head owner are retained prerequisites, no owner execution here',
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
        return path.resolve(strict=True)

    def closure():
        need(all(fact(p) == value for p, value in pins.items()), 'all inputs unchanged')
        need(all(str(Path(p).resolve(strict=True)) == value for p, value in aliases.items()),
             'all resolved aliases unchanged')
        need(all(fact(p) == value for p, value in artifacts.items()), 'all artifacts unchanged')
        need(all(Path(p).is_symlink() and os.readlink(p) == value for p, value in links.items()),
             'all private context links unchanged')
        need(all(Path(p).exists() == value for p, value in presence.items()), 'loader configuration presence')
        need(sorted(os.sched_getaffinity(0)) == [cpu], 'reserved CPU unchanged')

    def run(name, argv, profile='build', env=None):
        nonlocal stage
        stage = name
        closure()
        need(not any(row['name'] == name for row in r['commands']), 'unique command, no retry')
        row = dict(name=name, argv=list(map(str, argv)), bounds=BOUNDS[profile],
                   profile=profile, capture_limit=16 << 20, environment=dict(ENV if env is None else env), expected_exit=0)
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
        bind_maps_sources(pin)
        manifest = load(pin(HERE/'SOURCE.json'))
        for name, wanted in manifest['inputs'].items():
            need(historical(ROOT/name,wanted,fact(pin(ROOT/name))) == wanted, 'whole frozen source leaf: '+name)
        for name,wanted in manifest['artifacts'].items():
            need(historical(HERE/name,wanted,fact(pin(HERE/name)))==wanted,'whole frozen collector artifact: '+name)
        selected=ROOT/'tools/page-entry/selected'
        r['context_links']=links
        from call_owner.custody import check_archive
        from cached_ret_prerequisite import check as original_check
        def module(name,path):
            path=pin(path);spec=importlib.util.spec_from_file_location(name,path)
            need(spec is not None and spec.loader is not None,'exact source-owned helper loader')
            value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value
        from direct_call_native import return_heads
        components=module('direct_e8_components',HERE/'components.py')
        for module_value in tuple(sys.modules.values()):
            name = getattr(module_value, '__file__', None)
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
        r['ret_owner_prerequisite']=original_check(args.ret_owner_receipt,
            args.ret_owner_receipt_sha256,r,pin,pin,archive,build)
        r['return_heads_prerequisite']=return_heads.check(args.return_heads_receipt,
            args.return_heads_receipt_sha256,r,pin,pin,archive,build)
        r['prerequisites']=dict(original_nine=r['ret_owner_prerequisite'],
                              return_heads=r['return_heads_prerequisite'])
        r['archive_reuse'] = dict(receipt=fact(pin(args.archive_receipt)),
            archive=fact(archive), release_build=build, environment=archive_environment,
            fresh_build=False, source_tools_features_verified=True, qualification_credit=False)
        fixture = selected/'tests/direct_call_native'
        tools = {name: pin(shutil.which(name, path=ENV['PATH'])) for name in ('cc','nm','readelf','git','sh')}
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
        tools['python']=python
        r['tools'] = {name: str(path) for name, path in tools.items()}
        for name in ('cc','cc1','collect2','as','ld','nm','readelf','python'):
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
        builder=SimpleNamespace(paths={'archive':archive},tools=tools,environment=archive_environment)
        def owned_run(label,argv,profile='release_build',env=None):
            out,err=run(label,argv,profile,env)
            return r['commands'][-1],out,err
        components.run_all(builder,selected,private,manifest,pin,artifact,owned_run,r)
        for module_value in tuple(sys.modules.values()):
            name=getattr(module_value,'__file__',None)
            if name and Path(name).is_file():pin(name)
        closure()
        output = private/'direct-call-native'
        recipe = pin(fixture/'build.sh').read_text().replace('\\\n', ' ')
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
        assembly=private/'probe_assembly.S'
        assembly.symlink_to(pin(fixture/'probe.S'));links[str(assembly)]=str(pin(fixture/'probe.S'))
        need(assembly.is_symlink() and fact(pin(assembly))==fact(pin(fixture/'probe.S')),
             'byte-exact assembly alias avoids retained object-name collision')
        original_native_argv=list(compile_argv)
        compile_argv[compile_argv.index(str(fixture/'probe.S'))]=str(assembly)
        tus[1]=str(assembly)
        r['recipe'] = dict(file=fact(pin(fixture/'build.sh')), argv=compile_argv,
                          original_argv=original_native_argv,
                          diagnostic_only_additions=['-save-temps=obj','-Wl,--trace'])
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
        out, err = run('build', compile_argv[:-2]+r['recipe']['diagnostic_only_additions']+compile_argv[-2:])
        need(not err, 'strict exact native compiler/linker stderr empty')
        objects=set()
        for unit in tus:
            stem='direct-call-native-'+Path(unit).stem
            for suffix in (('.s','.o') if unit.endswith('.S') else ('.i','.s','.o','.su')):
                artifact(private/(stem+suffix))
            objects.add(str(private/(stem+'.o')))
        trace=out.decode().splitlines()
        need(trace and all(Path(x).is_absolute() for x in trace),'whole absolute native link trace')
        linked={str(Path(x).resolve(strict=True)) for x in trace}
        need(objects|{str(archive)}<=linked<=link_inputs|objects,
             'all native generated objects and only prebound actual link inputs')
        r['linked_inputs']=sorted(linked)
        artifact(output)
        r['binary'] = fact(output)
        need(int(fact(output)['mode'], 8) & 0o111, 'fresh executable output')
        out,err=run('native-providers',[tools['nm'],'-g','--defined-only',output])
        names=[m[1] for line in out.decode().splitlines()
               if (m:=re.fullmatch(r'[0-9a-fA-F]+ T (\S+)',line))]
        required=('li2_cd_describe','li2_cd_direct_target','li2_cd_emit','li2_cd_validate','li2_cd_recover')
        need(not err and all(names.count(name)==1 for name in required),
             'all exact typed direct-CALL providers in the actual native binary')
        r['native_providers']=dict(required=list(required),bytes=len(out),sha256=hashlib.sha256(out).hexdigest())
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
        for chunk in range(2):
            name = 'native-'+str(chunk)
            out, err = run(name, [output, str(chunk)], 'native')
            row = r['commands'][-1]
            need(not err and 576 <= len(out) < 16 << 20, 'whole bounded native comparison capture')
            h = struct.unpack_from('<64Q', out)
            count = 12
            need(h[:4] == (0x314e454432494c,1,512,362864) and
                 h[10:17] == (24,chunk,12*chunk,count,2*count,row['pid'],cpu) and
                 h[28:30] == (inspected['reload_address'],inspected['scratch_end_address']) and
                 len(out) == 512+2*count*362864+64,
                 'actual collector PID/CPU/ELF-bootstrap and exact native chunk joins')
            chunks.append(private/row['captures']['stdout']['file'])
            chunk_rows.append(dict(chunk=chunk,pid=row['pid'],cpu=cpu,
                 duration_ns=row['duration_ns'],capture=row['captures']['stdout']))
        r['native_chunks'] = chunk_rows
        out, err = run('read-all-chunks', [python,'-I','-S','-B',fixture/'read.py',
             '--expect-cpu',str(cpu),'--expect-pids',*[str(row['pid']) for row in chunk_rows],*chunks], 'native')
        need(not err, 'complete independent native reader stderr empty')
        observed = json.loads(out, object_pairs_hook=unique)
        need(observed['cpu'] == cpu and len(observed['sources']) == 2, 'complete native reader source roster')
        for source_row, child in zip(observed['sources'], chunk_rows):
            need(source_row == dict(chunk=child['chunk'],pid=child['pid'],
                 bytes=child['capture']['bytes'],sha256=child['capture']['sha256']),
                 'all independent reader inputs join actual process PID and whole captures')
        native_result=native_compact(observed)
        r['result']=dict(components={k:v['result'] for k,v in r['components'].items()},
            component_cohorts=15,native=native_result,owner_subjects=0,
            original_nine_subjects_replayed=0,return_heads_subjects_replayed=0,
            qualification_credit=False,performance_credit=False)
        need([row['name'] for row in r['commands']]==manifest['commands'],
             'complete fixed component and native schedule, no retries or omitted gates')
        r['emitted_execution'] = 24
        r['status'] = 'passed'
    except BaseException as error:
        r['error'] = type(error).__name__+': '+str(error)
    finally:
        try:
            for path in (private/'direct-call-native', *private.glob('direct-call-native-*'),
                         *(private/'components').rglob('*')):
                if path.is_file() and not path.is_symlink():artifact(path)
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
        pending=['actual E8 owner callee/return-head and external miss proof', 'whole392/522 qualification',
                 'warm reuse and real-program completion/performance'],
        source_unchanged=r['source_unchanged'], inputs_unchanged=r['inputs_unchanged'],
        cleanup_complete=r['cleanup_complete'], failed_stage=stage if r['status']=='failed' else None,
        final_error_count=len(r['final_errors']), receipt=fact(receipt), binary=r.get('binary'),
        reproducer=str(Path(__file__).resolve().relative_to(ROOT)),
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
