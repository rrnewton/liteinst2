#!/usr/bin/env python3
"""Two compile-only RET runtime profiles; no bridge or generated execution."""
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
HERE = Path(__file__).resolve().parent
ROOT = next(p for p in HERE.parents if (p/'evaluation/inprocess/page_selected_process.py').is_file())
BOUNDS = [30, 512 << 20, 16 << 20, 60]


def need(ok, message):
    if not ok:
        raise ValueError(message)


def fact(path):
    path = Path(path)
    need(path.is_file() and not path.is_symlink(), 'regular whole input: '+str(path))
    b = path.read_bytes()
    return dict(bytes=len(b), sha256=hashlib.sha256(b).hexdigest(), mode=format(stat.S_IMODE(path.stat().st_mode), '04o'))


def value(data):
    return dict(bytes=len(data), sha256=hashlib.sha256(data).hexdigest())


def unique(pairs):
    result = dict(pairs)
    need(len(result) == len(pairs), 'duplicate JSON field')
    return result


def load(path):
    return json.loads(Path(path).read_bytes(), object_pairs_hook=unique)


def image_identity(data):
    def take(at, count):
        need(type(at) is int and type(count) is int and 0 <= at <= len(data) and
             0 <= count <= len(data)-at, 'whole dynamic ELF input range')
        return data[at:at+count]
    h = struct.unpack('<16sHHIQQQIHHHHHH', take(0, 64))
    need(h[0][:7] == b'\x7fELF\x02\x01\x01' and h[1] in (2, 3) and h[2:4] == (62, 1) and
         h[8:10] == (64, 56) and 0 < h[10] <= 128, 'bounded original x86-64 ET_EXEC or ET_DYN')
    program = take(h[5], h[10]*56)
    loads = [struct.unpack('<IIQQQQQQ', program[i*56:(i+1)*56]) for i in range(h[10])]
    loads = [row for row in loads if row[0] == 1]
    need(loads and all(row[5] <= row[6] and row[3] < 1 << 47 and row[6] <= (1 << 47)-row[3]
                       and row[1] & ~7 == 0 for row in loads), 'bounded actual LOAD extents and flags')
    for row in loads:
        take(row[2], row[5])
    need(any(row[1] & 1 and row[3] <= h[4] < row[3]+row[5] for row in loads),
         'actual ELF entry belongs to a file-backed executable LOAD')
    return dict(image=value(data), elf_type=h[1], entry=h[4], load_count=len(loads),
                program_headers=value(program))


def provider_functions(data, nm_text, expected):
    """Join every required local function to the complete ELF and nm census."""
    def take(at, count):
        need(0 <= at <= len(data) and 0 <= count <= len(data)-at, 'bounded whole ELF provider range')
        return data[at:at+count]
    h = struct.unpack('<16sHHIQQQIHHHHHH', take(0,64))
    need(h[0][:7] == b'\x7fELF\2\1\1' and h[1:4] == (3,62,1) and
         h[8:10] == (64,56) and h[11] == 64 and 0 < h[10] <= 128 and 0 < h[12] <= 4096,
         'exact ELF64 shared bridge and bounded complete section/program tables')
    sections = [struct.unpack('<IIQQQQIIQQ', take(h[6]+64*i,64)) for i in range(h[12])]
    loads = [struct.unpack('<IIQQQQQQ', take(h[5]+56*i,56)) for i in range(h[10])]
    tables = [x for x in sections if x[1] == 2]
    need(len(tables) == 1, 'one complete static symbol table including localized providers')
    t = tables[0]
    need(t[9] == 24 and t[5] % 24 == 0 and 0 < t[6] < len(sections), 'whole symbol records/string-table index')
    names_row = sections[t[6]]
    need(names_row[1] == 3, 'actual symbol string table')
    names = take(names_row[4],names_row[5]); table = take(t[4],t[5]); symbols = {}
    for at in range(0,len(table),24):
        name, info, other, section, address, size = struct.unpack_from('<IBBHQQ',table,at)
        need(name < len(names) and b'\0' in names[name:], 'bounded NUL-terminated symbol name')
        name = names[name:names.index(b'\0',name)].decode('ascii')
        if name in expected:
            need(name not in symbols, 'one exact definition of every required provider')
            need(info == 2 and other == 0 and 0 < section < len(sections) and size > 0,
                 'actual LOCAL STT_FUNC definition with nonzero body, not UNDEF/ABS/COMMON or object')
            s = sections[section]
            need(s[1] == 1 and s[2] & 7 == 6 and s[3] <= address and size <= s[3]+s[5]-address,
                 'whole provider body in allocated executable nonwritable PROGBITS')
            executable = [x for x in loads if x[0] == 1 and x[1] == 5 and x[5] <= x[6] and
                          x[3] <= address and size <= x[3]+x[5]-address]
            need(len(executable) == 1, 'whole provider body in one actual file-backed RX LOAD')
            load = executable[0]; offset = s[4]+address-s[3]
            need(offset == load[2]+address-load[3], 'section and executable LOAD agree on actual function bytes')
            symbols[name] = dict(address=address,bytes=size,binding=0,type=2,visibility=0,section=section,
                                 file_offset=offset,sha256=hashlib.sha256(take(offset,size)).hexdigest())
    need(len(expected) == 67 and len(set(expected)) == 66 and set(symbols) == set(expected),
         'all58 original entries plus9 RET entries, all66 unique actual functions')
    observed = {}
    for line in nm_text.decode('ascii').splitlines():
        match = re.fullmatch(r'([0-9a-fA-F]+) ([A-Za-z?]) (\S+)',line)
        need(match is not None, 'complete defined-symbol nm row grammar')
        if match[3] in symbols:
            need(match[3] not in observed and match[2] == 't' and
                 int(match[1],16) == symbols[match[3]]['address'], 'nm actual local text symbol joins ELF function')
            observed[match[3]] = int(match[1],16)
    need(set(observed) == set(symbols), 'complete nm and ELF provider sets agree')
    return symbols


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--expect-revision', required=True)
    ap.add_argument('--output', type=Path, required=True)
    for name in ('archive','call-owner'):
        ap.add_argument('--'+name+'-receipt', type=Path, required=True)
        ap.add_argument('--'+name+'-receipt-sha256', required=True)
    args = ap.parse_args()
    m = load(HERE/'SOURCE.json')
    need(sys.version_info >= (3, 11) and not sys.flags.optimize and sorted(os.sched_getaffinity(0)) == [3],
         'Python3.11+, assertions and one independently reserved CPU3')
    need(re.fullmatch(r'[0-9a-f]{40}', args.expect_revision) is not None, 'explicit exact current revision')
    private = args.output.resolve()
    need(private.is_relative_to((ROOT/'target/evaluation/inprocess').resolve(strict=True)) and not private.exists(),
         'fresh exclusive private compile attempt')
    for name, wanted in m['inputs'].items():
        need(fact(ROOT/name) == wanted, 'exact frozen input: '+name)
    for name, wanted in m['artifacts'].items():
        need(fact(HERE/name) == wanted, 'exact collector artifact: '+name)
    sys.path.insert(0, str(ROOT/'evaluation/inprocess'))
    from checks import source
    from run import hardware
    from page_selected import ENV, save
    from page_selected_process import invoke
    from call_owner import custody
    from ret_owner import prerequisites
    os.chdir(ROOT)
    private.mkdir()
    receipt = private/'receipt.json'
    pins, aliases, artifacts, links, presence = {}, {}, {}, {}, {}
    r = dict(schema=1, profile='public-ret-runtime-compile-v1', status='failed',
             revision=args.expect_revision, source=None, cpu=3, hardware=hardware(3), bounds=BOUNDS,
             commands=[], profiles={}, error=None, final_errors=[], source_unchanged=False,
             inputs_unchanged=False, cleanup_complete=False, archive_builds=0,
             subject_executions=0, qualification_credit=False, performance_credit=False,
             pending=['full mandatory byte oracle', 'actual composed owner entry/lifetime/stack authority',
                      'actual pending RET/fault/nested/root-and-interior custody', 'whole392/522 qualification', 'real LS/true outcomes'])

    def pin(path):
        alias = Path(path).absolute(); resolved = alias.resolve(strict=True); f = fact(resolved)
        need(str(alias) not in aliases or aliases[str(alias)] == str(resolved), 'stable input alias')
        need(str(resolved) not in pins or pins[str(resolved)] == f, 'stable whole input')
        aliases[str(alias)] = str(resolved); pins[str(resolved)] = f
        return resolved

    def artifact(path):
        path = Path(path)
        need(path.is_relative_to(private), 'private artifact containment')
        f = fact(path)
        need(str(path) not in artifacts or artifacts[str(path)] == f, 'immutable completed artifact')
        artifacts[str(path)] = f
        return f

    def closure():
        need(all(fact(p) == f for p, f in pins.items()), 'all input/source/tool bytes and modes unchanged')
        need(all(str(Path(p).resolve(strict=True)) == q for p, q in aliases.items()), 'all aliases unchanged')
        need(all(fact(p) == f for p, f in artifacts.items()), 'all completed artifacts unchanged')
        need(all(Path(p).is_symlink() and os.readlink(p) == q for p, q in links.items()), 'all context links unchanged')
        need(all(Path(p).exists() == v for p,v in presence.items()), 'loader configuration presence unchanged')
        need(sorted(os.sched_getaffinity(0)) == [3], 'same reserved CPU3')

    def run(name, argv):
        closure()
        need(not any(x['name'] == name for x in r['commands']), 'one command per stage, no retries')
        argv = list(map(str, argv))
        executable = Path(argv[0]).resolve(strict=True)
        need(executable in {tools[x] for x in ('cc','nm','readelf','as','ld') if x in tools},
             'only bound compiler/metadata tools; never run a binder, archive build or produced bridge')
        row = dict(name=name, argv=argv, bounds=BOUNDS, capture_limit=16 << 20,
                   environment=dict(ENV), expected_exit=0)
        r['commands'].append(row); save(receipt, r)
        try:
            out, err = invoke(row, private, 3)
        finally:
            for f in row.get('captures', {}).values():
                q = private/f['file']; a = artifact(q)
                need({k: a[k] for k in ('bytes','sha256')} == {k: f[k] for k in ('bytes','sha256')}, 'whole post-reap capture')
            q = private/(name+'.json')
            if q.is_file(): artifact(q)
            save(receipt, r)
        need(row['exit'] == 0 and row['reaped'] and not row['cleanup_errors'] and not row['timed_out'],
             'exact completed owned command: '+name)
        return out, err

    try:
        r['source'] = source()
        need(r['source']['revision'] == args.expect_revision, 'clean reviewed source')
        for q in (HERE/'SOURCE.json', *[HERE/x for x in m['artifacts']], *[ROOT/x for x in m['inputs']]): pin(q)
        for module in tuple(sys.modules.values()):
            q = getattr(module, '__file__', None)
            if q and Path(q).resolve().is_relative_to(ROOT): pin(q)
        selected = private/'context/tools/page-entry/selected'; selected.mkdir(parents=True)
        context = []
        for directory,names in m['source_roster'].items():
            for name in names:
                relative = str(Path(directory)/name)
                need(not Path(relative).is_absolute() and '..' not in Path(relative).parts,
                     'contained installed source roster')
                context.append(dict(origin=relative,destination=relative))
        for row in context:
            q = pin(ROOT/row['origin']); target = private/'context'/row['destination']
            need(target.is_relative_to(private/'context') and not target.exists(),
                 'unique exact context destination')
            target.parent.mkdir(parents=True, exist_ok=True)
            target.symlink_to(q); links[str(target)] = str(q)
        r['composition'] = dict(context_files=len(context), regular_copies=0,
                                source_manifest=fact(HERE/'SOURCE.json'), tracked_changes=0)
        need(len({x['destination'] for x in context}) == len(context), 'unique complete source context')
        archive_path = pin(args.archive_receipt)
        archive,build,environment,exports,prior = custody.check_archive(
            archive_path,args.archive_receipt_sha256,r,pin)
        call_path = pin(args.call_owner_receipt)
        r['call_owner_prerequisite'] = prerequisites.call_owner(
            call_path,args.call_owner_receipt_sha256,r,pin,archive,build)
        call = load(call_path)
        app = prerequisites.row(call,'app-link')
        image = pin(call['application_build']['argv'][-1])
        need(app['argv'] == call['application_build']['argv'] and app['argv'][-1] == str(image) and
             fact(image) == call['artifacts'][str(image)] and
             value(image.read_bytes()) == call['application_build']['artifact'],
             'actual complete current CALL prerequisite application image, never executed here')
        r['original_image'] = dict(path=str(image),**fact(image))
        for old in (prior,call):
            for name,wanted in old['loader_presence'].items():
                need(Path(name).exists() == wanted, 'same actual loader configuration presence')
                need(name not in presence or presence[name] == wanted,'same prerequisite loader observations')
                presence[name] = wanted
        need(not presence.get('/etc/ld.so.preload', False), 'no global preload')
        need(build['status'] == 'passed' and build['command_completed'] is True and
             build['configuration_unchanged'] is True and build['final_errors'] == [] and
             build['decoder_features'] == ['scalar-region','scalar-span','linked-epoch','mov-guard'], 'actual decoder build/features')
        need(set(build['dep_info']) == set(m['decoder_sources']) and len(build['dep_info']) == 10, 'complete ten-source decoder closure')
        for name,wanted in build['dep_info'].items():
            q = pin(ROOT/name)
            need(value(q.read_bytes()) == wanted and fact(q) == prior['inputs'][str(q)], 'same compiled decoder source')
        for name in ('Cargo.toml','Cargo.lock'):
            q = pin(ROOT/'tools/page-entry/selected/decoder'/name)
            need(fact(q) == prior['inputs'][str(q)], 'same decoder manifest/lock')
        tools = {name: pin(shutil.which(name, path=ENV['PATH'])) for name in ('cc','nm','readelf')}
        tools['python'] = pin(sys.executable)
        for name in ('cc1','collect2','as','ld'):
            out, err = run('resolve-'+name, [tools['cc'], '-print-prog-name='+name]); text = out.decode().strip()
            need(text and not err, 'actual compiler subtool')
            tools[name] = pin(text if Path(text).is_absolute() else shutil.which(text, path=ENV['PATH']))
        for name in ('cc','cc1','collect2','as','ld','nm','readelf'):
            need(value(tools[name].read_bytes()) == {k: build['tools'][name][k] for k in ('bytes','sha256')}, 'same retained compiler/tool')
        for name in ('cc','as','ld','nm','readelf'):
            out, err = run('version-'+name, [tools[name], '--version']); need(out and not err, 'actual tool version')
        _, err = run('compiler-specs', [tools['cc'], '-dumpspecs']); need(not err, 'compiler specs stderr')
        out, err = run('archive-exports', [tools['nm'], '-g', '--defined-only', archive])
        need(not err and out == exports, 'whole retained archive exports')
        r['archive_reuse'] = dict(receipt=fact(archive_path), archive=fact(archive), build=build,
                                 fresh_build=False, source_tools_features_verified=True, prior_status=prior['status'],
                                 prior_owner_credit=False)
        r['tools'] = {k: str(v) for k,v in tools.items()}
        original = image_identity(image.read_bytes())
        for mode in ('release','differential'):
            output = private/mode; output.mkdir()
            suffix = '' if mode == 'release' else '-'+mode
            recipe = selected/m['recipes'][mode]['name']
            text = recipe.read_text().replace('\\\n',' ')
            lines = [line.strip() for line in text.splitlines() if line.strip().startswith('"$cc_bin" ')]
            need(len(lines) == 1 and '"${LI2_PYTHON:-python3}"' not in text and
                 all(text.count('test -f "$output/'+name+'"') == 1 for name in
                     ('persistent_ret_compile_binding.json','linked_epoch_config.h','persistent_group_config.h')),
                 'one exact compiler recipe, all three independently generated binding outputs required')
            sources = []
            for name in m['policy'][mode]:
                q = Path(os.path.normpath(selected/name))
                need(str(q) in links and q.is_symlink() and str(q.resolve(strict=True)) == links[str(q)],
                     'policy source is one authenticated immutable context alias')
                sources.append(dict(path=name, **value(pin(q).read_bytes())))
            need(len(sources) == len({x['path'] for x in sources}), 'distinct complete RET policy inputs')
            policy = hashlib.sha256(json.dumps(dict(sources=sources,original=original,mode=mode),sort_keys=True,separators=(',',':')).encode()).hexdigest()
            expected = dict(version=1,profile='private-persistent-ret-compile-'+mode+'-v1',mode=mode,native_probe=True,parse_memo=True,
                            unregistered=True,subentry=True,cross_pair=True,direct_frontier=True,call_dispatch=True,ret_dispatch=True,
                            maps_differential=mode=='differential',typed_capture=False,compile_only=True,archive=value(archive.read_bytes()),
                            policy_sha256=policy,original=original,sources=sources)
            literal = lambda s: '{'+','.join('0x'+s[i:i+2] for i in range(0,64,2))+'}'
            headers = {
                'linked_epoch_config.h':'#ifndef LI2_LINKED_EPOCH_CONFIG_H\n#define LI2_LINKED_EPOCH_CONFIG_H\n#define LI2_LINK_BINDING_VERSION 1\n#define LI2_LINK_ARCHIVE_SHA256 '+literal(expected['archive']['sha256'])+'\n#define LI2_LINK_POLICY_SHA256 '+literal(policy)+'\n#endif\n',
                'persistent_group_config.h':'#ifndef LI2_PERSISTENT_GROUP_CONFIG_H\n#define LI2_PERSISTENT_GROUP_CONFIG_H\n#define LI2_PG_BINDING_VERSION 1\n#define LI2_PG_GROUP_BINDING_VERSION 4\n#define LI2_PG_ARCHIVE_SHA256 '+literal(expected['archive']['sha256'])+'\n#define LI2_PG_POLICY_SHA256 '+literal(policy)+'\n#endif\n'}
            expected['headers'] = {name:value(data.encode()) for name,data in headers.items()}
            for name,data in headers.items():
                with (output/name).open('x') as stream: stream.write(data)
                need((output/name).read_bytes() == data.encode(), 'whole generated configuration bytes'); artifact(output/name)
            binding_path = output/'persistent_ret_compile_binding.json'
            with binding_path.open('x') as stream: stream.write(json.dumps(expected,sort_keys=True)+'\n')
            need(load(binding_path) == expected, 'complete independently generated RET composition binding')
            artifact(binding_path)
            binding = expected
            replacements = {'$cc_bin':tools['cc'],'$selected_dir':selected,'$parent_dir':selected.parent,
                            '$archive':archive,'$output':output}
            argv = []
            for word in shlex.split(lines[0]):
                for key,v in replacements.items(): word = word.replace(key,str(v))
                need('$' not in word and '`' not in word, 'closed literal compiler argv'); argv.append(word)
            tus = [str(selected.parent/name) for name in m['translation_units']]
            bridge = output/('bridge-persistent-ret'+suffix+'.so')
            need([x for x in argv if x.endswith(('.c','.S'))] == tus and len(tus) == 28 and
                 [x for x in argv if x.endswith('.a')] == [str(archive)] and argv[-2:] == ['-o',str(bridge)],
                 'exact27 original translation units plus RET TU/archive/output')
            flags = [x for x in argv[1:-2] if x not in tus and x != str(archive) and not x.startswith(('-Wl,','-l'))]
            out, err = run(mode+'-headers', [tools['cc'],*flags,'-M','-MT','ret_runtime',*tus])
            rules = out.decode().replace('\\\n',' ').splitlines()
            need(not err and len(rules) == 28 and all(x.startswith('ret_runtime: ') for x in rules), 'all28 complete actual compiler-M rules')
            observed = {str(pin(x)) for rule in rules for x in shlex.split(rule.split(':',1)[1])}
            required = {str(Path(x).resolve()) for x in tus} | {str((selected/x).resolve()) for x in m['required_headers']} | {str(output/x) for x in headers}
            need(required <= observed, 'complete actual typed CALL+RET/owner/pending/planner/config dependency closure')
            composed = {str((ROOT/x['origin']).resolve(strict=True)) for x in context} | {str(output/x) for x in headers}
            need({x for x in observed if Path(x).is_relative_to(ROOT)} <= composed,
                 'compiler used only the declared composed local sources and generated headers')
            before_inputs = {x:pins[x] for x in sorted(observed)}
            out, err = run(mode+'-build', argv)
            need(not out and not err, 'strict original compiler/linker output')
            artifact(bridge); image_identity(bridge.read_bytes())
            data = bridge.read_bytes(); eh = struct.unpack_from('<16sHHIQQQIHHHHHH',data)
            ph = [struct.unpack_from('<IIQQQQQQ',data,eh[5]+i*56) for i in range(eh[10])]
            need(eh[1] == 3 and not any(x[0] == 3 for x in ph) and
                 all(x[1]&3 != 3 for x in ph if x[0] == 1) and
                 sum(x[0] == 0x6474e551 and x[1] == 6 for x in ph) == 1, 'actual shared bridge, no interpreter, W^X LOADs and nonexecuting stack')
            out, err = run(mode+'-undefined', [tools['nm'],'-u',bridge]); need(not out and not err, 'no unresolved bridge symbols')
            out, err = run(mode+'-providers', [tools['nm'],'--defined-only',bridge]); need(not err, 'whole provider census')
            providers = re.findall(r'--undefined=([^,\\\s]+)',lines[0])
            need(providers == m['providers'], 'all old providers and all explicit RET additions in exact order')
            symbols = provider_functions(data,out,providers)
            out, err = run(mode+'-elf', [tools['readelf'],'-W','-h','-l','-d',bridge]); need(out and not err and '(NEEDED)' not in out.decode(), 'actual full bridge ELF/dynamic closure')
            need(all(fact(q) == f for q,f in before_inputs.items()), 'same whole compiler-M inputs after link')
            r['profiles'][mode] = dict(status='compile_only_passed',recipe=fact(recipe.resolve()),argv=argv,
                                      binding=binding,headers=sorted(observed),bridge=fact(bridge),providers=providers,provider_functions=symbols,
                                      mandatory_byte_oracle_executed=False,typed_capture=False,owner_credit=False)
            save(receipt,r)
        for module in tuple(sys.modules.values()):
            q = getattr(module, '__file__', None)
            if q and Path(q).is_file(): pin(q)
        need(list(r['profiles']) == ['release','differential'], 'both fixed maintained and differential compile profiles')
        r['status'] = 'compile_only_passed'
    except BaseException as error:
        r['error'] = type(error).__name__+': '+str(error)
    finally:
        for mode in ('release','differential'):
            output = private/mode
            if output.is_dir():
                for q in output.iterdir():
                    if q.is_file() and not q.is_symlink():
                        try: artifact(q)
                        except BaseException as error: r['final_errors'].append('partial-artifact: '+repr(error))
        try: closure(); r['inputs_unchanged'] = True
        except BaseException as error: r['final_errors'].append('inputs: '+repr(error))
        try:
            need(source() == r['source'], 'whole tracked source unchanged'); r['source_unchanged'] = True
        except BaseException as error: r['final_errors'].append('source: '+repr(error))
        r['cleanup_complete'] = all(x.get('reaped') and not x.get('cleanup_errors') and
                                   all(d['closed'] for d in x.get('descriptors',[])) for x in r['commands'])
        if r['error'] or r['final_errors'] or not all(r[k] for k in ('inputs_unchanged','source_unchanged','cleanup_complete')):
            r['status'] = 'failed'
        r.update(inputs=pins,aliases=aliases,artifacts=artifacts,context_links=links,loader_presence=presence)
        save(receipt,r)
    print(json.dumps(dict(status=r['status'],compiled=list(r['profiles']),subject_executions=0,
                         qualification_credit=False,receipt=str(receipt.relative_to(ROOT))),sort_keys=True))
    return int(r['status'] != 'compile_only_passed')


if __name__ == '__main__':
    raise SystemExit(main())
