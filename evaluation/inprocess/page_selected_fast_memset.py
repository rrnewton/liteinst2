#!/usr/bin/env python3
"""Exact scalar/REP-STOSB primitive oracle; production runtime remains scalar."""
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import shlex
import shutil
import sys
sys.dont_write_bytecode = True
from checks import source
from run import hardware
from page_selected import ENV, elf, fact, need, save
from page_selected_generic_build import PROFILES as BUILD_PROFILES
from page_selected_process import invoke

ROOT = Path(__file__).resolve().parents[2]
SELECTED = ROOT/'tools/page-entry/selected'
FIXTURE = SELECTED/'tests/fast_memset'
BOUNDS = dict(BUILD_PROFILES, native=[5, 512 << 20, 16 << 20, 15])
NATIVE = [('scalar-functional', 'scalar', False), ('fast-functional', 'fast', False),
          ('scalar-measured-1', 'scalar', True), ('fast-measured-1', 'fast', True),
          ('fast-measured-2', 'fast', True), ('scalar-measured-2', 'scalar', True)]


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()


def decode(raw):
    def unique(items):
        d = {}
        for k, v in items:
            need(k not in d, 'duplicate metadata key');d[k] = v
        return d
    def invalid(_):
        raise ValueError('nonfinite metadata')
    return json.loads(raw, object_pairs_hook=unique, parse_constant=invalid)


def symbol(text, name, kinds):
    rows = [line.split() for line in text.decode().splitlines() if line.split()[-1:] == [name]]
    need(len(rows) == 1 and len(rows[0]) == 4 and rows[0][2] in kinds, 'one actual symbol '+name)
    return int(rows[0][0], 16), int(rows[0][1], 16)


def layout_check(value, record_size):
    need(set(value) == {'slot_bytes', 'record', 'row'} and type(value['slot_bytes']) is int and
         1 < value['slot_bytes'] <= 1024*1024, 'actual bounded slot DWARF')
    head = 'magic version bytes status error completed slot_bytes measured iterations samples'.split()
    rf = {name: dict(offset=i*8, bytes=8) for i, name in enumerate(head)}
    rf.update(rows=dict(offset=80, bytes=273*136), nanoseconds=dict(offset=37208, bytes=64))
    names = 'ordinal length extent offset fill checked return_ok df_before df_after'.split()
    row = {name: dict(offset=i*8, bytes=8) for i, name in enumerate(names)}
    row.update(before=dict(offset=72, bytes=32), after=dict(offset=104, bytes=32))
    need(value['record'] == dict(bytes=37272, fields=rf) and record_size == 37272 and
         value['row'] == dict(bytes=136, fields=row), 'all actual ELF/DWARF record offsets')
    need(all(type(v['bytes']) is int and all(type(x) is int for f in v['fields'].values() for x in f.values())
             for v in (value['record'], value['row'])), 'integer DWARF values, no Boolean aliases')
    return value['slot_bytes']


def body_check(path, symbols, text, mode, symbol_name='li2_test_memset'):
    need(mode in ('scalar','fast'), 'closed primitive mode')
    address, size = symbol(symbols, symbol_name, 'Tt')
    data, head, ph = elf(path)
    need(head[1] in (2, 3) and any(p[0] == 1 and p[1]&1 and p[3] <= head[4] < p[3]+p[6] for p in ph),
         'actual hosted executable entry')
    need(all(p[0] != 1 or p[1]&3 != 3 for p in ph) and
         any(p[0] == 0x6474e551 and not p[1]&1 for p in ph), 'no WX or executable stack')
    owners = [p for p in ph if p[0] == 1 and p[1]&1 and p[3] <= address and address+size <= p[3]+p[5]]
    need(len(owners) == 1 and 0 < size <= 256, 'complete actual memset text owner')
    p = owners[0];raw = data[p[2]+address-p[3]:p[2]+address-p[3]+size]
    insns = []
    for line in text.decode().splitlines():
        m = re.fullmatch(r'\s*([0-9a-f]+):\s*((?:[0-9a-f]{2}\s)+)\s*(\S.*)', line)
        if m and address <= int(m[1], 16) < address+size:
            code, spelling = bytes.fromhex(m[2]), m[3].strip()
            # Binutils versions spell the same one-byte near return ret/retq.
            # Normalize only that authenticated opcode, not other return forms.
            if code == b'\xc3' and spelling == 'retq':spelling = 'ret'
            insns.append((int(m[1], 16), code, spelling))
    at = address
    for pc, b, _ in insns:
        need(pc == at and b, 'contiguous emitted instructions');at += len(b)
    need(at == address+size and b''.join(i[1] for i in insns) == raw, 'objdump equals full ELF bytes')
    need(insns and insns[-1][1] == b'\xc3', 'ordinary actual return')
    if mode == 'fast':
        regs = {r: ('initial', r) for r in ('rax','rbx','rcx','rdx','rsi','rdi','rbp','rsp')}
        regs.update({f'r{i}': ('initial', f'r{i}') for i in range(8, 16)})
        regs.update(rdi=('d',), rdx=('n',), rsi=('fill',))
        df = None;stores = 0
        reg32 = {'eax':'rax','ebx':'rbx','ecx':'rcx','edx':'rdx','esi':'rsi','edi':'rdi','ebp':'rbp','esp':'rsp'}
        reg32.update({f'r{i}d': f'r{i}' for i in range(8, 16)})
        for _, b, asm in insns:
            if b == b'\xfc':
                need(df is None and stores == 0, 'one CLD before REP');df = 0
            elif b == b'\xf3\xaa':
                need(df == 0 and stores == 0 and regs['rdi'] == ('d',) and regs['rcx'] == ('n',) and
                     regs['rax'] in (('fill',), ('low32', ('fill',))), 'actual AL/RDI/RCX input custody')
                stores += 1;regs['rdi'] = ('d+n',);regs['rcx'] = ('zero',)
            elif b == b'\xc3':
                need(stores == 1 and regs['rax'] == ('d',), 'original pointer returned')
            else:
                m = re.fullmatch(r'mov\s+%([a-z0-9]+),%([a-z0-9]+)', asm)
                need(m is not None, 'only register MOV around CLD/REP/RET')
                a, z = m.groups()
                if a in regs and z in regs:regs[z] = regs[a]
                else:
                    need(a in reg32 and z in reg32, 'exact MOV register widths')
                    regs[reg32[z]] = ('low32', regs[reg32[a]])
        need(all(regs[r] == ('initial', r) for r in ('rbx','rbp','rsp','r12','r13','r14','r15')),
             'actual callee-saved registers untouched')
    else:
        # This is the actual compiler-emitted scalar reference, not a copied
        # source substitute. Native whole-buffer comparisons remain mandatory.
        stores = [i for i in insns if re.fullmatch(r'mov\s+%(?:[abcd]l|[sd]il|r[0-9]+b),(?:-?0x[0-9a-f]+)?\(%[a-z0-9]+\)', i[2])]
        back = [i for i in insns if re.match(r'jne\s+[0-9a-f]+', i[2]) and
                address <= int(i[2].split()[1], 16) < i[0]]
        need(len(stores) == len(back) == 1 and
             all(i[2].split()[0] in ('mov','lea','test','je','nop','nopl','nopw','add','cmp','jne','ret') and
                 ('(' not in i[2] or i in stores or i[2].split()[0] in ('lea','nopl','nopw')) for i in insns) and
             all(i[1] != b'\xf3\xaa' for i in insns) and
             not re.search(r'\b(?:call|xmm[0-9]+|ymm[0-9]+|zmm[0-9]+)\b', '\n'.join(i[2] for i in insns)),
             'actual scalar byte-store/backedge with no call or vectors')
    return dict(address=address, bytes=size, code_hex=raw.hex(), sha256=hashlib.sha256(raw).hexdigest(),
                instructions=[dict(address=p, bytes=b.hex(), text=a) for p,b,a in insns])


def main():
    ap = argparse.ArgumentParser(description=__doc__);ap.add_argument('--expect-revision', required=True);args = ap.parse_args()
    need(not sys.flags.optimize and re.fullmatch('[0-9a-f]{40}', args.expect_revision), 'exact revision and enabled assertions')
    need(len(os.sched_getaffinity(0)) == 1, 'one externally reserved CPU')
    cpu = next(iter(os.sched_getaffinity(0)));os.chdir(ROOT)
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    name = stamp+'-page-selected-fast-memset-'+args.expect_revision[:12]
    private = ROOT/'target/evaluation/inprocess'/name;private.mkdir(parents=True, exist_ok=False)
    public = ROOT/'evaluation/inprocess/results'/(name+'.json')
    r = dict(version=1, profile='page-selected-fast-memset-v1', status='failed', expected_revision=args.expect_revision,
        started_utc=stamp, cpu=cpu, source=None, source_unchanged=False, commands=[], cases=[], error=None, final_errors=[],
        scope='Scalar versus opt-in REP STOSB primitive only; warm helper-call batches, no production enablement or real-program speed claim.',
        reproduce=['python3','evaluation/inprocess/page_selected_fast_memset.py','--expect-revision',args.expect_revision],
        build_status='not_started', rust_archive_used=False)
    pins, aliases, artifacts, modes, tools, versions, configurations = {}, {}, {}, {}, {}, {}, {}
    build = private/'build';env = dict(ENV)
    gdb_env = dict(env, XDG_CACHE_HOME=str(private/'gdb-cache'))
    def pin(path):
        need(path is not None, 'input/tool present');lexical = str(Path(path) if Path(path).is_absolute() else Path.cwd()/path)
        p = Path(lexical).resolve(strict=True)
        need(lexical not in aliases or aliases[lexical] == str(p), 'input alias unchanged');aliases[lexical] = str(p)
        v = fact(p);need(str(p) not in pins or pins[str(p)] == v, 'immutable input');pins[str(p)] = v;return p
    def binary(path):
        p = Path(path);need(p.is_file() and not p.is_symlink(), 'private regular artifact');v = fact(p)
        need(str(p) not in artifacts or artifacts[str(p)] == v, 'immutable artifact');artifacts[str(p)] = v
        mode = p.stat().st_mode & 0o777;need(str(p) not in modes or modes[str(p)] == mode, 'artifact mode');modes[str(p)] = mode
        return p
    def run(label, argv, profile='metadata', environment=None):
        need(all(Path(p).exists() == present for p,present in configurations.items()), 'loader configuration presence')
        need(all(str(Path(a).resolve(strict=True)) == p for a,p in aliases.items()), 'pre-command aliases')
        need(all(fact(p) == v for p,v in pins.items()) and all(fact(p) == v and Path(p).stat().st_mode & 0o777 == modes[p]
             for p,v in artifacts.items()), 'pre-command input/artifact closure')
        row = dict(name=label, argv=list(map(str,argv)), expected_exit=0, profile=profile, bounds=BOUNDS[profile],
                   capture_limit=65536 if profile == 'native' else 4 << 20, environment=dict(env if environment is None else environment))
        r['commands'].append(row);out,err = invoke(row, private, cpu)
        need(row['exit'] == 0, 'actual command exit '+label);return row,out,err
    try:
        r['source'] = source();need(r['source']['revision'] == args.expect_revision, 'clean committed source')
        r['hardware'] = hardware(cpu)
        for n in ('cc','sh','nm','readelf','objdump','gdb','git','dirname','mkdir'):
            tools[n] = pin(shutil.which(n, path=ENV['PATH']))
        tools['python'] = pin(sys.executable);env['LI2_CC'] = str(tools['cc'])
        for name in ('/etc/ld.so.cache','/etc/ld.so.preload'):
            configurations[name] = Path(name).exists()
            if configurations[name]:pin(name)
        need(not configurations['/etc/ld.so.preload'], 'no unrecorded global preload')
        _,out,err = run('source-paths', [tools['git'],'-C',ROOT,'ls-files','-z','tools/page-entry','evaluation/inprocess'])
        need(not err, 'source enumeration stderr')
        for path in out.split(b'\0'):
            if path and not os.fsdecode(path).startswith('evaluation/inprocess/results/'):pin(ROOT/os.fsdecode(path))
        for n in ('cc1','collect2','as','ld'):
            _,out,err = run('resolve-'+n, [tools['cc'],'-print-prog-name='+n]);value = out.decode().strip()
            need(value and not err, 'C subtool observation')
            tools[n] = pin(value if Path(value).is_absolute() else shutil.which(value,path=ENV['PATH']))
        for n in ('cc','python','gdb','objdump'):
            _,out,err = run('version-'+n,[tools[n],'--version'], environment=gdb_env if n == 'gdb' else None)
            need(not err, 'version stderr')
            m = re.search(r'\b([0-9]+)\.([0-9]+)(?:\.([0-9]+))?\b',out.decode())
            need(m is not None, 'actual numeric version');versions[n] = [int(m[1]),int(m[2]),int(m[3] or 0)]
        for name in ('crt1.o','Scrt1.o','crti.o','crtn.o','crtbegin.o','crtbeginS.o','crtend.o','crtendS.o','libgcc.a','libgcc_s.so','libc.so'):
            _,out,err = run('link-input-'+name,[tools['cc'],'-print-file-name='+name]);p = out.decode().strip()
            need(not err and Path(p).is_absolute(), 'actual C link input');pin(p)
        _,_,err = run('cc-specs',[tools['cc'],'-dumpspecs']);need(not err,'actual C specs stderr')
        # Expand the two actual frozen shell recipe lines, including mode and
        # explicit fast macro, to observe each exact preprocessing closure.
        recipe = pin(FIXTURE/'build-oracle.sh')
        lines = [x.strip() for x in recipe.read_text().replace('\\\n',' ').splitlines() if x.strip().startswith('"$cc_bin" ')]
        need(len(lines) == 2, 'exact bridge and oracle compiler lines')
        r['header_observations'] = []
        for mode in ('scalar','fast'):
            values = {'$cc_bin':str(tools['cc']),'$bridge_source':str(ROOT/'tools/page-entry/bridge.c'),
                '$selected_dir':str(SELECTED),'$parent_dir':str(SELECTED.parent),'$fixture_dir':str(FIXTURE),
                '$output_dir':str(build),'$mode':mode,'$extra':'-DLI2_FAST_MEMSET=1' if mode == 'fast' else ''}
            for i,line in enumerate(lines):
                argv = []
                for word in shlex.split(line):
                    for a,z in values.items():word = word.replace(a,z)
                    need('$' not in word and '`' not in word, 'closed compiler recipe')
                    if word:argv.append(word)
                need(argv[-2] == '-o' and argv[0] == str(tools['cc']), 'actual recipe compiler/output')
                sources = [x for x in argv[1:-2] if x.endswith('.c')]
                need(len(sources) == 1 and sources[0] == str(ROOT/'tools/page-entry/bridge.c' if i == 0 else FIXTURE/'oracle.c'), 'actual source TU')
                flags = [x for x in argv[1:-2] if x not in sources and not x.endswith('.o') and x != '-c' and not x.startswith('-Wl,')]
                need(('-DLI2_FAST_MEMSET=1' in flags) == (mode == 'fast' and i == 0), 'explicit opt-in compile command only')
                row,out,err = run('headers-'+mode+'-'+str(i),[tools['cc'],*flags,'-M','-MT','li2_headers',*sources])
                text = out.decode().replace('\\\n',' ');need(not err and text.startswith('li2_headers: ') and len(text.splitlines()) == 1, 'one exact header rule')
                deps = shlex.split(text.split(':',1)[1]);need(len(deps) == len(set(deps)) and sources[0] in deps and all(Path(p).is_absolute() for p in deps), 'complete lexical dependencies')
                observed = {p:dict(resolved=str(pin(p)),**fact(p)) for p in deps}
                need(any(p.endswith('/maps_phase.h') for p in deps), 'actual conditional profile header')
                r['header_observations'].append(dict(mode=mode,recipe_argv=argv,headers=observed,command=row['name']))
        r['build_status'] = 'started'
        run('build-oracles',[tools['sh'],recipe,ROOT/'tools/page-entry/bridge.c',SELECTED,build],profile='build')
        for mode in ('scalar','fast'):
            binary(build/('bridge-'+mode+'.o'));binary(build/('memset-'+mode))
        r['build_status'] = 'compiled'
        spec = importlib.util.spec_from_file_location('li2_fast_memset_check',pin(FIXTURE/'check.py'))
        check = importlib.util.module_from_spec(spec);spec.loader.exec_module(check)
        r['inspection'] = {};sizes = []
        for mode in ('scalar','fast'):
            path = build/('memset-'+mode)
            need(modes[str(path)] & 0o111, 'actual executable mode')
            _,symbols,err = run(mode+'-symbols',[tools['nm'],'-S','--defined-only',path],profile='inspect');need(not err,'ELF symbol stderr')
            record_address,record_size = symbol(symbols,'record','bB')
            _,out,err = run(mode+'-body',[tools['objdump'],'-d','-w','-M','att','--disassemble=li2_test_memset',path],profile='inspect');need(not err,'objdump stderr')
            body = body_check(path,symbols,out,mode)
            _,out,err = run(mode+'-dwarf',[tools['gdb'],'-q','-nx','-batch','-iex','set auto-load off','-iex','set debuginfod enabled off',
                '-iex','set index-cache enabled off','-iex','maintenance set worker-threads 1','--readnow',
                '--se='+str(path),'-x',FIXTURE/'layout.py'], environment=gdb_env)
            need(not err,'file-only DWARF stderr');layout = decode(out);slot = layout_check(layout,record_size);sizes.append(slot)
            data,_,ph = elf(path)
            need(sum(p[0] == 1 and p[1]&2 and p[3] <= record_address and record_address+record_size <= p[3]+p[6] for p in ph) == 1, 'actual full BSS record owner')
            interp = [p for p in ph if p[0] == 3];need(len(interp) == 1,'one actual hosted interpreter')
            p = interp[0];value = data[p[2]:p[2]+p[5]];need(value.startswith(b'/') and value.endswith(b'\0') and b'\0' not in value[:-1],'exact interpreter path')
            loader = pin(os.fsdecode(value[:-1]))
            _,out,err = run(mode+'-libraries',[loader,'--list',path]);need(not err,'loader dependency observation stderr')
            libraries = {};vdso = 0
            for line in out.decode().splitlines():
                if re.fullmatch(r'\s*linux-vdso\.so\.1 \(0x[0-9a-f]+\)',line):vdso += 1;continue
                m = re.fullmatch(r'\s*(?:(\S+) => )?(/\S+) \(0x[0-9a-f]+\)',line)
                need(m is not None,'closed actual loaded-library row');key = m[1] or 'interpreter'
                if m[1] and m[1].startswith('/'):
                    need(pin(m[1]) == pin(m[2]) == loader, 'absolute loader aliases name the actual ELF interpreter')
                    key = 'interpreter'
                need(key not in libraries,'unique loaded-library identity');libraries[key] = dict(path=str(pin(m[2])),**fact(m[2]))
            need(vdso == 1 and set(libraries) == {'libc.so.6','interpreter'} and
                 libraries['interpreter']['path'] == str(loader), 'only actual libc and interpreter')
            r['inspection'][mode] = dict(layout=layout,body=body,libraries=libraries,elf=fact(path))
        need(sizes[0] == sizes[1], 'same actual scalar/fast slot layout');r['slot_bytes'] = sizes[0]
        r['build_status'] = 'passed';baseline = None
        for label,mode,measured in NATIVE:
            case = dict(name=label,mode=mode,measured=measured,accepted=False);r['cases'].append(case)
            row,out,err = run(label,[build/('memset-'+mode),*(['m'] if measured else [])],profile='native')
            need(not err and len(out) == check.BYTES,'exact native stderr/record extent')
            result,rows = check.read(private/(label+'.stdout'),sizes[0],measured)
            if baseline is None:baseline = rows
            need(rows == baseline,'every retained functional row equals scalar baseline')
            case.update(accepted=True,actual_exit=row['exit'],result=result)
        need(len(r['cases']) == 6 and all(c['accepted'] for c in r['cases']), 'two functional then four measured processes')
        r['status'] = 'passed'
    except BaseException as exc:
        r['error'] = type(exc).__name__+': '+str(exc)
    finally:
        # Preserve any partial link/object independently, even when the shell
        # or an earlier observation failed. Do not replace the primary error.
        for name in ('bridge-scalar.o','bridge-fast.o','memset-scalar','memset-fast'):
            try:
                if os.path.lexists(build/name):binary(build/name)
            except BaseException as exc:r['final_errors'].append('partial artifact '+name+': '+repr(exc))
        for a,p in aliases.items():
            try:need(str(Path(a).resolve(strict=True)) == p,'alias closure')
            except BaseException as exc:r['final_errors'].append(a+': '+repr(exc))
        for p,present in configurations.items():
            try:need(Path(p).exists() == present,'loader configuration presence closure')
            except BaseException as exc:r['final_errors'].append(p+': '+repr(exc))
        for table in (pins,artifacts):
            for p,v in table.items():
                try:
                    need(fact(p) == v,'final byte closure')
                    if p in modes:need(Path(p).stat().st_mode & 0o777 == modes[p],'final mode closure')
                except BaseException as exc:r['final_errors'].append(p+': '+repr(exc))
        for row in r['commands']:
            try:
                need(row.get('reaped') and not row.get('timed_out') and not row.get('error') and not row.get('cleanup_errors'),'process cleanup closure')
                for cap in row.get('captures',{}).values():need(fact(private/cap['file']) == {k:cap[k] for k in ('bytes','sha256')},'capture closure')
            except BaseException as exc:r['final_errors'].append(row['name']+': '+repr(exc))
        try:
            r['source_after'] = source();r['source_unchanged'] = r['source_after'] == r['source'];need(r['source_unchanged'],'source changed')
        except BaseException as exc:r['final_errors'].append('source: '+repr(exc))
        if r['error'] or r['final_errors']:r['status'] = 'failed'
        r.update(inputs=pins,input_aliases=aliases,artifacts=artifacts,artifact_modes=modes,configuration_presence=configurations,
                 tools={n:dict(path=str(p),**pins[str(p)]) for n,p in tools.items()},numeric_versions=versions,environment=env)
        save(private/'receipt.json',r)
        output = {k:r.get(k) for k in ('version','profile','status','expected_revision','started_utc','cpu','source','source_unchanged',
            'hardware','scope','reproduce','build_status','rust_archive_used','slot_bytes','cases')}
        output.update(bounds=BOUNDS,environment=ENV,tool_versions=versions,tool_hashes={n:pins[str(p)] for n,p in tools.items()},
            private_receipt=fact(private/'receipt.json'),inputs_sha256=digest(pins),aliases_sha256=digest(aliases),artifacts_sha256=digest(artifacts),
            command_count=len(r['commands']),commands_sha256=digest(r['commands']),inspection_sha256=digest(r.get('inspection',{})),
            native_commands=[{k:row.get(k) for k in ('name','exit','expected_exit','timed_out','reaped')} for row in r['commands'] if row['profile']=='native'],
            final_error_count=len(r['final_errors']),failure_type=r['error'].split(':',1)[0] if r['error'] else ('FinalObservationError' if r['final_errors'] else None))
        text = json.dumps(output,indent=2,sort_keys=True,allow_nan=False)+'\n'
        need(len(text.encode()) < 20000 and not re.search(r'/home/|devbig[0-9]+|internalfb\.com',text) and
             not any(x and len(x)>1 and x in text for x in (str(ROOT),str(Path.home()),platform.node())), 'compact private-location-free publication')
        public.parent.mkdir(parents=True,exist_ok=True)
        with public.open('x') as f:f.write(text)
    print(json.dumps(dict(status=r['status'],cases=len(r['cases']),commands=len(r['commands']),receipt=str(public.relative_to(ROOT)))))
    return int(r['status'] != 'passed')


if __name__ == '__main__':
    raise SystemExit(main())
