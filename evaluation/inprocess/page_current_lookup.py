#!/usr/bin/env python3
"""Reproduce the actual current() lookup oracle; no timing or speedup claim."""
import argparse
from datetime import datetime, timezone
import hashlib, json, os, platform, re, shlex, shutil, sys
from pathlib import Path
from types import SimpleNamespace
sys.dont_write_bytecode = True
from checks import source
from run import hardware
from page_selected import ENV, elf, fact, need, save
from page_selected_process import invoke
from page_selected_fast_memset import decode, symbol
from page_selected_fast_zero_link import headers, compile_retained
from page_selected_provider_libraries import libraries as closed_libraries

ROOT = Path(__file__).resolve().parents[2]
SELECTED = ROOT/'tools/page-entry/selected'
FIXTURE = SELECTED/'tests/current_lookup'
BOUNDS = [5, 512 << 20, 16 << 20, 15]
EXPECTED = dict(version=1, record_capacity=8192, record_bytes=64, appends=8192, retirements=8192,
                rounds=292, queries=3716, hits=2615, misses=1101,
                whole_records_and_counts_unchanged=1, linear_and_literal_equal=1)
# Exact reviewed production lookup and unmodified whole-TU oracle/recipe.
INPUTS = {
    'lifecycle_loader.c':'cc25a232a3a8c5fda27eae439b63c1bb4b7e58c7e17f0bfe6261ee18929139ec',
    'tests/current_lookup/oracle.c':'684da2d92582b65acc0d1186e003372e8e9e70e9e7262d7a18a0fbd6b3d5337e',
    'tests/current_lookup/build.sh':'ee4077e450cc4feac2c059e17419f59e8a8092652f4f4a41e2a6f764ff371039',
    'tests/current_lookup/EXPECTED.json':'5033984bdf067cefb5ee1f8980ec3c6f39bf06545526bcbc5b0311096fde1f23',
}

def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()

def exact_result(raw):
    result = decode(raw)
    need(type(result) is dict and set(result) == set(EXPECTED) and
         all(type(result[k]) is int and result[k] == v for k,v in EXPECTED.items()), 'complete literal oracle result')
    return result

def project(r, receipt_fact):
    """Numeric success/failure prefixes; actual means a retained Popen PID."""
    native = [c for c in r['commands'] if c['profile'] == 'native']
    actual = [c for c in native if type(c.get('pid')) is int and c['pid'] > 0]
    closed = [c for c in actual if c.get('reaped') is True and not c.get('timed_out') and
              not c.get('error') and not c.get('cleanup_errors') and
              all(x['closed'] for x in c.get('descriptors',[]))]
    return dict(schema=1,profile=r['profile'],status=r['status'],revision=r['expected_revision'],
        started_utc=r['started_utc'],hardware=r.get('hardware'),source_unchanged=r['source_unchanged'],
        scope=r['scope'],rust_archive_used=False,bounds=BOUNDS,build_status=r['build_status'],
        result=r['result'],lookup_result_meaning={'hits':'positive results','misses':'null results'},
        oracle_processes=dict(attempted=len(native),actual=len(actual),closed=len(closed),
                              accepted=int(r['status']=='passed' and len(closed)==1 and
                                           type(closed[0].get('exit')) is int and closed[0]['exit']==0 and
                                           r['result']==EXPECTED)),
        commands=len(r['commands']),command_exits=[c.get('exit') for c in r['commands']],
        body={k:r['body'][k] for k in ('bytes','sha256')} if 'body' in r else None,
        private_receipt=receipt_fact,inputs=len(r['inputs']),inputs_sha256=digest(r['inputs']),
        artifacts=len(r['artifacts']),artifacts_sha256=digest(r['artifacts']),
        commands_sha256=digest(r['commands']),tool_versions=r['versions'],
        failure_type=r['error'].split(':',1)[0] if r['error'] else ('FinalObservationError' if r['final_errors'] else None),
        final_error_count=len(r['final_errors']),
        reproduce=['python3','evaluation/inprocess/page_current_lookup.py','--expect-revision',r['expected_revision']])


def main():
    ap = argparse.ArgumentParser(description=__doc__);ap.add_argument('--expect-revision', required=True);args = ap.parse_args()
    need(not sys.flags.optimize and re.fullmatch('[0-9a-f]{40}', args.expect_revision) and
         len(os.sched_getaffinity(0)) == 1, 'exact revision, enabled checks and one reserved CPU')
    os.chdir(ROOT);cpu = next(iter(os.sched_getaffinity(0)));stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    stem = stamp+'-page-current-lookup-'+args.expect_revision[:12]
    private = ROOT/'target/evaluation/inprocess'/stem;private.mkdir(parents=True, exist_ok=False)
    public = ROOT/'evaluation/inprocess/results'/(stem+'.json');build = private/'build';build.mkdir()
    executable = build/'current-lookup'
    r = dict(profile='page-current-lookup-v1', status='failed', expected_revision=args.expect_revision,
        started_utc=stamp, cpu=cpu, source=None, source_unchanged=False, commands=[], result=None, error=None, final_errors=[],
        scope='Actual current() versus the unchanged reverse scan and literal slots, with full records/counts conserved. Hits/misses count positive/null results, not memo hits. No timing or application-speed qualification.',
        rust_archive_used=False, build_status='not_started')
    pins, aliases, artifacts, tools, versions, presence, link_inputs = {}, {}, {}, {}, {}, {}, {}
    env = dict(ENV);pending = []
    def pin(path):
        need(path is not None, 'input present');alias = str(Path(path).absolute());p = Path(alias).resolve(strict=True)
        need(alias not in aliases or aliases[alias] == str(p), 'stable lexical alias');aliases[alias] = str(p)
        value = fact(p);need(str(p) not in pins or pins[str(p)] == value, 'immutable input');pins[str(p)] = value;return p
    def binary(path):
        p = Path(path);need(p.is_file() and not p.is_symlink(), 'regular retained artifact')
        value = dict(fact(p), mode=p.stat().st_mode & 0o777)
        need(str(p) not in artifacts or artifacts[str(p)] == value, 'immutable artifact');artifacts[str(p)] = value;return p
    def closure():
        need(all(Path(p).exists() == v for p,v in presence.items()), 'loader configuration presence')
        need(all(str(Path(a).resolve(strict=True)) == p for a,p in aliases.items()), 'lexical input aliases')
        need(all(fact(p) == v for p,v in pins.items()), 'input bytes')
        need(all(dict(fact(p), mode=Path(p).stat().st_mode & 0o777) == v for p,v in artifacts.items()), 'artifact bytes/modes')
    def run(name, argv, profile='metadata', env=env):
        closure();need(not any(c['name'] == name for c in r['commands']), 'unique command capture')
        row = dict(name=name, argv=list(map(str,argv)), profile=profile, bounds=BOUNDS, expected_exit=0,
                   capture_limit=65536 if profile == 'native' else 4 << 20, environment=dict(env))
        r['commands'].append(row)
        try:out,err = invoke(row,private,cpu)
        finally:
            # Keep secondary observation failures separate from the initiating error.
            for capture in row.get('captures',{}).values():
                try:
                    need(Path(capture['file']).name == capture['file'] and
                         fact(private/capture['file']) == {k:capture[k] for k in ('bytes','sha256')}, 'immediate capture custody')
                    binary(private/capture['file'])
                except BaseException as exc:r['final_errors'].append('capture: '+repr(exc))
            try:
                path = private/(name+'.json')
                need(json.loads(path.read_bytes()) == row, 'actual saved command row');binary(path)
            except BaseException as exc:r['final_errors'].append('command record: '+repr(exc))
        need(type(row['exit']) is int and row['exit'] == 0, 'actual command exit '+name);return row,out,err
    try:
        tools['git'] = pin(shutil.which('git',path=ENV['PATH']))
        r['source'] = source();need(r['source']['revision'] == args.expect_revision, 'exact clean committed source');r['hardware'] = hardware(cpu)
        for module in tuple(sys.modules.values()):
            path = getattr(module,'__file__',None)
            if path and Path(path).resolve().is_relative_to(ROOT):pin(path)
        for name,want in INPUTS.items():
            need(fact(pin(SELECTED/name))['sha256'] == want, 'exact reviewed lookup/oracle input '+name)
        exact_result((FIXTURE/'EXPECTED.json').read_bytes())
        for name in ('cc','nm','objdump'):tools[name] = pin(shutil.which(name,path=ENV['PATH']))
        tools['python'] = pin(sys.executable)
        for name in ('cc1','collect2','as','ld'):
            _,out,err = run('resolve-'+name,[tools['cc'],'-print-prog-name='+name]);value = out.decode().strip()
            need(value and not err, 'actual C subtool');tools[name] = pin(value if Path(value).is_absolute() else shutil.which(value,path=ENV['PATH']))
        for name in ('cc','nm','objdump','ld','as','python'):
            _,out,err = run('version-'+name,[tools[name],'--version']);need(not err,'version stderr')
            match = re.search(r'\b([0-9]+)\.([0-9]+)(?:\.([0-9]+))?\b',out.decode());need(match is not None,'numeric actual version')
            versions[name] = [int(match[1]),int(match[2]),int(match[3] or 0)]
        for name in ('crt1.o','Scrt1.o','crti.o','crtn.o','crtbegin.o','crtbeginS.o','crtend.o','crtendS.o','libgcc.a','libgcc_s.so','libc.so','libc_nonshared.a'):
            _,out,err = run('link-input-'+name,[tools['cc'],'-print-file-name='+name]);value = out.decode().strip()
            need(not err and Path(value).is_absolute(),'actual C link input');pin(value)
        for name in ('libc.so.6','libgcc_s.so.1'):
            _,out,err = run('runtime-input-'+name,[tools['cc'],'-print-file-name='+name]);value = out.decode().strip()
            need(not err and Path(value).is_absolute(), 'actual compiler-selected runtime')
            p = pin(value);link_inputs[name] = dict(path=str(p),**fact(p))
        r['link_inputs'] = link_inputs
        _,_,err = run('cc-specs',[tools['cc'],'-dumpspecs']);need(not err,'compiler specs stderr')
        for path in ('/etc/ld.so.cache','/etc/ld.so.preload'):
            presence[path] = Path(path).exists()
            if presence[path]:pin(path)
        need(not presence['/etc/ld.so.preload'],'no global preload')
        lines = [x.strip() for x in (FIXTURE/'build.sh').read_text().replace('\\\n',' ').splitlines() if x.strip().startswith('"$cc_bin" ')]
        need(len(lines) == 1,'one exact whole-TU C recipe');argv = []
        values = {'$cc_bin':str(tools['cc']),'$owner_context':str(SELECTED),'$selected_context':str(SELECTED),
                  '$parent_context':str(SELECTED.parent),'$fixture_dir':str(FIXTURE),'$output_dir':str(build)}
        for word in shlex.split(lines[0]):
            for old,new in values.items():word = word.replace(old,new)
            need('$' not in word and '`' not in word,'closed compiler recipe');argv.append(word)
        need(argv[0] == str(tools['cc']) and argv[-3:] == [str(FIXTURE/'oracle.c'),'-o',str(executable)] and
             '-O2' in argv and '-mgeneral-regs-only' in argv and '-Wall' in argv and '-Wextra' in argv and '-Werror' in argv,
             'actual unchanged release recipe and oracle output')
        need([x for x in argv if x.startswith('-DLI2_')] == ['-D'+x+'=1' for x in
             ('LI2_TF_HANDOFF','LI2_REGISTER_RUN','LI2_MAPS_PHASE_REUSE','LI2_RSEQ_INACTIVE',
              'LI2_NATIVE_PAGES','LI2_FAST_MEMSET','LI2_FAST_EQUAL','LI2_ONESHOT_PUBLICATION')], 'exact eight recipe macros')
        r['recipe'] = dict(script=fact(FIXTURE/'build.sh'), arguments=[str(SELECTED),str(SELECTED),str(build)],
                           expanded_argv=argv)
        builder = SimpleNamespace(tools=tools, environment=env)
        headers('headers',argv,builder,pin,run,r,required=[FIXTURE/'oracle.c',SELECTED/'lifecycle_loader.c',
                SELECTED/'maps_phase.inc',SELECTED/'native_lifecycle.inc',SELECTED/'oneshot_lifecycle.inc'])
        r['build_status'] = 'started'
        _,out,err = compile_retained('fixture-link',argv,run,binary,builder,pending,r['final_errors'])
        need(out == err == b'' and artifacts[str(executable)]['mode'] & 0o111,'quiet actual executable link')
        _,symbols,err = run('symbols',[tools['nm'],'-S','--defined-only',executable]);need(not err,'symbols stderr')
        address,size = symbol(symbols,'li2_current_oracle','T');data,head,ph = elf(executable)
        need(head[1] in (2,3) and all(p[0] != 1 or p[1]&3 != 3 for p in ph) and
             any(p[0] == 0x6474e551 and not p[1]&1 for p in ph), 'hosted ELF, no WX or executable stack')
        owners = [p for p in ph if p[0] == 1 and p[1]&1 and p[3] <= address and address+size <= p[3]+p[5]]
        need(len(owners) == 1 and 0 < size <= 512,'one complete actual lookup wrapper');p = owners[0]
        body = data[p[2]+address-p[3]:p[2]+address-p[3]+size]
        _,out,err = run('body',[tools['objdump'],'-d','-w','--disassemble=li2_current_oracle',executable]);need(not err,'body stderr')
        at = address;observed = bytearray()
        for line in out.decode().splitlines():
            m = re.fullmatch(r'\s*([0-9a-f]+):\s*((?:[0-9a-f]{2}\s)+)\s*\S.*',line)
            if m and address <= int(m[1],16) < address+size:
                code = bytes.fromhex(m[2]);need(int(m[1],16) == at and code,'contiguous actual body');observed += code;at += len(code)
        need(at == address+size and observed == body,'complete objdump/ELF body equality')
        r['body'] = dict(bytes=size,sha256=hashlib.sha256(body).hexdigest(),code_hex=body.hex())
        interps = [p for p in ph if p[0] == 3];need(len(interps) == 1,'one actual ELF interpreter');p = interps[0]
        value = data[p[2]:p[2]+p[5]];need(value.startswith(b'/') and value.endswith(b'\0') and b'\0' not in value[:-1],'exact interpreter string')
        loader = pin(os.fsdecode(value[:-1]));_,out,err = run('libraries',[loader,'--list',executable]);need(not err,'loader inspection stderr')
        r['libraries'] = closed_libraries(ROOT,executable,loader,out,link_inputs,pin)
        r['build_status'] = 'passed'
        _,out,err = run('native',[executable],'native');need(not err,'oracle stderr');r['result'] = exact_result(out)
        need(len(r['commands']) == 31 and sum(c['profile'] == 'native' for c in r['commands']) == 1,'complete metadata/build and one oracle')
        r['status'] = 'passed'
    except BaseException as exc:r['error'] = type(exc).__name__+': '+str(exc)
    finally:
        # Each observation is independent; none replaces the first failure.
        for path in pending:
            try:
                if os.path.lexists(path):binary(path)
            except BaseException as exc:r['final_errors'].append('partial artifact: '+repr(exc))
        for label,items,check in (
            ('alias',aliases.items(),lambda p,v:str(Path(p).resolve(strict=True)) == v),
            ('input',pins.items(),lambda p,v:fact(p) == v),
            ('artifact',artifacts.items(),lambda p,v:dict(fact(p),mode=Path(p).stat().st_mode & 0o777) == v),
            ('configuration',presence.items(),lambda p,v:Path(p).exists() == v)):
            for p,v in items:
                try:need(check(p,v),'final '+label+' closure')
                except BaseException as exc:r['final_errors'].append(label+' '+p+': '+repr(exc))
        for row in r['commands']:
            try:
                need(row.get('reaped') and not row.get('timed_out') and not row.get('error') and not row.get('cleanup_errors') and
                     all(d['closed'] for d in row.get('descriptors',[])), 'actual process cleanup')
                for cap in row.get('captures',{}).values():
                    need(Path(cap['file']).name == cap['file'] and fact(private/cap['file']) == {k:cap[k] for k in ('bytes','sha256')},'capture bytes')
            except BaseException as exc:r['final_errors'].append(row['name']+': '+repr(exc))
        try:r['source_after'] = source();r['source_unchanged'] = r['source_after'] == r['source'];need(r['source_unchanged'],'source changed')
        except BaseException as exc:r['final_errors'].append('source: '+repr(exc))
        if r['error'] or r['final_errors']:r['status'] = 'failed'
        r.update(inputs=pins,input_aliases=aliases,artifacts=artifacts,configuration_presence=presence,versions=versions,
                 tools={n:dict(path=str(p),**pins[str(p)]) for n,p in tools.items()})
        save(private/'receipt.json',r)
        try:
            output = project(r,fact(private/'receipt.json'))
            text = json.dumps(output,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n'
            need(len(text.encode()) < 8000 and not re.search(r'/home/|devbig[0-9]+|internalfb\.com',text) and
                 not any(x and len(x)>1 and x in text for x in (str(ROOT),str(Path.home()),platform.node())),'compact private-location-free projection')
            public.parent.mkdir(parents=True,exist_ok=True)
            with public.open('x') as f:f.write(text)
        except BaseException as exc:r['final_errors'].append('projection: '+repr(exc));r['status'] = 'failed';save(private/'receipt.json',r)
    print(json.dumps(dict(status=r['status'],commands=len(r['commands']),result=r['result'],receipt=str((private/'receipt.json').relative_to(ROOT)))))
    return int(r['status'] != 'passed')

if __name__ == '__main__':raise SystemExit(main())
