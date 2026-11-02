#!/usr/bin/env python3
"""Fixed effects13 metadata + forty three-lane native comparisons; no owner credit."""
import argparse
import csv
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import shlex
import sys
from types import SimpleNamespace

sys.dont_write_bytecode=True
from checks import source
from run import hardware
from page_selected import ENV,elf,fact,need,save
from page_selected_process import invoke
from page_selected_register_time_build import recipe,expand,headers
from persistent_dynamic import imported_sources
from persistent_loop_effects_native_prerequisite import authenticate as native_authenticate
from loop_components.run import LINK_NAMES,elf as dynamic_elf

ROOT=Path(__file__).resolve().parents[2]
SELECTED=ROOT/'tools/page-entry/selected'
FIXTURE=SELECTED/'tests/loop_effects13'
PROFILE='loop-effects13-component-v1'
STATUS='observed_component_comparisons'
BOUNDS={k:[30,512<<20,16<<20,60]for k in('metadata','build','native')}
CAP=16<<20
MODES=tuple(range(40))
FAULTS=(24,25,26,27)
CONTROL_COUNT=52
UNITS=(('tests/loop_effects13/metadata.c','tests/loop_effects13/bmg_model.c',
        'tests/linked_mov_guard/model.c','tests/decoder/support.c','linked_mov_guard.c'),
       ('tests/loop_effects13/native.c','tests/region_cache/machine.S','persistent_group_plan.c',
        'persistent_group_compact.c','loop_read_bridge.c','loop_envelope.c','loop_effects_bridge.c',
        'loop_effects_envelope.c','linked_direct_dispatch.c','linked_jmp_dispatch.c','linked_mov_guard.c'))
SCHEDULE=tuple(('link-'+n,'metadata')for n in LINK_NAMES)+tuple((kind+'-'+suffix,profile)
    for kind in('metadata','native')for suffix,profile in(('headers','metadata'),('build','build'),
        ('dependencies','metadata'),('elf','metadata'),('symbols','metadata')))+(('metadata-component','metadata'),)+tuple(('native-'+str(m),'native')for m in MODES)


def digest(v):return hashlib.sha256(json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode()).hexdigest()
def decode(raw):
    def unique(pairs):
        d=dict(pairs);need(len(d)==len(pairs),'unique receipt fields');return d
    return json.loads(raw,object_pairs_hook=unique,parse_constant=lambda x:(_ for _ in()).throw(ValueError(x)))
def artifact_fact(p):
    p=Path(p);need(p.is_file()and not p.is_symlink(),'regular whole artifact')
    return dict(fact(p),mode=p.stat().st_mode&0o777)
def load_reader(pin):
    path=pin(FIXTURE/'check.py');spec=importlib.util.spec_from_file_location('effects13_wire',path)
    reader=importlib.util.module_from_spec(spec);spec.loader.exec_module(reader)
    # These direct dependencies need not be installed in sys.modules.
    for module in(reader,reader.old,reader.independent,reader.direct):pin(module.__file__)
    imported_sources(pin);return reader

def preparation(raw):
    value=decode(raw);need(set(value)=={'previous_mask','mask','dispositions'}and
        type(value['previous_mask'])is int and 0<=value['previous_mask']<1<<64 and value['mask']==0 and
        type(value['mask'])is int and type(value['dispositions'])is list and
        [d['signal']for d in value['dispositions']]==[s for s in range(1,65)if s not in(9,19)]and
        all(set(d)=={'signal','before','after'}and all(type(x)is int for x in d.values())and
            0<=d['before']<1<<64 and d['after']==0 for d in value['dispositions']),
        'whole genuine reset mask and all62 signal dispositions before native entry')
    return value

def runtime(label,program,allowed,pin,run,environment):
    image=dynamic_elf(program);spelling=image['interpreter'];need(spelling is not None,'one actual dynamic interpreter')
    loader=pin(spelling);need(str(loader)in allowed,'actual interpreter bound before link')
    _,out,err=run(label+'-dependencies',[loader,'--list',program],env=environment);need(not err,'complete runtime listing stderr')
    dependencies=set()
    for line in out.decode().splitlines():
        line=line.strip()
        if re.fullmatch(r'linux-vdso\.so\.1 \(0x[0-9a-f]+\)',line):continue
        alias=re.fullmatch(r'(/[^ ]+) => (/[^ ]+) \(0x[0-9a-f]+\)',line)
        if alias:
            need(alias[1]==spelling and alias[2]==str(loader)and pin(alias[1])==pin(alias[2])==loader,'exact interpreter alias')
            path=loader
        else:
            match=re.fullmatch(r'(?:[^ /]+ => )?(/[^ ]+) \(0x[0-9a-f]+\)',line)
            need(match is not None,'whole runtime dependency grammar');path=pin(match[1])
        need(str(path)in allowed,'all runtime objects prebound');dependencies.add(str(path))
    need(str(loader)in dependencies,'actual interpreter included')
    actual={p:dynamic_elf(p)for p in sorted(dependencies)};sonames={}
    for p,info in actual.items():
        if info['soname']:
            need(info['soname']not in sonames,'unique actual SONAME');sonames[info['soname']]=p
    need('libc.so.6'in sonames and all(n in sonames for x in[image,*actual.values()]for n in x['needed']),'all dynamic edges closed')
    return dict(elf=image,objects=actual)

def workflow(private,native,archive,pin,binary,run,reader,*,create,result=None):
    """The same source-derived build/case path consumes actual or retained rows."""
    tools={k:pin(v['path'])for k,v in native['build']['tools'].items()}
    need(all(fact(tools[k])=={j:v[j]for j in('bytes','sha256')}for k,v in native['build']['tools'].items()),'whole native-qualified tools')
    builder=SimpleNamespace(tools=tools,environment=dict(native['build']['environment']))
    aliases={};allowed={str(archive)}
    for name in LINK_NAMES:
        _,out,err=run('link-'+name,[tools['cc'],'-print-file-name='+name],env=builder.environment)
        value=out.decode().strip();need(not err and Path(value).is_absolute(),'actual compiler-selected link input');allowed.add(str(pin(value)))
    pending=list(allowed)
    while pending:
        p=Path(pending.pop());b=p.read_bytes()
        if b.startswith((b'\x7fELF',b'!<arch>')):continue
        need(len(b)<4096 and b'GNU ld script'in b,'bounded actual linker script')
        for value in re.findall(r'/[^\s()]+',re.sub(r'/\*.*?\*/','',b.decode(),flags=re.S)):
            value=str(pin(value))
            if value not in allowed:allowed.add(value);pending.append(value)
    script=pin(FIXTURE/'build.sh');commands=recipe(script,'"$cc_bin"');need(len(commands)==2,'both exact actual component recipes')
    output=private/'component'
    if create:output.mkdir()
    else:need(output.is_dir()and not output.is_symlink(),'retained component directory')
    if result is None:result={}
    builds=result['builds']={};result['cases']=[];executables={}
    for index,kind in enumerate(('metadata','native')):
        sources=[str(pin(SELECTED/n))for n in UNITS[index]]
        argv=expand(commands[index],{'$cc_bin':tools['cc'],'$root':ROOT,'$selected':SELECTED,
            '$fixture':FIXTURE,'$archive':archive,'$output':output})
        need(argv[-2:]==['-o',str(output/('effects-'+kind))]and[x for x in argv if x.endswith(('.c','.S'))]==sources and
             argv.count(str(archive))==1 and all(x in argv for x in('-O2','-g','-Werror','-mgeneral-regs-only','-fstack-usage','-DLI2_LOOP_EFFECTS=1')),
             'whole source-owned recipe, exact TUs/archive/strict release flags')
        if kind=='native':need('-DLI2_PERSISTENT_LOOP_EFFECTS=1'in argv and '-DLI2_PG_LOOP_ENCODING_VERSION=2'in argv,'explicit new graph and existing encoding domains')
        state=dict(recipe=fact(script),argv=argv,archive=fact(archive));builds[kind]=state
        headers(kind+'-headers',argv,sources,archive,builder,pin,aliases,run,state)
        required={'decoder.h','linked_mov_guard.h','linked_byte_mov_guard.h','loop_scalar_decode.h'}
        if kind=='native':required|={'persistent_loop_effects_plan.h','persistent_loop_effects_plan.inc',
            'persistent_loop_effects_compact.inc','loop_effects_envelope.h','loop_effects_bridge.h','step_owner.h','tests/region_cache/machine.h'}
        need({str(pin(SELECTED/n))for n in required}<=set(state['headers']),'whole actual typed compiler-M closure')
        additions=['-save-temps=obj','-Wl,--trace'];state['diagnostic_only_additions']=additions
        _,out,err=run(kind+'-build',argv[:-2]+additions+argv[-2:],profile='build',env=builder.environment)
        need(not err,'strict original -Werror compilation and link')
        objects=set();stack=[]
        for unit in sources:
            prefix=output/('effects-'+kind+'-'+Path(unit).stem)
            suffixes=('.s','.o')if unit.endswith('.S')else('.i','.s','.o','.su')
            for suffix in suffixes:binary(str(prefix)+suffix)
            objects.add(str(Path(str(prefix)+'.o').resolve()))
            if unit.endswith('.c'):
                for line in Path(str(prefix)+'.su').read_text().splitlines():
                    parts=line.split('\t');need(len(parts)==3 and parts[1].isdigit()and parts[2]in('static','dynamic,bounded'),'bounded actual C stack usage')
                    site=parts[0].rsplit(':',3);need(len(site)==4 and site[1].isdigit()and site[2].isdigit()and str(pin(site[0]))in state['headers'],'actual C source stack row')
                    stack.append(dict(function=site[3],bytes=int(parts[1]),kind=parts[2]))
        trace=out.decode().splitlines();need(trace and all(Path(x).is_absolute()for x in trace),'whole absolute actual link trace')
        linked={str(Path(x).resolve(strict=True))for x in trace}
        need(objects|{str(archive)}<=linked<=allowed|objects,'every generated TU object and only prebound link objects')
        state['link_inputs']=sorted(linked);state['stack_rows']=stack
        if kind=='native':need(2*sum(x['bytes']for x in stack)+65536<=512<<10,'twice all bounded native C stack frames plus64KiB below actual alternate stack')
        exe=binary(output/('effects-'+kind));executables[kind]=exe;state['artifact']=artifact_fact(exe)
        b,h,segments=elf(exe)
        need(h[1]in(2,3)and h[2]==62 and exe.stat().st_mode&0o111 and all(s[2]+s[5]<=len(b)and s[5]<=s[6]and s[1]&3!=3 for s in segments if s[0]==1),'whole executable x86-64 load extents and W^X')
        state['runtime']=runtime(kind,exe,allowed,pin,run,builder.environment)
        _,_,err=run(kind+'-elf',[tools['readelf'],'-h','-l','-d','-r','-W',exe],env=builder.environment);need(not err,'whole actual ELF inspection')
        _,out,err=run(kind+'-symbols',[tools['nm'],'-S','--defined-only',exe],env=builder.environment);need(not err,'actual symbol census')
        names=('li2_decoder_byte_mov_store','li2_decoder_loop_scalar_describe','li2_decoder_loop_scalar_none','li2_decoder_mov_store','li2_mg_emit','li2_bmg_emit')
        if kind=='native':names+=('region_enter','region_capture','raw','li2_lpe_plan_pages','li2_lpe_plan_validate','li2_lpe_compact_recover')
        state['symbols']={}
        for name in names:
            rows=[line.split()for line in out.decode().splitlines()if line.split()[-1:]==[name]]
            need(len(rows)==1 and len(rows[0])==4 and rows[0][2]=='T','one actual required text definition '+name)
            address,size=int(rows[0][0],16),int(rows[0][1],16)
            need(size>0 and sum(s[0]==1 and s[1]==5 and s[3]<=address<address+size<=s[3]+s[5]for s in segments)==1,'whole required text in actual RX load')
            state['symbols'][name]=dict(address=address,bytes=size)
    row,out,err=run('metadata-component',[executables['metadata']],env=ENV)
    result['metadata']=reader.metadata(out,err,row['exit'])
    for mode in MODES:
        case=dict(mode=mode,status='failed',expected_exit=125 if mode in FAULTS else 0,error=None);result['cases'].append(case)
        try:
            row,out,err=run('native-'+str(mode),[executables['native'],mode],profile='native',expected=case['expected_exit'],env=dict(ENV,GLIBC_TUNABLES='glibc.pthread.rseq=0'),record=True)
            raw=binary(private/row['captures']['record']['file']).read_bytes()
            prep=preparation(binary(private/row['captures']['preparation']['file']).read_bytes())
            value=reader.check(raw,out,err,row['exit'],mode);controls=reader.controls(raw,out,err,row['exit'],mode)
            need(len(controls['refusals'])==CONTROL_COUNT and len(set(controls['refusals']))==CONTROL_COUNT,'all52 named actual-reader controls')
            case.update(status=value['status'],result=value,controls=controls,preparation_sha256=digest(prep))
        except BaseException as error:
            case['error']=type(error).__name__+': '+str(error)
            if not create or isinstance(error,(KeyboardInterrupt,SystemExit)):raise
    return result

def totals(value):
    cases=value.get('cases',[])
    return dict(planned_cases=40,completed_cases=sum(c['status']!='failed'for c in cases),
        original_lanes=sum(c['status']!='failed'for c in cases),generated_lanes=2*sum(c['status']!='failed'for c in cases),
        expected_fault_modes=4,observed_fault_modes=sum(c['status']=='observed_required_write_fault'for c in cases),
        reader_controls=sum(len(c.get('controls',{}).get('refusals',[]))for c in cases),
        policy13_loops=sum(c['status']!='failed'and c['mode']>=36 for c in cases),
        metadata_passed='metadata'in value)

def projection(r,receipt):
    host=dict(r.get('hardware')or{});flags=host.pop('isa_flags',[])
    if host:host.update(isa_flags_count=len(flags),isa_flags_sha256=digest(flags))
    value=dict(schema=1,profile=PROFILE,status=r['status'],revision=r['revision'],source=r.get('source'),cpu=r['cpu'],hardware=host,
        bounds=BOUNDS,receipt=fact(receipt),archive=r.get('archive'),native_prerequisite_sha256=r['native_sha256'],
        source_unchanged=r['source_unchanged'],inputs_unchanged=r['inputs_unchanged'],cleanup_complete=r['cleanup_complete'],
        counts=totals(r.get('result',{})),metadata=r.get('result',{}).get('metadata'),owner_credit=False,
        qualification_credit=False,performance_credit=False,error_type=(r.get('error')or'').split(':')[0]or None,
        final_error_count=len(r['final_errors']),command_count=len(r['commands']),commands_sha256=digest(r['commands']),
        validation_process_ns=sum(c.get('duration_ns',0)for c in r['commands']),
        cases=[dict(mode=c['mode'],status=c['status'],expected_exit=c['expected_exit'],
            error_type=(c.get('error')or'').split(':')[0]or None,result=c.get('result'),
            controls_sha256=digest(c.get('controls',{})),control_count=len(c.get('controls',{}).get('refusals',[])))for c in r.get('result',{}).get('cases',[])],
        scope='Finite native/generated comparison only; copied IMUL modes28..35 are reference scope. Four actual policy13 loops terminate branch-before. Old scalar_span58 and whole owner/qualification populations remain mandatory.')
    raw=(json.dumps(value,indent=2,sort_keys=True,allow_nan=False)+'\n').encode()
    need(not any(x in raw for x in(b'/home/',str(ROOT).encode(),b'http://',b'https://')),'compact projection has no host/private paths or links')
    stream=io.StringIO(newline='');writer=csv.writer(stream,lineterminator='\n');writer.writerow(('mode','status','expected_exit','reader_controls','raw_sha256'))
    for c in value['cases']:writer.writerow((c['mode'],c['status'],c['expected_exit'],c['control_count'],(c['result']or{}).get('raw_sha256','')))
    return raw,stream.getvalue().encode()

def prerequisite(path,expected_sha256,r,pin,binary,archive):
    """Strict retained authentication; never launches a process or accepts summaries as raw state."""
    path=pin(path);before=fact(path)
    need(path.name=='receipt.json'and path.parent.parent==ROOT/'target/evaluation/inprocess'and re.fullmatch('[0-9a-f]{64}',expected_sha256)and before['sha256']==expected_sha256,'whole explicit component receipt')
    actual=decode(path.read_bytes());private=path.parent
    need(actual['schema']==1 and actual['profile']==PROFILE and actual['status']==STATUS and
        all(digest(actual[k])==digest(r[k])for k in('revision','source','cpu','hardware'))and digest(actual['bounds'])==digest(BOUNDS) and
        all(actual[k]is True for k in('source_unchanged','inputs_unchanged','cleanup_complete'))and
        all(actual[k]is False for k in('owner_credit','qualification_credit','performance_credit'))and
        actual['error']is None and actual['final_errors']==[],'same-source/CPU/hardware fully completed component without promotion')
    def closure():
        need(fact(path)==before,'retained receipt unchanged')
        for p,v in actual['inputs'].items():need(fact(pin(p))==v,'whole retained input')
        for p,v in actual['artifacts'].items():need(artifact_fact(binary(p))==v,'whole retained artifact/mode')
        for p,v in actual['aliases'].items():need(str(pin(p))==v,'whole retained alias')
        for p,v in actual['presence'].items():need(os.path.lexists(p)==v,'whole loader presence')
    closure();need(actual['archive']==fact(archive)and set(actual['presence'])=={'/etc/ld.so.cache','/etc/ld.so.preload'}and actual['presence']['/etc/ld.so.preload']is False,'same actual effects archive and exact loader census')
    proof,_,_=native_authenticate(actual['native_receipt'],actual['native_sha256'],r,pin,binary,archive)
    need(proof==actual['native_prerequisite'],'whole original thirteen-source native prerequisite')
    native=decode(Path(actual['native_receipt']).read_bytes());rows=actual['commands']
    compiled_archive=pin(actual['archive_input']['path'])
    compiled_fact=artifact_fact(binary(compiled_archive))
    need(dict(path=str(compiled_archive),**compiled_fact)==actual['archive_input']==native['build']['artifacts']['decoder.a'] and
        compiled_archive==Path(actual['native_receipt']).parent/'artifacts/decoder.a' and
        fact(compiled_archive)==actual['archive']==fact(archive) and
        actual['inputs'].get(str(compiled_archive))==fact(compiled_archive) and
        actual['artifacts'].get(str(compiled_archive))==compiled_fact,
        'whole exact component compiler archive pathname, native provenance and current consumer bytes')
    need(tuple((c['name'],c['profile'])for c in rows)==SCHEDULE,'all fixed component commands, no skip/retry')
    used=set()
    def captured(row,name):
        v=row['captures'][name];p=pin(private/v['file'])
        need(p.parent==private and v['file']==row['name']+'.'+name and type(v['bytes'])is int and 0<=v['bytes']<=CAP and fact(p)=={k:v[k]for k in('bytes','sha256')},'whole bounded capture')
        return p.read_bytes()
    for row in rows:
        need(type(row['exit'])is int and type(row['expected_exit'])is int and row['exit']==row['expected_exit']and row['timed_out']is False and
            row['reaped']is True and row['error']is None and row['cleanup_errors']==[]and
            type(row['descriptors'])is list and all(d.get('closed')is True for d in row['descriptors'])and
            type(row['duration_ns'])is int and row['duration_ns']>=0 and digest(row['bounds'])==digest(BOUNDS[row['profile']])and
            row['capture_limit']==CAP and set(row['captures'])==({'stdout','stderr','record','preparation'}if row['profile']=='native'else{'stdout','stderr'}),
            'whole bounded closed command and actual capture population')
        for name in row['captures']:captured(row,name)
        need(decode(pin(private/(row['name']+'.json')).read_bytes())==row,'whole actual child record')
        if row['profile']=='native':need([d['name']for d in row['descriptors']]==['record','preparation']and row['descriptors'][0]['fd']==3,'actual exclusive fd3 and preparation ownership')
        else:need(row['descriptors']==[],'ordinary child has no invented descriptors')
    byname={c['name']:c for c in rows}
    def recorded(name,argv,profile='metadata',expected=0,env=None,record=False):
        need(name in byname and name not in used,'one source-derived closed command')
        row=byname[name];need(row['argv']==list(map(str,argv))and row['environment']==dict(ENV if env is None else env)and
            row['profile']==profile and row['expected_exit']==expected and record==(profile=='native'),'whole exact argv/env/profile/outcome')
        used.add(name);return row,captured(row,'stdout'),captured(row,'stderr')
    reader=load_reader(pin);result=workflow(private,native,compiled_archive,pin,binary,recorded,reader,create=False)
    reader.exact(result,actual['result'],'whole rederived build/metadata/forty raw states/controls')
    need(len(used)==len(SCHEDULE)and totals(result)==dict(planned_cases=40,completed_cases=40,original_lanes=40,generated_lanes=80,
        expected_fault_modes=4,observed_fault_modes=4,reader_controls=2080,policy13_loops=4,metadata_passed=True),'all mandatory finite populations')
    summary,csvraw=projection(actual,path)
    need(pin(private/'summary.json').read_bytes()==summary and pin(private/'summary.csv').read_bytes()==csvraw,'whole exact compact projection')
    closure()
    return dict(schema=1,kind='loop_effects13_component',status='verified_prerequisite',file=str(path.relative_to(ROOT)),**before,
        revision=r['revision'],cpu=r['cpu'],source_sha256=digest(r['source']),hardware_sha256=digest(r['hardware']),
        archive=fact(archive),counts=totals(result),owner_credit=False,qualification_credit=False,performance_credit=False)

def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--expect-revision',required=True)
    ap.add_argument('--cpu',required=True,type=int);ap.add_argument('--output',required=True,type=Path)
    ap.add_argument('--native-receipt',required=True,type=Path);ap.add_argument('--native-receipt-sha256',required=True)
    ap.add_argument('--archive',required=True,type=Path);ap.add_argument('--archive-sha256',required=True);args=ap.parse_args()
    need(not sys.flags.optimize and re.fullmatch('[0-9a-f]{40}',args.expect_revision)and sorted(os.sched_getaffinity(0))==[args.cpu],'exact revision, assertions and reserved singleton')
    private=args.output.resolve();need(private.parent==ROOT/'target/evaluation/inprocess'and re.fullmatch('[a-z0-9][a-z0-9-]+',private.name),'fresh private component namespace')
    private.mkdir(exist_ok=False);receipt=private/'receipt.json';os.chdir(ROOT)
    r=dict(schema=1,profile=PROFILE,status='failed',revision=args.expect_revision,cpu=args.cpu,source=None,hardware=None,bounds=BOUNDS,
        native_receipt=str(args.native_receipt.resolve()),native_sha256=args.native_receipt_sha256,commands=[],result={},
        source_unchanged=False,inputs_unchanged=False,cleanup_complete=False,owner_credit=False,qualification_credit=False,performance_credit=False,error=None,final_errors=[])
    pins={};artifacts={};aliases={};presence={}
    def pin(path):
        alias=Path(path).absolute();p=alias.resolve(strict=True);v=fact(p)
        need(str(alias)not in aliases or aliases[str(alias)]==str(p),'stable input alias')
        need(str(p)not in pins or pins[str(p)]==v,'stable whole input');aliases[str(alias)]=str(p);pins[str(p)]=v;return p
    native_dir=Path(r['native_receipt']).parent
    def binary(path):
        p=Path(path).resolve(strict=True);need(p.is_relative_to(private)or p.is_relative_to(native_dir),'private current or actual native artifact')
        v=artifact_fact(p);need(str(p)not in artifacts or artifacts[str(p)]==v,'stable whole artifact');artifacts[str(p)]=v;return p
    def closure():
        need(all(fact(p)==v for p,v in pins.items())and all(artifact_fact(p)==v for p,v in artifacts.items())and
            all(str(Path(p).resolve(strict=True))==v for p,v in aliases.items())and all(os.path.lexists(p)==v for p,v in presence.items()),'whole before/after input/artifact/alias/presence closure')
        need(sorted(os.sched_getaffinity(0))==[args.cpu],'same reserved singleton')
    def run(name,argv,profile='metadata',expected=0,env=None,record=False):
        need(not any(c['name']==name for c in r['commands'])and record==(profile=='native'),'unique fixed command and typed fd ownership')
        row=dict(name=name,argv=list(map(str,argv)),profile=profile,bounds=BOUNDS[profile],expected_exit=expected,capture_limit=CAP,environment=dict(ENV if env is None else env))
        r['commands'].append(row);save(receipt,r)
        try:out,err=invoke(row,private,args.cpu,record=record,step=record)
        finally:
            for v in row.get('captures',{}).values():
                p=binary(private/v['file']);need(fact(p)=={k:v[k]for k in('bytes','sha256')},'whole retained actual capture')
            if(private/(name+'.json')).is_file():binary(private/(name+'.json'))
            save(receipt,r)
        need(type(row['exit'])is int and row['exit']==expected,'exact actual component exit '+name);return row,out,err
    try:
        r['source']=source();need(r['source']['revision']==args.expect_revision,'clean exact current source');r['hardware']=hardware(args.cpu)
        for p in('/etc/ld.so.cache','/etc/ld.so.preload'):
            presence[p]=os.path.lexists(p)
            if presence[p]:pin(p)
        need(not presence['/etc/ld.so.preload'],'no global preload')
        archive=pin(args.archive);need(re.fullmatch('[0-9a-f]{64}',args.archive_sha256)and fact(archive)['sha256']==args.archive_sha256,'whole explicit effects archive')
        r['archive']=fact(archive)
        proof,_,_=native_authenticate(args.native_receipt,args.native_receipt_sha256,r,pin,binary,archive);r['native_prerequisite']=proof
        native=decode(Path(r['native_receipt']).read_bytes())
        r['archive_input']=dict(path=str(archive),**artifact_fact(binary(archive)))
        need(r['archive_input']==native['build']['artifacts']['decoder.a'] and
            archive==Path(r['native_receipt']).parent/'artifacts/decoder.a',
            'whole exact supplied archive is the authenticated native retained artifact')
        reader=load_reader(pin);pin(__file__);pin(sys.executable);closure()
        workflow(private,native,archive,pin,binary,run,reader,create=True,result=r['result'])
        need(tuple((c['name'],c['profile'])for c in r['commands'])==SCHEDULE and all(c['status']!='failed'for c in r['result']['cases'])and len(r['result']['cases'])==40,'all fixed commands and forty actual state comparisons')
        r['status']=STATUS
    except BaseException as error:r['error']=type(error).__name__+': '+str(error)
    finally:
        output=private/'component'
        if output.is_dir():
            for p in output.iterdir():
                if p.is_file()and not p.is_symlink():
                    try:binary(p)
                    except BaseException as error:r['final_errors'].append('partial artifact: '+repr(error))
        try:imported_sources(pin);closure();r['inputs_unchanged']=True
        except BaseException as error:r['final_errors'].append('closure: '+repr(error))
        try:need(source()==r['source'],'whole source unchanged');r['source_unchanged']=True
        except BaseException as error:r['final_errors'].append('source: '+repr(error))
        r['cleanup_complete']=bool(r['commands'])and all(c.get('reaped')is True and c.get('cleanup_errors')==[]and all(d.get('closed')is True for d in c.get('descriptors',[]))for c in r['commands'])
        if r['error']or r['final_errors']or not all(r[k]for k in('source_unchanged','inputs_unchanged','cleanup_complete')):r['status']='failed'
        r.update(inputs=pins,artifacts=artifacts,aliases=aliases,presence=presence);save(receipt,r)
    raw,csvraw=projection(r,receipt);(private/'summary.json').write_bytes(raw);(private/'summary.csv').write_bytes(csvraw)
    print(json.dumps(dict(status=r['status'],counts=totals(r['result']),receipt=str(receipt.relative_to(ROOT)),qualification_credit=False),sort_keys=True))
    return int(r['status']!=STATUS)

if __name__=='__main__':raise SystemExit(main())
