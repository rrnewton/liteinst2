#!/usr/bin/env python3
"""Fixed40 actual scalar native/application-owner subjects; no throughput credit."""
import argparse,ctypes,csv,hashlib,importlib.util,io,json,os,platform,re,shlex,shutil,struct,sys
from datetime import datetime,timezone
from pathlib import Path
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[2];HERE=Path(__file__).resolve().parent
SELECTED=ROOT/'tools/page-entry/selected';FIXTURE=SELECTED/'tests/scalar_region_app'
OWNER=SELECTED/'tests/scalar_region_owner'
REUSE_OWNER=SELECTED/'tests/scalar_region_reuse_owner'
CERTIFICATE_OWNER=SELECTED/'tests/scalar_region_reuse_certificate_owner'
def owner_directory(r):
    if r.get('certificate',False):return CERTIFICATE_OWNER
    return REUSE_OWNER if r['reuse'] else OWNER
sys.path[:0]=[str(HERE),str(SELECTED.parent)]
from checks import source
from run import hardware
from page_selected import ENV,elf,fact,interpreter,need,save
from page_selected_generic_build import Build,PROFILES
from page_selected_process import invoke
from page_selected_effect_ls import program_invoke
from page_selected_oneshot_build import before_default
from page_selected_register_time_build import expand,recipe,headers
from scalar_region_build import build_bridge
import namespace
import scalar_region_app_reports as reports
import scalar_region_mapping_controls as mapping_controls
import scalar_case_strings
BOUNDS=dict(PROFILES,release_build=[30,512<<20,16<<20,60],program=[30,512<<20,16<<20,60],seed=[5,512<<20,16<<20,15],boundary=[3,256<<20,1<<20,10],mapping_guard=[3,256<<20,1<<20,10])
MASK=((1<<64)-1)^sum(1<<(s-1)for s in(4,5,9,11,19,31))
H=lambda b:hashlib.sha256(b).hexdigest()
ORDER=tuple((lane,mode,0)for lane in('native','gated')for mode in range(13))+tuple(('gated',0,c)for c in range(1,15))
OWNER_CONTROL_COUNTS={(mode,0):86 if mode<5 else 88 if mode<11 else 96 for mode in range(13)}
OWNER_CONTROL_COUNTS.update({(0,control):count for control,count in enumerate(
    (102,82,86,82,82,49,83,68,68,68,82,68,68,81),1)})
REUSE_ORDER=ORDER+tuple(('gated',0,c)for c in (15,16,17))
REUSE_CONTROL_COUNTS={(0, 0): 140, (1, 0): 140, (2, 0): 140, (3, 0): 140, (4, 0): 140, (5, 0): 142, (6, 0): 142, (7, 0): 142, (8, 0): 142, (9, 0): 142, (10, 0): 142, (11, 0): 157, (12, 0): 157, (0, 1): 156, (0, 2): 136, (0, 3): 140, (0, 4): 136, (0, 5): 136, (0, 6): 106, (0, 7): 137, (0, 8): 122, (0, 9): 122, (0, 10): 122, (0, 11): 136, (0, 12): 122, (0, 13): 122, (0, 14): 135, (0, 15): 136, (0, 16): 136, (0, 17): 136}


def digest(value):return H(json.dumps(value,sort_keys=True,separators=(',',':')).encode())


def expand_cases(public):
    """Restore ordinary numerical case dictionaries from the published tables."""
    if public['case_encoding']=='shared-numerical-columns-v2':public=scalar_case_strings.restore(public)
    columns=public['case_columns'];subcolumns=public['case_subcolumns'];result=[]
    def expand(row,keys):
        need(type(row)is list and len(row)==len(keys)+1 and type(row[0])is int and 0<=row[0]<1<<len(keys),
             'complete presence mask and numerical row')
        return {key:row[i+1]for i,key in enumerate(keys)if row[0]>>i&1}
    for encoded in public['cases']:
        need(type(encoded)is list and encoded and type(encoded[0])is int and 0<=encoded[0]<1<<len(subcolumns),
             'exact dictionary-type mask, distinct from retained scalar or list values')
        row=expand(encoded[1:],columns)
        for i,field in enumerate(sorted(subcolumns)):
            keys=subcolumns[field]
            if encoded[0]>>i&1:
                need(field in row,'encoded dictionary field is actually present')
                row[field]=expand(row[field],keys)
        result.append(row)
    return result


def case_projection(rows):
    """Shared column names only; numeric values/types and missing fields survive."""
    fields=('owner_summary','pair','control_reference','boundary_observation')
    columns=sorted({k for row in rows for k in row})
    subcolumns={field:sorted({k for row in rows if type(row.get(field))is dict for k in row[field]})for field in fields}
    def packed(row,keys):return [sum(1<<i for i,k in enumerate(keys)if k in row),*[row.get(k)for k in keys]]
    data=[]
    for row in rows:
        value=dict(row);dictionaries=0
        for i,field in enumerate(sorted(subcolumns)):
            keys=subcolumns[field]
            if type(value.get(field))is dict:
                value[field]=packed(value[field],keys);dictionaries|=1<<i
        data.append([dictionaries,*packed(value,columns)])
    public=dict(case_encoding='shared-numerical-columns-v1',case_columns=columns,case_subcolumns=subcolumns,cases=data)
    serialized=json.loads(json.dumps(public,sort_keys=True,separators=(',',':'),allow_nan=False))
    need(digest(expand_cases(serialized))==digest(rows),'complete canonical typed inverse of every actual case field')
    return public


def prerequisite(public,revision,pin,binary,kind):
    """Read closed exact-revision qualification; no parser/native replay."""
    public=pin(public)
    need(public.parent==HERE/'results' and public.suffix=='.json' and public.stat().st_size<=32<<10,
         'bounded retained public prerequisite')
    value=json.loads(public.read_bytes());private=ROOT/'target/evaluation/inprocess'/public.stem/'receipt.json'
    need(fact(pin(private))==value['private_receipt'],'exact private prerequisite receipt')
    actual=json.loads(private.read_bytes())
    profile,status=('region-decoder-v1','passed_decoder')if kind=='decoder'else('scalar-region-component-v1','passed_component')
    current=source()
    for record in (value,actual):
        need(record['profile']==profile and record['status']==status and record['expected_revision']==revision and
             record['source']==current and record['source_unchanged']is True and record['cleanup_complete']is True,
             'complete same-revision '+kind+' prerequisite')
    need(actual['error']is None and actual['final_errors']==[] and value['final_error_count']==0 and
         value['totals']==actual['totals'],'one exact passed prerequisite population')
    need(value['bounds']==actual['bounds'],'unchanged recorded prerequisite bounds')
    hw=dict(actual['hardware']);flags=hw.pop('isa_flags')
    hw.update(isa_flags_count=len(flags),isa_flags_sha256=digest(flags))
    need(value['hardware']==hw,'exact prerequisite hardware projection')
    projected=[{**{k:v for k,v in c.items()if k not in ('error','reader_controls')},
        'reader_control_count':len(c.get('reader_controls',[])),
        'reader_controls_sha256':digest(c.get('reader_controls',[]))}for c in actual['cases']]
    need(value['cases']==projected,'all public prerequisite case fields equal actual closed rows')
    if kind=='decoder':
        need(actual['totals']==dict(required_processes=8,launch_attempts=8,launched=8,qualified=8,reader_refusals=104),
             'all original/new decoder processes and104 controls')
        cases=actual['cases'];labels=('original112','original-fatal102','original-fatal106','original-freestanding',
            'descriptor-matrix','guarded-source','test-busy','test-alloc101')
        need(len(cases)==8 and [c['row']for c in cases]==list(range(8)) and
             [c['label']for c in cases]==list(labels) and
             [c['expected_exit']for c in cases]==[0,125,125,0,0,0,0,125] and
             [c['artifact_scope']for c in cases]==['production']*6+['test_exports']*2 and
             [c['status']for c in cases]==['qualified','qualified_required_failure','qualified_required_failure',
                 'qualified','qualified','qualified','qualified','qualified_required_failure'] and
             [len(c['reader_controls'])for c in cases]==[12,4,4,14,22,22,22,4],
             'exact production versus injected-artifact decoder cases without relabels')
        need(actual['bounds']['decoder']==[3,256<<20,1<<20,10] and actual['test_artifact']['status']=='passed',
             'original decoder bounds and separate actual test artifact')
    else:
        need(actual['totals']==dict(required_modes=11,launch_attempts=11,launched=11,observed_exits=11,qualified=11,
             completed_paths=5,required_read_failures=6,reader_refusals=535),
             'all eleven actual full-state component comparisons and535 refusals')
        need([c['mode']for c in actual['cases']]==list(range(11)) and
             [c['status']for c in actual['cases']]==['qualified_component']*5+['qualified_required_failure']*6 and
             [len(c['reader_controls'])for c in actual['cases']]==[47]*5+[50]*6 and
             actual['bounds']['native']==actual['bounds']['planner']==[5,512<<20,16<<20,15],
             'exact eleven cases and original component/planner bounds')
        planner=actual['planner_prerequisite']
        need(planner['status']=='qualified_planner_only' and planner['launched']is True and planner['exit']==0 and
             planner['result']==dict(version=1,planner_only=1,positive=16,refused=27,corrupt=23,mapped=195,
                 interior_or_outside=827,postseal_equal=1) and
             actual['component_build']['status']==actual['planner_build']['status']=='passed',
             'separate complete planner and whole post-seal assertion before component credit')
    need(actual['inputs_before']==actual['inputs_after'] and actual['artifacts_before']==actual['artifacts_after'],
         'complete prerequisite input/artifact closure')
    for path,want in actual['inputs_before'].items():need(fact(pin(path))==want,'exact retained prerequisite input')
    for path,want in actual['artifacts_before'].items():
        retained=binary(path);need(dict(fact(retained),mode=retained.stat().st_mode&0o777)==want,'whole retained prerequisite artifact')
    aliases=actual.get('aliases_before',actual.get('aliases'))
    need(type(aliases)is dict and aliases and actual.get('aliases_after',aliases)==aliases,'complete prerequisite aliases')
    for lexical,resolved in aliases.items():need(str(pin(lexical))==resolved,'same prerequisite alias resolution')
    commands=actual['commands']
    need(commands and len({c['name']for c in commands})==len(commands) and
         all(type(c.get('exit'))is int and c.get('reaped')is True and c.get('timed_out')is False and not c.get('error') and
             c.get('cleanup_errors')==[] and isinstance(c.get('descriptors'),list) and
             all(d.get('closed')is True for d in c['descriptors']) and
             c['bounds']==actual['bounds'][c['profile']] and
             (c.get('expected_exit')is None or c['exit']==c['expected_exit'])for c in commands),
         'all prerequisite commands retain exact exits/bounds/reaping/descriptor closure')
    need(actual['build']['status']=='passed' and actual['build']['command_completed']is True and
         actual['build']['decoder_features']==['scalar-region'] and
         value['command_count']==len(commands) and value['commands_sha256']==digest(commands),
         'actual feature archive and complete command digest')
    csv_path=public.with_suffix('.csv')
    need(value['csv']['file']==csv_path.name and fact(pin(csv_path))=={k:value['csv'][k]for k in ('bytes','sha256')},
         'exact prerequisite CSV')
    return dict(file=public.name,**fact(public),private_receipt=fact(private),profile=profile,status=status,
                totals=actual['totals'],commands=len(commands),commands_sha256=digest(commands))


def load(name,path,pin):
    spec=importlib.util.spec_from_file_location(name,pin(path));module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module);return module


def reader_support(builder,private,pin,binary,run,r):
    reader=load('scalar_app_read',FIXTURE/'read.py',pin)
    owner=load('scalar_owner_read',owner_directory(r)/'read.py',pin)
    policy=private/'native-policy.so';unit=pin(SELECTED/'native_policy.c')
    flags=['-std=gnu11','-O2','-g','-Wall','-Wextra','-Werror','-fPIC','-shared']
    _,out,err=run('policy-headers',[builder.tools['cc'],*flags,'-M','-MT','li2_policy',unit],env=builder.environment)
    lines=out.decode().replace('\\\n',' ').splitlines()
    need(not err and len(lines)==1 and lines[0].startswith('li2_policy: '),'complete policy include rule')
    headers={str(pin(path)):fact(pin(path))for path in shlex.split(lines[0].split(':',1)[1])}
    need(str(unit)in headers and str(SELECTED/'native_policy.h')in headers,'actual policy sources')
    run('policy-link',[builder.tools['cc'],*flags,'-Wl,-z,noexecstack,--build-id=none',unit,'-o',policy],profile='release_build',env=builder.environment)
    r['reader_support']=dict(headers=headers,native_policy=fact(binary(policy)))
    lib=ctypes.CDLL(str(policy));lib.li2_native_policy.argtypes=(ctypes.c_void_p,ctypes.c_size_t);lib.li2_native_policy.restype=ctypes.c_uint
    return reader,owner,lambda data:lib.li2_native_policy(data,len(data))


def build_boundary_probe(builder,products,private,pin,binary,aliases,run,r):
    """Exact production archive observations, never generated execution."""
    archive=pin(products['archive']);retained=builder.record['artifacts']['decoder.a']
    need(builder.extra_decoder_sources==('region.rs',) and builder.decoder_features==('scalar-region',) and
         builder.record['status']=='passed' and builder.record['command_completed']is True and
         archive==builder.paths['archive']==builder.retained/'decoder.a' and str(archive)==retained['path'] and
         fact(archive)=={k:retained[k]for k in ('bytes','sha256')},'same retained production region decoder archive')
    sources=[str(pin((REUSE_OWNER if r.get('certificate',False)else owner_directory(r))/'boundary_probe.c')),str(pin(SELECTED/'tests/decoder/support.c'))]
    executable=private/'boundary-probe'
    flags=['-std=c11','-O2','-Wall','-Wextra','-Werror','-fno-builtin',
           '-fno-tree-loop-distribute-patterns','-mgeneral-regs-only']
    argv=[builder.tools['cc'],*flags,*sources,archive,'-Wl,--gc-sections','-o',executable]
    state=r['boundary_probe_build']=dict(status='failed',argv=list(map(str,argv)),archive=fact(archive))
    headers('boundary-headers',list(map(str,argv)),sources,archive,builder,pin,aliases,run,state)
    need({str(SELECTED/'decoder.h'),str(SELECTED/'region_decode.h')}<=set(state['headers']),
         'complete actual old decoder and304-byte descriptor include closure before compilation')
    run('boundary-link',argv,profile='release_build',env=builder.environment)
    executable=binary(executable);data,head,segments=elf(executable)
    need(executable.stat().st_mode&0o111 and head[1]in (2,3) and head[2:4]==(62,1) and
         all(p[2]+p[5]<=len(data) and p[5]<=p[6] and p[1]&3!=3 for p in segments if p[0]==1),
         'complete actual bounded metadata ELF without WX')
    _,_,err=run('boundary-elf',[builder.tools['readelf'],'-h','-l','-d','-r','-W',executable],profile='inspect',env=builder.environment)
    need(not err,'complete actual metadata ELF inspection')
    _,out,err=run('boundary-symbols',[builder.tools['nm'],'-g','--defined-only',executable],profile='inspect',env=builder.environment)
    rows=[x.split()for x in out.splitlines()]
    need(not err and all(sum(x[-2:]==[b'T',name]for x in rows)==1 for name in
         (b'li2_decoder_region_describe',b'li2_decoder_initialize',b'li2_decoder_stats')) and
         not any(x and x[-1].startswith(b'li2_region_test_')for x in rows),
         'actual production descriptor/initialization/stats APIs and no injected test exports')
    loader=pin(interpreter(executable))
    _,out,err=run('boundary-libraries',[loader,'--list',executable],profile='inspect',env=builder.environment)
    need(not err,'actual metadata library list');libraries={}
    for line in out.decode().splitlines():
        if re.fullmatch(r'\s*linux-vdso.so.1 \(0x[0-9a-f]+\)',line):continue
        match=re.fullmatch(r'\s*(?:\S+ => )?(/\S+) \(0x[0-9a-f]+\)',line)
        need(match is not None,'complete actual metadata resolved library')
        path=pin(match[1]);need(path.name not in libraries,'unique metadata library basename')
        libraries[path.name]=dict(path=str(path),**fact(path))
    need(any(v['path']==str(loader)for v in libraries.values()),'actual metadata interpreter in resolved closure')
    state.update(status='passed',artifact=fact(executable),runtime_libraries=libraries)
    return executable


def compile_subject(builder,private,pin,binary,run,r):
    script=pin(FIXTURE/'build.sh');rows=recipe(script,'"$cc"');need(len(rows)==1,'one exact three-TU app recipe')
    output=private/'application';output.mkdir()
    argv=expand(rows[0],{'$cc':builder.tools['cc'],'$source_dir':FIXTURE,'$output':output})
    sources=[str(pin(FIXTURE/x))for x in('main.c','pure.c','machine.S')]
    need(argv[-2:]==['-o',str(output/'scalar-region-app')]and[x for x in argv if x.endswith(('.c','.S'))]==sources and
         [x for x in argv if x.startswith('-D')]==['-DLI2_FAST_EQUAL=1']and all(x in argv for x in
         ('-O2','-g','-Wall','-Wextra','-Werror','-fno-builtin','-mgeneral-regs-only','-mcmodel=large',
          '-fno-asynchronous-unwind-tables','-fno-unwind-tables','-fno-pie','-no-pie')),
         'actual release application source/whole-range helper configuration')
    linker=pin(FIXTURE/'pure.ld');need('-Wl,-T,'+str(linker)in argv,'exact retained helper-page linker source')
    state=r['application_build']=dict(status='failed',recipe=fact(script),linker=fact(linker),argv=argv)
    flags=[x for x in argv[1:-2]if x not in sources and not x.startswith('-Wl,')]
    _,out,err=run('app-headers',[builder.tools['cc'],*flags,'-M','-MT','li2_app',*sources],env=builder.environment)
    lines=out.decode().replace('\\\n',' ').splitlines()
    need(not err and len(lines)==3 and all(x.startswith('li2_app: ')for x in lines),'complete actual three-TU app include closure')
    includes={}
    for line in lines:
        for name in shlex.split(line.split(':',1)[1]):p=pin(name);includes[str(p)]=fact(p)
    need(set(sources)|{str(FIXTURE/'app.h')}<=set(includes),'actual complete app header/source inputs before compilation')
    state['headers']=includes
    run('app-link',argv,profile='release_build',env=builder.environment)
    original=binary(output/'scalar-region-app');_,head,segments=elf(original)
    need(head[1:4]==(2,62,1)and not any(s[0]==1 and s[1]&3==3 for s in segments),'actual non-PIE x86-64 app without WX')
    _,_,err=run('app-elf',[builder.tools['readelf'],'-h','-l','-d','-r','-W',original],profile='inspect',env=builder.environment)
    need(not err,'actual complete app ELF inspection')
    objdump=pin(shutil.which('objdump',path=ENV['PATH']))
    _,out,err=run('app-objdump-version',[objdump,'--version'],env=builder.environment);need(out and not err,'actual app disassembler identity')
    _,out,err=run('app-symbols',[builder.tools['nm'],'-S','--defined-only',original],profile='inspect',env=builder.environment)
    need(not err,'actual emitted helper symbols');symbols={}
    for name in ('main','copy','same','ua_data_pattern','ua_stack_pattern'):
        found=[line.split()for line in out.decode().splitlines()if line.split()[-1:]==[name]]
        need(len(found)==1 and len(found[0])==4 and found[0][2]=='T','one complete actual app text symbol')
        address,size=int(found[0][0],16),int(found[0][1],16)
        need(size>0 and sum(p[0]==1 and p[1]==5 and p[3]<=address<address+size<=p[3]+p[5]for p in segments)==1,'whole symbol in exact actual RX segment')
        if name!='main':need(0x200001000<=address<address+size<=0x200002000,'actual high full-range helper body')
        symbols[name]=dict(address=address,bytes=size)
        _,assembly,err=run('app-body-'+name,[objdump,'-d','-w','-M','att','--start-address='+hex(address),'--stop-address='+hex(address+size),original],profile='inspect',env=builder.environment)
        need(assembly and not err and ('<'+name+'>:').encode()in assembly,'complete emitted helper/caller inspection')
        emitted=[];cursor=address
        for line in assembly.decode().splitlines():
            matched=re.fullmatch(r'\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s+)+)(.*)',line)
            if matched:
                chunk=bytes.fromhex(matched[2]);need(int(matched[1],16)==cursor and chunk and cursor+len(chunk)<=address+size,
                    'every emitted instruction byte lies contiguously inside the actual symbol')
                emitted.append(chunk);cursor+=len(chunk)
        segment=next(p for p in segments if p[0]==1 and p[1]==5 and p[3]<=address<address+size<=p[3]+p[5])
        offset=segment[2]+address-segment[3]
        need(cursor==address+size and b''.join(emitted)==original.read_bytes()[offset:offset+size],
             'complete actual nm-sized body bytes equal the retained ELF range')
        if name=='main':main_assembly=assembly.decode()
    for name in ('copy','same','ua_data_pattern','ua_stack_pattern'):
        need(re.search(r'\bmovabsq?\s+\$0x'+format(symbols[name]['address'],'x')+r',',main_assembly)is not None,
             'actual main materializes each full-width high helper address without truncated relocation')
    state.update(status='passed',artifact=fact(original),symbols=symbols);return original


def nested_emission(builder,bridge,pin,run,r):
    """Whole fresh ELF bytes, including every instruction after the last save."""
    objdump=pin(shutil.which('objdump',path=ENV['PATH']));data,_,segments=elf(bridge)
    need(data==bridge.read_bytes(),'same freshly retained bridge for emitted observation proof')
    _,out,err=run('nested-symbols',[builder.tools['nm'],'-S','--defined-only',bridge],profile='inspect',env=builder.environment)
    need(out and not err,'complete actual nested shim/gateway symbol inspection');bodies={}
    for name in ('uho_nested_raw','li2_raw6'):
        found=[line.split()for line in out.decode().splitlines()if line.split()[-1:]==[name]]
        need(len(found)==1 and len(found[0])==4 and found[0][2]=='t','one actual hidden nested observation function')
        address,size=int(found[0][0],16),int(found[0][1],16)
        loads=[p for p in segments if p[0]==1 and p[1]==5 and p[3]<=address<address+size<=p[3]+p[5]]
        need(0<size<=1024 and len(loads)==1,'whole bounded observation body in one actual RX load')
        _,assembly,err=run('nested-body-'+name,[objdump,'-d','-w','-M','att','--start-address='+hex(address),
            '--stop-address='+hex(address+size),bridge],profile='inspect',env=builder.environment)
        need(assembly and not err and ('<'+name+'>:').encode()in assembly,'complete actual nested body inspection')
        rows=[];cursor=address
        for line in assembly.decode().splitlines():
            match=re.fullmatch(r'\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s+)+)(.*)',line)
            if match:
                chunk=bytes.fromhex(match[2]);need(int(match[1],16)==cursor and chunk and cursor+len(chunk)<=address+size,
                    'every nested instruction byte lies contiguously in its actual symbol')
                rows.append((cursor,chunk,re.sub(r'\s+','',match[3])));cursor+=len(chunk)
        offset=loads[0][2]+address-loads[0][3];raw=b''.join(x[1]for x in rows)
        need(cursor==address+size and raw==data[offset:offset+size],'whole emitted nested body equals retained ELF bytes')
        bodies[name]=(address,raw,rows)
    gateway=bodies['li2_raw6'];shim=bodies['uho_nested_raw']
    need(gateway[1]==bytes.fromhex('4889f84889f74889d64889ca4d89c24d89c84c8b4c24080f05c3'),
        'whole original scalar RAW7 gateway and exact syscall return offset25')
    # GNU AT&T spellings for fixed non-branch instructions. Branches additionally
    # use their actual encoded displacement, never a printed symbol annotation.
    expected='''mov%rdi,%r10|movq$0x1,0x8(%r10)|mov%rsp,0x28(%r10)|mov0x8(%rsp),%rax|mov%rax,0x70(%r10)|test%rax,%rax|jne
mov0x18(%r10),%rsi|cmp%rsi,%rsp|jbe|mov%rsp,%rax|sub%rsi,%rax|mov%rax,0x30(%r10)|add$0x10,%rax|cmp0x20(%r10),%rax|ja|cld
lea0x80(%r10),%rdi|xor%eax,%eax|mov$0x2000,%ecx|repstos%rax,%es:(%rdi)
lea0x10080(%r10),%rdi|mov$0xffffffffffffffff,%rax|mov$0x2000,%ecx|repstos%rax,%es:(%rdi)
lea0x10280(%r10),%rdi|xor%eax,%eax|mov$0x8,%ecx|repstos%rax,%es:(%rdi)
mov0x58(%r10),%rax|mov%rax,%rdx|shr$0x20,%rdx|xsave640x80(%r10)|movq$0x1,0x60(%r10)
mov0x58(%r10),%rax|mov%rax,%rdx|shr$0x20,%rdx|xsave640x10080(%r10)|movq$0x1,0x68(%r10)
mov0x18(%r10),%rsi|lea0x20080(%r10),%rdi|mov0x30(%r10),%rcx|repmovsb%ds:(%rsi),%es:(%rdi)|movq$0x1,0x10(%r10)
mov0x40(%r10),%rsi|mov0x48(%r10),%rdx|mov0x50(%r10),%rcx|xor%r8d,%r8d|xor%r9d,%r9d|mov$0xea,%edi|jmp
mov$0xffffffffffffffea,%rax|ret'''.replace('\n','|').split('|')
    rows=shim[2];need(len(rows)==len(expected),'every instruction of the complete fixed scalar snapshot/tail shim')
    bad=rows[-2][0]
    for (pc,chunk,text),want in zip(rows,expected,strict=True):
        if want in ('jne','jbe','ja','jmp'):
            short={'jne':0x75,'jbe':0x76,'ja':0x77,'jmp':0xeb}[want]
            near={'jne':b'\x0f\x85','jbe':b'\x0f\x86','ja':b'\x0f\x87','jmp':b'\xe9'}[want]
            need((len(chunk)==2 and chunk[0]==short)or(len(chunk)==len(near)+4 and chunk.startswith(near)),
                'exact conditional or direct branch opcode/extent')
            width=1 if len(chunk)==2 else 4;target=pc+len(chunk)+int.from_bytes(chunk[-width:],'little',signed=True)
            need(target==(gateway[0]if want=='jmp'else bad),'actual error branches and direct unchanged-gateway tail target')
        elif want=='ret':
            need(chunk==b'\xc3','exact one-byte near return, independent of ret/retq display spelling')
        else:need(text==want,'exact emitted scalar snapshot instruction '+want)
    need(sum(x=='xsave640x80(%r10)'for x in expected)==1 and sum(x=='xsave640x10080(%r10)'for x in expected)==1,
        'two exact standard64-bit saves, no compacted or optimized variant')
    r['nested_emission']=dict(status='passed',bridge=fact(bridge),functions={name:dict(address=v[0],bytes=len(v[1]),
        sha256=H(v[1]),instructions=len(v[2]))for name,v in bodies.items()})


def observed_layout(builder,bridge,private,pin,binary,run,r):
    gdb=pin(shutil.which('gdb',path=ENV['PATH']));script=pin(owner_directory(r)/'layout.py')
    _,out,err=run('layout-gdb-version',[gdb,'--version'],env=builder.environment);need(out and not err,'actual GDB identity')
    _,out,err=run('owner-layout',[gdb,'-q','-nx','-nh','-batch','-iex','set auto-load off','-iex','set debuginfod enabled off',
        '-iex','set index-cache enabled off','-iex','maintenance set worker-threads 1','--readnow','--se='+str(bridge),'-x',script],
        profile='inspect',env=dict(builder.environment,MALLOC_ARENA_MAX='1'))
    need(not err and out.endswith(b'\n')and out.count(b'\n')==1,'one actual bounded DWARF observation; no inferior execution')
    layout=json.loads(out);need(layout['record']=='sro_wire'and 0<layout['types']['sro_wire']['bytes']<(16 if r.get('certificate',False)else 8)<<20,'actual retained owner wire')
    path=private/'owner-dwarf-layout.json'
    with path.open('xb')as f:f.write(out)
    r['owner_layout']=dict(artifact=fact(binary(path)),bridge=fact(bridge),reader=fact(script));return layout


def seed_prerequisite(builder,private,pin,binary,run,r):
    """One unchanged native seed probe; never an owner/application subject."""
    directory=SELECTED/'tests/provider_app/seed_probe'
    seed_reader=load('unrolled_seed_read',directory/'read.py',pin)
    xstate=load('unrolled_seed_xstate',SELECTED/'tests/b2_reference/xstate.py',pin)
    script=pin(directory/'build.sh');rows=recipe(script,'"${LI2_CC:')
    need(len(rows)==1,'one unchanged independent seed recipe')
    executable=private/'seed-probe'
    argv=expand(rows[0],{'${LI2_CC:?exact compiler required}':builder.tools['cc'],'$1':directory,'$2':executable})
    unit=str(pin(directory/'probe.c'));state=r['seed_prerequisite'];state['status']='failed'
    need(argv[-2:]==['-o',str(executable)]and[x for x in argv if x.endswith(('.c','.S'))]==[unit]and
         not any(x.startswith('-D')for x in argv)and all(x in argv for x in
         ('-O2','-g','-Wall','-Wextra','-Werror','-mgeneral-regs-only','-fno-tree-vectorize',
          '-fno-tree-loop-distribute-patterns','-fno-builtin','-fno-pie','-no-pie')),
         'unchanged seed compiler/producer recipe')
    flags=[x for x in argv[1:-2]if x!=unit and not x.startswith('-Wl,')]
    _,out,err=run('seed-headers',[builder.tools['cc'],*flags,'-M','-MT','li2_seed',unit],env=builder.environment)
    lines=out.decode().replace('\\\n',' ').splitlines()
    need(not err and len(lines)==1 and lines[0].startswith('li2_seed: '),'complete seed include rule')
    headers={str(pin(p)):fact(pin(p))for p in shlex.split(lines[0].split(':',1)[1])}
    need({unit,str(directory/'record.h')}<=set(headers),'whole seed source/header closure before compilation')
    state.update(recipe=fact(script),argv=argv,headers=headers)
    run('seed-link',argv,profile='release_build',env=builder.environment)
    executable=binary(executable);_,head,segments=elf(executable)
    need(executable.stat().st_mode&0o111 and head[1:4]==(2,62,1)and
         not any(p[0]==1 and p[1]&3==3 for p in segments),'actual fixed seed ELF without WX')
    state['elf']=fact(executable)
    loader=pin(interpreter(executable))
    _,out,err=run('seed-libraries',[loader,'--list',executable],profile='inspect',env=builder.environment)
    need(not err,'actual seed library list');libraries={}
    for line in out.decode().splitlines():
        if re.fullmatch(r'\s*linux-vdso.so.1 \(0x[0-9a-f]+\)',line):continue
        match=re.fullmatch(r'\s*(?:\S+ => )?(/\S+) \(0x[0-9a-f]+\)',line)
        need(match is not None,'complete actual seed resolved library')
        path=pin(match[1]);need(path.name not in libraries,'unique seed library basename')
        libraries[path.name]=dict(path=str(path),**fact(path))
    need(any(v['path']==str(loader)for v in libraries.values()),'actual seed interpreter in resolved library closure')
    state['runtime_libraries']=libraries
    try:row,out,err=run('seed-prerequisite',[executable],profile='seed')
    finally:
        if r['commands'][-1]['name']=='seed-prerequisite':
            actual=r['commands'][-1]
            state.update(launched=type(actual.get('pid'))is int,exit=actual.get('exit'),pid=actual.get('pid'),
                         whole_process_ns=actual.get('duration_ns'),timed_out=actual.get('timed_out'))
            state['captures']={k:{j:v[j]for j in('bytes','sha256')}for k,v in actual.get('captures',{}).items()}
    need(not err and len(out)==seed_reader.SIZE,'complete unchanged seed output and empty stderr')
    # Derive the candidate format from the actual first machine observation;
    # unchanged read() validates both machines and all four complete FXSAVEs.
    h=struct.unpack_from('<16Q',out,128)
    cp=[struct.unpack_from('<6I',out,256+24*i)for i in range(67)]
    facts=xstate.profile(cp,h[8],h[10],h[12],h[5],h[6])
    profile=seed_reader.read(out,executable.read_bytes(),facts,xstate,cpu=r['cpu'],pid=row['pid'])
    need(seed_reader.require(profile,facts,cpu=r['cpu'])==bytes(16),'independently qualified exact zero seed pointers')
    state.update(status='passed',profile=profile,format=facts)
    return seed_reader,xstate,profile,facts


def prepare_inputs(original,bridge,builder,private,pin,binary,run,r):
    interp=pin(interpreter(original));roots=[original.parent,Path('/usr/lib64')]
    _,out,err=run('app-libraries',[interp,'--list',original],profile='inspect',env=dict(builder.environment,LD_LIBRARY_PATH=':'.join(map(str,roots))))
    need(not err,'actual native library list');r['runtime_libraries']={}
    for line in out.decode().splitlines():
        if re.fullmatch(r'\s*linux-vdso.so.1 \(0x[0-9a-f]+\)',line):continue
        m=re.fullmatch(r'\s*(?:\S+ => )?(/\S+) \(0x[0-9a-f]+\)',line);need(m is not None,'complete actual resolved library')
        p=pin(m[1]);need(p.name not in r['runtime_libraries'],'unique actual runtime basename');r['runtime_libraries'][p.name]=dict(path=str(p),**fact(p))
    need(any(v['path']==str(interp)for v in r['runtime_libraries'].values()),'actual interpreter in resolved library closure')
    objects,description=namespace.plan(original,roots,bytes.fromhex(fact(original)['sha256']),bytes.fromhex(fact(interp)['sha256']))
    for item in objects:
        need(fact(pin(item['path']))['sha256']==H(item['bytes'])and any(v['path']==str(item['path'])and v['sha256']==H(item['bytes'])for v in r['runtime_libraries'].values()),'same actual sealed source and loader-resolved input')
    r['namespace_plan']=description
    images,raws,known=[],[],{};directory=private/'external-inputs';directory.mkdir()
    for role,path in [('original',original),('interpreter',interp)]+[('dependency-'+str(i),o['path'])for i,o in enumerate(objects)]:
        data=pin(path).read_bytes();identity=dict(bytes=len(data),sha256=H(data));need(fact(path)==identity,'complete independently retained ELF')
        if identity['sha256']in known:
            i=known[identity['sha256']];need(raws[i]==data,'duplicate content equality');images[i]['roles'].append(role);continue
        p=directory/(str(len(images))+'.elf')
        with p.open('xb')as f:f.write(data)
        need(fact(binary(p))==identity,'whole retained input copy');known[identity['sha256']]=len(images)
        images.append(dict(identity,roles=[role]));raws.append(data)
    r['external_inputs']=images;carrier=private/'carrier'
    _,out,err=run('carrier',[builder.tools['python'],'-B',pin(SELECTED.parent/'carrier.py'),'make',original,bridge,carrier],profile='program')
    need(not err,'carrier construction stderr');binary(carrier);identity=json.loads(out)
    need(all(identity[k+'_sha256']==fact(p)['sha256']for k,p in(('original',original),('interpreter',interp),('bridge',bridge),('carrier',carrier)))and interpreter(carrier)==bridge,'whole actual carrier source identities')
    r['subject_artifacts']={k:fact(p)for k,p in(('original',original),('interpreter',interp),('bridge',bridge),('carrier',carrier))}
    return interp,roots,objects,description,images,raws,carrier


def preparation(case,row,directory,original,roots,objects,description,carrier,private,binary,r):
    lane,mode,control=case['lane'],case['mode'],case['control'];prep=json.loads(binary(directory/'preparation.json').read_bytes())
    need(prep['schema_version']==1 and prep['status']=='prepared_not_executed'and prep['role']==lane and
        prep['pid']==row['pid']and prep['cpu']==[r['cpu']]and prep['reset_mask']==0 and prep['launch_mask']==(MASK if lane=='native'else 0)and
        prep['argv']==[str(original),str(mode),lane]+([case['protection_test']]if case.get('protection_test')else [])and prep['default_rseq']is True and prep['mode']==mode and prep['control']==control and prep.get('reuse',False)==r['reuse'] and
        [x['signal']for x in prep['dispositions']]==[n for n in range(1,65)if n not in(9,19)]and all(x['after']==0 for x in prep['dispositions']),
        'actual exact launch signal/mode/environment preparation')
    if lane=='native':
        need(prep['observer']is None and prep['environment']==dict(PATH='/usr/bin:/bin',LANG='C',LC_ALL='C',TZ='UTC',LD_BIND_NOW='1',LD_LIBRARY_PATH=':'.join(map(str,roots))),'actual closed native exec environment')
        return None
    ns=directory/'namespace';manifest=json.loads(binary(ns/'namespace.json').read_bytes());launch=json.loads(binary(ns/'launch.json').read_bytes())
    need(all(manifest[k]==v for k,v in description.items())and len(manifest['objects'])==len(objects)and manifest['schema_version']==1 and
        manifest['scope']=='explicit_sealed_dependency_namespace'and manifest['status']=='prepared_not_executed'and manifest['directory']==str(ns)and
        manifest['search_policy']=='explicit roots; no RPATH/RUNPATH/cache emulation'and manifest['identity_policy']=='sealed copies and private paths; not filesystem transparency',
        'actual namespace matches complete independent source plan')
    fds=[]
    for observed,item in zip(manifest['objects'],objects,strict=True):
        need(observed['names']==item['names']and observed['needed']==item['info']['needed']and observed['source']==str(item['path'])and
            observed['descriptive_pt_interp']==(str(item['info']['interpreter'])if item['info']['interpreter']else None)and observed['sha256']==H(item['bytes'])and
            observed['size']==len(item['bytes'])and observed['seals']==namespace.SEALS and type(observed['fd'])is int and observed['fd']>3 and observed['fd']not in fds and
            type(observed['device'])is int and observed['device']>0 and type(observed['inode'])is int and observed['inode']>0,'actual sealed dependency identity')
        fds.append(observed['fd'])
        for name in item['names']:
            p=ns/name;value='/proc/self/fd/'+str(observed['fd']);need(p.is_symlink()and os.readlink(p)==value,'actual sealed dependency alias');r['namespace_aliases'][str(p)]=value
    need(launch==dict(schema_version=1,scope='first_entry_loader_candidate',status='prepared_not_executed',argv=prep['argv'],dependency_fds=fds,
        carrier_sha256=fact(carrier)['sha256'],carrier_size=fact(carrier)['bytes'],environment=dict(PATH='/usr/bin:/bin',LANG='C',LC_ALL='C',TZ='UTC',
        LD_BIND_NOW='1',LD_LIBRARY_PATH=str(ns),LI2_DEPENDENCY_FDS=','.join(map(str,fds)),LI2_SCALAR_REGION_CAPTURE_CONTROL=('0123456789abcdefgh'if r['reuse']else '0123456789abcde')[control]))and
        prep['late_sonames']==[]and prep['environment_source']==str(ns/'launch.json'),'actual exact gated capture-control exec environment')
    record=private/row['captures']['record']['file'];st=record.stat()
    need(prep['observer']==dict(fd=3,device=st.st_dev,inode=st.st_ino)and st.st_nlink==1 and st.st_mode&0o7777==0o600,'same exclusive owner record descriptor')
    return manifest


def image_inventory(original,interp,carrier,objects,manifest):
    n=len(objects);rows={}
    for i,(item,observed)in enumerate(zip(objects,manifest['objects'],strict=True)):
        rows[i]=dict(data=item['bytes'],carrier_bytes=len(item['bytes']),kind=0,
            backing=dict(launch_fd=observed['fd'],dev=observed['device'],ino=observed['inode'],size=observed['size'],seals=observed['seals']))
    rows[n]=dict(data=original.read_bytes(),carrier_bytes=carrier.stat().st_size,kind=1)
    rows[n+1]=dict(data=interp.read_bytes(),carrier_bytes=interp.stat().st_size,kind=2)
    return dict(objects=rows,main_object=n,interpreter_object=n+1,uid=os.getuid())


def control_reference(reader,native,gated,owner,control):
    return reader.control_reference(native,gated,owner,control)


def cohort(builder,products,private,pin,binary,aliases,run,r):
    reader,owner_reader,native_policy=reader_support(builder,private,pin,binary,run,r)
    if r['reuse']:r['mapping_guard_summary']=mapping_controls.guard_oracle(builder,private,pin,binary,run,r)
    active_reports,bridge_builder,reuse_application=reports,build_bridge,None
    if r['reuse']:
        active_reports=load('scalar_reuse_terminal',HERE/'scalar_reuse_reports.py',pin)
        bridge_builder=load('scalar_reuse_builder',HERE/'scalar_region_reuse_build.py',pin).build_bridge
        reuse_application=load('scalar_reuse_app_controls',REUSE_OWNER/'application.py',pin)
    certificate_profile=None
    if r.get('certificate',False):
        certificate_profile=load('certificate_owner_profile',HERE/'scalar_reuse_certificate_profile.py',pin)
        active_reports=load('certificate_owner_terminal',HERE/'scalar_reuse_certificate_reports.py',pin)
        bridge_builder=load('certificate_owner_builder',HERE/'scalar_region_reuse_certificate_build.py',pin).build_bridge
        certificate_profile.require_controls(owner_reader,r)
        certificate_profile.component(builder,products,private,pin,binary,aliases,run,r,load)
    required_counts=REUSE_CONTROL_COUNTS if r['reuse']else OWNER_CONTROL_COUNTS
    expected_keys={(mode,0)for mode in range(13)}|{(0,control)for control in range(1,18 if r['reuse']else 15)}
    need(type(owner_reader.CONTROL_COUNTS)is dict and owner_reader.CONTROL_COUNTS==required_counts and
         set(required_counts)==expected_keys and sum(required_counts.values())==(4102 if r['reuse']else 2219) and
         all(type(k)is tuple and len(k)==2 and all(type(x)is int for x in k)for k in owner_reader.CONTROL_COUNTS) and
         all(type(n)is int and 0<n<=(157 if r['reuse']else 128)for n in owner_reader.CONTROL_COUNTS.values()),
         'complete source-fixed supplied owner-control population for every gated case')
    r['required_owner_reader_controls']={str(mode)+':'+str(control):count for (mode,control),count in sorted(owner_reader.CONTROL_COUNTS.items())}
    boundary_probe=build_boundary_probe(builder,products,private,pin,binary,aliases,run,r)
    original=compile_subject(builder,private,pin,binary,run,r);app_layout=reader.elf(original.read_bytes(),native_policy)
    r['application_layout']={k:v for k,v in app_layout.items()if k!='source'}
    seed_reference=seed_prerequisite(builder,private,pin,binary,run,r)
    bridge_extra=('SCALAR_REGION_CAPTURE','SCALAR_REGION_REUSE_CERTIFICATE_CAPTURE')if r.get('certificate',False)else ('SCALAR_REGION_CAPTURE',)
    bridge=bridge_builder(builder,products,private,pin,binary,aliases,run,r,bridge_extra,capture_image=original)
    nested_emission(builder,bridge,pin,run,r)
    layout=observed_layout(builder,bridge,private,pin,binary,run,r)
    interp,roots,objects,description,images,raws,carrier=prepare_inputs(original,bridge,builder,private,pin,binary,run,r)
    carrier_bytes=carrier.read_bytes();launcher=pin(FIXTURE/'launch.py');native_records={}
    for module in tuple(sys.modules.values()):
        path=getattr(module,'__file__',None)
        if path and Path(path).is_file():pin(path)
    for c in r['cases']:
        lane,mode,control=c['lane'],c['mode'],c['control'];label=c['label'];c['status']='failed';directory=private/label;directory.mkdir()
        command_start=len(r['commands']);expected_commands=[label]
        argv=[builder.tools['python'],'-B',launcher,'--root',ROOT,'--role',lane,'--mode',str(mode),'--control',str(control),
            '--original',original,'--preparation',directory/'preparation.json']
        if r['reuse']:argv+=['--reuse']
        for p in roots:argv+=['--library-root',p]
        if lane=='gated':argv+=['--carrier',carrier,'--namespace',directory/'namespace','--record-fd','{record_fd}']
        try:
            try:row,out,err=run(label,argv,profile='program',expected=c['expected_exit'],record=lane=='gated')
            finally:
                if r['commands'][-1]['name']==label:
                    actual=r['commands'][-1];c.update(exit=actual.get('exit'),whole_process_ns=actual.get('duration_ns'),timed_out=actual.get('timed_out'),launched=type(actual.get('pid'))is int)
                    c['captures']={k:{j:v[j]for j in('bytes','sha256')}for k,v in actual.get('captures',{}).items()}
            manifest=preparation(c,row,directory,original,roots,objects,description,carrier,private,binary,r)
            if lane=='native':
                need(err==b'','native stderr remains empty')
                parsed=reader.read(out,mode,True,row['exit'],app_layout,row['pid'],r['cpu'],seed_reference)
                native_records[mode]=(out,row['pid']);c['status']='qualified_native_reference'
            else:
                capture=row['captures']['record'];record_path=binary(private/capture['file'])
                need(fact(record_path)=={k:capture[k]for k in('bytes','sha256')},'whole actual protected owner record')
                record=record_path.read_bytes();image=image_inventory(original,interp,carrier,objects,manifest)
                if r.get('certificate',False):
                    image['certificate_bridge']=bridge.read_bytes()
                    image['certificate_binding']=r['release_build']['certificate_binding']
                    image['certificate_headers']=r['release_build']['headers']
                prefix_reader=reuse_application if r['reuse']and control>=15 else reader
                parsed=(prefix_reader.control_prefix(out,control,row['exit'],app_layout,row['pid'],r['cpu'],seed_reference)if control else
                        reader.read(out,mode,False,row['exit'],app_layout,row['pid'],r['cpu'],seed_reference))
                request=owner_reader.boundary_requests(record,layout)
                need(type(request)is bytes and 32<=len(request)<=(2272 if r['reuse']else 2112),'bounded actual boundary metadata request')
                magic,version,count,width=struct.unpack_from('<4Q',request)
                need((magic,version,width)==(0x315152534c49324c,1,32) and count<=(70 if r['reuse']else 65)and len(request)==32+32*count,
                     'complete exact request header and source-window rows')
                request_path=private/(label+'-boundary-request.bin')
                with request_path.open('xb')as stream:stream.write(request)
                binary(request_path)
                observation=c['boundary_observation']=dict(requests=count,request_bytes=len(request),request_sha256=H(request))
                metadata_label='boundary-'+label;expected_commands.append(metadata_label)
                try:metadata,boundaries,metadata_err=run(metadata_label,[boundary_probe,request_path],profile='boundary',env=builder.environment)
                finally:
                    if r['commands'][-1]['name']==metadata_label:
                        actual=r['commands'][-1];observation['exit']=actual.get('exit')
                        cap=actual.get('captures',{}).get('stdout')
                        if cap:observation.update(response_bytes=cap['bytes'],response_sha256=cap['sha256'])
                need(not metadata_err and 128<=len(boundaries)<=(24208 if r['reuse']else 22488) and
                     struct.unpack_from('<4Q',boundaries)==(0x315352534c49324c,1,count,344) and
                     len(boundaries)==128+344*count,'complete actual bounded metadata response and empty stderr')
                actual_owner=owner_reader.read(record,layout,image,parsed,row['pid'],r['cpu'],row['exit'],control=control,boundaries=boundaries)
                terminal_args=(row['pid'],row['exit'],row['stdout_provenance_before'],images,raws,fact(carrier),carrier_bytes,actual_owner,owner_reader,mode)
                terminal,c['terminal']=active_reports.check(err,*terminal_args);r['terminal_reports'][label]=terminal
                c['terminal_controls']=active_reports.controls(err,*terminal_args)
                c['owner_summary']=actual_owner['summary']
                need(type(c['owner_summary'])is dict and c['owner_summary']and
                     all(type(k)is str and type(v)is int and 0<=v<1<<64 for k,v in c['owner_summary'].items()),
                     'compact actual numeric owner summary, no raw frame or guessed completion')
                if control:
                    need(0 in native_records,'actual mode0 native reference required for every control')
                    nout,npid=native_records[0]
                    native=reader.read(nout,0,True,0,app_layout,npid,r['cpu'],seed_reference)
                    c['control_reference']=control_reference(prefix_reader,native,parsed,actual_owner,control)
                    c['status']='qualified_required_owner_refusal'
                else:
                    need(mode in native_records,'same-mode complete native reference required')
                    nout,npid=native_records[mode]
                    def compare(n,g):
                        native=reader.read(n,mode,True,125 if 5<=mode<=10 else 0,app_layout,npid,r['cpu'],seed_reference)
                        gated=reader.read(g,mode,False,row['exit'],app_layout,row['pid'],r['cpu'],seed_reference)
                        owner=owner_reader.read(record,layout,image,gated,row['pid'],r['cpu'],row['exit'],control=0,boundaries=boundaries)
                        return reader.pair(native,gated,owner)
                    c['pair']=compare(nout,out);c['application_controls']=reader.controls(compare,nout,out,mode)
                    need(c['application_controls']==dict(supplied_refusals=31 if mode>=11 else 26,native_operations=0),'all fixed app rejection controls')
                    c['status']='qualified_required_read_failure'if 5<=mode<=10 else 'qualified_application'
                c['owner_reader_controls']=owner_reader.controls(record,layout,image,parsed,row['pid'],r['cpu'],row['exit'],control=control,boundaries=boundaries)
                want=required_counts[mode,control]
                need(len(c['owner_reader_controls']['refusals'])==want and c['owner_reader_controls']['native_operations']==0 and
                     c['owner_reader_controls']['original_sha256']==H(record),'complete fixed actual owner-record refusal controls')
                if r.get('certificate',False):certificate_profile.case_controls(c,mode,control,record,err)
        except Exception as error:
            c['status']='failed';c['error_type']=type(error).__name__;c['error']=type(error).__name__+': '+str(error)
            if r['error']is None:r['error']=c['error']
            actual_commands=r['commands'][command_start:]
            if not([x.get('name')for x in actual_commands]==expected_commands and
                all(type(x.get('exit'))is int and x.get('reaped')is True and not x.get('error') and x.get('cleanup_errors')==[] and
                    isinstance(x.get('descriptors'),list)and all(d.get('closed')is True for d in x['descriptors'])for x in actual_commands)):
                raise
    if r.get('certificate',False):
        certificate_mapping=load('certificate_mapping_controls',HERE/'scalar_reuse_certificate_mapping.py',pin)
        certificate_mapping.run_controls(builder=builder,private=private,pin=pin,binary=binary,run=run,r=r,reader=reader,
            app_layout=app_layout,seed_reference=seed_reference,original=original,roots=roots,objects=objects,
            description=description,carrier=carrier,preparation=preparation,launcher=launcher,
            boundary_probe=boundary_probe,owner_reader=owner_reader,owner_layout=layout,
            image_inventory=image_inventory,interp=interp,bridge=bridge)
    elif r['reuse']:
        mapping_controls.run_controls(builder=builder,private=private,pin=pin,binary=binary,run=run,r=r,reader=reader,
            app_layout=app_layout,seed_reference=seed_reference,original=original,roots=roots,objects=objects,
            description=description,carrier=carrier,preparation=preparation,launcher=launcher)
    need(len(r['cases'])==(43 if r['reuse']else 40)and all(c['status'].startswith('qualified_')for c in r['cases'])and not r['error'],'every required actual subject qualifies, no failed-prefix completion credit')
    need(sum(c.get('pair',{}).get('qualified_case',0)for c in r['cases'])==13 and
        sum(c.get('application_controls',{}).get('supplied_refusals',0)for c in r['cases'])==348 and
        sum(len(c.get('terminal_controls',{}).get('refusals',[]))for c in r['cases'])==(1964 if r['reuse']else 27*49+7*2)and
        sum(len(c.get('owner_reader_controls',{}).get('refusals',[]))for c in r['cases'])==(4102 if r['reuse']else 2219),
        'all13 actual pairs and fixed application/terminal/owner-record refusal controls')
    need(sum(x['profile']=='boundary'for x in r['commands'])==(38 if r.get('certificate',False)else 30 if r['reuse']else 27)and r['boundary_probe_build']['status']=='passed',
         'every gated record has one separately bounded metadata observation, without execution authority')
    if r.get('certificate',False):certificate_profile.complete(r)


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--expect-revision',required=True);parser.add_argument('--decoder-receipt',type=Path,required=True);parser.add_argument('--component-receipt',type=Path,required=True);parser.add_argument('--reuse',action='store_true',help='explicit bounded completed-generation reuse; original40 plus3 required owner refusals');parser.add_argument('--certificate',action='store_true',help='distinct generation-bound certificate; requires --reuse and all8 transaction components plus43 owner subjects');args=parser.parse_args()
    need(not args.certificate or args.reuse,'certificate profile explicitly requires completed-generation reuse')
    if args.certificate:BOUNDS['certificate_component']=[3,256<<20,1<<20,10]
    need(not sys.flags.optimize and re.fullmatch('[0-9a-f]{40}',args.expect_revision)and len(os.sched_getaffinity(0))==1,'exact revision/assertions and one reserved CPU')
    os.chdir(ROOT)
    args.decoder_receipt=args.decoder_receipt.resolve(strict=True).relative_to(ROOT)
    args.component_receipt=args.component_receipt.resolve(strict=True).relative_to(ROOT)
    need(all(p.parent==Path('evaluation/inprocess/results')and p.suffix=='.json'for p in
         (args.decoder_receipt,args.component_receipt)),'exact retained public prerequisite locations')
    cpu=next(iter(os.sched_getaffinity(0)));stamp=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    stem=stamp+('-scalar-region-reuse-certificate-owner-'if args.certificate else '-scalar-region-reuse-owner-'if args.reuse else '-scalar-region-owner-')+args.expect_revision[:12];private=ROOT/'target/evaluation/inprocess'/stem;private.mkdir(mode=0o700)
    pins,aliases,artifacts,presence={},{},{},{}
    r=dict(schema=1,reuse=args.reuse,profile='scalar-region-reuse-owner-v1'if args.reuse else 'scalar-region-owner-v1',status='failed',expected_revision=args.expect_revision,started_utc=stamp,cpu=cpu,
        hardware=hardware(cpu),commands=[],cases=[dict(label='subject-'+lane+'-'+str(mode)+'-'+str(control),lane=lane,mode=mode,control=control,
        expected_exit=125 if control or 5<=mode<=10 else 0,status='unexecuted',launched=False)for lane,mode,control in (REUSE_ORDER if args.reuse else ORDER)],
        namespace_aliases={},terminal_reports={},bounds=BOUNDS,error=None,final_errors=[],
        seed_prerequisite=dict(planned=1,status='unexecuted',launched=False,expected_exit=0,
            bounds=BOUNDS['seed'],owner_subjects=0,completed_applications=0,performance_credit=False))
    certificate_profile=None
    if args.certificate:
        r['certificate']=True;r['profile']='scalar-region-reuse-certificate-owner-v1'
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
                   profile=profile, bounds=BOUNDS[profile], capture_limit=1 << 20 if profile in ('boundary','mapping_guard')or r.get('certificate',False)and profile=='certificate_component'else 16 << 20, expected_exit=expected)
        r['commands'].append(row)
        try:
            out, err = (program_invoke if name.startswith('subject-') else invoke)(row, private, cpu, record=record)
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

    builder=Build(r,private,pin,binary,build_run,extra_decoder_sources=('region.rs',))
    try:
        r['source']=source();need(r['source']['revision']==args.expect_revision,'exact clean committed source')
        git=pin(shutil.which('git',path=ENV['PATH']))
        _,names,err=run('source-paths',[git,'-C',ROOT,'ls-files','-z','tools/page-entry','evaluation/inprocess']);need(not err,'source enumeration stderr')
        tracked={os.fsdecode(name)for name in names.split(b'\0')if name}
        required={str(p.relative_to(ROOT))for p in (Path(__file__),HERE/'scalar_region_app_reports.py',HERE/'scalar_region_build.py',HERE/'scalar_region_mapping_controls.py',HERE/'scalar_case_strings.py',
            FIXTURE/'main.c',FIXTURE/'pure.c',FIXTURE/'pure.ld',FIXTURE/'machine.S',FIXTURE/'app.h',FIXTURE/'read.py',FIXTURE/'build.sh',FIXTURE/'launch.py',
            OWNER/'read.py',OWNER/'layout.py',OWNER/'wire.py',OWNER/'plan.py',OWNER/'boundaries.py',OWNER/'boundary_probe.c')}
        required|={str((SELECTED/'tests/provider_app/seed_probe'/n).relative_to(ROOT))for n in('probe.c','record.h','read.py','build.sh')}
        required.add(str((SELECTED/'tests/b2_reference/xstate.py').relative_to(ROOT)))
        required|={str((SELECTED/p).relative_to(ROOT))for p in('initial_code_protection.h',
            'tests/initial_code_protection/oracle.c','tests/initial_code_protection/build.sh')}
        if r['reuse']:
            required|={str(p.relative_to(ROOT))for p in (HERE/'scalar_reuse_reports.py',HERE/'scalar_region_reuse_build.py',
                SELECTED/'build-scalar-region-reuse.sh',SELECTED/'selected_scalar_reuse.inc')}
            required|={str((REUSE_OWNER/n).relative_to(ROOT))for n in ('read.py','wire.py','layout.py','boundaries.py','boundary_probe.c','application.py')}
        if r.get('certificate',False):
            required|={str((HERE/name).relative_to(ROOT))for name in ('scalar_reuse_certificate_reports.py',
                'scalar_reuse_certificate_mapping.py','scalar_reuse_certificate_profile.py',
                'scalar_region_reuse_certificate_build.py')}
            required|={str((CERTIFICATE_OWNER/name).relative_to(ROOT))for name in ('read.py','wire.py','layout.py','certificate.py')}
            required|={str((SELECTED/name).relative_to(ROOT))for name in ('build-scalar-region-reuse-certificate.sh',
                'region_reuse_certificate.h','selected_scalar_reuse_certificate.inc','rseq_region_live.h','rseq_region_live.inc',
                'scalar_reuse_certificate_observe.h','scalar_reuse_certificate_observe.inc',
                'tests/reuse_certificate/oracle.c','tests/reuse_certificate/build.sh','tests/reuse_certificate/check.py')}
        need(required<=tracked,'all application/owner/build/reader sources committed')
        for name in sorted(tracked):
            if not name.startswith('evaluation/inprocess/results/'):pin(ROOT/name)
        if r.get('certificate',False):certificate_profile=load('certificate_public_profile',HERE/'scalar_reuse_certificate_profile.py',pin)
        for name in('/etc/ld.so.cache','/etc/ld.so.preload'):
            presence[name]=os.path.lexists(name)
            if presence[name]:pin(name)
        need(not presence['/etc/ld.so.preload'],'no global preload')
        temporary=private/'tmp';temporary.mkdir()
        _,out,err=run('namespace-controls',[pin(sys.executable),'-B','-m','unittest','discover','-s',SELECTED.parent,'-p','namespace*_tests.py','-v'],
            profile='program',env=dict(ENV,TMPDIR=str(temporary)))
        need(not out and re.search(rb'\nRan 12 tests in [0-9.]+s\n\nOK\n\Z',err)is not None,'all five existing and seven additive namespace controls')
        r['namespace_controls']=dict(status='passed',tests=12,existing=5,added=7)
        r['prerequisites']={kind:prerequisite(path,args.expect_revision,pin,binary,kind)for kind,path in
            (('decoder',args.decoder_receipt),('component',args.component_receipt))}
        products=builder.prepare()
        for module in tuple(sys.modules.values()):
            path=getattr(module,'__file__',None)
            if path and Path(path).is_file():pin(path)
        cohort(builder,products,private,pin,binary,aliases,run,r)
        need(len(r['cases'])==(43 if r['reuse']else 40)and all(c['status'].startswith('qualified_')for c in r['cases']),'all native/application/control attempts required')
        need(r['seed_prerequisite']['status']=='passed','independent seed prerequisite remains separately mandatory')
        r['status']='passed'
    except BaseException as error:
        if r['error']is None:r['error']=type(error).__name__+': '+str(error)
    finally:
        try:
            for module in tuple(sys.modules.values()):
                path=getattr(module,'__file__',None)
                if path and Path(path).is_file():pin(path)
        except BaseException as error:
            r['final_errors'].append('final imported source closure: '+repr(error))
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
        r['inputs_before']=dict(pins);r['aliases_before']=dict(aliases);r['artifacts_before']=dict(artifacts)
        r['inputs_after']={};r['artifacts_after']={};r['aliases_after']={}
        for table,observed,fn in(('inputs_after',pins,fact),('artifacts_after',artifacts,lambda p:dict(fact(p),mode=Path(p).stat().st_mode&0o777)),
                                  ('aliases_after',aliases,lambda p:str(Path(p).resolve(strict=True)))):
            for p in observed:
                try:r[table][p]=fn(p)
                except BaseException as error:r['final_errors'].append(table+' '+p+': '+type(error).__name__)
        r['source_unchanged'] = r.get('source') is not None and r.get('source_after') == r['source'] and \
            r['inputs_before']==r['inputs_after'] and r['aliases_before']==r['aliases_after']
        r['cleanup_complete'] = all(type(c.get('exit'))is int and c.get('reaped') is True and c.get('timed_out')is False and
            not c.get('error') and c.get('cleanup_errors')==[] and all(d['closed'] for d in c.get('descriptors', []))
            for c in r['commands'])
        if r['error'] or r['final_errors'] or not r['source_unchanged'] or r['artifacts_before']!=r['artifacts_after'] or not r['cleanup_complete']:
            r['status'] = 'failed'
        r['totals']=dict(planned=43 if r['reuse']else 40,launched=sum(c['launched']for c in r['cases']),qualified=sum(c['status'].startswith('qualified_')for c in r['cases']),
            native=sum(c['lane']=='native'and c['status'].startswith('qualified_')for c in r['cases']),
            gated=sum(c['lane']=='gated'and not c['control']and c['status'].startswith('qualified_')for c in r['cases']),
            owner_controls=sum(c['status']=='qualified_required_owner_refusal'for c in r['cases']),
            qualified_pairs=sum(c.get('pair',{}).get('qualified_case',0)for c in r['cases']if c['status'].startswith('qualified_')),
            completed_applications=sum(c['status'].startswith('qualified_')and c['control']==0 and (c['mode']<5 or c['mode']>=11) for c in r['cases']),
            required_read_faults=sum(c['status']=='qualified_required_read_failure'for c in r['cases']),
            required_reference_faults=sum(c['status']=='qualified_native_reference'and 5<=c['mode']<=10 for c in r['cases']),
            required_owner_refusals=sum(c['status']=='qualified_required_owner_refusal'for c in r['cases']),
            application_reader_refusals=sum(c.get('application_controls',{}).get('supplied_refusals',0)for c in r['cases']),
            terminal_reader_refusals=sum(len(c.get('terminal_controls',{}).get('refusals',[]))for c in r['cases']),
            owner_reader_refusals=sum(len(c.get('owner_reader_controls',{}).get('refusals',[]))for c in r['cases']),
            boundary_metadata_commands=sum(c['profile']=='boundary'for c in r['commands']))
        if r.get('certificate',False):
            r['totals'].update(certificate_owner_reader_refusals=sum(len(c.get('owner_reader_controls',{}).get('certificate_refusals',[]))for c in r['cases']),
                certificate_terminal_reader_refusals=sum(len(c.get('terminal_controls',{}).get('certificate_refusals',[]))for c in r['cases']),
                certificate_mapping_reader_refusals=sum(len(c.get('certificate_controls',{}).get('certificate_refusals',[]))for c in r.get('mapping_controls',{}).get('cases',[])))
        save(private/'receipt.json',r)
        hw=dict(r['hardware']);flags=hw.pop('isa_flags');hw.update(isa_flags_count=len(flags),isa_flags_sha256=digest(flags))
        public={k:r.get(k)for k in('schema','profile','status','expected_revision','started_utc','cpu','source','source_unchanged','cleanup_complete','bounds','totals','namespace_controls','prerequisites')}
        public['seed_prerequisite']={k:v for k,v in r['seed_prerequisite'].items()if k in
            ('planned','status','launched','expected_exit','bounds','owner_subjects','completed_applications','performance_credit',
             'elf','exit','pid','whole_process_ns','timed_out','captures','profile')}
        case_rows=[]
        for c in r['cases']:
            value={k:c[k]for k in('label','lane','mode','control','expected_exit','status','launched','exit','whole_process_ns','timed_out','captures','pair','owner_summary','control_reference','boundary_observation','error_type')if k in c}
            value['terminal_control_count']=len(c.get('terminal_controls',{}).get('refusals',[]));value['terminal_controls_sha256']=digest(c.get('terminal_controls',{}))
            value['application_control_count']=c.get('application_controls',{}).get('supplied_refusals',0)
            value['owner_control_count']=len(c.get('owner_reader_controls',{}).get('refusals',[]));value['owner_controls_sha256']=digest(c.get('owner_reader_controls',{}))
            case_rows.append(value)
        public.update(case_projection(case_rows))
        if r.get('certificate',False)and certificate_profile is not None:
            public['certificate_component']=certificate_profile.component_summary(r.get('certificate_component'))
        if r['reuse']:
            public['mapping_controls']=mapping_controls.public_summary(r.get('mapping_controls'))
            public['mapping_guard_oracle']=r.get('mapping_guard_summary',{'status':'unqualified'})
        public.update(hardware=hw,private_receipt=fact(private/'receipt.json'),
            reproduce=['python3','-B','evaluation/inprocess/scalar_region_owner.py','--expect-revision',args.expect_revision,
                '--decoder-receipt',str(args.decoder_receipt),'--component-receipt',str(args.component_receipt)]+(['--reuse']if r['reuse']else [])+(['--certificate']if r.get('certificate',False)else []),
            input_manifest_sha256=digest(pins),artifact_manifest_sha256=digest(artifacts),command_count=len(r['commands']),commands_sha256=digest(r['commands']),
            failure_type=r['error'].split(':',1)[0]if r['error']else None,final_error_count=len(r['final_errors']),
            performance_credit=False,whole_ls_eligibility_credit=False,
            scope='Required40 subjects:13 actual native references,13 actual generated-owner pairs including six real read faults, and14 required owner refusals. Repeat and generation cases bind actual immutable keys and fresh tickets. One separate unchanged seed prerequisite qualifies exact zero FIP/FDP on the same CPU and actual format. Each gated record has a separate bounded production-decoder metadata observation: full unsupported boundary descriptors are compared exactly; accepted forms/CFG/image are independently reconstructed. Neither metadata nor seed gives owner/application/performance credit. Whole native/gated GPR, actual AF, FP, stack and data comparisons are mandatory. Failed operations never count as completed applications. No general function/data-pointer authority or throughput claim.')
        if r['reuse']:
            public['scope']='Required43 owner subjects: unchanged13 native references,13 generated-owner pairs including six real read faults, and original14 plus3 actual completed-generation reuse refusals. All original40 remain mandatory. Full GPR/AF/FP/224stack/data and fresh source/rseq/cleanup joins remain exact. Thirty separately bounded production metadata observations cover at most70 current/historical windows each; no metadata execution authority. Eight mapping refusals and754 supplied range-predicate cases are separately counted with no graph-owner credit. No performance or whole-application coverage claim.'
        if r.get('certificate',False):
            public['scope']='Certificate profile: all43 owner subjects and original4102/1964/348 controls remain mandatory. Adds998 record,450 terminal and160 mapping controls; separate8 transaction cases/256 controls use supplied boundaries. Mapping8/152, predicate754 and38 metadata children remain required. Full GPR/AF/FP/224stack/data checks; no performance credit.'
        columns=('lane','mode','control','status','expected_exit','exit','whole_process_ns','application_control_count','terminal_control_count','owner_control_count')
        stream=io.StringIO(newline='');writer=csv.writer(stream,lineterminator='\n');writer.writerow(columns)
        for c in case_rows:writer.writerow([c.get(k,'')for k in columns])
        raw=stream.getvalue().encode();public_csv=HERE/'results'/(stem+'.csv');public_json=HERE/'results'/(stem+'.json')
        need(len(raw)<=8192,'all40 compact outcome CSV rows')
        public['csv']=dict(file=public_csv.name,bytes=len(raw),sha256=H(raw))
        if r['reuse']:
            original=json.dumps(public,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n'
            need(not any(x and len(x)>1 and(x in original or x in stream.getvalue())for x in(str(ROOT),str(Path.home()),platform.node(),'/home/')),
                 'complete uncompressed public numerical result has no private paths or host names')
            compact=scalar_case_strings.project(public)
            need(digest(scalar_case_strings.restore(json.loads(json.dumps(compact,allow_nan=False))))==digest(public),
                 'complete canonical typed public inverse including all case and mapping fields')
            public=compact
        encoded=json.dumps(public,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n'
        need(len(encoded.encode())<=32<<10 and not any(x and len(x)>1 and(x in encoded or x in stream.getvalue())for x in(str(ROOT),str(Path.home()),platform.node(),'/home/')),'compact public numerical result without private paths/host names')
        with public_csv.open('xb')as f:f.write(raw)
        with public_json.open('x')as f:f.write(encoded)
        print(json.dumps(dict(status=r['status'],result=str(public_json.relative_to(ROOT)),commands=len(r['commands']),failure_type=public['failure_type']),sort_keys=True))
    return 0 if r['status']=='passed'else 1
if __name__=='__main__':raise SystemExit(main())
