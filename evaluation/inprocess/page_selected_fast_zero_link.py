"""Actual bridge extraction and definition-only fixture adapters; no copied memset."""
import hashlib
import json
from pathlib import Path
import re
import shlex
import struct

from page_selected import elf, fact, need
from page_selected_components import plain_executable
from page_selected_register import executable_layout
from page_selected_register_controls import control_layout
from page_selected_register_time_build import recipe, expand
from page_selected_register_time_compare import decode
from page_selected_chain_fixture_build import ROOTS
from page_selected_fast_memset import body_check

OLD = b'void *memset(void *d,int c,size_t n) {unsigned char *p=d;for(size_t i=0;i<n;i++)p[i]=(unsigned char)c;return d;}\n'
NEW = b'void *memset(void *,int,size_t);\n'
PREDECESSORS = {
    'generic':'b0c758cb466ef3f8a35442f7cecbda77eb58c269a7ac90270d769c53440b2910',
    'chain':'3f21a0ed42e34c459d3a510471dd1056f9282bbf2897b0dd583997ec7517cdb0',
    'register':'ecf5a0a0ad92a5ab88ba46c2b11eaff5bba0ff07fb0dfd466c237bc9324f833c',
    'controls':'49f738fab848dc56e64f4d3e52cc9f0e1320d4c968953dfdeaca474c3138f31d',
}


def adapt(source, target, kind, pin, binary, state):
    before = pin(source).read_bytes()
    need(hashlib.sha256(before).hexdigest() == PREDECESSORS[kind] and before.count(OLD) == 1,
         'exact scalar fixture predecessor')
    after = before.replace(OLD, NEW)
    need(after.count(NEW) == 1 and after.replace(NEW, OLD) == before, 'complete definition-only inverse')
    with target.open('xb') as f: f.write(after)
    binary(target);pin(target)
    need(source.read_bytes() == before and target.read_bytes() == after, 'adapter byte closure')
    state.setdefault('adapters', []).append(dict(kind=kind, source=fact(source), result=fact(target)))
    return target


def memset_body(path, extracted=False):
    """Read actual ELF section/symbol bytes without executing or trusting nm text."""
    b=Path(path).read_bytes();need(len(b)>=64 and b[:7]==b'\x7fELF\x02\x01\x01','ELF64 little endian')
    h=struct.unpack_from('<16sHHIQQQIHHHHHH',b)
    need(h[2]==62 and h[1] in (1,2,3) and h[11]==64 and 0<h[12]<65536 and h[13]<h[12], 'closed ELF section table')
    need(h[6]+h[11]*h[12]<=len(b),'whole ELF section table')
    sections=[struct.unpack_from('<IIQQQQIIQQ',b,h[6]+64*i)for i in range(h[12])]
    def content(index):
        s=sections[index];need(s[1]!=8 and s[4]+s[5]<=len(b),'whole file-backed section')
        return b[s[4]:s[4]+s[5]]
    symbols=[];undefined=[];globals_=[]
    for index,s in enumerate(sections):
        if s[1]!=2:continue
        need(s[9]==24 and s[5]%24==0 and s[6]<len(sections),'whole actual symtab')
        strings=content(s[6]);raw=content(index)
        for off in range(0,len(raw),24):
            name,info,other,section,value,size=struct.unpack_from('<IBBHQQ',raw,off)
            need(name<len(strings) and b'\0' in strings[name:],'bounded symbol name')
            name=strings[name:strings.index(0,name)].decode('ascii')
            if name and section==0:undefined.append(name)
            if name and section!=0 and info>>4 in (1,2):globals_.append(name)
            if name=='memset':symbols.append((info,other,section,value,size))
    need(len(symbols)==1,'one actual memset symbol')
    info,other,index,address,size=symbols[0]
    need(info==0x12 and index<len(sections) and size>0,'global function memset')
    s=sections[index];offset=address if h[1]==1 else address-s[3]
    need(s[2]&6==6 and not s[2]&1 and 0<=offset and offset+size<=s[5], 'whole memset in executable readonly section')
    body=content(index)[offset:offset+size]
    for relocation in sections:
        if relocation[1] in (4,9) and relocation[7]==index:
            need(relocation[5]==0,'memset has no relocations')
    if extracted:
        need(h[1]==1 and globals_==['memset'] and not undefined,'sole extracted global and no undefined symbols')
        need(all(not(q[2]&2) or q[5]==0 or (i==index and offset==0 and size==q[5])
                 for i,q in enumerate(sections)),'only actual function has allocated bytes')
    return dict(address=address,bytes=size,sha256=hashlib.sha256(body).hexdigest(),body=body)


def headers(label,argv,builder,pin,run,state,required=()):
    sources=[x for x in argv[1:-2]if x.endswith(('.c','.S'))]
    need(sources and len(sources)==len(set(sources)),'unique actual translation units')
    flags=[x for x in argv[1:-2]if x not in sources and not x.endswith(('.a','.o'))
           and not x.startswith('-Wl,')and x!='-c']
    _,out,err=run(label,[builder.tools['cc'],*flags,'-M','-MT','li2_fast_zero',*sources],profile='metadata',env=builder.environment)
    lines=out.decode().replace('\\\n',' ').splitlines()
    need(not err and len(lines)==len(sources) and all(x.startswith('li2_fast_zero: ')for x in lines),'one actual include rule per TU')
    deps={}
    for line in lines:
        for name in shlex.split(line.split(':',1)[1]):deps[str(pin(name))]=fact(name)
    need(set(map(str,map(Path,sources)))<=set(deps) and set(map(str,required))<=set(deps),'actual source and required adapted include closure')
    state.setdefault('units',[]).append(dict(argv=argv,headers=deps));return deps


def compile_retained(label,argv,run,binary,builder,pending,errors):
    target=Path(argv[-1]);need(argv[-2]=='-o' and not target.exists(),'unique new output')
    pending.append(target)
    try:return run(label,argv,profile='fixture_link',env=builder.environment)
    finally:
        try:
            if target.is_file():binary(target)
        except BaseException as exc:errors.append('partial artifact retention: '+repr(exc))


def extract(builder,products,root,private,pin,binary,run,record,pending):
    selected=root/'tools/page-entry/selected';output=private/'extracted';output.mkdir()
    script=pin(selected/'build-rseq-inactive.sh');commands=recipe(script,'"$cc_bin"')
    need(len(commands)==3 and commands[0]==['$cc_bin','--version','>','$output_dir/cc-version.txt'],
         'exact compiler metadata followed by production bridge and observer recipes')
    commands=commands[1:]
    argv=expand(commands[0],{'$cc_bin':builder.tools['cc'],'$parent_dir':selected.parent,
        '$source_dir':selected,'$output_dir':output})
    units=[x for x in argv[1:-2]if x.endswith(('.c','.S'))]
    need(len(units)==13 and units[0]==str(selected.parent/'bridge.c'),'actual unobserved production13TU recipe')
    flags=[x for x in argv[1:-2]if x not in units and not x.endswith('.a')and not x.startswith('-Wl,')]
    need(all(x in flags for x in ('-O2','-g','-fPIC','-fvisibility=hidden','-mgeneral-regs-only',
         '-fno-builtin','-fno-tree-loop-distribute-patterns','-fno-tree-vectorize','-ffunction-sections','-fdata-sections',
         '-DLI2_TF_HANDOFF=1','-DLI2_REGISTER_RUN=1','-DLI2_MAPS_PHASE_REUSE=1','-DLI2_RSEQ_INACTIVE=1')),
         'exact optimized production flags and macros')
    full=output/'bridge-fast.o';raw=output/'bridge-memset-debug.o';leaf=output/'bridge-memset.o'
    command=[builder.tools['cc'],*flags,'-DLI2_FAST_MEMSET=1','-c',pin(selected.parent/'bridge.c'),'-o',full]
    command=list(map(str,command));state=record['extraction']=dict(status='failed',recipe=fact(script))
    headers('bridge-headers',command,builder,pin,run,state)
    compile_retained('bridge-object',command,run,binary,builder,pending,record['final_errors'])
    before=memset_body(full)
    compile_retained('memset-extract',[str(builder.tools['ld']),'-r','--gc-sections','--undefined=memset',str(full),'-o',str(raw)],
                     run,binary,builder,pending,record['final_errors'])
    need(memset_body(raw)['body']==before['body'],'actual bridge body survives section extraction exactly')
    # GNU ld preserves debug relocations and their now-unused undefined symbols.
    # Remove that metadata from a retained copy; keep the final leaf guard strict.
    need(not leaf.exists(),'unique stripped helper output');pending.append(leaf)
    try:
        run('memset-strip',[builder.tools['objcopy'],'--strip-debug','--strip-unneeded','--keep-symbol=memset',raw,leaf],
            profile='fixture_link',env=builder.environment)
    finally:
        try:
            if leaf.is_file():binary(leaf)
        except BaseException as exc:record['final_errors'].append('partial stripped artifact retention: '+repr(exc))
    after=memset_body(leaf,True);need(before['body']==after['body'],'actual bridge body survives extraction exactly')
    _,out,err=run('memset-undefined',[builder.tools['nm'],'-u',leaf],profile='inspect',env=builder.environment)
    need(out==err==b'','no unresolved extracted helper')
    state.update(status='passed',whole_object=fact(full),debug_object=fact(raw),object=fact(leaf),
                 function={k:v for k,v in after.items()if k!='body'})
    return leaf,after['body']


def build_group(kind,builder,products,root,private,pin,binary,run,state,leaf,body,pending,errors):
    selected=root/'tools/page-entry/selected';folder={'generic':'generic','chain':'trace_chain','register':'register_run',
        'controls':'register_run_controls','repeat':'repeat'}[kind]
    fixture=selected/'tests'/folder;state.update(status='failed',layouts={},fixtures={},elf={})
    originals=private/'original-support';originals.mkdir()
    if kind in ('chain','register','controls'):
        args=[builder.tools['python'],pin(fixture/'prepare.py'),pin(selected/'tests/generic/fixture.c')]
        if kind=='controls':args += [pin(selected/'tests/register_run/fixture.c'),originals]
        else:args += [originals/('chain_support.inc'if kind=='chain'else'run_support.inc')]
        pending.extend(originals/name for name in (('run_support.inc','control_support.inc')if kind=='controls'else
            ('chain_support.inc',)if kind=='chain'else('run_support.inc',)))
        _,out,err=run('fixture-support',args,profile='metadata',env=builder.environment)
        need(not err,'unchanged support generator stderr');state['generator']=decode(out)
        expected = ({'run_support.inc':{'bytes':34613,'sha256':PREDECESSORS['controls']},
                     'control_support.inc':{'bytes':30510,'sha256':'bae491633d24aaeb03c59e533d2cb3eae77100d801341d97eb04585309748d7f'}}
                    if kind=='controls'else dict(source_sha256=PREDECESSORS['generic'],source_bytes=34870,
                        generated_sha256=PREDECESSORS[kind],generated_bytes=34630 if kind=='chain' else 34605))
        need(state['generator']==expected,'exact unchanged generator observation')
        support='chain_support.inc'if kind=='chain'else'run_support.inc'
        pending.append(private/support)
        adapted=adapt(originals/support,private/support,kind,pin,binary,state)
        if kind=='controls':
            source=pin(originals/'control_support.inc')
            need(fact(source)=={'bytes':30510,'sha256':'bae491633d24aaeb03c59e533d2cb3eae77100d801341d97eb04585309748d7f'},'unchanged controls support')
            target=private/source.name;pending.append(target)
            with target.open('xb')as f:f.write(source.read_bytes())
            binary(target);pin(target)
    else:
        shadow=private/'include/tests/generic';shadow.mkdir(parents=True)
        pending.append(shadow/'fixture.c')
        adapted=adapt(selected/'tests/generic/fixture.c',shadow/'fixture.c','generic',pin,binary,state)
    templates=recipe(pin(fixture/'build.sh'),'"$cc_bin"')
    need(len(templates)==(2 if kind=='controls'else 1),'exact existing fixture recipe count')
    values={'$cc_bin':builder.tools['cc'],'$source_dir':fixture,'$fixture_dir':fixture,'$selected_dir':selected,
        '$parent_dir':selected.parent,'$decoder_archive':products['archive'],'$output_dir':private}
    if kind=='controls':
        argv=expand(templates[0],values);headers('publisher-headers',argv,builder,pin,run,state)
        compile_retained('publisher-build',argv,run,binary,builder,pending,errors)
        _,out,err=run('publisher-adapter-import',[builder.tools['nm'],'-u',private/'publisher-controls.o'],profile='inspect',env=builder.environment)
        imports=[x.split()[-1]for x in out.splitlines()if x.split()]
        need(not err and imports.count(b'li2_control_raw')==1 and b'li2_step_raw'not in imports,'only publisher object binds named raw-control adapter')
    fixtures={}
    for group in range(4 if kind=='register'else 1):
        argv=expand(templates[-1],dict(values,**{'$group':group}));original=list(argv)
        if kind=='generic':
            needle=str(fixture/'fixture.c');need(argv.count(needle)==1,'one generic source substitution');argv[argv.index(needle)]=str(adapted)
        if kind=='repeat':
            index=next(i for i,x in enumerate(argv)if x.startswith('-I'));argv.insert(index,'-I'+str(private/'include'))
        argv.insert(-2,str(leaf));state.setdefault('recipes',[]).append(dict(original=original,adapted=argv))
        label='header-dependencies'if kind=='repeat'else'fixture-'+str(group)+'-headers'
        required=[adapted]
        if kind=='repeat':required += [selected/'repeat_owner.h',selected/'repeat_owner.inc']
        deps=headers(label,argv,builder,pin,run,state,required)
        if kind=='generic':need(str(selected/'tests/generic/fixture.c')not in deps,'no unadapted scalar definition consumed')
        compile_retained('fixture-build'if kind=='repeat'else'fixture-'+str(group)+'-build',argv,run,binary,builder,pending,errors)
        path=Path(argv[-1]);fixtures[path.name]=path;state['fixtures'][path.name]=fact(path)
        state['elf'][path.name]=plain_executable(path)
        need(memset_body(path)['body']==body,'final actual helper bytes equal extracted product body')
        _,out,err=run('fixture-undefined'if kind=='repeat'else path.name+'-undefined',[builder.tools['nm'],'-u',path],profile='inspect',env=builder.environment)
        need(out==err==b'','no fixture undefined symbols')
        if kind=='generic':
            _,symbols,err=run('memset-symbols',[builder.tools['nm'],'-S','--defined-only',path],profile='inspect',env=builder.environment)
            need(not err,'actual final helper symbol stderr')
            _,disassembly,err=run('memset-disassembly',[builder.tools['objdump'],'-d','-w','-M','att','--disassemble=memset',path],profile='inspect',env=builder.environment)
            need(not err,'actual final helper disassembly stderr')
            state['actual_body']=body_check(path,symbols,disassembly,'fast',symbol_name='memset')
            need(bytes.fromhex(state['actual_body']['code_hex'])==body,'shared actual ABI/body validator binds extracted bytes')
        if kind in ('register','controls'):
            _,out,err=run(path.name+'-layout',[builder.tools['nm'],'-S','--defined-only',path],profile='inspect',env=builder.environment)
            need(not err,'actual record symbols stderr')
            state['layouts'][path.name]=(executable_layout if kind=='register'else control_layout)(path,out)
        if kind=='repeat':
            _,out,err=run('fixture-sections',[builder.tools['readelf'],'-S','-W',path],profile='inspect',env=builder.environment)
            need(not err and b'.debug_info 'in out and b'.debug_abbrev 'in out and b'.debug_line 'in out,'retain actual executable DWARF')
    state['status']='passed';return fixtures,fixture


def chain_layout(binary_path,builder,binary,run,state,pin,root,gdb_environment):
    _,out,err=run('chain-symbols',[builder.tools['nm'],'-S','--defined-only',binary_path],
        profile='inspect',env=builder.environment)
    need(not err,'actual record symbol inspection stderr')
    _,_,segments=elf(binary_path);symbols={};counts={k:0 for k in ROOTS}
    for line in out.decode('ascii').splitlines():
        words=line.split()
        if words and words[-1] in ROOTS:counts[words[-1]]+=1
        if len(words)!=4 or words[-1] not in ROOTS:continue
        address,size,kind,key=words
        need(key not in symbols and kind in ('b','B') and re.fullmatch('[0-9a-fA-F]+',address) and
             re.fullmatch('[0-9a-fA-F]+',size),'unique actual BSS record identity')
        address,size=int(address,16),int(size,16)
        need(size>0 and sum(s[0]==1 and s[1]==6 and s[3]<=address<address+size<=s[3]+s[6]
             for s in segments)==1,'whole actual record in writable NX ELF segment')
        symbols[key]=dict(address=address,bytes=size)
    need(set(symbols)==ROOTS and all(n==1 for n in counts.values()),'three unique complete ELF record symbols')
    intervals=sorted((x['address'],x['address']+x['bytes'])for x in symbols.values())
    need(all(a[1]<=b[0]for a,b in zip(intervals,intervals[1:])),'actual record objects disjoint')
    state['symbols']=symbols
    dwarf=pin(root/'evaluation/inprocess/page_selected_chain_dwarf.py')
    _,out,err=run('chain-dwarf',[builder.tools['gdb'],'-q','-nx','-batch','-iex','set auto-load off',
        '-iex','set debuginfod enabled off','-iex','set index-cache enabled off',
        '-iex','maintenance set worker-threads 1','--readnow',
        '--se='+str(binary_path),'-x',dwarf],profile='metadata',env=gdb_environment)
    need(not err,'file-only actual DWARF stderr');layout=decode(out)
    need(set(layout)==ROOTS and all(layout[k]['bytes']==symbols[k]['bytes']for k in ROOTS),
         'actual DWARF and ELF agree for every complete record')
    need(layout['samples']['kind']=='array' and layout['samples']['count']==21 and
         sum((layout['li2_chain_record']['bytes'],layout['samples']['element']['bytes'],layout['ctl']['bytes']))<16<<20,
         'unchanged finite record extent below actual16MiB cap')
    state['layout']=layout;state['status']='passed';return binary_path,layout
