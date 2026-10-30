#!/usr/bin/env python3
"""Actual-TU REP zero-helper controls; no timing or runtime-owner qualification."""
import argparse
from datetime import datetime,timezone
import hashlib,json,os,platform,re,shlex,shutil,struct,sys
from pathlib import Path
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]
sys.path.insert(0,str(HERE))
from checks import source
from run import hardware
from page_selected import ENV,fact,need,save
from page_selected_process import invoke
SELECTED=ROOT/'tools/page-entry/selected'
FIXTURE=SELECTED/'tests/repeat_zero'
sys.path.insert(0,str(SELECTED/'tests/fast_equal'))
from equal_inspect import elf,operands,linked
BOUNDS=dict(metadata=[10,512<<20,16<<20,20],inspect=[10,512<<20,16<<20,20],
            build=[20,512<<20,16<<20,30],native=[5,512<<20,16<<20,15])
MACROS=['LI2_REPEAT_RX_LEASE','LI2_RUN_CACHE_REUSE','LI2_EFFECT_PROVIDER','LI2_ONESHOT_REUSABLE',
    'LI2_ONESHOT_PUBLICATION','LI2_TF_SEALED_CUSTODY','LI2_TF_SAME_PAGE_LEASE','LI2_TF_HANDOFF',
    'LI2_REGISTER_RUN','LI2_MAPS_PHASE_REUSE','LI2_RSEQ_INACTIVE','LI2_NATIVE_PAGES',
    'LI2_CPUID_NX_ONLY','LI2_RSEQ_NATIVE','LI2_RSEQ_NATIVE_BOUNDARY','LI2_RSEQ_TCGETS_BTRFS',
    'LI2_RSEQ_TIOCGWINSZ_BTRFS','LI2_FAST_MEMSET','LI2_FAST_EQUAL','LI2_REPEAT_ZERO_ORACLE']
HELPERS=[('step_owner','li2_repeat_owner_zero_oracle','repeat_lease_zero'),
         ('lifecycle_loader','li2_repeat_custody_zero_oracle','rep_zero')]


def digest(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()).hexdigest()


def body(path,nm_text,disassembly,wrapper,helper):
    data,h,sections,section_names,symbols=elf(path)
    need((wrapper,helper)in {(w,h)for _,w,h in HELPERS},'exact actual zero-helper family');fast=True;functions={}
    for s in symbols:
        if s['info']&15==2 and (s['name']==wrapper or re.fullmatch(re.escape(helper)+r'(?:\.(?:isra|constprop|part)\.[0-9]+)?',s['name'])):
            name=s['name'];need(name not in functions and s['section']<len(sections)and 0<s['bytes']<=512,'unique bounded actual function')
            sec=sections[s['section']];offset=s['value']if h[1]==1 else s['value']-sec[3]
            need(sec[1]==1 and sec[2]&6==6 and not sec[2]&1 and 0<=offset and offset+s['bytes']<=sec[5], 'complete nonwritable text section')
            raw=data[sec[4]+offset:sec[4]+offset+s['bytes']];need(len(raw)==s['bytes'],'whole function bytes')
            matches=[x.split()for x in nm_text.decode().splitlines()if x.split()[-1:]==[name]]
            need(len(matches)==1 and len(matches[0])==4 and matches[0][2]in('t','T')and
                 int(matches[0][0],16)==s['value']and int(matches[0][1],16)==s['bytes'],'nm and ELF symbol agree')
            functions[name]=dict(**s,offset=offset,raw=raw,insns=[])
    need(wrapper in functions,'actual external zero wrapper')
    current=None
    for line in disassembly.decode().splitlines():
        title=re.fullmatch(r'([0-9a-f]+) <([^>]+)>:',line.strip())
        if title:current=title[2]if title[2]in functions else None;continue
        if current is None:continue
        m=re.fullmatch(r'\s*([0-9a-f]+):\s*((?:[0-9a-f]{2}\s)+)\s*(\S.*)',line)
        if m:
            s=functions[current];at=int(m[1],16)
            if s['value']<=at<s['value']+s['bytes']:
                code=bytes.fromhex(m[2]);asm=m[3].strip().split('#',1)[0].strip()
                if code==b'\xc3'and asm=='retq':asm='ret'
                if len(code)==5 and code[0]==0xe9 and asm.startswith('jmpq '):asm='jmp '+asm[5:]
                s['insns'].append((at,code,asm))
    for s in functions.values():
        at=s['value']
        for pc,code,_ in s['insns']:need(pc==at and code,'contiguous body');at+=len(code)
        need(at==s['value']+s['bytes']and b''.join(i[1]for i in s['insns'])==s['raw'],'whole objdump bytes equal actual ELF')
    # ET_REL relocation bytes may differ at final link, but only the explicit
    # local helper branch field is permitted. Every other body byte stays exact.
    relocations={name:[]for name in functions}
    for sec in sections:
        if sec[1]!=4:continue
        need(sec[9]==24 and sec[5]%24==0 and sec[4]+sec[5]<=len(data),'whole RELA section')
        for at in range(sec[4],sec[4]+sec[5],24):
            offset,info,addend=struct.unpack_from('<QQq',data,at);kind=info&0xffffffff;symbol=info>>32
            for name,s in functions.items():
                if sec[7]!=s['section']or not s['offset']<=offset<s['offset']+s['bytes']:continue
                target=[x for x in symbols if x['table']==sec[6]and x['index']==symbol]
                need(len(target)==1 and kind in(2,4)and offset+4<=s['offset']+s['bytes'],'only bounded rel32 helper relocation')
                target=target[0];names=[n for n,v in functions.items()if target['section']==v['section']and
                     (target['name']==n or target['info']&15==3 and target['value']+addend+4==v['value'])]
                need(len(names)==1 and names[0]!=wrapper,'relocation names one actual local helper')
                relocations[name].append(dict(offset=offset-s['offset'],bytes=4,target=names[0],kind=kind,addend=addend))
    reached=set();pending=[wrapper];loads=[];edges=[];used_relocations=set()
    reg64=r'(?:r(?:ax|bx|cx|dx|si|di|bp|sp|[89]|1[0-5]))'
    prefix_nops={bytes.fromhex(x)for x in ('662e0f1f840000000000','66662e0f1f840000000000')}
    while pending:
        name=pending.pop()
        if name in reached:continue
        reached.add(name);s=functions[name];starts={x[0]for x in s['insns']}
        for pc,code,asm in s['insns']:
            op=asm.split()[0];args=asm[len(op):].strip()
            if op in ('cs','data16'):
                need(code in prefix_nops and re.fullmatch(r'(?:data16 )?cs nopw .+',asm)is not None,
                     'only exact non-memory canonical prefixed NOP padding');continue
            if op in ('ret',):need(code==b'\xc3','exact near return');continue
            if op.startswith('j'):
                need(op in ('jmp','je','jne','jb','ja','jbe','jae','jz','jnz'),'closed equality branch')
                m=re.fullmatch(r'([0-9a-f]+) <([^>]+)>',args);need(m is not None,'direct named branch')
                destination=int(m[1],16);symbol=m[2].split('+',1)[0]
                rel=[r for r in relocations[name]if pc-s['value']<r['offset']<pc-s['value']+len(code)]
                if rel:
                    need(op=='jmp'and len(rel)==1,'only helper tail relocation');symbol=rel[0]['target'];pending.append(symbol);edges.append((name,symbol))
                    used_relocations.add((name,rel[0]['offset']))
                elif symbol==name:need(destination in starts,'branch within actual function')
                else:
                    need(op=='jmp'and symbol in functions and destination==functions[symbol]['value'],'only local helper tail');pending.append(symbol);edges.append((name,symbol))
                continue
            need(op in ('mov','movzbl','movzbq','cmp','cmpb','cmpq','test','testb','testq','add','sub','and','or','xor','lea','nop','nopl','nopw','xchg','sete','setne'),
                 'only ordinary integer equality operations, no call/string/vector/privileged effects')
            if op in ('nop','nopl','nopw'):continue
            args=operands(args)
            register_form=r'%(?:r(?:ax|bx|cx|dx|si|di|bp|sp|[89]|1[0-5])|e(?:ax|bx|cx|dx|si|di|bp|sp)|(?:ax|bx|cx|dx|si|di|bp|sp)|[abcd][lh]|[sd]il|[bs]pl|r(?:[89]|1[0-5])[dwb])'
            integer=r'-?(?:0x[0-9a-f]+|[0-9]+)'
            address=r'(?:'+integer+r')?\((?:%'+reg64+r')?(?:,%'+reg64+r'(?:,[1248])?)?\)'
            need(all(re.fullmatch(register_form,x)or re.fullmatch(r'\$'+integer,x)or
                     re.fullmatch(address,x)and '%'in x for x in args),
                 'closed GPR/immediate/register-address operands; no absolute or unrecognized memory')
            # AT&T destinations are after the final comma; all data writes
            # must target GPRs. Address calculations/nops do not read memory.
            if op not in ('cmp','cmpb','cmpq','test','testb','testq'):
                need(args[-1].startswith('%'),'no memory-writing helper instruction')
                need(re.fullmatch(r'%(?:[re]?(?:bx|bp|sp)|b[lh]|bpl|spl|r(?:1[2-5])(?:d|w|b)?)',args[-1])is None,
                     'callee-saved registers and actual stack pointer untouched')
            if op=='or':
                need(len(args)==2 and re.fullmatch('%'+reg64,args[1])is not None and
                     (re.fullmatch('%'+reg64,args[0])is not None or re.fullmatch(address,args[0])is not None),
                     'only exact 64-bit read-only OR reduction into a GPR')
            if op=='xchg':need(len(args)==2 and args[0]==args[1],'only actual register self-exchange padding')
            memory=[x for x in args if '('in x]
            if not memory or op=='lea':continue
            need(op in ('mov','movzbl','movzbq','cmp','cmpb','cmpq','or')and len(args)==2 and len(memory)==1 and
                 not re.search(r'%(?:rip|eip|rsp|rbp|fs|gs)',memory[0]),'only input-register addressing')
            if op.startswith('mov')or op=='or':need(memory[0]==args[0],'load, never store')
            register=next(x for x in args if x not in memory)
            if register.startswith('$'):
                need(register in ('$0','$0x0')and op in ('cmpb','cmpq')and memory[0]==args[1],
                     'only exact read-only byte/word comparison against immediate zero')
                width=1 if op=='cmpb'else 8
            else:
                need(register.startswith('%'),'one memory read to/against register')
                if op in ('movzbl','movzbq','cmpb')or re.fullmatch(r'%(?:[abcd]l|[sd]il|r(?:[89]|1[0-5])b)',register):width=1
                else:need(re.fullmatch('%'+reg64,register)is not None,'exact eight-byte memory read');width=8
            loads.append(dict(function=name,offset=pc-s['value'],bytes=width))
    need(loads and any(x['bytes']==1 for x in loads)and any(x['bytes']==8 for x in loads),'actual word and byte-tail zero primitive')
    need(all((name,r['offset'])in used_relocations for name in reached for r in relocations[name]),'every body relocation belongs to an inspected direct helper tail')
    result={}
    for name in sorted(reached):
        s=functions[name];result[name]=dict(address=s['value'],bytes=s['bytes'],section=section_names[s['section']],
           code_hex=s['raw'].hex(),sha256=hashlib.sha256(s['raw']).hexdigest(),relocations=relocations[name],
           instructions=[dict(offset=pc-s['value'],bytes=b.hex(),text=a)for pc,b,a in s['insns']])
    return dict(fast=fast,elf_type=h[1],functions=result,loads=loads,edges=edges)



def layout(path):
    data,h,sections,names,symbols=elf(path)
    need(h[1]==2 and h[9]==56 and 0<h[10]<=32 and h[5]+56*h[10]<=len(data),
         'actual non-PIE hosted executable and complete program headers')
    ph=[struct.unpack_from('<IIQQQQQQ',data,h[5]+56*i)for i in range(h[10])]
    need(any(p[0]==1 and p[1]&1 and p[3]<=h[4]<p[3]+p[6]for p in ph), 'actual executable entry')
    need(all(p[0]!=1 or p[1]&3!=3 for p in ph) and
         any(p[0]==0x6474e551 and not p[1]&1 for p in ph),'no writable executable load or executable stack')
    found=[p for p in ph if p[0]==3];need(len(found)==1,'one actual interpreter')
    p=found[0];need(p[2]<=len(data)and 0<p[5]<=len(data)-p[2],'bounded actual interpreter bytes')
    raw=data[p[2]:p[2]+p[5]]
    need(raw.startswith(b'/')and raw.endswith(b'\0')and b'\0'not in raw[:-1],'exact interpreter path')
    return dict(elf_type=2,interpreter=raw[:-1].decode('ascii'),writable_executable=False,executable_stack=False)


def projection(r,private_receipt):
    hw=dict(r.get('hardware',{}));flags=hw.pop('isa_flags',None)
    if flags is not None:hw.update(isa_flags_count=len(flags),isa_flags_sha256=digest(flags))
    out={k:r.get(k)for k in ('schema','profile','status','expected_revision','source','source_unchanged',
        'started_utc','cpu','scope','build_status','rust_archive_used','numeric_versions','cases','cleanup_complete')}
    out.update(hardware=hw,bounds=BOUNDS,environment=ENV,private_receipt=private_receipt,
        commands=len(r['commands']),commands_sha256=digest(r['commands']),
        inputs_sha256=digest(r.get('inputs',{})),artifacts_sha256=digest(r.get('artifacts',{})),
        aliases_sha256=digest(r.get('aliases',{})),headers_sha256=digest(r['header_observations']),
        inspection_sha256=digest(r['inspection']),tools_sha256=digest(r.get('tools',{})),
        fixture=r.get('fixture'),configuration_presence=r.get('configuration_presence'),
        required_native_processes=1,actual_native_processes=sum(c['profile']=='native'and type(c.get('pid'))is int for c in r['commands']),
        native_commands=[{k:c.get(k)for k in ('name','exit','expected_exit','reaped','timed_out')}
                         for c in r['commands']if c['profile']=='native'],
        failure_type=r['error'].split(':',1)[0]if r['error']else ('FinalObservationError'if r['final_errors']else None),
        final_error_count=len(r['final_errors']),timing_measured=False,runtime_owner_qualification=False,
        application_performance_credit=False,
        reproduce=['python3','evaluation/inprocess/page_selected_repeat_zero.py','--expect-revision',r['expected_revision']],
        recipe=dict(source='Actual step_owner.c and lifecycle_loader.c; no copied or extracted helper',
          template='tools/page-entry/selected/tests/repeat_zero/build.sh',compile_commands=3,
          native=[dict(name='zero-controls',argv=['repeat-zero'])]),
        interpretation='One bounded supplied-input primitive process. Full-byte reference, read-only guarded inputs, unaligned/tail ranges and whole-owner boundaries; no signal, REP execution, application completion or speedup credit. Actual accepted counts appear only after exact output and cleanup acceptance.')
    text=json.dumps(out,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n'
    need(len(text.encode())<8192 and not re.search(r'/home/|devbig[0-9]+|internalfb\.com',text)and
         not any(x and len(x)>1 and x in text for x in (str(ROOT),str(Path.home()),platform.node())),
         'public projection below8KiB without private locations/names')
    return text


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--expect-revision',required=True);args=ap.parse_args()
    need(not sys.flags.optimize and re.fullmatch('[0-9a-f]{40}',args.expect_revision)and len(os.sched_getaffinity(0))==1,
         'exact committed revision, enabled assertions, one reserved CPU')
    os.chdir(ROOT);cpu=next(iter(os.sched_getaffinity(0)));stamp=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    stem=stamp+'-page-selected-repeat-zero-'+args.expect_revision[:12]
    private=ROOT/'target/evaluation/inprocess'/stem;private.mkdir(parents=True,exist_ok=False)
    public=HERE/'results'/(stem+'.json');need(not public.exists(),'unique public receipt')
    build=private/'build';build.mkdir()
    r=dict(schema=1,profile='page-selected-repeat-zero-v1',status='failed',expected_revision=args.expect_revision,
      source=None,source_unchanged=False,started_utc=stamp,cpu=cpu,
      scope='Finite actual-TU whole-range zero checks only. No owner lifecycle, signal, application, timing or performance qualification.',
      build_status='not_started',rust_archive_used=False,commands=[],cases=[],error=None,final_errors=[],inspection={},header_observations=[])
    pins,aliases,artifacts,tools,versions,presence={},{},{},{},{},{}
    env=dict(ENV)
    def pin(path):
        need(path is not None,'input exists');lexical=str(Path(path).absolute());resolved=Path(lexical).resolve(strict=True)
        need(lexical not in aliases or aliases[lexical]==str(resolved),'lexical alias changed');aliases[lexical]=str(resolved)
        value=fact(resolved);need(str(resolved)not in pins or pins[str(resolved)]==value,'input bytes changed');pins[str(resolved)]=value
        return resolved
    def binary(path):
        path=Path(path);need(path.is_file()and not path.is_symlink(),'regular retained output')
        value=dict(fact(path),mode=path.stat().st_mode&0o777)
        need(str(path)not in artifacts or artifacts[str(path)]==value,'artifact bytes/mode changed');artifacts[str(path)]=value;return path
    def closure():
        need(all(Path(p).exists()==v for p,v in presence.items()),'loader configuration presence')
        need(all(str(Path(a).resolve(strict=True))==p for a,p in aliases.items()),'all lexical input aliases')
        need(all(fact(p)==v for p,v in pins.items()),'source/tool/header input closure')
        need(all(dict(fact(p),mode=Path(p).stat().st_mode&0o777)==v for p,v in artifacts.items()),'exact artifact closure')
    def run(name,argv,profile='metadata'):
        closure();need(not any(c['name']==name for c in r['commands']),'unique capture name')
        row=dict(name=name,argv=list(map(str,argv)),profile=profile,bounds=BOUNDS[profile],expected_exit=0,
            capture_limit=65536 if profile=='native'else 4<<20,environment=dict(env))
        r['commands'].append(row);out,err=invoke(row,private,cpu)
        need(type(row['exit'])is int and row['exit']==0,'actual command exit '+name);return row,out,err
    expected_outputs=[build/name for name in ('step_owner.o','lifecycle_loader.o','repeat-zero')]
    try:
        tools['git']=pin('/usr/bin/git')
        r['source']=source();need(r['source']['revision']==args.expect_revision,'exact clean current source')
        r['hardware']=hardware(cpu)
        _,out,err=run('source-paths',[tools['git'],'-C',ROOT,'ls-files','-z','tools/page-entry','evaluation/inprocess'])
        need(not err,'source enumeration stderr')
        for value in out.split(b'\0'):
            if value and not os.fsdecode(value).startswith('evaluation/inprocess/results/'):pin(ROOT/os.fsdecode(value))
        for module in tuple(sys.modules.values()):
            file=getattr(module,'__file__',None)
            if file and Path(file).resolve().is_relative_to(ROOT):pin(file)
        for name in ('cc','nm','objdump','readelf'):tools[name]=pin(shutil.which(name,path=ENV['PATH']))
        tools['python']=pin(sys.executable)
        for name in ('cc1','collect2','as','ld'):
            _,out,err=run('resolve-'+name,[tools['cc'],'-print-prog-name='+name]);value=out.decode().strip()
            need(value and not err,'actual C subtool');tools[name]=pin(value if Path(value).is_absolute()else shutil.which(value,path=ENV['PATH']))
        for name in ('cc','nm','objdump','readelf','ld','as','python'):
            _,out,err=run('version-'+name,[tools[name],'--version']);need(not err,'tool version stderr')
            match=re.search(r'\b([0-9]+)\.([0-9]+)(?:\.([0-9]+))?\b',out.decode());need(match is not None,'numeric version')
            versions[name]=[int(match[1]),int(match[2]),int(match[3]or 0)]
        for name in ('crt1.o','Scrt1.o','crti.o','crtn.o','crtbegin.o','crtbeginS.o','crtend.o','crtendS.o','libgcc.a','libgcc_s.so','libc.so','libc_nonshared.a'):
            _,out,err=run('link-input-'+name,[tools['cc'],'-print-file-name='+name]);value=out.decode().strip()
            need(not err and Path(value).is_absolute(),'actual C runtime link input');pin(value)
        _,_,err=run('cc-specs',[tools['cc'],'-dumpspecs']);need(not err,'compiler specs stderr')
        for name in ('/etc/ld.so.cache','/etc/ld.so.preload'):
            presence[name]=Path(name).exists()
            if presence[name]:pin(name)
        need(not presence['/etc/ld.so.preload'],'no global preload')
        recipe=pin(FIXTURE/'build.sh');text=recipe.read_text().replace('\\\n',' ')
        profile=[shlex.split(line.split('=',1)[1])for line in text.splitlines()if line.startswith('profile=')]
        need(len(profile)==1 and len(profile[0])==1,'one literal fixed macro profile')
        macros=shlex.split(profile[0][0]);need(macros==['-D'+name+'=1'for name in MACROS],'exact production profile plus test-only wrapper macro')
        lines=[shlex.split(line.strip())for line in text.splitlines()if line.strip().startswith('"$cc_bin" ')]
        need(len(lines)==2,'actual two-TU object template and one libc fixture link')
        commands=[]
        for index,name in enumerate(('step_owner','lifecycle_loader','oracle')):
            values={'$cc_bin':str(tools['cc']),'$selected_context':str(SELECTED),'$parent_context':str(SELECTED.parent),
                '$fixture_dir':str(FIXTURE),'$output_dir':str(build),'$source':name}
            argv=[]
            for word in lines[0 if index<2 else 1]:
                if word=='$profile':argv+=macros;continue
                for key,value in values.items():word=word.replace(key,value)
                need('$'not in word and '`'not in word,'literal source-bound compiler argv');argv.append(word)
            source_path=pin(SELECTED/(name+'.c')if index<2 else FIXTURE/'oracle.c')
            need(argv[0]==str(tools['cc'])and argv[-2:]==['-o',str(expected_outputs[index])]and
                 [x for x in argv if x.endswith('.c')]==[str(source_path)]and
                 [x for x in argv if x.startswith('-D')]==macros,'actual original translation unit, output and complete profile')
            need(all(x in argv for x in ('-std=gnu11','-O2','-g','-fno-builtin','-fno-stack-protector',
                '-fno-tree-loop-distribute-patterns','-fno-tree-vectorize','-mgeneral-regs-only',
                '-fno-asynchronous-unwind-tables','-ffunction-sections','-fdata-sections','-Wall','-Wextra','-Werror')),
                'unchanged release helper/compiler bounds')
            if index<2:need('-c'in argv and '-fPIC'in argv and '-fvisibility=hidden'in argv,'actual production TU flags')
            else:need('-c'not in argv and '-no-pie'in argv and '-fno-pie'in argv and
                [x for x in argv if x.endswith('.o')]==list(map(str,expected_outputs[:2]))and
                '-Wl,--gc-sections,-z,noexecstack,--build-id=none'in argv,'only two real objects, fixed dynamic non-PIE link')
            need(not any(x.endswith('.a')for x in argv),'no decoder archive or helper stub')
            flags=[x for x in argv[1:-2]if x!=str(source_path)and not x.endswith('.o')and x!='-c'and not x.startswith('-Wl,')]
            row,out,err=run('headers-'+name,[tools['cc'],*flags,'-M','-MT','li2_zero_headers',source_path])
            rule=out.decode().replace('\\\n',' ');need(not err and len(rule.splitlines())==1 and rule.startswith('li2_zero_headers: '),'one complete conditional header rule')
            deps=shlex.split(rule.split(':',1)[1]);need(len(deps)==len(set(deps))and str(source_path)in deps and all(Path(x).is_absolute()for x in deps),'actual lexical dependencies')
            observed={x:dict(resolved=str(pin(x)),**fact(x))for x in deps}
            required=('repeat_lease.h','repeat_lease.inc')if index==0 else ('repeat_custody.h','repeat_custody.inc')if index==1 else ('repeat_lease.h',)
            need(all(str(SELECTED/n)in observed for n in required),'actual complete helper/header inclusion, never copied helper')
            r['header_observations'].append(dict(translation_unit=str(source_path),argv=argv,headers=observed,command=row['name']))
            commands.append((name,argv))
        r['build_status']='started'
        for name,argv in commands:
            _,out,err=run('build-'+name,argv,'build');need(out==err==b'','quiet exact compile/link');binary(argv[-1])
        r['build_status']='compiled';path=expected_outputs[-1]
        for unit,wrapper,helper in HELPERS:
            inspected=r['inspection'][unit]={}
            for kind,actual in (('object',build/(unit+'.o')),('final',path)):
                _,symbols,err=run(unit+'-'+kind+'-symbols',[tools['nm'],'-S','--defined-only',actual],'inspect');need(not err,'actual symbol stderr')
                *_,symtab=elf(actual)
                names=[x['name']for x in symtab if x['info']&15==2 and (x['name']==wrapper or re.fullmatch(re.escape(helper)+r'(?:\.(?:isra|constprop|part)\.[0-9]+)?',x['name']))]
                need(1<=len(names)<=8 and len(names)==len(set(names)),'bounded complete helper symbol set')
                blocks=[]
                for number,symbol in enumerate(sorted(names)):
                    _,code,err=run(unit+'-'+kind+'-body-'+str(number),[tools['objdump'],'-d','-w','-M','att','--disassemble='+symbol,actual],'inspect')
                    need(not err,'actual helper body stderr');blocks.append(code)
                inspected[kind]=body(actual,symbols,b'\n'.join(blocks),wrapper,helper)
            need(linked(inspected['object'],inspected['final']),'complete actual object-to-final helper identity')
        need(artifacts[str(path)]['mode']&0o111,'actual executable mode');actual_layout=layout(path)
        _,_,err=run('fixture-elf',[tools['readelf'],'-h','-l','-d','-r','-W',path],'inspect');need(not err,'actual ELF stderr')
        loader=pin(actual_layout['interpreter']);_,out,err=run('fixture-libraries',[loader,'--list',path]);need(not err,'actual library stderr')
        libraries={};vdso=0
        for line in out.decode().splitlines():
            if re.fullmatch(r'\s*linux-vdso\.so\.1 \(0x[0-9a-f]+\)',line):vdso+=1;continue
            match=re.fullmatch(r'\s*(?:(\S+) => )?(/\S+) \(0x[0-9a-f]+\)',line);need(match is not None,'closed actual dependency row')
            key=match[1]or'interpreter'
            if match[1]and match[1].startswith('/'):
                need(pin(match[1])==pin(match[2])==loader,'both actual interpreter aliases');key='interpreter'
            need(key not in libraries,'unique dependency');libraries[key]=dict(path=str(pin(match[2])),**fact(match[2]))
        need(vdso==1 and set(libraries)=={'libc.so.6','interpreter'}and libraries['interpreter']['path']==str(loader),'only actual libc/interpreter')
        r['inspection']['executable']=dict(layout=actual_layout,libraries=libraries);r['fixture']=fact(path)
        r['build_status']='passed';case=dict(name='zero-controls',accepted=False,actual_exit=None);r['cases'].append(case)
        try:row,out,err=run('zero-controls',[path],'native')
        finally:
            if r['commands']and r['commands'][-1]['name']=='zero-controls':case['actual_exit']=r['commands'][-1].get('exit')
        # The fixed expected call arithmetic is bound to the independently reviewed C matrix.
        expected=dict(version=1,status=0,error=0,fast=1,owner_bytes=269440,short_cases=2322,
            large_cases=24,null_guard_cases=3,calls=[[4695,298572,404057454],[4695,298572,404057454]],
            verified_bytes=15998976,opened=2,closed=2)
        need(not err and out==(json.dumps(expected,separators=(',',':'))+'\n').encode(),'exact complete numeric helper cohort')
        case.update(accepted=True,result=expected,record=fact(private/'zero-controls.stdout'))
        need(len(r['cases'])==1 and r['cases'][0]['accepted']and sum(c['profile']=='native'for c in r['commands'])==1,'one actual complete fixed helper process')
        r['status']='passed'
    except BaseException as exc:r['error']=type(exc).__name__+': '+str(exc)
    finally:
        for path in expected_outputs:
            try:
                if os.path.lexists(path):binary(path)
            except BaseException as exc:r['final_errors'].append('partial artifact '+path.name+': '+repr(exc))
        for alias,path in aliases.items():
            try:need(str(Path(alias).resolve(strict=True))==path,'final alias')
            except BaseException as exc:r['final_errors'].append('alias '+alias+': '+repr(exc))
        for path,before in pins.items():
            try:need(fact(path)==before,'final input')
            except BaseException as exc:r['final_errors'].append('input '+path+': '+repr(exc))
        for path,before in artifacts.items():
            try:need(dict(fact(path),mode=Path(path).stat().st_mode&0o777)==before,'final artifact')
            except BaseException as exc:r['final_errors'].append('artifact '+path+': '+repr(exc))
        for row in r['commands']:
            try:
                need(row.get('reaped')and not row.get('timed_out')and not row.get('error')and not row.get('cleanup_errors')and all(x['closed']for x in row.get('descriptors',[])),'actual cleanup')
                for cap in row.get('captures',{}).values():
                    need(Path(cap['file']).name==cap['file']and fact(private/cap['file'])=={k:cap[k]for k in ('bytes','sha256')},'actual capture bytes')
            except BaseException as exc:r['final_errors'].append('command '+row['name']+': '+repr(exc))
        try:closure()
        except BaseException as exc:r['final_errors'].append('closure: '+repr(exc))
        try:r['source_after']=source();r['source_unchanged']=r['source_after']==r['source'];need(r['source_unchanged'],'source changed')
        except BaseException as exc:r['final_errors'].append('source: '+repr(exc))
        r['cleanup_complete']=all(x.get('reaped')and not x.get('timed_out')and not x.get('error')and not x.get('cleanup_errors')and all(d['closed']for d in x.get('descriptors',[]))for x in r['commands'])
        if r['error']or r['final_errors']or not r['cleanup_complete']:r['status']='failed'
        r.update(inputs=pins,aliases=aliases,artifacts=artifacts,configuration_presence=presence,
          tools={k:dict(path=str(v),**pins[str(v)])for k,v in tools.items()},numeric_versions=versions,environment=env)
        save(private/'receipt.json',r)
        try:
            text=projection(r,fact(private/'receipt.json'))
            public.parent.mkdir(parents=True,exist_ok=True)
            with public.open('x')as f:f.write(text)
        except BaseException as exc:
            r['final_errors'].append('projection: '+repr(exc));r['status']='failed';save(private/'receipt.json',r)
    print(json.dumps(dict(status=r['status'],commands=len(r['commands']),cases=len(r['cases']),receipt=str((private/'receipt.json').relative_to(ROOT)),public=str(public.relative_to(ROOT)))))
    return int(r['status']!='passed')


if __name__=='__main__':raise SystemExit(main())
