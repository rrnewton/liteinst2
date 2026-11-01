"""Exact emitted helper and unchanged complete-byte copy oracle for the direct fixture."""
import os,re,shlex,shutil
import namespace
from pathlib import Path
from page_selected import need,elf,ENV,fact
from page_selected_register_time_build import recipe,expand
from persistent_dynamic import H
from persistent_active_domain import COPY_COUNTS,COPY_STDOUT
FIXTURE=Path(__file__).resolve().parents[2]/'tools/page-entry/selected/tests/persistent_fused_app'

DONOR=FIXTURE.parent/'persistent_direct_frontier_app'
from direct_frontier_loop_build import inspect_application

def compile_subject(builder,private,pin,binary,aliases,run,r):
    output=private/'application';output.mkdir()
    script=pin(FIXTURE/'build.sh');linker=pin(DONOR/'app.ld')
    rows=recipe(script,'"$cc"');need(len(rows)==2,'exact interpreter and freestanding application recipes')
    values={'$cc':builder.tools['cc'],'$source_dir':FIXTURE,'$donor_dir':DONOR,'$output':output}
    interp_unit=pin(DONOR/'fixture-interpreter.S')
    donor=pin(FIXTURE.parents[2]/'fixture-interpreter.S')
    need(interp_unit.read_bytes()==donor.read_bytes(),'complete original source-owned fixture interpreter')
    interp_argv=expand(rows[0],values)
    expected=[str(builder.tools['cc']),'-nostdlib','-shared','-Wl,-e,_start,-z,noexecstack,--build-id=none',
              str(interp_unit),'-o',str(output/'fixture-interpreter.so')]
    need(interp_argv==expected,'exact original tiny-interpreter compiler recipe')
    _,out,err=run('app-interpreter-headers',[builder.tools['cc'],'-nostdlib','-shared','-M','-MT','li2_interp',interp_unit],env=builder.environment)
    rules=out.decode().replace('\\\n',' ').splitlines()
    need(not err and len(rules)==1 and rules[0].startswith('li2_interp: '),'whole actual interpreter include rule')
    interp_headers={str(pin(n)):fact(pin(n))for n in shlex.split(rules[0].split(':',1)[1])}
    need(str(interp_unit)in interp_headers,'actual tiny-interpreter translation unit')
    _,out,err=run('app-interpreter-link',interp_argv,profile='release_build',env=builder.environment)
    need(out==err==b'','strict actual tiny-interpreter build')
    interpreter=pin(binary(interp_argv[-1]));data,head,segments=elf(interpreter)
    need(head[1:4]==(3,62,1)and all(p[2]+p[5]<=len(data)and p[5]<=p[6]and p[1]&3!=3
         for p in segments if p[0]==1)and not any(p[0]==3 for p in segments),
         'whole actual unchained ET_DYN interpreter without WX')
    info=namespace.parse(data)
    need(info==dict(elf_type=3,needed=[],soname=None,interpreter=None),
         'exact tiny interpreter has no external dynamic dependencies')
    _,out,err=run('app-interpreter-undefined',[builder.tools['nm'],'-u',interpreter],profile='inspect',env=builder.environment)
    need(out==err==b'','no unresolved actual tiny-interpreter imports')
    _,out,err=run('app-interpreter-symbols',[builder.tools['nm'],'-S','--defined-only',interpreter],profile='inspect',env=builder.environment)
    found=[line.split()for line in out.splitlines()if line.split()[-1:]==[b'_start']]
    need(not err and len(found)==1 and len(found[0])==4 and found[0][2]==b'T',
         'one exact source-owned interpreter entry symbol')
    start,size=int(found[0][0],16),int(found[0][1],16)
    owners=[p for p in segments if p[0]==1 and p[1]==5 and p[3]<=start<start+size<=p[3]+p[5]]
    expected_body=bytes.fromhex('0fa2488b0c24488d74cc1048ad4885c075f948ad4889c148ad4883f90974074885c975ee0f0bffe0')
    need(len(owners)==1 and size==len(expected_body)==40 and head[4]==start,
         'whole40-byte actual interpreter entry range')
    owner=owners[0];at=owner[2]+start-owner[3]
    need(data[at:at+size]==expected_body,'complete actual interpreter performs original auxv AT_ENTRY transfer')
    argv=expand(rows[1],values)
    units=[str(pin((FIXTURE if n in ('main.c','machine.S')else DONOR)/n))for n in ('main.c','pure.c','machine.S','entry.S')]
    need([x for x in argv if x.endswith(('.c','.S'))]==units and
         argv[-2:]==['-o',str(output/'persistent-fused-app')]and
         '-Wl,-T,'+str(linker)in argv and '-DLI2_FAST_EQUAL=1'in argv and
         '-DLI2_DIRECT_FRONTIER_INTERPRETER="'+str(interpreter)+'"'in argv and
         all(f in argv for f in ('-O2','-g','-Wall','-Wextra','-Werror','-mgeneral-regs-only',
             '-mcmodel=large','-fno-pie','-no-pie','-fno-builtin','-fno-strict-aliasing',
             '-fno-stack-protector','-fno-tree-vectorize','-nostdlib')),
         'exact whole freestanding application source and no-FP full-range recipe')
    state=r['application_build']=dict(status='failed',recipe=fact(script),argv=argv,
        interpreter=dict(path=str(interpreter),**fact(interpreter)),interpreter_source=fact(interp_unit),
        interpreter_headers=interp_headers,interpreter_argv=interp_argv,
        interpreter_entry=dict(address=start,bytes=size,sha256=H(expected_body)),
        linker=fact(linker),qualification_credit=False)
    flags=[x for x in argv[1:-2]if x not in units and not x.startswith('-Wl,')]
    _,out,err=run('app-headers',[builder.tools['cc'],*flags,'-M','-MT','li2_app',*units],env=builder.environment)
    rules=out.decode().replace('\\\n',' ').splitlines()
    need(not err and len(rules)==4 and all(x.startswith('li2_app: ')for x in rules),
         'one complete include rule for every actual freestanding translation unit')
    includes={}
    for rule in rules:
        for name in shlex.split(rule.split(':',1)[1]):
            path=Path(name).absolute();resolved=str(pin(path))
            need(str(path)not in aliases or aliases[str(path)]==resolved,'unchanged application header alias')
            aliases[str(path)]=resolved;includes[resolved]=fact(resolved)
    need(set(units)|{str(DONOR/'app.h')}<=set(includes),'all actual freestanding source/header inputs')
    state['headers']=includes
    _,out,err=run('app-link',argv,profile='release_build',env=builder.environment)
    need(out==err==b'','strict actual freestanding application build')
    image=binary(argv[-1]);info=namespace.parse(image.read_bytes())
    need(info==dict(elf_type=2,needed=[],soname=None,interpreter=interpreter),
         'actual application names only exact fresh source-owned interpreter and no dependencies')
    _,out,err=run('app-undefined',[builder.tools['nm'],'-u',image],profile='inspect',env=builder.environment)
    need(out==err==b'','no unresolved actual freestanding application imports')
    return inspect_application(builder,private,pin,binary,run,state,image,units)
