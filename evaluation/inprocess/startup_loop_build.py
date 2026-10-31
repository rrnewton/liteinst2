"""Exact emitted helper and unchanged complete-byte copy oracle for the startup fixture."""
import os,re,shlex,shutil
from pathlib import Path
from page_selected import need,elf,ENV,fact
from page_selected_register_time_build import recipe,expand
from persistent_dynamic import H
from persistent_active_domain import COPY_COUNTS,COPY_STDOUT
FIXTURE=Path(__file__).resolve().parents[2]/'tools/page-entry/selected/tests/persistent_interpreter_loop_app'

def inspect_application(builder,private,pin,binary,run,state,original,app_units):
    _,head,segments=elf(original)
    need(head[1:4]==(2,62,1)and not any(s[0]==1 and s[1]&3==3 for s in segments),'actual non-PIE x86-64 app without WX')
    _,_,err=run('app-elf',[builder.tools['readelf'],'-h','-l','-d','-r','-W',original],profile='inspect',env=builder.environment)
    need(not err,'actual complete app ELF inspection')
    objdump=pin(shutil.which('objdump',path=ENV['PATH']))
    _,out,err=run('app-objdump-version',[objdump,'--version'],env=builder.environment);need(out and not err,'actual app disassembler identity')
    _,out,err=run('app-symbols',[builder.tools['nm'],'-S','--defined-only',original],profile='inspect',env=builder.environment)
    need(not err,'actual emitted helper symbols');symbols={};bodies={}
    for name in ('main','collect','copy','same','ua_data_pattern','ua_stack_pattern'):
        found=[line.split()for line in out.decode().splitlines()if line.split()[-1:]==[name]]
        need(len(found)==1 and len(found[0])==4 and found[0][2]==('t'if name=='collect'else'T'),'one complete actual app text symbol')
        address,size=int(found[0][0],16),int(found[0][1],16)
        need(size>0 and sum(p[0]==1 and p[1]==5 and p[3]<=address<address+size<=p[3]+p[5]for p in segments)==1,'whole symbol in exact actual RX segment')
        if name not in ('main','collect'):need(0x200001000<=address<address+size<=0x200002000,'actual high full-range helper body')
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
        bodies[name]=assembly.decode()
    # This fixture keeps collect out of line. Bind its complete body and the
    # main-to-collect edge as well as every helper's actual full-width caller.
    callers={'copy':'main','same':'collect','ua_data_pattern':'main','ua_stack_pattern':'main','collect':'main'}
    for name,caller in callers.items():
        need(re.search(r'\bmovabsq?\s+\$0x'+format(symbols[name]['address'],'x')+r',',bodies[caller])is not None,
             'actual '+caller+' materializes full-width '+name+' address without truncated relocation')
    state['helper_callers']=callers
    copy_oracle(builder,private,pin,binary,run,state,original,symbols['copy'],app_units)
    state.update(status='passed',artifact=fact(original),symbols=symbols);return original



def copy_oracle(builder,private,pin,binary,run,state,original,app_symbol,app_units):
    """Bound the actual fixture helper to an independent complete-byte oracle."""
    script=pin(FIXTURE/'build-copy-oracle.sh');output=private/'active-app-copy-oracle'
    rows=recipe(script,'"$cc"');need(len(rows)==1,'one actual two-TU copy oracle recipe')
    argv=expand(rows[0],{'$cc':builder.tools['cc'],'$source_dir':FIXTURE,'$output':output})
    units=[str(pin(FIXTURE/n))for n in('copy_oracle.c','pure.c')]
    flags=lambda args,inputs:[x for x in args[1:-2]if x not in inputs and not x.startswith('-Wl,')]
    need(argv[-2:]==['-o',str(output)]and[x for x in argv if x.endswith('.c')]==units and
         flags(argv,units)==flags(state['argv'],app_units)and '-DNDEBUG'not in argv and
         '-Wl,-z,relro,-z,now,-z,noexecstack'in argv,
         'copy oracle uses exact actual application helper-affecting compiler flags')
    observed=state['copy_oracle']=dict(status='failed',recipe=fact(script),argv=argv,
        expected_counts=COPY_COUNTS,qualification_credit=False,performance_credit=False)
    _,out,err=run('app-copy-headers',[builder.tools['cc'],*flags(argv,units),'-M','-MT','li2_copy',*units],
        profile='finite',env=builder.environment)
    lines=out.decode().replace('\\\n',' ').splitlines()
    need(not err and len(lines)==2 and all(x.startswith('li2_copy: ')for x in lines),
         'whole actual two-TU copy oracle header closure')
    includes={str(pin(n)):fact(pin(n))for line in lines for n in shlex.split(line.split(':',1)[1])}
    need(set(units)|{str(FIXTURE/'app.h')}<=set(includes)and
         includes[str(FIXTURE/'pure.c')]==state['headers'][str(FIXTURE/'pure.c')],
         'oracle and application use the same complete actual helper source')
    observed['headers']=includes
    run('app-copy-link',argv,profile='finite',env=builder.environment)
    executable=binary(output);data,head,segments=elf(executable)
    need(head[1:4]==(2,62,1)and all(s[2]+s[5]<=len(data)and s[5]<=s[6]and s[1]&3!=3
         for s in segments if s[0]==1),'complete actual non-PIE copy oracle without WX')
    _,symbols,err=run('app-copy-symbols',[builder.tools['nm'],'-S','--defined-only',executable],
        profile='finite',env=builder.environment)
    found=[line.split()for line in symbols.splitlines()if line.split()[-1:]==[b'copy']]
    need(not err and len(found)==1 and len(found[0])==4 and found[0][2]==b'T'and int(found[0][1],16)>0,
         'one complete nonempty actual copy oracle text symbol')
    address,size=int(found[0][0],16),int(found[0][1],16)
    def body(image,at,n):
        raw,_,loads=elf(image)
        owners=[s for s in loads if s[0]==1 and s[1]==5 and s[3]<=at<at+n<=s[3]+s[5]]
        need(len(owners)==1 and n>0,'whole copy body lies in one actual RX load')
        item=owners[0];offset=item[2]+at-item[3];return raw[offset:offset+n]
    actual=body(executable,address,size);expected=body(original,app_symbol['address'],app_symbol['bytes'])
    need(actual==expected,'oracle executes the exact whole emitted application copy body')
    objdump=pin(shutil.which('objdump',path=ENV['PATH']))
    _,assembly,err=run('app-copy-body',[objdump,'-d','-w','-M','att',
        '--start-address='+hex(address),'--stop-address='+hex(address+size),executable],
        profile='finite',env=builder.environment)
    need(not err and b'<copy>:'in assembly,'actual complete copy disassembly')
    emitted=[];cursor=address;instructions=[]
    for line in assembly.decode().splitlines():
        match=re.fullmatch(r'\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s+)+)(.*)',line)
        if match:
            chunk=bytes.fromhex(match[2]);need(int(match[1],16)==cursor and chunk and cursor+len(chunk)<=address+size,
                'complete contiguous actual copy instruction bytes')
            emitted.append(chunk);instructions.append(match[3]);cursor+=len(chunk)
    need(cursor==address+size and b''.join(emitted)==actual,'whole copy disassembly equals both actual ELFs')
    forbidden=r'\b(?:l?callq?|rep(?:e|ne|z|nz)?|(?:movs|stos|lods|scas|cmps|ins|outs)[bwlq]?)\b|%[xyz]?mm[0-9]+\b'
    need(all(re.search(forbidden,x)is None for x in instructions),
         'actual copy has no call, string, REP or vector instruction')
    observed['body']=dict(bytes=len(actual),sha256=H(actual))
    observed['app_symbol']=app_symbol;observed['oracle_symbol']=dict(address=address,bytes=size)
    interps=[s for s in segments if s[0]==3];need(len(interps)==1,'one actual copy oracle interpreter')
    item=interps[0];literal=data[item[2]:item[2]+item[5]]
    need(literal.startswith(b'/')and literal.endswith(b'\0')and b'\0'not in literal[:-1],
         'complete literal copy oracle interpreter')
    loader=pin(os.fsdecode(literal[:-1]));observed['runtime_libraries']={}
    _,out,err=run('app-copy-libraries',[loader,'--list',executable],profile='finite',env=builder.environment)
    need(not err,'actual complete copy oracle runtime library listing')
    for line in out.decode().splitlines():
        if re.fullmatch(r'\s*linux-vdso.so.1 \(0x[0-9a-f]+\)',line):continue
        match=re.fullmatch(r'\s*(?:\S+ => )?(/\S+) \(0x[0-9a-f]+\)',line)
        need(match is not None,'one resolved actual copy oracle library')
        path=pin(match[1]);need(path.name not in observed['runtime_libraries'],'unique copy oracle library name')
        observed['runtime_libraries'][path.name]=dict(path=str(path),**fact(path))
    need(any(v['path']==str(loader)for v in observed['runtime_libraries'].values()),
         'actual interpreter belongs to complete copy oracle runtime closure')
    observed['artifact']=fact(executable)
    label='app-copy-run'
    row,out,err=run(label,[executable],profile='finite',env=builder.environment)
    need(out==COPY_STDOUT and err==b''and row['exit']==0,'every exact copy oracle case completes')
    need(all(fact(path)==value for path,value in includes.items()),'copy oracle whole source closure unchanged')
    observed.update(status='passed',counts=COPY_COUNTS,exit=row['exit'],duration_ns=row['duration_ns'],
        bounds=row['bounds'],captures={k:{j:v[j]for j in('bytes','sha256')}for k,v in row['captures'].items()})
