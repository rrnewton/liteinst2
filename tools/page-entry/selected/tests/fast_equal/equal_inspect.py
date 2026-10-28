"""File-only ELF/body checks for the actual scalar/word equality primitive."""
import hashlib,re,struct
from pathlib import Path

def need(x,m):
    if not x:raise ValueError(m)

def operands(text):
    result=[];start=0;depth=0
    for i,c in enumerate(text):
        depth+=(c=='(')-(c==')');need(depth>=0,'balanced addressing')
        if c==','and not depth:result.append(text[start:i]);start=i+1
    need(depth==0,'complete addressing');result.append(text[start:]);return result

def elf(path):
    data=Path(path).read_bytes();need(len(data)>=64,'complete ELF header')
    h=struct.unpack_from('<16sHHIQQQIHHHHHH',data)
    need(h[0][:7]==b'\x7fELF\x02\x01\x01' and h[2]==62 and h[1]in(1,2,3), 'actual x86-64 ELF')
    need(h[11]==64 and 0<h[12]<65536 and h[6]+64*h[12]<=len(data),'complete section table')
    sections=[struct.unpack_from('<IIQQQQIIQQ',data,h[6]+64*i)for i in range(h[12])]
    need(h[13]<len(sections),'section string table');s=sections[h[13]];names=data[s[4]:s[4]+s[5]]
    def cstr(raw,at):
        need(0<=at<len(raw)and b'\0'in raw[at:],'bounded ELF string');return raw[at:raw.index(0,at)].decode('ascii')
    section_names=[cstr(names,s[0])for s in sections];symbols=[]
    for index,s in enumerate(sections):
        if s[1]!=2:continue
        need(s[9]==24 and s[5]%24==0 and s[4]+s[5]<=len(data)and s[6]<len(sections),'complete symtab')
        strings=sections[s[6]];st=data[strings[4]:strings[4]+strings[5]]
        for at in range(s[4],s[4]+s[5],24):
            name,info,other,shndx,value,size=struct.unpack_from('<IBBHQQ',data,at)
            symbols.append(dict(table=index,index=(at-s[4])//24,name=cstr(st,name),info=info,other=other,section=shndx,value=value,bytes=size))
    need(symbols,'actual non-stripped symtab')
    return data,h,sections,section_names,symbols

def body(path,nm_text,disassembly,fast):
    data,h,sections,section_names,symbols=elf(path)
    need(type(fast)is bool,'explicit lane');functions={}
    for s in symbols:
        if s['info']&15==2 and (s['name']=='li2_equal_oracle'or re.fullmatch(r'equal(?:\.(?:isra|constprop|part)\.[0-9]+)?',s['name'])):
            name=s['name'];need(name not in functions and s['section']<len(sections)and 0<s['bytes']<=512,'unique bounded actual function')
            sec=sections[s['section']];offset=s['value']if h[1]==1 else s['value']-sec[3]
            need(sec[1]==1 and sec[2]&6==6 and not sec[2]&1 and 0<=offset and offset+s['bytes']<=sec[5], 'complete nonwritable text section')
            raw=data[sec[4]+offset:sec[4]+offset+s['bytes']];need(len(raw)==s['bytes'],'whole function bytes')
            matches=[x.split()for x in nm_text.decode().splitlines()if x.split()[-1:]==[name]]
            need(len(matches)==1 and len(matches[0])==4 and matches[0][2]in('t','T')and
                 int(matches[0][0],16)==s['value']and int(matches[0][1],16)==s['bytes'],'nm and ELF symbol agree')
            functions[name]=dict(**s,offset=offset,raw=raw,insns=[])
    need('li2_equal_oracle'in functions,'actual external wrapper')
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
                need(len(names)==1 and names[0]!='li2_equal_oracle','relocation names one actual local helper')
                relocations[name].append(dict(offset=offset-s['offset'],bytes=4,target=names[0],kind=kind,addend=addend))
    reached=set();pending=['li2_equal_oracle'];loads=[];edges=[];used_relocations=set()
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
            need(op in ('mov','movzbl','movzbq','cmp','cmpb','cmpq','test','testb','testq','add','sub','and','xor','lea','nop','nopl','nopw','xchg','sete','setne'),
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
            if op=='xchg':need(len(args)==2 and args[0]==args[1],'only actual register self-exchange padding')
            memory=[x for x in args if '('in x]
            if not memory or op=='lea':continue
            need(op in ('mov','movzbl','movzbq','cmp','cmpb','cmpq')and len(args)==2 and len(memory)==1 and
                 not re.search(r'%(?:rip|eip|rsp|rbp|fs|gs)',memory[0]),'only input-register addressing')
            if op.startswith('mov'):need(memory[0]==args[0],'load, never store')
            register=next(x for x in args if x not in memory);need(register.startswith('%'),'one memory read to/against register')
            if op in ('movzbl','movzbq','cmpb')or re.fullmatch(r'%(?:[abcd]l|[sd]il|r(?:[89]|1[0-5])b)',register):width=1
            else:need(re.fullmatch('%'+reg64,register)is not None,'exact eight-byte memory read');width=8
            loads.append(dict(function=name,offset=pc-s['value'],bytes=width))
    need(loads and any(x['bytes']==1 for x in loads)and (any(x['bytes']==8 for x in loads)==fast),'actual byte-only versus byte-and-word primitive')
    need(all((name,r['offset'])in used_relocations for name in reached for r in relocations[name]),'every body relocation belongs to an inspected direct helper tail')
    result={}
    for name in sorted(reached):
        s=functions[name];result[name]=dict(address=s['value'],bytes=s['bytes'],section=section_names[s['section']],
           code_hex=s['raw'].hex(),sha256=hashlib.sha256(s['raw']).hexdigest(),relocations=relocations[name],
           instructions=[dict(offset=pc-s['value'],bytes=b.hex(),text=a)for pc,b,a in s['insns']])
    return dict(fast=fast,elf_type=h[1],functions=result,loads=loads,edges=edges)

def linked(object_body,final_body):
    need(object_body['fast']==final_body['fast']and object_body['elf_type']==1 and final_body['elf_type']in(2,3),'actual object/final pairing')
    need(set(object_body['functions'])==set(final_body['functions']),'same complete reachable helper graph')
    for name,before in object_body['functions'].items():
        after=final_body['functions'][name];a=bytearray.fromhex(before['code_hex']);b=bytearray.fromhex(after['code_hex'])
        need(len(a)==len(b)and not after['relocations'],'same final function extent, no dynamic helper relocation')
        for rel in before['relocations']:
            at=rel['offset'];target=after['address']+at+4+struct.unpack_from('<i',b,at)[0]
            need(target==final_body['functions'][rel['target']]['address'],'link relocation reaches exact owned helper')
            a[at:at+4]=b[at:at+4]=b'\0'*4
        need(a==b,'every nonrelocation emitted helper byte identical')
    return True

def layout(path,nm_text):
    data,h,sections,names,symbols=elf(path);need(h[1]in(2,3)and h[9]==56 and 0<h[10]<=32,'actual hosted executable')
    ph=[struct.unpack_from('<IIQQQQQQ',data,h[5]+56*i)for i in range(h[10])]
    need(h[5]+56*h[10]<=len(data)and any(p[0]==1 and p[1]&1 and p[3]<=h[4]<p[3]+p[6]for p in ph),'actual entry')
    need(all(p[0]!=1 or p[1]&3!=3 for p in ph)and any(p[0]==0x6474e551 and not p[1]&1 for p in ph),'no WX/execstack')
    found=[s for s in symbols if s['name']=='record'];need(len(found)==1,'one actual record')
    s=found[0];need(s['info']&15==1 and s['bytes']==4800 and sum(p[0]==1 and p[1]==6 and p[3]<=s['value']<s['value']+4800<=p[3]+p[6]for p in ph)==1,'whole actual4800B writable NX record')
    matches=[x.split()for x in nm_text.decode().splitlines()if x.split()[-1:]==['record']]
    need(len(matches)==1 and len(matches[0])==4 and int(matches[0][0],16)==s['value']and int(matches[0][1],16)==4800 and matches[0][2]in('b','B'),'nm record binding')
    interp=[p for p in ph if p[0]==3];need(len(interp)==1,'actual interpreter');p=interp[0];raw=data[p[2]:p[2]+p[5]]
    need(raw.startswith(b'/')and raw.endswith(b'\0')and b'\0'not in raw[:-1],'actual interpreter path')
    return dict(record_bytes=4800,record_address=s['value'],elf_type=h[1],interpreter=raw[:-1].decode())
