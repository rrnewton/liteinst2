#!/usr/bin/env python3
"""Two cold CALL cases, each native and two fully built protected-owner lanes."""
import argparse
import ast
import copy
import ctypes
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import stat
import struct
import sys
from types import SimpleNamespace

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BOUNDS = {'release_build':[30,512<<20,16<<20,60],
          'metadata':[30,512<<20,64<<20,60], 'inspect':[10,256<<20,4<<20,20],
          'native':[5,512<<20,16<<20,15], 'program':[30,512<<20,16<<20,60],
          'seed':[5,512<<20,16<<20,15], 'finite':[5,512<<20,16<<20,15]}


def need(ok, message):
    if not ok:
        raise ValueError(message)


def fact(path):
    path = Path(path)
    need(path.is_file() and not path.is_symlink(), 'regular whole input: '+str(path))
    data = path.read_bytes()
    return dict(bytes=len(data),sha256=hashlib.sha256(data).hexdigest(),
                mode=format(stat.S_IMODE(path.stat().st_mode),'04o'))


def unique(pairs):
    result = dict(pairs)
    need(len(result) == len(pairs), 'duplicate JSON field')
    return result


def load(path):
    return json.loads(Path(path).read_bytes(),object_pairs_hook=unique)


def digest(value):
    return {k:value[k] for k in ('bytes','sha256')}


def schema_check(layout, wire):
    """Compare actual DWARF against the independent source declarations only."""
    need(set(layout) == {'record','types','edges','member_witnesses','symbols','registrations',
                        'retained_storage','uc_bytes','uc','si'} and layout['record'] == 'pclo_wire',
         'whole distinct actual history layout result')
    need(set(layout['types']) == set(layout['edges']) == set(wire.GROUPS) and len(wire.GROUPS) == 116,
         'all and only 116 independently declared reachable types')
    modeled = {}; active = set()
    def shape(name):
        if name in modeled:return modeled[name]
        need(name not in active,'acyclic embedded type graph');active.add(name)
        rows,alignment = wire.GROUPS[name];fields = {};edges = {};end = 0
        for keys,size,align in rows:
            child = size if type(size) is str else size[0] if type(size) is tuple else None
            width = shape(child)['bytes']*(size[1] if type(size) is tuple else 1) if child else size
            need(type(width) is int and width > 0 and align > 0 and not align&(align-1),
                 'positive whole member size and alignment')
            for key in keys.split():
                need(key not in fields,'unique independently declared member')
                offset = 0 if name in wire.UNIONS else (end+align-1)&-align
                fields[key] = dict(offset=offset,bytes=width,alignment=align)
                end = max(end,width) if name in wire.UNIONS else offset+width
                if child:edges[key] = child
        value = dict(bytes=(end+alignment-1)&-alignment,alignment=alignment,fields=fields)
        actual = layout['types'][name]
        need(set(actual) == set(value) and actual['bytes'] == value['bytes'] and
             actual['alignment'] == alignment and set(actual['fields']) == set(fields),
             'complete exact type extent/alignment/field inventory: '+name)
        for key,expected in fields.items():
            observed = actual['fields'][key]
            need(set(observed) == {'offset','bytes','alignment','type'} and
                 {k:observed[k] for k in expected} == expected and
                 type(observed['type']) is str and bool(observed['type']),
                 'whole actual field offset/width/alignment: '+name+'.'+key)
        need(layout['edges'][name] == edges,'exact embedded type/array edges: '+name)
        modeled[name] = value;active.remove(name);return value
    for name in wire.GROUPS:shape(name)
    count = sum(len(x['fields']) for x in modeled.values())
    need(count == 1249 and modeled['pclo_wire']['bytes'] == wire.RAW_BYTES == 990144,
         'all1249 fields and whole raw extent, without any invented record')
    need(layout['member_witnesses'] == {'li2_step_frame.fp':dict(
         symbol='pclo_step_frame_fp_alignment',bytes=8,alignment=64)},'actual aligned FP member witness')
    need(layout['uc_bytes'] == 968 and layout['uc'] == dict(
        offsets=dict(flags=0,link=8,greg=40,fp_pointer=224,mask=296,stack_sp=16,stack_flags=24,stack_size=32),
        widths=dict(flags=8,link=8,greg=184,fp_pointer=8,mask=128,stack_sp=8,stack_flags=4,stack_size=8)),
        'whole actual Linux UC ABI')
    need(layout['si'] == dict(bytes=128,offsets=dict(signo=0,errno=4,code=8,addr=16,pid=16,uid=20),
        widths=dict(signo=4,errno=4,code=4,addr=8,pid=4,uid=4)),'whole actual SI ABI')
    need(set(layout['registrations']) == set(wire.REGISTERED),'exact registration symbol set')
    for name,(source,tag) in wire.REGISTERED.items():
        row = layout['registrations'][name]
        need(row['address'] == layout['symbols'][name] > 0 and row['bytes'] > 0 and
             Path(row['source']).name == source and row['tag'] == tag,
             'actual complete registration symbol/source/type: '+name)
    return dict(types=116,fields=1249,raw_bytes=990144,record_bytes_observed=0,
                schema_only=True,owner_credit=0)


def byte_fact(data):
    return dict(bytes=len(data),sha256=hashlib.sha256(data).hexdigest())


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
    return dict(image=byte_fact(data), elf_type=h[1], entry=h[4], load_count=len(loads),
                program_headers=byte_fact(program))


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
    need(len(expected) == 60 and len(set(expected)) == 59 and set(symbols) == set(expected),
         'all60 unchanged recipe entries including one original duplicate, all59 unique functions')
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



def preparation(case,row,directory,original,roots,objects,description,carrier,private,binary,r):
    lane,mode,control=case['lane'],case['mode'],case['control'];role='native'if lane=='native'else'gated';prep=json.loads(binary(directory/'preparation.json').read_bytes())
    need(not any(k in prep for k in('current_custody','current_control','physical_fallback')),'no unrelated launch profile')
    need(prep['schema_version']==1 and prep['status']=='prepared_not_executed'and prep['role']==role and
        prep['pid']==row['pid']and prep['cpu']==[r['cpu']]and prep['reset_mask']==0 and prep['launch_mask']==(MASK if lane=='native'else 0)and
        prep['argv']==[str(original),str(mode),role]and prep['default_rseq']is False and prep['mode']==mode and prep['control']==control and
        [x['signal']for x in prep['dispositions']]==[n for n in range(1,65)if n not in(9,19)]and all(x['after']==0 for x in prep['dispositions']),
        'actual exact launch signal/mode/environment preparation')
    if lane=='native':
        need(prep['observer']is None and prep['environment']==dict(PATH='/usr/bin:/bin',LANG='C',LC_ALL='C',TZ='UTC',LD_BIND_NOW='1',GLIBC_TUNABLES='glibc.pthread.rseq=0',LD_LIBRARY_PATH=':'.join(map(str,roots))),'actual closed native exec environment')
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
        LD_BIND_NOW='1',LD_LIBRARY_PATH=str(ns),LI2_DEPENDENCY_FDS=','.join(map(str,fds)),GLIBC_TUNABLES='glibc.pthread.rseq=0',
        LI2_PERSISTENT_CALL_OWNER_APP_MODE=str(mode)))and
        prep['late_sonames']==[]and prep['environment_source']==str(ns/'launch.json'),'actual exact gated capture-control exec environment')
    record=private/row['captures']['record']['file'];st=record.stat()
    need(prep['observer']==dict(fd=3,device=st.st_dev,inode=st.st_ino)and st.st_nlink==1 and st.st_mode&0o7777==0o600,'same exclusive owner record descriptor')
    return manifest



def build_bridge(builder,private,pin,binary,aliases,run,record,image,app,selected,manifest,differential,fast_bytes,maps_view):
    """Build the actual capture bridge and finish its mandatory byte oracle."""
    from linked_epoch_build import FIXED_DOMAIN, fixed_domain_source
    from persistent_epoch_build import FEATURES
    mode='differential' if differential else 'capture'
    need(type(differential) is bool and builder.mov_guard is True and builder.linked_epoch is True and
         builder.scalar_span is True and builder.extra_decoder_sources==('region.rs','mov_guard.rs') and
         builder.decoder_features==FEATURES and builder.record['decoder_features']==list(FEATURES) and
         builder.environment['LI2_DECODER_FEATURES']=='linked-epoch,mov-guard',
         'one explicit complete persistent decoder feature/source closure')
    archive=pin(builder.paths['archive']);retained=builder.record['artifacts']['decoder.a']
    need(builder.record['status']=='passed' and builder.record['command_completed'] is True and
         archive==builder.retained/'decoder.a' and str(archive)==retained['path'] and
         digest(fact(archive))==digest(retained),'actual retained successful archive in place')
    need(all(type(builder.record['archive_text_exports'].get(n)) is int and
         builder.record['archive_text_exports'][n]==1 for n in ('li2_decoder_region_describe',
         'li2_decoder_span_describe','li2_decoder_link_none','li2_decoder_mov_store',
         'li2_decoder_tf_classify','li2_decoder_write_footprint')),'every descriptor provider exactly once')
    output=private/('persistent-call-owner-'+mode);output.mkdir()
    recipe=pin(selected/('build-persistent-call-owner'+('-differential' if differential else '')+'.sh'))
    text=recipe.read_text().replace('\\\n',' ')
    lines=[line.strip() for line in text.splitlines() if line.strip().startswith('"$cc_bin" ')]
    binders=[line.strip() for line in text.splitlines() if line.strip().startswith('"${LI2_PYTHON:-python3}" ')]
    need(len(lines)==len(binders)==1 and binders[0]==
         '"${LI2_PYTHON:-python3}" "$selected_dir/persistent_call_owner_binding.py" "$selected_dir" "$archive" "$image" "$output" '+mode,
         'one exact source-owned compiler and binding invocation')
    sources=[]
    for name in manifest['policy'][mode]:
        path=pin(selected/name);item=digest(fact(path))
        if name in FIXED_DOMAIN:
            size,sha=fixed_domain_source(name,path)
            need(item==dict(bytes=size,sha256=sha),'unchanged reviewed scalar/NONE decoder domain')
        if name.endswith('.rs'):
            need(builder.record['dep_info'].get('tools/page-entry/selected/'+name)==item,
                 'actual archive compiled every bound decoder source')
        sources.append(dict(path=name,**item))
    need(len(sources)==(82 if differential else 81) and len({x['path'] for x in sources})==len(sources),
         'exact complete ordered capture policy population')
    original=image_identity(image.read_bytes())
    policy=hashlib.sha256(json.dumps(dict(sources=sources,original=original,mode=mode),sort_keys=True,separators=(',',':')).encode()).hexdigest()
    expected=dict(version=1,profile='persistent-call-owner-'+mode+'-v1',mode=mode,native_probe=True,
        parse_memo=True,unregistered=True,subentry=True,cross_pair=True,direct_frontier=True,call_dispatch=True,
        maps_differential=differential,typed_capture=True,call_owner_capture=True,capture_schema=1,
        archive=digest(fact(archive)),policy_sha256=policy,original=original,sources=sources)
    literal=lambda s:'{'+','.join('0x'+s[i:i+2] for i in range(0,64,2))+'}'
    config={
        'linked_epoch_config.h':'#ifndef LI2_LINKED_EPOCH_CONFIG_H\n#define LI2_LINKED_EPOCH_CONFIG_H\n#define LI2_LINK_BINDING_VERSION 1\n#define LI2_LINK_ARCHIVE_SHA256 '+literal(expected['archive']['sha256'])+'\n#define LI2_LINK_POLICY_SHA256 '+literal(policy)+'\n#endif\n',
        'persistent_group_config.h':'#ifndef LI2_PERSISTENT_GROUP_CONFIG_H\n#define LI2_PERSISTENT_GROUP_CONFIG_H\n#define LI2_PG_BINDING_VERSION 1\n#define LI2_PG_GROUP_BINDING_VERSION 4\n#define LI2_PG_ARCHIVE_SHA256 '+literal(expected['archive']['sha256'])+'\n#define LI2_PG_POLICY_SHA256 '+literal(policy)+'\n#endif\n',
        'persistent_call_owner_config.h':'#ifndef LI2_PERSISTENT_CALL_OWNER_CONFIG_H\n#define LI2_PERSISTENT_CALL_OWNER_CONFIG_H\n#define LI2_PCLO_VERSION 1\n'+''.join(
            '#define LI2_PCLO_'+name+'_RVA 0x'+format(value,'x')+'ULL\n' for name,value in (
                ('PAGE',app['page']),('U_PAGE',app['page']+8192),('A',app['head']),
                ('CALL',app['page']+0x20a),('RETURN',app['page']+0x20d),('B',app['page']+0x300),
                ('B_EXIT',app['page']+0x304),('U',app['page']+0x2100),
                ('CAPTURE',app['symbols']['region_app_capture_high'])))+'#endif\n'}
    expected['headers']={name:byte_fact(data.encode()) for name,data in config.items()}
    _,out,err=run('binding',[builder.tools['python'],'-B',selected/'persistent_call_owner_binding.py',
                           selected,archive,image,output,mode],env=builder.environment)
    need(not out and not err,'silent actual source-owned binder')
    binding_path=binary(output/'persistent_call_owner_binding.json');binding=load(binding_path)
    need(binding==expected and binding_path.read_bytes()==(json.dumps(expected,sort_keys=True)+'\n').encode(),
         'whole independently reconstructed typed CALL capture binding')
    header_paths={}
    for name,data in config.items():
        path=binary(output/name);need(path.read_bytes()==data.encode(),'whole independent generated header')
        header_paths[name]=dict(path=str(path),**digest(fact(path)))
    replacements={'$cc_bin':builder.tools['cc'],'$selected_dir':selected,'$parent_dir':selected.parent,
                  '$archive':archive,'$output':output}
    argv=[]
    for word in shlex.split(lines[0]):
        for key,value in replacements.items():word=word.replace(key,str(value))
        need('$' not in word and '`' not in word,'closed literal compiler argv');argv.append(word)
    tus=[str(selected.parent/name) for name in manifest['translation_units']]
    bridge=output/'bridge-persistent-call-owner.so'
    macros=manifest['macros'][mode]
    need([x for x in argv if x.endswith(('.c','.S'))]==tus and len(tus)==27 and
         [x for x in argv if x.endswith('.a')]==[str(archive)] and argv[-2:]==['-o',str(bridge)] and
         [x for x in argv if x.startswith('-DLI2_')]==macros and
         all(x in argv for x in ('-O2','-g','-nostdlib','-shared','-fPIC','-fvisibility=hidden',
         '-mgeneral-regs-only','-fno-builtin','-fno-tree-loop-distribute-patterns','-fno-tree-vectorize',
         '-Wall','-Wextra','-Werror')),'exact27-TU no-FP typed capture recipe and original compiler policy')
    state=record['release_build']=dict(status='failed',profile=expected['profile'],recipe=fact(recipe),
        archive=digest(fact(archive)),argv=argv,persistent_binding=binding,capture=True,
        call_owner_capture=True,qualification_credit=False)
    flags=[x for x in argv[1:-2] if x not in tus and x!=str(archive) and not x.startswith(('-Wl,','-l'))]
    _,out,err=run('headers',[builder.tools['cc'],*flags,'-M','-MT','call_owner',*tus],env=builder.environment)
    rules=out.decode().replace('\\\n',' ').splitlines()
    need(not err and len(rules)==27 and all(x.startswith('call_owner: ') for x in rules),
         'one complete actual compiler-M rule per translation unit')
    observed={str(pin(x)):digest(fact(pin(x))) for rule in rules for x in shlex.split(rule.split(':',1)[1])}
    required={str(Path(x).resolve()) for x in tus}|{str((selected/x).resolve()) for x in manifest['required_headers']}|{str(output/x) for x in config}
    need(required<=set(observed),'complete inherited map/custody/CALL/owner/config dependency closure')
    for item in sources:
        if item['path'].endswith(('.c','.h','.inc')):
            need(observed.get(str((selected/item['path']).resolve()))==digest(item),
                 'every whole bound C policy source is an actual compiler input')
    names={Path(x).name for x in observed}
    need(not names.intersection(manifest['forbidden_headers']) and
         not any(('observe' in n and n not in {'persistent_call_owner_observe.h','persistent_call_owner_observe.inc'})
                 or n.startswith(('linked_preedge_','linked_native_hint')) for n in names),
         'no old owner/capture/counter/census/header aliases')
    for item in header_paths.values():need(observed.get(item['path'])==digest(item),'all generated headers actually compiled')
    state['headers']=observed;state['header_paths']=header_paths
    _,out,err=run('link',argv,profile='release_build',env=builder.environment)
    need(not out and not err,'strict actual compiler/linker completion')
    state['bridge']=digest(fact(binary(bridge)));state['elf']=maps_view.bridge_check(bridge)
    _,out,err=run('undefined',[builder.tools['nm'],'-u',bridge],env=builder.environment)
    need(not out and not err,'no unresolved actual bridge imports')
    _,out,err=run('providers',[builder.tools['nm'],'--defined-only',bridge],env=builder.environment)
    need(not err,'complete actual provider census')
    providers=re.findall(r'--undefined=([^,\\\s]+)',lines[0])
    need(providers==manifest['providers'],'exact complete source-owned provider order')
    state['provider_functions']=provider_functions(bridge.read_bytes(),out,providers)
    _,symbols,err=run('symbols',[builder.tools['nm'],'-S','--defined-only',bridge],env=builder.environment)
    need(not err,'complete actual sized symbol census')
    state['symbols_capture']=byte_fact(symbols)
    for name,size in (('maps_parse_memo',376856),('pclo_wire',990144),('pe',3988544),('pcw',3112)):
        rows=[line.split() for line in symbols.splitlines() if line.split()[-1:]==[name.encode()]]
        need(len(rows)==1 and len(rows[0])==4 and rows[0][2] in (b'b',b'B') and
             int(rows[0][0],16)>0 and int(rows[0][1],16)==size,'complete actual protected BSS '+name)
        if name=='pclo_wire':state['capture_symbol']=dict(address=int(rows[0][0],16),bytes=size)
    _,out,err=run('elf',[builder.tools['readelf'],'-W','-h','-l','-d',bridge],env=builder.environment)
    need(out and not err and '(NEEDED)' not in out.decode(),'whole bridge ELF and no dynamic dependency')
    objdump=pin(shutil.which('objdump',path=maps_view.ENV['PATH']))
    _,out,err=run('objdump-version',[objdump,'--version'],env=builder.environment)
    need(out and not err,'actual reset disassembler identity')
    _,assembly,err=run('reset',[objdump,'-d','-w','-M','att','--disassemble=memset',bridge],env=builder.environment)
    need(not err,'whole actual reset disassembly')
    state['reset']=maps_view.hidden_memset(bridge,maps_view.body_check(bridge,symbols,assembly,'fast',symbol_name='memset'))
    fast_bytes(builder,output,pin,binary,aliases,run,state)
    need(digest(fact(archive))==binding['archive'] and digest(fact(image))==original['image'] and
         all(digest(fact(selected/x['path']))==digest(x) for x in sources) and
         all(digest(fact(x))==value for x,value in observed.items()) and
         binding_path.read_bytes()==(json.dumps(expected,sort_keys=True)+'\n').encode() and
         all((output/name).read_bytes()==data.encode() for name,data in config.items()) and
         fact(recipe)==state['recipe'],'all archive/image/policy/header/recipe bytes unchanged through mandatory byte oracle')
    state['status']='passed'
    return bridge


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--expect-revision',required=True)
    ap.add_argument('--output',type=Path,required=True)
    ap.add_argument('--cpu',type=int,required=True)
    for name in ('archive','components','native136'):
        ap.add_argument('--'+name+'-receipt',type=Path,required=True)
        ap.add_argument('--'+name+'-receipt-sha256',required=True)
    args = ap.parse_args(); manifest = load(HERE/'SOURCE.json')
    need(not sys.flags.optimize and sys.version_info >= (3,11) and
         sorted(os.sched_getaffinity(0)) == [args.cpu],
         'assertions, Python3.11+ and original archive CPU independently reserved')
    need(re.fullmatch('[0-9a-f]{40}',args.expect_revision) is not None, 'explicit full installed revision')
    for name,value in manifest['artifacts'].items():
        need(fact(HERE/name) == value,'frozen collector artifact: '+name)
    for name,value in manifest['inputs'].items():
        need(fact((ROOT/name).resolve(strict=True)) == value,'frozen source input: '+name)
    private = args.output.resolve(); cpu = args.cpu
    need(private.is_relative_to((ROOT/'target/evaluation/inprocess').resolve(strict=True)) and
         not private.exists(),'fresh contained private result')
    private.mkdir(); facade = ROOT
    context = {}; context_links = {}
    for directory,names in manifest['source_roster'].items():
        for name in names:
            relative=str(Path(directory)/name);path=ROOT/relative
            need(not Path(relative).is_absolute() and '..' not in Path(relative).parts and
                 relative not in context,'unique contained installed source roster')
            context[relative]=dict(origin=relative,copy=False,**fact(path))
    # Installed source modules retain their original natural ROOT/SELECTED.
    # Every original context member is pinned in place; no facade copies or
    # module-global substitution creates another source view.
    sys.path[:0] = [str(ROOT/'evaluation/inprocess'),str(HERE),str(ROOT/'tools/page-entry')]
    import custody
    from checks import source, admission
    from run import hardware
    global MASK, H, namespace
    import namespace
    from page_selected import ENV, save, interpreter
    from page_selected_process import invoke
    from page_selected_generic_build import package_check
    os.chdir(ROOT); receipt = private/'receipt.json'
    pins,aliases,artifacts,presence = {},{},{},{}
    prerequisite_files,prerequisite_aliases = {},{}
    r = dict(schema=1,profile='public-call-owner-gated-v1',status='failed',
        revision=args.expect_revision,source=None,source_unchanged=False,inputs_unchanged=False,
        cleanup_complete=False,cpu=cpu,hardware=hardware(cpu),bounds=BOUNDS,commands=[],result=None,
        context=context,context_links=context_links,lanes={},error=None,final_errors=[],
        archive_builds=0,qualification_credit=False,performance_credit=False,
        namespace_aliases={},terminal_reports={},pending=['original392','original522','ten_run_DR'],
        seed_prerequisite=dict(planned=1,status='unexecuted',launched=False,expected_exit=0,
            bounds=BOUNDS['seed'],owner_subjects=0,completed_applications=0,performance_credit=False),
        cases=[dict(label='subject-'+lane+'-'+str(mode)+'-0',lane='native' if lane=='native' else 'gated',
                    mapping_lane=lane,mode=mode,control=0,status='unexecuted',launched=False,expected_exit=0,
                    bounds=BOUNDS['native' if lane=='native' else 'program'])
               for mode in (0,1) for lane in ('native','maintained','differential')])

    def pin(path):
        need(path is not None,'required source/tool path')
        alias = Path(path).absolute(); resolved = alias.resolve(strict=True); value = fact(resolved)
        need(str(alias) not in aliases or aliases[str(alias)] == str(resolved),'stable input alias')
        need(str(resolved) not in pins or pins[str(resolved)] == value,'stable whole input')
        aliases[str(alias)] = str(resolved); pins[str(resolved)] = value
        return resolved

    def binary(path):
        path = Path(path).absolute(); resolved = path.resolve(strict=True)
        need(resolved.is_relative_to(private) and not path.is_symlink(),'private regular produced artifact')
        value = fact(resolved)
        need(str(resolved) not in artifacts or artifacts[str(resolved)] == value,'stable complete artifact')
        artifacts[str(resolved)] = value
        return resolved

    def imports():
        for module in tuple(sys.modules.values()):
            name = getattr(module,'__file__',None)
            if name and Path(name).is_file():pin(name)

    def closure():
        need(all(fact(p) == value for p,value in pins.items()),'all source/tool/library inputs unchanged')
        need(all(str(Path(p).resolve(strict=True)) == value for p,value in aliases.items()),'all aliases unchanged')
        need(all(fact(p) == value for p,value in artifacts.items()),'all full artifacts/captures unchanged')
        need(all(Path(p).is_symlink() and os.readlink(p) == value for p,value in context_links.items()),
             'all exact read-only context aliases unchanged')
        need(all(Path(p).exists() == value for p,value in presence.items()),'loader configuration presence')
        need(all(Path(p).is_symlink() and os.readlink(p)==value for p,value in r['namespace_aliases'].items()),
             'all actual sealed dependency aliases unchanged')
        need(sorted(os.sched_getaffinity(0)) == [cpu],'reserved CPU unchanged')

    def run(name, argv, profile='inspect', env=None, expected=0, record=False):
        closure();argv=list(map(str,argv));pin(argv[0])
        need(profile in BOUNDS and type(record) is bool and expected == 0 and
             not any(x['name']==name for x in r['commands']), 'fixed bounded commands, no retries')
        subjects={x['label']:x for x in r['cases']}
        if name in subjects:
            case=subjects[name]
            need(profile == ('native' if case['lane']=='native' else 'program') and
                 record == (case['lane']=='gated'), 'exact native/gated bounds and record ownership')
        else:need(record is False,'only declared gated subjects own protected record descriptors')
        row=dict(name=name,argv=argv,profile=profile,bounds=BOUNDS[profile],
                 environment=dict(ENV if env is None else env),capture_limit=16<<20,expected_exit=0)
        r['commands'].append(row);save(receipt,r)
        try:
            out,err=program_invoke(row,private,cpu,record=record) if name in subjects else invoke(row,private,cpu)
        finally:
            for value in row.get('captures',{}).values():
                path=binary(private/value['file'])
                need(digest(fact(path))==digest(value),'whole post-reap capture fact')
            path=private/(name+'.json')
            if path.is_file():binary(path)
            save(receipt,r)
        need(row['exit']==0 and row['reaped'] is True and row['timed_out'] is False and
             row['error'] is None and not row['cleanup_errors'] and
             all(x['closed'] is True for x in row['descriptors']), 'exact bounded command completion: '+name)
        return row,out,err

    def module(name,path):
        path=pin(path);spec=importlib.util.spec_from_file_location(name,path)
        need(spec is not None and spec.loader is not None,'actual source-owned reader loader')
        value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value

    def controls(value,count):
        names=value['refusals']
        need(type(names) is list and len(names)==len(set(names))==count and
             all(type(n) is str and n for n in names) and type(value['native_operations']) is int and
             value['native_operations']==0,'exact distinct source-owned refusal population')

    registry = []; environment = None
    try:
        r['source'] = source();need(r['source']['revision'] == args.expect_revision,'exact clean checkout')
        for name in ('SOURCE.json',*manifest['artifacts']):pin(HERE/name)
        for name in manifest['inputs']:pin(ROOT/name)
        for rel,item in context.items():
            pin(facade/rel)
            if item['copy']:binary(facade/rel)
        pin(sys.executable);imports();closure()
        # Resolve the installed selector before downstream imports. Its
        # natural source root is the authenticated checkout.
        import page_selected_repeat_lease_ls as selector
        import maps_view
        from page_selected_effect_ls import program_invoke
        from persistent_dynamic import MASK, H, seed_prerequisite, named, image_inventory, raw_emission
        from direct_frontier_loop_helpers import prepare_inputs
        from scalar_span_trace_build import fast_bytes, fast_bytes_completed
        need(maps_view.SELECTED == selector.SELECTED == facade/'tools/page-entry/selected' and
             selector.ROOT == facade and Path(selector.__file__) == facade/'evaluation/inprocess/page_selected_repeat_lease_ls.py',
             'natural exact installed SELECTED module; actual checkout process/build helpers')
        imports();closure()
        for name in ('/etc/ld.so.cache','/etc/ld.so.preload'):
            presence[name]=Path(name).exists()
            if presence[name]:pin(name)
        need(not presence['/etc/ld.so.preload'],'no global preload')
        prior_path=pin(args.archive_receipt)
        archive,build,environment,archive_exports,prior=custody.check_archive(
            prior_path,args.archive_receipt_sha256,r,pin)
        build=copy.deepcopy(build)
        registry=build['registry_before']
        for name,wanted in prior['loader_presence'].items():
            need(Path(name).exists()==wanted,'same loader configuration presence');presence[name]=wanted
        need(not presence.get('/etc/ld.so.preload',False),'no global preload')
        tools={name:pin(shutil.which(name,path=ENV['PATH'])) for name in ('cc','nm','readelf','git','sh')}
        tools['python']=pin(sys.executable)
        for name in ('cc1','collect2','as','ld'):
            _,out,err=run('resolve-'+name,[tools['cc'],'-print-prog-name='+name]);text=out.decode().strip()
            need(text and not err,'actual compiler subtool')
            tools[name]=pin(text if Path(text).is_absolute() else shutil.which(text,path=ENV['PATH']))
        for name in ('cc','cc1','collect2','as','ld','nm','readelf','python'):
            need(byte_fact(tools[name].read_bytes())==digest(build['tools'][name]),'same retained compiler/tool')
        for name in ('cc','as','ld','nm','readelf','python'):
            _,out,err=run('version-'+name,[tools[name],'--version']);need(out and not err,'actual tool version')
        _,out,err=run('compiler-specs',[tools['cc'],'-dumpspecs']);need(out and not err,'whole compiler specs')
        _,out,err=run('archive-exports',[tools['nm'],'-g','--defined-only',archive])
        need(not err and out==archive_exports,'whole actual retained archive exports')
        r['archive_reuse']=dict(receipt=fact(prior_path),archive=fact(archive),build=build,cpu=cpu,
            fresh_build=False,source_tools_features_verified=True,prior_status=prior['status'],prior_owner_credit=False)
        builder=SimpleNamespace(record=build,tools=tools,environment=environment,
            mov_guard=True,linked_epoch=True,scalar_span=True,extra_decoder_sources=('region.rs','mov_guard.rs'),
            decoder_features=('scalar-region','scalar-span','linked-epoch','mov-guard'),
            retained=archive.parent,paths=dict(archive=archive))
        r['tools']={name:str(path) for name,path in tools.items()}
        components=custody.check_components(args.components_receipt,args.components_receipt_sha256,r,pin,archive)
        actual_native=custody.whole_receipt(args.native136_receipt,args.native136_receipt_sha256,r,pin,
            'public-call-dispatch-native-v1','passed')
        need(actual_native['bounds']=={'build':[30,512<<20,16<<20,60],'native':[5,512<<20,16<<20,15]} and
             actual_native['archive_reuse']['archive']==fact(archive) and
             actual_native['archive_reuse']['release_build']==build and
             actual_native['archive_builds']==0 and actual_native['emitted_execution']==136 and
             actual_native['owner_credit']==0,
             'complete separate native136 prerequisite, same actual archive/build and no owner credit')
        native_gate=module('public_call_native_prerequisite',ROOT/'evaluation/inprocess/call_dispatch_native/run.py')
        last=actual_native['commands'][-1]
        need(last['name']=='read-all-chunks' and last['captures']['stderr']['bytes']==0,
             'actual final complete native136 reader command')
        observed=load(Path(args.native136_receipt).resolve().parent/last['captures']['stdout']['file'])
        need(actual_native['result']==native_gate.native_compact(observed),
             'whole native136 result is exact source-owned reader projection')
        chunks=[x for x in actual_native['commands'] if re.fullmatch('native-[0-5]',x['name'])]
        need(len(chunks)==len(observed['sources'])==6 and observed['cpu']==cpu,
             'six original native136 raw chunks retained')
        for index,(row,value) in enumerate(zip(chunks,observed['sources'],strict=True)):
            need(row['name']=='native-'+str(index) and row['bounds']==[5,512<<20,16<<20,15] and
                 row['captures']['stderr']['bytes']==0 and value==dict(chunk=index,pid=row['pid'],
                 bytes=row['captures']['stdout']['bytes'],sha256=row['captures']['stdout']['sha256']),
                 'all six native136 process/PID/CPU/bound/raw-reader joins')
        need(actual_native['prerequisites']['model']['receipt']==fact(Path(args.components_receipt).resolve()) and
             all(x['environment']==ENV for x in actual_native['commands']),
             'same complete component prerequisite and unchanged native environment')
        r['finite_prerequisites']=dict(
            components=dict(receipt=fact(Path(args.components_receipt).resolve()),revision=components['revision'],
                results={k:v['result'] for k,v in components['components'].items()},fresh_execution=False,owner_credit=False),
            native136=dict(receipt=fact(Path(args.native136_receipt).resolve()),revision=actual_native['revision'],
                result=actual_native['result'],fresh_execution=False,owner_credit=False))
        fixture=facade/'tools/page-entry/selected/tests/persistent_call_owner_app'
        owner=facade/'tools/page-entry/selected/tests/persistent_call_owner_owner'
        app_helper=module('call_owner_app_build',facade/'evaluation/inprocess/call_owner_loop_build.py')
        need(app_helper.FIXTURE==fixture,'natural exact app helper geometry')
        reader=module('call_owner_app',fixture/'read.py')
        owner_reader=module('call_owner_semantics',owner/'read.py')
        reports=module('call_owner_reports',facade/'evaluation/inprocess/persistent_call_owner_reports.py')
        need(reader.APP_CONTROL_COUNTS=={0:40,1:40} and reader.PAIR_CONTROL_COUNTS=={0:40,1:40} and
             reader.FRAME==66784 and reader.TRACES==(6,6) and owner_reader.OWNER_CONTROL_COUNTS=={0:164,1:164} and
             reports.CONTROL_COUNTS=={(0,0):73,(1,0):73} and reports.REPEAT_TLS_CONTROLS==33 and
             reports.SUBENTRY_CONTROL_COUNT==19 and reports.probe.CONTROL_COUNT==22,
             'literal complete app/owner/pair/terminal/TLS/probe/subentry populations')
        image=app_helper.compile_subject(builder,private,pin,binary,aliases,run,r)
        policy=private/'native-policy.so';unit=pin(facade/'tools/page-entry/selected/native_policy.c')
        flags=['-std=gnu11','-O2','-g','-Wall','-Wextra','-Werror','-fPIC','-shared']
        _,out,err=run('policy-headers',[tools['cc'],*flags,'-M','-MT','li2_policy',unit],env=environment)
        lines=out.decode().replace('\\\n',' ').splitlines()
        need(not err and len(lines)==1 and lines[0].startswith('li2_policy: '),'complete policy include rule')
        headers={str(pin(path)):digest(fact(pin(path))) for path in shlex.split(lines[0].split(':',1)[1])}
        need(str(unit) in headers and str(pin(facade/'tools/page-entry/selected/native_policy.h')) in headers,
             'actual policy sources')
        run('policy-link',[tools['cc'],*flags,'-Wl,-z,noexecstack,--build-id=none',unit,'-o',policy],
            profile='release_build',env=environment)
        binary(policy);r['reader_support']=dict(headers=headers,native_policy=fact(policy))
        lib=ctypes.CDLL(str(policy));lib.li2_native_policy.argtypes=(ctypes.c_void_p,ctypes.c_size_t)
        lib.li2_native_policy.restype=ctypes.c_uint
        app=reader.elf(image.read_bytes(),lambda data:lib.li2_native_policy(data,len(data)))
        r['application_layout']={k:v for k,v in app.items() if k not in ('source','continuation')}
        for key in ('source','continuation'):r['application_layout'][key]=byte_fact(app[key])
        seed=seed_prerequisite(builder,private,pin,binary,run,r)
        need(r['seed_prerequisite']['status']=='passed','unchanged original seed prerequisite')
        prepared={}
        for lane,differential in (('maintained',False),('differential',True)):
            directory=private/lane;directory.mkdir();state=r['lanes'][lane]={}
            def lane_run(name,argv,**kwargs):return run(lane+'-'+name,argv,**kwargs)
            bridge=build_bridge(builder,directory,pin,binary,aliases,lane_run,state,image,app,
                facade/'tools/page-entry/selected',manifest,differential,fast_bytes,maps_view)
            need(state['release_build']['status']=='passed' and
                 state['release_build']['call_owner_capture'] is True,
                 'full build completed including mandatory byte oracle')
            fast_bytes_completed(state['release_build'],r['commands'],binary)
            raw_emission(builder,bridge,pin,lane_run,state)
            gdb=pin(shutil.which('gdb',path=ENV['PATH']))
            _,out,err=lane_run('whole-call-owner-layout',[gdb,'-nx','-nh','-batch',
                '-iex','set auto-load off','-iex','set debuginfod enabled off',
                '-iex','set index-cache enabled off','-iex','maintenance set worker-threads 1',
                '-ex','file '+str(bridge),'-ex','source '+str(owner/'layout.py')],
                env=dict(environment,MALLOC_ARENA_MAX='1'))
            need(out and not err,'complete file-only actual DWARF layout')
            layout=json.loads(out,object_pairs_hook=unique);state['schema']=schema_check(layout,owner_reader.wire)
            need(layout['types']['pe_payload']['bytes']==362672 and
                 ((layout['types']['pe_payload']['bytes']+4095)&~4095)==89*4096 and
                 layout['types']['li2_pg_guard']['bytes']==6488 and
                 layout['types']['li2_cd_plan']['fields']['image']['bytes']==512 and
                 layout['registrations']['pe']['bytes']==3988544 and
                 layout['registrations']['pcw']['bytes']==3112 and
                 layout['registrations']['pclo_wire']['bytes']==990144 and
                 layout['symbols']['pclo_wire']==state['release_build']['capture_symbol']['address'],
                 'exact owner/window/payload storage and unchanged89-page proof,6488 guard,512 image caps')
            from page_selected import elf
            _,_,segments=elf(bridge)
            need(all(sum(p[0]==1 and p[1]==6 and p[3]<=x['address']<x['address']+x['bytes']<=p[3]+p[6]
                 for p in segments)==1 for x in layout['registrations'].values()),
                 'every complete registered owner/observer object belongs to one bridge RW/NX LOAD')
            path=directory/'layout.json';save(path,layout);binary(path)
            inputs=prepare_inputs(image,bridge,builder,directory,pin,binary,lane_run,state,r['application_build'])
            prepared[lane]=(bridge,layout,*inputs)
        native={};launcher=pin(fixture/'launch.py');imports();closure()
        for case in r['cases']:
            selected='maintained' if case['lane']=='native' else case['mapping_lane']
            bridge,layout,interp,roots,objects,description,images,raws,carrier=prepared[selected]
            mode=case['mode']
            state=r['lanes'][selected];directory=private/case['label'];directory.mkdir()
            argv=[tools['python'],'-B',launcher,'--root',ROOT,'--role',case['lane'],'--mode',str(mode),'--control','0',
                  '--original',image,'--preparation',directory/'preparation.json']
            for path in roots:argv+=['--library-root',path]
            if case['lane']=='gated':argv+=['--carrier',carrier,'--namespace',directory/'namespace','--record-fd','{record_fd}']
            case['status']='failed'
            try:
                try:
                    row,out,err=run(case['label'],argv,profile='native' if case['lane']=='native' else 'program',
                                    record=case['lane']=='gated')
                finally:
                    if r['commands'][-1]['name']==case['label']:
                        row=r['commands'][-1];case.update(exit=row.get('exit'),launched=type(row.get('pid')) is int,
                            whole_process_ns=row.get('duration_ns'),timed_out=row.get('timed_out'),captures=row.get('captures',{}))
                    if (directory/'preparation.json').is_file():binary(directory/'preparation.json')
                launch=preparation(case,row,directory,image,roots,objects,description,carrier,private,binary,r)
                args_read=(out,mode,case['lane']=='native',row['exit'],app,row['pid'],cpu,seed)
                parsed=reader.read(*args_read)
                if case['lane']=='native':
                    need(not err,'complete native reference has empty stderr')
                    case['application_controls']=reader.controls(*args_read)
                    named(case['application_controls'],40,hashlib.sha256(out).hexdigest())
                    need(len(parsed['observations'])==1 and len(parsed['observations'][0]['frames'])==7,
                         'all seven native full signal frames')
                    native[mode]=parsed
                else:
                    capture=row['captures']['record'];record_path=binary(private/capture['file'])
                    need(capture['bytes']==990144+64<4<<20 and digest(fact(record_path))==digest(capture),
                         'whole literal CALL owner body/footer under original strict4MiB cap')
                    record=record_path.read_bytes();inventory=image_inventory(image,interp,carrier,objects,launch)
                    inventory.update(bridge=bridge.read_bytes(),persistent_binding=state['release_build']['persistent_binding'],
                                     headers=state['release_build']['headers'])
                    args_owner=(record,layout,inventory,parsed,row['pid'],cpu,row['exit'])
                    actual=owner_reader.read(*args_owner)
                    case['owner_controls']=owner_reader.controls(*args_owner);controls(case['owner_controls'],164)
                    case['owner_record_sha256']=hashlib.sha256(record).hexdigest()
                    term_args=(row['pid'],row['exit'],row['stdout_provenance_before'],images,raws,digest(fact(carrier)),
                               carrier.read_bytes(),actual,owner_reader,mode)
                    terminal,case['terminal']=reports.check(err,*term_args,lane=selected,application=parsed)
                    r['terminal_reports'][case['label']]=terminal
                    case['terminal_controls']=reports.controls(err,*term_args,lane=selected,application=parsed)
                    named(case['terminal_controls'],73,hashlib.sha256(err).hexdigest(),hash_key='original_stderr_sha256')
                    case['tls_controls']=reports.repeat_tls_controls(err,terminal,row['pid'],images,raws,
                        digest(fact(carrier)),carrier.read_bytes(),actual,parsed)
                    named(case['tls_controls'],33,hashlib.sha256(err).hexdigest(),hash_key='original_stderr_sha256')
                    case['probe_controls']=reports.probe_controls(err,terminal)
                    named(case['probe_controls'],22,hashlib.sha256(err).hexdigest(),hash_key='original_stderr_sha256')
                    case['subentry_controls']=reports.subentry_controls(err,actual,owner_reader)
                    named(case['subentry_controls'],19,hashlib.sha256(err).hexdigest(),hash_key='original_stderr_sha256')
                    case['effect_controls']=reports.effect_controls(err,terminal)
                    named(case['effect_controls'],12,hashlib.sha256(err).hexdigest(),hash_key='original_stderr_sha256')
                    need(mode in native,'fresh complete same-mode/CPU native reference before gated joins')
                    case['pair']=reader.pair(native[mode],parsed,actual)
                    expected=dict(observed_call_owner=1,mode=mode,invocations=1,native_instructions=6,native_full_frames=7,
                        generated_completed=1,cold_publications=1,domain_members=1,closed_pages=17,
                        modeled_generated_instructions=2 if mode else 4,modeled_ordinary_call=int(bool(mode)),
                        modeled_cached_call=int(not mode),original_return_pc=app['page']+0x20d,stack_bytes=520,
                        measured_interior_signals=0,lifetime_mode=2,registration_epoch=0,registration_calls=0,
                        word_observed=0,qualification_credit=False)
                    need(case['pair']==expected,'exact full-state CALL hit/miss result, no whole-profile credit')
                    case['pair_controls']=reader.pair_controls(native[mode],parsed,actual)
                    controls(case['pair_controls'],40)
                    case['owner_summary']={k:actual[k] for k in ('mode','cold_publications','completed',
                        'domain_members','closed_pages','anchor_released','interior_signals','lifetime_mode',
                        'registration_epoch','registration_calls','word_observed')}
                case['status']='passed'
            except Exception as exc:
                case['error']=repr(exc)
                if r['error'] is None:r['error']=repr(exc)
                last=r['commands'][-1]
                if not(last['name']==case['label'] and last.get('reaped') is True and
                       not last.get('cleanup_errors') and all(d['closed'] for d in last.get('descriptors',[]))):raise
        need(all(x['status']=='passed' for x in r['cases']) and r['error'] is None,
             'all six original-bound subjects and every exact comparator must pass')
        imports();closure()
        r['result']=dict(native_subjects=2,gated_subjects=4,full_builds=2,byte_oracles=2,seed_prerequisites=1,
            native_frames=14,application_controls=80,owner_controls=656,pair_controls=160,
            terminal_controls=292,tls_controls=132,probe_controls=88,subentry_controls=76,effect_controls=48,
            finite_prerequisites=2,owner_pairs=4,raw_bytes=990144,record_bytes=990208,record_limit=4194304,
            archive_builds=0,whole_profile_qualified=False,qualification_credit=False,performance_credit=False)
        r['status']='passed'
    except BaseException as exc:
        r['error'] = repr(exc);r['status'] = 'failed'
    finally:
        for directory in (private/'maintained',private/'differential'):
            if directory.exists():
                for path in directory.rglob('*'):
                    if path.is_file() and not path.is_symlink():
                        try:binary(path)
                        except BaseException as exc:r['final_errors'].append('partial artifact: '+repr(exc))
        for label,action in (('retained prerequisite closure',lambda:need(
            all(fact(p)==v for p,v in prerequisite_files.items()) and
            all(str(Path(p).resolve(strict=True))==v for p,v in prerequisite_aliases.items()),
            'all retained finite prerequisite files/modes/aliases unchanged')),('imports',imports),('input closure',closure),
            ('registry closure',lambda:need([package_check(x) for x in registry] == registry,'locked registry unchanged'))):
            try:action()
            except BaseException as exc:r['final_errors'].append(label+': '+repr(exc))
        try:
            r['source_unchanged'] = source() == r['source']
            need(r['source_unchanged'],'whole source closure')
            if environment is not None:
                need(admission.cargo_configuration(environment) == build['cargo_configuration'],'Cargo configuration unchanged')
        except BaseException as exc:r['final_errors'].append('source/configuration: '+repr(exc))
        r['inputs_unchanged'] = not r['final_errors']
        r['cleanup_complete'] = all(x.get('reaped') is True and not x.get('cleanup_errors') and
            all(d['closed'] for d in x.get('descriptors',[])) for x in r['commands'])
        if r['final_errors'] or not r['cleanup_complete']:r['status'] = 'failed'
        r.update(inputs=pins,aliases=aliases,artifacts=artifacts,loader_presence=presence,
            prerequisite_files=prerequisite_files,prerequisite_aliases=prerequisite_aliases);save(receipt,r)
        host=dict(r['hardware']);host.pop('runner_euid',None);isa=host.pop('isa_flags')
        host['isa_flags_count']=len(isa);host['isa_flags_sha256']=hashlib.sha256(
            json.dumps(isa,sort_keys=True,separators=(',',':')).encode()).hexdigest()
        cases=[]
        for case in r['cases']:
            row={k:case[k] for k in ('label','lane','mapping_lane','mode','control','status','launched',
                 'expected_exit','bounds','exit','whole_process_ns','timed_out','captures','pair','owner_summary') if k in case}
            row['controls']={name:len(case.get(name,{}).get('refusals',[])) for name in
                 ('application_controls','owner_controls','pair_controls','terminal_controls',
                  'tls_controls','probe_controls','subentry_controls','effect_controls')}
            row['error_type']=case['error'].split('(',1)[0].split(':',1)[0] if case.get('error') else None
            cases.append(row)
        commands=[{k:x.get(k) for k in ('name','bounds','expected_exit','exit','duration_ns','reaped',
            'timed_out','captures')} for x in r['commands']]
        summary=dict(schema=1,profile=r['profile'],status=r['status'],revision=r['revision'],cpu=cpu,
            hardware=host,bounds=BOUNDS,result=r['result'],cases=cases,commands=commands,
            source_unchanged=r['source_unchanged'],inputs_unchanged=r['inputs_unchanged'],
            cleanup_complete=r['cleanup_complete'],pending=r['pending'],qualification_credit=False,
            performance_credit=False,receipt=digest(fact(receipt)),
            source_input_count=len(pins),artifact_count=len(artifacts),archive_builds=0,
            reproducer='evaluation/inprocess/call_owner/run.py',
            execution_argv_sha256=hashlib.sha256(json.dumps(sys.argv,separators=(',',':')).encode()).hexdigest())
        payload=json.dumps(summary,sort_keys=True,indent=2)+'\n'
        need(str(ROOT) not in payload and str(private) not in payload and '/home/' not in payload,
             'public summary excludes raw paths and host paths')
        (private/'summary.json').write_text(payload)
    print(json.dumps(dict(status=r['status'],receipt=str(receipt),result=r['result']),sort_keys=True))
    return 0 if r['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
