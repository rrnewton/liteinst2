"""Complete distinct version9 direct-E8 owner build; full mandatory byte oracle retained."""
import hashlib
import json
from pathlib import Path
import re
import shlex
import struct
import shutil
from call_owner.run import need, fact, digest, load, byte_fact, image_identity


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
    need(len(expected) == 70 and len(set(expected)) == 69 and set(symbols) == set(expected),
         'all70 exact recipe entries including one original duplicate, all69 unique functions')
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
    output=private/('persistent-direct-call-owner-'+mode);output.mkdir()
    recipe=pin(selected/('build-persistent-direct-call-owner'+('-differential' if differential else '')+'.sh'))
    text=recipe.read_text().replace('\\\n',' ')
    lines=[line.strip() for line in text.splitlines() if line.strip().startswith('"$cc_bin" ')]
    binders=[line.strip() for line in text.splitlines() if line.strip().startswith('"${LI2_PYTHON:-python3}" ')]
    need(len(lines)==len(binders)==1 and binders[0]==
         '"${LI2_PYTHON:-python3}" "$selected_dir/persistent_direct_call_owner_binding.py" "$selected_dir" "$archive" "$image" "$output" '+mode,
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
    need(len(sources)==(86 if differential else 85) and len({x['path'] for x in sources})==len(sources),
         'exact complete ordered capture policy population')
    original=image_identity(image.read_bytes())
    policy=hashlib.sha256(json.dumps(dict(sources=sources,original=original,mode=mode),sort_keys=True,separators=(',',':')).encode()).hexdigest()
    expected=dict(version=1,profile='persistent-direct-call-owner-'+mode+'-v1',mode=mode,native_probe=True,
        parse_memo=True,unregistered=True,subentry=True,cross_pair=True,direct_frontier=True,call_dispatch=True,ret_dispatch=True,call_return_heads=True,direct_call=True,plan_version=9,
        maps_differential=differential,typed_capture=True,ret_owner_capture=True,capture_schema=1,
        archive=digest(fact(archive)),policy_sha256=policy,original=original,sources=sources)
    literal=lambda s:'{'+','.join('0x'+s[i:i+2] for i in range(0,64,2))+'}'
    config={
        'linked_epoch_config.h':'#ifndef LI2_LINKED_EPOCH_CONFIG_H\n#define LI2_LINKED_EPOCH_CONFIG_H\n#define LI2_LINK_BINDING_VERSION 1\n#define LI2_LINK_ARCHIVE_SHA256 '+literal(expected['archive']['sha256'])+'\n#define LI2_LINK_POLICY_SHA256 '+literal(policy)+'\n#endif\n',
        'persistent_group_config.h':'#ifndef LI2_PERSISTENT_GROUP_CONFIG_H\n#define LI2_PERSISTENT_GROUP_CONFIG_H\n#define LI2_PG_BINDING_VERSION 1\n#define LI2_PG_GROUP_BINDING_VERSION 4\n#define LI2_PG_ARCHIVE_SHA256 '+literal(expected['archive']['sha256'])+'\n#define LI2_PG_POLICY_SHA256 '+literal(policy)+'\n#endif\n',
        'persistent_ret_owner_config.h':'#ifndef LI2_PERSISTENT_RET_OWNER_CONFIG_H\n#define LI2_PERSISTENT_RET_OWNER_CONFIG_H\n#define LI2_PRTO_VERSION 1\n'+''.join(
            '#define LI2_PRTO_'+name+'_RVA 0x'+format(value,'x')+'ULL\n' for name,value in (
                ('PAGE',app['page']),('U_PAGE',app['page']+8192),('A',app['head']),
                ('A_MISS',app['page']+0x600),('B',app['page']+0x300),
                ('RET',app['page']+0x30a),('U',app['page']+0x2100),
                ('CAPTURE',app['symbols']['region_app_capture_high'])))+'#endif\n'}
    expected['headers']={name:byte_fact(data.encode()) for name,data in config.items()}
    _,out,err=run('binding',[builder.tools['python'],'-B',selected/'persistent_direct_call_owner_binding.py',
                           selected,archive,image,output,mode],env=builder.environment)
    need(not out and not err,'silent actual source-owned binder')
    binding_path=binary(output/'persistent_direct_call_owner_binding.json');binding=load(binding_path)
    need(binding==expected and binding_path.read_bytes()==(json.dumps(expected,sort_keys=True)+'\n').encode(),
         'whole independently reconstructed typed RET capture binding')
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
    bridge=output/'bridge-persistent-direct-call-owner.so'
    macros=manifest['macros'][mode]
    need([x for x in argv if x.endswith(('.c','.S'))]==tus and len(tus)==28 and
         [x for x in argv if x.endswith('.a')]==[str(archive)] and argv[-2:]==['-o',str(bridge)] and
         [x for x in argv if x.startswith('-DLI2_')]==macros and
         all(x in argv for x in ('-O2','-g','-nostdlib','-shared','-fPIC','-fvisibility=hidden',
         '-mgeneral-regs-only','-fno-builtin','-fno-tree-loop-distribute-patterns','-fno-tree-vectorize',
         '-Wall','-Wextra','-Werror')),'exact28-TU no-FP typed capture recipe and original compiler policy')
    state=record['release_build']=dict(status='failed',profile=expected['profile'],recipe=fact(recipe),
        archive=digest(fact(archive)),argv=argv,persistent_binding=binding,capture=True,
        ret_owner_capture=True,qualification_credit=False)
    flags=[x for x in argv[1:-2] if x not in tus and x!=str(archive) and not x.startswith(('-Wl,','-l'))]
    _,out,err=run('headers',[builder.tools['cc'],*flags,'-M','-MT','ret_owner',*tus],env=builder.environment)
    rules=out.decode().replace('\\\n',' ').splitlines()
    need(not err and len(rules)==28 and all(x.startswith('ret_owner: ') for x in rules),
         'one complete actual compiler-M rule per translation unit')
    observed={str(pin(x)):digest(fact(pin(x))) for rule in rules for x in shlex.split(rule.split(':',1)[1])}
    required={str(Path(x).resolve()) for x in tus}|{str((selected/x).resolve()) for x in manifest['required_headers']}|{str(output/x) for x in config}
    need(required<=set(observed),'complete inherited map/custody/CALL/RET/owner/config dependency closure')
    for item in sources:
        if item['path'].endswith(('.c','.h','.inc')):
            need(observed.get(str((selected/item['path']).resolve()))==digest(item),
                 'every whole bound C policy source is an actual compiler input')
    names={Path(x).name for x in observed}
    need(not names.intersection(manifest['forbidden_headers']) and
         not any(('observe' in n and n not in {'persistent_ret_owner_observe.h','persistent_ret_owner_observe.inc'})
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
    for name,size in (('maps_parse_memo',376856),('prto_wire',1261760),('pe',3998208),('pcw',3112),('prr',72256)):
        rows=[line.split() for line in symbols.splitlines() if line.split()[-1:]==[name.encode()]]
        need(len(rows)==1 and len(rows[0])==4 and rows[0][2] in (b'b',b'B') and
             int(rows[0][0],16)>0 and int(rows[0][1],16)==size,'complete actual protected BSS '+name)
        if name=='prto_wire':state['capture_symbol']=dict(address=int(rows[0][0],16),bytes=size)
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
