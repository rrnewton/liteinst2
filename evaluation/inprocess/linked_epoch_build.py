#!/usr/bin/env python3
"""Exact archive/policy/ELF binding for the distinct linked execution epoch."""
import json,shutil,struct
from pathlib import Path
from maps_view import (need,fact,SELECTED,UNITS,MACROS,recipe,expand,headers,
    bridge_check,ENV,hidden_memset,body_check,digest,H)
from scalar_span_trace_build import fast_bytes

FEATURES=('scalar-region','scalar-span','linked-epoch')
FIXED_DOMAIN={
    'decoder/src/region.rs':(51594,'2c3b9712afb01e82ac797000a397f790565a412f6a6590cab8672dd0b3334e3a'),
    'decoder/src/tf.rs':(45018,'e09a1c170f50c59f8faa34ecdc69ddfe9e651158f0f00a668ed7ef2c82059e38'),
    'decoder/src/write_footprint.rs':(10124,'754fbc625a52f27dfe20ce3353f761586a4eb1640c64fe846634c8d14501dfe7'),
    'region_decode.h':(7150,'d9ccb59abd39bff378ecb30460e6d5c45142c2f77636b2c25068db9446a6e529'),
}
# Exact order is part of the production binder's canonical policy digest.
POLICY_INPUTS=(
    'decoder/Cargo.toml','decoder/src/region.rs','decoder/src/tf.rs',
    'decoder/src/write_footprint.rs','region_decode.h','linked_plan.h','linked_plan.c',
    'linked_source.h','linked_source.inc','linked_rseq.h','linked_rseq.inc',
    'linked_proof.h','linked_proof.inc','linked_controller.inc','linked_reuse.inc',
    'lifecycle_loader.c','span_source.inc','rseq_guard.c','rseq_region.inc',
    'runtime_loader.c','selected_globals.inc','selected_chain.inc',
    'native_lifecycle.inc','native_pair_lifecycle.inc','tf_span_transfer.inc',
    'span_fetch.inc','span_fast_bytes.h','build-linked-epoch.sh','linked_epoch_binding.py',
)
HINT_POLICY_INPUTS=POLICY_INPUTS+('linked_native_hint.h','linked_native_hint.inc',
    'native_pair_controller.inc','build-linked-epoch-native-hint.sh')
PREEDGE_POLICY_INPUTS=HINT_POLICY_INPUTS+('linked_preedge_plan.h','linked_preedge_plan.c','linked_preedge_source.h',
    'linked_preedge_source.inc','linked_preedge_rseq.h','linked_preedge_rseq.inc',
    'linked_preedge_proof.h','build-linked-preedge.sh')
PREEDGE_CAPTURE_HEADERS=('linked_preedge_observe.h','linked_preedge_observe.inc',
    'linked_preedge_observe_memory.h','linked_preedge_observe_memory.inc')
CAPTURE_HEADERS=('linked_epoch_observe.h','linked_epoch_observe.inc','linked_refault_observe.h','linked_refault_observe.inc',
    'linked_epoch_observe_memory.h','linked_epoch_observe_memory.inc','unrolled_hash_nested_fp.h')


def binding_config(builder,archive,output,pin,binary,run,*,native_hint=False,preedge=False):
    """Run the source-owned binder, then independently authenticate every byte."""
    need(type(native_hint)is bool,'exact native-hint binding selector')
    need(type(preedge)is bool and (not preedge or native_hint),'exact v2 pre-edge binding selector')
    values=[]
    for name in PREEDGE_POLICY_INPUTS if preedge else HINT_POLICY_INPUTS if native_hint else POLICY_INPUTS:
        path=pin(SELECTED/name);value=fact(path)
        if name in FIXED_DOMAIN:
            size,sha=FIXED_DOMAIN[name]
            need(digest(value)==digest(dict(bytes=size,sha256=sha)),'exact reviewed linked131/NONE policy '+name)
        if name.endswith('.rs'):
            need(digest(builder.record['dep_info'].get('tools/page-entry/selected/'+name))==digest(value),
                 'actual retained archive compiled the exact linked proof source')
        values.append(dict(path=name,**value))
    need(all(type(builder.record['archive_text_exports'].get(name))is int and
         builder.record['archive_text_exports'][name]==1 for name in
         ('li2_decoder_region_describe','li2_decoder_span_describe','li2_decoder_link_none',
          'li2_decoder_tf_classify','li2_decoder_write_footprint')),
         'actual archive has every exact cold proof provider')
    archive_fact=fact(pin(archive));policy=digest(values)
    header=output/'linked_epoch_config.h';manifest=output/'linked_epoch_binding.json'
    need(not header.exists()and not manifest.exists(),'fresh exclusive binding output paths')
    _,out,err=run('linked-policy-binding',[builder.tools['python'],'-B',SELECTED/'linked_epoch_binding.py',
        SELECTED,archive,output,*(['native-hint-preedge']if preedge else['native-hint']if native_hint else[])],env=builder.environment)
    need(out==err==b'','complete actual production policy binder without diagnostics')
    literal=lambda sha:'{'+','.join('0x'+sha[i:i+2]for i in range(0,64,2))+'}'
    expected=('#ifndef LI2_LINKED_EPOCH_CONFIG_H\n#define LI2_LINKED_EPOCH_CONFIG_H\n'
        '#define LI2_LINK_BINDING_VERSION 1\n'
        + ('#define LI2_LINK_PREEDGE_BINDING_VERSION 2\n'if preedge else'') +
        '#define LI2_LINK_ARCHIVE_SHA256 '+literal(archive_fact['sha256'])+'\n'
        '#define LI2_LINK_POLICY_SHA256 '+literal(policy)+'\n#endif\n').encode()
    header=pin(binary(header));manifest=pin(binary(manifest))
    need(header.read_bytes()==expected,'whole actual archive/policy header matches independent derivation')
    record=dict(version=1,archive=archive_fact,policy_sha256=policy,sources=values,header_sha256=H(expected))
    need(manifest.read_bytes()==(json.dumps(record,sort_keys=True)+'\n').encode(),
         'whole typed production binding record and canonical source order')
    return dict(version=1,archive=archive_fact,policy_sha256=policy,sources=values,
        header=fact(header),path=str(header),manifest=fact(manifest),manifest_path=str(manifest))


def capture_config(path,output,pin,binary,reuse=False):
    """The finite image's actual head, whole gapped source and literal exits."""
    path=pin(binary(path));data=path.read_bytes()
    def take(at,n):
        need(type(at)is int and type(n)is int and 0<=at<=len(data)and 0<=n<=len(data)-at,'bounded actual capture ELF range')
        return data[at:at+n]
    h=struct.unpack('<16sHHIQQQIHHHHHH',take(0,64))
    need(h[0][:7]==b'\x7fELF\x02\x01\x01'and h[1:4]==(2,62,1)and h[8:10]==(64,56)and
         0<h[10]<=32 and h[11]==64 and 0<h[12]<=256,'bounded actual x86-64 ET_EXEC capture image')
    ph=[struct.unpack('<IIQQQQQQ',take(h[5]+56*i,56))for i in range(h[10])]
    sections=[struct.unpack('<IIQQQQIIQQ',take(h[6]+64*i,64))for i in range(h[12])]
    tables=[s for s in sections if s[1]==2]
    need(len(tables)==1 and tables[0][9]==24 and tables[0][5]%24==0,'one whole actual capture symbol table')
    t=tables[0];need(t[6]<len(sections),'actual capture string table index');table=sections[t[6]]
    need(table[1]==3,'actual string table type');names=take(table[4],table[5]);symbols={}
    wanted={b'region_app_'+n for n in ((b'head',b'page',b'exit0',b'predecessor',b'source_end',b'capture_high')if reuse else
        (b'head',b'page',b'block_b',b'block_c',b'block_d',b'exit0',b'frontier_next',b'exit1',b'constant',b'predecessor',b'source_end',b'capture_high'))}
    for at in range(t[4],t[4]+t[5],24):
        n,info,other,section,pc,size=struct.unpack('<IBBHQQ',take(at,24))
        need(n<len(names)and b'\0'in names[n:],'whole symbol name');name=names[n:names.index(b'\0',n)]
        if name in wanted:
            need(section and name not in symbols,'unique actual defined graph symbol');symbols[name]=(pc,size)
    need(set(symbols)==wanted,'complete actual graph symbol set')
    pc,size=symbols[b'region_app_head'];page=pc&-4096
    need(4096<=page<1<<31 and pc-page==0x200 and size==(10 if reuse else 18)and
         symbols[b'region_app_page'][0]==page and symbols[b'region_app_source_end'][0]==page+4096,
         'actual first graph head and complete same-page extent')
    need(symbols[b'region_app_predecessor'][0]==page+0x1fe,'genuine ordinary predecessor')
    owners=[s for s in ph if s[0]==1 and s[1]==5 and s[5]<=s[6]and s[3]<=page and page-s[3]+4096<=s[5]]
    need(len(owners)==1,'full source in one actual RX file range');segment=owners[0]
    source=take(segment[2]+page-segment[3],4096);expected=bytearray(b'\xcc'*4096)
    if reuse:
        need(symbols[b'region_app_exit0']==(page+0xc00,6),'actual65-key shared unsupported frontier')
        for i in range(65):
            off=0x200+32*i
            expected[off-2:off]=b'\x66\x90'
            expected[off:off+10]=b'\xb8'+struct.pack('<I',i+1)+b'\xe9'+struct.pack('<i',0xc00-off-10)
        expected[0xc00:0xc0e]=b'\xff\x25\0\0\0\0'+struct.pack('<Q',symbols[b'region_app_capture_high'][0])
    else:
        for name,offset,n in ((b'block_b',0x300,13),(b'block_c',0x400,14),(b'block_d',0x500,24),
            (b'exit0',0x600,2),(b'frontier_next',0x602,6),(b'exit1',0x620,6),(b'constant',0x700,4)):
            need(symbols[b'region_app_'+name]==(page+offset,n),'exact native noncontiguous graph geometry')
        expected[0x1fe:0x200]=expected[0x600:0x602]=b'\x66\x90'
        fragments={0x200:'b80700000085f60f84f3010000e9ee000000',0x300:'448b07488d444802e9f3010000',
            0x400:'448b074531c94801d0e9f2000000',0x500:'458b12448b1df601000083f80f0f850d010000e9e8000000'}
        for offset,value in fragments.items():value=bytes.fromhex(value);expected[offset:offset+len(value)]=value
        for offset in(0x602,0x620):expected[offset:offset+14]=b'\xff\x25\0\0\0\0'+struct.pack('<Q',symbols[b'region_app_capture_high'][0])
        expected[0x700:0x704]=struct.pack('<I',0x89abcdef)
    need(source==expected,'whole actual finite or65-key source, gaps and immutable external targets')
    header=output/'linked_epoch_capture_config.h'
    with header.open('x')as stream:stream.write('#define LI2_LINK_APP_HEAD_RVA 0x%xULL\n'%pc)
    header=pin(binary(header))
    return dict(image=fact(path),head_rva=pc,source_sha256=H(source),header=fact(header),path=str(header))


def preedge_capture_config(path,output,pin,binary):
    """Bind all three complete source/target pairs to the actual finite ELF."""
    path=pin(binary(path));data=path.read_bytes()
    def take(at,n):
        need(type(at)is int and type(n)is int and 0<=at<=len(data)and 0<=n<=len(data)-at,'bounded actual capture ELF range')
        return data[at:at+n]
    h=struct.unpack('<16sHHIQQQIHHHHHH',take(0,64))
    need(h[0][:7]==b'\x7fELF\x02\x01\x01'and h[1:4]==(2,62,1)and h[8:10]==(64,56)and
         0<h[10]<=32 and h[11]==64 and 0<h[12]<=256,'bounded actual x86-64 ET_EXEC capture image')
    ph=[struct.unpack('<IIQQQQQQ',take(h[5]+56*i,56))for i in range(h[10])]
    sections=[struct.unpack('<IIQQQQIIQQ',take(h[6]+64*i,64))for i in range(h[12])]
    tables=[s for s in sections if s[1]==2]
    need(len(tables)==1 and tables[0][9]==24 and tables[0][5]%24==0,'one whole actual capture symbol table')
    t=tables[0];need(t[6]<len(sections),'actual capture string table index');table=sections[t[6]]
    need(table[1]==3,'actual string table type');names=take(table[4],table[5]);symbols={}
    geometry={
        'page':(0,None),'head':(4060,30),'predecessor':(4058,None),'cut':(4090,6),
        'taken':(3968,6),'fallthrough':(4096,6),'source_end':(4096,None),
        'next_page':(8192,None),'next_head':(12256,30),'next_predecessor':(12254,None),
        'next_cut':(12286,2),'next_target':(12288,6),'next_end':(12288,None),
        'unsupported_page':(16384,None),'unsupported_head':(20448,30),
        'unsupported_predecessor':(20446,None),'unsupported_cut':(20478,2),
        'unsupported_target':(20480,6),'unsupported_end':(20480,None)}
    wanted={('region_app_'+n).encode()for n in geometry}|{b'region_app_capture_high'}
    for at in range(t[4],t[4]+t[5],24):
        n,info,other,section,pc,size=struct.unpack('<IBBHQQ',take(at,24))
        need(n<len(names)and b'\0'in names[n:],'whole pre-edge symbol name')
        name=names[n:names.index(b'\0',n)]
        if name in wanted:
            need(section and name not in symbols,'unique actual defined pre-edge symbol');symbols[name]=(pc,size)
    need(set(symbols)==wanted,'complete actual pre-edge symbol set')
    page=symbols[b'region_app_page'][0]
    need(page%4096==0 and 4096<=page and page+24576<1<<31,'three low original pages and separate real next-page targets')
    for name,(offset,size)in geometry.items():
        observed=symbols[('region_app_'+name).encode()]
        need(observed[0]==page+offset and(size is None or observed[1]==size),'exact whole pre-edge symbol geometry '+name)
    owners=[s for s in ph if s[0]==1 and s[1]==5 and s[5]<=s[6]and s[3]<=page and page-s[3]+24576<=s[5]]
    need(len(owners)==1,'whole six-page primitive in one actual RX file range');segment=owners[0]
    source=take(segment[2]+page-segment[3],24576);expected=bytearray(b'\xcc'*24576)
    high=symbols[b'region_app_capture_high'][0]
    need(high>=1<<33 and symbols[b'region_app_capture_high'][1]>0 and
         sum(s[0]==1 and s[1]==5 and s[3]<=high and high-s[3]+symbols[b'region_app_capture_high'][1]<=s[5]for s in ph)==1,
         'whole actual high transparent capture target in one RX file load')
    stub=b'\xff\x25\0\0\0\0'+struct.pack('<Q',high)
    for index,offset in enumerate((4060,12256,20448)):
        expected[offset-2:offset]=b'\x66\x90';expected[offset:offset+30]=bytes.fromhex('b807000000')*6
        cut=offset+30;expected[cut:cut+(6 if index==0 else 2)]=(b'\x0f\x85'+struct.pack('<i',3968-4096)if index==0 else b'\x31\xc0'if index==1 else b'\x66\x90')
    for offset in(3968,4096,12288,20480):expected[offset:offset+14]=stub
    need(source==expected,'whole six-page source, actual cut instructions, CC gaps and immutable target literals')
    names=('head','next_head','unsupported_head','cut','next_cut','unsupported_cut',
           'taken','fallthrough','next_target','unsupported_target')
    rvas={name:symbols[('region_app_'+name).encode()][0]for name in names}
    raw=''.join('#define LI2_PREEDGE_APP_'+name.upper()+'_RVA 0x%xULL\n'%rvas[name]for name in names).encode()
    header=output/'linked_preedge_capture_config.h'
    with header.open('xb')as stream:stream.write(raw)
    header=pin(binary(header))
    need(header.read_bytes()==raw,'whole exact actual-image pre-edge configuration')
    return dict(image=fact(path),rvas=rvas,source_sha256=H(source),header=fact(header),path=str(header))


def build_bridge(builder,products,private,pin,binary,aliases,run,r,extra=(),capture_image=None,*,native_hint=False,graph_observe=False,preedge=False):
    need(type(native_hint)is bool,'exact distinct native-hint build selector')
    preedge_capture=extra==('LINKED_PREEDGE_CAPTURE',)
    need(type(preedge)is bool and (not preedge or native_hint and not graph_observe and
         (extra==()and capture_image is None or preedge_capture and capture_image is not None)),
         'explicit pre-edge v2 release or dedicated capture; all old capture profiles are rejected')
    need(not preedge_capture or preedge,'dedicated pre-edge capture requires the typed v2 runtime')
    need(type(graph_observe)is bool and (not graph_observe or
         native_hint and extra==()and capture_image is None),'release-only native-hint graph observer')
    need(builder.linked_epoch is True and builder.scalar_span is True and builder.extra_decoder_sources==('region.rs',)and
         builder.decoder_features==FEATURES and builder.record.get('decoder_features')==list(FEATURES)and
         builder.environment.get('LI2_DECODER_FEATURES')=='linked-epoch','exact new linked-epoch Build/archive selection')
    archive=pin(products['archive']);retained=builder.record['artifacts']['decoder.a']
    need(builder.record['status']=='passed'and builder.record['command_completed']is True and
         archive==builder.paths['archive']==builder.retained/'decoder.a'and str(archive)==retained['path']and
         digest(fact(archive))==digest({k:retained[k]for k in('bytes','sha256')}),'fresh completed Build owns actual linked archive')
    need(extra in((),('MAPS_DIFFERENTIAL',),('LINKED_EPOCH_CAPTURE',),('LINKED_EPOCH_CAPTURE','LINKED_EPOCH_REUSE_CAPTURE'),('LINKED_PREEDGE_CAPTURE',)),'exact normal, differential or distinct finite capture profile')
    reuse=extra==('LINKED_EPOCH_CAPTURE','LINKED_EPOCH_REUSE_CAPTURE');capture='LINKED_EPOCH_CAPTURE'in extra or preedge_capture
    need((capture_image is not None)==capture,'fresh image iff explicit linked capture profile')
    output=private/'release';output.mkdir();binding=binding_config(builder,archive,output,pin,binary,run,native_hint=native_hint,preedge=preedge)
    config=(preedge_capture_config(capture_image,output,pin,binary)if preedge_capture else capture_config(capture_image,output,pin,binary,reuse))if capture else None
    script=pin(SELECTED/('build-linked-preedge-capture.sh'if preedge_capture else'build-linked-epoch-reuse-capture.sh'if reuse else'build-linked-epoch-capture.sh'if capture else'build-linked-preedge.sh'if preedge else'build-linked-epoch-graph-observe.sh'if graph_observe else'build-linked-epoch-native-hint.sh'if native_hint else'build-linked-epoch.sh'))
    rows=recipe(script,'"$cc_bin"');need(len(rows)==1,'one exact linked runtime compiler recipe')
    argv=expand(rows[0],{'$cc_bin':builder.tools['cc'],'$selected_dir':SELECTED,'$parent_dir':SELECTED.parent,
        '$archive':archive,'$output':output})
    if not capture:argv[1:1]=['-DLI2_'+x+'=1'for x in extra]
    elif native_hint and not preedge_capture:argv.insert(argv.index('-DLI2_LINKED_EPOCH=1'),'-DLI2_LINKED_NATIVE_HINT=1')
    units=[str(SELECTED.parent/x)for x in UNITS]+[str(SELECTED/x)for x in(('unrolled_hash_plan.c','region_plan.c','linked_plan.c','linked_preedge_plan.c')if preedge else('unrolled_hash_plan.c','region_plan.c','linked_plan.c'))]
    macros=(('LINKED_PREEDGE',)if preedge else())+(('LINK_GRAPH_OBSERVE',)if graph_observe else())+extra+(('LINKED_NATIVE_HINT',)if native_hint else())+('LINKED_EPOCH','SCALAR_SPAN','SCALAR_SPAN_TRACE','SPAN_FAST_BYTES','MAPS_CURRENT_TF',
        'SCALAR_REGION','SCALAR_REGION_REUSE','INITIAL_CODE_PROTECTION','UNROLLED_HASH','MAPS_MAINTAINED')+MACROS
    need(argv[-2:]==['-o',str(output/'bridge-linked-epoch.so')]and
         [x for x in argv if x.endswith(('.c','.S'))]==units and
         [x for x in argv if x.startswith('-DLI2_')]==['-DLI2_'+x+'=1'for x in macros]and
         all(x in argv for x in('-O2','-g','-nostdlib','-shared','-fPIC','-fvisibility=hidden','-mgeneral-regs-only',
             '-fno-builtin','-fno-tree-loop-distribute-patterns','-fno-tree-vectorize','-Wall','-Wextra','-Werror')),
         'exact22-TU pre-edge runtime macro/feature/no-FP recipe'if preedge else'exact21-TU linked runtime macro/feature/no-FP recipe')
    state=r['release_build']=dict(status='failed',recipe=fact(script),archive=fact(archive),argv=argv,
        linked_binding=binding,capture_config=config)
    if native_hint:state['native_hint']=True
    if preedge:
        state['preedge']=dict(version=2,plan_bytes=40744,proof_payload_bytes=45288,capture=preedge_capture)
        donor=pin(SELECTED/'build-linked-epoch-native-hint.sh')
        expected=donor.read_bytes().replace(b'# Distinct positive-native-receipt advisory; every actual NX admission remains mandatory.',b'# Distinct typed v2 pre-edge release profile; original NX cuts require separate qualification.',1)
        expected=expected.replace(b'\"$output\" native-hint',b'\"$output\" native-hint-preedge',1).replace(b'-DLI2_LINKED_NATIVE_HINT=1',b'-DLI2_LINKED_PREEDGE=1 -DLI2_LINKED_NATIVE_HINT=1',1)
        expected=expected.replace(b'--undefined=li2_link_plan_validate ',b'--undefined=li2_link_plan_validate,--undefined=li2_preedge_plan_page,--undefined=li2_preedge_plan_validate ',1)
        expected=expected.replace(b'\"$selected_dir/linked_plan.c\" \"$archive\"',b'\"$selected_dir/linked_plan.c\" \"$selected_dir/linked_preedge_plan.c\" \"$archive\"',1)
        if preedge_capture:expected=expected.replace(b'-DLI2_LINKED_PREEDGE=1',b'-DLI2_LINKED_PREEDGE=1 -DLI2_LINKED_PREEDGE_CAPTURE=1',1)
        need(script.read_bytes()==expected,'whole v2 recipe differs only by explicit profile, providers, TU and selected capture macro')
    if graph_observe:
        donor=pin(SELECTED/'build-linked-epoch-native-hint.sh')
        need(script.read_bytes()==donor.read_bytes().replace(b'-DLI2_LINKED_NATIVE_HINT=1',
             b'-DLI2_LINK_GRAPH_OBSERVE=1 -DLI2_LINKED_NATIVE_HINT=1',1),
             'whole source-owned hint recipe plus only the observer macro')
        state['graph_observe']=True
    headers('release-bridge-headers',argv,units,archive,builder,pin,aliases,run,state)
    required=('maps_phase.inc','maps_view.inc','initial_code_protection.h','selected_unrolled_hash.inc','unrolled_hash.h',
        'unrolled_source.inc','unrolled_source.h','rseq_unrolled.inc','region_plan.h','region_source.h','region_source.inc',
        'selected_scalar_region.inc','selected_scalar_reuse.inc','tf_span_transfer.h','span_fetch.h','span_source.h',
        'rseq_span.inc','fetch_current_custody.h','fetch_current_custody.inc','maps_current_ticket.h')
    need(all(str((SELECTED/name).resolve())in state['headers']for name in required),'complete inherited map/custody/owner dependency closure')
    for value in binding['sources']:
        name=value['path']
        if name.endswith(('.c','.h','.inc')):
            need(digest(state['headers'].get(str((SELECTED/name).resolve())))==digest({k:value[k]for k in('bytes','sha256')}),
                 'every bound C policy source occurs in actual compiler-M closure')
    need(digest(state['headers'].get(binding['path']))==digest(binding['header']),'actual archive/policy header observed by compiler')
    need(all((str((SELECTED/name).resolve())in state['headers'])==native_hint
         for name in('linked_native_hint.h','linked_native_hint.inc')),
         'actual native-hint headers iff the distinct literal profile is selected')
    need(all((str((SELECTED/name).resolve())in state['headers'])==preedge for name in
         ('linked_preedge_plan.h','linked_preedge_plan.c','linked_preedge_source.h','linked_preedge_source.inc',
          'linked_preedge_rseq.h','linked_preedge_rseq.inc','linked_preedge_proof.h')),
         'actual v2 typed plan/source/NONE/proof closure iff pre-edge selected')
    need(all(str((SELECTED/name).resolve())not in state['headers']for name in
         ('selected_scalar_span.inc','selected_scalar_span_reuse.inc','scalar_region_observe.inc',
          'unrolled_hash_observe.inc','current_tf_observe.inc','span_trace_observe.inc')),
         'no substituted span owner or legacy capture adapter')
    wanted_capture=set(PREEDGE_CAPTURE_HEADERS)if preedge_capture else set(('linked_epoch_reuse_observe.h','linked_epoch_reuse_observe.inc',
        'linked_epoch_observe_memory.h','linked_epoch_observe_memory.inc'))if reuse else set(CAPTURE_HEADERS)if capture else set()
    hint_capture={'linked_hint_observe.h','linked_hint_observe.inc'}
    if capture and native_hint and not reuse and not preedge_capture:wanted_capture|=hint_capture
    all_capture=set(CAPTURE_HEADERS)|set(PREEDGE_CAPTURE_HEADERS)|{'linked_epoch_reuse_observe.h','linked_epoch_reuse_observe.inc'}|hint_capture
    need(all((str((SELECTED/name).resolve())in state['headers'])==(name in wanted_capture)for name in all_capture),
         'complete exact distinct finite/reuse capture seams iff selected')
    if capture:need(digest(state['headers'].get(config['path']))==digest(config['header']),'actual image-derived capture header')
    bridge=Path(argv[-1]);run('release-bridge-link',argv,profile='release_build',env=builder.environment)
    state['bridge']=fact(binary(bridge));state['elf']=bridge_check(bridge)
    _,out,err=run('release-bridge-undefined',[builder.tools['nm'],'-u',bridge],profile='inspect',env=builder.environment)
    need(out==err==b'','actual linked bridge has no unresolved imports')
    objdump=pin(shutil.which('objdump',path=ENV['PATH']))
    _,out,err=run('release-objdump-version',[objdump,'--version'],env=builder.environment);need(out and not err,'actual objdump identity')
    _,symbols,err=run('release-bridge-symbols',[builder.tools['nm'],'-S','--defined-only',bridge],profile='inspect',env=builder.environment)
    need(not err,'complete actual linked bridge symbols')
    for name in ('li2_decoder_link_none','li2_link_plan_page','li2_link_plan_validate')+(('li2_preedge_plan_page','li2_preedge_plan_validate','li2_rseq_check_preedge_cold','li2_lifecycle_preedge_begin','li2_lifecycle_preedge_release')if preedge else()):
        found=[line.split()for line in symbols.splitlines()if line.split()[-1:]==[name.encode()]]
        need(len(found)==1 and len(found[0])==4 and found[0][2]in(b't',b'T')and int(found[0][1],16)>0,
             'whole retained linked proof provider in actual bridge')
    if reuse or preedge_capture:need(not any(line.split()[-1:]==[b'uho_nested_raw']for line in symbols.splitlines()),'reuse bridge has no fictitious nested-control shim')
    _,assembly,err=run('release-bridge-memset',[objdump,'-d','-w','-M','att','--disassemble=memset',bridge],profile='inspect',env=builder.environment)
    need(not err,'actual reset disassembly');state['reset']=hidden_memset(bridge,body_check(bridge,symbols,assembly,'fast',symbol_name='memset'))
    fast_bytes(builder,output,pin,binary,aliases,run,state)
    need(digest(fact(archive))==digest(binding['archive'])and fact(binding['path'])==binding['header']and
         fact(binding['manifest_path'])==binding['manifest']and all(fact(SELECTED/x['path'])=={k:x[k]for k in('bytes','sha256')}
         for x in binding['sources']),'all archive/policy/header sources unchanged through compiler and actual byte oracle')
    if capture:need(fact(capture_image)==config['image']and fact(config['path'])==config['header'],'fresh capture image/header unchanged through build')
    state['status']='passed';return bridge
