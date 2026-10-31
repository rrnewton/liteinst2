#!/usr/bin/env python3
"""Distinct generation-certificate build binding; no qualification authority."""
import json,shutil,struct
from pathlib import Path
from linked_epoch_build import fixed_domain_source
from maps_view import (need,fact,SELECTED,UNITS,MACROS,recipe,expand,headers,bridge_check,
    ENV,hidden_memset,body_check)

FIXED_DOMAIN = {
    'decoder/src/region.rs': (51594, '2c3b9712afb01e82ac797000a397f790565a412f6a6590cab8672dd0b3334e3a'),
    'decoder/src/write_footprint.rs': (10124, '754fbc625a52f27dfe20ce3353f761586a4eb1640c64fe846634c8d14501dfe7'),
    'decoder/src/tf.rs': (45018, 'e09a1c170f50c59f8faa34ecdc69ddfe9e651158f0f00a668ed7ef2c82059e38'),
    'region_decode.h': (7150, 'd9ccb59abd39bff378ecb30460e6d5c45142c2f77636b2c25068db9446a6e529'),
}
POLICY_INPUTS = tuple(FIXED_DOMAIN) + (
    'region_plan.c','region_plan.h','region_source.h','region_source.inc',
    'rseq_guard.c','rseq_guard.h','rseq_region.inc','rseq_region_live.h','rseq_region_live.inc',
    'region_reuse_certificate.h','selected_scalar_region.inc','selected_scalar_reuse.inc',
    'selected_scalar_reuse_certificate.inc',)
CERTIFICATE_HEADERS = ('region_reuse_certificate.h','selected_scalar_reuse_certificate.inc',
                       'rseq_region_live.h','rseq_region_live.inc')


def binding_config(builder,archive,output,pin,binary):
    """Pin actual policy/archive and publish the complete header before compiler-M."""
    identities={}
    for name in POLICY_INPUTS:
        path=pin(SELECTED/name);value=fact(path)
        if name in FIXED_DOMAIN:
            size,sha=fixed_domain_source(name,path)
            need(value==dict(bytes=size,sha256=sha),'exact reviewed47-form and old NONE policy '+name)
        if name.endswith('.rs'):
            key='tools/page-entry/selected/'+name
            need(builder.record['dep_info'].get(key)==value,'actual retained archive compiled this exact policy source')
        identities[name]=value
    need(all(builder.record['archive_text_exports'].get(name)==1 for name in
         ('li2_decoder_region_describe','li2_decoder_tf_classify','li2_decoder_write_footprint')),
         'actual archive exports all exact cold proof providers')
    archive_fact=fact(pin(archive))
    policy=dict(version=1,scope='reviewed47-forms plus generation-certificate authority',inputs=identities)
    encoded=json.dumps(policy,sort_keys=True,separators=(',',':'),allow_nan=False).encode()+b'\n'
    policy_path=output/'scalar_reuse_certificate_policy.json'
    with policy_path.open('xb')as stream:stream.write(encoded)
    policy_path=pin(binary(policy_path));policy_fact=fact(policy_path)
    def literal(sha):
        value=bytes.fromhex(sha);need(len(value)==32,'complete SHA256 binding')
        return '{'+','.join('0x%02x'%b for b in value)+'}'
    header=output/'scalar_reuse_certificate_config.h'
    text=('#define LI2_REUSE_CERTIFICATE_BINDING_VERSION 1\n'
          '#define LI2_REUSE_CERTIFICATE_ARCHIVE_SHA256 '+literal(archive_fact['sha256'])+'\n'
          '#define LI2_REUSE_CERTIFICATE_POLICY_SHA256 '+literal(policy_fact['sha256'])+'\n')
    with header.open('x')as stream:stream.write(text)
    header=pin(binary(header))
    return dict(version=1,archive=archive_fact,policy=policy_fact,policy_path=str(policy_path),
                policy_inputs=identities,header=fact(header),path=str(header))


def capture_config(path,output,pin,binary):
    """Derive the only capture macro from a retained ET_EXEC symbol and bytes."""
    path=pin(binary(path));data=path.read_bytes()
    def take(at,n):
        need(type(at)is int and type(n)is int and 0<=at<=len(data)and 0<=n<=len(data)-at,'bounded actual capture ELF range')
        return data[at:at+n]
    h=struct.unpack('<16sHHIQQQIHHHHHH',take(0,64))
    need(h[0][:7]==b'\x7fELF\x02\x01\x01'and h[1:4]==(2,62,1)and h[8:10]==(64,56)and
         0<h[10]<=32 and h[11]==64 and 0<h[12]<=256,'one actual bounded x86-64 ET_EXEC capture image')
    ph=[struct.unpack('<IIQQQQQQ',take(h[5]+i*56,56))for i in range(h[10])]
    sections=[struct.unpack('<IIQQQQIIQQ',take(h[6]+i*64,64))for i in range(h[12])]
    tables=[s for s in sections if s[1]==2]
    need(len(tables)==1 and tables[0][9]==24 and tables[0][5]%24==0,'one complete actual capture symtab')
    t=tables[0];need(t[6]<len(sections),'capture symbol string index');strings=sections[t[6]];names=take(strings[4],strings[5]);heads=[]
    for at in range(t[4],t[4]+t[5],24):
        n,info,other,section,pc,size=struct.unpack('<IBBHQQ',take(at,24))
        need(n<len(names)and b'\0'in names[n:],'complete capture symbol name')
        if names[n:names.index(b'\0',n)]==b'region_app_head':
            need(section!=0,'actual defined capture head');heads.append(pc)
    need(len(heads)==1 and heads[0]>=4096 and heads[0]<(1<<47)and heads[0]%4096<=4096-15,'one actual application head with complete fetch15 in its page');pc=heads[0];page=pc&~4095
    owners=[s for s in ph if s[0]==1 and s[1]==5 and s[5]<=s[6]and s[3]<=page and page-s[3]+4096<=s[5]]
    need(len(owners)==1,'complete actual capture source page in one RX load');segment=owners[0]
    body=take(segment[2]+page-segment[3],4096)
    need(len(body)==4096 and pc-page<=4096-15,'full source page and original fetch15 in actual capture ELF')
    header=output/'scalar_region_capture_config.h';text='#define LI2_REGION_APP_HEAD_RVA 0x%xULL\n'%pc
    with header.open('x')as stream:stream.write(text)
    header=pin(binary(header))
    return dict(image=fact(path),head_rva=pc,header=fact(header),path=str(header))


def build_bridge(builder,products,private,pin,binary,aliases,run,r,extra=(),capture_image=None):
    need(builder.extra_decoder_sources==('region.rs',)and builder.decoder_features==('scalar-region',)and
         builder.record.get('decoder_features')==['scalar-region']and
         builder.environment.get('LI2_DECODER_FEATURES')=='scalar-region',
         'explicit scalar-region Build/archive feature and exact region source')
    archive=pin(products['archive']);retained=builder.record['artifacts']['decoder.a']
    need(builder.record['status']=='passed'and builder.record['command_completed']is True and
         archive==builder.paths['archive']==builder.retained/'decoder.a'and str(archive)==retained['path']and
         fact(archive)=={k:retained[k]for k in('bytes','sha256')},'fresh Build.prepare owns this exact archive')
    capture_profile=('SCALAR_REGION_CAPTURE','SCALAR_REGION_REUSE_CERTIFICATE_CAPTURE')
    need(extra in ((),('MAPS_DIFFERENTIAL',),capture_profile),
         'distinct normal, differential or complete certificate capture profile')
    need((capture_image is not None)==(extra==capture_profile),
         'actual capture image required only for exact certificate capture profile')
    output=private/'release';output.mkdir();config=binding_config(builder,archive,output,pin,binary)
    capture=capture_config(capture_image,output,pin,binary)if capture_image is not None else None
    bridge_recipe=pin(SELECTED/'build-scalar-region-reuse-certificate.sh');rows=recipe(bridge_recipe,'"$cc_bin"')
    need(len(rows)==1,'one explicit bounded unrolled release link recipe')
    argv=expand(rows[0],{'$cc_bin':builder.tools['cc'],'$selected_dir':SELECTED,
        '$parent_dir':SELECTED.parent,'$archive':archive,'$output':output})
    argv[1:1]=['-DLI2_'+x+'=1'for x in extra];units=[str(SELECTED.parent/x)for x in UNITS]+[str(SELECTED/'unrolled_hash_plan.c'),str(SELECTED/'region_plan.c')]
    need(argv[-2:]==['-o',str(output/'bridge-scalar-region-reuse-certificate.so')]and
         [x for x in argv if x.endswith(('.c','.S'))]==units and
         [x for x in argv if x.startswith('-DLI2_')]==['-DLI2_'+x+'=1'for x in extra+('SCALAR_REGION','SCALAR_REGION_REUSE','SCALAR_REGION_REUSE_CERTIFICATE','INITIAL_CODE_PROTECTION','UNROLLED_HASH','MAPS_MAINTAINED')+MACROS]and
         all(x in argv for x in('-O2','-g','-nostdlib','-shared','-fPIC','-fvisibility=hidden','-mgeneral-regs-only','-fno-builtin','-Werror')),
         'exact20-TU scalar-region release recipe and explicitly selected diagnostic macros')
    state=r['release_build']=dict(status='failed',recipe=fact(bridge_recipe),archive=fact(archive),argv=argv,certificate_binding=config)
    if capture is not None:state['capture_config']=capture
    headers('release-bridge-headers',argv,units,archive,builder,pin,aliases,run,state)
    need(all(str((SELECTED/name).resolve())in state['headers']for name in
         ('maps_phase.inc','maps_view.inc','initial_code_protection.h','selected_unrolled_hash.inc','unrolled_hash.h',
          'unrolled_source.inc','unrolled_source.h','rseq_unrolled.inc','region_decode.h',
          'region_plan.h','region_source.h','region_source.inc','rseq_region.inc','selected_scalar_region.inc','selected_scalar_reuse.inc')),
         'compiler observes all maintained-view and actual unrolled owner seams')
    need(all(str((SELECTED/name).resolve())in state['headers']for name in CERTIFICATE_HEADERS)and
         str((SELECTED/'selected_scalar_certificate.inc').resolve())not in state['headers'],
         'complete new certificate/live guard and no old certificate lifetime')
    need(all((str((SELECTED/name).resolve())in state['headers'])==(capture is not None)for name in
         ('scalar_region_observe.inc','scalar_reuse_certificate_observe.h','scalar_reuse_certificate_observe.inc')),
         'all three capture seams present exactly in distinct certificate capture profile')
    capture_header=str((output/'scalar_region_capture_config.h').resolve())
    need((capture_header in state['headers'])==(capture is not None),
         'ELF-derived capture header present exactly in capture profile')
    if capture is not None:need(state['headers'].get(capture['path'])==capture['header'],
         'actual compiler observes exact ELF-derived capture header')
    need(state['headers'].get(config['path'])==config['header'],
         'actual compiler observes exact archive/policy binding header')
    need(all(name.endswith('.rs')or state['headers'].get(str((SELECTED/name).resolve()))==value
         for name,value in config['policy_inputs'].items()),
         'every bound C policy source is in actual compiler dependency closure')
    bridge=Path(argv[-1]);run('release-bridge-link',argv,profile='release_build',env=builder.environment)
    state['bridge']=fact(binary(bridge));state['elf']=bridge_check(bridge)
    _,out,err=run('release-bridge-undefined',[builder.tools['nm'],'-u',bridge],profile='inspect',env=builder.environment)
    need(out==err==b'','actual effect bridge has no unresolved imports')
    objdump=pin(shutil.which('objdump',path=ENV['PATH']))
    _,out,err=run('release-objdump-version',[objdump,'--version'],env=builder.environment);need(out and not err,'actual objdump identity')
    _,symbols,err=run('release-bridge-symbols',[builder.tools['nm'],'-S','--defined-only',bridge],profile='inspect',env=builder.environment)
    need(not err,'actual reset symbol inspection')
    _,assembly,err=run('release-bridge-memset',[objdump,'-d','-w','-M','att','--disassemble=memset',bridge],profile='inspect',env=builder.environment)
    need(not err,'actual reset disassembly');state['reset']=hidden_memset(bridge,body_check(bridge,symbols,assembly,'fast',symbol_name='memset'))
    need(fact(archive)==config['archive']and fact(config['path'])==config['header']and
         fact(config['policy_path'])==config['policy']and
         all(fact(SELECTED/name)==value for name,value in config['policy_inputs'].items()),
         'complete policy/archive/header identity remains exact after actual compiler observations')
    if capture is not None:need(fact(capture_image)==capture['image']and fact(capture['path'])==capture['header'],
         'actual capture image and generated header remain exact after compiler observations')
    state['status']='passed';return bridge
