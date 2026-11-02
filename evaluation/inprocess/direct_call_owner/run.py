#!/usr/bin/env python3
"""Three direct-E8 owner subjects after complete retained component/native and owner gates."""
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
ROOT = next(p for p in HERE.parents if (p/'evaluation/inprocess/page_selected_process.py').is_file())
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
                        'retained_storage','uc_bytes','uc','si'} and layout['record'] == 'prto_wire',
         'whole distinct actual history layout result')
    need(set(layout['types']) == set(layout['edges']) == set(wire.GROUPS) and len(wire.GROUPS) == 128,
         'all and only 128 independently declared reachable types')
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
    need(count == 1388 and modeled['prto_wire']['bytes'] == wire.RAW_BYTES == 1261760,
         'all1388 fields and whole raw extent, without any invented record')
    need(layout['member_witnesses'] == {'li2_step_frame.fp':dict(
         symbol='prto_step_frame_fp_alignment',bytes=8,alignment=64)},'actual aligned FP member witness')
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
    return dict(types=128,fields=1388,raw_bytes=1261760,record_bytes_observed=0,
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
        LI2_PERSISTENT_RET_OWNER_APP_MODE=str(mode)))and
        prep['late_sonames']==[]and prep['environment_source']==str(ns/'launch.json'),'actual exact gated capture-control exec environment')
    record=private/row['captures']['record']['file'];st=record.stat()
    need(prep['observer']==dict(fd=3,device=st.st_dev,inode=st.st_ino)and st.st_nlink==1 and st.st_mode&0o7777==0o600,'same exclusive owner record descriptor')
    return manifest





def main():
    sys.path.insert(0,str(ROOT/'evaluation/inprocess'))
    from page_selected_maps_sources import historical, bind as bind_maps_sources
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--expect-revision',required=True)
    ap.add_argument('--output',type=Path,required=True)
    ap.add_argument('--cpu',type=int,required=True)
    for name in ('archive','call-owner','ret','ret15','runtime-compile','ret-owner','return-heads','direct-native'):
        ap.add_argument('--'+name+'-receipt',type=Path,required=True)
        ap.add_argument('--'+name+'-receipt-sha256',required=True)
    args = ap.parse_args(); manifest = load(HERE/'SOURCE.json')
    need(not sys.flags.optimize and sys.version_info >= (3,11) and
         args.cpu == 3 and sorted(os.sched_getaffinity(0)) == [args.cpu],
         'assertions, Python3.11+ and original archive CPU independently reserved')
    need(re.fullmatch('[0-9a-f]{40}',args.expect_revision) is not None, 'explicit full installed revision')
    for name,value in manifest['artifacts'].items():
        need(historical(HERE/name,value,fact(HERE/name)) == value,'frozen collector artifact: '+name)
    for name,value in manifest['inputs'].items():
        need(historical((ROOT/name).resolve(strict=True),value,fact((ROOT/name).resolve(strict=True))) == value,'frozen source input: '+name)
    private = args.output.resolve(); cpu = args.cpu
    need(private.is_relative_to((ROOT/'target/evaluation/inprocess').resolve(strict=True)) and
         not private.exists(),'fresh contained private result')
    private.mkdir(); facade = ROOT
    context = {}; context_links = {}
    for directory,names in manifest['source_roster'].items():
        for name,expected in names.items():
            relative=str(Path(directory)/name);path=ROOT/relative
            need(not Path(relative).is_absolute() and '..' not in Path(relative).parts and
                 relative not in context,'unique contained installed source roster')
            value=fact(path)
            need(historical(path,expected,value)==expected,'whole source-bound installed roster member: '+relative)
            context[relative]=dict(origin=relative,copy=False,**value)
    # Installed source modules retain their original natural ROOT/SELECTED.
    # Every original context member is pinned in place; no facade copies or
    # module-global substitution creates another source view.
    sys.path[:0] = [str(ROOT/'evaluation/inprocess'),str(HERE),str(ROOT/'tools/page-entry')]
    from call_owner import custody
    from checks import source, admission
    from run import hardware
    global MASK, H, namespace
    import namespace
    from page_selected import ENV, save, interpreter
    from page_selected_process import invoke
    from page_selected_generic_build import package_check
    os.chdir(ROOT); receipt = private/'receipt.json'
    pins,aliases,artifacts,presence = {},{},{},{}
    r = dict(schema=1,profile='public-direct-call-owner-v1',status='failed',
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
               for mode in (1,) for lane in ('native','maintained','differential')])

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
        bind_maps_sources(pin)
        for name in ('SOURCE.json',*manifest['artifacts']):pin(HERE/name)
        for name in manifest['inputs']:pin(ROOT/name)
        for rel,item in context.items():
            pin(facade/rel)
            if item['copy']:binary(facade/rel)
        pin(sys.executable);imports();closure()
        # Resolve the installed selector before downstream imports. Its
        # natural selected-source root is the authenticated facade.
        import page_selected_repeat_lease_ls as selector
        from ret_owner import prerequisites
        from call_return_heads import original_owner
        from direct_call_native import return_heads
        direct_native=module('direct_e8_retained_native',HERE/'prerequisite.py')
        import maps_view
        from page_selected_effect_ls import program_invoke
        from persistent_dynamic import MASK, H, seed_prerequisite, named, image_inventory, raw_emission
        from direct_frontier_loop_helpers import prepare_inputs
        from scalar_span_trace_build import fast_bytes, fast_bytes_completed
        need(maps_view.SELECTED == selector.SELECTED == facade/'tools/page-entry/selected' and
             selector.ROOT == facade and Path(selector.__file__) == facade/'evaluation/inprocess/page_selected_repeat_lease_ls.py',
             'natural exact installed SELECTED and checkout process/build helpers')
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
        r['finite_prerequisites']=prerequisites.check_all(args,r,pin,archive,build)
        r['original_owner_prerequisite']=original_owner.check(args,r,pin,archive,build)
        r['ret_owner_prerequisite']=r['original_owner_prerequisite']['installed_gate']
        r['return_heads_prerequisite']=return_heads.check(args.return_heads_receipt,
            args.return_heads_receipt_sha256,r,pin,pin,archive,build)
        r['direct_native_prerequisite']=direct_native.check(args.direct_native_receipt,
            args.direct_native_receipt_sha256,r,pin,archive,build,manifest)
        fixture=facade/'tools/page-entry/selected/tests/persistent_direct_call_owner_app'
        owner=facade/'tools/page-entry/selected/tests/persistent_direct_call_owner_owner'
        app_helper=module('ret_owner_app_build',facade/'evaluation/inprocess/direct_call_owner_app_build.py')
        need(app_helper.FIXTURE==fixture,'natural exact app helper geometry')
        reader=module('ret_owner_app',fixture/'read.py')
        owner_reader=module('ret_owner_semantics',owner/'read.py')
        reports=module('ret_owner_reports',facade/'evaluation/inprocess/persistent_ret_owner_reports.py')
        need(reader.APP_CONTROL_COUNTS=={1:60} and
             reader.FRAME==66784 and reader.TRACES==(9,9,9) and
             owner_reader.OWNER_CONTROL_COUNTS=={1:252} and
             owner_reader.PAIR_CONTROL_COUNTS=={1:56} and
             reports.CONTROL_COUNTS=={(0,0):73,(1,0):73,(2,0):73} and reports.REPEAT_TLS_CONTROLS==33 and
             reports.SUBENTRY_CONTROL_COUNT==19 and reports.probe.CONTROL_COUNT==22,
             'literal complete app/owner/pair/terminal/TLS/probe/subentry populations')
        build_helper=module('ret_owner_full_build',facade/'evaluation/inprocess/direct_call_owner_build.py')
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
            bridge=build_helper.build_bridge(builder,directory,pin,binary,aliases,lane_run,state,image,app,
                facade/'tools/page-entry/selected',manifest,differential,fast_bytes,maps_view)
            need(state['release_build']['status']=='passed' and
                 state['release_build']['ret_owner_capture'] is True and
                 state['release_build']['persistent_binding']['call_return_heads'] is True and
                 state['release_build']['persistent_binding']['direct_call'] is True and
                 state['release_build']['persistent_binding']['plan_version']==9,
                 'full build completed including mandatory byte oracle')
            fast_bytes_completed(state['release_build'],r['commands'],binary)
            raw_emission(builder,bridge,pin,lane_run,state)
            gdb=pin(shutil.which('gdb',path=ENV['PATH']))
            _,out,err=lane_run('whole-ret-owner-layout',[gdb,'-nx','-nh','-batch',
                '-iex','set auto-load off','-iex','set debuginfod enabled off',
                '-iex','set index-cache enabled off','-iex','maintenance set worker-threads 1',
                '-ex','file '+str(bridge),'-ex','source '+str(facade/'tools/page-entry/selected/tests/persistent_ret_owner_owner/layout.py')],
                env=dict(environment,MALLOC_ARENA_MAX='1'))
            need(out and not err,'complete file-only actual DWARF layout')
            layout=json.loads(out,object_pairs_hook=unique);state['schema']=schema_check(layout,owner_reader.wire)
            need(layout['types']['pe_payload']['bytes']==362688 and
                 ((layout['types']['pe_payload']['bytes']+4095)&~4095)==89*4096 and
                 layout['types']['li2_pg_guard']['bytes']==6488 and
                 layout['types']['li2_cd_plan']['fields']['image']['bytes']==512 and
                 layout['registrations']['pe']['bytes']==3998208 and
                 layout['registrations']['pcw']['bytes']==3112 and
                 layout['registrations']['prto_wire']['bytes']==1261760 and
                 layout['registrations']['prr']['bytes']==72256 and
                 layout['types']['li2_rd_plan']['fields']['image']['bytes']==512 and
                 layout['symbols']['prto_wire']==state['release_build']['capture_symbol']['address'],
                 'exact owner/window/payload storage and unchanged89-page proof,6488 guard,512 image caps')
            from page_selected import elf
            _,_,segments=elf(bridge)
            need(all(sum(p[0]==1 and p[1]==6 and p[3]<=x['address']<x['address']+x['bytes']<=p[3]+p[6]
                 for p in segments)==1 for x in layout['registrations'].values()),
                 'every complete registered owner/observer object belongs to one bridge RW/NX LOAD')
            path=directory/'layout.json';save(path,layout);binary(path)
            inputs=prepare_inputs(image,bridge,builder,directory,pin,binary,lane_run,state,r['application_build'])
            prepared[lane]=(bridge,layout,*inputs)
        native={};launcher=pin(facade/'tools/page-entry/selected/tests/persistent_ret_owner_app/launch.py');imports();closure()
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
                    named(case['application_controls'],60,hashlib.sha256(out).hexdigest())
                    need(len(parsed['observations'])==1 and len(parsed['observations'][0]['frames'])==10,
                         'all ten native full signal frames')
                    native[mode]=parsed
                else:
                    capture=row['captures']['record'];record_path=binary(private/capture['file'])
                    need(capture['bytes']==1261760+64<4<<20 and digest(fact(record_path))==digest(capture),
                         'whole literal RET owner body/footer under original strict4MiB cap')
                    record=record_path.read_bytes();inventory=image_inventory(image,interp,carrier,objects,launch)
                    inventory.update(bridge=bridge.read_bytes(),persistent_binding=state['release_build']['persistent_binding'],
                                     headers=state['release_build']['headers'])
                    args_owner=(record,layout,inventory,parsed,row['pid'],cpu,row['exit'])
                    actual=owner_reader.read(*args_owner)
                    case['owner_controls']=owner_reader.controls(*args_owner);controls(case['owner_controls'],252)
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
                    case['pair']=owner_reader.pair(native[mode],parsed,actual)
                    expected=dict(observed_ret_owner=1,mode=mode,return_head_observation=True,
                        plan_version=9,directory_heads=8,return_head_index=5,
                        direct_call_observation=True,callee_head_index=4,direct_target_tag=16,
                        invocations=1,native_instructions=9,native_full_frames=10,
                        generated_completed=1,cold_publications=1,domain_members=1,closed_pages=17,
                        modeled_completed_in_generated=7,generated_ret_load=1,cached_call=1,
                        cached_ret_hit=1,loaded_miss=0,private_C3=0,
                        consumed_word_poisoned=0,original_return_pc=app['page']+0x60f,
                        stack_bytes=520,measured_interior_signals=0,lifetime_mode=2,
                        registration_epoch=0,registration_calls=0,word_observed=0,
                        qualification_credit=False,performance_credit=False)
                    need(case['pair']==expected,'exact full-state admitted original return head hit; original miss/poison coverage stays in prerequisite')
                    case['pair_controls']=owner_reader.pair_controls(native[mode],parsed,actual)
                    controls(case['pair_controls'],56)
                    case['owner_summary']={k:actual[k] for k in ('mode','cold_publications','completed',
                        'domain_members','closed_pages','anchor_released','interior_signals','lifetime_mode',
                        'registration_epoch','registration_calls','word_observed','cached_ret_hits','loaded_misses','consumed_word_poisoned')}
                case['status']='passed'
            except Exception as exc:
                case['error']=repr(exc)
                if r['error'] is None:r['error']=repr(exc)
                last=r['commands'][-1]
                if not(last['name']==case['label'] and last.get('reaped') is True and
                       not last.get('cleanup_errors') and all(d['closed'] for d in last.get('descriptors',[]))):raise
        need(all(x['status']=='passed' for x in r['cases']) and r['error'] is None,
             'all three additive original-bound subjects and every exact comparator must pass')
        imports();closure()
        need([c['name'] for c in r['commands']]==manifest['commands'],
             'all79 exact fresh commands, no retries or omitted build/subject gates')
        r['result']=dict(native_subjects=1,gated_subjects=2,full_builds=2,byte_oracles=2,seed_prerequisites=1,
            native_frames=10,application_controls=60,owner_controls=504,pair_controls=112,
            terminal_controls=146,tls_controls=66,probe_controls=44,subentry_controls=38,effect_controls=24,
            finite_prerequisites=4,original_owner_subjects=9,return_heads_owner_subjects=3,
            fresh_components=0,retained_component_cohorts=15,retained_native_pairs=24,owner_pairs=2,
            plan_version=9,return_head_index=5,callee_head_index=4,direct_target_tag=16,raw_bytes=1261760,record_bytes=1261824,record_limit=4194304,
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
        # The prerequisite helper pins every retained input, artifact and alias
        # into the same whole-run closure as this collector's fresh artifacts.
        for label,action in (('imports',imports),('input closure',closure),
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
        r.update(inputs=pins,aliases=aliases,artifacts=artifacts,loader_presence=presence);save(receipt,r)
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
            return_heads_prerequisite=r.get('return_heads_prerequisite'),
            direct_native_prerequisite=r.get('direct_native_prerequisite'),
            original_owner_prerequisite=r.get('original_owner_prerequisite'),
            source_unchanged=r['source_unchanged'],inputs_unchanged=r['inputs_unchanged'],
            cleanup_complete=r['cleanup_complete'],pending=r['pending'],qualification_credit=False,
            performance_credit=False,receipt=digest(fact(receipt)),
            source_input_count=len(pins),artifact_count=len(artifacts),archive_builds=0,
            reproducer=str(Path(__file__).resolve().relative_to(ROOT)),
            execution_argv_sha256=hashlib.sha256(json.dumps(sys.argv,separators=(',',':')).encode()).hexdigest())
        payload=json.dumps(summary,sort_keys=True,indent=2)+'\n'
        need(str(ROOT) not in payload and str(private) not in payload and '/home/' not in payload,
             'public summary excludes raw paths and host paths')
        (private/'summary.json').write_text(payload)
    print(json.dumps(dict(status=r['status'],receipt=str(receipt),result=r['result']),sort_keys=True))
    return 0 if r['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
