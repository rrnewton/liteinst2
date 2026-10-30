"""Explicit certificate owner support using the existing bounded process owner.

The eight transaction components are separately counted supplied-boundary
experiments. They cannot replace any of the43 actual native/owner cases.
"""
import json,re
from pathlib import Path
from page_selected import need,fact,elf,interpreter
from page_selected_register_time_build import recipe,expand,headers
from maps_view import UNITS,MACROS

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]
SELECTED=ROOT/'tools/page-entry/selected'
OWNER=SELECTED/'tests/scalar_region_reuse_certificate_owner'
COMPONENT=SELECTED/'tests/reuse_certificate'
COMPONENT_BOUNDS=[3,256<<20,1<<20,10]
COMPONENT_EXITS=(0,0,0,125,125,125,125,125)


def digest(value):
    import hashlib
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()).hexdigest()


def component(builder,products,private,pin,binary,aliases,run,r,load):
    """Eight real production-TU transactions, before actual owner qualification."""
    build=load('certificate_build_binding',HERE/'scalar_region_reuse_certificate_build.py',pin)
    reader=load('certificate_component_reader',COMPONENT/'check.py',pin)
    need(type(reader.CONTROL_COUNT)is int and reader.CONTROL_COUNT==32,
         'source-fixed32 transaction-record refusals per actual case')
    archive=pin(products['archive']);retained=builder.record['artifacts']['decoder.a']
    need(builder.extra_decoder_sources==('region.rs',)and builder.decoder_features==('scalar-region',)and
         builder.record['status']=='passed'and builder.record['command_completed']is True and
         archive==builder.paths['archive']==builder.retained/'decoder.a'and str(archive)==retained['path']and
         fact(archive)=={k:retained[k]for k in('bytes','sha256')},
         'actual same retained production scalar archive for transaction component')
    output=private/'certificate-component';output.mkdir()
    binding=build.binding_config(builder,archive,output,pin,binary)
    script=pin(COMPONENT/'build.sh');unit=pin(COMPONENT/'oracle.c')
    rows=recipe(script,'"$cc_bin"');need(len(rows)==1,'one exact certificate transaction recipe')
    argv=expand(rows[0],{'$cc_bin':builder.tools['cc'],'$selected_dir':SELECTED,
        '$parent_dir':SELECTED.parent,'$fixture_dir':COMPONENT,'$archive':archive,
        '$output':output,'$config_dir':output})
    units=[str(unit)if name=='selected/runtime_loader.c'else str(SELECTED.parent/name)for name in UNITS]
    units += [str(SELECTED/'unrolled_hash_plan.c'),str(SELECTED/'region_plan.c')]
    macros=('SCALAR_REGION','SCALAR_REGION_REUSE','SCALAR_REGION_REUSE_CERTIFICATE',
            'INITIAL_CODE_PROTECTION','UNROLLED_HASH','MAPS_MAINTAINED')+MACROS
    executable=output/'reuse-certificate'
    need(argv[-2:]==['-o',str(executable)]and
         [x for x in argv if x.endswith(('.c','.S'))]==units and
         [x for x in argv if x.startswith('-D')]==['-D_start=li2_certificate_component_unused_start']+
             ['-DLI2_'+name+'=1'for name in macros]and
         all(x in argv for x in('-std=gnu11','-O2','-g','-fPIC','-fvisibility=hidden','-fno-stack-protector',
             '-fno-builtin','-fno-tree-loop-distribute-patterns','-fno-tree-vectorize','-mgeneral-regs-only',
             '-fno-asynchronous-unwind-tables','-ffunction-sections','-fdata-sections','-Wall','-Wextra','-Werror')),
         'exact production transaction TU recipe; only unused loader start symbol renamed')
    state=r['certificate_component']=dict(status='failed',planned=8,bounds=COMPONENT_BOUNDS,
        build=dict(status='failed',recipe=fact(script),argv=argv,archive=fact(archive),binding=binding),
        cases=[dict(mode=mode,expected_exit=status,status='unexecuted',launched=False)
               for mode,status in enumerate(COMPONENT_EXITS)],
        supplied_boundary=True,supplied_completion_modes=[1,2],native_owner_credit=False,performance_credit=False)
    built=state['build']
    headers('certificate-component-headers',argv,units,archive,builder,pin,aliases,run,built)
    need(all(str((SELECTED/name).resolve())in built['headers']for name in build.CERTIFICATE_HEADERS)and
         built['headers'].get(binding['path'])==binding['header']and
         all(name.endswith('.rs')or built['headers'].get(str((SELECTED/name).resolve()))==value
             for name,value in binding['policy_inputs'].items()),
         'all actual production policy and generated identity headers observed before compile')
    need(str((SELECTED/'runtime_loader.c').resolve())in built['headers']and
         str(unit)in built['headers']and
         str((SELECTED/'scalar_region_observe.inc').resolve())not in built['headers'],
         'actual included runtime TU and no capture-profile substitution')
    run('certificate-component-link',argv,profile='release_build',env=builder.environment)
    executable=binary(executable);data,head,segments=elf(executable)
    need(executable.stat().st_mode&0o111 and head[1]in(2,3)and head[2:4]==(62,1)and
         all(p[2]+p[5]<=len(data)and p[5]<=p[6]and p[1]&3!=3 for p in segments if p[0]==1),
         'complete actual transaction ELF without a writable executable load')
    _,_,err=run('certificate-component-elf',[builder.tools['readelf'],'-h','-l','-d','-r','-W',executable],
                profile='inspect',env=builder.environment)
    need(not err,'complete actual transaction ELF metadata')
    _,out,err=run('certificate-component-symbols',[builder.tools['nm'],'-g','--defined-only',executable],
                  profile='inspect',env=builder.environment)
    rows=[line.split()for line in out.splitlines()]
    need(not err and all(sum(row[-2:]==[b'T',name]for row in rows)==1 for name in
         (b'li2_decoder_region_describe',b'li2_decoder_initialize',b'li2_decoder_stats'))and
         not any(row and row[-1].startswith(b'li2_region_test_')for row in rows),
         'actual production decoder APIs and no injected decoder test exports')
    loader=pin(interpreter(executable))
    _,out,err=run('certificate-component-libraries',[loader,'--list',executable],profile='inspect',env=builder.environment)
    need(not err,'actual transaction interpreter/library inspection');libraries={}
    for line in out.decode().splitlines():
        if re.fullmatch(r'\s*linux-vdso.so.1 \(0x[0-9a-f]+\)',line):continue
        match=re.fullmatch(r'\s*(?:\S+ => )?(/\S+) \(0x[0-9a-f]+\)',line)
        need(match is not None,'complete actual resolved transaction library')
        path=pin(match[1]);need(path.name not in libraries,'unique actual transaction library basename')
        libraries[path.name]=dict(path=str(path),**fact(path))
    need(any(value['path']==str(loader)for value in libraries.values()),'actual transaction interpreter in closure')
    need(fact(archive)==binding['archive']and fact(binding['path'])==binding['header']and
         fact(binding['policy_path'])==binding['policy']and
         all(fact(SELECTED/name)==value for name,value in binding['policy_inputs'].items()),
         'whole policy/archive/config closure after compilation')
    built.update(status='passed',artifact=fact(executable),runtime_libraries=libraries)
    for case in state['cases']:
        mode=case['mode'];label='certificate-component-mode-'+str(mode)
        start=len(r['commands']);case['status']='failed'
        try:
            try:row,out,err=run(label,[executable,str(mode)],profile='certificate_component',
                                expected=case['expected_exit'],env=builder.environment)
            finally:
                if len(r['commands'])>start and r['commands'][-1]['name']==label:
                    actual=r['commands'][-1]
                    case.update(launched=type(actual.get('pid'))is int,exit=actual.get('exit'),
                        whole_process_ns=actual.get('duration_ns'),timed_out=actual.get('timed_out'))
                    case['captures']={key:{k:value[k]for k in('bytes','sha256')}
                        for key,value in actual.get('captures',{}).items()}
            args=(out,err,row['exit'],mode,binding['archive']['sha256'],binding['policy']['sha256'])
            case['result']=reader.check(*args);case['reader_controls']=reader.controls(*args)
            need(digest(case['reader_controls'])==digest(dict(refusals=32,native_operations=0)),
                 'exact typed32 actual supplied transaction refusals')
            case['status']='qualified_transaction'if mode<3 else 'qualified_required_transaction_failure'
        except Exception as error:
            case['error_type']=type(error).__name__;case['error']=str(error)
            if r['error']is None:r['error']=type(error).__name__+': '+str(error)
            commands=r['commands'][start:]
            need(len(commands)==1 and commands[0].get('name')==label and
                 type(commands[0].get('exit'))is int and commands[0].get('reaped')is True and
                 not commands[0].get('error')and commands[0].get('cleanup_errors')==[]and
                 isinstance(commands[0].get('descriptors'),list)and
                 all(d.get('closed')is True for d in commands[0]['descriptors']),
                 'failed transaction process still requires exact identity and full cleanup')
    cases=state['cases']
    need(len(cases)==8 and [case['mode']for case in cases]==list(range(8))and
         [case['exit']for case in cases]==list(COMPONENT_EXITS)and
         [case['status']for case in cases]==['qualified_transaction']*3+
             ['qualified_required_transaction_failure']*5 and
         sum(case['reader_controls']['refusals']for case in cases)==256,
         'all eight actual transaction modes and256 supplied controls remain mandatory')
    state.update(status='passed_component_only',totals=dict(planned=8,launched=8,qualified=8,
        completed_transactions=3,required_failed_transactions=5,reader_refusals=256))


def component_summary(state):
    # All raw records/control names remain private under the existing complete
    # receipt and command digests. No descriptor history is published here.
    cases=[]if state is None else state['cases']
    return dict(planned=8,status='unexecuted'if state is None else state['status'],
        component_only=True,columns=['mode','exit','qualified','refusals'],
        cases=[[c['mode'],c.get('exit'),int(c['status']in
            ('qualified_transaction','qualified_required_transaction_failure')),
            c.get('reader_controls',{}).get('refusals',0)]for c in cases],
        totals=None if state is None else state.get('totals'))


CERTIFICATE_CONTROL_COUNTS={(0, 0): 34, (1, 0): 34, (2, 0): 34, (3, 0): 34, (4, 0): 34, (5, 0): 34, (6, 0): 34, (7, 0): 34, (8, 0): 34, (9, 0): 34, (10, 0): 34, (11, 0): 48, (12, 0): 48, (0, 1): 35, (0, 2): 34, (0, 3): 34, (0, 4): 34, (0, 5): 34, (0, 6): 20, (0, 7): 34, (0, 8): 28, (0, 9): 28, (0, 10): 28, (0, 11): 34, (0, 12): 28, (0, 13): 28, (0, 14): 28, (0, 15): 34, (0, 16): 34, (0, 17): 34}


def require_controls(owner_reader,r):
    need(r.get('certificate')is True and r['reuse']is True,'distinct explicit reuse certificate profile')
    need(type(owner_reader.CERTIFICATE_MAPPING_CONTROL_COUNT)is int and
         owner_reader.CERTIFICATE_MAPPING_CONTROL_COUNT==23,
         'exact23 certificate mapping-record refusals per actual case')
    actual=owner_reader.CERTIFICATE_CONTROL_COUNTS
    need(type(actual)is dict and all(type(k)is tuple and len(k)==2 and
         all(type(v)is int for v in k)and type(n)is int for k,n in actual.items())and
         actual==CERTIFICATE_CONTROL_COUNTS and sum(actual.values())==999,
         'exact source-fixed999 additive certificate controls over the original30 gated records')
    r['required_certificate_reader_controls']={str(mode)+':'+str(control):count
        for (mode,control),count in sorted(CERTIFICATE_CONTROL_COUNTS.items())}


def case_controls(case,mode,control,record,stderr):
    import hashlib
    owner=case['owner_reader_controls'];terminal=case['terminal_controls']
    names=owner['certificate_refusals'];rows=terminal['certificate_refusals']
    need(type(names)is list and all(type(n)is str for n in names)and
         len(names)==len(set(names))==CERTIFICATE_CONTROL_COUNTS[mode,control]and
         type(owner['native_operations'])is int and owner['native_operations']==0 and
         owner['original_sha256']==hashlib.sha256(record).hexdigest(),
         'every fixed additional certificate-record mutation is actually refused')
    need(type(rows)is list and all(type(n)is str for n in rows)and len(rows)==len(set(rows))==15 and
         type(terminal['native_operations'])is int and terminal['native_operations']==0 and
         terminal['original_stderr_sha256']==hashlib.sha256(stderr).hexdigest(),
         'all15 additional certificate terminal mutations are actually refused')


def complete(r):
    state=r['certificate_component'];rows=r['cases'];mapping=r['mapping_controls']
    need(state['status']=='passed_component_only'and digest(state['totals'])==digest(dict(
         planned=8,launched=8,qualified=8,completed_transactions=3,required_failed_transactions=5,
         reader_refusals=256))and len(state['cases'])==8,
         'all eight actual transaction components and256 refusals remain separately mandatory')
    need(len(rows)==43 and sum(c['lane']=='gated'for c in rows)==30 and
         all(c['status'].startswith('qualified_')for c in rows)and not r['error']and
         sum(len(c.get('owner_reader_controls',{}).get('certificate_refusals',[]))for c in rows)==999 and
         sum(len(c.get('terminal_controls',{}).get('certificate_refusals',[]))for c in rows)==450,
         'all43 old owner cases plus every999 record and450 terminal certificate refusal')
    need(mapping['status']=='passed'and len(mapping['cases'])==8 and
         sum(len(c.get('certificate_controls',{}).get('certificate_refusals',[]))for c in mapping['cases'])==184 and
         all(c['reader_refusals']==19 and len(c['certificate_controls']['certificate_refusals'])==23
             for c in mapping['cases'])and sum(c['profile']=='boundary'for c in r['commands'])==38,
         'all eight v3 mapping refusals retain old152 plus new184 controls and all38 metadata commands')
