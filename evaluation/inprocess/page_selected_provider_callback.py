"""Focused actual callback component, sharing a caller's closed Build/command custody."""
import hashlib
import importlib.util
import json
from pathlib import Path
import os
import re
import shlex
from page_selected import fact,need,elf
from page_selected_component_build import symbols
from page_selected_register_time_build import recipe,expand
from page_selected_provider_libraries import libraries as provider_libraries

BOUNDS={'provider_component':[3,256<<20,1<<20,10],
        'provider_component_build':[30,512<<20,16<<20,60]}
NORMAL_BYTES=269224
NESTED_BYTES=153760


def component(builder,products,root,private,pin,binary,aliases,run,receipt):
    presence={}
    def configuration_unchanged():
        need(all(os.path.lexists(path)==before for path,before in presence.items()),
             'callback loader configuration presence unchanged')
    def guarded_run(*args,**kwargs):
        configuration_unchanged()
        return run(*args,**kwargs)
    try:
        return _component(builder,products,root,private,pin,binary,aliases,guarded_run,receipt,presence)
    finally:
        try:configuration_unchanged()
        except BaseException as exc:
            receipt['final_errors'].append('callback loader configuration: '+type(exc).__name__+': '+str(exc))


def _component(builder,products,root,private,pin,binary,aliases,run,receipt,presence):
    selected=root/'tools/page-entry/selected';donor=selected/'tests/provider'
    fixture=selected/'tests/provider_callback';output=private/'provider-callback-build'
    state=receipt['provider_callback']=dict(status='failed',cases=[],units=[],generated={},archive=fact(products['archive']))
    for name,bounds in BOUNDS.items():need(receipt['bounds'].get(name)==bounds,'unchanged bounded callback profile '+name)
    def load(name,path):
        spec=importlib.util.spec_from_file_location(name,pin(path))
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
    cases=load('provider_callback_cases',fixture/'cases.py').cohort()
    record=load('provider_callback_record',fixture/'record.py')
    old=load('provider_callback_original_compare',donor/'compare.py')
    need(len(cases)==51 and sum(c['nested']for c in cases)==2,'complete focused callback cohort')
    state['case_manifest_sha256']=hashlib.sha256(json.dumps(cases,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    for name in ('probe.c','fixture.h','machine.S','xstate.c','support.c'):pin(donor/name)
    for name in ('prepare.py','callback.inc','build.sh'):pin(fixture/name)
    for name in ('provider.c','provider.h','provider_callback.h','provider_policy.h','decoder.h'):pin(selected/name)
    build=pin(fixture/'build.sh');state['recipe']=fact(build)
    state['configuration_presence']=presence
    state['link_inputs']={}
    for name in ('crt1.o','Scrt1.o','crti.o','crtn.o','crtbegin.o','crtbeginS.o',
                 'crtend.o','crtendS.o','libgcc.a','libgcc_s.so','libc.so','libc_nonshared.a','libgcc_s.so.1','libc.so.6'):
        command,out,err=run('provider-callback-link-input-'+name,
                            [builder.tools['cc'],'-print-file-name='+name],env=builder.environment)
        value=out.decode().strip()
        need(not err and Path(value).is_absolute(),'actual compiler-selected callback runtime link input')
        path=pin(value)
        state['link_inputs'][name]=dict(command=command['name'],alias=value,path=str(path),**fact(path))
    command,_,err=run('provider-callback-cc-specs',[builder.tools['cc'],'-dumpspecs'],env=builder.environment)
    need(not err,'actual callback compiler specs stderr');state['compiler_specs_command']=command['name']
    for name in ('/etc/ld.so.cache','/etc/ld.so.preload'):
        presence[name]=os.path.lexists(name)
        if presence[name]:pin(name)
    need(not presence['/etc/ld.so.preload'],'no global callback preload')
    values={'$cc_bin':builder.tools['cc'],'$python_bin':builder.tools['python'],
            '$selected':selected,'$donor':donor,'$archive':products['archive'],'$output':output,'$here':fixture}
    generations=recipe(build,'"$python_bin"');commands=recipe(build,'"$cc_bin"')
    need(len(generations)==1 and len(commands)==6,'one source generation, five object commands and one link')
    generated_names=('probe.c','callback.inc','operations.json')
    try:
        _,out,err=run('provider-callback-generate',expand(generations[0],values),env=builder.environment)
        need(not out and not err,'exact source generation protocol')
    finally:
        for name in generated_names:
            try:
                path=output/name
                if path.exists()or path.is_symlink():state['generated'][name]=fact(binary(path))
            except BaseException as exc:receipt['final_errors'].append('callback generated '+name+': '+type(exc).__name__+': '+str(exc))
    need(set(state['generated'])==set(generated_names),'complete generated callback support')
    operations=json.loads((output/'operations.json').read_bytes());text=(output/'probe.c').read_text()
    need(set(operations)=={'donor_sha256','operations'} and len(operations['operations'])==8 and
         operations['donor_sha256']==fact(donor/'probe.c')['sha256'],'exact donor and eight source adapters')
    for operation in reversed(operations['operations']):
        need(set(operation)=={'before','after'} and text.count(operation['after'])==1,'unique exact inverse adapter')
        text=text.replace(operation['after'],operation['before'])
    need(text.encode()==(donor/'probe.c').read_bytes() and
         (output/'callback.inc').read_bytes()==(fixture/'callback.inc').read_bytes(),'complete original probe and callback source identity')
    state['inverse_adapter_count']=8
    sources=[output/'probe.c',donor/'xstate.c',donor/'support.c',donor/'machine.S',selected/'provider.c']
    objects=[]
    common=['-std=c11','-O2','-Wall','-Wextra','-Werror','-ffreestanding','-fno-builtin',
            '-fno-tree-loop-distribute-patterns','-fno-stack-protector','-fno-pie','-mgeneral-regs-only',
            '-ffunction-sections','-fdata-sections','-I'+str(donor),'-I'+str(selected),'-I'+str(donor)+'/../..']
    for i,(words,source)in enumerate(zip(commands[:5],sources)):
        argv=expand(words,values);destination=output/(['probe.c.o','xstate.c.o','support.c.o','machine.S.o','provider.o'][i])
        flags=['-O2','-fno-pie']if i==3 else common
        need(argv==[str(builder.tools['cc']),*flags,'-c',str(source),'-o',str(destination)],'exact original compile options and source '+str(i))
        unit=dict(argv=argv,headers={});state['units'].append(unit)
        _,out,err=run('provider-callback-headers-'+str(i),[builder.tools['cc'],*flags,'-M','-MT','provider_callback',source],env=builder.environment)
        need(not err,'actual callback compiler include stderr')
        rules=out.decode().replace('\\\n',' ').splitlines()
        need(len(rules)==1 and rules[0].startswith('provider_callback: '),'one full actual source include rule')
        for token in shlex.split(rules[0].split(':',1)[1]):
            alias=Path(token).absolute();resolved=str(alias.resolve(strict=True))
            need(str(alias)not in aliases or aliases[str(alias)]==resolved,'actual callback include alias')
            aliases[str(alias)]=resolved;unit['headers'][resolved]=fact(pin(alias))
        need(str(source.resolve(strict=True))in unit['headers'],'actual translation unit in its include closure')
        try:run('provider-callback-compile-'+str(i),argv,profile='provider_component_build',env=builder.environment)
        finally:
            try:
                if destination.exists()or destination.is_symlink():unit['artifact']=fact(binary(destination))
            except BaseException as exc:receipt['final_errors'].append('callback partial object '+str(i)+': '+type(exc).__name__+': '+str(exc))
        binary(destination);objects.append(destination)
    executable=output/'provider-callback-fixture';argv=expand(commands[5],values)
    need(argv==[str(builder.tools['cc']),'-no-pie',*map(str,objects),str(products['archive']),
                '-Wl,--no-undefined,--gc-sections','-o',str(executable)],'exact callback link with current retained archive')
    state['link_argv']=argv
    try:run('provider-callback-link',argv,profile='provider_component_build',env=builder.environment)
    finally:
        try:
            if executable.exists()or executable.is_symlink():state['binary']=fact(binary(executable))
        except BaseException as exc:receipt['final_errors'].append('callback partial link: '+type(exc).__name__+': '+str(exc))
    binary(executable)
    image,head,segments=elf(executable);interpreters=[p for p in segments if p[0]==3]
    need(head[1]==2 and len(interpreters)==1 and
         any(p[0]==1 and p[1]&1 and p[3]<=head[4]<p[3]+p[6] for p in segments) and
         not any(p[0]==1 and p[1]&3==3 for p in segments),'actual dynamic ET_EXEC component without RWX')
    interp=interpreters[0];name=image[interp[2]:interp[2]+interp[5]]
    need(len(name)==interp[5] and name[:1]==b'/' and name[-1:]==b'\0' and b'\0'not in name[:-1],
         'actual component interpreter pathname')
    interpreter=pin(Path(name[:-1].decode()))
    state['elf']=dict(type='ET_EXEC',interpreter=fact(interpreter),dynamic=True)
    _,out,err=run('provider-callback-libraries',[interpreter,'--list',executable],env=builder.environment)
    need(not err,'actual callback loader dependency stderr')
    state['libraries']=provider_libraries(root,executable,interpreter,out,state['link_inputs'],pin)
    _,out,err=run('provider-callback-symbols',[builder.tools['nm'],'-S','--defined-only',executable],profile='inspect',env=builder.environment)
    need(not err,'actual component symbol capture')
    actual=symbols(executable)
    for name in ('li2_selected_complete_callback','fixture_enter','fixture_post_entry'):
        rows=[r for r in actual if r[0]==name]
        need(len(rows)==1 and rows[0][1]==2 and rows[0][4]>0,'actual component function '+name)
    roots={'kernel_before':65536,'kernel_after':65536,'uc_before':2048,'uc_after':2048,
           'fixture_pre_fp':65536,'fixture_post_fp':65536,'fixture_pre':192,'fixture_post':192,
           'stack_before':512,'stack_after':512,'image_before':8192,'callback_cpuid':480}
    for name,size in roots.items():
        rows=[r for r in actual if r[0]==name]
        need(len(rows)==1 and rows[0][1]==1 and rows[0][4]==size and
             sum(p[0]==1 and p[1]==6 and p[3]<=rows[0][3]<rows[0][3]+size<=p[3]+p[6] for p in segments)==1,
             'actual complete writable NX state storage '+name)
    state['storage_bytes']=roots
    totals=dict(processes=0,completed=0,refused_before_commit=0,failed_callback_without_return=0,
                callback_entered=0,callback_returned=0,callback_completed=0,cpuid_samples=0)
    state['totals']=totals
    for case in cases:
        name='provider-callback-'+case['name'];row=dict(name=name,case=case,accepted=False);state['cases'].append(row)
        env=dict(builder.environment)
        for key in ('LI2_FIXTURE_SCRIPT_CF0','LI2_FIXTURE_CALLBACK_DF'):env.pop(key,None)
        if case['cf0']:env['LI2_FIXTURE_SCRIPT_CF0']='1'
        if case['df']:env['LI2_FIXTURE_CALLBACK_DF']='1'
        command,out,err=run(name,[executable,'{record_fd}',*map(str,case['args'])],profile='provider_component',
                            expected=125 if case['nested']else 0,env=env,record=True)
        need(command['bounds']==BOUNDS['provider_component'] and not err and
             out==(b''if case['nested']else b'LI2_PROVIDER_CAPTURE 1\n'),'exact callback process protocol')
        path=private/(name+'.record');data=path.read_bytes();row['record']=fact(binary(path))
        need(len(data)==(NESTED_BYTES if case['nested']else NORMAL_BYTES),'complete exact callback record')
        result=record.check(data,case,old);row.update(comparison=result,accepted=True)
        totals['processes']+=1;totals[result['outcome']]+=1
        for key in ('callback_entered','callback_returned','callback_completed','cpuid_samples'):totals[key]+=result[key]
    need(totals==dict(processes=51,completed=23,refused_before_commit=26,failed_callback_without_return=2,
                     callback_entered=33,callback_returned=31,callback_completed=23,cpuid_samples=306),
         'complete exact focused callback outcomes, including unreturned failures')
    state['status']='passed'
    return executable


def summary(receipt):
    state=receipt.get('provider_callback',{})
    return dict(status=state.get('status','unexecuted'),totals=state.get('totals'),
                case_count=len(state.get('cases',[])),accepted=sum(c.get('accepted')is True for c in state.get('cases',[])),
                case_manifest_sha256=state.get('case_manifest_sha256'),normal_record_bytes=NORMAL_BYTES,
                nested_record_bytes=NESTED_BYTES,old_provider_385_required_separately=True)
