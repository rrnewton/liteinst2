"""Exact additive generation build; whole old compiler-M and byte oracle retained."""
import hashlib,json,shlex,sys
from pathlib import Path
from types import SimpleNamespace
from page_selected import ENV,bridge_check,need
from page_selected_register_time_build import recipe,expand
import scalar_span_trace_build as byte_oracle

ROOT=Path(__file__).resolve().parents[3]
HERE=Path(__file__).resolve().parent
SELECTED=ROOT/'tools/page-entry/selected'

from resident_three.build import compile


def build(private,archive,tools,state,pin,binary,aliases,run,fact,effect):
    need(type(effect)is int and effect in(0,1,2,3),'one exact source-owned finite effect case')
    contract=json.loads(pin(HERE/'CONTRACT.json').read_bytes())
    selected=SELECTED;cc=tools['cc'];nm=tools['nm'];readelf=pin('/usr/bin/readelf')
    fixture=selected/'tests/resident_generation_app';application=private/'application';application.mkdir()
    script=pin(fixture/'build.sh');pin(fixture/'app.ld')
    rows=recipe(script,'"$cc"');need(len(rows)==2,'both unchanged source-owned application recipes')
    apps=[]
    for i,row in enumerate(rows):
        argv=expand(row,{'$cc':cc,'$source_dir':fixture,'$output':application,'$effect':str(effect)})
        apps.append(compile('app-'+str(i),argv,state,pin,binary,run,fact))
    interp,app=apps
    need(interp==application/'fixture-interpreter.so' and app==application/'resident-generation-app',
         'the exact original two fixture outputs')
    state['application']=state['builds']['app-1']['output'];state['interpreter']=state['builds']['app-0']['output']
    state['application_recipe']=dict(path=str(script),**fact(script))
    output=private/'resident';output.mkdir()
    binder=pin(selected/'resident_generation_binding.py');pin(selected/'persistent_direct_frontier_binding.py')
    pin(selected/'persistent_group_binding.py')
    run('bind',[sys.executable,'-B',binder,selected,archive,app,output])
    for p in output.iterdir():binary(p)
    binding=json.loads((output/'resident_three_binding.json').read_bytes())
    need([x['path']for x in binding['sources']]==contract['policy'] and
         binding['flag_stack'] is True and binding['helper_tf'] is True and
         binding['tf_nx_page_boundary'] is True and binding['stable_generation'] is True and
         binding['generation_capture'] is True and binding['activations']==2 and
         binding['profile']==contract['profile'],'whole actual source-policy closure')
    for member in binding['sources']:
        need({k:fact(pin(selected/member['path']))[k] for k in ('bytes','sha256')}==
             {k:member[k] for k in ('bytes','sha256')},'actual complete bound policy source')
    rows=recipe(pin(selected/'build-resident-generation.sh'),'"$cc_bin"');need(len(rows)==1,'one exact bridge recipe')
    argv=expand(rows[0],{'$cc_bin':cc,'$selected_dir':selected,'$parent_dir':selected.parent,'$archive':archive,'$output':output})
    need([x for x in argv if x.startswith('-D')]==contract['macros'],'exact explicit macro set')
    need([x for x in argv if x.endswith(('.c','.S'))]==[str(ROOT/x)for x in contract['translation_units']],
         'whole actual28-unit sequence')
    bridge=compile('bridge',argv,state,pin,binary,run,fact);state['elf']=bridge_check(bridge)
    _,out,err=run('undefined',[nm,'-u',bridge]);need(out==err==b'','no unresolved imports')
    _,out,err=run('symbols',[nm,'-S','--defined-only',bridge]);need(not err,'complete nm')
    symbols={line.split()[-1]for line in out.decode().splitlines()if len(line.split())==4 and line.split()[2]in('t','T')}
    need(set(contract['providers'])<=symbols,'all declared actual code providers')
    run('elf',[readelf,'-h','-l','-d','-r','-W',bridge])
    gdb=pin('/usr/bin/gdb');layout=pin(selected/'tests/resident_generation_owner/layout.py')
    cache=private/'gdb-cache';cache.mkdir()
    _,dwarf,diagnostic=run('dwarf',[gdb,'-nx','-nh','-batch','-iex','set auto-load off',
        '-iex','set debuginfod enabled off','-iex','set index-cache enabled off',
        '-iex','maintenance set worker-threads 1','-ex','file '+str(bridge),'-ex','source '+str(layout)],
        env=dict(ENV,MALLOC_ARENA_MAX='1',XDG_CACHE_HOME=str(cache)))
    need(not diagnostic,'clean actual DWARF diagnostics')
    actual_layout=json.loads(dwarf)
    need(actual_layout['record']=='rgo_bundle' and len(actual_layout['types'])==113 and
        sum(len(v['fields'])for v in actual_layout['types'].values())==1254 and
        actual_layout['types']['rgo_bundle']['bytes']==4129856 and
        actual_layout['types']['r3o_wire']['bytes']==2064000 and
        actual_layout['types']['li2_r3_owner']['bytes']==1246784,'unchanged complete capture type closure')
    state['layout']=dict(bytes=len(dwarf),sha256=hashlib.sha256(dwarf).hexdigest(),
        types=113,fields=1254,raw_bytes=4129856,footer_bytes=64)
    need(byte_oracle.SELECTED==selected,'same natural source-owned mandatory byte oracle')
    state['byte_oracle']={};builder=SimpleNamespace(tools=tools,environment=dict(ENV))
    byte_oracle.fast_bytes(builder,private,pin,binary,aliases,run,state['byte_oracle'])
    byte_oracle.fast_bytes_completed(state['byte_oracle'],state['commands'],binary)
    need([v['name'] for v in state['commands']]==contract['compile_commands'],
         'whole fresh application/bridge/oracle command schedule')
    return app,interp,bridge,builder
