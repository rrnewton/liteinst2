"""Exact additive RX build; whole old compiler-M and byte oracle retained."""
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


def build(private,archive,tools,state,pin,binary,aliases,run,fact,case,*,source_context=None):
    need(type(case)is int and case in range(8),'one exact positive or additive causal case')
    compiler_root=ROOT if source_context is None else source_context['compiler_root']
    reader_root=ROOT if source_context is None else source_context['reader_root']
    real_root=ROOT if source_context is None else source_context['root']
    contract_path=HERE/'CONTRACT.json'if source_context is None else source_context['contract']
    retained=source_context is not None and source_context['prior_case0'] is not None and case==0
    if retained:need(private==source_context['prior_case0']['directory'],'same authenticated compiler output directory')
    contract=json.loads(pin(contract_path).read_bytes())
    selected=compiler_root/'tools/page-entry/selected';cc=tools['cc'];nm=tools['nm'];readelf=pin('/usr/bin/readelf')
    fixture=selected/'tests/resident_generation_app';application=private/'application';application.mkdir(exist_ok=retained)
    causal=selected/'tests/resident_rx_app'
    script=pin((causal if case else fixture)/'build.sh');pin(fixture/'app.ld')
    if case:
        prepare=pin(causal/'prepare.py');pin(causal/'controls.h');pin(fixture/'main.c')
        run('app-prepare',[tools['python'],'-B',prepare,'--donor',fixture/'main.c',
            '--output',application/'main.c'])
        binary(application/'main.c')
    rows=recipe(script,'"$cc"');need(len(rows)==2,'both complete source-owned application recipes')
    apps=[]
    for i,row in enumerate(rows):
        argv=expand(row,{'$cc':cc,'$source_dir':causal if case else fixture,
            '$base_dir':fixture,'$output':application,'$control':str(case),'$effect':'0'})
        apps.append(compile('app-'+str(i),argv,state,pin,binary,run,fact))
    interp,app=apps
    need(interp==application/'fixture-interpreter.so'and
        app==application/('resident-rx-app'if case else'resident-generation-app'),
        'the two exact image outputs; positive source/recipe remain original')
    state['application']=state['builds']['app-1']['output'];state['interpreter']=state['builds']['app-0']['output']
    state['application_recipe']=dict(path=str(script),**fact(script))
    output=private/'resident';output.mkdir(exist_ok=retained)
    binder=pin(selected/'resident_rx_binding.py');pin(selected/'persistent_direct_frontier_binding.py')
    pin(selected/'persistent_group_binding.py');pin(selected/'resident_generation_binding.py')
    run('bind',[sys.executable,'-B',binder,selected,archive,app,output])
    for p in output.iterdir():binary(p)
    binding=json.loads((output/'resident_three_binding.json').read_bytes())
    need([x['path']for x in binding['sources']]==contract['policy'] and
         binding['flag_stack'] is True and binding['helper_tf'] is True and
         binding['tf_nx_page_boundary'] is True and binding['stable_generation'] is True and
         binding['rx_capture'] is True and binding['resident_rx'] is True and binding['causal']['case']==case and binding['activations']==2 and
         binding['profile']==contract['profile'],'whole actual source-policy closure')
    for member in binding['sources']:
        need({k:fact(pin(selected/member['path']))[k] for k in ('bytes','sha256')}==
             {k:member[k] for k in ('bytes','sha256')},'actual complete bound policy source')
    rows=recipe(pin(selected/'build-resident-rx.sh'),'"$cc_bin"');need(len(rows)==1,'one exact bridge recipe')
    argv=expand(rows[0],{'$cc_bin':cc,'$selected_dir':selected,'$parent_dir':selected.parent,'$archive':archive,'$output':output})
    need([x for x in argv if x.startswith('-D')]==contract['macros'],'exact explicit macro set')
    need([x for x in argv if x.endswith(('.c','.S'))]==[str(compiler_root/x)for x in contract['translation_units']],
         'whole actual28-unit sequence')
    bridge=compile('bridge',argv,state,pin,binary,run,fact);state['elf']=bridge_check(bridge)
    _,out,err=run('undefined',[nm,'-u',bridge]);need(out==err==b'','no unresolved imports')
    _,out,err=run('symbols',[nm,'-S','--defined-only',bridge]);need(not err,'complete nm')
    symbols={line.split()[-1]for line in out.decode().splitlines()if len(line.split())==4 and line.split()[2]in('t','T')}
    need(set(contract['providers'])<=symbols,'all declared actual code providers')
    run('elf',[readelf,'-h','-l','-d','-r','-W',bridge])
    gdb=pin('/usr/bin/gdb');layout=pin(reader_root/'tools/page-entry/selected/tests/resident_rx_owner/layout.py')
    cache=private/'gdb-cache';cache.mkdir()
    _,dwarf,diagnostic=run('dwarf',[gdb,'-nx','-nh','-batch','-iex','set auto-load off',
        '-iex','set debuginfod enabled off','-iex','set index-cache enabled off',
        '-iex','maintenance set worker-threads 1','-ex','file '+str(bridge),'-ex','source '+str(layout)],
        env=dict(ENV,MALLOC_ARENA_MAX='1',XDG_CACHE_HOME=str(cache)))
    need(not diagnostic,'clean actual DWARF diagnostics')
    actual_layout=json.loads(dwarf)
    need(actual_layout['record']=='rrx_bundle' and len(actual_layout['types'])==116 and
        sum(len(v['fields'])for v in actual_layout['types'].values())==1309 and
        actual_layout['types']['rrx_bundle']['bytes']==4173888 and
        actual_layout['types']['r3o_wire']['bytes']==2065920 and
        actual_layout['types']['li2_r3_owner']['bytes']==1247040,'unchanged complete capture type closure')
    state['layout']=dict(bytes=len(dwarf),sha256=hashlib.sha256(dwarf).hexdigest(),
        types=116,fields=1309,raw_bytes=4173888,footer_bytes=64)
    if source_context is None:
        need(byte_oracle.SELECTED==selected,'same natural source-owned mandatory byte oracle')
    else:
        need(byte_oracle.SELECTED==real_root/'tools/page-entry/selected',
             'same natural source-owned mandatory byte oracle')
        compiled=pin(selected/'span_fast_bytes.h');actual=pin(byte_oracle.SELECTED/'span_fast_bytes.h')
        need(fact(compiled)==fact(actual)and
             {k:state['builds']['bridge']['headers'][str(compiled)][k]for k in('bytes','sha256')}==fact(actual),
             'whole actual compiled byte helper equals the unchanged mandatory oracle header')
    state['byte_oracle']={};builder=SimpleNamespace(tools=tools,environment=dict(ENV))
    byte_oracle.fast_bytes(builder,private,pin,binary,aliases,run,state['byte_oracle'])
    byte_oracle.fast_bytes_completed(state['byte_oracle'],state['commands'],binary)
    need([v['name'] for v in state['commands']]==(['app-prepare']if case else[])+contract['compile_commands'],
         'whole fresh application/bridge/oracle command schedule')
    return app,interp,bridge,builder,actual_layout,binding
