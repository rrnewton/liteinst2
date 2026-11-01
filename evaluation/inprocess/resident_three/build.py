"""Natural-source version of the complete D3 app/bridge compiler and byte oracle."""
import hashlib,json,shlex,sys
from pathlib import Path
from types import SimpleNamespace
from page_selected import ENV,bridge_check,need
from page_selected_register_time_build import recipe,expand
import scalar_span_trace_build as byte_oracle

ROOT=Path(__file__).resolve().parents[3]
HERE=Path(__file__).resolve().parent
SELECTED=ROOT/'tools/page-entry/selected'

def compile(name,argv,state,pin,binary,run,fact):
    units=[x for x in argv if x.endswith(('.c','.S'))]
    need(units and len(set(units))==len(units) and argv[-2]=='-o','whole compiler recipe')
    flags=[x for x in argv[1:-2] if x not in units and not x.endswith(('.a','.o')) and not x.startswith('-Wl,')]
    _,out,err=run(name+'-headers',[argv[0],*flags,'-M','-MT','li2_resident',*units])
    need(not err,'clean compiler-M diagnostics')
    lines=out.decode().replace('\\\n',' ').splitlines()
    need(len(lines)==len(units),'one actual dependency rule per TU')
    deps={}
    for unit,line in zip(units,lines):
        need(line.startswith('li2_resident: '),'literal dependency target')
        names=shlex.split(line.split(':',1)[1]);need(unit in names,'actual source present')
        for n in names:
            need(Path(n).is_absolute(),'absolute compiler dependency');deps[n]=dict(resolved=str(pin(n)),**fact(n))
    state.setdefault('builds',{})[name]=dict(argv=argv,headers=deps)
    _,out,err=run(name+'-link',argv,profile='release_build')
    need(out==err==b'','strict compilation without diagnostics')
    state['builds'][name]['output']=dict(path=str(binary(argv[-1])),**fact(argv[-1]))
    return Path(argv[-1])


def build(private,archive,tools,state,pin,binary,aliases,run,fact):
    contract=json.loads(pin(HERE/'CONTRACT.json').read_bytes())
    selected=SELECTED;cc=tools['cc'];nm=tools['nm'];readelf=pin('/usr/bin/readelf')
    fixture=selected/'tests/resident_three_app';application=private/'application';application.mkdir()
    script=pin(fixture/'build.sh');pin(fixture/'app.ld')
    rows=recipe(script,'"$cc"');need(len(rows)==2,'both unchanged source-owned application recipes')
    apps=[]
    for i,row in enumerate(rows):
        argv=expand(row,{'$cc':cc,'$source_dir':fixture,'$output':application})
        apps.append(compile('app-'+str(i),argv,state,pin,binary,run,fact))
    interp,app=apps
    need(interp==application/'fixture-interpreter.so' and app==application/'resident-three-app',
         'the exact original two fixture outputs')
    state['application']=state['builds']['app-1']['output'];state['interpreter']=state['builds']['app-0']['output']
    state['application_recipe']=dict(path=str(script),**fact(script))
    output=private/'resident';output.mkdir()
    binder=pin(selected/'resident_three_flags_binding.py');pin(selected/'persistent_direct_frontier_binding.py')
    pin(selected/'persistent_group_binding.py')
    run('bind',[sys.executable,'-B',binder,selected,archive,app,output])
    for p in output.iterdir():binary(p)
    binding=json.loads((output/'resident_three_binding.json').read_bytes())
    need([x['path']for x in binding['sources']]==contract['policy'] and
         binding['flag_stack'] is True and binding['helper_tf'] is True and
         binding['tf_nx_page_boundary'] is True,'whole actual source-policy closure')
    for member in binding['sources']:
        need({k:fact(pin(selected/member['path']))[k] for k in ('bytes','sha256')}==
             {k:member[k] for k in ('bytes','sha256')},'actual complete bound policy source')
    rows=recipe(pin(selected/'build-resident-three-flags.sh'),'"$cc_bin"');need(len(rows)==1,'one exact bridge recipe')
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
    gdb=pin('/usr/bin/gdb');layout=pin(selected/'tests/resident_three_owner/layout.py')
    cache=private/'gdb-cache';cache.mkdir()
    _,dwarf,diagnostic=run('dwarf',[gdb,'-nx','-nh','-batch','-iex','set auto-load off',
        '-iex','set debuginfod enabled off','-iex','set index-cache enabled off',
        '-iex','maintenance set worker-threads 1','-ex','file '+str(bridge),'-ex','source '+str(layout)],
        env=dict(ENV,MALLOC_ARENA_MAX='1',XDG_CACHE_HOME=str(cache)))
    need(not diagnostic,'clean actual DWARF diagnostics')
    actual_layout=json.loads(dwarf)
    need(actual_layout['record']=='r3o_wire' and len(actual_layout['types'])==110 and
        sum(len(v['fields'])for v in actual_layout['types'].values())==1229 and
        actual_layout['types']['r3o_wire']['bytes']==2063040,'unchanged complete capture type closure')
    state['layout']=dict(bytes=len(dwarf),sha256=hashlib.sha256(dwarf).hexdigest(),
        types=110,fields=1229,raw_bytes=2063040,footer_bytes=64)
    byte_oracle.SELECTED=selected;state['byte_oracle']={};builder=SimpleNamespace(tools=tools,environment=dict(ENV))
    byte_oracle.fast_bytes(builder,private,pin,binary,aliases,run,state['byte_oracle'])
    byte_oracle.fast_bytes_completed(state['byte_oracle'],state['commands'],binary)
    need([v['name'] for v in state['commands']]==contract['compile_commands'],
         'whole fresh application/bridge/oracle command schedule')
    return app,interp,bridge,builder
