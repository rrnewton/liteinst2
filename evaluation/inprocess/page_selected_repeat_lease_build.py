"""Source-bound finite link; actual retained ELF symbols and file-only DWARF."""
from pathlib import Path
import re
from page_selected import elf, fact, need
from page_selected_components import plain_executable
from page_selected_register_time_build import recipe, expand, headers
from page_selected_register_time_compare import decode

ROOTS={'rl','samples'}


def build(builder,products,root,private,pin,binary,aliases,run,receipt,inputs):
    selected=root/'tools/page-entry/selected';fixture=selected/'tests/repeat_lease'
    output=private/'finite';output.mkdir()
    state=receipt['finite_build']=dict(status='failed',archive=fact(products['archive']))
    adapter_path=pin(fixture/'ADAPTERS.json')
    need(fact(adapter_path)==dict(bytes=3768,sha256='e665f6bbf55102cdb5b5eda272a88e436a92e0f3f613c279442a07db77bb1653'),'fixed exact instrumentation inverse catalogue')
    adapters=decode(adapter_path.read_bytes());expected=[]
    for row in adapters:
        need(fact(pin(selected/row['source']))==dict(bytes=row['before_bytes'],sha256=row['before_sha256']),
             'actual runtime/generic adapter before-image')
        expected.append({k:row[k]for k in ('source','target','before_sha256','after_sha256','before_bytes','after_bytes')})
    _,out,err=run('lease-support',[builder.tools['python'],pin(fixture/'prepare.py'),selected,output],
        profile='metadata',env=builder.environment)
    need(not err and decode(out)==expected,'exact five source-bound instrumentation views')
    state['generated']={}
    for row in adapters:
        generated=pin(output/row['target']);value=dict(bytes=row['after_bytes'],sha256=row['after_sha256'])
        need(fact(generated)==value,'complete exact generated source');state['generated'][row['target']]=value
    path=pin(fixture/'build.sh');state['recipe']=fact(path)
    commands=recipe(path,'"$cc_bin"');need(len(commands)==1,'one exact fixture link recipe')
    argv=expand(commands[0],{'$cc_bin':builder.tools['cc'],'$fixture_dir':fixture,
        '$selected_dir':selected,'$parent_dir':selected.parent,'$decoder_archive':products['archive'],
        '$output_dir':output})
    sources=[str(output/x)for x in ('step_owner.c','lifecycle_loader.c')]+[str(selected/x)for x in
        ('rseq_guard.c','tests/generic/tf_controls.c','tests/repeat_lease/fixture.c','tests/generic/fixture.S')]
    binary_path=output/'repeat-lease-fixture'
    need(argv[-2:]==['-o',str(binary_path)] and all(x in argv for x in
        ('-std=gnu11','-O2','-g','-nostdlib','-static','-no-pie','-fno-pie',
         '-DLI2_EFFECT_PROVIDER=1','-DLI2_RSEQ_INACTIVE=1','-DLI2_MAPS_PHASE_REUSE=1','-DLI2_REPEAT_RX_LEASE=1','-DLI2_FAST_EQUAL=1')),'exact optimized freestanding REP lease fixture')
    need([x for x in argv if x.startswith('-D')]==['-DLI2_EFFECT_PROVIDER=1','-DLI2_RSEQ_INACTIVE=1',
         '-DLI2_MAPS_PHASE_REUSE=1','-DLI2_REPEAT_RX_LEASE=1','-DLI2_FAST_EQUAL=1'],'exact five macros including fast equality and complete zero checks')
    state['argv']=argv
    headers('chain-headers',argv,sources,products['archive'],builder,pin,aliases,run,state)
    run('chain-link',argv,profile='fixture_link',env=builder.environment)
    binary_path=binary(binary_path);state['artifact']=fact(binary_path)
    state['elf']=plain_executable(binary_path)
    _,out,err=run('chain-undefined',[builder.tools['nm'],'-u',binary_path],profile='inspect',env=builder.environment)
    need(out==err==b'','no unresolved fixture imports')
    _,out,err=run('chain-symbols',[builder.tools['nm'],'-S','--defined-only',binary_path],
        profile='inspect',env=builder.environment)
    need(not err,'actual record symbol inspection stderr')
    _,_,segments=elf(binary_path);symbols={};counts={k:0 for k in ROOTS}
    for line in out.decode('ascii').splitlines():
        words=line.split()
        if words and words[-1] in ROOTS:counts[words[-1]]+=1
        if len(words)!=4 or words[-1] not in ROOTS:continue
        address,size,kind,key=words
        need(key not in symbols and kind in ('b','B') and re.fullmatch('[0-9a-fA-F]+',address) and
             re.fullmatch('[0-9a-fA-F]+',size),'unique actual BSS record identity')
        address,size=int(address,16),int(size,16)
        need(size>0 and sum(s[0]==1 and s[1]==6 and s[3]<=address<address+size<=s[3]+s[6]
             for s in segments)==1,'whole actual record in writable NX ELF segment')
        symbols[key]=dict(address=address,bytes=size)
    need(set(symbols)==ROOTS and all(n==1 for n in counts.values()),'two unique complete ELF record symbols')
    intervals=sorted((x['address'],x['address']+x['bytes'])for x in symbols.values())
    need(all(a[1]<=b[0]for a,b in zip(intervals,intervals[1:])),'actual record objects disjoint')
    state['symbols']=symbols
    dwarf=pin(root/'evaluation/inprocess/page_selected_repeat_lease_dwarf.py')
    _,out,err=run('chain-dwarf',[builder.tools['gdb'],'-q','-nx','-batch','-iex','set auto-load off',
        '-iex','set debuginfod enabled off','-iex','maintenance set worker-threads 1','--readnow',
        '--se='+str(binary_path),'-x',dwarf],profile='metadata',env=builder.environment)
    need(not err,'file-only actual DWARF stderr');layout=decode(out)
    need(set(layout)==ROOTS|{'frame'} and all(layout[k]['bytes']==symbols[k]['bytes']for k in ROOTS),
         'actual DWARF and ELF agree for every complete record')
    need(layout['samples']['kind']=='array' and layout['samples']['count']==21 and
         sum((layout['rl']['bytes'],layout['samples']['element']['bytes']))<16<<20,
         'additive fixed record extent below actual16MiB cap')
    state['layout']=layout;state['status']='passed';return binary_path,layout
