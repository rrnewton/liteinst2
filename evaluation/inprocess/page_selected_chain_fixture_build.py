"""Source-bound finite link; actual retained ELF symbols and file-only DWARF."""
from pathlib import Path
import re
from page_selected import elf, fact, need
from page_selected_components import plain_executable
from page_selected_register_time_build import recipe, expand, headers
from page_selected_register_time_compare import decode

ROOTS={'li2_chain_record','samples','ctl'}


def build(builder,products,root,private,pin,binary,aliases,run,receipt,inputs):
    selected=root/'tools/page-entry/selected';fixture=selected/'tests/trace_chain'
    output=private/'finite';output.mkdir()
    state=receipt['finite_build']=dict(status='failed',archive=fact(products['archive']))
    generated=output/'chain_support.inc'
    _,out,err=run('chain-support',[builder.tools['python'],pin(fixture/'prepare.py'),
        pin(selected/'tests/generic/fixture.c'),generated],profile='metadata',env=builder.environment)
    need(not err and decode(out)==inputs['generator']['stdout'],'exact three-adapter support observation')
    need(fact(pin(generated))==inputs['generator']['fact'],'complete exact generated support')
    state['generated']=fact(generated)
    path=pin(fixture/'build.sh');state['recipe']=fact(path)
    commands=recipe(path,'"$cc_bin"');need(len(commands)==1,'one exact fixture link recipe')
    argv=expand(commands[0],{'$cc_bin':builder.tools['cc'],'$fixture_dir':fixture,
        '$selected_dir':selected,'$parent_dir':selected.parent,'$decoder_archive':products['archive'],
        '$output_dir':output})
    sources=[str(selected/x) for x in ('tests/trace_chain/owner_wrapper.c','lifecycle_loader.c',
        'tests/generic/tf_controls.c','tests/trace_chain/route_controls.c',
        'tests/trace_chain/fixture.c','tests/generic/fixture.S')]
    binary_path=output/'trace-chain-fixture'
    need(argv[-2:]==['-o',str(binary_path)] and all(x in argv for x in
        ('-std=gnu11','-O2','-g','-nostdlib','-static','-no-pie','-fno-pie',
         '-DLI2_TF_HANDOFF=1','-DLI2_MAPS_PHASE_REUSE=1')),'exact optimized freestanding chain fixture')
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
    need(set(symbols)==ROOTS and all(n==1 for n in counts.values()),'three unique complete ELF record symbols')
    intervals=sorted((x['address'],x['address']+x['bytes'])for x in symbols.values())
    need(all(a[1]<=b[0]for a,b in zip(intervals,intervals[1:])),'actual record objects disjoint')
    state['symbols']=symbols
    dwarf=pin(root/'evaluation/inprocess/page_selected_chain_dwarf.py')
    _,out,err=run('chain-dwarf',[builder.tools['gdb'],'-q','-nx','-batch','-iex','set auto-load off',
        '-iex','set debuginfod enabled off','-iex','maintenance set worker-threads 1','--readnow',
        '--se='+str(binary_path),'-x',dwarf],profile='metadata',env=builder.environment)
    need(not err,'file-only actual DWARF stderr');layout=decode(out)
    need(set(layout)==ROOTS and all(layout[k]['bytes']==symbols[k]['bytes']for k in ROOTS),
         'actual DWARF and ELF agree for every complete record')
    need(layout['samples']['kind']=='array' and layout['samples']['count']==21 and
         sum((layout['li2_chain_record']['bytes'],layout['samples']['element']['bytes'],layout['ctl']['bytes']))<16<<20,
         'unchanged finite record extent below actual16MiB cap')
    state['layout']=layout;state['status']='passed';return binary_path,layout
