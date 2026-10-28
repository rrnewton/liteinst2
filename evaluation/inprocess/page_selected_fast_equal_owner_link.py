"""Original five fixture recipes, with only their owner TU compiled for fast equality."""
from pathlib import Path
import re
from page_selected import fact,need
from page_selected_fast_zero_link import (PREDECESSORS,adapt,recipe,expand,decode,headers,
    compile_retained,memset_body,plain_executable,body_check,executable_layout,control_layout,
    extract,chain_layout)
from page_selected_fast_equal import equal_inspect


def compile_owner(kind,group,argv,selected,builder,pin,binary,run,state,pending,errors):
    tu=selected/'tests/trace_chain/owner_wrapper.c'if kind=='chain'else selected/'step_owner.c'
    other=selected/'step_owner.c'if kind=='chain'else selected/'tests/trace_chain/owner_wrapper.c'
    need(argv.count(str(tu))==1 and str(other)not in argv and
         not any(x.startswith(('-DLI2_FAST_EQUAL','-DLI2_EQUAL_ORACLE'))for x in argv),
         'exact original owner translation unit and no previous equality enablement')
    units=[x for x in argv[1:-2]if x.endswith(('.c','.S'))]
    flags=[x for x in argv[1:-2]if x not in units and not x.endswith(('.a','.o'))and not x.startswith('-Wl,')]
    need('-c'not in flags and all(x in flags for x in ('-O2','-g','-fno-builtin','-mgeneral-regs-only',
         '-fno-tree-loop-distribute-patterns','-fno-tree-vectorize','-Wall','-Wextra','-Werror')),
         'all original release owner flags retained')
    output=Path(argv[-1]).parent/('owner-fast-'+str(group)+'.o')
    command=[str(builder.tools['cc']),*flags,'-DLI2_FAST_EQUAL=1','-DLI2_EQUAL_ORACLE=1',
             '-c',str(pin(tu)),'-o',str(output)]
    label='equal-owner-'+str(group)
    owner=dict(status='failed',translation_unit=str(tu),source=fact(tu),owner_source=fact(pin(selected/'step_owner.c')),
               argv=command)
    state.setdefault('equal_owners',[]).append(owner)
    required=[selected/'step_owner.c',tu]
    if kind=='repeat':required += [selected/'repeat_owner.h',selected/'repeat_owner.inc']
    headers(label+'-headers',command,builder,pin,run,owner,required=required)
    compile_retained(label+'-build',command,run,binary,builder,pending,errors)
    owner['object']=fact(output)
    linked=list(argv);linked[linked.index(str(tu))]=str(output)
    linked.insert(-2,'-Wl,--undefined=li2_equal_oracle')
    inverse=list(linked);inverse.remove('-Wl,--undefined=li2_equal_oracle');inverse[inverse.index(str(output))]=str(tu)
    need(inverse==argv,'complete exact owner-object and retained-wrapper link inverse')
    return linked,output,owner


def inspect_owner(group,owner,fixture,builder,run,state,primitive_body):
    for kind,path in (('object',owner),('final',fixture)):
        label='equal-owner-'+str(group)+'-'+kind
        _,symbols,err=run(label+'-symbols',[builder.tools['nm'],'-S','--defined-only',path],profile='inspect',env=builder.environment)
        need(not err,'actual equality symbol stderr')
        # Inspect every actual candidate helper symbol separately, so the old
        # per-command capture cap need not grow with unrelated Rust text.
        *_,elf_symbols=equal_inspect.elf(path)
        names=[s['name']for s in elf_symbols if s['info']&15==2 and
               (s['name']=='li2_equal_oracle'or re.fullmatch(r'equal(?:\.(?:isra|constprop|part)\.[0-9]+)?',s['name']))]
        need(1<=len(names)<=8 and len(names)==len(set(names)),'bounded complete actual equality symbol set')
        blocks=[]
        for name in sorted(names):
            _,code,err=run(label+'-body-'+name,[builder.tools['objdump'],'-d','-w','-M','att','--disassemble='+name,path],
                          profile='inspect',env=builder.environment)
            need(not err,'actual equality body stderr');blocks.append(code)
        state[kind+'_body']=equal_inspect.body(path,symbols,b'\n'.join(blocks),True)
    need(equal_inspect.linked(state['object_body'],state['final_body']),
         'actual owner object and final fixture contain identical complete helper graph')
    need(equal_inspect.linked(primitive_body,state['final_body']),
         'final owner helper equals passed same-revision primitive; contextual differences fail')
    state['status']='passed'


def build_group(kind,builder,products,root,private,pin,binary,run,state,leaf,body,pending,errors,primitive_body):
    selected=root/'tools/page-entry/selected';folder={'generic':'generic','chain':'trace_chain','register':'register_run',
        'controls':'register_run_controls','repeat':'repeat'}[kind]
    fixture=selected/'tests'/folder;state.update(status='failed',layouts={},fixtures={},elf={})
    originals=private/'original-support';originals.mkdir()
    if kind in ('chain','register','controls'):
        args=[builder.tools['python'],pin(fixture/'prepare.py'),pin(selected/'tests/generic/fixture.c')]
        if kind=='controls':args += [pin(selected/'tests/register_run/fixture.c'),originals]
        else:args += [originals/('chain_support.inc'if kind=='chain'else'run_support.inc')]
        pending.extend(originals/name for name in (('run_support.inc','control_support.inc')if kind=='controls'else
            ('chain_support.inc',)if kind=='chain'else('run_support.inc',)))
        _,out,err=run('fixture-support',args,profile='metadata',env=builder.environment)
        need(not err,'unchanged support generator stderr');state['generator']=decode(out)
        expected = ({'run_support.inc':{'bytes':34613,'sha256':PREDECESSORS['controls']},
                     'control_support.inc':{'bytes':30510,'sha256':'bae491633d24aaeb03c59e533d2cb3eae77100d801341d97eb04585309748d7f'}}
                    if kind=='controls'else dict(source_sha256=PREDECESSORS['generic'],source_bytes=34870,
                        generated_sha256=PREDECESSORS[kind],generated_bytes=34630 if kind=='chain' else 34605))
        need(state['generator']==expected,'exact unchanged generator observation')
        support='chain_support.inc'if kind=='chain'else'run_support.inc'
        pending.append(private/support)
        adapted=adapt(originals/support,private/support,kind,pin,binary,state)
        if kind=='controls':
            source=pin(originals/'control_support.inc')
            need(fact(source)=={'bytes':30510,'sha256':'bae491633d24aaeb03c59e533d2cb3eae77100d801341d97eb04585309748d7f'},'unchanged controls support')
            target=private/source.name;pending.append(target)
            with target.open('xb')as f:f.write(source.read_bytes())
            binary(target);pin(target)
    else:
        shadow=private/'include/tests/generic';shadow.mkdir(parents=True)
        pending.append(shadow/'fixture.c')
        adapted=adapt(selected/'tests/generic/fixture.c',shadow/'fixture.c','generic',pin,binary,state)
    templates=recipe(pin(fixture/'build.sh'),'"$cc_bin"')
    need(len(templates)==(2 if kind=='controls'else 1),'exact existing fixture recipe count')
    values={'$cc_bin':builder.tools['cc'],'$source_dir':fixture,'$fixture_dir':fixture,'$selected_dir':selected,
        '$parent_dir':selected.parent,'$decoder_archive':products['archive'],'$output_dir':private}
    if kind=='controls':
        argv=expand(templates[0],values);headers('publisher-headers',argv,builder,pin,run,state)
        compile_retained('publisher-build',argv,run,binary,builder,pending,errors)
        _,out,err=run('publisher-adapter-import',[builder.tools['nm'],'-u',private/'publisher-controls.o'],profile='inspect',env=builder.environment)
        imports=[x.split()[-1]for x in out.splitlines()if x.split()]
        need(not err and imports.count(b'li2_control_raw')==1 and b'li2_step_raw'not in imports,'only publisher object binds named raw-control adapter')
    fixtures={}
    for group in range(4 if kind=='register'else 1):
        argv=expand(templates[-1],dict(values,**{'$group':group}));original=list(argv)
        if kind=='generic':
            needle=str(fixture/'fixture.c');need(argv.count(needle)==1,'one generic source substitution');argv[argv.index(needle)]=str(adapted)
        if kind=='repeat':
            index=next(i for i,x in enumerate(argv)if x.startswith('-I'));argv.insert(index,'-I'+str(private/'include'))
        argv.insert(-2,str(leaf))
        argv,owner,owner_state=compile_owner(kind,group,argv,selected,builder,pin,binary,run,state,pending,errors)
        state.setdefault('recipes',[]).append(dict(original=original,adapted=argv))
        label='header-dependencies'if kind=='repeat'else'fixture-'+str(group)+'-headers'
        required=[adapted]
        deps=headers(label,argv,builder,pin,run,state,required)
        if kind=='generic':need(str(selected/'tests/generic/fixture.c')not in deps,'no unadapted scalar definition consumed')
        compile_retained('fixture-build'if kind=='repeat'else'fixture-'+str(group)+'-build',argv,run,binary,builder,pending,errors)
        path=Path(argv[-1]);fixtures[path.name]=path;state['fixtures'][path.name]=fact(path)
        state['elf'][path.name]=plain_executable(path)
        need(memset_body(path)['body']==body,'final actual helper bytes equal extracted product body')
        inspect_owner(group,owner,path,builder,run,owner_state,primitive_body)
        _,out,err=run('fixture-undefined'if kind=='repeat'else path.name+'-undefined',[builder.tools['nm'],'-u',path],profile='inspect',env=builder.environment)
        need(out==err==b'','no fixture undefined symbols')
        if kind=='generic':
            _,symbols,err=run('memset-symbols',[builder.tools['nm'],'-S','--defined-only',path],profile='inspect',env=builder.environment)
            need(not err,'actual final helper symbol stderr')
            _,disassembly,err=run('memset-disassembly',[builder.tools['objdump'],'-d','-w','-M','att','--disassemble=memset',path],profile='inspect',env=builder.environment)
            need(not err,'actual final helper disassembly stderr')
            state['actual_body']=body_check(path,symbols,disassembly,'fast',symbol_name='memset')
            need(bytes.fromhex(state['actual_body']['code_hex'])==body,'shared actual ABI/body validator binds extracted bytes')
        if kind in ('register','controls'):
            _,out,err=run(path.name+'-layout',[builder.tools['nm'],'-S','--defined-only',path],profile='inspect',env=builder.environment)
            need(not err,'actual record symbols stderr')
            state['layouts'][path.name]=(executable_layout if kind=='register'else control_layout)(path,out)
        if kind=='repeat':
            _,out,err=run('fixture-sections',[builder.tools['readelf'],'-S','-W',path],profile='inspect',env=builder.environment)
            need(not err and b'.debug_info 'in out and b'.debug_abbrev 'in out and b'.debug_line 'in out,'retain actual executable DWARF')
    state['status']='passed';return fixtures,fixture
