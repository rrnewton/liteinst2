"""Pure exact adapter of the frozen product C link; never executes commands."""
import hashlib,shlex
from pathlib import Path

ROOT=Path(__file__).resolve().parents[5]
HERE=Path(__file__).resolve().parent
VIEW=ROOT
RECIPE=VIEW/'tools/page-entry/selected/build-oneshot.sh'
RECIPE_SHA='3ae6dfa945f27904ffdece29d8e0b5a79a697931d3b2ba5b9710412ad617e8f6'
RENAMES={name:'li2_fixture_product_'+name.removeprefix('li2_oneshot_') for name in
         ('li2_oneshot_initialize','li2_oneshot_nx','li2_oneshot_ud','li2_oneshot_abort_close')}

def need(value,label):
    if not value:raise ValueError(label)

def commands(cc,archive,output):
    """Return exact owner/object, link and compiler-M argument vectors.

    Only the unchanged owner TU receives entry-name renames. Every other
    production TU calls the fixture interposer through its original symbol.
    The controller, Rust archive and lifecycle receive no test definitions.
    """
    raw=RECIPE.read_bytes();need(hashlib.sha256(raw).hexdigest()==RECIPE_SHA,'frozen product recipe')
    text=raw.decode().replace('\\\n',' ')
    begin=text.index('"$cc_bin" -std=gnu11 -O2 -g -nostdlib -shared')
    end=text.index('\n"$cc_bin"',begin+1)
    args=shlex.split(text[begin:end]);need(args[0]=='$cc_bin','actual product compiler')
    substitutions={'$source_dir':str(VIEW/'tools/page-entry/selected'),
                   '$parent_dir':str(VIEW/'tools/page-entry'),'$output_dir':str(ROOT/'target/page-entry/oneshot')}
    args=[str(cc)]+[next((x.replace(k,v)for k,v in substitutions.items()if k in x),x)for x in args[1:]]
    sources=[x for x in args if x.endswith(('.c','.S'))]
    owner=str(VIEW/'tools/page-entry/selected/oneshot.c')
    need(sources.count(owner)==1 and args[-2:]==['-o',str(ROOT/'target/page-entry/oneshot/bridge-oneshot.so')],
         'exact product owner and output')
    flags=args[1:args.index(sources[0])]
    frontend=[x for x in flags if x!='-shared' and not x.startswith('-Wl,')]
    rename=['-D'+k+'='+v for k,v in RENAMES.items()]
    obj=output/'owner.o';bridge=output/'bridge-failure.so'
    compile_owner=[str(cc),*frontend,*rename,'-c',owner,'-o',str(obj)]
    link=list(args);link[link.index(owner)]=str(obj)
    old_archive=str(ROOT/'target/page-entry/oneshot/decoder.a')
    need(link.count(old_archive)==1,'actual frozen Rust archive operand')
    link[link.index(old_archive):link.index(old_archive)+1]=[str(HERE/'fixture.c'),str(archive)]
    link[link.index(sources[0]):link.index(sources[0])]=['-I'+str(HERE)]
    link[-1]=str(bridge)
    dependencies=[]
    for index,source in enumerate(sources+[str(HERE/'fixture.c')]):
        extra=rename if source==owner else []
        dependencies.append([str(cc),*frontend,'-I'+str(HERE),*extra,'-M','-MT','li2_'+str(index),source])
    return dict(owner=compile_owner,link=link,dependencies=dependencies,
                outputs=[str(obj),str(bridge)],product_sources=sources)
