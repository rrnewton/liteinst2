#!/usr/bin/env python3
"""Compile actual retired observers/comparators with supplied owner metadata."""
import hashlib,json,os,shlex,sys
from pathlib import Path
assert len(sys.argv)==5 and not sys.flags.optimize
selected,config,output=map(lambda x:Path(x).resolve(),sys.argv[1:4]);cc=sys.argv[4]
assert selected.is_dir() and config.is_dir() and not output.exists()
unit=Path(str(output)+'.c');assert not unit.exists()
fixture=Path(__file__).resolve().parent
for name in ('persistent_group_config.h','linked_epoch_config.h','loop_ro_certificate_config.h'):
    assert (config/name).is_file(),name
inputs={}
def read(path):
    data=path.read_bytes();inputs[str(path)]=dict(bytes=len(data),sha256=hashlib.sha256(data).hexdigest());return data.decode()
def body(source,signature):
    assert source.count(signature)==1,signature
    start=source.index(signature);opening=source.index('{',start);end=opening+1;depth=1
    while depth:depth+=(source[end]=='{')-(source[end]=='}');end+=1
    return source[start:end]+(';' if signature.startswith('struct ') else '')+'\n'
def line(source,prefix):
    rows=[x for x in source.splitlines(keepends=True) if x.startswith(prefix)]
    assert len(rows)==1,prefix
    return rows[0]
def byte_wrapper(source,signature):
    start='#ifdef LI2_SPAN_FAST_BYTES\n'+signature
    assert source.count(start)==1,signature
    first=source.index(start);last=source.index('#endif\n',first)+len('#endif\n')
    return source[first:last]
c=read(selected/'persistent_group_controller.inc');linked=read(selected/'linked_controller.inc')
runtime=read(selected/'runtime_loader.c');lifecycle=read(selected/'lifecycle_loader.c')
span=read(selected/'span_source.inc');group=read(selected/'persistent_group_source.inc')
registry=read(selected/'selected_register_run.inc');bridge=read(selected.parent/'bridge.c')
a=c.index('enum pe_error {');b=c.index('static struct li2_pg_epoch pe;');assert a<b
prefix='#define _GNU_SOURCE\n#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n#include <limits.h>\n#include <fcntl.h>\n#include "persistent_group_runtime.h"\n#include "span_fast_bytes.h"\n'
prefix+=line(lifecycle,'#define PAGE ')+line(runtime,'#define RANGES ')
prefix+=line(lifecycle,'#define OBJECTS ')+line(lifecycle,'#define SEALS ')+line(lifecycle,'enum backing {')
prefix+=body(linked,'struct le_frame {')+body(linked,'struct le_permission {')+c[a:b]
prefix+='static struct li2_pg_epoch pe;\nstatic volatile sig_atomic_t pe_busy;\n'
prefix+=line(lifecycle,'static size_t object_count;')+line(runtime,'static struct li2_fork_range protected[')
prefix+='static size_t protected_count;\n'
prefix+=byte_wrapper(bridge,'void copy(')+byte_wrapper(bridge,'int equal(')
prefix+=body(registry,'static int selected_run_protect_contains(')
for signature in ('static int span_source_page_equal(', 'static int span_source_backing_equal('):
    prefix+=body(span,signature)
for signature in ('static unsigned pgs_loop_page_class(', 'static int pgs_loop_anonymous_backing(',
                  'static int pgs_loop_backing_equal(', 'int li2_pg_source_key_equal('):
    prefix+=body(group,signature)
prefix+='#include "loop_ro_retired.h"\n'
prefix+='static union { struct li2_lrx_record record;unsigned char page[4096]; } bank __attribute__((aligned(4096)));\nstruct li2_pgc_record *li2_pgc_current=&bank.record.base.base.base.base;\n'
prefix+=line(c,'#define PGC_REF(n) (&li2_pgc_current')+line(c,'#define PGC_VALUE(n) __atomic_load_n')
prefix+='#include "loop_ro_reasons_owner.inc"\n#include "loop_ro_retired_owner.inc"\n'
prefix+='#include "'+str(fixture/'oracle.c')+'"\n';unit.write_text(prefix)
recipe=read(selected/'build-persistent-loop-ro-retired.sh').replace('\\\n',' ')
rows=[shlex.split(x) for x in recipe.splitlines() if x.startswith('"$cc_bin" ')]
assert len(rows)==1
macros=[x for x in rows[0] if x.startswith('-DLI2_')]
for name in ('LOOP_RO_RETIRED','LOOP_RO_REASONS','PERSISTENT_GROUP_COUNTERS',
             'PERSISTENT_RETAINED_TWO_COUNTERS','PERSISTENT_LOOP_COUNTERS','PERSISTENT_LOOP_EFFECTS_COUNTERS'):
    assert macros.count('-DLI2_'+name+'=1')==1
assert not any('DIFFERENTIAL' in x or 'CAPTURE' in x for x in macros)
argv=[cc,'-std=gnu11','-O2','-g','-fno-pie','-no-pie','-fno-builtin','-fno-tree-loop-distribute-patterns','-fno-tree-vectorize','-mgeneral-regs-only','-Wall','-Wextra','-Werror',*macros,'-include',str(config/'loop_ro_certificate_config.h'),'-I'+str(config),'-I'+str(selected),'-I'+str(selected.parent),'-MD','-MF',str(output)+'.d',str(unit),'-Wl,-z,now,-z,relro,-z,noexecstack,--no-undefined','-o',str(output)]
for name in ('loop_ro_reasons.h','loop_ro_reasons_owner.inc','loop_ro_retired.h',
             'loop_ro_retired_owner.inc','persistent_active_domain_types.inc','span_fast_bytes.h'):
    read(selected/name)
read(fixture/'oracle.c')
for name in ('persistent_group_config.h','linked_epoch_config.h','loop_ro_certificate_config.h'):read(config/name)
Path(str(output)+'.source.json').write_text(json.dumps(dict(scope='supplied-metadata actual retired observer/comparator only',inputs=inputs,argv=argv),sort_keys=True)+'\n')
os.execvp(cc,argv)
