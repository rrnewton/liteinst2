#!/usr/bin/env python3
"""Compile the actual observer with exact source types and a controlled gate table."""
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
    return source[start:end]+';\n'
c=read(selected/'persistent_group_controller.inc');linked=read(selected/'linked_controller.inc')
a=c.index('enum pe_error {');b=c.index('static struct li2_pg_epoch pe;');assert a<b
prefix='#define _GNU_SOURCE\n#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n#include <limits.h>\n#include "persistent_group_runtime.h"\n#define PAGE 4096UL\n#define RANGES 128U\n'
prefix+=body(linked,'struct le_frame {')+body(linked,'struct le_permission {')+c[a:b]
prefix+='static struct li2_pg_epoch pe;\n#include "loop_ro_reasons.h"\n'
prefix+='static union { struct li2_lrr_record record;unsigned char page[4096]; } bank __attribute__((aligned(4096)));\nstruct li2_pgc_record *li2_pgc_current=&bank.record.base.base.base;\n#include "loop_ro_reasons_owner.inc"\n'
start=c.index('if(RCC_TEST(0,');end=c.index(') {\n        pe_need(ped_permitted()',start)
expression=c[start+3:end]
# Retain the exact operator/preprocessor structure; substitute only supplied
# predicate return values. This is not an alternative runtime predicate.
parts=[];position=0;bits=[]
while True:
    i=expression.find('RCC_TEST(',position)
    if i<0:parts.append(expression[position:]);break
    opening=i+len('RCC_TEST(');comma=expression.index(',',opening);bit=int(expression[opening:comma])
    depth=1;j=comma+1
    while depth:depth+=(expression[j]=='(')-(expression[j]==')');j+=1
    parts.extend((expression[position:i],f'RCC_TEST({bit},test_gate({bit}))'));bits.append(bit);position=j
assert bits==[0,1,2,3,4,4,5,6,7,8,9]
expression=''.join(parts)
plain='#define RCC_TEST(bit,value) (value)';observed='#define RCC_TEST(bit,value) lrr_test((bit),!!(value))'
assert c.count(plain)==c.count(observed)==1
prefix+='static int test_gate(unsigned);\n'+plain+'\nstatic int original_decision(void) { return !!('+expression+'); }\n#undef RCC_TEST\n'+observed+'\nstatic int observed_decision(void) { return !!('+expression+'); }\n#undef RCC_TEST\n'
prefix+='#include "'+str(fixture/'oracle.c')+'"\n';unit.write_text(prefix)
recipe=read(selected/'build-persistent-loop-ro-reasons.sh').replace('\\\n',' ')
rows=[shlex.split(x) for x in recipe.splitlines() if x.startswith('"$cc_bin" ')]
assert len(rows)==1
macros=[x for x in rows[0] if x.startswith('-DLI2_')]
for name in ('LOOP_RO_REASONS','PERSISTENT_GROUP_COUNTERS','PERSISTENT_RETAINED_TWO_COUNTERS','PERSISTENT_LOOP_COUNTERS','PERSISTENT_LOOP_EFFECTS_COUNTERS'):
    assert macros.count('-DLI2_'+name+'=1')==1
assert not any('DIFFERENTIAL' in x or 'CAPTURE' in x for x in macros)
argv=[cc,'-std=gnu11','-O2','-g','-fno-pie','-no-pie','-fno-builtin','-fno-tree-loop-distribute-patterns','-fno-tree-vectorize','-mgeneral-regs-only','-Wall','-Wextra','-Werror',*macros,'-include',str(config/'loop_ro_certificate_config.h'),'-I'+str(config),'-I'+str(selected),'-I'+str(selected.parent),'-MD','-MF',str(output)+'.d',str(unit),'-Wl,-z,now,-z,relro,-z,noexecstack,--no-undefined','-o',str(output)]
for name in ('loop_ro_reasons.h','loop_ro_reasons_owner.inc','persistent_active_domain_types.inc'):read(selected/name)
read(fixture/'oracle.c')
for name in ('persistent_group_config.h','linked_epoch_config.h','loop_ro_certificate_config.h'):read(config/name)
Path(str(output)+'.source.json').write_text(json.dumps(dict(scope='supplied-metadata actual observer only',inputs=inputs,argv=argv,expression=expression),sort_keys=True)+'\n')
os.execvp(cc,argv)
