#!/usr/bin/env python3
"""Build one pure TU from the actual runtime types and predicate bodies.

No candidate import. No copied production body or relaxed predicate substitute.
The caller records the selected source inputs and compiler dependencies.
"""
from pathlib import Path
import re
import sys
assert len(sys.argv)==3
selected=Path(sys.argv[1]).resolve()
output=Path(sys.argv[2])
assert not output.exists()
def read(name):
    return (selected/name).read_text()
def body(source,signature):
    assert source.count(signature)==1,signature
    start=source.index(signature);opening=source.index('{',start)
    depth=1;end=opening+1
    while depth:
        depth+=(source[end]=='{')-(source[end]=='}');end+=1
    return source[start:end]+'\n'
def struct(source,name):
    text=body(source,'struct '+name+' {')
    assert source[source.index(text.rstrip())+len(text.rstrip())]==';'
    return text.rstrip()+';\n'
controller=read('persistent_group_controller.inc')
linked=read('linked_controller.inc')
span=read('span_source.inc')
start=controller.index('enum pe_error {')
end=controller.index('static struct li2_pg_epoch pe;')
result='''#define _GNU_SOURCE
#include <assert.h>
#include <setjmp.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <fcntl.h>
#include "persistent_group_runtime.h"
#define PAGE 4096UL
#define RANGES 128U
'''
result+=next(line+'\n'for line in read('lifecycle_loader.c').splitlines()if line.startswith('#define SEALS '))
result+=struct(linked,'le_frame')+struct(linked,'le_permission')
result+=controller[start:end]
result+='''static struct li2_pg_epoch pe;
static volatile sig_atomic_t pe_busy,pe_active;
static const unsigned char pe_archive[32]={1},pe_policy[32]={2};
static struct li2_fork_range protected[RANGES];
static size_t protected_count;
#define PE_SLOT(field) (pe.retained[pe.selected_slot].field)
static int equal(const void *a,const void *b,size_t n) {return !memcmp(a,b,n);}
static jmp_buf failed;
static unsigned failure_code;
static long failure_detail;
static void pe_need(int yes,unsigned code,long detail) {
    if(!yes){failure_code=code;failure_detail=detail;longjmp(failed,1);}
}
static int ptr_storage(void);
'''
result+=body(read('selected_register_run.inc'),'static int selected_run_protect_contains(')
for name in ('static uintptr_t pg_extent(','static size_t pg_extent_bytes(','static struct li2_pg_layout pg_layout(',
             'static int pg_layout_equal(','static int pg_query_complete(','static int pg_proof_query_complete(',
             'static int pg_proof_permission_complete(','static int pg_closed(',
             'static unsigned char pg_code_byte(',
             'static int pe_registered_storage(','static const struct pe_payload *pe_payload(',
             'static int pe_bytes('):
    if name=='static struct li2_pg_layout pg_layout(':
        marker='#ifdef LI2_PERSISTENT_ACTIVE_DOMAIN\n'
        assert controller.count(marker+name)==1,'one explicit active-domain layout alternative'
        first=controller.index(marker+name)
        last=controller.index('\n#endif\n',first)+len('\n#endif\n')
        guarded=controller[first:last]
        active,original=guarded[len(marker):-len('#endif\n')].split('#else\n')
        assert body(active,name)==active and body(original,name)==original
        result+=guarded
    else:
        result+=body(controller,name)
for name in ('static int span_source_page_equal(','static int span_source_backing_equal('):result+=body(span,name)
result+=body(read('persistent_group_source.inc'),'int li2_pg_source_key_equal(')
result+='#include "persistent_retained_two.inc"\n'
result+='#include "tests/persistent_retained_two/metadata.c"\n'
output.write_text(result)
