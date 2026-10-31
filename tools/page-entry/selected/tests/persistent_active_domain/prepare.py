#!/usr/bin/env python3
"""Extract actual protected-state predicates, not substitute authorities."""
from pathlib import Path
import sys
assert len(sys.argv)==3
selected=Path(sys.argv[1]).resolve();output=Path(sys.argv[2]);assert not output.exists()
def read(name):return (selected/name).read_text()
def body(source,signature,expected=1):
    assert source.count(signature)==expected,(signature,source.count(signature))
    start=source.index(signature);opening=source.index('{',start);depth=1;end=opening+1
    while depth:
        depth+=(source[end]=='{')-(source[end]=='}');end+=1
    return source[start:end]+'\n'
def structure(source,name):return body(source,'struct '+name+' {').rstrip()+';\n'
c=read('persistent_group_controller.inc');d=read('persistent_active_domain.inc')
linked=read('linked_controller.inc');span=read('span_source.inc');retained=read('persistent_retained_two.inc')
out='''#define _GNU_SOURCE
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
out+=next(x+'\n' for x in read('lifecycle_loader.c').splitlines() if x.startswith('#define SEALS '))
out+=structure(linked,'le_frame')+structure(linked,'le_permission')
out+=c[c.index('enum pe_error {'):c.index('static struct li2_pg_epoch pe;')]
out+='''static struct li2_pg_epoch pe;
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
static int pda_permitted(unsigned);
static int pe_permission(uintptr_t,size_t,int,struct le_permission *);
'''
out+=body(read('selected_register_run.inc'),'static int selected_run_protect_contains(')
for name in ('static uintptr_t pg_extent(','static size_t pg_extent_bytes(',
             'static int pg_layout_equal(','static int pg_query_complete(','static int pg_proof_query_complete(',
             'static int pg_proof_permission_complete(','static int pg_closed(',
             'static unsigned char pg_code_byte(','static int pe_registered_storage(',
             'static const struct pe_payload *pe_payload(','static int pe_bytes('):out+=body(c,name)
out+=body(c,'static struct li2_pg_layout pg_layout(',2) # first is the explicit domain branch
for name in ('static int span_source_page_equal(','static int span_source_backing_equal('):out+=body(span,name)
out+=body(read('persistent_group_source.inc'),'int li2_pg_source_key_equal(')
out+=body(read('persistent_group_source.inc'),'int li2_pgd_source_pair_equal(')
out+='#include "persistent_retained_two.inc"\n'
for name in ('static unsigned pda_bank(','static int pda_query(','static int pda_zero(',
             'static int pda_receipt(','static int pda_permitted(','static void pda_claim(',
             'static int pda_directory_seal(','static int pda_directory_equal('):out+=body(d,name)
# The exact cell-selection block is also exercised; no copied lookalike gate.
bind=body(d,'static int pda_bind(')
a=bind.index('    for(unsigned i=0;i<LI2_PGD_RECEIPTS;i++) {')
b=bind.index('    w->bound=1;',a)
out+='static int choose_receipt(void) {\n    struct pda_work *w=&pe.domain.work;\n'+bind[a:b]+'    return 0;\n}\n'
preentry=body(d,'static int pda_preentry(')
a=preentry.index('    member=LI2_PGD_MEMBERS;')
b=preentry.index('    /* Only after savedPC',a)
out+='static int recovery_member(uintptr_t pc) {\n    struct pda_work *w=&pe.domain.work;unsigned member;\n'+preentry[a:b]+'    return (int)member;\n}\n'
out+='#include "tests/persistent_active_domain/authority.c"\n'
output.write_text(out)
