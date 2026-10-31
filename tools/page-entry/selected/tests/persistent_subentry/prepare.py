#!/usr/bin/env python3
"""Extract unchanged production bodies; scripted observations are in oracle.c."""
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
s=read('persistent_group_source.inc');life=read('lifecycle_loader.c')
linked=read('linked_controller.inc');span=read('span_source.inc')
out='''#define _GNU_SOURCE
#include <assert.h>
#include <setjmp.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <fcntl.h>
#include "persistent_group_runtime.h"
#define RANGES 128U
'''
for key in ('PAGE ','RECORDS ','OBJECTS ','SEALS '):
    out+=next(x+'\n' for x in life.splitlines() if x.startswith('#define '+key))
out+=next(x+'\n' for x in life.splitlines() if x.startswith('enum backing '))
out+=structure(life,'owned_page')+structure(life,'transaction')
out+='''static struct owned_page records[RECORDS];
static size_t used,object_count;
static int active;
static struct transaction tx;
'''
out+=structure(linked,'le_frame')+structure(linked,'le_permission')
out+=c[c.index('enum pe_error {'):c.index('static struct li2_pg_epoch pe;')]
out+='''static struct li2_pg_epoch pe;
static volatile sig_atomic_t pe_busy,pe_active;
static const unsigned char pe_archive[32]={1},pe_policy[32]={2};
static struct li2_fork_range protected[RANGES];
static size_t protected_count;
#define PE_SLOT(field) (pe.retained[pe.selected_slot].field)
static int equal(const void *a,const void *b,size_t n) {return !memcmp(a,b,n);}
/* The sole failure transport substitute: actual code/detail are asserted. */
static jmp_buf failed;
static unsigned failure_code;
static long failure_detail;
static void pe_need(int yes,unsigned code,long detail) {
    if(!yes){failure_code=code;failure_detail=detail;longjmp(failed,1);}
}
static int ptr_storage(void);
static int ptr_selected(void);
static int pda_permitted(unsigned);
'''
out+=body(read('selected_register_run.inc'),'static int selected_run_protect_contains(')
for name in ('static uintptr_t pg_extent(','static size_t pg_extent_bytes(',
             'static int pg_layout_equal(','static int pg_query_complete(','static int pg_proof_query_complete(',
             'static int pg_proof_permission_complete(','static int pg_closed(',
             'static int pe_registered_storage(','static const struct pe_payload *pe_payload('):out+=body(c,name)
out+=body(c,'static struct li2_pg_layout pg_layout(',2)
for name in ('unsigned li2_pg_owner_phase(','static int pe_token(',
             'const struct li2_pg_layout *li2_pg_owner_layout(',
             'static unsigned ped_bank_for(uintptr_t pc)'):out+=body(c,name)
for name in ('static int span_source_page_equal(','static int span_source_backing_equal('):out+=body(span,name)
for name in ('int li2_pg_source_key_equal(','int li2_pgd_source_pair_equal(',
             'int li2_pg_source_pair_advisory('):out+=body(s,name)
out+=s[s.index('static struct {'):s.index('} pg_source;')+len('} pg_source;')]+'\n'
for name in ('static int pgs_layout(','static int pgs_layout_bound(','static int pgs_token(',
             'const struct li2_pg_sources *li2_pg_source_view('):out+=body(s,name)
out+='''static struct li2_pg_rseq_progress pg_rseq;
'''
out+=body(read('persistent_group_rseq.inc'),'const struct li2_pg_rseq_progress *li2_pg_rseq_progress(')
out+='#include "persistent_subentry_source.inc"\n#include "persistent_retained_two.inc"\n'
for name in ('static unsigned pda_bank(','static int pda_query(','static int pda_zero(',
             'static int pda_receipt(','static int pda_permitted(','static void pda_claim(',
             'static int pda_registration('):out+=body(d,name)
out+='#include "persistent_subentry.inc"\n#include "tests/persistent_subentry/oracle.c"\n'
output.write_text(out)
