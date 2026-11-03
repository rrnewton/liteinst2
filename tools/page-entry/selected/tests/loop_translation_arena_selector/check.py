#!/usr/bin/env python3
"""Compile the actual advisory selector body against scripted dependencies.

This checks selection and fail-closed traversal, not publication, physical
permissions, execution admission, or native correctness. The caller supplies
normal command bounds; no production predicate or runtime source is rewritten.
"""
import argparse
from pathlib import Path
import subprocess

HARNESS = r'''
#include <assert.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#define PTR_NODE_COUNT 12U
#define LI2_PTR_SLOTS 8U
/* ACTUAL_ERRORS */
_Static_assert(PE_STATE==3300 && PE_PUBLICATION==3303 && PE_RELEASE==3309,"actual error identities");
struct pe_sub_choice { unsigned slot,bank,subentry;uintptr_t page[2]; };
struct li2_pgs_target { uintptr_t root,page[2]; };
struct plan { unsigned node; };
struct pe_payload { struct plan plan;struct { uintptr_t entry; } source; };
struct li2_ptr_slot {
    struct { unsigned installed;uintptr_t generated; } generation;
    struct { struct { uintptr_t entry; } source; } publication;
    const void *proof;
    struct { uintptr_t generated; } banks[2];
    uint64_t last_completed;
};
static struct li2_ptr_slot nodes[PTR_NODE_COUNT];
static struct pe_payload payloads[PTR_NODE_COUNT];
static unsigned closed[PTR_NODE_COUNT],advisory[PTR_NODE_COUNT];
static unsigned closed_calls[PTR_NODE_COUNT],lookup_calls[PTR_NODE_COUNT];
static int found[PTR_NODE_COUNT];
static uintptr_t target_root[PTR_NODE_COUNT];
static struct pe_sub_choice active_choice;
static jmp_buf failure;
static unsigned error_code;
static long error_detail;
#define PTR_NODE_AT(i) nodes[i]
static void pe_need(int value,unsigned code,long detail) {
    if(!value){error_code=code;error_detail=detail;longjmp(failure,1);}
}
static int pe_sub_choose(uintptr_t pc,struct pe_sub_choice *out) {
    (void)pc;*out=active_choice;return 1;
}
static unsigned ptr_node_index(unsigned slot){return slot<LI2_PTR_SLOTS?slot:PTR_NODE_COUNT;}
static int lta_node_bound(unsigned node){return node<LI2_PTR_SLOTS?(int)node:-1;}
static int lta_closed_value(unsigned node){++closed_calls[node];return closed[node];}
static int li2_pgs_head_lookup(const struct plan *plan,uintptr_t pc,struct li2_pgs_target *out) {
    (void)pc;unsigned node=plan->node;++lookup_calls[node];
    *out=(struct li2_pgs_target){target_root[node],{node,0}};return found[node];
}
static int li2_pgs_source_pair_advisory(uintptr_t pc,const uintptr_t pages[2]) {
    (void)pc;return advisory[pages[0]];
}
/* ACTUAL_SELECTOR */
static void reset(void) {
    memset(nodes,0,sizeof nodes);memset(payloads,0,sizeof payloads);
    memset(closed_calls,0,sizeof closed_calls);memset(lookup_calls,0,sizeof lookup_calls);
    memset(found,0,sizeof found);memset(target_root,0,sizeof target_root);
    for(unsigned i=0;i<PTR_NODE_COUNT;i++){closed[i]=advisory[i]=1;payloads[i].plan.node=i;nodes[i].proof=&payloads[i];}
    active_choice=(struct pe_sub_choice){0,0,0,{0,0}};error_code=0;error_detail=0;
}
static void node(unsigned i,uintptr_t root,unsigned bank) {
    nodes[i].generation.installed=1;nodes[i].publication.source.entry=root;
    nodes[i].banks[0].generated=0x10000+2*i*4096;
    nodes[i].banks[1].generated=nodes[i].banks[0].generated+4096;
    nodes[i].generation.generated=nodes[i].banks[bank].generated;
    payloads[i].source.entry=target_root[i]=root;found[i]=1;
}
static void choose(unsigned want,unsigned bank,unsigned subentry) {
    struct pe_sub_choice out;unsigned selected=PTR_NODE_COUNT;
    assert(!setjmp(failure));assert(lta_choose(0x2200,&out,&selected));
    assert(selected==want && out.bank==bank && out.subentry==subentry);
    if(want>=LI2_PTR_SLOTS && found[want])assert(out.page[0]==want && out.page[1]==0);
}
static void refuse(unsigned code,long detail) {
    struct pe_sub_choice out;unsigned selected=PTR_NODE_COUNT;
    if(!setjmp(failure)){(void)lta_choose(0x2200,&out,&selected);assert(!"invalid candidate accepted");}
    assert(error_code==code && error_detail==detail);
}
int main(void) {
    /* Different immutable roots share the same requested subentry. */
    reset();node(8,0x2100,0);node(9,0x2180,1);choose(8,0,1);
    assert(closed_calls[8]==1 && closed_calls[9]==1 && lookup_calls[9]==1);
    /* Exact root outranks an earlier head; later heads cannot overwrite it. */
    reset();node(8,0x2100,0);node(9,0x2200,1);node(10,0x2180,0);choose(9,1,0);
    assert(closed_calls[10]==1 && lookup_calls[10]==1);
    reset();node(8,0x2200,0);node(9,0x2180,1);choose(8,0,0);
    /* Duplicate roots retain the original owner-state refusal. */
    reset();node(8,0x2200,0);node(9,0x2200,1);refuse(PE_STATE,9234);
    /* Every later eligible candidate is validated, including its own bank. */
    reset();node(8,0x2100,0);node(9,0x2180,1);nodes[9].generation.generated=1;refuse(PE_STATE,9235);
    reset();node(8,0x2100,0);node(9,0x2180,1);closed[9]=0;refuse(PE_RELEASE,9232);
    reset();node(8,0x2100,0);node(9,0x2180,1);found[9]=-1;refuse(PE_PUBLICATION,9233);
    reset();node(8,0x2100,0);node(9,0x2180,1);target_root[9]=0x2190;refuse(PE_STATE,9235);
    reset();node(8,0x2100,0);node(9,0x2180,1);advisory[8]=0;choose(9,1,1);
    /* The existing active-root and active-head precedence is unchanged. */
    reset();active_choice=(struct pe_sub_choice){2,1,1,{0,0}};node(8,0x2200,0);choose(2,1,1);assert(!closed_calls[8]);
    reset();active_choice=(struct pe_sub_choice){2,1,0,{0,0}};node(2,0x2200,1);node(8,0x2100,0);choose(2,1,0);assert(!closed_calls[8]);
    /* No matching head retains unused-first and oldest-inactive policy. */
    reset();node(0,0x2100,0);choose(8,0,0);
    reset();node(0,0x2100,0);nodes[0].last_completed=10;
    for(unsigned i=8;i<12;i++){node(i,0x2000+i,0);found[i]=0;nodes[i].last_completed=i==9?1:2;}
    choose(9,0,0);
    puts("ARENA_SELECTOR cases=13 actual_body=1 advisory_only=1");return 0;
}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('selected', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--cc', default='cc')
    args = parser.parse_args()
    source = (args.selected / 'persistent_subentry.inc').read_text()
    begin = 'static int lta_choose('
    end = '\n#endif\nstatic int pe_sub_candidate('
    if source.count(begin) != 1 or source.count(end) != 1:
        raise ValueError('one complete actual arena selector at its original source boundary')
    body = source[source.index(begin):source.index(end)]
    if body.count('{') != body.count('}') or not body.endswith('}'):
        raise ValueError('complete actual selector function body')
    generated = args.output.with_suffix('.c')
    if args.output.exists() or generated.exists():
        raise ValueError('fresh output and generated source paths')
    controller = (args.selected / 'persistent_group_controller.inc').read_text()
    marker = 'enum pe_error {'
    if controller.count(marker) != 1:
        raise ValueError('one actual persistent-controller error enum')
    at = controller.index(marker)
    errors = controller[at:controller.index('};', at) + 2]
    generated.write_text(HARNESS.replace('/* ACTUAL_SELECTOR */', body)
                         .replace('/* ACTUAL_ERRORS */', errors))
    subprocess.run([args.cc, '-std=gnu11', '-O2', '-Wall', '-Wextra', '-Werror',
                    str(generated), '-o', str(args.output)], check=True)
    subprocess.run([str(args.output.resolve())], check=True)


if __name__ == '__main__':
    main()
