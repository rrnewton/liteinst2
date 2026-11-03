#!/usr/bin/env python3
"""Compile actual arena capacity bodies against scripted dependencies.

These finite boundary checks grant no source, physical, admission, claim, or
native authority. The caller supplies ordinary command bounds. Both the
12-node default and explicit 128-node representation are exercised.
"""
import argparse
from pathlib import Path
import re
import subprocess

HARNESS = r'''
#include <assert.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#define LI2_LOOP_TRANSLATION_ARENA 1
#define LI2_PTR_SLOTS 8U
#define LI2_LTA_NODES PTR_NODE_COUNT
/* Physical operations below are scripted, not permission evidence. */
#define PAGE 4096U
#define PE_PROOF_BYTES PAGE
/* ACTUAL_ERRORS */
/* ACTUAL_PHASES */
_Static_assert(PE_STATE==3300 && PE_PUBLICATION==3303 && PE_RELEASE==3309,"actual error identities");
/* ACTUAL_TRIAL_TYPE */
struct lta_binding { uint64_t generation;unsigned node,reserved; };
struct li2_pgd_view { unsigned count;struct { struct { unsigned slot; } identity; } member[8]; };
struct pda_work { unsigned bound;struct li2_pgd_view view; };
struct plan { unsigned node; };
struct pe_payload { struct plan plan; };
struct li2_ptr_slot {
    struct { unsigned index;uint64_t generation; } identity;
    struct { unsigned installed;uint64_t ready_generation; } generation;
    size_t registry_count;uint64_t registry[2];const void *proof;
    uint64_t last_completed;unsigned char publication[PAGE];
};
static struct li2_ptr_slot nodes[PTR_NODE_COUNT];
static struct pe_payload payloads[PTR_NODE_COUNT];
static struct {
    unsigned initialized,registered,selected_slot,selected_bank,consumed,warm,resuming;
    struct { unsigned phase; } p;
    struct { unsigned initialized;uint64_t next_binding;struct lta_binding binding[8]; } arena;
    struct { struct pda_work work; } domain;
} pe;
static struct { struct { unsigned ro_initialized,ro_writable_mask; } state; } sg_owner;
static struct { uint64_t mirror_opens,mirror_seals; } lrc_observed;
static unsigned pe_busy,pe_active,pe_failing,handling;
static unsigned topology,stored[PTR_NODE_COUNT],closed[PTR_NODE_COUNT],registered_node[PTR_NODE_COUNT];
static unsigned reachable_after[PTR_NODE_COUNT],closed_calls[PTR_NODE_COUNT],moves,moved_node,moved_slot;
static unsigned permission_calls,raw_calls,readonly_calls,cases;
static size_t protected_count=2;
static uint64_t protected[2]={11,22};
static jmp_buf failure;
static unsigned error_code;static long error_detail;
#define PTR_NODE_AT(i) nodes[i]
#define PTR_SLOT_AT(i) nodes[ptr_node_index(i)]
#define PE_SLOT(f) (PTR_SLOT_AT(pe.selected_slot).f)
#define SBC_NODE_INDEX ptr_node_index(pe.selected_slot)
/* ACTUAL_WRITER_MACRO */
static void pe_need(int value,unsigned code,long detail) {
    if(!value){error_code=code;error_detail=detail;longjmp(failure,1);}
}
static int equal(const void *a,const void *b,size_t n){return !memcmp(a,b,n);}
static int lta_topology_live(void){return topology;}
static int ptr_node_storage(unsigned node){assert(node<PTR_NODE_COUNT);return stored[node];}
/* ACTUAL_NODE_INDEX */
/* ACTUAL_STORAGE */
/* ACTUAL_NODE_BOUND */
static int lta_closed_value(unsigned node){++closed_calls[node];return closed[node];}
static int pda_registration(const struct pe_payload *p){return registered_node[p->plan.node];}
static int lc8_reachable(const struct li2_pgd_view *v,const struct plan *p){return v->count>=reachable_after[p->node];}
static int lta_move(unsigned slot,unsigned node){++moves;moved_slot=slot;moved_node=node;return 0;}
/* ACTUAL_PROPOSE */
/* ACTUAL_SELECTED_NODE */
static int lrc_live(void){return topology && !sg_owner.state.ro_writable_mask;}
static int sbc_unpublished(void){return 1;}
static int pe_identity(void){return 1;}
static int sg_permission(int prot){assert(prot==PROT_READ || prot==(PROT_READ|PROT_WRITE));++permission_calls;return 0;}
static int lrc_readonly(uintptr_t at,size_t bytes){assert(at && bytes==PE_PROOF_BYTES);++readonly_calls;return 0;}
static long raw(long number,long a,long b,long c,long d,long e,long f){
    assert(number==SYS_mprotect && a && b==PE_PROOF_BYTES && !d && !e && !f);
    assert(c==PROT_READ || c==(PROT_READ|PROT_WRITE));++raw_calls;return 0;
}
/* ACTUAL_MIRROR_BEGIN */
/* ACTUAL_MIRROR_END */
static void reset(void) {
    memset(&pe,0,sizeof pe);memset(nodes,0,sizeof nodes);memset(&sg_owner,0,sizeof sg_owner);
    memset(&lrc_observed,0,sizeof lrc_observed);memset(closed_calls,0,sizeof closed_calls);
    pe.initialized=pe.registered=pe.arena.initialized=topology=pe_busy=handling=1;
    pe.arena.next_binding=8;pe.p.phase=LI2_PG_BOUND;pe_active=pe_failing=0;
    pe.domain.work.view.count=1;pe.domain.work.view.member[0].identity.slot=0;
    for(unsigned i=0;i<PTR_NODE_COUNT;i++) {
        stored[i]=closed[i]=registered_node[i]=reachable_after[i]=1;
        payloads[i].plan.node=i;nodes[i].proof=&payloads[i];nodes[i].identity.index=8;
        nodes[i].identity.generation=100U+i;nodes[i].registry_count=protected_count;
        memcpy(nodes[i].registry,protected,sizeof protected);nodes[i].last_completed=i;
        if(i<8){pe.arena.binding[i]=(struct lta_binding){i+1U,i,0};nodes[i].identity.index=i;}
    }
    sg_owner.state.ro_initialized=1;moves=permission_calls=raw_calls=readonly_calls=0;
    error_code=0;error_detail=0;
}
static void bind(unsigned slot,unsigned node) {
    nodes[pe.arena.binding[slot].node].identity.index=8;
    pe.arena.binding[slot].node=node;nodes[node].identity.index=slot;
}
static void storage_cases(unsigned node) {
    reset();bind(7,node);assert(lta_storage());++cases;
    pe.arena.binding[6].node=node;assert(!lta_storage());++cases;
    reset();bind(7,node);stored[node]=0;assert(!lta_storage());++cases;
    reset();bind(7,node);pe.arena.binding[7].generation=pe.arena.binding[6].generation;
    assert(!lta_storage());++cases;
}
static void proposal_cases(unsigned node) {
    struct lta_peer_trials tried={0};
    reset();nodes[node].generation.installed=1;
    assert(lta_propose_peer(&tried)==1 && moved_node==node && moved_slot==1 && moves==1 && tried.node[node]==1);++cases;
    assert(lta_propose_peer(&tried)==8 && moves==1);++cases;
    reset();memset(&tried,0,sizeof tried);nodes[node].generation.installed=1;reachable_after[node]=2;
    assert(lta_propose_peer(&tried)==8 && !moves && !tried.node[node]);++cases;
    pe.domain.work.view.count=2;pe.domain.work.view.member[1].identity.slot=1;
    assert(lta_propose_peer(&tried)==2 && moved_node==node && moves==1 && tried.node[node]==1);++cases;
    reset();memset(&tried,0,sizeof tried);nodes[node].generation.installed=1;nodes[node].registry[0]=99;
    assert(lta_propose_peer(&tried)==8 && !moves && !tried.node[node]);++cases;
    nodes[node].registry[0]=protected[0];assert(lta_propose_peer(&tried)==1 && moved_node==node);++cases;
    reset();memset(&tried,0,sizeof tried);nodes[node].generation.installed=1;closed[node]=0;
    if(!setjmp(failure)){(void)lta_propose_peer(&tried);assert(!"closed predicate bypassed");}
    assert(error_code==PE_RELEASE && error_detail==9236 && !moves && !tried.node[node]);++cases;
}
static void writer_cases(unsigned node) {
    reset();bind(0,node);pe.p.phase=LI2_PG_PUBLISHING;pe.consumed=1;
    assert(!lrc_mirror_begin());unsigned writer=sg_owner.state.ro_writable_mask;
#ifdef LI2_LOOP_TRANSLATION_ARENA_CAPACITY
    assert(writer==node+1U);unsigned other=node^32U;
#else
    assert(writer==(1U<<node));unsigned other=node==8?9:8;
#endif
    assert(lrc_observed.mirror_opens==1 && permission_calls==2 && raw_calls==1);++cases;
    assert(lrc_mirror_begin()==PE_STATE && permission_calls==2 && raw_calls==1);++cases;
    bind(0,other);assert(lrc_mirror_end()==PE_STATE && sg_owner.state.ro_writable_mask==writer &&
        permission_calls==2 && raw_calls==1 && !readonly_calls);++cases;
    bind(0,node);assert(!lrc_mirror_end() && !sg_owner.state.ro_writable_mask &&
        lrc_observed.mirror_seals==1 && permission_calls==4 && raw_calls==2 && readonly_calls==1);++cases;
}
int main(void) {
#ifdef LI2_LOOP_TRANSLATION_ARENA_CAPACITY
    static const unsigned boundary[]={31,32,63,64,127};
    _Static_assert(PTR_NODE_COUNT==128,"explicit capacity harness");
#else
    static const unsigned boundary[]={8,9,10,11};
    _Static_assert(PTR_NODE_COUNT==12,"original capacity harness");
#endif
    for(unsigned i=0;i<sizeof boundary/sizeof boundary[0];i++) {
        storage_cases(boundary[i]);proposal_cases(boundary[i]);writer_cases(boundary[i]);
    }
    reset();pe.arena.binding[7].node=PTR_NODE_COUNT;assert(!lta_storage());++cases;
    reset();topology=0;assert(!lta_storage());++cases;
    printf("ARENA_CAPACITY nodes=%u cases=%u actual_bodies=1 synthetic_only=1\n",PTR_NODE_COUNT,cases);
    return 0;
}
'''


def function(source, name):
    pattern = re.compile(r'^static [^\n]+\b' + re.escape(name) + r'\([^\n]*\) \{', re.M)
    matches = list(pattern.finditer(source))
    if len(matches) != 1:
        raise ValueError(f'one actual {name} definition')
    start = matches[0].start()
    end = source.index('\n}', matches[0].end()) + 2
    body = source[start:end]
    if body.count('{') != body.count('}'):
        raise ValueError(f'complete actual {name} body')
    return body


def declaration(source, marker):
    if source.count(marker) != 1:
        raise ValueError(f'one actual {marker}')
    start = source.index(marker)
    return source[start:source.index('};', start) + 2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('selected', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--cc', default='cc')
    args = parser.parse_args()
    sources = {name: (args.selected / name).read_text() for name in (
        'loop_translation_arena_storage.inc', 'loop_translation_arena_owner.inc',
        'loop_translation_arena_types.inc', 'loop_ro_certificate.inc',
        'sealed_generation.inc', 'persistent_group_controller.inc', 'persistent_group_lifetime.h')}
    bindings = {
        'NODE_INDEX': ('loop_translation_arena_storage.inc', 'ptr_node_index'),
        'STORAGE': ('loop_translation_arena_storage.inc', 'lta_storage'),
        'NODE_BOUND': ('loop_translation_arena_owner.inc', 'lta_node_bound'),
        'PROPOSE': ('loop_translation_arena_owner.inc', 'lta_propose_peer'),
        'SELECTED_NODE': ('sealed_generation.inc', 'sg_selected_node'),
        'MIRROR_BEGIN': ('loop_ro_certificate.inc', 'lrc_mirror_begin'),
        'MIRROR_END': ('loop_ro_certificate.inc', 'lrc_mirror_end'),
    }
    text = HARNESS
    for key, (path, name) in bindings.items():
        text = text.replace(f'/* ACTUAL_{key} */', function(sources[path], name))
    for key, path, marker in (
        ('ERRORS', 'persistent_group_controller.inc', 'enum pe_error {'),
        ('PHASES', 'persistent_group_lifetime.h', 'enum li2_pg_phase {'),
        ('TRIAL_TYPE', 'loop_translation_arena_types.inc', 'struct lta_peer_trials {'),
    ):
        text = text.replace(f'/* ACTUAL_{key} */', declaration(sources[path], marker))
    macros = re.findall(r'^#define LRC_WRITER_NODE (.+)$', sources['loop_ro_certificate.inc'], re.M)
    if macros != ['(SBC_NODE_INDEX+1U)', '(1U<<SBC_NODE_INDEX)', '(1U<<SBC_NODE_INDEX)']:
        raise ValueError('exact program-only writer representation and preserved default branches')
    text = text.replace('/* ACTUAL_WRITER_MACRO */', '#ifdef LI2_LOOP_TRANSLATION_ARENA_CAPACITY\n'
                        '#define LRC_WRITER_NODE ' + macros[0] + '\n#else\n'
                        '#define LRC_WRITER_NODE ' + macros[1] + '\n#endif')
    if '/* ACTUAL_' in text:
        raise ValueError('every actual-source placeholder resolved')
    generated = args.output.with_suffix('.c')
    outputs = [args.output.with_name(args.output.name + '-' + str(n)) for n in (12, 128)]
    if args.output.exists() or generated.exists() or any(p.exists() for p in outputs):
        raise ValueError('fresh generated source and both executable paths')
    generated.write_text(text)
    for nodes, output in zip((12, 128), outputs):
        flags = [f'-DPTR_NODE_COUNT={nodes}U']
        if nodes == 128:
            flags += ['-DLI2_LOOP_TRANSLATION_ARENA_CAPACITY=128']
        subprocess.run([args.cc, '-std=gnu11', '-O2', '-Wall', '-Wextra', '-Werror', *flags,
                        str(generated), '-o', str(output)], check=True)
        subprocess.run([str(output.resolve())], check=True)


if __name__ == '__main__':
    main()
