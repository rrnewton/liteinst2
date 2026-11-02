/* Whole old PF oracle first. Added actual-API controls execute no generated code. */
#define main old_pf_main
#define __wrap_li2_mg_recover old_wrap_mg_recover
#include "tests/bounded_fusion_plan/oracle.c"
#undef __wrap_li2_mg_recover
#undef main
#include "persistent_loop_fused_plan.h"
#define LI2_PERSISTENT_LOOP_RUNTIME 1
#define LI2_PERSISTENT_FUSED_RUNTIME 1
#define LI2_PERSISTENT_RETAINED_TWO 1
#define LI2_PERSISTENT_SUBENTRY 1
#define LI2_PERSISTENT_UNREGISTERED 1
#include "persistent_loop_runtime.h"
#undef LI2_PERSISTENT_UNREGISTERED
#undef LI2_PERSISTENT_SUBENTRY
#undef LI2_PERSISTENT_RETAINED_TWO
#undef LI2_PERSISTENT_FUSED_RUNTIME
#undef LI2_PERSISTENT_LOOP_RUNTIME
/* Reuse the separately reviewed independent far-byte interpreter, while the
   original PF oracle retains its original DD model in its original TU. */
#define dd_model_run lpf_model_run
#define dd_model_taken lpf_model_taken
#include "tests/loop_direct_far/direct_model.c"
#undef dd_model_taken
#undef dd_model_run

static uintptr_t lpf_pages[2];
static struct li2_pg_layout lpf_layout;
static struct li2_mg_table lpf_table;
static unsigned char lpf_source[2][4096];
static struct li2_pg_plan lpf_graph,lpf_expected;
static const struct li2_pg_compact *lpf_current;
static unsigned lpf_head,near_plans,far_plans,histories,graph_controls,refusals,partial_cases,partial_controls;
static unsigned lpf_models,lpf_mov_models,lpf_corruptions,lpf_literals,lpf_interiors,lpf_links,lpf_copied,lpf_sentinels;
static uint64_t lpf_steps,lpf_mov_steps,lpf_typed,lpf_mov_typed;

int __real_li2_ld_recover(const struct li2_dd_plan *,uintptr_t,const uint64_t[16],uint64_t,
    const uint64_t[4],struct li2_dd_recovered *);
int __wrap_li2_ld_recover(const struct li2_dd_plan *p,uintptr_t pc,const uint64_t r[16],uint64_t flags,
    const uint64_t spill[4],struct li2_dd_recovered *out) {
    unsigned was_nested=nested;nested=1;uint64_t before=calls;
    int e=__real_li2_ld_recover(p,pc,r,flags,spill,out);nested=was_nested;assert(calls==before);
    if(lpf_current && !nested) {
        struct li2_pg_recovered got;nested=1;
        assert(!e && !li2_lpf_compact_recover(lpf_current,pc,r,flags,spill,&recovery,&got));nested=0;
        assert(calls==before && got.complete==1 && got.member==lpf_head/64 && got.head==lpf_head%64 &&
            got.link==UINT32_MAX && got.kind==LI2_PG_DIRECT_MAP && got.phase==LI2_DD_BEFORE &&
            got.original_pc==out->original_pc && got.flags==out->flags && !memcmp(got.gpr,out->gpr,sizeof got.gpr) &&
            !memcmp(&recovery.direct,p,sizeof *p));++lpf_typed;
    }
    return e;
}
int __wrap_li2_mg_recover(const struct li2_mg_plan *p,uintptr_t pc,const uint64_t r[16],uint64_t flags,
    const uint64_t spill[4],struct li2_mg_recovered *out) {
    uint64_t before=calls;int e=old_wrap_mg_recover(p,pc,r,flags,spill,out);assert(calls==before);
    if(lpf_current && !nested) {
        struct li2_pg_recovered got;nested=1;
        assert(!e && !li2_lpf_compact_recover(lpf_current,pc,r,flags,spill,&recovery,&got));nested=0;
        assert(calls==before && got.complete==1 && got.member==lpf_head/64 && got.head==lpf_head%64 &&
            got.link==UINT32_MAX && got.kind==LI2_PG_GUARD && got.phase==out->phase &&
            got.original_pc==out->original_pc && got.flags==out->flags && !memcmp(got.gpr,out->gpr,sizeof got.gpr) &&
            !memcmp(&recovery.mov,p,sizeof *p));++lpf_mov_typed;
    }
    return e;
}
static void lpf_setup(uintptr_t page,uintptr_t generated) {
    lpf_pages[0]=page;lpf_pages[1]=page+4096;memset(lpf_source,0xcc,sizeof lpf_source);
    lpf_layout=(struct li2_pg_layout){{generated,generated+0x8000},generated+0x10000,
        generated+0x11000,generated+0x12000,generated+0x20000};
    const struct li2_mg_range ranges[4]={{page,page+8192},{generated,generated+0x13000},
        {generated+0x20000,generated+0x23000},{generated+0x30000,generated+0x90000}};
    assert(!li2_mg_table_build(ranges,4,generated+0x30000+offsetof(struct li2_pg_plan,table),&lpf_table));
}
static void lpf_put(unsigned offset,const unsigned char *b,unsigned n) {
    assert(offset<8192 && n<=8192-offset);
    for(unsigned i=0;i<n;i++)lpf_source[(offset+i)/4096][(offset+i)%4096]=b[i];
}
static void lpf_branch(unsigned offset,unsigned cc,uintptr_t target) {
    unsigned char b[6]={0x0f,(unsigned char)(0x80+cc)};unsigned n=cc==16?5:6;
    if(cc==16)b[0]=0xe9;
    int64_t delta=(int64_t)target-(int64_t)(lpf_pages[0]+offset+n);assert(delta>=INT32_MIN && delta<=INT32_MAX);
    for(unsigned j=0;j<4;j++)b[n-4+j]=(unsigned char)((uint32_t)delta>>(8*j));lpf_put(offset,b,n);
}
static unsigned lpf_shape(unsigned shape) {
    static const unsigned char mov[3]={0x48,0x89,0xd8};
    static const unsigned char b[15]={0x4c,0x89,0x0f,0x49,0x83,0xe9,1,0x4c,0x89,0xc9,0xe9,0xf1,0,0,0};
    if(shape==0) {lpf_put(256,b,sizeof b);return 256;}
    if(shape==1)lpf_branch(512,16,lpf_pages[0]+768);
    if(shape==2) {lpf_put(512,mov,3);lpf_branch(515,4,lpf_pages[0]+512);}
    if(shape==3) {lpf_branch(512,4,lpf_pages[0]+768);lpf_put(518,mov,3);lpf_branch(521,16,lpf_pages[0]+512);}
    if(shape==4) {lpf_branch(8186,4,lpf_pages[0]+8192);return 8186;}
    if(shape==5) {for(unsigned j=0;j<65;j++)lpf_put(512+3*j,mov,3);lpf_branch(707,4,lpf_pages[0]+512);}
    assert(shape<6);return 512;
}
static void lpf_history(void) {
    assert(!li2_lpf_graph_history(lpf_pages,lpf_source,full.entry,&lpf_layout,lpf_table.address,&lpf_graph));
    lpf_expected=full;lpf_expected.ready=0;
    memset(lpf_expected.image,0,sizeof lpf_expected.image);memset(lpf_expected.stub_image,0,sizeof lpf_expected.stub_image);
    memset(lpf_expected.guard,0,sizeof lpf_expected.guard);memset(&lpf_expected.table,0,sizeof lpf_expected.table);
    lpf_expected.table.address=lpf_table.address;
    for(unsigned i=0;i<128;i++)lpf_expected.head[i].generated_length=0;
    assert(!memcmp(&lpf_graph,&lpf_expected,sizeof lpf_graph) && !lpf_graph.ready && !lpf_graph.result);
    for(unsigned ready=0;ready<2;ready++) {
        lpf_graph.ready=ready;
        assert(li2_pf_plan_validate(&lpf_graph,&scratch)==LI2_PG_CORRUPT &&
            li2_lpf_plan_validate(&lpf_graph,&scratch)==LI2_PG_CORRUPT &&
            li2_lpf_compact_build(&lpf_graph,&scratch,&bad)==LI2_PG_CORRUPT);
    }
    ++histories;
}
static void lpf_bytes(unsigned far) {
    uint64_t r[16],spill[4]={0x1234,0x5678,0x9abc,0xdef0};
    for(unsigned j=0;j<16;j++)r[j]=UINT64_C(0x1234567800000000)+0x101*j;
    for(unsigned i=0;i<compact.heads;i++) {
        const struct li2_pe_head *h=&compact.head[i];lpf_current=&compact;lpf_head=i;
        if(h->kind==LI2_PG_DIRECT) {
            assert(!li2_lpf_compact_direct(&compact,i/64,i%64,&direct) && !memcmp(&direct,&full.guard[i].direct,sizeof direct));
            assert(direct.record.version==(far?2U:1U) && !li2_ld_validate(&direct));uint64_t visited=0;
            for(unsigned f=0;f<64;f++)for(unsigned mode=0;mode<3;mode++) {
                uint64_t flags=flags_for(f);unsigned arms=direct.original.flow==LI2_REGION_JCC?2:1;
                unsigned arm=arms==1?0U:(lpf_model_taken(direct.original.condition,flags)?0U:1U);
                struct li2_jd_domain_directory dir={.version=1,.serial=40};
                for(unsigned a=0;a<arms;a++)if(direct.original.external_mask&(1U<<a))
                    dir.row[dir.count++]=(struct li2_jd_domain_row){direct.original.target[a]+(mode==1),0x50000000,7,0,0};
                if(mode==2)dir.count=0;
                struct dd_model_result got;assert(!lpf_model_run(&direct,&dir,r,flags,&got));
                int exit=li2_lpf_compact_exit(&compact,direct.original.decoded.pc,flags);
                if(direct.original.external_mask&(1U<<arm)) {
                    assert(exit==(int)(h->successors[arm]-128));
                    if(!mode)assert(got.hit && !got.miss && !got.internal && got.target==0x50000000 && got.cell_writes==1);
                    else assert(got.miss && !got.hit && !got.internal && got.target==direct.original.decoded.pc && !got.cell_writes);
                } else assert(exit==-1 && got.internal && !got.hit && !got.miss && got.target==direct.internal[arm] && !got.cell_writes);
                assert(got.steps==got.recoveries);visited|=got.visited;lpf_steps+=got.steps;++lpf_models;
            }
            assert(visited==((UINT64_C(1)<<direct.record.boundaries)-1));
        } else if(h->kind==LI2_PE_MOV) {
            assert(!li2_lpf_compact_guard(&compact,i/64,i%64,&guard) && !memcmp(&guard,&full.guard[i].mov,sizeof guard));
            const uintptr_t addresses[5]={0x60000000,lpf_pages[0],lpf_layout.generated[0],lpf_layout.directory,lpf_table.address};
            for(unsigned f=0;f<64;f++)for(unsigned a=0;a<5;a++) {
                r[7]=addresses[a];r[9]=UINT64_C(0xfedcba9876543210);struct model_result got;
                assert(!model_run(&guard,r,flags_for(f),&got));
                if(!a)assert(got.writes==1 && !got.rejected && got.first==addresses[a] && got.width==8 && got.value==r[9]);
                else assert(!got.writes && got.rejected);
                assert(got.steps==got.recoveries+got.writes);lpf_mov_steps+=got.recoveries;++lpf_mov_models;
            }
        }
        lpf_current=0;
        for(unsigned offset=0;offset<512;offset++) {
            unsigned boundary=0;
            if(h->kind==LI2_PG_DIRECT)for(unsigned j=0;j<direct.record.boundaries;j++)boundary+=direct.record.boundary[j].offset==offset;
            else if(h->kind==LI2_PE_MOV)for(unsigned j=0;j<guard.boundaries;j++)boundary+=guard.boundary[j].offset==offset;
            else boundary=offset==0 || (full.original[i].flow!=LI2_REGION_JMP && offset==(full.original[i].flow==LI2_REGION_JCC?6U:h->source_length));
            if(!boundary) {
                struct li2_pg_recovered got;uint64_t before=calls;
                assert(li2_lpf_compact_recover(&compact,lpf_layout.generated[i/64]+512*(i%64)+offset,r,flags_for(63),spill,&recovery,&got)==LI2_PG_MISS && calls==before);++lpf_interiors;
            } else if(h->kind==LI2_PE_NONE) {
                struct li2_pg_recovered got;uint64_t before=calls;const struct li2_span_decoded *d=&compact.original[i];
                assert(!li2_lpf_compact_recover(&compact,lpf_layout.generated[i/64]+512*(i%64)+offset,r,flags_for(63),spill,&recovery,&got) && calls==before &&
                    got.complete==1 && got.member==i/64 && got.head==i%64 && got.link==UINT32_MAX &&
                    got.original_pc==(offset?d->decoded.next_pc:d->decoded.pc) &&
                    got.phase==(offset?LI2_MG_AFTER:LI2_MG_BEFORE) &&
                    got.kind==(offset?LI2_PG_EDGE:d->flow==LI2_REGION_NEXT?LI2_PG_COPIED:LI2_PG_BRANCH) &&
                    got.flags==flags_for(63) && !memcmp(got.gpr,r,sizeof r));++lpf_copied;
            }
        }
        if(far && h->kind==LI2_PG_DIRECT) {
            unsigned miss=direct.record.miss_offset;
            for(unsigned k=0;k<25;k++) {
                bad=compact;
                if(k<8)bad.image[i/64][512*(i%64)+miss+6+k]^=1;
                else switch(k-8) {
                case 0:bad.guard[i].direct.version=1;break;
                case 1:--bad.guard[i].direct.image_bytes;break;
                case 2:++bad.guard[i].direct.hit_offset;break;
                case 3:++bad.guard[i].direct.miss_offset;break;
                case 4:--bad.guard[i].direct.boundaries;break;
                case 5:++bad.guard[i].direct.boundary[0].offset;break;
                case 6:++bad.guard[i].direct.boundary[0].length;break;
                case 7:bad.guard[i].direct.boundary[0].spill_valid^=1;break;
                case 8:bad.guard[i].direct.boundary[0].dirty^=1;break;
                case 9:bad.guard[i].direct.boundary[0].flags^=1;break;
                case 10:bad.guard[i].direct.boundary[0].phase^=1;break;
                case 11:bad.instruction[i].direct.external_mask^=1;break;
                case 12:bad.layout.directory+=4096;break;
                case 13:++bad.entry;break;
                case 14:bad.version=12;break;
                case 15:bad.source[h->source_page][h->source_offset]^=1;break;
                case 16:bad.table.node[0].first^=1;break;
                }
                assert(li2_lpf_compact_validate(&bad,&scratch,&rebuilt)==LI2_PG_CORRUPT);++lpf_corruptions;
            }
            for(unsigned k=0;k<8;k++) {
                bad=compact;bad.guard[i].direct.boundary[0].offset=miss+6+k;
                struct li2_pg_recovered got;uint64_t before=calls;
                assert(li2_lpf_compact_recover(&bad,lpf_layout.generated[i/64]+512*(i%64)+miss+6+k,r,flags_for(63),spill,&recovery,&got)==LI2_PG_CORRUPT && calls==before);++lpf_literals;
            }
        }
    }
    for(unsigned j=0;j<compact.links;j++) {
        struct li2_pg_recovered got;uint64_t before=calls;
        assert(!li2_lpf_compact_recover(&compact,compact.edge[j].stub,r,flags_for(63),spill,&recovery,&got) && calls==before &&
            got.complete==1 && got.kind==LI2_PG_LINK && got.phase==LI2_PG_COMMITTED_EDGE && got.link==j &&
            got.member==UINT32_MAX && got.head==UINT32_MAX && got.original_pc==compact.edge[j].original_target &&
            got.flags==flags_for(63) && !memcmp(got.gpr,r,sizeof r));++lpf_links;
    }
}
static void lpf_plans(void) {
    const unsigned heads[6]={4,1,2,3,1,66},exits[6]={1,1,1,1,2,1};
    for(unsigned far=0;far<2;far++)for(unsigned direction=0;direction<2;direction++)for(unsigned shape=0;shape<6;shape++) {
        uintptr_t page=direction?UINT64_C(0x700000000000):0x400000;
        uintptr_t generated=far?(direction?0x10000000:UINT64_C(0x700000000000)):page+0x100000;
        lpf_setup(page,generated);unsigned entry=lpf_shape(shape);struct li2_pg_miss miss,other,empty={.version=11};
        assert(!li2_lpf_plan_pages(lpf_pages,lpf_source,page+entry,&lpf_layout,&lpf_table,&full,&miss) &&
            !memcmp(&miss,&empty,sizeof miss) && full.version==11 && full.ready==1 && full.heads==heads[shape] &&
            full.exits==exits[shape] && full.stores==(shape==0) && full.links==(shape==5?2U:0U));
        assert(!li2_lpf_plan_validate(&full,&scratch) && !memcmp(&full,&scratch,sizeof full));
        assert(!li2_lpf_compact_build(&full,&scratch,&compact) && !li2_lpf_compact_validate(&compact,&scratch,&rebuilt) && !memcmp(&compact,&rebuilt,sizeof compact));
        int e=li2_pf_plan_pages(lpf_pages,lpf_source,page+entry,&lpf_layout,&lpf_table,&old,&other);
        if(!far) {
            assert(!e && !memcmp(&old,&full,sizeof full) && !memcmp(&other,&miss,sizeof miss));
            assert(!li2_pf_compact_build(&full,&scratch,&bad) && !memcmp(&bad,&compact,sizeof compact));++near_plans;
        } else {
            assert(e==LI2_PG_RELOCATION && !old.ready && old.guard_result==LI2_DD_RELOCATION &&
                li2_pf_plan_validate(&full,&scratch)==LI2_PG_CORRUPT && li2_pf_compact_validate(&compact,&scratch,&bad)==LI2_PG_CORRUPT);++far_plans;
            /* The unchanged old branch(16) leaves this exact unpatched
               sentinel when its final original-PC displacement fails. */
            unsigned first=0;while(first<old.heads && old.head[first].kind!=LI2_PG_DIRECT)++first;
            assert(first<old.heads);const struct li2_dd_plan *failed=&old.guard[first].direct;
            static const unsigned char unpatched[5]={0xe9,0x90,0,0,0};
            assert(failed->record.version==LI2_DD_VERSION && !failed->record.ready && failed->record.result==LI2_DD_RELOCATION &&
                failed->record.miss_offset>0 && failed->record.miss_offset<=LI2_DD_SLOT_BYTES-5 &&
                failed->record.image_bytes==failed->record.miss_offset+5 && failed->record.boundaries>0 &&
                failed->record.boundaries<=LI2_DD_BOUNDARIES &&
                !memcmp(failed->image+failed->record.miss_offset,unpatched,sizeof unpatched));
            const struct li2_mg_boundary *last=&failed->record.boundary[failed->record.boundaries-1];
            assert(last->offset==failed->record.miss_offset && last->length==5 && last->spill_valid==15 &&
                !last->dirty && last->flags==LI2_MG_PHYSICAL && last->phase==LI2_DD_BEFORE);++lpf_sentinels;
        }
        lpf_history();lpf_bytes(far);
    }
}
static void lpf_history_controls(void) {
    lpf_setup(UINT64_C(0x700000000000),0x10000000);unsigned entry=lpf_shape(0);
    assert(!li2_lpf_graph_history(lpf_pages,lpf_source,lpf_pages[0]+entry,&lpf_layout,lpf_table.address,&lpf_expected));
    assert(!li2_lpf_graph_history(lpf_pages,lpf_source,lpf_pages[0]+entry+3,&lpf_layout,lpf_table.address,&lpf_graph) &&
        memcmp(&lpf_graph,&lpf_expected,sizeof lpf_graph));++graph_controls;
    struct li2_pg_layout moved=lpf_layout;moved.directory+=4096;
    assert(!li2_lpf_graph_history(lpf_pages,lpf_source,lpf_pages[0]+entry,&moved,lpf_table.address,&lpf_graph) &&
        memcmp(&lpf_graph,&lpf_expected,sizeof lpf_graph));++graph_controls;
    assert(!li2_lpf_graph_history(lpf_pages,lpf_source,lpf_pages[0]+entry,&lpf_layout,lpf_table.address+8,&lpf_graph) &&
        memcmp(&lpf_graph,&lpf_expected,sizeof lpf_graph));++graph_controls;
    assert(li2_lpf_graph_history(lpf_pages,lpf_source,lpf_pages[0]+entry,&lpf_layout,lpf_table.address+1,&lpf_graph)==LI2_PG_ARGUMENT);++graph_controls;
    moved=lpf_layout;moved.generated[1]=moved.generated[0];
    assert(li2_lpf_graph_history(lpf_pages,lpf_source,lpf_pages[0]+entry,&moved,lpf_table.address,&lpf_graph)==LI2_PG_ARGUMENT);++graph_controls;
    assert(li2_lpf_graph_history(lpf_pages,lpf_source,lpf_pages[0]-1,&lpf_layout,lpf_table.address,&lpf_graph)==LI2_PG_ARGUMENT);++graph_controls;
    assert(li2_lpf_graph_history(lpf_pages,lpf_source,lpf_pages[0]+entry,&lpf_layout,UINTPTR_MAX,&lpf_graph)==LI2_PG_ARGUMENT);++graph_controls;
    assert(li2_lpf_graph_history(lpf_expected.page,lpf_expected.source,lpf_expected.entry,&lpf_expected.layout,lpf_table.address,&lpf_expected)==LI2_PG_ARGUMENT);++graph_controls;
}
static void lpf_refusals(void) {
    const unsigned char mov[3]={0x48,0x89,0xd8};
    for(unsigned direction=0;direction<2;direction++)for(unsigned kind=0;kind<6;kind++) {
        lpf_setup(direction?UINT64_C(0x700000000000):0x400000,direction?0x10000000:UINT64_C(0x700000000000));
        if(kind==1) {lpf_put(512,mov,3);lpf_branch(515,16,lpf_pages[0]+512);}
        if(kind==2) {lpf_put(512,mov,3);lpf_branch(515,4,lpf_pages[0]+513);}
        if(kind==3)for(unsigned j=0;j<129;j++)lpf_put(512+3*j,mov,3);
        if(kind==4)for(unsigned j=0;j<9;j++)lpf_branch(512+6*j,4,lpf_pages[0]+2304);
        if(kind==5)lpf_branch(512,4,lpf_pages[0]+496);
        struct li2_pg_miss miss,other;int e=li2_lpf_plan_pages(lpf_pages,lpf_source,lpf_pages[0]+512,&lpf_layout,&lpf_table,&full,&miss);
        assert(e && !full.ready && li2_pf_plan_pages(lpf_pages,lpf_source,lpf_pages[0]+512,&lpf_layout,&lpf_table,&old,&other)==e &&
            !memcmp(&full,&old,sizeof full) && !memcmp(&miss,&other,sizeof miss) && !li2_lpf_miss_validate(&full,&miss,e,&scratch));
        assert(li2_lpr_fallback_miss_valid(&full,&miss,e,&scratch)==li2_pfr_miss_valid(&full,&miss,e,&scratch));++refusals;
    }
}
static void lpf_partial(void) {
    for(unsigned direction=0;direction<2;direction++)for(unsigned store=0;store<2;store++) {
        lpf_setup(direction?UINT64_C(0x700000000000):0x400000,direction?0x10000000:UINT64_C(0x700000000000));
        lpf_branch(512,4,lpf_pages[0]+768);
        unsigned char b[7]={0x48,(unsigned char)(store?0x89:0x8b),0x05,0,0,0,0};
        uint32_t displacement=(uint32_t)((lpf_pages[0]+0x900000)-(lpf_pages[0]+518+7));
        for(unsigned j=0;j<4;j++)b[3+j]=(unsigned char)(displacement>>(8*j));lpf_put(518,b,7);
        struct li2_pg_miss miss;int e=li2_lpf_plan_pages(lpf_pages,lpf_source,lpf_pages[0]+512,&lpf_layout,&lpf_table,&full,&miss);
        assert(e==LI2_PG_RELOCATION && !full.ready && full.guard[0].direct.record.ready==1 && full.guard[0].direct.record.version==2 &&
            miss.reason==(store?LI2_PGD_GUARD_RIP_REACH:LI2_PGD_RIP_REACH) && miss.site==LI2_PGD_EMIT && miss.pc==lpf_pages[0]+518);
        assert(!li2_lpf_miss_validate(&full,&miss,e,&scratch) && li2_pf_miss_validate(&full,&miss,e,&scratch)==LI2_PG_CORRUPT &&
            li2_lpr_fallback_miss_valid(&full,&miss,e,&scratch)==!store && !li2_pfr_miss_valid(&full,&miss,e,&scratch));
        for(unsigned k=0;k<6;k++) {
            struct li2_pg_miss changed=miss;
            if(k==0)changed.version^=1;if(k==1)changed.status^=1;if(k==2)changed.reason^=1;
            if(k==3)changed.site^=1;if(k==4)changed.pc^=1;if(k==5)changed.detail^=1;
            assert(li2_lpf_miss_validate(&full,&changed,e,&scratch)==LI2_PG_CORRUPT &&
                !li2_lpr_fallback_miss_valid(&full,&changed,e,&scratch));++partial_controls;
        }
        ++partial_cases;
    }
}

/* Additive guard-cancellation proof only. No owner, permissions, publication,
   cancellation lifecycle, or emitted execution is instantiated here. */
static unsigned gc_positive,gc_root,gc_partial,gc_miss_controls,gc_plan_controls,gc_prefix_controls;
static unsigned gc_reason_controls,gc_result_controls,gc_argument_controls,gc_status_controls;
static unsigned gc_success,gc_follow,gc_copied,gc_spill,gc_spill_forged;

static void gc_helper(void) {
    /* machine.S region_app_enter stores RSP,RBX,RBP,R12..R15 then PUSHFQ.
       The actual failed root's RBX bytes are retained independently below;
       this source-relative placement also exercises the opposite direction. */
    const unsigned regs[7]={4,3,5,12,13,14,15};
    static const unsigned char observed[7]={0x48,0x89,0x1d,0xb2,0x02,0x01,0x00};
    for(unsigned j=0;j<7;j++) {
        unsigned char b[7]={(unsigned char)(0x48|((regs[j]>>3)<<2)),0x89,
            (unsigned char)(5|((regs[j]&7)<<3)),0,0,0,0};
        uint32_t displacement=0x102b1+j;
        for(unsigned k=0;k<4;k++)b[3+k]=(unsigned char)(displacement>>(8*k));
        lpf_put(7*j,b,7);
    }
    const unsigned char pushfq=0x9c;lpf_put(49,&pushfq,1);
    assert(!memcmp(lpf_source[0]+7,observed,sizeof observed));
}

static void gc_plan_mutation(unsigned k,unsigned i) {
    struct li2_pe_head *h=&full.head[i];struct li2_mg_plan *g=&full.guard[i].mov;
    switch(k) {
    case 0:full.version^=1;break;
    case 1:full.bytes^=1;break;
    case 2:full.ready=1;break;
    case 3:full.result^=1;break;
    case 4:--full.heads;break;
    case 5:++full.exits;break;
    case 6:++full.stores;break;
    case 7:++full.source_bytes;break;
    case 8:full.source_mask^=1;break;
    case 9:full.decoder_result=1;break;
    case 10:full.guard_result=LI2_MG_DECODER;break;
    case 11:full.reserved=1;break;
    case 12:full.reserved2=1;break;
    case 13:++full.member_heads[0];break;
    case 14:++full.entry;break;
    case 15:full.page[0]+=4096;break;
    case 16:full.layout.generated[0]+=4096;break;
    case 17:full.layout.generated[1]+=4096;break;
    case 18:full.layout.stubs+=4096;break;
    case 19:full.layout.slots+=4096;break;
    case 20:full.layout.spill+=4096;break;
    case 21:full.layout.directory+=4096;break;
    case 22:full.source[h->source_page][h->source_offset]^=1;break;
    case 23:full.image[0][0]^=1;break;
    case 24:full.table.node[0].first^=1;break;
    case 25:h->kind=LI2_PE_NONE;break;
    case 26:++h->source_length;break;
    case 27:h->successor_count=2;break;
    case 28:h->successors[0]=LI2_PG_HEADS+LI2_PG_BOUNDARIES;break;
    case 29:++full.original[i].decoded.next_pc;break;
    case 30:++full.original[i].decoded.pc;break;
    case 31:full.instruction[i].mov.rip_relative=0;break;
    case 32:full.instruction[i].mov.rip_target^=1;break;
    case 33:++full.instruction[i].mov.displacement_offset;break;
    case 34:g->version=2;break;
    case 35:g->ready=1;break;
    case 36:g->result=LI2_MG_DECODER;break;
    case 37:++g->image_bytes;break;
    case 38:++g->boundaries;break;
    case 39:g->store_offset=1;break;
    case 40:g->reject_offset=1;break;
    case 41:g->reserved=1;break;
    case 42:g->generated^=512;break;
    case 43:g->spill+=8;break;
    case 44:g->successor^=1;break;
    case 45:g->original.rip_target^=1;break;
    case 46:g->table.node[0].first^=1;break;
    case 47:g->boundary[0].length^=1;break;
    case 48:g->image[0]^=1;break;
    case 49:g->scratch_regs[0]=1;break;
    case 50:full.original[i].decoded.bytes[0]^=1;break;
    case 51:h->source_page^=1;break;
    case 52:h->source_offset^=1;break;
    case 53:full.original[i?0:1].decoded.pc=full.original[i].decoded.pc;break;
    default:assert(0);
    }
}

static void gc_controls(const struct li2_pg_miss *miss,unsigned i,unsigned partial) {
    struct li2_pg_miss original=*miss;old=full;
    for(unsigned k=0;k<6;k++) {
        struct li2_pg_miss changed=original;
        if(k==0)changed.version^=1;if(k==1)changed.status^=1;if(k==2)changed.reason^=1;
        if(k==3)changed.site^=1;if(k==4)changed.pc^=1;if(k==5)changed.detail^=1;
        assert(memcmp(&changed,&original,sizeof changed) &&
            !li2_lpf_guard_relocation_reason(&full,&changed,LI2_PG_RELOCATION,&scratch));++gc_miss_controls;
    }
    for(unsigned k=0;k<54;k++) {
        full=old;gc_plan_mutation(k,i);
        assert(memcmp(&full,&old,sizeof full) &&
            !li2_lpf_guard_relocation_reason(&full,&original,LI2_PG_RELOCATION,&scratch));++gc_plan_controls;
    }
    full=old;
    if(partial)for(unsigned k=0;k<2;k++) {
        full=old;
        if(!k)full.guard[0].direct.image[full.guard[0].direct.record.miss_offset+6]^=1;
        else full.guard[0].direct.record.ready=0;
        assert(memcmp(&full,&old,sizeof full) &&
            !li2_lpf_guard_relocation_reason(&full,&original,LI2_PG_RELOCATION,&scratch));++gc_prefix_controls;
    }
    full=old;
    for(unsigned reason=0;reason<=LI2_PGD_REASON_COUNT;reason++)if(reason!=LI2_PGD_GUARD_RIP_REACH) {
        struct li2_pg_miss changed=original;changed.reason=reason;
        assert(memcmp(&changed,&original,sizeof changed) &&
            !li2_lpf_guard_relocation_reason(&full,&changed,LI2_PG_RELOCATION,&scratch));++gc_reason_controls;
    }
    const unsigned other_reasons[2]={LI2_PFD_BACKWARD_UNSUPPORTED,UINT32_MAX};
    for(unsigned k=0;k<2;k++) {
        struct li2_pg_miss changed=original;changed.reason=other_reasons[k];
        assert(memcmp(&changed,&original,sizeof changed) &&
            !li2_lpf_guard_relocation_reason(&full,&changed,LI2_PG_RELOCATION,&scratch));++gc_reason_controls;
    }
    const int results[8]={0,LI2_PG_MISS,LI2_PG_ARGUMENT,LI2_PG_DECODER,
        LI2_PG_BOUNDARY,LI2_PG_GRAPH,LI2_PG_CORRUPT,9999};
    for(unsigned k=0;k<8;k++) {
        assert(!li2_lpf_guard_relocation_reason(&full,&original,results[k],&scratch));++gc_result_controls;
    }
    assert(!li2_lpf_guard_relocation_reason(0,&original,LI2_PG_RELOCATION,&scratch));++gc_argument_controls;
    assert(!li2_lpf_guard_relocation_reason(&full,0,LI2_PG_RELOCATION,&scratch));++gc_argument_controls;
    assert(!li2_lpf_guard_relocation_reason(&full,&original,LI2_PG_RELOCATION,0));++gc_argument_controls;
    assert(!li2_lpf_guard_relocation_reason(&full,&original,LI2_PG_RELOCATION,&full));++gc_argument_controls;
    /* These are explicit malformed-status controls, not manufactured observed
       decoder/internal failures. Actual far spill and FOLLOW failures follow. */
    const unsigned statuses[6]={LI2_MG_OK,LI2_MG_ARGUMENT,LI2_MG_DECODER,LI2_MG_FORM,LI2_MG_CAPACITY,LI2_MG_CORRUPT};
    for(unsigned k=0;k<6;k++) {
        full=old;full.guard_result=statuses[k];
        assert(memcmp(&full,&old,sizeof full) &&
            !li2_lpf_guard_relocation_reason(&full,&original,LI2_PG_RELOCATION,&scratch));++gc_status_controls;
    }
    full=old;assert(!memcmp(miss,&original,sizeof original));
}

static void gc_positives(void) {
    for(unsigned direction=0;direction<2;direction++)for(unsigned partial=0;partial<2;partial++) {
        uintptr_t page=direction?UINT64_C(0x700000000000):UINT64_C(0x200021000);
        uintptr_t generated=direction?0x10000000:UINT64_C(0x700000000000);
        lpf_setup(page,generated);unsigned entry=7,i=0;
        if(!partial)gc_helper();
        else {
            entry=512;i=1;lpf_branch(512,4,page+768);
            unsigned char b[7]={0x48,0x89,0x05,0,0,0,0};
            uint32_t displacement=(uint32_t)((page+0x900000)-(page+518+7));
            for(unsigned j=0;j<4;j++)b[3+j]=(unsigned char)(displacement>>(8*j));lpf_put(518,b,7);
        }
        struct li2_pg_miss miss;int e=li2_lpf_plan_pages(lpf_pages,lpf_source,page+entry,&lpf_layout,&lpf_table,&full,&miss);
        assert(e==LI2_PG_RELOCATION && !full.ready && full.result==LI2_PG_RELOCATION &&
            !full.decoder_result && full.guard_result==LI2_MG_RELOCATION &&
            full.heads==(partial?2U:6U) && full.stores==(partial?1U:6U) &&
            miss.version==11 && miss.status==LI2_PG_RELOCATION && miss.site==LI2_PGD_EMIT &&
            miss.reason==LI2_PGD_GUARD_RIP_REACH && miss.pc==page+(partial?518U:7U) &&
            miss.detail==page+(partial?0x900000U:0x102c0U));
        assert(full.head[i].kind==LI2_PE_MOV && full.head[i].source_length==7 &&
            full.instruction[i].mov.rip_relative==1 && full.instruction[i].mov.rip_target==miss.detail &&
            !full.guard[i].mov.ready && full.guard[i].mov.result==LI2_MG_RELOCATION &&
            full.guard[i].mov.image_bytes==28 && full.guard[i].mov.boundaries==4 &&
            !full.guard[i].mov.store_offset && !full.guard[i].mov.reject_offset);
        if(partial) {
            assert(full.guard[0].direct.record.version==2 && full.guard[0].direct.record.ready==1 &&
                !full.guard[0].direct.record.result && full.head[0].generated_length==full.guard[0].direct.record.image_bytes);
            ++gc_partial;
        } else {
            assert(full.entry==page+7 && full.exit_pc[0]==page+49 &&
                full.original[0].decoded.next_pc==page+14 && full.instruction[0].mov.source_reg==3);
            ++gc_root;
        }
        old=full;struct li2_pg_miss saved=miss;
        assert(li2_lpf_guard_relocation_reason(&full,&miss,e,&scratch)==LI2_PGD_GUARD_RIP_REACH &&
            !memcmp(&scratch,&full,sizeof full) && !memcmp(&full,&old,sizeof full) && !memcmp(&miss,&saved,sizeof miss));
        assert(!li2_lpr_fallback_miss_valid(&full,&miss,e,&scratch) &&
            !li2_pfr_miss_valid(&full,&miss,e,&scratch));
        assert(li2_lpf_plan_validate(&full,&scratch)==LI2_PG_CORRUPT &&
            li2_lpf_compact_build(&full,&scratch,&bad)==LI2_PG_CORRUPT && !bad.ready && bad.result==LI2_PG_CORRUPT &&
            !full.ready && !memcmp(&full,&old,sizeof full) && !memcmp(&miss,&saved,sizeof miss));
        ++gc_positive;gc_controls(&miss,i,partial);
    }
}

static void gc_other_results(void) {
    static const unsigned char store[3]={0x48,0x89,0x0f};
    for(unsigned direction=0;direction<2;direction++) {
        uintptr_t page=direction?UINT64_C(0x700000000000):UINT64_C(0x200021000);
        uintptr_t generated=direction?0x10000000:UINT64_C(0x700000000000);
        struct li2_pg_miss miss;int e;
        /* The identical helper with reachable generated bytes is an ordinary
           ready success, not a relocation cancellation. */
        lpf_setup(page,page+0x100000);gc_helper();
        assert(!li2_lpf_plan_pages(lpf_pages,lpf_source,page+7,&lpf_layout,&lpf_table,&full,&miss) && full.ready==1 &&
            !li2_lpf_guard_relocation_reason(&full,&miss,0,&scratch));++gc_success;
        /* Non-RIP MOV emits a real store but cannot reach its original-PC
           unsupported successor. FOLLOW remains rejected by the new API. */
        lpf_setup(page,generated);lpf_put(512,store,sizeof store);
        e=li2_lpf_plan_pages(lpf_pages,lpf_source,page+512,&lpf_layout,&lpf_table,&full,&miss);
        assert(e==LI2_PG_RELOCATION && !full.ready && full.guard_result==LI2_MG_RELOCATION &&
            miss.reason==LI2_PGD_GUARD_FOLLOW_REACH && miss.site==LI2_PGD_EMIT && miss.pc==page+512 && miss.detail==page+515 &&
            full.guard[0].mov.store_offset && !full.guard[0].mov.reject_offset &&
            !li2_lpf_miss_validate(&full,&miss,e,&scratch) &&
            !li2_lpf_guard_relocation_reason(&full,&miss,e,&scratch) &&
            !li2_lpr_fallback_miss_valid(&full,&miss,e,&scratch) && !li2_pfr_miss_valid(&full,&miss,e,&scratch));++gc_follow;
        /* A real copied RIP load still uses the original old classifier; the
           new guarded-write API must not borrow that distinct reason. */
        lpf_setup(page,generated);
        unsigned char load[7]={0x48,0x8b,0x05,0,0,0,0};
        uint32_t delta=(uint32_t)((page+0x900000)-(page+512+7));
        for(unsigned j=0;j<4;j++)load[3+j]=(unsigned char)(delta>>(8*j));lpf_put(512,load,7);
        e=li2_lpf_plan_pages(lpf_pages,lpf_source,page+512,&lpf_layout,&lpf_table,&full,&miss);
        assert(e==LI2_PG_RELOCATION && !full.ready && miss.reason==LI2_PGD_RIP_REACH &&
            !li2_lpf_miss_validate(&full,&miss,e,&scratch) && li2_lpr_fallback_miss_valid(&full,&miss,e,&scratch) &&
            !li2_lpf_guard_relocation_reason(&full,&miss,e,&scratch));++gc_copied;
        /* A fully successful non-RIP MOV+far DIRECT baseline isolates spill
           reach as the only changed input of the following failed build. */
        lpf_setup(page,generated);lpf_put(512,store,sizeof store);lpf_branch(515,16,page+768);
        assert(!li2_lpf_plan_pages(lpf_pages,lpf_source,page+512,&lpf_layout,&lpf_table,&full,&miss) && full.ready==1 &&
            full.guard[1].direct.record.version==2 && !li2_lpf_guard_relocation_reason(&full,&miss,0,&scratch));++gc_success;
        lpf_layout.spill=page+0x200000;
        const struct li2_mg_range ranges[5]={{page,page+8192},{generated,generated+0x12000},
            {generated+0x20000,generated+0x23000},{generated+0x30000,generated+0x90000},
            {lpf_layout.spill,lpf_layout.spill+4096}};
        assert(!li2_mg_table_build(ranges,5,generated+0x30000+offsetof(struct li2_pg_plan,table),&lpf_table));
        e=li2_lpf_plan_pages(lpf_pages,lpf_source,page+512,&lpf_layout,&lpf_table,&full,&miss);
        struct li2_pg_miss empty={.version=11,.status=LI2_PG_RELOCATION};
        assert(e==LI2_PG_RELOCATION && !full.ready && full.guard_result==LI2_MG_RELOCATION &&
            !memcmp(&miss,&empty,sizeof miss) && !full.guard[0].mov.ready &&
            full.guard[0].mov.result==LI2_MG_RELOCATION && !full.guard[0].mov.image_bytes && !full.guard[0].mov.boundaries &&
            !li2_lpf_miss_validate(&full,&miss,e,&scratch) && !li2_lpf_guard_relocation_reason(&full,&miss,e,&scratch));++gc_spill;
        struct li2_pg_miss forged=miss;forged.reason=LI2_PGD_GUARD_RIP_REACH;forged.site=LI2_PGD_EMIT;
        forged.pc=page+512;forged.detail=page+0x102c0;
        assert(memcmp(&forged,&miss,sizeof miss) && li2_lpf_miss_validate(&full,&forged,e,&scratch)==LI2_PG_CORRUPT &&
            !li2_lpf_guard_relocation_reason(&full,&forged,e,&scratch));++gc_spill_forged;
    }
}

static void lpf_guard_relocation(void) {
    struct li2_decoder_stats before,after;assert(!li2_decoder_stats(&before));
    gc_positives();gc_other_results();
    assert(gc_positive==4 && gc_root==2 && gc_partial==2 && gc_miss_controls==24 && gc_plan_controls==216 &&
        gc_prefix_controls==4 && gc_reason_controls==80 && gc_result_controls==32 && gc_argument_controls==16 &&
        gc_status_controls==24 && gc_success==4 && gc_follow==2 && gc_copied==2 && gc_spill==2 && gc_spill_forged==2);
    assert(!li2_decoder_stats(&after) && after.phase==2 && !after.first_fatal_reason &&
        after.allocation_calls==before.allocation_calls && after.deallocation_calls==before.deallocation_calls);
    printf("{\"profile\":\"loop-guard-relocation-component-v1\",\"positive\":%u,\"root\":%u,\"partial\":%u,\"miss_controls\":%u,\"plan_controls\":%u,\"prefix_controls\":%u,\"reason_controls\":%u,\"result_controls\":%u,\"argument_controls\":%u,\"status_controls\":%u,\"success_refusals\":%u,\"follow_refusals\":%u,\"copied_refusals\":%u,\"spill_refusals\":%u,\"spill_forged_refusals\":%u,\"emitted_execution\":0,\"owner_credit\":0}\n",
        gc_positive,gc_root,gc_partial,gc_miss_controls,gc_plan_controls,gc_prefix_controls,gc_reason_controls,
        gc_result_controls,gc_argument_controls,gc_status_controls,gc_success,gc_follow,gc_copied,gc_spill,gc_spill_forged);
}

int main(void) {
    assert(!old_pf_main());struct li2_decoder_stats before,after;assert(!li2_decoder_stats(&before));
    lpf_plans();lpf_history_controls();lpf_refusals();lpf_partial();
    assert(near_plans==12 && far_plans==12 && histories==24 && graph_controls==8 && refusals==12 &&
        partial_cases==4 && partial_controls==24 && lpf_models==4608 && lpf_mov_models==1280 &&
        lpf_corruptions==300 && lpf_literals==96 && lpf_links==8 && lpf_copied==556 && lpf_sentinels==12 && lpf_interiors>0);
    assert(lpf_typed==2*lpf_steps && lpf_mov_typed==2*lpf_mov_steps && !lpf_current && !nested);
    assert(!li2_decoder_stats(&after) && after.phase==2 && !after.first_fatal_reason &&
        after.allocation_calls==before.allocation_calls && after.deallocation_calls==before.deallocation_calls);
    printf("{\"profile\":\"loop-fused-far-component-v1\",\"near\":%u,\"far\":%u,\"histories\":%u,\"graph_controls\":%u,\"refusals\":%u,\"partial\":%u,\"partial_controls\":%u,\"direct_models\":%u,\"mov_models\":%u,\"corruptions\":%u,\"literal_refusals\":%u,\"links\":%u,\"copied_boundaries\":%u,\"old_sentinels\":%u,\"interiors\":%u,\"direct_steps\":%llu,\"mov_recoveries\":%llu,\"emitted_execution\":0,\"owner_credit\":0}\n",
        near_plans,far_plans,histories,graph_controls,refusals,partial_cases,partial_controls,lpf_models,lpf_mov_models,
        lpf_corruptions,lpf_literals,lpf_links,lpf_copied,lpf_sentinels,lpf_interiors,(unsigned long long)lpf_steps,(unsigned long long)lpf_mov_steps);
    lpf_guard_relocation();
    return 0;
}
