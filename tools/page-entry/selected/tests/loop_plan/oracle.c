/* Pure policy12 component. Supplied bytes are decoded and emitted into
   nonexecuted arrays. No owner, faults, mapping authority or timing credit. */
#include "persistent_loop_plan.h"
#include "persistent_block_plan.h"
#include "tests/persistent_direct_frontier/model.h"
#include "tests/linked_mov_guard/model.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
static _Alignas(64) unsigned char arena[16U<<20];
static struct li2_pg_plan full,scratch;
static struct li2_pg_compact compact,rebuilt,bad;
static struct li2_le_witness witness;
static union li2_pg_guard recovery;
static struct li2_dd_plan direct;
static struct li2_mg_plan guard;
static struct li2_mg_table table;
static unsigned char source[2][4096];
static uintptr_t pages[2];
static struct li2_pg_layout layout;
static unsigned plans,misses,corruptions,old_checks,direct_models,mov_models,copied,interiors,bridges;
static uint64_t calls,typed_direct,typed_mov,direct_steps,mov_boundaries;
static const struct li2_pg_compact *current;
static unsigned current_head,nested;
uint32_t __real_li2_decoder_decode(uint64_t,const unsigned char *,size_t,struct li2_decoded *);
uint32_t __wrap_li2_decoder_decode(uint64_t pc,const unsigned char *b,size_t n,struct li2_decoded *out) {
    ++calls;return __real_li2_decoder_decode(pc,b,n,out);
}
int __real_li2_dd_recover(const struct li2_dd_plan *,uintptr_t,const uint64_t[16],uint64_t,const uint64_t[4],struct li2_dd_recovered *);
int __wrap_li2_dd_recover(const struct li2_dd_plan *p,uintptr_t pc,const uint64_t r[16],uint64_t flags,
    const uint64_t spill[4],struct li2_dd_recovered *out) {
    uint64_t before=calls;int e=__real_li2_dd_recover(p,pc,r,flags,spill,out);assert(calls==before);
    if(current && !nested) {
        struct li2_pg_recovered got;nested=1;
        assert(!e && !li2_lp_compact_recover(current,pc,r,flags,spill,&recovery,&got));nested=0;
        assert(calls==before && got.complete==1 && got.member==current_head/64 && got.head==current_head%64 &&
            got.link==UINT32_MAX && got.kind==LI2_PG_DIRECT_MAP && got.phase==LI2_DD_BEFORE &&
            got.original_pc==out->original_pc && got.flags==out->flags && !memcmp(got.gpr,out->gpr,sizeof got.gpr) &&
            !memcmp(&recovery.direct,p,sizeof *p));++typed_direct;
    }
    return e;
}
int __real_li2_mg_recover(const struct li2_mg_plan *,uintptr_t,const uint64_t[16],uint64_t,const uint64_t[4],struct li2_mg_recovered *);
int __wrap_li2_mg_recover(const struct li2_mg_plan *p,uintptr_t pc,const uint64_t r[16],uint64_t flags,
    const uint64_t spill[4],struct li2_mg_recovered *out) {
    uint64_t before=calls;int e=__real_li2_mg_recover(p,pc,r,flags,spill,out);assert(calls==before);
    if(current && !nested) {
        struct li2_pg_recovered got;nested=1;
        assert(!e && !li2_lp_compact_recover(current,pc,r,flags,spill,&recovery,&got));nested=0;
        assert(calls==before && got.complete==1 && got.member==current_head/64 && got.head==current_head%64 &&
            got.link==UINT32_MAX && got.kind==LI2_PG_GUARD && got.phase==out->phase &&
            got.original_pc==out->original_pc && got.flags==out->flags && !memcmp(got.gpr,out->gpr,sizeof got.gpr) &&
            !memcmp(&recovery.mov,p,sizeof *p));++typed_mov;
    }
    return e;
}
static uint64_t flags_for(unsigned v) {
    const unsigned bits[6]={0,2,4,6,7,11};uint64_t f=0x602;
    for(unsigned i=0;i<6;i++)f|=(uint64_t)((v>>i)&1)<<bits[i];return f;
}
static const unsigned char tunables[]={
    0x49,0x83,0xc1,0x01,0x49,0x83,0xe8,0x80,0x49,0x83,0xf9,0x25,
    0x0f,0x84,0x72,0xff,0xff,0xff,0x41,0x80,0x78,0xf8,0x00,0x4d,0x63,0xd1,
    0x75,0xe4,0x41,0x0f,0xb6,0x38,0x40,0x84,0xff,0x74,0xdb,
    0x4c,0x89,0xcd,0x4c,0x89,0xc6,0x48,0x89,0xd8,0x89,0xf9,0x48,0xc1,0xe5,0x07,
    0x0f,0x1f,0x40,0x00,0x0f,0xb6,0x10,0x84,0xd2,0x74,0xc1,0x38,0xca,0x75,0xbd,
    0x0f,0xb6,0x4e,0x01,0x48,0x83,0xc6,0x01,0x48,0x83,0xc0,0x01,0x84,0xc9,
    0x75,0xe5,0x80,0x38,0x3d,0x75,0xa8,0x45,0x85,0xdb,0x74,0x11,0x41,0x8b,0x40,0xfc,
    0x85,0xc0,0x0f,0x84,0x13,0x03,0x00,0x00,0x83,0xf8,0x02,0x75,0x92,
    0x49,0xc1,0xe2,0x07,0x48,0x8d,0x05,0x47,0x0f,0x02,0x00,0x42,0x83,0x7c,0x10,0x30,0x03,
    0x0f,0x84,0xe9,0x02,0x00,0x00,0x48,0x8b,0x3c,0x24,0x31,0xf6,0xe8,0xb0,0x5f,0xff,0xff
};
static const unsigned off[28]={0,4,8,12,18,23,26,28,32,35,37,40,43,46,48,52,
    56,59,61,63,65,67,71,75,79,81,83,86};
/* -1 is the source's outside escape; -2 is the true last fallthrough.
   Other values are literal linear-head ordinals, never decoder output. */
static const int first[28]={1,2,3,-1,5,6,0,8,9,0,11,12,13,14,15,16,
    17,18,0,20,0,22,23,24,25,16,27,0};
static const int second[28]={-3,-3,-3,4,-3,-3,7,-3,-3,10,-3,-3,-3,-3,-3,-3,
    -3,-3,19,-3,21,-3,-3,-3,-3,26,-3,-2};
static void init(uintptr_t page,unsigned adjacent) {
    pages[0]=page;pages[1]=page+(adjacent?4096:16384);memset(source,0xcc,sizeof source);
    layout=(struct li2_pg_layout){{page+0x100000,page+0x108000},page+0x110000,
        page+0x111000,page+0x112000,page+0x200000};
    const struct li2_mg_range range[4]={{page,page+0x5000},{page+0x100000,page+0x113000},
        {page+0x200000,page+0x203000},{page+0x300000,page+0x360000}};
    assert(!li2_mg_table_build(range,4,page+0x300000+offsetof(struct li2_pg_compact,table),&table));
}
static void put(unsigned offset,const unsigned char *bytes,size_t n) {
    assert(offset<sizeof source && n<=sizeof source-offset);memcpy((unsigned char *)source+offset,bytes,n);
}
static void put32(unsigned char *p,uint32_t n) {for(unsigned i=0;i<4;i++)p[i]=(unsigned char)(n>>(8*i));}
static void nops(unsigned offset,unsigned count) {
    const unsigned char nop[]={0x0f,0x1f,0x00};for(unsigned i=0;i<count;i++)put(offset+3*i,nop,sizeof nop);
}
static void accept(uintptr_t entry,unsigned heads,unsigned exits,unsigned stores,unsigned links) {
    struct li2_pg_miss miss,empty={.version=12};
    assert(!li2_lp_plan_pages(pages,source,entry,&layout,&table,&full,&miss,&witness));
    assert(!memcmp(&miss,&empty,sizeof miss) && full.version==12 && full.ready==1 && full.heads==heads &&
        full.exits==exits && full.stores==stores && full.links==links && full.original[0].decoded.pc==entry);
    assert(!li2_lp_plan_validate(&full,&scratch,&witness) && !memcmp(&full,&scratch,sizeof full));
    assert(!li2_lp_compact_build(&full,&scratch,&compact,&witness) &&
        !li2_lp_compact_validate(&compact,&scratch,&rebuilt,&witness) && !memcmp(&compact,&rebuilt,sizeof compact));
    assert(li2_pg_plan_validate(&full,&scratch)==LI2_PG_CORRUPT && li2_pb_plan_validate(&full,&scratch)==LI2_PG_CORRUPT &&
        li2_pf_plan_validate(&full,&scratch)==LI2_PG_CORRUPT && li2_pg_compact_validate(&compact,&scratch,&rebuilt)==LI2_PG_CORRUPT &&
        li2_pb_compact_validate(&compact,&scratch,&rebuilt)==LI2_PG_CORRUPT &&
        li2_pf_compact_validate(&compact,&scratch,&rebuilt)==LI2_PG_CORRUPT);old_checks+=6;++plans;
}
static void refuse(uintptr_t entry,int result) {
    struct li2_pg_miss miss;
    assert(li2_lp_plan_pages(pages,source,entry,&layout,&table,&full,&miss,&witness)==result &&
        !full.ready && !miss.reason && miss.status==(unsigned)result && miss.site==LI2_PGD_SOURCE &&
        miss.pc==entry && miss.detail==(unsigned)result);
    assert(!li2_lp_miss_validate(&full,&miss,result,&scratch,&witness));
    assert(li2_lp_plan_validate(&full,&scratch,&witness)==LI2_PG_CORRUPT);
    struct li2_pg_miss changed=miss;changed.detail^=1;
    assert(li2_lp_miss_validate(&full,&changed,result,&scratch,&witness)==LI2_PG_CORRUPT);++misses;
}
static void literal_graph(uintptr_t base,unsigned entry) {
    const struct li2_le_shape *s=&witness.selected;
    assert(s->choice.first==base && s->choice.end==base+88 && s->choice.latch==base+86);
    assert(s->choice.result==0 && s->choice.heads==28 && s->choice.exits==2 && !s->choice.links);
    assert(s->choice.backwards==6 && !s->choice.stores && s->choice.source_bytes==88);
    unsigned queue[28]={entry},rank[28],count=1;
    for(unsigned i=0;i<28;i++)rank[i]=28;
    rank[entry]=0;
    for(unsigned at=0;at<count;at++) {
        const int edge[2]={first[queue[at]],second[queue[at]]};
        for(unsigned arm=0;arm<2;arm++)if(edge[arm]>=0 && rank[edge[arm]]==28) {
            rank[edge[arm]]=count;queue[count++]=(unsigned)edge[arm];
        }
    }
    assert(count==28);unsigned exit=0;
    for(unsigned at=0;at<28;at++) {
        unsigned i=queue[at];const struct li2_le_head *h=&s->head[at];
        const int edge[2]={first[i],second[i]};unsigned arms=second[i]==-3?1:2;
        assert(h->pc==base+off[i] && h->kind==LI2_LE_NONE && h->successors==arms);
        assert(h->flow==(arms==2?LI2_REGION_JCC:LI2_REGION_NEXT));
        assert(h->decoded<witness.decoded && witness.node[h->decoded].scalar.decoded.pc==h->pc);
        unsigned mask=0;
        for(unsigned arm=0;arm<arms;arm++) {
            if(edge[arm]>=0)assert(h->token[arm]==rank[edge[arm]]);
            else {
                assert(h->token[arm]==128+exit);mask|=1U<<arm;
                assert(s->exit[exit].head==at && s->exit[exit].arm==arm);
                assert(s->exit[exit].target==base+(edge[arm]==-1?(uintptr_t)-124:88));exit++;
            }
        }
        assert(h->external_mask==mask && !h->reserved);
        const struct li2_pe_head *p=&compact.head[at];
        assert(compact.original[at].decoded.pc==base+off[i] && p->source_length==(i==27?2:off[i+1]-off[i]) &&
            p->successor_count==arms && !memcmp(p->successors,h->token,sizeof p->successors));
        assert(p->kind==(mask?LI2_PG_DIRECT:LI2_PE_NONE));
        if(mask)assert(compact.instruction[at].direct.external_mask==mask && compact.original[at].version==1);
        else assert(compact.original[at].version==((i==4 || i==5 || i==8 || i==15 || i==17 || i==19 || i==24 || i==26)?2U:1U));
    }
    assert(exit==2 && s->head[0].pc==base+off[entry]);
}
/* Whole existing DIRECT/MOV interpreters supply all modeled typed states.
   Only the component route, literal MOV base/source registers and copied
   internal-Jcc boundary length differ from the old PF oracle caller. */
static void models(unsigned with_mov) {
    uint64_t r[16],spill[4]={0x1234,0x5678,0x9abc,0xdef0};
    for(unsigned j=0;j<16;j++)r[j]=UINT64_C(0x1234567800000000)+0x101*j;
    for(unsigned i=0;i<compact.heads;i++) {
        current=&compact;current_head=i;const struct li2_pe_head *h=&compact.head[i];
        if(h->kind==LI2_PG_DIRECT) {
            assert(!li2_lp_compact_direct(&compact,i/64,i%64,&direct) && !memcmp(&direct,&full.guard[i].direct,sizeof direct));
            uint64_t visited=0;
            for(unsigned f=0;f<64;f++)for(unsigned mode=0;mode<3;mode++) {
                uint64_t flags=flags_for(f);unsigned arm=dd_model_taken(direct.original.condition,flags)?0:1;
                struct li2_jd_domain_directory dir={.version=1,.serial=40};
                for(unsigned a=0;a<2;a++)if(direct.original.external_mask&(1U<<a))
                    dir.row[dir.count++]=(struct li2_jd_domain_row){direct.original.target[a]+(mode==1),0x50000000,7,0,0};
                if(mode==2)dir.count=0;
                struct dd_model_result out;assert(!dd_model_run(&direct,&dir,r,flags,&out));
                int selected=li2_lp_compact_exit(&compact,direct.original.decoded.pc,flags);
                if(direct.original.external_mask&(1U<<arm)) {
                    assert(selected==(int)(h->successors[arm]-LI2_PG_HEADS));
                    if(mode==0)assert(out.hit && !out.miss && !out.internal && out.target==0x50000000 && out.cell_writes==1);
                    else assert(out.miss && !out.hit && !out.internal && out.target==direct.original.decoded.pc && !out.cell_writes);
                } else assert(selected==-1 && out.internal && !out.hit && !out.miss && out.target==direct.internal[arm] && !out.cell_writes);
                assert(out.steps==out.recoveries);visited|=out.visited;direct_steps+=out.steps;++direct_models;
            }
            assert(direct.record.boundaries<64 && visited==((UINT64_C(1)<<direct.record.boundaries)-1));
        } else if(h->kind==LI2_PE_MOV) {
            assert(with_mov && !li2_lp_compact_guard(&compact,i/64,i%64,&guard) && !memcmp(&guard,&full.guard[i].mov,sizeof guard));
            const uintptr_t address[5]={pages[0]+0x500000,pages[0],layout.generated[0],layout.directory,table.address};
            for(unsigned f=0;f<64;f++)for(unsigned a=0;a<5;a++) {
                r[7]=address[a];r[0]=UINT64_C(0xfedcba9876543210);struct model_result out;
                assert(!model_run(&guard,r,flags_for(f),&out));
                if(!a)assert(out.writes==1 && !out.rejected && out.first==address[a] && out.width==8 && out.value==r[0]);
                else assert(!out.writes && out.rejected);
                assert(out.steps==out.recoveries+out.writes);mov_boundaries+=out.recoveries;++mov_models;
            }
        }
        current=0;
        for(unsigned offset=0;offset<512;offset++) {
            unsigned boundary=0;
            if(h->kind==LI2_PG_DIRECT)for(unsigned j=0;j<full.guard[i].direct.record.boundaries;j++)boundary|=offset==full.guard[i].direct.record.boundary[j].offset;
            else if(h->kind==LI2_PE_MOV)for(unsigned j=0;j<full.guard[i].mov.boundaries;j++)boundary|=offset==full.guard[i].mov.boundary[j].offset;
            else {
                unsigned flow=compact.original[i].flow,length=flow==LI2_REGION_NEXT?h->source_length:flow==LI2_REGION_JCC?6:5;
                boundary=offset==0 || (flow!=LI2_REGION_JMP && offset==length);
            }
            struct li2_pg_recovered out;uintptr_t pc=layout.generated[i/64]+512*(i%64)+offset;
            if(!boundary) {assert(li2_lp_compact_recover(&compact,pc,r,flags_for(63),spill,&recovery,&out)==LI2_PG_MISS);++interiors;}
            else if(h->kind==LI2_PE_NONE) {
                assert(!li2_lp_compact_recover(&compact,pc,r,flags_for(63),spill,&recovery,&out) && out.complete==1 &&
                    out.original_pc==(offset?compact.original[i].decoded.next_pc:compact.original[i].decoded.pc) &&
                    out.phase==(offset?LI2_MG_AFTER:LI2_MG_BEFORE) && out.flags==flags_for(63) && !memcmp(out.gpr,r,sizeof r));++copied;
            }
        }
    }
    for(unsigned j=0;j<compact.links;j++) {
        struct li2_pg_recovered out;
        assert(!li2_lp_compact_recover(&compact,layout.stubs+6*j,r,0x602,spill,&recovery,&out) &&
            out.original_pc==compact.edge[j].original_target && out.phase==LI2_PG_COMMITTED_EDGE &&
            out.kind==LI2_PG_LINK && out.link==j && out.member==UINT32_MAX && out.head==UINT32_MAX &&
            out.flags==0x602 && !memcmp(out.gpr,r,sizeof r));
        for(unsigned k=1;k<6;k++)assert(li2_lp_compact_recover(&compact,layout.stubs+6*j+k,r,0x602,spill,&recovery,&out)==LI2_PG_MISS);
    }
}
static void entries(void) {
    init(0x400000,1);put(512,tunables,sizeof tunables);
    for(unsigned entry=0;entry<28;entry++) {
        accept(pages[0]+512+off[entry],28,2,0,0);literal_graph(pages[0]+512,entry);
        if(entry==5)models(0);
    }
    const uintptr_t place[2]={0x400000,UINT64_C(0x700000000000)};
    for(unsigned i=0;i<2;i++) {
        init(place[i],1);put(4032,tunables,sizeof tunables);
        accept(pages[0]+4032+23,28,2,0,0);literal_graph(pages[0]+4032,5);
        assert(compact.source_mask==3);
    }
}
static void puzzles(void) {
    const unsigned char forward[]={0x74,0x06,0x0f,0x1f,0x00,0x0f,0x1f,0x00,0x75,0xf6};
    init(0x400000,0);put(512,forward,sizeof forward);accept(pages[0]+512,4,1,0,0);
    assert(compact.head[0].kind==LI2_PE_NONE && compact.head[0].successors[0]==1 && compact.head[0].successors[1]==2);models(0);
    const unsigned char mov[]={0x48,0x89,0x07,0x75,0xfb};
    init(0x400000,0);put(512,mov,sizeof mov);accept(pages[0]+512,2,1,1,0);models(1);
    /* Exact128 supported heads, no early cut. The page end ends discovery. */
    init(0x400000,0);unsigned start=4096-387;nops(start,127);source[0][start+381]=0x0f;source[0][start+382]=0x85;
    put32(source[0]+start+383,0U-387U);accept(pages[0]+start,128,1,0,2);models(0);
    /* New memory-read form is relocated from original RIP to the same data
       address; neither the planner nor this metadata oracle dereferences it. */
    init(0x400000,1);unsigned char rip[]={0x80,0x3d,0,0,0,0,0,0x75,0xf7};
    uintptr_t target=pages[0]+0x900000;put32(rip+2,(uint32_t)(target-(pages[0]+512+7)));
    put(512,rip,sizeof rip);accept(pages[0]+512,2,1,0,0);
    assert(compact.original[0].version==2 && compact.original[0].rip_target==target &&
        compact.original[0].relocation==LI2_SPAN_RIP_DISP32);models(0);
    const unsigned char no_exit[]={0x0f,0x1f,0x00,0x0f,0x1f,0x00,0xeb,0xf8};
    init(0x400000,0);put(512,no_exit,sizeof no_exit);refuse(pages[0]+512,LI2_LE_NO_ENVELOPE);
    const unsigned char interior[]={0x0f,0x1f,0x40,0,0x75,0xfb,0x75,0xf8};
    init(0x400000,0);put(512,interior,sizeof interior);refuse(pages[0]+512,LI2_LE_NO_ENVELOPE);
    const unsigned char unsupported[]={0xcc,0x0f,0x1f,0x00,0x75,0xfa};
    init(0x400000,0);put(512,unsupported,sizeof unsupported);refuse(pages[0]+516,LI2_LE_NO_ENVELOPE);
    init(0x400000,0);nops(512,32);source[0][608]=0x75;source[0][609]=0x9e;nops(610,96);
    refuse(pages[0]+512,LI2_LE_DISCOVERY_LIMIT);
    init(0x400000,0);for(unsigned i=0;i<8;i++){source[0][512+2*i]=0x74;source[0][513+2*i]=0x40;}
    source[0][528]=0x75;source[0][529]=0xee;refuse(pages[0]+512,LI2_LE_NO_ENVELOPE);
    assert(witness.candidate[0].result==LI2_LE_EXIT_LIMIT && witness.candidate[0].exits==9);
    const unsigned char excluded[3][3]={{0x90,0x75,0xfd},{0xc3,0x75,0xfd},{0xff,0xe0,0xcc}};
    for(unsigned i=0;i<3;i++){init(0x400000,0);put(512,excluded[i],3);refuse(pages[0]+512,LI2_LE_NO_ENVELOPE);}
}
static void bridge_controls(void) {
    const unsigned char bytes[7][8]={{0x48,0x89,0xd8},{0x75,0xfe},{0x4d,0x63,0xd1},
        {0x41,0x80,0x78,0xf8,0},{0x40,0x84,0xff},{0x38,0xca},{0x0f,0x1f,0x40,0}};
    const unsigned lengths[7]={3,2,3,5,3,2,4};
    const size_t fields[6]={offsetof(struct li2_span_decoded,version),offsetof(struct li2_span_decoded,ready),
        offsetof(struct li2_span_decoded,decoded)+offsetof(struct li2_decoded,pc),
        offsetof(struct li2_span_decoded,decoded)+offsetof(struct li2_decoded,bytes),
        offsetof(struct li2_span_decoded,flags_written),sizeof(struct li2_span_decoded)-1};
    for(unsigned i=0;i<7;i++) {
        struct li2_span_decoded oldrow,row;struct li2_le_decoded node={0};struct li2_lr_node got;
        assert(!li2_decoder_span_describe(0x400200,bytes[i],lengths[i],&oldrow) &&
            !li2_lr_describe(0x400200,bytes[i],lengths[i],&row) && row.ready && row.version==(i<2?1U:2U));
        if(i<2)assert(!memcmp(&row,&oldrow,sizeof row));else assert(!oldrow.ready);
        assert(!li2_lr_none(0x400200,bytes[i],lengths[i],&row));
        assert(!li2_decoder_scalar_read_describe(0x400200,bytes[i],lengths[i],&node.scalar));node.kind=LI2_LE_NONE;
        assert(!li2_lr_bridge_node(0x400200,bytes[i],lengths[i],&node,&got) &&
            !memcmp(&got.original,&row,sizeof row) && got.kind==LI2_LE_NONE && !got.reserved);
        for(unsigned f=0;f<6;f++) {
            struct li2_span_decoded changed=row;((unsigned char *)&changed)[fields[f]]^=1;
            assert(li2_lr_none(0x400200,bytes[i],lengths[i],&changed)==LI2_LR_CORRUPT);++bridges;
        }
        node.stop=LI2_LE_UNSUPPORTED;
        assert(li2_lr_bridge_node(0x400200,bytes[i],lengths[i],&node,&got)==LI2_LR_CORRUPT);++bridges;
    }
    struct li2_span_decoded row;const unsigned char nop[]={0x90},store[]={0x48,0x89,0x07};
    assert(!li2_lr_describe(0x400200,nop,1,&row) && !row.ready && row.version==1);
    assert(li2_lr_none(0x400200,nop,1,&row)==LI2_LR_FORM);
    assert(!li2_lr_describe(0x400200,store,3,&row) && !row.ready && row.version==1);
    assert(li2_lr_none(0x400200,store,3,&row)==LI2_LR_FORM);
    memset(&row,0xa5,sizeof row);struct li2_span_decoded saved=row;
    assert(li2_lr_describe(0x400200,(unsigned char *)&row,3,&row)==LI2_LR_ARGUMENT && !memcmp(&row,&saved,sizeof row));
    assert(li2_lr_describe(0x400200,nop,1,0)==LI2_LR_ARGUMENT);bridges+=4;
}
static void corrupt(void) {
    init(0x400000,1);put(512,tunables,sizeof tunables);accept(pages[0]+512+23,28,2,0,0);
    unsigned direct_head=UINT32_MAX;
    for(unsigned i=0;i<compact.heads;i++)if(compact.head[i].kind==LI2_PG_DIRECT){direct_head=i;break;}
    assert(direct_head<28);
    for(unsigned i=0;i<16;i++) {
        bad=compact;
        if(i==0)bad.version=11;
        if(i==1)bad.entry=pages[0]+512;
        if(i==2)bad.instruction[direct_head].direct.external_mask^=3;
        if(i==3)bad.guard[direct_head].direct.boundary[0].offset^=1;
        if(i==4)bad.head[0].successors[0]=0;
        if(i==5)bad.image[0][511]^=1;
        if(i==6)bad.source[0][512+23]^=1;
        if(i==7)bad.head[0].kind=LI2_PG_DISPATCH;
        if(i==8)bad.source_mask=0;
        if(i==9)bad.table.node[0].first^=1;
        if(i==10)bad.original[0].version=1;
        if(i==11)bad.original[0].decoded.reserved=1;
        if(i==12)bad.stores=1;
        if(i==13)bad.instruction[127].mov.bytes[0]=1;
        if(i==14)bad.original[0].flags_written^=1;
        if(i==15)bad.reserved2=1;
        assert(li2_lp_compact_validate(&bad,&scratch,&rebuilt,&witness)==LI2_PG_CORRUPT);++corruptions;
    }
    assert(li2_lp_plan_pages(pages,source,pages[0]+535,&layout,&table,&full,(struct li2_pg_miss *)&full,&witness)==LI2_PG_ARGUMENT);
    assert(li2_lp_compact_validate(&compact,&scratch,&rebuilt,(struct li2_le_witness *)&scratch)==LI2_PG_ARGUMENT);
}
int main(void) {
    struct li2_decoder_stats before,after;assert(!li2_decoder_initialize(arena,sizeof arena,&before));
    bridge_controls();entries();puzzles();corrupt();
    assert(!li2_decoder_stats(&after) && after.phase==2 && !after.first_fatal_reason &&
        after.allocation_calls==before.allocation_calls && after.deallocation_calls==before.deallocation_calls);
    assert(plans==35 && misses==8 && corruptions==16 && bridges==53 && old_checks==210);
    assert(direct_models==1152 && mov_models==320 && copied==314 && interiors>0);
    assert(typed_direct==2*direct_steps && typed_mov==2*mov_boundaries);
    printf("{\"profile\":\"loop-plan-component-v1\",\"version\":12,\"plans\":%u,\"misses\":%u,\"corruptions\":%u,\"bridge_controls\":%u,\"old_version_refusals\":%u,\"direct_models\":%u,\"mov_models\":%u,\"typed_direct\":%llu,\"typed_mov\":%llu,\"copied_boundaries\":%u,\"interiors\":%u,\"emitted_execution\":0,\"owner_credit\":0}\n",
        plans,misses,corruptions,bridges,old_checks,direct_models,mov_models,(unsigned long long)typed_direct,(unsigned long long)typed_mov,copied,interiors);
    return 0;
}
