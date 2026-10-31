/* Pure descriptions only. No generated instruction, source lease, rseq pin,
   permission or native guest runs. Link/model observations are not execution. */
#include "persistent_group_compact.h"
#include "tf_owner.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
static _Alignas(64) unsigned char arena[16U<<20];
static struct li2_pg_plan plan,scratch,changed;
static struct li2_pg_compact compact,rebuilt,bad;
static struct li2_mg_plan materialized,untouched;
static struct li2_mg_table table;
static struct li2_pg_miss miss;
static unsigned char source[2][4096];
static const uintptr_t pages[2]={0x400000,0x401000};
static struct li2_pg_layout layout;
static unsigned inject,positives,classified,terminal,miss_controls,proof_controls;
static unsigned recoveries,mov_boundaries,link_boundaries,pc_refusals,placement;
static const uintptr_t table_at=0x10020000;
uint32_t __real_li2_decoder_span_describe(uint64_t,const unsigned char *,size_t,struct li2_span_decoded *);
uint32_t __wrap_li2_decoder_span_describe(uint64_t pc,const unsigned char *b,size_t n,struct li2_span_decoded *d) {
    uint32_t r=__real_li2_decoder_span_describe(pc,b,n,d);if(r)return r;
    if(inject==1 && pc>=pages[0] && pc<pages[1]+4096)return LI2_BUSY;
    if(inject==5 && pc>=pages[0] && pc<pages[1]+4096) {
        struct li2_decoded original=d->decoded;memset(d,0,sizeof *d);
        d->decoded=original;d->version=1;d->refusal=LI2_REGION_EFFECTS;
    }
    return 0;
}
uint32_t __real_li2_decoder_decode(uint64_t,const unsigned char *,size_t,struct li2_decoded *);
uint32_t __wrap_li2_decoder_decode(uint64_t pc,const unsigned char *b,size_t n,struct li2_decoded *d) {
    uint32_t r=__real_li2_decoder_decode(pc,b,n,d);if(r)return r;
    if(inject==2 && pc>=layout.stubs && pc<layout.stubs+4096)return LI2_BUSY;
    if(inject==3 && pc>=layout.stubs && pc<layout.stubs+4096)d->code^=1;
    if(inject==7 && pc>=pages[0] && pc<pages[1]+4096)return LI2_BUSY;
    return 0;
}
uint32_t __real_li2_decoder_tf_classify(uint64_t,const unsigned char *,size_t,struct li2_tf_classification *);
uint32_t __wrap_li2_decoder_tf_classify(uint64_t pc,const unsigned char *b,size_t n,struct li2_tf_classification *d) {
    uint32_t r=__real_li2_decoder_tf_classify(pc,b,n,d);if(r)return r;
    if(inject==4 && pc>=layout.stubs && pc<layout.stubs+4096)d->policy=2;
    return 0;
}
uint32_t __real_li2_decoder_mov_store(uint64_t,const unsigned char *,size_t,struct li2_mg_store *);
uint32_t __wrap_li2_decoder_mov_store(uint64_t pc,const unsigned char *b,size_t n,struct li2_mg_store *d) {
    uint32_t r=__real_li2_decoder_mov_store(pc,b,n,d);if(r)return r;
    if(inject==6)d->tf.family=1;
    return 0;
}
static void at(unsigned offset,const unsigned char *b,size_t n) {
    assert(offset<=8192 && n<=8192-offset);
    for(size_t i=0;i<n;i++)source[(offset+i)/4096][(offset+i)%4096]=b[i];
}
static void rel(unsigned offset,unsigned length,unsigned displacement,unsigned target) {
    int64_t delta=(int64_t)target-(int64_t)(offset+length);assert(delta>=INT32_MIN && delta<=INT32_MAX);
    unsigned char b[4];for(unsigned i=0;i<4;i++)b[i]=(unsigned char)((uint32_t)delta>>(8*i));
    at(offset+displacement,b,4);
}
static void bank(uintptr_t code) {
    layout=(struct li2_pg_layout){{code,code+32768},code+65536,code+69632,code+73728};
}
static void empty(void) {memset(source,0xcc,sizeof source);bank(0x10000000);inject=0;}
static unsigned reg_chain(unsigned n) {
    static const unsigned char mov[]={0x48,0x89,0xc0};
    for(unsigned i=0;i<n;i++)at(0x100+3*i,mov,3);
    return 0x100+3*n;
}
static void loop(void) {
    empty();static const unsigned char add[]={0x48,0x83,0xc0,1},sub[]={0x48,0x83,0xe9,1};
    static const unsigned char jump[]={0xe9,0,0,0,0},jcc[]={0x0f,0x85,0,0,0,0},ret[]={0xc3};
    for(unsigned i=0;i<30;i++)at(0xe00+4*i,add,4);
    at(0xe78,jump,5);rel(0xe78,5,1,0x1100);
    for(unsigned i=0;i<31;i++)at(0x1100+4*i,add,4);
    at(0x117c,jump,5);rel(0x117c,5,1,0xf00);
    at(0xf00,sub,4);at(0xf04,jcc,6);rel(0xf04,6,2,0xe00);at(0xf0a,ret,1);
}
static void accepted(uintptr_t entry,unsigned heads,unsigned stores,unsigned links) {
    assert(!li2_pg_plan_pages(pages,source,entry,&layout,&table,&plan,&miss));
    const struct li2_pg_miss zero={.version=1};assert(!memcmp(&miss,&zero,sizeof miss));
    assert(plan.ready==1 && !plan.result && plan.heads==heads && plan.stores==stores &&
        plan.links==links && plan.exits==1 && plan.member_heads[0]==64 && plan.member_heads[1]==heads-64);
    assert(!li2_pg_miss_valid(&plan,&miss,0));
    assert(!li2_pg_plan_validate(&plan,&scratch) && !memcmp(&plan,&scratch,sizeof plan));
    assert(!li2_pg_compact_build(&plan,&scratch,&compact));
    assert(!li2_pg_compact_validate(&compact,&scratch,&rebuilt) && !memcmp(&compact,&rebuilt,sizeof compact));
    assert(!memcmp(compact.source,plan.source,sizeof source) && !memcmp(compact.image,plan.image,sizeof plan.image));
    assert(!memcmp(compact.stub_image,plan.stub_image,sizeof plan.stub_image));
    assert(li2_pg_placement(entry,&layout)==1);++placement;++positives;
}
static void refused(uintptr_t entry,unsigned reason,int status) {
    int result=li2_pg_plan_pages(pages,source,entry,&layout,&table,&plan,&miss);
    assert(result==status && !plan.ready && plan.result==(unsigned)status &&
        miss.version==1 && miss.status==(unsigned)status && miss.reason==reason);
    if(!reason) {
        const struct li2_pg_miss zero={.version=1,.status=(unsigned)status};
        assert(!memcmp(&miss,&zero,sizeof miss) && !li2_pg_miss_valid(&plan,&miss,status));++terminal;return;
    }
    assert(li2_pg_miss_valid(&plan,&miss,status));++classified;
    for(unsigned i=0;i<4;i++) {
        struct li2_pg_miss changed_miss=miss;
        if(i==0)changed_miss.version=0;
        if(i==1)changed_miss.status^=1;
        if(i==2)changed_miss.site=0;
        if(i==3)changed_miss.pc=0;
        assert(!li2_pg_miss_valid(&plan,&changed_miss,status));++miss_controls;
    }
}
static void whole_controls(void) {
    const size_t full[]={offsetof(struct li2_pg_plan,source)+0xe00,
        offsetof(struct li2_pg_plan,image)+32767,offsetof(struct li2_pg_plan,image)+32768,
        offsetof(struct li2_pg_plan,stub_image),offsetof(struct li2_pg_plan,stub_image)+4095,
        offsetof(struct li2_pg_plan,member_heads),offsetof(struct li2_pg_plan,edge)+offsetof(struct li2_pg_edge,target_head),
        offsetof(struct li2_pg_plan,edge)+offsetof(struct li2_pg_edge,successor),
        offsetof(struct li2_pg_plan,edge)+offsetof(struct li2_pg_edge,slot),
        offsetof(struct li2_pg_plan,head)+63*sizeof(struct li2_pe_head)+offsetof(struct li2_pe_head,successors),
        offsetof(struct li2_pg_plan,original)+64*sizeof(struct li2_span_decoded)+offsetof(struct li2_span_decoded,flags_read),
        offsetof(struct li2_pg_plan,guard)+127*sizeof(struct li2_mg_plan)};
    for(unsigned i=0;i<sizeof full/sizeof full[0];i++) {
        changed=plan;((unsigned char *)&changed)[full[i]]^=1;
        assert(li2_pg_plan_validate(&changed,&scratch)==LI2_PG_CORRUPT);++proof_controls;
    }
    const size_t small[]={offsetof(struct li2_pg_compact,source)+0xe00,
        offsetof(struct li2_pg_compact,image)+32767,offsetof(struct li2_pg_compact,image)+32768,
        offsetof(struct li2_pg_compact,stub_image),offsetof(struct li2_pg_compact,stub_image)+4095,
        offsetof(struct li2_pg_compact,member_heads),offsetof(struct li2_pg_compact,edge)+offsetof(struct li2_pg_edge,source_head),
        offsetof(struct li2_pg_compact,edge)+offsetof(struct li2_pg_edge,original_target),
        offsetof(struct li2_pg_compact,edge)+offsetof(struct li2_pg_edge,generated_target),
        offsetof(struct li2_pg_compact,layout)+offsetof(struct li2_pg_layout,slots),
        offsetof(struct li2_pg_compact,table)+offsetof(struct li2_mg_table,root),
        offsetof(struct li2_pg_compact,guard)+127*sizeof(struct li2_pe_guard_record)};
    for(unsigned i=0;i<sizeof small/sizeof small[0];i++) {
        bad=compact;((unsigned char *)&bad)[small[i]]^=1;
        assert(li2_pg_compact_validate(&bad,&scratch,&rebuilt)==LI2_PG_CORRUPT);++proof_controls;
    }
    /* Coherent copied targets still cannot turn a backward edge into a
       different original successor or duplicate the globally owned head. */
    changed=plan;changed.head[64].successors[0]=1;changed.edge[1].target_head=1;
    changed.edge[1].original_target=changed.original[1].decoded.pc;
    changed.edge[1].generated_target=layout.generated[0]+512;
    assert(li2_pg_plan_validate(&changed,&scratch)==LI2_PG_CORRUPT);++proof_controls;
    bad=compact;bad.original[64]=bad.original[0];bad.head[64].source_offset=bad.head[0].source_offset;
    assert(li2_pg_compact_validate(&bad,&scratch,&rebuilt)==LI2_PG_CORRUPT);++proof_controls;
}
static void recovery(void) {
    uint64_t raw[16],spill[4];for(unsigned i=0;i<16;i++)raw[i]=UINT64_C(0x1234000000000000)+17*i;
    for(unsigned i=0;i<4;i++)spill[i]=UINT64_C(0xaabb000000000000)+31*i;
    const uint64_t flags=UINT64_C(0x10ad7);struct li2_pg_recovered out;
    for(unsigned i=0;i<plan.heads;i++) {
        unsigned member=i/64,local=i%64;uintptr_t base=layout.generated[member]+512*local;
        const struct li2_pe_head *h=&plan.head[i];const struct li2_span_decoded *d=&plan.original[i];
        if(h->kind==LI2_PE_MOV) {
            assert(!li2_pg_compact_guard(&compact,member,local,&materialized));
            assert(!memcmp(&materialized,&plan.guard[i],sizeof materialized));
            for(unsigned j=0;j<plan.guard[i].boundaries;j++) {
                uint64_t frame[16];memcpy(frame,raw,sizeof frame);
                if(plan.guard[i].boundary[j].flags)frame[0]=(frame[0]&~UINT64_C(0xffff))|
                    ((flags&UINT64_C(0xd5))<<8)|((flags>>11)&1);
                struct li2_mg_recovered donor;
                uintptr_t pc=base+plan.guard[i].boundary[j].offset;
                assert(!li2_mg_recover(&plan.guard[i],pc,frame,flags,spill,&donor));
                assert(!li2_pg_compact_recover(&compact,pc,frame,flags,spill,&materialized,&out));
                assert(out.complete==1 && out.member==member && out.head==local && out.link==UINT32_MAX &&
                    out.kind==LI2_PG_GUARD && out.phase==donor.phase && out.original_pc==donor.original_pc &&
                    out.flags==donor.flags && !memcmp(out.gpr,donor.gpr,sizeof out.gpr));
                if(donor.phase==LI2_MG_AFTER)assert(out.original_pc==d->decoded.next_pc);
                ++recoveries;++mov_boundaries;
            }
        } else {
            assert(!li2_pg_compact_recover(&compact,base,raw,flags,spill,&materialized,&out));
            assert(out.complete==1 && out.member==member && out.head==local && out.link==UINT32_MAX &&
                out.phase==LI2_MG_BEFORE && out.original_pc==d->decoded.pc && out.flags==flags && !memcmp(out.gpr,raw,sizeof raw));
            ++recoveries;
            if(d->flow!=LI2_REGION_JMP) {
                unsigned length=d->flow==LI2_REGION_JCC?6:h->source_length;
                assert(!li2_pg_compact_recover(&compact,base+length,raw,flags,spill,&materialized,&out));
                assert(out.complete==1 && out.phase==LI2_MG_AFTER && out.original_pc==d->decoded.next_pc &&
                    out.flags==flags && !memcmp(out.gpr,raw,sizeof raw));++recoveries;
            }
        }
        assert(li2_pg_compact_recover(&compact,base+1,raw,flags,spill,&materialized,&out)==LI2_PG_MISS && !out.complete);
        assert(li2_pg_compact_recover(&compact,base+h->generated_length,raw,flags,spill,&materialized,&out)==LI2_PG_MISS && !out.complete);
        pc_refusals+=2;
    }
    for(unsigned offset=0;offset<4096;offset++) {
        unsigned j=offset/6;int valid=offset%6==0 && j<plan.links;
        memset(&materialized,0xa5,sizeof materialized);untouched=materialized;
        int e=li2_pg_compact_recover(&compact,layout.stubs+offset,raw,flags,spill,&materialized,&out);
        assert(!memcmp(&materialized,&untouched,sizeof materialized));
        if(valid) {
            assert(!e && out.complete==1 && out.member==UINT32_MAX && out.head==UINT32_MAX && out.link==j &&
                out.kind==LI2_PG_LINK && out.phase==LI2_PG_COMMITTED_EDGE &&
                out.original_pc==plan.edge[j].original_target && out.flags==flags && !memcmp(out.gpr,raw,sizeof raw));
            ++recoveries;++link_boundaries;
        } else {assert(e==LI2_PG_MISS && !out.complete);++pc_refusals;}
    }
}
static void stores(void) {
    static const unsigned char forms[4][7]={{0x89,7},{0x48,0x89,7},{0xc7,7,1,2,3,4},{0x48,0xc7,7,1,2,3,4}};
    static const unsigned lengths[4]={2,3,6,7};
    const unsigned char mov[]={0x48,0x89,0xc0},ret[]={0xc3};
    for(unsigned member=0;member<2;member++)for(unsigned form=0;form<4;form++) {
        empty();unsigned at_pc=0x100;
        for(unsigned i=0;i<65;i++) {
            if(i==63+member) {at(at_pc,forms[form],lengths[form]);at_pc+=lengths[form];}
            else {at(at_pc,mov,3);at_pc+=3;}
        }
        at(at_pc,ret,1);accepted(pages[0]+0x100,65,1,1);
        assert(plan.store_original[63+member].width_bytes==((form&1)?8:4));
        if(!member)assert(plan.guard[63].successor==layout.stubs && plan.guard[63].original.tf.next_pc==plan.original[64].decoded.pc);
        recovery();
    }
}
static void refusals(void) {
    static const unsigned char ret[]={0xc3},badop[]={0x0f,4},jcc[]={0x0f,0x85,0,0,0,0},jump[]={0xe9,0,0,0,0};
    empty();at(0x100,ret,1);refused(pages[0]+0x100,LI2_PGD_ROOT_UNSUPPORTED,LI2_PG_MISS);
    empty();at(0x100,badop,2);refused(pages[0]+0x100,LI2_PGD_SOURCE_INVALID,LI2_PG_BOUNDARY);
    empty();source[1][4095]=0x0f;refused(pages[1]+4095,LI2_PGD_SOURCE_TRUNCATED,LI2_PG_BOUNDARY);
    empty();at(0x100,jcc,6);rel(0x100,6,2,0x107);static const unsigned char overlapping[]={0x48,0x89,0xc0,0xc3};
    at(0x106,overlapping,4);refused(pages[0]+0x100,LI2_PGD_SOURCE_OVERLAP,LI2_PG_GRAPH);
    empty();at(0x100,jump,5);rel(0x100,5,1,8192);refused(pages[0]+0x100,LI2_PGD_OUTSIDE_PAIR,LI2_PG_GRAPH);
    empty();at(reg_chain(129),ret,1);refused(pages[0]+0x100,LI2_PGD_HEAD_LIMIT,LI2_PG_GRAPH);
    empty();for(unsigned i=0;i<9;i++) {at(0x100+6*i,jcc,6);rel(0x100+6*i,6,2,0x500+i);at(0x500+i,ret,1);}
    at(0x100+54,ret,1);refused(pages[0]+0x100,LI2_PGD_EXIT_LIMIT,LI2_PG_GRAPH);
    empty();for(unsigned i=0;i<255;i++) {unsigned x=0x100+16*i;at(x,jcc,6);rel(x,6,2,0x100+16*(2*i+1));at(x+6,jump,5);rel(x+6,5,1,0x100+16*(2*i+2));}
    refused(pages[0]+0x100,LI2_PGD_QUEUE_LIMIT,LI2_PG_GRAPH);
    empty();at(0x100,jump,5);rel(0x100,5,1,0x100);refused(pages[0]+0x100,LI2_PGD_NO_EXIT,LI2_PG_GRAPH);
    empty();unsigned end=reg_chain(64);at(end,ret,1);refused(pages[0]+0x100,LI2_PGD_SINGLE_MEMBER,LI2_PG_MISS);
    empty();end=reg_chain(64);for(unsigned i=0;i<8;i++) {at(end+6*i,jcc,6);rel(end+6*i,6,2,0x100+3*i);}
    at(end+48,ret,1);refused(pages[0]+0x100,LI2_PGD_LINK_LIMIT,LI2_PG_GRAPH);
    /* Real source-stage relocation failures, after a complete two-member
       graph. These must not classify generated decoder/spill contradictions. */
    static const unsigned char rip[]={0x48,0x8b,5,0,0,0,0};
    empty();end=reg_chain(64);at(end,rip,7);at(end+7,ret,1);bank(UINT64_C(0x600000000000));
    refused(pages[0]+0x100,LI2_PGD_RIP_REACH,LI2_PG_RELOCATION);
    empty();end=reg_chain(64);at(end,jump,5);rel(end,5,1,0x800);at(0x800,ret,1);bank(UINT64_C(0x600000000000));
    refused(pages[0]+0x100,LI2_PGD_BRANCH_REACH,LI2_PG_RELOCATION);
    empty();end=reg_chain(65);at(end,ret,1);bank(UINT64_C(0x600000000000));
    refused(pages[0]+0x100,LI2_PGD_FALLTHROUGH_REACH,LI2_PG_RELOCATION);
    static const unsigned char ripstore[]={0x48,0x89,5,0,0,0,0},store[]={0x48,0x89,7};
    empty();end=reg_chain(64);at(end,ripstore,7);at(end+7,ret,1);bank(UINT64_C(0x600000000000));
    refused(pages[0]+0x100,LI2_PGD_GUARD_RIP_REACH,LI2_PG_RELOCATION);
    empty();end=reg_chain(64);at(end,store,3);at(end+3,ret,1);bank(UINT64_C(0x600000000000));
    refused(pages[0]+0x100,LI2_PGD_GUARD_FOLLOW_REACH,LI2_PG_RELOCATION);
    static const unsigned char selected[7][4]={{0x0f,0xa2},{0x48,0x0f,0xc7,0xf0},{0x48,0x0f,0xc7,0xf8},
        {0xf3,0x0f,0xc7,0xf8},{0x0f,0x31},{0x0f,0x01,0xf9},{0x0f,0x05}};
    static const unsigned lengths[7]={2,4,4,4,2,3,2};
    for(unsigned i=0;i<7;i++) {empty();at(0x100,selected[i],lengths[i]);refused(pages[0]+0x100,LI2_PGD_ROOT_SELECTED,LI2_PG_MISS);assert(miss.detail==i+1);}
    for(unsigned i=1;i<=4;i++) {loop();inject=i;refused(pages[0]+0xe00,0,LI2_PG_DECODER);}
    empty();end=reg_chain(1);at(end,ret,1);inject=5;refused(pages[0]+0x100,0,LI2_PG_MISS);
    for(unsigned i=6;i<=7;i++) {empty();at(0x100,selected[4],2);inject=i;refused(pages[0]+0x100,0,LI2_PG_MISS);}
}
int main(void) {
    struct li2_decoder_stats before,after;
    assert(!li2_decoder_initialize(arena,sizeof arena,&before) && before.phase==2 && !before.first_fatal_reason);
    const struct li2_mg_range ranges[]={{pages[0],pages[1]+4096},{0x10000000,0x10013000},
        {table_at,table_at+8192},{0x70000008,0x70000010}};
    assert(!li2_mg_table_build(ranges,sizeof ranges/sizeof ranges[0],table_at,&table));
    loop();accepted(pages[0]+0xe00,65,0,2);
    assert(plan.source_mask==3 && plan.source_bytes==264 && plan.exit_pc[0]==pages[0]+0xf0a);
    assert(plan.edge[0].source_head==63 && plan.edge[0].target_head==64 && plan.edge[0].successor==0);
    assert(plan.edge[1].source_head==64 && plan.edge[1].target_head==0 && plan.edge[1].successor==0);
    recovery();whole_controls();stores();refusals();
    assert(!li2_decoder_stats(&after) && !memcmp(&before,&after,sizeof before));
    assert(positives==9 && classified==23 && terminal==7 && miss_controls==92 && proof_controls==26);
    assert(link_boundaries==10 && placement==9 && mov_boundaries>0 && recoveries>mov_boundaries);
    printf("{\"group_schema\":1,\"positives\":%u,\"classified\":%u,\"terminal\":%u,\"miss_controls\":%u,\"proof_controls\":%u,\"recoveries\":%u,\"mov_boundaries\":%u,\"link_boundaries\":%u,\"pc_refusals\":%u,\"placement_ready\":%u,\"full_bytes\":%zu,\"compact_bytes\":%zu,\"postseal_equal\":1,\"emitted_execution\":0}\n",
        positives,classified,terminal,miss_controls,proof_controls,recoveries,mov_boundaries,link_boundaries,pc_refusals,placement,sizeof plan,sizeof compact);
    return 0;
}
