/* Pure integrated descriptions and byte interpretation only. Independent PC
   rows/graph geometry are authored below, never copied from planner output.
   Existing MOV/JMP byte models and the old group fixture remain unchanged. */
#include "persistent_group_compact.h"
#include "tests/linked_jmp_dispatch/model.h"
#include "tests/linked_mov_guard/model.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#if !defined(LI2_PERSISTENT_DISPATCH) || LI2_PERSISTENT_DISPATCH != 1
#error "separate typed dispatch integration only"
#endif
static _Alignas(64) unsigned char arena[16U<<20];
static struct li2_pg_plan plan,scratch,changed;
static struct li2_pg_compact compact,rebuilt,bad;
static union li2_pg_guard materialized,recovery_scratch;
static struct li2_mg_table table;
static unsigned char source[2][4096];
static const uintptr_t pages[2]={0x400000,0x401000};
static const struct li2_pg_layout layout={{0x10000000,0x10008000},0x10010000,0x10011000,0x10012000};
static struct li2_mg_range ranges[4];
static uint64_t rows[128];
static unsigned kinds[128],lengths[128],expected_heads,expected_stores,expected_links,case_id;
static uintptr_t proof_base;
static unsigned positives,decoded_boundaries,sweeps,pc_refusals,typed_refusals,proof_refusals,binding_refusals;
static unsigned jd_models,mov_models,handoffs,model_calls,model_repeated,jd_recoveries,mov_recoveries,looped_models;
static unsigned model_active,nested,active_head,visited[128][64];
static uint64_t decoder_calls;
uint32_t __real_li2_decoder_decode(uint64_t,const unsigned char *,size_t,struct li2_decoded *);
uint32_t __wrap_li2_decoder_decode(uint64_t pc,const unsigned char *b,size_t n,struct li2_decoded *d) {
    ++decoder_calls;return __real_li2_decoder_decode(pc,b,n,d);
}
static uintptr_t generated(unsigned i) {return layout.generated[i/64]+512*(i%64);}
static void same_frame(const struct li2_pg_recovered *out,unsigned i,unsigned kind,unsigned phase,
                       uint64_t pc,const uint64_t raw[16],uint64_t flags) {
    assert(out->complete==1 && out->member==i/64 && out->head==i%64 && out->link==UINT32_MAX &&
        out->kind==kind && out->phase==phase && out->original_pc==pc && out->flags==flags &&
        !memcmp(out->gpr,raw,16*sizeof *raw));
}
static void visited_at(uintptr_t pc,const struct li2_mg_boundary *b,unsigned count) {
    unsigned found=0;
    for(unsigned j=0;j<count;j++)if(generated(active_head)+b[j].offset==pc) {
        if(visited[active_head][j]++)++model_repeated;++found;
    }
    assert(found==1);++model_calls;
}
int __real_li2_jd_recover(const struct li2_jd_plan *,uintptr_t,const uint64_t[16],uint64_t,
                         const uint64_t[4],struct li2_jd_recovered *);
int __wrap_li2_jd_recover(const struct li2_jd_plan *p,uintptr_t pc,const uint64_t raw[16],uint64_t flags,
                         const uint64_t spill[4],struct li2_jd_recovered *out) {
    int e=__real_li2_jd_recover(p,pc,raw,flags,spill,out);
    if(model_active && !nested) {
        assert(!e && kinds[active_head]==LI2_PG_DISPATCH &&
            !memcmp(p,&plan.guard[active_head].dispatch,sizeof *p));
        struct li2_pg_recovered typed;const uint64_t before=decoder_calls;nested=1;
        assert(!li2_pg_compact_recover(&compact,pc,raw,flags,spill,&recovery_scratch,&typed));nested=0;
        assert(decoder_calls==before && !memcmp(&recovery_scratch,&plan.guard[active_head],sizeof recovery_scratch));
        same_frame(&typed,active_head,LI2_PG_DISPATCH_MAP,LI2_JD_BEFORE,rows[active_head],out->gpr,out->flags);
        assert(out->complete==1 && out->phase==LI2_JD_BEFORE && out->original_pc==rows[active_head]);
        visited_at(pc,p->record.boundary,p->record.boundaries);
    }
    return e;
}
int __real_li2_mg_recover(const struct li2_mg_plan *,uintptr_t,const uint64_t[16],uint64_t,
                         const uint64_t[4],struct li2_mg_recovered *);
int __wrap_li2_mg_recover(const struct li2_mg_plan *p,uintptr_t pc,const uint64_t raw[16],uint64_t flags,
                         const uint64_t spill[4],struct li2_mg_recovered *out) {
    int e=__real_li2_mg_recover(p,pc,raw,flags,spill,out);
    if(model_active && !nested) {
        assert(!e && kinds[active_head]==LI2_PE_MOV && !memcmp(p,&plan.guard[active_head].mov,sizeof *p));
        struct li2_pg_recovered typed;const uint64_t before=decoder_calls;nested=1;
        assert(!li2_pg_compact_recover(&compact,pc,raw,flags,spill,&recovery_scratch,&typed));nested=0;
        assert(decoder_calls==before && !memcmp(&recovery_scratch,&plan.guard[active_head],sizeof recovery_scratch));
        same_frame(&typed,active_head,LI2_PG_GUARD,out->phase,out->original_pc,out->gpr,out->flags);
        assert(out->complete==1 && out->original_pc==rows[active_head]+(out->phase==LI2_MG_AFTER?lengths[active_head]:0));
        visited_at(pc,p->boundary,p->boundaries);
    }
    return e;
}
static uint64_t flags_for(unsigned n) {
    static const unsigned bits[6]={0,2,4,6,7,11};uint64_t f=0x602;
    for(unsigned j=0;j<6;j++)f|=(uint64_t)((n>>j)&1)<<bits[j];return f;
}
static void frame(uint64_t r[16]) {
    for(unsigned j=0;j<16;j++)r[j]=UINT64_C(0x1234567800000000)+0x101*j;
    r[7]=0x70000000;
}
static void at(unsigned offset,const unsigned char *b,unsigned length) {
    assert(offset<=8192 && length<=8192-offset);
    for(unsigned j=0;j<length;j++)source[(offset+j)/4096][(offset+j)%4096]=b[j];
}
static void head(unsigned offset,unsigned kind,const unsigned char *bytes,unsigned length) {
    assert(expected_heads<128);unsigned i=expected_heads++;
    rows[i]=pages[0]+offset;kinds[i]=kind;lengths[i]=length;expected_stores+=kind==LI2_PE_MOV;at(offset,bytes,length);
}
static void geometry(unsigned which) {
    case_id=which;expected_heads=expected_stores=expected_links=0;
    memset(source,0xcc,sizeof source);memset(rows,0,sizeof rows);memset(kinds,0,sizeof kinds);memset(lengths,0,sizeof lengths);
    const unsigned char jump_rax[]={0xff,0xe0},jump_rbx[]={0xff,0xe3},jump_r12[]={0x41,0xff,0xe4};
    const unsigned char mov[]={0x48,0x89,0xc0},store[]={0x48,0x89,7},add[]={0x48,0x83,0xc0,1};
    if(which==0 || which==4)head(which==4?4095:0x100,LI2_PG_DISPATCH,jump_rax,2);
    else if(which==1) {
        head(0x100,LI2_PE_MOV,store,3);head(0x103,LI2_PE_NONE,add,4);head(0x107,LI2_PG_DISPATCH,jump_rbx,2);
    } else {
        assert(which==2 || which==3);
        for(unsigned i=0;i<63;i++)head(0x100+3*i,LI2_PE_NONE,mov,3);
        const unsigned offset=0x100+3*63,target=0x1100;
        unsigned char jump[5]={0xe9,0,0,0,0};uint32_t delta=target-(offset+5);
        for(unsigned j=0;j<4;j++)jump[1+j]=(unsigned char)(delta>>(8*j));
        head(offset,LI2_PE_NONE,jump,5);head(target,LI2_PE_MOV,store,3);
        for(unsigned i=1;i<=4;i++)head(target+3*i,LI2_PE_NONE,mov,3);
        head(target+15,LI2_PG_DISPATCH,jump_r12,3);expected_links=1;
    }
    proof_base=which==3?UINT64_C(0x600000000000):UINT64_C(0x20000000);
    ranges[0]=(struct li2_mg_range){pages[0],pages[1]+4096};
    ranges[1]=(struct li2_mg_range){layout.generated[0],layout.spill+4096};
    ranges[2]=(struct li2_mg_range){proof_base,proof_base+((sizeof compact+4095)&~(size_t)4095)};
    ranges[3]=(struct li2_mg_range){0x70000008,0x70000010};
    assert(!li2_mg_table_build(ranges,4,proof_base+offsetof(struct li2_pg_compact,table),&table));
}
static void accepted(void) {
    struct li2_pg_miss miss,empty={.version=2};
    assert(!li2_pg_plan_pages(pages,source,rows[0],&layout,&table,&plan,&miss) && !memcmp(&miss,&empty,sizeof miss));
    assert(plan.version==2 && plan.ready==1 && !plan.result && plan.heads==expected_heads &&
        plan.exits==1 && plan.stores==expected_stores && plan.links==expected_links &&
        plan.member_heads[0]==(expected_heads<64?expected_heads:64) && plan.member_heads[1]==(expected_heads>64?expected_heads-64:0));
    assert(!li2_pg_plan_validate(&plan,&scratch) && !memcmp(&plan,&scratch,sizeof plan));
    assert(!li2_pg_compact_build(&plan,&scratch,&compact));
    assert(!li2_pg_compact_validate(&compact,&scratch,&rebuilt) && !memcmp(&compact,&rebuilt,sizeof compact));
    assert(plan.bytes==sizeof plan && compact.bytes==sizeof compact &&
        !memcmp((const unsigned char *)&plan+offsetof(struct li2_pg_plan,ready),
            (const unsigned char *)&compact+offsetof(struct li2_pg_compact,ready),
            offsetof(struct li2_pg_plan,guard)-offsetof(struct li2_pg_plan,ready)));
    assert(!memcmp(plan.source,source,sizeof source) && !memcmp(compact.source,source,sizeof source));
    unsigned bytes=0;
    for(unsigned i=0;i<expected_heads;i++) {
        const struct li2_pe_head *h=&plan.head[i];bytes+=lengths[i];
        assert(h->kind==kinds[i] && h->source_length==lengths[i] && h->source_page==(rows[i]-pages[0])/4096 &&
            h->source_offset==(rows[i]-pages[0])%4096 && plan.original[i].decoded.pc==rows[i]);
        for(unsigned j=0;j<i;j++)assert(rows[j]!=rows[i]);
        if(kinds[i]==LI2_PG_DISPATCH) {
            assert(!h->successor_count && !h->successors[0] && !h->successors[1] && plan.exit_pc[0]==rows[i]);
            assert(!memcmp(&plan.frontier[0],&plan.original[i],sizeof plan.frontier[0]));
            const struct li2_jd_binding expected={proof_base+offsetof(struct li2_pg_compact,original),
                {layout.generated[0],layout.generated[1]},expected_heads,i};
            assert(!memcmp(&plan.guard[i].dispatch.binding,&expected,sizeof expected));
        } else assert(h->successor_count==1 && h->successors[0]==i+1 && !h->successors[1]);
    }
    assert(plan.source_bytes==bytes && plan.source_mask==((case_id>=2)?3U:1U));
    if(expected_links)assert(plan.edge[0].source_head==63 && plan.edge[0].target_head==64 && !plan.edge[0].successor &&
        plan.edge[0].original_target==rows[64] && plan.edge[0].generated_target==layout.generated[1] &&
        plan.edge[0].stub==layout.stubs && plan.edge[0].slot==layout.slots);
    ++positives;
}
static void decode_boundary(uintptr_t pc,const unsigned char *b,unsigned length) {
    struct li2_decoded d;assert(length && length<=15);
    assert(!li2_decoder_decode(pc,b,length,&d) && d.abi_version==1 && d.decode_status==LI2_VALID &&
        d.pc==pc && d.next_pc==pc+length && d.length==length && d.available==length && !memcmp(d.bytes,b,length));
    for(unsigned j=length;j<16;j++)assert(!d.bytes[j]);++decoded_boundaries;
}
static void boundary_sweep(unsigned i,const struct li2_mg_boundary *b,unsigned count) {
    for(unsigned j=0;j<count;j++) {
        uint64_t logical[16],raw[16],spill[4];frame(logical);memcpy(raw,logical,sizeof raw);
        const unsigned *regs=kinds[i]==LI2_PG_DISPATCH?plan.guard[i].dispatch.record.scratch_regs:plan.guard[i].mov.scratch_regs;
        const uint64_t flags=flags_for(j%64);
        for(unsigned k=0;k<4;k++) {spill[k]=logical[regs[k]];if(b[j].dirty&(1U<<k))raw[regs[k]]=UINT64_C(0xfeed000000000000)+k;}
        if(b[j].flags)raw[0]=(raw[0]&~UINT64_C(0xffff))|(((flags&0xd5)|2)<<8)|((flags>>11)&1);
        struct li2_pg_recovered out;const uint64_t before=decoder_calls;
        memset(&recovery_scratch,0xa5,sizeof recovery_scratch);
        assert(!li2_pg_compact_recover(&compact,generated(i)+b[j].offset,raw,flags,spill,&recovery_scratch,&out));
        assert(decoder_calls==before && !memcmp(&recovery_scratch,&plan.guard[i],sizeof recovery_scratch));
        unsigned phase=kinds[i]==LI2_PG_DISPATCH?LI2_JD_BEFORE:b[j].phase;
        same_frame(&out,i,kinds[i]==LI2_PG_DISPATCH?LI2_PG_DISPATCH_MAP:LI2_PG_GUARD,
            phase,rows[i]+(phase==LI2_MG_AFTER?lengths[i]:0),logical,flags);++sweeps;
    }
}
static int interval_allowed(uint64_t first) {
    if(first>UINT64_MAX-8)return 0;
    for(unsigned j=0;j<4;j++)if(first<ranges[j].end && ranges[j].first<first+8)return 0;
    return 1;
}
static void mov_model(unsigned i,const uint64_t r[16],uint64_t flags) {
    assert(kinds[i]==LI2_PE_MOV);struct model_result result;struct li2_mg_plan actual;
    assert(!li2_pg_compact_guard(&compact,i/64,i%64,&actual) && !memcmp(&actual,&plan.guard[i].mov,sizeof actual));
    const uint64_t before=decoder_calls;active_head=i;model_active=1;
    assert(!model_run(&actual,r,flags,&result));model_active=0;
    assert(decoder_calls==before && result.steps && result.recoveries);mov_recoveries+=result.recoveries;
    int allowed=interval_allowed(r[7]);assert(result.writes==(unsigned)allowed && result.rejected==(unsigned)!allowed);
    if(allowed)assert(result.first==r[7] && result.width==8 && result.value==r[0]);++mov_models;
}
static void dispatch_model(unsigned i,uint64_t target,int target_index,uint64_t flags) {
    uint64_t raw[16],spill[4]={11,22,33,44};frame(raw);raw[plan.instruction[i].dispatch.target]=target;
    struct jd_model_result result;struct li2_jd_plan actual;
    assert(!li2_pg_compact_dispatch(&compact,i/64,i%64,&actual) && !memcmp(&actual,&plan.guard[i].dispatch,sizeof actual));
    const uint64_t before=decoder_calls;active_head=i;model_active=1;
    assert(!jd_model_run(&actual,rows,raw,flags,&result));model_active=0;
    assert(decoder_calls==before && result.steps==result.recoveries && result.recoveries);
    jd_recoveries+=result.recoveries;looped_models+=result.row_reads>1;
    if(target_index<0)assert(result.miss==1 && !result.hit && !result.cell_writes && result.target==rows[i] && result.row_reads==expected_heads);
    else {
        unsigned target_head=(unsigned)target_index;assert(target_head<expected_heads && rows[target_head]==target);
        assert(result.hit==1 && !result.miss && result.cell_writes==1 && result.row_reads==target_head+1 && result.target==generated(target_head));
        struct li2_pg_recovered out;
        assert(!li2_pg_compact_recover(&compact,result.target,raw,flags,spill,&recovery_scratch,&out));
        unsigned kind=kinds[target_head]==LI2_PG_DISPATCH?LI2_PG_DISPATCH_MAP:kinds[target_head]==LI2_PE_MOV?LI2_PG_GUARD:
            plan.original[target_head].flow==LI2_REGION_JMP?LI2_PG_BRANCH:LI2_PG_COPIED;
        same_frame(&out,target_head,kind,LI2_MG_BEFORE,rows[target_head],raw,flags);
        if(kinds[target_head]==LI2_PE_MOV) {mov_model(target_head,raw,flags);++handoffs;}
    }
    ++jd_models;
}
static void model_paths(void) {
    for(unsigned i=0;i<expected_heads;i++)if(kinds[i]==LI2_PE_MOV) {
        memset(visited[i],0,sizeof visited[i]);
        uint64_t addresses[8]={0,0x70000000,0x70000001,0x70000008,0x7000000f,UINT64_MAX-7,UINT64_MAX,proof_base};
        for(unsigned j=0;j<8;j++) {uint64_t r[16];frame(r);r[7]=addresses[j];mov_model(i,r,flags_for(7*j));}
        if(case_id==1)for(unsigned f=0;f<64;f++)for(unsigned reject=0;reject<2;reject++) {
            uint64_t r[16];frame(r);r[7]=reject?0x70000008:0x70000000;mov_model(i,r,flags_for(f));
        }
        for(unsigned j=0;j<plan.guard[i].mov.boundaries;j++)assert(visited[i][j]);
    }
    unsigned i=expected_heads-1;assert(kinds[i]==LI2_PG_DISPATCH);memset(visited[i],0,sizeof visited[i]);
    for(unsigned j=0;j<expected_heads;j++)dispatch_model(i,rows[j],(int)j,flags_for(j%64));
    dispatch_model(i,rows[0]+1,-1,flags_for(63));dispatch_model(i,pages[1]+0x800,-1,flags_for(0));
    if(case_id==0)for(unsigned f=0;f<64;f++) {
        dispatch_model(i,rows[0],0,flags_for(f));dispatch_model(i,rows[0]+1,-1,flags_for(f));
    }
    /* Both bank-selection paths are reachable only in the two-member case.
       Every boundary is independently decoded/swept in all five cases. */
    if(expected_heads==70)for(unsigned j=0;j<plan.guard[i].dispatch.record.boundaries;j++)assert(visited[i][j]);
}
static void generated_maps(void) {
    uint64_t raw[16],spill[4]={11,22,33,44};frame(raw);const uint64_t flags=flags_for(63);
    for(unsigned i=0;i<expected_heads;i++) {
        unsigned char valid[512]={0};const unsigned char *image=compact.image[i/64]+512*(i%64);
        const struct li2_pe_head *h=&plan.head[i];memset(&materialized,0,sizeof materialized);
        if(kinds[i]==LI2_PG_DISPATCH || kinds[i]==LI2_PE_MOV) {
            const struct li2_mg_boundary *b;unsigned count;
            if(kinds[i]==LI2_PG_DISPATCH) {
                assert(!li2_pg_compact_dispatch(&compact,i/64,i%64,&materialized.dispatch));
                assert(li2_pg_compact_guard(&compact,i/64,i%64,&recovery_scratch.mov)==LI2_PG_CORRUPT);++typed_refusals;
                b=materialized.dispatch.record.boundary;count=materialized.dispatch.record.boundaries;
            } else {
                assert(!li2_pg_compact_guard(&compact,i/64,i%64,&materialized.mov));
                assert(li2_pg_compact_dispatch(&compact,i/64,i%64,&recovery_scratch.dispatch)==LI2_PG_CORRUPT);++typed_refusals;
                b=materialized.mov.boundary;count=materialized.mov.boundaries;
            }
            assert(!memcmp(&materialized,&plan.guard[i],sizeof materialized));
            for(unsigned j=0;j<count;j++) {
                assert(b[j].offset<512 && !valid[b[j].offset]);valid[b[j].offset]=1;
                decode_boundary(generated(i)+b[j].offset,image+b[j].offset,b[j].length);
            }
            boundary_sweep(i,b,count);
        } else {
            assert(li2_pg_compact_guard(&compact,i/64,i%64,&materialized.mov)==LI2_PG_CORRUPT &&
                li2_pg_compact_dispatch(&compact,i/64,i%64,&materialized.dispatch)==LI2_PG_CORRUPT);typed_refusals+=2;
            unsigned n=plan.original[i].flow==LI2_REGION_JMP?5:lengths[i];valid[0]=1;
            decode_boundary(generated(i),image,n);struct li2_pg_recovered out;
            assert(!li2_pg_compact_recover(&compact,generated(i),raw,flags,spill,&recovery_scratch,&out));
            same_frame(&out,i,plan.original[i].flow==LI2_REGION_JMP?LI2_PG_BRANCH:LI2_PG_COPIED,LI2_MG_BEFORE,rows[i],raw,flags);
            if(plan.original[i].flow!=LI2_REGION_JMP) {
                valid[n]=1;decode_boundary(generated(i)+n,image+n,5);
                assert(!li2_pg_compact_recover(&compact,generated(i)+n,raw,flags,spill,&recovery_scratch,&out));
                same_frame(&out,i,LI2_PG_EDGE,LI2_MG_AFTER,rows[i+1],raw,flags);
            }
        }
        for(unsigned off=0;off<512;off++)if(!valid[off]) {
            struct li2_pg_recovered out;assert(li2_pg_compact_recover(&compact,generated(i)+off,raw,flags,spill,&recovery_scratch,&out)==LI2_PG_MISS && !out.complete);++pc_refusals;
        }
        for(unsigned off=h->generated_length;off<512;off++)assert(image[off]==0xcc);
    }
    for(unsigned off=0;off<4096;off++) {
        struct li2_pg_recovered out;int e=li2_pg_compact_recover(&compact,layout.stubs+off,raw,flags,spill,&recovery_scratch,&out);
        if(expected_links && off==0) {
            decode_boundary(layout.stubs,compact.stub_image,6);
            assert(!e && out.complete==1 && out.member==UINT32_MAX && out.head==UINT32_MAX && !out.link &&
                out.kind==LI2_PG_LINK && out.phase==LI2_PG_COMMITTED_EDGE && out.original_pc==rows[64] &&
                out.flags==flags && !memcmp(out.gpr,raw,sizeof raw));
        } else {assert(e==LI2_PG_MISS && !out.complete);++pc_refusals;}
    }
}
static void proof_controls(void) {
    assert(case_id==2 && expected_heads==70);const unsigned i=69;
#define FULL(f) offsetof(struct li2_pg_plan,f)
#define SMALL(f) offsetof(struct li2_pg_compact,f)
    const size_t full[]={FULL(version),FULL(source)+0x100,FULL(image)+32768+5*512,
        FULL(image)+32768+5*512+plan.head[i].generated_length,FULL(original)+i*sizeof plan.original[0]+offsetof(struct li2_span_decoded,decoded.code),
        FULL(instruction)+i*sizeof plan.instruction[0]+offsetof(struct li2_jd_descriptor,target),
        FULL(guard)+i*sizeof plan.guard[0]+offsetof(struct li2_jd_plan,record.boundary)+5*sizeof(struct li2_mg_boundary)+offsetof(struct li2_mg_boundary,flags),
        FULL(guard)+i*sizeof plan.guard[0]+sizeof(struct li2_jd_plan),FULL(guard)+127*sizeof plan.guard[0],
        FULL(member_heads)+4,FULL(exit_pc),FULL(frontier)+offsetof(struct li2_span_decoded,refusal),
        FULL(head)+i*sizeof plan.head[0]+offsetof(struct li2_pe_head,successor_count),FULL(table)+offsetof(struct li2_mg_table,root),
        FULL(edge)+offsetof(struct li2_pg_edge,target_head),FULL(stub_image)+4095};
    const size_t small[]={SMALL(version),SMALL(source)+0x100,SMALL(image)+32768+5*512,
        SMALL(image)+32768+5*512+compact.head[i].generated_length,SMALL(original)+i*sizeof compact.original[0]+offsetof(struct li2_span_decoded,decoded.code),
        SMALL(instruction)+i*sizeof compact.instruction[0]+offsetof(struct li2_jd_descriptor,target),
        SMALL(guard)+i*sizeof compact.guard[0]+offsetof(struct li2_jd_record,boundary)+5*sizeof(struct li2_mg_boundary)+offsetof(struct li2_mg_boundary,flags),
        SMALL(guard)+i*sizeof compact.guard[0]+offsetof(struct li2_jd_record,boundary)+63*sizeof(struct li2_mg_boundary),
        SMALL(guard)+127*sizeof compact.guard[0],SMALL(member_heads)+4,SMALL(exit_pc),SMALL(frontier)+offsetof(struct li2_span_decoded,refusal),
        SMALL(head)+i*sizeof compact.head[0]+offsetof(struct li2_pe_head,successor_count),SMALL(table)+offsetof(struct li2_mg_table,root),
        SMALL(edge)+offsetof(struct li2_pg_edge,target_head),SMALL(stub_image)+4095};
#undef FULL
#undef SMALL
    assert(sizeof full/sizeof full[0]==16 && sizeof small/sizeof small[0]==16);
    for(unsigned j=0;j<16;j++) {
        changed=plan;((unsigned char *)&changed)[full[j]]^=1;
        assert(li2_pg_plan_validate(&changed,&scratch)==LI2_PG_CORRUPT);++proof_refusals;
        bad=compact;((unsigned char *)&bad)[small[j]]^=1;
        assert(li2_pg_compact_validate(&bad,&scratch,&rebuilt)==LI2_PG_CORRUPT);++proof_refusals;
    }
    changed=plan;changed.original[64]=changed.original[0];changed.head[64].source_page=changed.head[0].source_page;changed.head[64].source_offset=changed.head[0].source_offset;
    assert(li2_pg_plan_validate(&changed,&scratch)==LI2_PG_CORRUPT);++proof_refusals;
    bad=compact;bad.original[64]=bad.original[0];bad.head[64].source_page=bad.head[0].source_page;bad.head[64].source_offset=bad.head[0].source_offset;
    assert(li2_pg_compact_validate(&bad,&scratch,&rebuilt)==LI2_PG_CORRUPT);++proof_refusals;
    changed=plan;changed.original[i].decoded.code^=1;changed.frontier[0]=changed.original[i];changed.instruction[i].dispatch.decoded=changed.original[i].decoded;
    assert(li2_pg_plan_validate(&changed,&scratch)==LI2_PG_CORRUPT);++proof_refusals;
    bad=compact;bad.original[i].decoded.code^=1;bad.frontier[0]=bad.original[i];bad.instruction[i].dispatch.decoded=bad.original[i].decoded;
    assert(li2_pg_compact_validate(&bad,&scratch,&rebuilt)==LI2_PG_CORRUPT);++proof_refusals;
    /* A valid standalone emitter bound to a different immutable row array
       still cannot be substituted into the full or compact group proof. */
    struct li2_jd_plan other;struct li2_jd_binding binding=plan.guard[i].dispatch.binding;binding.rows+=4096;
    const struct li2_jd_descriptor *d=&plan.instruction[i].dispatch;
    assert(!li2_jd_emit(rows[i],d->decoded.bytes,d->available,generated(i),layout.spill,&binding,&other) && !li2_jd_validate(&other));
    changed=plan;memset(&changed.guard[i],0,sizeof changed.guard[i]);changed.guard[i].dispatch=other;
    memcpy(changed.image[i/64]+512*(i%64),other.image,other.record.image_bytes);
    assert(li2_pg_plan_validate(&changed,&scratch)==LI2_PG_CORRUPT);++proof_refusals;
    bad=compact;bad.guard[i].dispatch=other.record;memcpy(bad.image[i/64]+512*(i%64),other.image,other.record.image_bytes);
    assert(li2_pg_compact_validate(&bad,&scratch,&rebuilt)==LI2_PG_CORRUPT);++proof_refusals;
}
static void binding_controls(void) {
    for(unsigned j=0;j<10;j++) {
        uintptr_t pair[2]={pages[0],pages[1]},at=table.address;unsigned heads=70,head_index=69;
        struct li2_pg_layout candidate=layout;struct li2_jd_binding out;
        if(j==0)heads=0;if(j==1)heads=129;if(j==2)head_index=70;
        if(j==3)at=offsetof(struct li2_pg_plan,table)-1;if(j==4)at++;
        if(j==5)at=pages[0]-offsetof(struct li2_pg_plan,original)+offsetof(struct li2_pg_plan,table);
        if(j==6)at=layout.generated[0]-offsetof(struct li2_pg_plan,original)+offsetof(struct li2_pg_plan,table);
        if(j==7)pair[1]=pair[0];if(j==8)candidate.generated[1]=candidate.generated[0];
        if(j==9)at=UINT64_C(0x800000000000);
        assert(li2_pg_dispatch_binding(pair,&candidate,at,heads,head_index,&out)==LI2_PG_ARGUMENT);++binding_refusals;
    }
}
int main(void) {
    struct li2_decoder_stats before,after;
    assert(!li2_decoder_initialize(arena,sizeof arena,&before) && before.phase==2 && !before.first_fatal_reason);
    _Static_assert(offsetof(struct li2_pg_plan,original)==offsetof(struct li2_pg_compact,original),"immutable row location");
    _Static_assert(offsetof(struct li2_pg_plan,table)==offsetof(struct li2_pg_compact,table),"immutable table location");
    _Static_assert(sizeof plan==981312 && sizeof compact==353600,"unchanged bounded storage");
    for(unsigned which=0;which<5;which++) {
        geometry(which);accepted();generated_maps();model_paths();
        if(which==2) {proof_controls();binding_controls();}
    }
    assert(!model_active && !nested && !li2_decoder_stats(&after) && !memcmp(&before,&after,sizeof before));
    assert(positives==5 && sweeps==301 && decoded_boundaries==575 && typed_refusals==282 && pc_refusals==94145);
    assert(proof_refusals==38 && binding_refusals==10 && jd_models==283 && mov_models==155 && handoffs==3);
    assert(jd_recoveries==37346 && mov_recoveries==5143 && looped_models==146);
    assert(model_calls==2*(jd_recoveries+mov_recoveries) && model_calls==84978 && model_repeated==84686);
    printf("{\"dispatch_integration_schema\":1,\"graphs\":%u,\"decoded_boundaries\":%u,\"typed_boundary_sweeps\":%u,\"pc_refusals\":%u,\"typed_refusals\":%u,\"proof_refusals\":%u,\"binding_refusals\":%u,\"jmp_models\":%u,\"mov_models\":%u,\"jmp_to_mov\":%u,\"typed_model_recoveries\":%u,\"repeated_model_boundaries\":%u,\"jmp_recoveries\":%u,\"mov_recoveries\":%u,\"looped_models\":%u,\"full_bytes\":%zu,\"compact_bytes\":%zu,\"postseal_equal\":1,\"emitted_execution\":0}\n",
        positives,decoded_boundaries,sweeps,pc_refusals,typed_refusals,proof_refusals,binding_refusals,jd_models,mov_models,handoffs,
        model_calls,model_repeated,jd_recoveries,mov_recoveries,looped_models,sizeof plan,sizeof compact);
    return 0;
}
