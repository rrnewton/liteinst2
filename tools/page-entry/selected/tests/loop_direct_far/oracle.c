/* Additive actual-emitter component. The entire old oracle and all its
   assertions run first. All generated instructions remain nonexecuted data. */
#define main old_loop_main
#include "tests/loop_plan/oracle.c"
#undef main

static unsigned adapters,near_adapters,far_adapters,far_models,literal_refusals;
static unsigned direct_corruptions,far_plans,plan_corruptions,relocation_cases,relocation_controls;
static uint64_t far_steps;
static struct li2_pg_plan saved_plan;
static struct li2_le_witness saved_choice,check_choice;
int __real_li2_ld_recover(const struct li2_dd_plan *,uintptr_t,const uint64_t[16],uint64_t,
    const uint64_t[4],struct li2_dd_recovered *);
int __wrap_li2_ld_recover(const struct li2_dd_plan *p,uintptr_t pc,const uint64_t r[16],uint64_t flags,
    const uint64_t spill[4],struct li2_dd_recovered *out) {
    /* Suppress the old wrapper's nested bookkeeping whether the linker folds
       or interposes the same-TU v1 call. The one real API call stays intact. */
    unsigned was_nested=nested;nested=1;uint64_t before=calls;
    int e=__real_li2_ld_recover(p,pc,r,flags,spill,out);nested=was_nested;assert(calls==before);
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
static void raw_frame(uint64_t raw[16]) {
    for(unsigned i=0;i<16;i++)raw[i]=UINT64_C(0x1234567800000000)+0x101*i;
}
static void adapter(uintptr_t generated,uintptr_t pc,unsigned cc,unsigned mask,unsigned want_far) {
    unsigned char bytes[2]={(unsigned char)(cc==16?0xeb:0x70+cc),62};
    struct li2_jd_binding binding={.rows=generated+0x40000,.image={generated,generated+0x8000},
        .heads=4,.head=0,.directory=generated+0x20000};
    uintptr_t internal[2]={0,0};
    if(cc!=16)for(unsigned a=0;a<2;a++)if(!(mask&(1U<<a)))internal[a]=generated+1024;
    struct li2_dd_plan p,old;
    int old_result=li2_dd_emit(pc,bytes,2,mask,generated,generated+0x12000,&binding,internal,&old);
    assert(!li2_ld_emit(pc,bytes,2,mask,generated,generated+0x12000,&binding,internal,&p));
    assert(!li2_ld_validate(&p) && p.original.version==1 && p.record.version==(want_far?2U:1U));
    unsigned prefix=cc==16?0U:mask==3?21U:11U;
    assert(p.record.image_bytes==206U+prefix+9U*want_far && p.record.miss_offset==153U+prefix &&
        p.record.hit_offset==200U+prefix+9U*want_far &&
        p.record.boundaries==37U+(cc==16?0U:mask==3?3U:2U));
    uint64_t raw[16],spill[4]={0x1234,0x5678,0x9abc,0xdef0};raw_frame(raw);
    if(!want_far) {
        assert(!old_result && !memcmp(&p,&old,sizeof p) && !li2_dd_validate(&p));++near_adapters;
    } else {
        assert(old_result==LI2_DD_RELOCATION && old.record.version==1 && !old.record.ready &&
            old.record.image_bytes==old.record.miss_offset+5 && li2_dd_validate(&p)==LI2_DD_CORRUPT);
        struct li2_dd_recovered got;
        assert(li2_dd_recover(&p,p.generated,raw,flags_for(63),spill,&got)!=0);
        unsigned at=p.record.miss_offset;
        assert(!memcmp(p.image+at,"\xff\x25\0\0\0\0",6));
        for(unsigned i=0;i<8;i++)assert(p.image[at+6+i]==(unsigned char)(pc>>(8*i)));
        for(unsigned i=0;i<14;i++) {
            struct li2_dd_plan changed=p;changed.image[at+i]^=1;
            assert(li2_ld_validate(&changed)==LI2_DD_CORRUPT);++direct_corruptions;
        }
        for(unsigned i=0;i<8;i++) {
            struct li2_dd_plan forged=p;
            forged.record.boundary[0]=(struct li2_mg_boundary){at+6+i,1,0,0,LI2_MG_PHYSICAL,LI2_DD_BEFORE};
            uint64_t before=calls;
            assert(li2_ld_recover(&p,generated+at+6+i,raw,flags_for(63),spill,&got)==LI2_DD_CORRUPT &&
                li2_ld_recover(&forged,generated+at+6+i,raw,flags_for(63),spill,&got)==LI2_DD_CORRUPT && calls==before);
            ++literal_refusals;
        }
        struct li2_dd_plan changed=p;changed.record.version=1;
        assert(li2_ld_validate(&changed)==LI2_DD_CORRUPT);++direct_corruptions;++far_adapters;
    }
    uint64_t visited=0;
    for(unsigned f=0;f<64;f++)for(unsigned mode=0;mode<3;mode++) {
        struct li2_jd_domain_directory dir={.version=1,.serial=40};
        for(unsigned a=0;a<(cc==16?1U:2U);a++)if(mask&(1U<<a))
            dir.row[dir.count++]=(struct li2_jd_domain_row){p.original.target[a]+(mode==1),generated+0x80000,7,0,0};
        if(mode==2)dir.count=0;
        struct dd_model_result out;uint64_t flags=flags_for(f);
        assert(!dd_model_run(&p,&dir,raw,flags,&out));
        unsigned arm=cc==16?0U:dd_model_taken(cc,flags)?0U:1U;
        if(!(mask&(1U<<arm)))assert(out.internal && !out.hit && !out.miss && out.target==internal[arm] && !out.cell_writes);
        else if(!mode)assert(out.hit && !out.miss && !out.internal && out.target==generated+0x80000 && out.cell_writes==1);
        else assert(out.miss && !out.hit && !out.internal && out.target==pc && !out.cell_writes);
        assert(out.steps==out.recoveries);visited|=out.visited;far_steps+=out.steps;++far_models;
    }
    /* JMP has an unreachable equal-target second selection arm; all real
       boundary rows in each adapter remain reached by these directory cases. */
    assert(visited==((UINT64_C(1)<<p.record.boundaries)-1));
    for(unsigned offset=0;offset<512;offset++) {
        unsigned found=0;for(unsigned j=0;j<p.record.boundaries;j++)found+=p.record.boundary[j].offset==offset;
        if(!found) {
            struct li2_dd_recovered got;uint64_t before=calls;
            assert(li2_ld_recover(&p,generated+offset,raw,flags_for(63),spill,&got)==LI2_DD_CORRUPT && calls==before);
        }
    }
    ++adapters;
}
static void standalone(void) {
    const uintptr_t generated=UINT64_C(0x4000000000);
    const int64_t delta[6]={-INT64_C(2147483649),-INT64_C(2147483648),-INT64_C(2147483647),
        INT64_C(2147483646),INT64_C(2147483647),INT64_C(2147483648)};
    for(unsigned j=0;j<6;j++)for(unsigned shape=0;shape<3;shape++) {
        unsigned prefix=shape==0?0U:shape==1?11U:21U;
        uintptr_t pc=(uintptr_t)((int64_t)(generated+153+prefix+5)+delta[j]);
        adapter(generated,pc,shape?4:16,shape==2?3:1,j==0||j==5);
    }
    for(unsigned cc=0;cc<16;cc++)for(unsigned mask=1;mask<=3;mask++)
        adapter(0x10000000,UINT64_C(0x700000000200),cc,mask,1);
    adapter(0x10000000,UINT64_C(0x700000000200),16,1,1);
    for(unsigned shape=0;shape<3;shape++)
        adapter(UINT64_C(0x700000000000),0x400200,shape?4:16,shape==2?3:1,1);
}
static void separated(uintptr_t page,uintptr_t generated) {
    pages[0]=page;pages[1]=page+4096;memset(source,0xcc,sizeof source);
    layout=(struct li2_pg_layout){{generated,generated+0x8000},generated+0x10000,
        generated+0x11000,generated+0x12000,generated+0x20000};
    const struct li2_mg_range range[4]={{page,page+8192},{generated,generated+0x13000},
        {generated+0x20000,generated+0x23000},{generated+0x30000,generated+0x90000}};
    assert(!li2_mg_table_build(range,4,generated+0x30000+offsetof(struct li2_pg_compact,table),&table));
}
static void whole_plans(void) {
    for(unsigned direction=0;direction<2;direction++)for(unsigned root=0;root<2;root++) {
        uintptr_t page=direction?UINT64_C(0x700000000000):0x400000;
        uintptr_t generated=direction?0x10000000:UINT64_C(0x700000000000);
        separated(page,generated);put(512,tunables,sizeof tunables);
        assert(li2_pg_placement(page+512,&layout)==0 && li2_lp_placement(page+512,&layout)==1);
        accept(page+512+(root?23:0),28,2,0,0);literal_graph(page+512,root?5:0);
        uint64_t before_steps=direct_steps,before_typed=typed_direct;models(0);
        assert(typed_direct-before_typed==2*(direct_steps-before_steps));
        unsigned count=0;
        for(unsigned i=0;i<compact.heads;i++)if(compact.head[i].kind==LI2_PG_DIRECT) {
            assert(compact.guard[i].direct.version==2);++count;
            unsigned at=compact.guard[i].direct.miss_offset;
            for(unsigned byte=0;byte<8;byte++) {
                bad=compact;bad.image[i/64][512*(i%64)+at+6+byte]^=1;
                assert(li2_lp_compact_validate(&bad,&scratch,&rebuilt,&witness)==LI2_PG_CORRUPT);++plan_corruptions;
                bad=compact;bad.guard[i].direct.boundary[0].offset=at+6+byte;
                uint64_t raw[16],spill[4]={0};raw_frame(raw);struct li2_pg_recovered got;
                uint64_t before=calls;
                assert(li2_lp_compact_recover(&bad,generated+512*i+at+6+byte,raw,flags_for(63),spill,&recovery,&got)==LI2_PG_CORRUPT && calls==before);
                ++plan_corruptions;
            }
        }
        assert(count==2);++far_plans;
    }
}
static void relocation_negative(const struct li2_pg_miss *original,int result,unsigned policy) {
    saved_plan=full;unsigned reason=policy==12?li2_lp_relocation_reason(&full,original,result,&scratch,&check_choice):
        li2_lp_fallback_relocation_reason(&full,original,result,&scratch);
    assert(reason && !memcmp(&full,&saved_plan,sizeof full));
    const size_t fields[8]={offsetof(struct li2_pg_miss,version),offsetof(struct li2_pg_miss,status),
        offsetof(struct li2_pg_miss,reason),offsetof(struct li2_pg_miss,site),offsetof(struct li2_pg_miss,pc),
        offsetof(struct li2_pg_miss,detail),offsetof(struct li2_pg_miss,pc)+7,offsetof(struct li2_pg_miss,detail)+7};
    for(unsigned j=0;j<8;j++) {
        struct li2_pg_miss changed=*original;((unsigned char *)&changed)[fields[j]]^=1;
        assert(!(policy==12?li2_lp_relocation_reason(&full,&changed,result,&scratch,&check_choice):
            li2_lp_fallback_relocation_reason(&full,&changed,result,&scratch)));++relocation_controls;
    }
    for(unsigned j=0;j<8;j++) {
        full=saved_plan;
        if(j==0)full.source[0][512]^=1;
        if(j==1)full.layout.generated[0]+=4096;
        if(j==2)full.entry++;
        if(j==3)full.decoder_result=1;
        if(j==4)full.guard_result^=1;
        if(j==5)full.ready=1;
        if(j==6)full.original[0].rip_target^=1;
        if(j==7)full.result^=1;
        assert(!(policy==12?li2_lp_relocation_reason(&full,original,result,&scratch,&check_choice):
            li2_lp_fallback_relocation_reason(&full,original,result,&scratch)));++relocation_controls;
    }
    full=saved_plan;
    assert(!(policy==12?li2_lp_relocation_reason(&full,original,LI2_PG_ARGUMENT,&scratch,&check_choice):
        li2_lp_fallback_relocation_reason(&full,original,LI2_PG_ARGUMENT,&scratch)));++relocation_controls;
}
static void relocation(void) {
    for(unsigned direction=0;direction<2;direction++)for(unsigned store=0;store<2;store++) {
        uintptr_t page=direction?UINT64_C(0x700000000000):0x400000;
        uintptr_t generated=direction?0x10000000:UINT64_C(0x700000000000);
        separated(page,generated);
        unsigned char bytes[9]={0x80,0x3d,0,0,0,0,0,0x75,0xf7};
        if(store){bytes[0]=0x48;bytes[1]=0x89;bytes[2]=0x05;}
        uintptr_t target=page+0x900000;
        put32(bytes+(store?3:2),(uint32_t)(target-(page+512+7)));put(512,bytes,sizeof bytes);
        struct li2_pg_miss miss;int e=li2_lp_plan_pages(pages,source,page+512,&layout,&table,&full,&miss,&witness);
        assert(e==LI2_PG_RELOCATION && !full.ready && witness.ready==1 && !witness.result &&
            miss.version==12 && miss.site==LI2_PGD_EMIT && miss.pc==page+512 &&
            miss.reason==(store?LI2_PGD_GUARD_RIP_REACH:LI2_PGD_RIP_REACH));
        saved_choice=witness;
        assert(li2_lp_relocation_reason(&full,&miss,e,&scratch,&check_choice)==miss.reason &&
            !memcmp(&saved_choice,&check_choice,sizeof saved_choice));
        relocation_negative(&miss,e,12);++relocation_cases;
    }
    for(unsigned direction=0;direction<2;direction++) {
        uintptr_t page=direction?UINT64_C(0x700000000000):0x400000;
        uintptr_t generated=direction?0x10000000:UINT64_C(0x700000000000);
        separated(page,generated);const unsigned char bytes[]={0x48,0x89,0xd8,0xe9,0xf8,0x00,0x00,0x00};
        put(512,bytes,sizeof bytes);
        assert(li2_le_choose(pages,source,page+512,&witness)==LI2_LE_NO_ENVELOPE &&
            !witness.ready && !witness.eligible && !li2_le_validate(pages,source,page+512,&witness,&check_choice));
        struct li2_pg_miss miss,empty={.version=11,.status=LI2_PG_RELOCATION};
        int e=li2_pf_plan_pages(pages,source,page+512,&layout,&table,&full,&miss);
        assert(e==LI2_PG_RELOCATION && !memcmp(&miss,&empty,sizeof miss) && !full.ready &&
            full.guard_result==LI2_DD_RELOCATION && li2_lp_fallback_relocation_reason(&full,&miss,e,&scratch)==LI2_PGD_BRANCH_REACH);
        relocation_negative(&miss,e,11);++relocation_cases;
        /* Same exact source and old PF11 remain ordinary version1 when near. */
        separated(page,page+0x100000);put(512,bytes,sizeof bytes);
        assert(!li2_pf_plan_pages(pages,source,page+512,&layout,&table,&full,&miss) && full.ready==1 &&
            !li2_pf_plan_validate(&full,&scratch));
        for(unsigned i=0;i<full.heads;i++)if(full.head[i].kind==LI2_PG_DIRECT)
            assert(full.guard[i].direct.record.version==1);
    }
    struct li2_pg_layout invalid=layout;invalid.generated[0]++;
    assert(li2_lp_placement(pages[0]+512,&invalid)==-1 && li2_lp_placement(pages[0]+4090,&layout)==-1);
}
int main(void) {
    assert(!old_loop_main());struct li2_decoder_stats before,after;assert(!li2_decoder_stats(&before));
    standalone();whole_plans();relocation();
    assert(adapters==70 && near_adapters==12 && far_adapters==58 && far_models==13440 &&
        literal_refusals==464 && direct_corruptions==870 && far_plans==4 && plan_corruptions==128 &&
        relocation_cases==6 && relocation_controls==102);
    assert(!li2_decoder_stats(&after) && after.phase==2 && !after.first_fatal_reason &&
        after.allocation_calls==before.allocation_calls && after.deallocation_calls==before.deallocation_calls);
    printf("{\"profile\":\"loop-far-direct-component-v1\",\"adapters\":%u,\"near\":%u,\"far\":%u,\"models\":%u,\"steps\":%llu,\"literal_refusals\":%u,\"direct_corruptions\":%u,\"plans\":%u,\"plan_corruptions\":%u,\"relocations\":%u,\"relocation_controls\":%u,\"emitted_execution\":0,\"owner_credit\":0}\n",
        adapters,near_adapters,far_adapters,far_models,(unsigned long long)far_steps,literal_refusals,
        direct_corruptions,far_plans,plan_corruptions,relocation_cases,relocation_controls);
    return 0;
}
