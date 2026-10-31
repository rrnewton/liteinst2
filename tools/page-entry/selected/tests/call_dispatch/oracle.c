/* Actual decoder and typed emitter; independent interpretation, no generated
   execution. Supplied directory/window values do not prove live owner custody.
   In particular the standalone CALL-RSP hit is not an owner-admitted case. */
#include "model.h"
#include "persistent_group_plan.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
static _Alignas(64) unsigned char arena[16U<<20];
static struct li2_cd_plan plan,good;
static struct li2_jd_domain_directory directory;
static struct li2_cd_window window;
static const uintptr_t original_pc=0x400200,generated=0x10000000,spill_at=0x10012000;
static const struct li2_cd_binding binding={.rows=0x30000000,.image={0x10000000,0x10008000},
    .heads=1,.head=0,.directory=0x70000000,.window=0x70010000};
static unsigned descriptors,decoded,models,forms,arguments,bindings,corruptions,interiors,geometry,recovery_controls;
static uint64_t steps,recoveries;
_Static_assert(sizeof(struct li2_cd_plan)<=sizeof(union li2_pg_guard),"actual unchanged group union fits adapter");
static uint64_t flags_for(unsigned n,unsigned df) {
    static const unsigned bits[6]={0,2,4,6,7,11};uint64_t out=0x202|((uint64_t)df<<10);
    for(unsigned i=0;i<6;i++)out|=(uint64_t)((n>>i)&1)<<bits[i];return out;
}
static void registers(uint64_t r[16]) {
    for(unsigned i=0;i<16;i++)r[i]=UINT64_C(0x1234567800000000)+0x101*i;
    r[4]=0x60000100;
}
static unsigned bytes_for(unsigned reg,unsigned char bytes[15]) {
    memset(bytes,0xcc,15);unsigned prefix=reg>=8;
    if(prefix)bytes[0]=0x41;
    bytes[prefix]=0xff;bytes[prefix+1]=(unsigned char)(0xd0+(reg&7));return prefix+2;
}
static void directory_value(unsigned count) {
    memset(&directory,0,sizeof directory);directory.version=1;directory.serial=73;directory.count=count;
    for(unsigned i=0;i<count && i<LI2_JD_DOMAIN_HEADS;i++)directory.row[i]=(struct li2_jd_domain_row){
        .pc=0x500200+0x1000*i,.generated=0x20000000+512*i,.generation=91+i/128,.slot=i/128,.head=i%128};
}
static void window_value(uint64_t rsp) {
    window=(struct li2_cd_window){.version=1,.owner=0x72000000,.serial=73,.first=rsp-256,.end=rsp+256};
}
static void model(const struct li2_cd_plan *p,const uint64_t r[16],uint64_t flags) {
    struct cd_model_result out;assert(!cd_model_run(p,&directory,&window,r,flags,&out));
    unsigned row=LI2_JD_DOMAIN_HEADS;
    if(directory.count && directory.count<=LI2_JD_DOMAIN_HEADS && r[4]>=window.first+8 && r[4]<=window.end)
        for(unsigned i=0;i<directory.count;i++)if(directory.row[i].pc==r[p->original.target]) {row=i;break;}
    if(row<LI2_JD_DOMAIN_HEADS) {
        assert(out.hit==1 && !out.miss && out.cell_writes==1 && out.stack_writes==1 &&
            out.row_reads==row+1 && out.target==directory.row[row].generated &&
            out.stack_address==r[4]-8 && out.return_word==p->original.decoded.next_pc);
    } else {
        assert(!out.hit && out.miss==1 && !out.cell_writes && !out.stack_writes &&
            !out.stack_address && !out.return_word && out.target==p->original.decoded.pc);
        if(r[4]<window.first+8 || r[4]>window.end || !directory.count || directory.count>LI2_JD_DOMAIN_HEADS)
            assert(!out.row_reads);
        else assert(out.row_reads==directory.count);
    }
    assert(out.steps==out.recoveries && out.steps<=2048);
    steps+=out.steps;recoveries+=out.recoveries;++models;
}
static void all_registers(void) {
    for(unsigned reg=0;reg<16;reg++) {
        unsigned char bytes[15];unsigned length=bytes_for(reg,bytes);
        assert(!li2_cd_emit(original_pc,bytes,15,generated,spill_at,&binding,&plan));
        struct li2_cd_descriptor expected={.decoded={.pc=original_pc,.next_pc=original_pc+length,
            .abi_version=1,.decode_status=LI2_VALID,.code=759,.kind=LI2_NONE,.destination=16,
            .step_disposition=LI2_STEP_UNSUPPORTED,.available=15,.length=length},
            .tf={.pc=original_pc,.next_pc=original_pc+length,.abi_version=1,.policy=1,.code=759,
                .length=length,.flow=LI2_TF_NEAR_FLOW,.family=LI2_TF_CALL},
            .version=1,.ready=1,.available=15,.target=reg};
        memcpy(expected.decoded.bytes,bytes,15);assert(!memcmp(&plan.original,&expected,sizeof expected));++descriptors;
        assert(!li2_cd_validate(&plan) && plan.record.image_bytes==248 && plan.record.boundaries==46 &&
            plan.record.miss_offset==189 && plan.record.push_offset==236 && plan.record.transfer_offset==242 &&
            plan.record.literal_offset==504);
        for(unsigned i=0;i<plan.record.boundaries;i++) {
            const struct li2_mg_boundary *m=&plan.record.boundary[i];struct li2_decoded d;
            assert(!li2_decoder_decode(generated+m->offset,plan.image+m->offset,m->length,&d) &&
                d.decode_status==LI2_VALID && d.length==m->length && d.next_pc==generated+m->offset+m->length);++decoded;
        }
        directory_value(4);
        for(unsigned df=0;df<2;df++)for(unsigned f=0;f<64;f++)for(unsigned hit=0;hit<2;hit++) {
            uint64_t r[16];registers(r);r[reg]=hit?directory.row[2].pc:0x590203;
            window_value(r[4]);model(&plan,r,flags_for(f,df));
        }
        if(reg==0)good=plan;
    }
}
static void window_and_directory(void) {
    uint64_t r[16];registers(r);directory_value(4);r[0]=directory.row[0].pc;window_value(r[4]);
    uint64_t positions[6]={window.first+8,window.end,window.first+7,window.end+1,0,UINT64_C(0x800000000000)};
    for(unsigned i=0;i<6;i++) {r[4]=positions[i];model(&good,r,flags_for(i,1));}
    registers(r);window_value(r[4]);
    const unsigned counts[4]={0,1,256,257};
    for(unsigned i=0;i<4;i++) {
        directory_value(counts[i]);r[0]=counts[i]==256?directory.row[255].pc:0x500200;model(&good,r,flags_for(i,0));
    }
    directory_value(4);
    uint64_t targets[4]={directory.row[0].pc+1,0,UINT64_C(0x800000000000),UINT64_MAX};
    for(unsigned i=0;i<4;i++) {r[0]=targets[i];model(&good,r,flags_for(i,1));}
}
static void grammar(void) {
    struct li2_cd_descriptor d;unsigned char bytes[15];
    for(unsigned prefix=0;prefix<256;prefix++) {
        memset(bytes,0xcc,15);bytes[0]=(unsigned char)prefix;bytes[1]=0xff;bytes[2]=0xd0;
        int result=li2_cd_describe(original_pc,bytes,15,&d);
        assert(result==(prefix==0x41?0:LI2_CD_FORM));
        assert(d.ready==(prefix==0x41) && d.refusal==(unsigned)result);++forms;
    }
    for(unsigned modrm=0;modrm<256;modrm++) {
        memset(bytes,0xcc,15);bytes[0]=0xff;bytes[1]=(unsigned char)modrm;
        int allowed=modrm>=0xd0 && modrm<=0xd7;
        int result=li2_cd_describe(original_pc,bytes,15,&d);
        assert(result==(allowed?0:LI2_CD_FORM) && d.ready==(unsigned)allowed && d.refusal==(unsigned)result);++forms;
    }
    bytes_for(0,bytes);
    assert(li2_cd_describe(original_pc,bytes,2,0)==LI2_CD_ARGUMENT);++arguments;
    assert(li2_cd_describe(original_pc,0,2,&d)==LI2_CD_ARGUMENT);++arguments;
    assert(li2_cd_describe(original_pc,bytes,0,&d)==LI2_CD_ARGUMENT);++arguments;
    assert(li2_cd_describe(original_pc,bytes,16,&d)==LI2_CD_ARGUMENT);++arguments;
    assert(li2_cd_describe(UINT64_C(0x800000000000),bytes,2,&d)==LI2_CD_ARGUMENT);++arguments;
    assert(li2_cd_describe(UINT64_C(0x7fffffffffff),bytes,2,&d)==LI2_CD_ARGUMENT);++arguments;
    assert(li2_cd_describe(original_pc,bytes,1,&d)==LI2_CD_FORM);++arguments;
    bytes_for(8,bytes);assert(li2_cd_describe(original_pc,bytes,2,&d)==LI2_CD_FORM);++arguments;
    const uintptr_t pc[4]={0x400ffe,0x400ffd,UINT64_C(0x500000400ffe),UINT64_C(0x7ffffffffffe)};
    for(unsigned i=0;i<4;i++) {
        unsigned n=bytes_for(i==1?8:0,bytes);
        assert(!li2_cd_describe(pc[i],bytes,n,&d) && d.decoded.next_pc==pc[i]+n && d.available==n);++geometry;
        if(i<3) {
            uintptr_t shift=i==2?UINT64_C(0x500000000000):0;
            struct li2_cd_binding placed=binding;
            placed.rows+=shift;placed.image[0]+=shift;placed.image[1]+=shift;
            placed.directory+=shift;placed.window+=shift;
            assert(!li2_cd_emit(pc[i],bytes,n,generated+shift,spill_at+shift,&placed,&plan) && !li2_cd_validate(&plan));
            uint64_t literal=0;for(unsigned j=0;j<8;j++)literal|=(uint64_t)plan.image[504+j]<<(8*j);
            assert(literal==pc[i]+n && literal==shift+0x401000);
            if(i==2) {
                uint64_t r[16];registers(r);directory_value(4);r[0]=directory.row[0].pc;
                window_value(r[4]);model(&plan,r,flags_for(63,1));
            }
        }
    }
}
static void bad_bindings(void) {
    for(unsigned i=0;i<12;i++) {
        struct li2_cd_binding b=binding;uintptr_t g=generated,s=spill_at;
        if(i==0)b.heads=0;
        if(i==1)b.heads=129;
        if(i==2)b.head=1;
        if(i==3)b.rows++;
        if(i==4)b.image[1]=b.image[0];
        if(i==5)s++;
        if(i==6)b.directory=b.image[0];
        if(i==7)b.window++;
        if(i==8)b.window=b.directory;
        if(i==9)b.window=b.image[0];
        if(i==10)b.window=spill_at;
        if(i==11)g++;
        assert(li2_cd_emit(original_pc,good.original.decoded.bytes,15,g,s,&b,&plan)==LI2_CD_ARGUMENT &&
            !plan.record.ready && plan.record.result==LI2_CD_ARGUMENT);++bindings;
    }
}
static void bad_material(void) {
    for(unsigned i=0;i<16;i++) {
        struct li2_cd_plan bad=good;
        if(i==0)bad.record.version++;
        if(i==1)bad.binding.window+=4096;
        if(i==2)bad.record.boundaries--;
        if(i==3)bad.record.boundary[0].spill_valid=1;
        if(i==4)bad.record.boundary[5].dirty^=1;
        if(i==5)bad.record.boundary[45].phase=LI2_CD_BEFORE;
        if(i==6)bad.record.boundary[44].phase=LI2_CD_COMMITTED;
        if(i==7)bad.record.push_offset++;
        if(i==8)bad.record.transfer_offset++;
        if(i==9)bad.record.literal_offset--;
        if(i==10)bad.image[504]^=1;
        if(i==11)bad.image[248]=1;
        if(i==12)bad.original.target^=1;
        if(i==13)bad.record.reserved[2]=1;
        if(i==14)bad.image[236]^=1;
        if(i==15)bad.original.tf.family=LI2_TF_BRANCH;
        assert(li2_cd_validate(&bad)==LI2_CD_CORRUPT);++corruptions;
    }
    uint64_t r[16],spill[4]={UINT64_MAX,0xdeadbeef,0x12345678,0};registers(r);
    for(unsigned offset=0;offset<512;offset++) {
        unsigned found=0;for(unsigned j=0;j<good.record.boundaries;j++)found|=good.record.boundary[j].offset==offset;
        if(!found) {struct li2_cd_recovered out;
            assert(li2_cd_recover(&good,generated+offset,r,0x202,spill,&out)==LI2_CD_CORRUPT && !out.complete);++interiors;}
    }
}
static void committed_negatives(void) {
    for(unsigned i=0;i<8;i++) {
        struct li2_cd_plan bad=good;uint64_t r[16],spill[4]={0};registers(r);r[0]=0x500200;r[4]-=8;
        const unsigned last=good.record.boundaries-1;
        if(i==0)r[4]=UINT64_MAX;
        if(i==1)r[4]=UINT64_C(0x7ffffffffff8);
        if(i==2)r[0]=UINT64_C(0x800000000000);
        if(i==3)bad.record.boundary[last].dirty=1;
        if(i==4)bad.record.boundary[last].flags=LI2_MG_AH_AL;
        if(i==5)bad.record.boundary[last-1].offset=bad.record.boundary[last].offset;
        if(i==6)bad.record.scratch_regs[1]=4;
        if(i==7)bad.record.transfer_offset++;
        struct li2_cd_recovered out;
        assert(li2_cd_recover(&bad,generated+good.record.transfer_offset,r,0x202,spill,&out)==LI2_CD_CORRUPT && !out.complete);
        ++recovery_controls;
    }
}
int main(void) {
    struct li2_decoder_stats before,after;assert(!li2_decoder_initialize(arena,sizeof arena,&before));
    all_registers();window_and_directory();grammar();bad_bindings();bad_material();committed_negatives();
    assert(!li2_decoder_stats(&after) && after.phase==2 && !after.first_fatal_reason &&
        after.allocation_calls==before.allocation_calls && after.deallocation_calls==before.deallocation_calls);
    assert(descriptors==16 && decoded==736 && models==4111 && forms==512 && arguments==8 &&
        bindings==12 && corruptions==16 && interiors==466 && geometry==4 && recovery_controls==8 && steps==recoveries);
    printf("call-dispatch descriptors=%u decoded=%u models=%u forms=%u arguments=%u bindings=%u corruptions=%u interiors=%u geometry=%u recovery_controls=%u\n",
        descriptors,decoded,models,forms,arguments,bindings,corruptions,interiors,geometry,recovery_controls);
    return 0;
}
