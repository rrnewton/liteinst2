/* Actual decoder and typed emitter; independent byte model, no generated
   execution. Supplied directory/window values do not prove live owner custody.
   A loaded miss is observed only, never claimed as a resumed RET. */
#include "model.h"
#include "persistent_group_plan.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
static _Alignas(64) unsigned char arena[16U<<20];
static struct li2_rd_plan plan,good;
static struct li2_jd_domain_directory directory;
static struct li2_rd_window window;
static const uintptr_t original_pc=0x400200,generated=0x10000000,spill_at=0x10012000;
static const struct li2_rd_binding binding={.rows=0x30000000,.image={0x10000000,0x10008000},
    .heads=1,.head=0,.directory=0x70000000,.window=0x70010000,.loaded_miss=0x70010040};
static unsigned descriptors,decoded,models,forms,arguments,bindings,corruptions,interiors,geometry,recovery_controls;
static uint64_t steps,recoveries;
_Static_assert(sizeof(struct li2_rd_plan)<=sizeof(union li2_pg_guard),"unchanged actual full group guard");
static uint64_t flags_for(unsigned n,unsigned df) {
    static const unsigned bits[6]={0,2,4,6,7,11};uint64_t out=0x202|((uint64_t)df<<10);
    for(unsigned i=0;i<6;i++)out|=(uint64_t)((n>>i)&1)<<bits[i];return out;
}
static void registers(uint64_t r[16]) {
    for(unsigned i=0;i<16;i++)r[i]=UINT64_C(0x1234567800000000)+0x101*i;
    r[4]=0x60000100;
}
static void directory_value(unsigned count) {
    memset(&directory,0,sizeof directory);directory.version=1;directory.serial=73;directory.count=count;
    for(unsigned i=0;i<count && i<LI2_JD_DOMAIN_HEADS;i++)directory.row[i]=(struct li2_jd_domain_row){
        .pc=0x500200+0x1000*i,.generated=0x20000000+512*i,.generation=91+i/128,.slot=i/128,.head=i%128};
}
static void window_value(uint64_t rsp) {
    window=(struct li2_rd_window){.version=1,.owner=0x72000000,.serial=73,.first=rsp-256,.end=rsp+256};
}
static void model(const struct li2_rd_plan *p,const uint64_t r[16],uint64_t flags,uint64_t word,unsigned readable) {
    struct rd_model_result out;assert(!rd_model_run(p,&directory,&window,r,flags,word,readable,&out));
    assert(!out.stack_writes && out.original_rsp==r[4]);
    if(r[4]<window.first || r[4]>window.end) {
        assert(out.before_miss==1 && !out.loaded_miss && !out.hit && !out.load_fault &&
            !out.load_attempts && !out.guest_reads && !out.target_writes && !out.cell_writes &&
            !out.row_reads && out.target==p->original.decoded.pc && out.final_rsp==r[4]);
    } else if(!readable) {
        assert(out.load_fault==1 && !out.before_miss && !out.loaded_miss && !out.hit &&
            out.load_attempts==1 && !out.guest_reads && !out.target_writes && !out.cell_writes &&
            !out.row_reads && out.final_rsp==r[4]);
    } else {
        assert(out.load_attempts==1 && out.guest_reads==1 && out.target_writes==1 &&
            out.loaded_target==word && !out.before_miss && !out.load_fault);
        unsigned row=LI2_JD_DOMAIN_HEADS;
        if(directory.count && directory.count<=LI2_JD_DOMAIN_HEADS)
            for(unsigned i=0;i<directory.count;i++)if(directory.row[i].pc==word) {row=i;break;}
        if(row<LI2_JD_DOMAIN_HEADS) {
            assert(out.hit==1 && !out.loaded_miss && out.cell_writes==1 && out.row_reads==row+1 &&
                out.target==directory.row[row].generated && out.final_rsp==r[4]+8);
        } else {
            assert(!out.hit && out.loaded_miss==1 && !out.cell_writes &&
                out.target==p->binding.loaded_miss && out.final_rsp==r[4]);
            if(!directory.count || directory.count>LI2_JD_DOMAIN_HEADS)assert(!out.row_reads);
            else assert(out.row_reads==directory.count);
        }
    }
    assert(out.steps==out.recoveries && out.steps<=2048);
    steps+=out.steps;recoveries+=out.recoveries;++models;
}
static void exact_descriptor(void) {
    unsigned char bytes[15];memset(bytes,0xcc,15);bytes[0]=0xc3;
    for(unsigned available=1;available<=15;available++) {
        assert(!li2_rd_emit(original_pc,bytes,available,generated,spill_at,&binding,&plan));
        struct li2_rd_descriptor expected={.decoded={.pc=original_pc,.next_pc=original_pc+1,
            .abi_version=1,.decode_status=LI2_VALID,.code=396,.kind=LI2_NONE,.destination=16,
            .step_disposition=LI2_STEP_UNSUPPORTED,.available=available,.length=1},
            .tf={.pc=original_pc,.next_pc=original_pc+1,.abi_version=1,.policy=1,.code=396,
                .length=1,.flow=LI2_TF_NEAR_FLOW,.family=LI2_TF_RETURN},
            .version=1,.ready=1,.available=available};
        memcpy(expected.decoded.bytes,bytes,available);assert(!memcmp(&plan.original,&expected,sizeof expected));++descriptors;
        assert(!li2_rd_validate(&plan) && plan.record.image_bytes==284 && plan.record.boundaries==53 &&
            plan.record.load_offset==68 && plan.record.save_offset==72 &&
            plan.record.loaded_miss_offset==190 && plan.record.miss_offset==226 &&
            plan.record.commit_offset==273 && plan.record.transfer_offset==278);
        for(unsigned i=0;i<plan.record.boundaries;i++) {
            const struct li2_mg_boundary *m=&plan.record.boundary[i];struct li2_decoded d;
            assert(!li2_decoder_decode(generated+m->offset,plan.image+m->offset,m->length,&d) &&
                d.decode_status==LI2_VALID && d.length==m->length && d.next_pc==generated+m->offset+m->length);++decoded;
        }
    }
    good=plan;directory_value(4);
    for(unsigned df=0;df<2;df++)for(unsigned f=0;f<64;f++)for(unsigned kind=0;kind<5;kind++) {
        uint64_t r[16];registers(r);window_value(r[4]);
        uint64_t word=kind==0?directory.row[0].pc:kind==1?directory.row[3].pc:
            kind==2?directory.row[1].pc+1:kind==3?UINT64_C(0x0100000000000000):directory.row[2].pc;
        model(&good,r,flags_for(f,df),word,kind!=4);
    }
    for(unsigned i=0;i<16;i++) {
        uint64_t r[16];registers(r);r[i]=i==4?0x60000207:UINT64_MAX-0x123*i;
        window_value(r[4]);model(&good,r,flags_for(i,1),directory.row[1].pc,1);
    }
}
static void window_and_directory(void) {
    uint64_t r[16];registers(r);directory_value(4);window_value(r[4]);
    uint64_t positions[6]={window.first,window.end,window.first-1,window.end+1,0,UINT64_C(0x800000000000)};
    for(unsigned i=0;i<6;i++) {r[4]=positions[i];model(&good,r,flags_for(i,1),directory.row[0].pc,1);}
    registers(r);window_value(r[4]);
    const unsigned counts[4]={0,1,256,257};
    for(unsigned i=0;i<4;i++) {
        directory_value(counts[i]);uint64_t target=counts[i]==256?directory.row[255].pc:0x500200;
        model(&good,r,flags_for(i,0),target,1);
    }
    directory_value(4);
    uint64_t targets[4]={directory.row[0].pc+1,0,UINT64_C(0x800000000000),UINT64_MAX};
    for(unsigned i=0;i<4;i++)model(&good,r,flags_for(i,1),targets[i],1);
}
static void grammar(void) {
    struct li2_rd_descriptor d;unsigned char bytes[15];
    for(unsigned first=0;first<256;first++) {
        memset(bytes,0xcc,15);bytes[0]=(unsigned char)first;
        int result=li2_rd_describe(original_pc,bytes,15,&d);
        assert(result==(first==0xc3?0:LI2_RD_FORM) && d.ready==(first==0xc3) && d.refusal==(unsigned)result);++forms;
    }
    for(unsigned leading=0;leading<256;leading++) {
        memset(bytes,0xcc,15);bytes[0]=(unsigned char)leading;bytes[1]=0xc3;
        int result=li2_rd_describe(original_pc,bytes,15,&d);
        /* Leading C3 is itself the one-byte RET, never an accepted prefix. */
        assert(result==(leading==0xc3?0:LI2_RD_FORM) && d.ready==(leading==0xc3) && d.refusal==(unsigned)result);++forms;
    }
    memset(bytes,0xcc,15);bytes[0]=0xc3;
    assert(li2_rd_describe(original_pc,bytes,1,0)==LI2_RD_ARGUMENT);++arguments;
    assert(li2_rd_describe(original_pc,0,1,&d)==LI2_RD_ARGUMENT);++arguments;
    assert(li2_rd_describe(original_pc,bytes,0,&d)==LI2_RD_ARGUMENT);++arguments;
    assert(li2_rd_describe(original_pc,bytes,16,&d)==LI2_RD_ARGUMENT);++arguments;
    assert(li2_rd_describe(UINT64_C(0x800000000000),bytes,1,&d)==LI2_RD_ARGUMENT);++arguments;
    assert(li2_rd_describe(UINT64_C(0x7fffffffffff),bytes,2,&d)==LI2_RD_ARGUMENT);++arguments;
    const uintptr_t pc[4]={0x400fff,0x400ffe,UINT64_C(0x500000400fff),UINT64_C(0x7fffffffffff)};
    for(unsigned i=0;i<4;i++) {
        assert(!li2_rd_describe(pc[i],bytes,1,&d) && d.decoded.next_pc==pc[i]+1 && d.available==1);++geometry;
        if(i<3) {
            uintptr_t shift=i==2?UINT64_C(0x500000000000):0;
            struct li2_rd_binding placed=binding;placed.rows+=shift;placed.image[0]+=shift;placed.image[1]+=shift;
            placed.directory+=shift;placed.window+=shift;placed.loaded_miss+=shift;
            assert(!li2_rd_emit(pc[i],bytes,1,generated+shift,spill_at+shift,&placed,&plan) && !li2_rd_validate(&plan));
            if(i==2) {
                uint64_t r[16];registers(r);directory_value(4);window_value(r[4]);
                for(unsigned j=0;j<4;j++){directory.row[j].pc+=shift;directory.row[j].generated+=shift;}
                model(&plan,r,flags_for(63,1),directory.row[2].pc,1);
            }
        }
    }
}
static void bad_bindings(void) {
    for(unsigned i=0;i<16;i++) {
        struct li2_rd_binding b=binding;uintptr_t g=generated,s=spill_at;
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
        if(i==12)b.loaded_miss++;
        if(i==13)b.loaded_miss=b.window+56;
        if(i==14)b.loaded_miss=b.window+4096;
        if(i==15)b.loaded_miss=UINT64_MAX;
        assert(li2_rd_emit(original_pc,good.original.decoded.bytes,15,g,s,&b,&plan)==LI2_RD_ARGUMENT &&
            !plan.record.ready && plan.record.result==LI2_RD_ARGUMENT);++bindings;
    }
}
static void bad_material(void) {
    for(unsigned i=0;i<20;i++) {
        struct li2_rd_plan bad=good;
        if(i==0)bad.record.version++;
        if(i==1)bad.binding.window+=4096;
        if(i==2)bad.record.boundaries--;
        if(i==3)bad.record.boundary[0].spill_valid=1;
        if(i==4)bad.record.boundary[5].dirty^=1;
        if(i==5)bad.record.boundary[52].phase=LI2_RD_BEFORE;
        if(i==6)bad.record.boundary[51].phase=LI2_RD_COMMITTED;
        if(i==7)bad.record.load_offset++;
        if(i==8)bad.record.transfer_offset++;
        if(i==9)bad.record.save_offset++;
        if(i==10)bad.record.commit_offset++;
        if(i==11)bad.image[284]=1;
        if(i==12)bad.original.reserved[0]=1;
        if(i==13)bad.record.reserved=1;
        if(i==14)bad.image[68]^=1;
        if(i==15)bad.original.tf.family=LI2_TF_BRANCH;
        if(i==16)bad.binding.loaded_miss+=8;
        if(i==17)bad.image[273]^=1;
        if(i==18)bad.record.loaded_miss_offset++;
        if(i==19)bad.record.boundary[14].phase=LI2_RD_SAVED;
        assert(li2_rd_validate(&bad)==LI2_RD_CORRUPT);++corruptions;
    }
    uint64_t r[16],words[6]={UINT64_MAX,0xdeadbeef,0x12345678,0,0,0};registers(r);
    for(unsigned offset=0;offset<512;offset++) {
        unsigned found=0;for(unsigned j=0;j<good.record.boundaries;j++)found|=good.record.boundary[j].offset==offset;
        if(!found) {struct li2_rd_recovered out;
            assert(li2_rd_recover(&good,generated+offset,r,0x202,words,&out)==LI2_RD_CORRUPT && !out.complete);++interiors;}
    }
}
static void recovery_negatives(void) {
    for(unsigned i=0;i<12;i++) {
        struct li2_rd_plan bad=good;uint64_t r[16],words[6]={0,0,0,0,UINT64_MAX,0x500200};registers(r);r[4]+=8;
        unsigned last=good.record.boundaries-1;
        if(i==0)r[4]=7;
        if(i==1)r[4]=UINT64_C(0x800000000000);
        if(i==2)words[5]=UINT64_C(0x800000000000);
        if(i==3)bad.record.boundary[last].dirty=1;
        if(i==4)bad.record.boundary[last].flags=LI2_MG_AH_AL;
        if(i==5)bad.record.boundary[last-1].offset=bad.record.boundary[last].offset;
        if(i==6)bad.record.scratch_regs[1]=4;
        if(i==7)bad.record.transfer_offset++;
        if(i==8)bad.record.boundary[last].spill_valid=7;
        if(i==9)bad.record.boundary[last].phase=LI2_RD_LOADED;
        if(i==10)bad.record.boundary[last].phase=LI2_RD_LOAD;
        if(i==11)bad.record.boundary[last].phase=LI2_RD_LOADED_MISS;
        struct li2_rd_recovered out;
        assert(li2_rd_recover(&bad,generated+good.record.transfer_offset,r,0x202,words,&out)==LI2_RD_CORRUPT && !out.complete);
        ++recovery_controls;
    }
    uint64_t r[16],words[6]={0,0,0,0,UINT64_MAX,UINT64_MAX};registers(r);
    struct li2_rd_recovered out;
    assert(li2_rd_recover_loaded_miss(&good,binding.loaded_miss+8,r,0x202,words,&out)==LI2_RD_CORRUPT && !out.complete);++recovery_controls;
    assert(li2_rd_recover(&good,binding.loaded_miss,r,0x202,words,&out)==LI2_RD_CORRUPT && !out.complete);++recovery_controls;
    assert(li2_rd_recover_loaded_miss(&good,generated+good.record.loaded_miss_offset,r,0x202,words,&out)==LI2_RD_CORRUPT && !out.complete);++recovery_controls;
    r[4]=UINT64_C(0x7ffffffffff8);
    assert(li2_rd_recover_loaded_miss(&good,binding.loaded_miss,r,0x202,words,&out)==LI2_RD_CORRUPT && !out.complete);++recovery_controls;
}
int main(void) {
    struct li2_decoder_stats before,after;assert(!li2_decoder_initialize(arena,sizeof arena,&before));
    exact_descriptor();window_and_directory();grammar();bad_bindings();bad_material();recovery_negatives();
    assert(!li2_decoder_stats(&after) && after.phase==2 && !after.first_fatal_reason &&
        after.allocation_calls==before.allocation_calls && after.deallocation_calls==before.deallocation_calls);
    assert(descriptors==15 && decoded==795 && models==671 && forms==512 && arguments==6 &&
        bindings==16 && corruptions==20 && interiors==459 && geometry==4 && recovery_controls==16 && steps==recoveries);
    printf("ret-dispatch descriptors=%u decoded=%u models=%u forms=%u arguments=%u bindings=%u corruptions=%u interiors=%u geometry=%u recovery_controls=%u\n",
        descriptors,decoded,models,forms,arguments,bindings,corruptions,interiors,geometry,recovery_controls);
    return 0;
}
