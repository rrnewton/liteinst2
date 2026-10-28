#include "provider_policy.h"
#define CALLBACK_MAGIC UINT64_C(0x314b42434332494c)
static struct li2_selected_callback_progress callback_progress;
static const struct li2_selected_script *callback_supplied;
static ucontext_t *callback_outer;
static uint64_t callback_calls,callback_cpuid[6][10];
static void callback_controls(void) {
    static const uint32_t leaves[6][2]={{0,0},{1,0},{1,7},{7,0},{7,1},{0x80000000U,0}};
    for(size_t i=0;i<6;i++) {
        uint32_t a=leaves[i][0],c=leaves[i][1],b,d;
        __asm__ volatile("cpuid":"+a"(a),"=b"(b),"+c"(c),"=d"(d)::"memory");
        struct li2_selected_cpuid_input in={leaves[i][0],leaves[i][1],{a,b,c,d}};
        struct li2_selected_cpuid_result out;
        require(!li2_policy_cpuid_mask_v1(&in,&out),70,1);
        uint32_t expected_b=b,expected_c=c;
        if(i==1 || i==2)expected_c=c&UINT32_C(0xbfffffff);
        if(i==3){expected_b=b&UINT32_C(0xfffbffff);expected_c=c&UINT32_C(0xffbfffff);}
        require(out.eax==a && out.ebx==expected_b && out.ecx==expected_c && out.edx==d,70,2);
        uint64_t *r=callback_cpuid[i];r[0]=in.leaf;r[1]=in.subleaf;
        r[2]=a;r[3]=b;r[4]=c;r[5]=d;r[6]=out.eax;r[7]=out.ebx;r[8]=out.ecx;r[9]=out.edx;
    }
}
static void callback_record(unsigned format) {
    const struct li2_selected_callback_input *i=&callback_progress.input;
    const struct li2_selected_script *s=&callback_progress.script;
    uint64_t words[40]={CALLBACK_MAGIC,format,callback_calls,
        (uint64_t)(int64_t)callback_progress.callback_status,
        (uint64_t)callback_progress.entered,(uint64_t)callback_progress.returned,
        (uint64_t)callback_progress.committed,callback_progress.first_error,
        callback_progress.abi_version,i->abi_version,i->kind,i->width_bits,i->destination,
        i->pc,i->next_pc,i->logical_flags,i->input_destination,
        s->kind,s->width_bits,s->carry,s->reserved,s->value,6};
    write_all(words,sizeof words);write_all(callback_cpuid,sizeof callback_cpuid);
}
static int callback_decide(const struct li2_selected_callback_input *in,struct li2_selected_script *out) {
    require(callback_calls==0 && in==&callback_progress.input && out==&callback_progress.script &&
        callback_progress.entered==1 && !callback_progress.returned && !callback_progress.committed &&
        completion.phase==LI2_SELECTED_VALIDATED && !completion.native_attempts,71,1);
    ++callback_calls;
    require(in->abi_version==1 && in->kind==kind && in->width_bits==width && in->destination==reg &&
        in->pc==fixture_target && in->next_pc==fixture_target+instruction_bytes &&
        in->logical_flags==fixture_pre[16] && in->input_destination==fixture_pre[reg],71,2);
    int result=li2_policy_mask_random_v1(in,out);require(!result,71,3);
    if(control==49)return 71; /* Returned callback failure, not native failure. */
    if(control==50) {
        /* A genuine fetch fault inside the callback on the already-NX first
           source page. No instruction at this address executes. */
        ((void (*)(void))(program+128))();fixture_die(71,4);
    }
    if(control==53 || control==54 || (control>=13 && control<=18)) {
        require(callback_supplied!=0,71,5);*out=*callback_supplied;
    }
    if(control==32)return LI2_SELECTED_SCRIPT;
    return 0;
}
static int callback_complete(ucontext_t *uc,const struct li2_selected_request *request,
                             const struct li2_selected_script *supplied,
                             struct li2_selected_completion *out) {
    callback_supplied=supplied;callback_outer=uc;
    return li2_selected_complete_callback(uc,request,control==51?0:callback_decide,&callback_progress,out);
}
static _Noreturn void callback_nested(int sig,siginfo_t *si,ucontext_t *uc) {
    require(control==50 && in_handler && sig==SIGSEGV && si && uc &&
        si->si_signo==SIGSEGV && si->si_code==SEGV_ACCERR && !si->si_errno &&
        uc->uc_mcontext.gregs[REG_TRAPNO]==14 && uc->uc_mcontext.gregs[REG_ERR]==21 &&
        (uintptr_t)uc->uc_mcontext.gregs[REG_RIP]==(uintptr_t)program+128 &&
        (uintptr_t)si->si_addr==(uintptr_t)program+128 &&
        callback_progress.entered==1 && !callback_progress.returned && !callback_progress.committed &&
        callback_calls==1 && completion.phase==LI2_SELECTED_VALIDATED && !completion.native_attempts &&
        !returned && fault_count==1 && callback_outer,72,1);
    size_t fp=fp_capture(callback_outer,kernel_after);fixture_copy(uc_after,callback_outer,sizeof *callback_outer);
    fixture_copy(stack_after,(void *)(uintptr_t)(fixture_input[4]-STACK_BYTES/2),STACK_BYTES);
    require(fp==header[20] && fixture_equal(uc_before,uc_after,UC_BYTES) &&
        fixture_equal(kernel_before,kernel_after,FP_BYTES) && fixture_equal(stack_before,stack_after,STACK_BYTES) &&
        fixture_equal(program,image_before,2*PAGE),72,2);
    uint64_t h[24]={CALLBACK_MAGIC,2,50,(unsigned)sig,(unsigned)si->si_code,
        (uint64_t)uc->uc_mcontext.gregs[REG_TRAPNO],(uint64_t)uc->uc_mcontext.gregs[REG_ERR],
        (uintptr_t)uc->uc_mcontext.gregs[REG_RIP],(uintptr_t)si->si_addr,(uintptr_t)program+128,
        sizeof(ucontext_t),offsetof(ucontext_t,uc_mcontext.gregs),offsetof(ucontext_t,uc_mcontext.fpregs),
        fp,fixture_target,fixture_target+instruction_bytes,completion.phase,completion.native_attempts,
        returned,fault_count,layout,prefix,kind,width};
    write_all(h,sizeof h);callback_record(2);write_all(fixture_pre,sizeof fixture_pre);
    write_all(uc_before,UC_BYTES);write_all(uc_after,UC_BYTES);
    write_all(kernel_before,FP_BYTES);write_all(kernel_after,FP_BYTES);
    write_all(image_before,2*PAGE);write_all(program,2*PAGE);
    write_all(stack_before,STACK_BYTES);write_all(stack_after,STACK_BYTES);
    RAW(SYS_exit_group,125,0,0,0,0,0);__builtin_trap();
}
