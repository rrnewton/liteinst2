/* Fixture-only policy. Include after provider_policy.h, provider_builtin_policy.h
   before the generated script header. This never modifies the actual frame.
   prepared/accepted count authenticated script stages, not production callback
   entered/returned. The real provider progress must be recorded separately. */
struct b2_script_row {
    uint64_t kind,width,destination,length,pc,next,flags,after_flags,carry,values[4];
    unsigned char bytes[16];uint64_t before[16],after[16];
};
/* Define B2_SCRIPT_HEADER as the exact retained per-case emitted header path. */
#include B2_SCRIPT_HEADER
static volatile sig_atomic_t b2_script_prepared,b2_script_accepted,b2_script_committed;
static unsigned b2_script_clock_count;
static const int b2_greg[16]={REG_RAX,REG_RCX,REG_RDX,REG_RBX,REG_RSP,REG_RBP,REG_RSI,REG_RDI,
    REG_R8,REG_R9,REG_R10,REG_R11,REG_R12,REG_R13,REG_R14,REG_R15};
static int b2_script_before(const ucontext_t *uc,const unsigned char *actual_source,size_t n,
                           uint64_t original_pc,uint64_t logical_flags) {
    unsigned i=(unsigned)b2_script_committed;
    if(!uc || !actual_source || i>=B2_SCRIPT_ROWS || b2_script_prepared!=(sig_atomic_t)i ||
       b2_script_accepted!=(sig_atomic_t)i)return 1;
    const struct b2_script_row *r=&b2_script[i];
    if(original_pc!=r->pc || n!=r->length || logical_flags!=r->flags ||
       (uint64_t)uc->uc_mcontext.gregs[REG_RIP]!=r->pc ||
       (uint64_t)uc->uc_mcontext.gregs[REG_EFL]!=(r->flags|UINT64_C(0x10000)))return 2;
    for(size_t j=0;j<n;j++)if(actual_source[j]!=r->bytes[j])return 3;
    for(unsigned j=0;j<16;j++)if((uint64_t)uc->uc_mcontext.gregs[b2_greg[j]]!=r->before[j])return 4;
    /* Publish only after authenticating the actual scalar input. This marks
       policy entry preparation, not callback return or architectural commit. */
    b2_script_prepared=(sig_atomic_t)(i+1);return 0;
}
static const struct b2_script_row *b2_pending(unsigned kind) {
    unsigned i=(unsigned)b2_script_committed;
    if(i>=B2_SCRIPT_ROWS || b2_script_prepared!=(sig_atomic_t)(i+1) ||
       b2_script_accepted!=(sig_atomic_t)i || b2_script[i].kind!=kind)return 0;
    return &b2_script[i];
}
static int b2_cpuid_callback(const struct li2_selected_cpuid_input *in,struct li2_selected_cpuid_result *out) {
    const struct b2_script_row *r=b2_pending(LI2_CPUID);
    if(!in || !out || !r || in->leaf!=(uint32_t)r->before[0] || in->subleaf!=(uint32_t)r->before[1])return LI2_SELECTED_SCRIPT;
    *out=(struct li2_selected_cpuid_result){(uint32_t)r->values[0],(uint32_t)r->values[1],(uint32_t)r->values[2],(uint32_t)r->values[3]};
    ++b2_script_accepted;return 0;
}
static int b2_random_callback(const struct li2_selected_callback_input *in,struct li2_selected_script *out) {
    if(!in || !out)return LI2_SELECTED_ARGUMENT;
    const struct b2_script_row *r=b2_pending(in->kind);
    if(!r || in->abi_version!=1 || in->kind<LI2_RDRAND || in->kind>LI2_RDPID ||
       in->width_bits!=r->width || in->destination!=r->destination || in->pc!=r->pc ||
       in->next_pc!=r->next || in->logical_flags!=r->flags || in->input_destination!=r->before[r->destination])return LI2_SELECTED_SCRIPT;
    *out=(struct li2_selected_script){(uint32_t)r->kind,(uint32_t)r->width,(uint32_t)r->carry,0,r->values[0]};
    ++b2_script_accepted;return 0;
}
static int b2_clock_callback(const struct li2_selected_clock_input *in,struct li2_selected_clock_result *out) {
    if(!in || !out)return LI2_SELECTED_ARGUMENT;
    const struct b2_script_row *r=b2_pending(in->kind);
    if(!r || in->abi_version!=1 || (in->kind!=LI2_RDTSC && in->kind!=LI2_RDTSCP) ||
       in->pc!=r->pc || in->next_pc!=r->next || in->logical_flags!=r->flags ||
       in->ordinal!=(uint64_t)b2_script_clock_count+1)return LI2_SELECTED_SCRIPT;
    *out=(struct li2_selected_clock_result){r->values[0],(uint32_t)r->values[1],0};
    ++b2_script_clock_count;++b2_script_accepted;return 0;
}
static int b2_syscall_callback(const struct li2_selected_syscall_input *in,struct li2_selected_syscall_result *out) {
    const struct b2_script_row *r=b2_pending(LI2_SYSCALL);
    if(!in || !out || !r || in->abi_version!=1 || in->reserved || in->pc!=r->pc ||
       in->next_pc!=r->next || in->logical_flags!=r->flags || in->number!=39 ||
       in->number!=r->before[0] || in->input_rcx!=r->before[1] || in->input_r11!=r->before[11])return LI2_SELECTED_SCRIPT;
    const unsigned order[6]={7,6,2,10,8,9};
    for(unsigned j=0;j<6;j++)if(in->args[j]!=r->before[order[j]])return LI2_SELECTED_SCRIPT;
    *out=(struct li2_selected_syscall_result){LI2_SYSCALL_REPLACE,0,r->values[0]};
    ++b2_script_accepted;return 0;
}
static int b2_script_after(const ucontext_t *actual) {
    unsigned i=(unsigned)b2_script_committed;
    if(!actual || i>=B2_SCRIPT_ROWS || b2_script_prepared!=(sig_atomic_t)(i+1) ||
       b2_script_accepted!=(sig_atomic_t)(i+1))return 1;
    const struct b2_script_row *r=&b2_script[i];
    if((uint64_t)actual->uc_mcontext.gregs[REG_RIP]!=r->next ||
       (uint64_t)actual->uc_mcontext.gregs[REG_EFL]!=r->after_flags)return 2;
    for(unsigned j=0;j<16;j++)if((uint64_t)actual->uc_mcontext.gregs[b2_greg[j]]!=r->after[j])return 3;
    ++b2_script_committed;return 0;
}
