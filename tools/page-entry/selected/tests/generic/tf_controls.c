/* Source-only supplied-byte controls. Run only after genuine decoder arena
   initialization/sealing; no instruction below executes as target code.
   A refusal is exact policy/flow/family zero, not an alternate success code. */
#include "tf_owner.h"
struct tf_refusal_case { const char *name; size_t length; unsigned char bytes[15]; };
static const struct tf_refusal_case tf_refusals[]={
    {"pushfq",1,{0x9c}}, {"pushfw",2,{0x66,0x9c}},
    {"popfq",1,{0x9d}}, {"popfw",2,{0x66,0x9d}},
    {"iretq",2,{0x48,0xcf}}, {"iretd",1,{0xcf}},
    {"mov_ss_ax",2,{0x8e,0xd0}}, {"lss_rax_memory",4,{0x48,0x0f,0xb2,0x00}},
    {"sti",1,{0xfb}}, {"cli",1,{0xfa}},
    {"rep_movsb",2,{0xf3,0xa4}}, {"repe_cmpsb",2,{0xf3,0xa6}},
    {"repne_scasb",2,{0xf2,0xae}}, {"rep_lodsb",2,{0xf3,0xac}},
    {"rep_stosb",2,{0xf3,0xaa}}, {"lock_add_memory",3,{0xf0,0x01,0x00}},
    {"ignored_cs_nop",2,{0x2e,0x90}}, {"ignored_66_rexw_nop",3,{0x66,0x48,0x90}},
    {"repeated_rex_nop",3,{0x48,0x48,0x90}}, {"legacy_after_rex_nop",3,{0x48,0x66,0x90}},
    {"xbegin",6,{0xc7,0xf8,0,0,0,0}}, {"xend",3,{0x0f,0x01,0xd5}},
    {"xabort",3,{0xc6,0xf8,0}}, {"xtest",3,{0x0f,0x01,0xd6}},
    {"syscall",2,{0x0f,0x05}}, {"sysenter",2,{0x0f,0x34}},
    {"int80",2,{0xcd,0x80}}, {"int3",1,{0xcc}}, {"icebp",1,{0xf1}},
    {"far_return",1,{0xcb}}, {"hlt",1,{0xf4}},
    {"wrpkru",3,{0x0f,0x01,0xef}}, {"wrfsbase",5,{0xf3,0x48,0x0f,0xae,0xd0}},
    {"xrstor",3,{0x0f,0xae,0x28}}, {"fxsave",3,{0x0f,0xae,0x00}},
    {"enclu",3,{0x0f,0x01,0xd7}}, {"vmcall",3,{0x0f,0x01,0xc1}},
    {"rdmsr",2,{0x0f,0x32}}, {"mov_rax_cr0",3,{0x0f,0x20,0xc0}},
    {"lldt_ax",3,{0x0f,0x00,0xd0}}, {"ud2",2,{0x0f,0x0b}},
    {"selected_rdrand",4,{0x48,0x0f,0xc7,0xf0}},
    {"selected_rdseed",4,{0x48,0x0f,0xc7,0xf8}},
    {"selected_rdpid",4,{0xf3,0x0f,0xc7,0xf8}},
    {"selected_rdtsc",2,{0x0f,0x31}}, {"selected_rdtscp",3,{0x0f,0x01,0xf9}},
    {"selected_cpuid",2,{0x0f,0xa2}},
};
size_t li2_tf_refusal_count(void) { return sizeof(tf_refusals)/sizeof(tf_refusals[0]); }
const char *li2_tf_refusal_name(size_t index) {
    return index<li2_tf_refusal_count()?tf_refusals[index].name:0;
}
/* All progress/result slots are retained caller-owned output. No native call
   or successful hardware completion is represented by these parser controls. */
int li2_tf_refusal_controls(size_t *completed,size_t *failed_index,
                            uint32_t *decoder_result,struct li2_tf_classification *last) {
    if(!completed || !failed_index || !decoder_result || !last)return LI2_STEP_ARGUMENT;
    *completed=0;*failed_index=SIZE_MAX;*decoder_result=0;
    *last=(struct li2_tf_classification){0};
    for(size_t i=0;i<li2_tf_refusal_count();i++) {
        *failed_index=i;
        *decoder_result=li2_decoder_tf_classify(UINT64_C(0x1000),tf_refusals[i].bytes,
                                               tf_refusals[i].length,last);
        if(*decoder_result || last->abi_version!=1 || last->pc!=UINT64_C(0x1000) ||
           last->policy || last->flow || last->family)return LI2_TF_CLASSIFICATION;
        *completed=i+1;
    }
    *failed_index=SIZE_MAX;
    return 0;
}
