/* Explicit configured profile only; ordinary builds do not include this file. */
#include "provider_policy.h"
struct selected_provider_binding {
    li2_selected_callback random;
    li2_selected_cpuid_callback cpuid;
};
static const struct selected_provider_binding selected_provider_binding={
    li2_policy_mask_random_v1,li2_policy_cpuid_mask_v1
};
static struct {
    unsigned initialized,mode;
    volatile sig_atomic_t busy;
    uint64_t attempts,completed[4];
    struct li2_selected_callback_progress random;
    struct {
        volatile sig_atomic_t entered,returned,committed;
        int callback_status;
        struct li2_selected_cpuid_input input;
        struct li2_selected_cpuid_result result;
    } cpuid;
} selected_provider_state;
static void selected_provider_configure(void) {
    checked(!selected_provider_state.initialized,1600,0);
    const char *const *env=bridge_environment();
    const char key[]="LI2_SELECTED_PROVIDER=";
    const char mode[]="mask-random-v1";
    unsigned seen=0,configured=0;
    for(size_t i=0;env[i];i++) {
        checked(i<8192,1600,1);
        size_t j=0;while(j<sizeof(key)-1 && env[i][j]==key[j])++j;
        if(j!=sizeof(key)-1)continue;
        checked(!seen++,1600,2);
        const char *value=env[i]+sizeof(key)-1;
        size_t n=0;while(n<sizeof(mode)-1 && value[n]==mode[n])++n;
        if(n==sizeof(mode)-1 && !value[n])configured=1;
        else {
            const char native[]="native";
            n=0;while(n<sizeof(native)-1 && value[n]==native[n])++n;
            checked(n==sizeof(native)-1 && !value[n],1600,3);
        }
    }
    selected_provider_state.mode=configured;
    __asm__ volatile("":::"memory");selected_provider_state.initialized=1;
}
static void selected_provider_begin(void) {
    checked(selected_provider_state.initialized && selected_provider_state.mode==1 &&
        !selected_provider_state.busy && selected_provider_state.attempts!=UINT64_MAX,1601,0);
    selected_provider_state.busy=1;++selected_provider_state.attempts;
}
static void selected_provider_finish(unsigned kind) {
    checked(kind<4 && selected_provider_state.busy &&
        selected_provider_state.completed[kind]!=UINT64_MAX,1601,1);
    ++selected_provider_state.completed[kind];selected_provider_state.busy=0;
}
static int selected_provider_random(ucontext_t *uc,const struct li2_selected_request *request) {
    selected_provider_begin();
    int result=li2_selected_complete_callback(uc,request,selected_provider_binding.random,
        &selected_provider_state.random,&selected_completion);
    if(result)return result; /* retain failed prefix/busy until terminal cleanup */
    checked(selected_provider_state.random.entered==1 && selected_provider_state.random.returned==1 &&
        selected_provider_state.random.committed==1 && !selected_provider_state.random.first_error &&
        !selected_provider_state.random.callback_status && !selected_completion.native_attempts,1602,0);
    selected_provider_finish(selected_decoded.kind-LI2_RDRAND+1);
    return 0;
}
static void selected_provider_cpuid(uint32_t leaf,uint32_t subleaf,
                                    uint32_t *a,uint32_t *b,uint32_t *c,uint32_t *d) {
    selected_provider_begin();
    /* Original sample remains in selected_builtin_prefix. Its gate was already
       restored successfully; this copied result has no native authority. */
    __typeof__(selected_provider_state.cpuid) *p=&selected_provider_state.cpuid;
    *p=(__typeof__(*p)){.input={leaf,subleaf,{*a,*b,*c,*d}}};
    __asm__ volatile("":::"memory");p->entered=1;
    __asm__ volatile("":::"memory");
    p->callback_status=selected_provider_binding.cpuid(&p->input,&p->result);
    __asm__ volatile("":::"memory");p->returned=1;
    __asm__ volatile("":::"memory");
    checked(!p->callback_status,1603,p->callback_status);
    *a=p->result.eax;*b=p->result.ebx;*c=p->result.ecx;*d=p->result.edx;
    /* This only retains an application result. Frame commit is still the
       original builtin operation and publishes committed afterward. */
}
static void selected_provider_cpuid_committed(void) {
    checked(selected_provider_state.cpuid.entered==1 && selected_provider_state.cpuid.returned==1 &&
        !selected_provider_state.cpuid.committed,1603,1);
    __asm__ volatile("":::"memory");selected_provider_state.cpuid.committed=1;
    selected_provider_finish(0);
}
static void selected_provider_report(unsigned status,unsigned code) {
    if(!selected_provider_state.mode)return; /* default native report stays exact */
    struct writer w={.used=0};
    text(&w,"LI2_PROVIDER {\"version\":1,\"scope\":\"configured_cpuid_random_id\",\"policy\":\"mask-random-v1\"");
    field(&w,",\"status\":",status);field(&w,",\"failure_code\":",code);
    field(&w,",\"initialized\":",selected_provider_state.initialized);
    field(&w,",\"attempts\":",selected_provider_state.attempts);
    field(&w,",\"busy\":",selected_provider_state.busy);
    field(&w,",\"cpuid_completed\":",selected_provider_state.completed[0]);
    field(&w,",\"rdrand_completed\":",selected_provider_state.completed[1]);
    field(&w,",\"rdseed_completed\":",selected_provider_state.completed[2]);
    field(&w,",\"rdpid_completed\":",selected_provider_state.completed[3]);
    field(&w,",\"random_entered\":",selected_provider_state.random.entered);
    field(&w,",\"random_returned\":",selected_provider_state.random.returned);
    field(&w,",\"random_committed\":",selected_provider_state.random.committed);
    field(&w,",\"random_error\":",selected_provider_state.random.first_error);
    field(&w,",\"cpuid_entered\":",selected_provider_state.cpuid.entered);
    field(&w,",\"cpuid_returned\":",selected_provider_state.cpuid.returned);
    field(&w,",\"cpuid_committed\":",selected_provider_state.cpuid.committed);
    text(&w,"}\n");(void)raw(SYS_write,report_fd<0?2:report_fd,(long)w.bytes,w.used,0,0,0);
}
