/* Fixture-only immutable binding. The named production policy always runs;
   exactly one declared test result is then made invalid, or genuinely faults.
   No runtime validator, source owner, frame or syscall gate is changed. */
static unsigned pb_negative,pb_used,pb_callback_hits;
static unsigned pb_target(void) {
    static const unsigned target[13]={99,0,7,0,0,3,10,3,5,11,10,10,3};
    return pb_negative<=12?target[pb_negative]:99;
}
static int __attribute__((noinline)) pb_clock_callback(
    const struct li2_selected_clock_input *in,struct li2_selected_clock_result *out) {
    int result=li2_policy_clock_v1(in,out);
    if(!pb_negative || pb_used!=pb_target())return result;
    ++pb_callback_hits;
    if(pb_negative==1)return 7;
    if(pb_negative==2)out->reserved=1;
    if(pb_negative==3)out->aux=1;
    if(pb_negative==4)__asm__ volatile(".global pb_clock_fault\npb_clock_fault: ud2":::"memory");
    return result;
}
static int __attribute__((noinline)) pb_syscall_callback(
    const struct li2_selected_syscall_input *in,struct li2_selected_syscall_result *out) {
    int result=li2_policy_syscall_v1(in,out);
    if(!pb_negative || pb_used!=pb_target())return result;
    ++pb_callback_hits;
    if(pb_negative==5)return 7;
    if(pb_negative==6)out->reserved=1;
    if(pb_negative==7)*out=(struct li2_selected_syscall_result){LI2_SYSCALL_NATIVE,0,1};
    if(pb_negative==8)*out=(struct li2_selected_syscall_result){LI2_SYSCALL_REPLACE,0,LI2_POLICY_PID};
    if(pb_negative==9)out->value=LI2_POLICY_PID;
    if(pb_negative==10)out->action=2;
    if(pb_negative==11)__asm__ volatile(".global pb_syscall_fault\npb_syscall_fault: ud2":::"memory");
    /* Mode12 deliberately leaves NATIVE intact for a real forbidden prctl. */
    return result;
}
