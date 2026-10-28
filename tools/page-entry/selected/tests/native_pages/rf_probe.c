#define _GNU_SOURCE
#include <errno.h>
#include <inttypes.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <ucontext.h>
#include <unistd.h>

/* Architecture component oracle, not a substitute for the production owner.
 * Both lanes execute the same original selected PC. The NX lane uses a real
 * instruction-fetch #PF and completes precisely that operation in its handler.
 * No synthetic signal/frame, debugger, TF, source modification or value repair.
 * RF history is deliberately not reconstructed: only the next successful
 * operation's architectural result is compared. See Intel Vol.3 18.3.1.1.
 */
#define PAGE 4096u
#define RF UINT64_C(0x10000)
#define ARITH UINT64_C(0x8d5)
#define CASES 48u
enum { A, B, C, D, SI, DI, BP, SP, R8, R9, R10, R11, R12, R13, R14, R15, FLAGS };
static const int greg_index[16] = { REG_RAX, REG_RBX, REG_RCX, REG_RDX,
    REG_RSI, REG_RDI, REG_RBP, REG_RSP, REG_R8, REG_R9, REG_R10, REG_R11,
    REG_R12, REG_R13, REG_R14, REG_R15 };
uint64_t rf_seed[16], rf_out[17], rf_host_sp, rf_entry, rf_flags, rf_stack;
unsigned char rf_fp_seed[512] __attribute__((aligned(64)));
unsigned char rf_fp_out[512] __attribute__((aligned(64)));
extern void rf_enter(void), rf_capture(void);
__asm__(
".text\n.p2align 4\n.global rf_enter\n.type rf_enter,@function\nrf_enter:\n"
"push %rbp\npush %rbx\npush %r12\npush %r13\npush %r14\npush %r15\n"
"mov %rsp,rf_host_sp(%rip)\nfxrstor64 rf_fp_seed(%rip)\n"
"pushq $0x2b\npushq rf_stack(%rip)\npushq rf_flags(%rip)\npushq $0x33\npushq rf_entry(%rip)\n"
"mov rf_seed+0(%rip),%rax\nmov rf_seed+8(%rip),%rbx\n"
"mov rf_seed+16(%rip),%rcx\nmov rf_seed+24(%rip),%rdx\n"
"mov rf_seed+32(%rip),%rsi\nmov rf_seed+40(%rip),%rdi\nmov rf_seed+48(%rip),%rbp\n"
"mov rf_seed+64(%rip),%r8\nmov rf_seed+72(%rip),%r9\nmov rf_seed+80(%rip),%r10\n"
"mov rf_seed+88(%rip),%r11\nmov rf_seed+96(%rip),%r12\nmov rf_seed+104(%rip),%r13\n"
"mov rf_seed+112(%rip),%r14\nmov rf_seed+120(%rip),%r15\niretq\n.size rf_enter,.-rf_enter\n"
".p2align 4\n.global rf_capture\n.type rf_capture,@function\nrf_capture:\n"
"mov %rax,rf_out+0(%rip)\nmov %rbx,rf_out+8(%rip)\nmov %rcx,rf_out+16(%rip)\n"
"mov %rdx,rf_out+24(%rip)\nmov %rsi,rf_out+32(%rip)\nmov %rdi,rf_out+40(%rip)\n"
"mov %rbp,rf_out+48(%rip)\nmov %rsp,rf_out+56(%rip)\nmov %r8,rf_out+64(%rip)\n"
"mov %r9,rf_out+72(%rip)\nmov %r10,rf_out+80(%rip)\nmov %r11,rf_out+88(%rip)\n"
"mov %r12,rf_out+96(%rip)\nmov %r13,rf_out+104(%rip)\nmov %r14,rf_out+112(%rip)\n"
"mov %r15,rf_out+120(%rip)\npushfq\npopq rf_out+128(%rip)\n"
"fxsave64 rf_fp_out(%rip)\ncld\nmov rf_host_sp(%rip),%rsp\n"
"pop %r15\npop %r14\npop %r13\npop %r12\npop %rbx\npop %rbp\nret\n"
".size rf_capture,.-rf_capture\n");

struct row {
    uint64_t id, operation, restored_rf, arithmetic_epoch, input_flags, logical_flags;
    uint64_t seed[16], native[17], completed[17], fault_greg[NGREG];
    uint64_t signal_number, signal_code, signal_errno, signal_address, signal_mask;
    uint64_t raw_operations, faults, mprotect_returned, frame_fp_unchanged;
    unsigned char native_fp[512], completed_fp[512], fault_fp[512];
};
static struct row rows[CASES];
static struct row *current;
static unsigned char *selected_page, *selected_pc;
static volatile sig_atomic_t expecting_nx;
static uint64_t expected_pid;

static void fail(unsigned code) {
    /* Retain the entire initialized/partial prefix on every failure. */
    (void)write(3, rows, sizeof(rows));
    _exit((int)code);
}
static void need(int yes, unsigned code) { if (!yes) fail(code); }
static long raw3(long n, long a, long b, long c) {
    long r;
    __asm__ volatile("syscall" : "=a"(r) : "0"(n), "D"(a), "S"(b), "d"(c)
                     : "rcx", "r11", "memory", "cc");
    return r;
}
static void fault(int sig, siginfo_t *si, void *context) {
    ucontext_t *uc = context;
    greg_t *g = uc->uc_mcontext.gregs;
    struct row *r = current;
    if (!r || !si || !expecting_nx) fail(101);
    ++r->faults;
    for (size_t i = 0; i < NGREG; ++i) r->fault_greg[i] = (uint64_t)g[i];
    r->signal_number = (unsigned)sig; r->signal_code = (unsigned)si->si_code;
    r->signal_errno = (unsigned)si->si_errno; r->signal_address = (uintptr_t)si->si_addr;
    memcpy(&r->signal_mask, &uc->uc_sigmask, 8);
    need(g[REG_CSGSFS] % 65536 == 0x33 && uc->uc_mcontext.fpregs != NULL, 102);
    memcpy(r->fault_fp, uc->uc_mcontext.fpregs, 512);
    need(sig == SIGSEGV && si->si_signo == SIGSEGV && si->si_code == SEGV_ACCERR &&
         !si->si_errno && r->faults == 1 && g[REG_TRAPNO] == 14 && g[REG_ERR] == 21 &&
         (uintptr_t)g[REG_RIP] == (uintptr_t)selected_pc &&
         (uintptr_t)g[REG_CR2] == (uintptr_t)selected_pc && si->si_addr == selected_pc &&
         !r->signal_mask, 103);
    need((uint64_t)g[REG_EFL] == (r->logical_flags | RF), 104);
    for (size_t i = 0; i < 16; ++i)
        need((uint64_t)g[greg_index[i]] == (i == R8 && r->arithmetic_epoch ? 0 : r->seed[i]), 105);
    need(selected_pc[0] == 0x0f && selected_pc[1] == (r->operation ? 0xa2 : 0x05), 106);
    if (!r->operation) {
        long result = raw3(SYS_getpid, 0, 0, 0);
        ++r->raw_operations;
        need(result > 0 && (uint64_t)result == expected_pid, 107);
        g[REG_RAX] = result;
        g[REG_RCX] = (greg_t)(selected_pc + 2);
        g[REG_R11] = (greg_t)((uint64_t)g[REG_EFL] & ~RF);
    } else {
        uint32_t a = (uint32_t)g[REG_RAX], c = (uint32_t)g[REG_RCX], b, d;
        __asm__ volatile("cpuid" : "+a"(a), "=b"(b), "+c"(c), "=d"(d));
        ++r->raw_operations;
        g[REG_RAX] = a; g[REG_RBX] = b; g[REG_RCX] = c; g[REG_RDX] = d;
    }
    g[REG_EFL] = (greg_t)((uint64_t)g[REG_EFL] & ~RF);
    g[REG_RIP] += 2;
    /* Component-only permission transition: the production native owner is
       deliberately not replaced or simulated by this independent oracle. */
    long result = raw3(SYS_mprotect, (long)selected_page, PAGE, PROT_READ | PROT_EXEC);
    r->mprotect_returned = 1;
    need(result == 0, 108);
    need(!memcmp(r->fault_fp, uc->uc_mcontext.fpregs, 512), 109);
    r->frame_fp_unchanged = 1;
    expecting_nx = 0;
}
static void jump(unsigned char *p, uintptr_t to) {
    static const unsigned char opcode[6] = {0xff, 0x25, 0, 0, 0, 0};
    memcpy(p, opcode, sizeof(opcode)); memcpy(p + 6, &to, sizeof(to));
}
int main(void) {
    static const uint64_t patterns[6] = {0x202, 0x203, 0x246, 0xa96, 0x602, 0xed7};
    alarm(5);
    need(sysconf(_SC_PAGESIZE) == PAGE, 110);
    expected_pid = (uint64_t)getpid();
    sigset_t empty; sigemptyset(&empty);
    need(sigprocmask(SIG_SETMASK, &empty, NULL) == 0, 111);
    unsigned char *alt = mmap(NULL, 65536, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    unsigned char *stack = mmap(NULL, 65536, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    selected_page = mmap(NULL, PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    unsigned char *epoch = mmap(NULL, PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    need(alt != MAP_FAILED && stack != MAP_FAILED && selected_page != MAP_FAILED && epoch != MAP_FAILED, 112);
    stack_t ss = {.ss_sp = alt, .ss_size = 65536};
    need(sigaltstack(&ss, NULL) == 0, 113);
    struct sigaction sa = {.sa_sigaction = fault, .sa_flags = SA_SIGINFO | SA_ONSTACK};
    sigemptyset(&sa.sa_mask);
    need(sigaction(SIGSEGV, &sa, NULL) == 0, 114);
    selected_pc = selected_page + 128;
    epoch[0] = 0x49; epoch[1] = 0x83; epoch[2] = 0xc0; epoch[3] = 1; /* ADD R8,1 */
    jump(epoch + 4, (uintptr_t)selected_pc);
    need(mprotect(epoch, PAGE, PROT_READ | PROT_EXEC) == 0, 115);
    __asm__ volatile("fxsave64 %0" : "=m"(rf_fp_seed));
    size_t id = 0;
    for (unsigned op = 0; op < 2; ++op) {
        need(mprotect(selected_page, PAGE, PROT_READ | PROT_WRITE) == 0, 116);
        memset(selected_page, 0x90, PAGE);
        selected_pc[0] = 0x0f; selected_pc[1] = op ? 0xa2 : 0x05;
        jump(selected_pc + 2, (uintptr_t)rf_capture);
        unsigned char original[PAGE]; memcpy(original, selected_page, PAGE);
        for (unsigned arithmetic = 0; arithmetic < 2; ++arithmetic)
        for (unsigned pattern = 0; pattern < 6; ++pattern)
        for (unsigned restored = 0; restored < 2; ++restored) {
            struct row *r = &rows[id]; current = r;
            r->id = id; r->operation = op; r->restored_rf = restored; r->arithmetic_epoch = arithmetic;
            r->input_flags = patterns[pattern] | (restored ? RF : 0);
            r->logical_flags = arithmetic ? ((patterns[pattern] & ~ARITH) | 0x55) : patterns[pattern];
            for (size_t i = 0; i < 16; ++i) r->seed[i] = UINT64_C(0x13579bdf02468000) + 0x111 * i;
            r->seed[A] = op ? 0 : SYS_getpid; r->seed[C] = 0; r->seed[R8] = UINT64_MAX;
            r->seed[SP] = (uintptr_t)(stack + 65536 - 256);
            memcpy(rf_seed, r->seed, sizeof(rf_seed));
            rf_stack = r->seed[SP]; rf_flags = r->input_flags;
            rf_entry = (uintptr_t)(arithmetic ? epoch : selected_pc);
            need(mprotect(selected_page, PAGE, PROT_READ | PROT_EXEC) == 0, 117);
            memset(rf_out, 0, sizeof(rf_out)); memset(rf_fp_out, 0, sizeof(rf_fp_out));
            rf_enter();
            memcpy(r->native, rf_out, sizeof(rf_out)); memcpy(r->native_fp, rf_fp_out, 512);
            need(mprotect(selected_page, PAGE, PROT_READ) == 0, 118);
            memset(rf_out, 0, sizeof(rf_out)); memset(rf_fp_out, 0, sizeof(rf_fp_out));
            expecting_nx = 1; rf_enter();
            memcpy(r->completed, rf_out, sizeof(rf_out)); memcpy(r->completed_fp, rf_fp_out, 512);
            need(!expecting_nx && r->faults == 1 && r->raw_operations == 1 &&
                 r->mprotect_returned && r->frame_fp_unchanged, 119);
            need(!memcmp(r->native, r->completed, sizeof(r->native)), 120);
            need(!memcmp(r->native_fp, r->completed_fp, 512), 121);
            need(r->native[FLAGS] == r->logical_flags, 122);
            for (size_t i = 0; i < 16; ++i) {
                if ((!op && (i == A || i == C || i == R11)) || (op && i <= D)) continue;
                need(r->native[i] == (i == R8 && arithmetic ? 0 : r->seed[i]), 123);
            }
            if (!op) need(r->native[A] == expected_pid && r->native[C] == (uintptr_t)(selected_pc + 2) &&
                          r->native[R11] == r->logical_flags, 124);
            need(!memcmp(original, selected_page, PAGE), 125);
            ++id;
        }
    }
    need(id == CASES, 126);
    need(write(3, rows, sizeof(rows)) == (ssize_t)sizeof(rows), 127);
    printf("{\"schema\":1,\"cases\":%u,\"native_operations\":%u,\"nx_operations\":%u,\"same_pc\":true,\"rows\":[", CASES, CASES, CASES);
    for (size_t i = 0; i < CASES; ++i) {
        const struct row *r = &rows[i];
        printf("%s[%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 "]",
               i ? "," : "", r->id, r->operation, r->restored_rf, r->arithmetic_epoch, r->input_flags,
               r->fault_greg[REG_EFL], r->native[FLAGS], r->completed[FLAGS], r->native[R11]);
    }
    puts("]}");
    need(munmap(epoch, PAGE) == 0 && munmap(selected_page, PAGE) == 0 && munmap(stack, 65536) == 0, 128);
    ss.ss_flags = SS_DISABLE; need(sigaltstack(&ss, NULL) == 0 && munmap(alt, 65536) == 0, 129);
    return 0;
}
