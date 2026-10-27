#define _GNU_SOURCE
#include <asm/prctl.h>
#include <elf.h>
#include <link.h>
#include <linux/audit.h>
#include <linux/prctl.h>
#include <signal.h>
#include <stddef.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/auxv.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/ucontext.h>
#include <time.h>
#include <unistd.h>
#include "probe_api.h"
#include "lifecycle.h"

#define PAGE 4096UL
#define MAX_RANGES 256
#define MAX_PAGES 8192
#define ALT_BYTES (512UL * 1024)
#define RESTORER_FLAG 0x04000000UL
#define USER_DISPATCH 2

extern long li2_raw6(long, long, long, long, long, long, long);
extern void li2_restorer(void);
extern char li2_gateway_start[], li2_gateway_end[];

struct range { uintptr_t first, end; };
struct page { uintptr_t address; unsigned admitted; };
struct kernel_action {
    void (*handler)(int, siginfo_t *, void *);
    unsigned long flags;
    void (*restorer)(void);
    uint64_t mask;
};
struct linux_dirent64 {
    uint64_t ino;
    int64_t offset;
    unsigned short length;
    unsigned char type;
    char name[];
};
static struct range executable[MAX_RANGES], protected[MAX_RANGES];
static struct page pages[MAX_PAGES];
static size_t executable_count, protected_count, page_count, main_pages;
static void *alternate_stack;
static int report_fd = 2;
static volatile sig_atomic_t in_handler;
static _Atomic uint64_t started_ns, nx_faults, nx_total_ns, nx_max_ns;
static _Atomic uint64_t cpuid_traps, rdtsc_traps, rdtscp_traps, syscall_traps, forwarded;
static _Atomic uint64_t mmap_calls, mprotect_calls, munmap_calls;
static _Atomic uint64_t self_cpuid, self_rdtsc, self_syscall;
static _Atomic unsigned capability_checks;
_Static_assert(ATOMIC_LLONG_LOCK_FREE == 2 && ATOMIC_INT_LOCK_FREE == 2, "handler counters must be lock-free");
static volatile sig_atomic_t selfcheck;
static volatile sig_atomic_t reported;

__attribute__((visibility("default")))
void li2_dynamic_snapshot(struct li2_dynamic_counters *out) {
    out->nx_faults = atomic_load_explicit(&nx_faults, memory_order_relaxed);
    out->syscall_traps = atomic_load_explicit(&syscall_traps, memory_order_relaxed);
    out->forwarded_syscalls = atomic_load_explicit(&forwarded, memory_order_relaxed);
}

__attribute__((visibility("default")))
void li2_dynamic_lifecycle_snapshot(struct li2_lifecycle_counts *out) { li2_lifecycle_snapshot(out); }
__attribute__((visibility("default")))
int li2_dynamic_lifecycle_page(uintptr_t address,struct li2_lifecycle_page_view *out) { return li2_lifecycle_query(address,out); }

static void activate(void) __attribute__((constructor));
static void fail(unsigned code, long detail) __attribute__((noreturn));

static long raw(long n, long a, long b, long c, long d, long e, long f) {
    return li2_raw6(n, a, b, c, d, e, f);
}

static uint64_t now(void) {
    struct timespec t;
    long result = raw(SYS_clock_gettime, CLOCK_MONOTONIC, (long)&t, 0, 0, 0, 0);
    if (result != 0) fail(1, result);
    return (uint64_t)t.tv_sec * 1000000000ULL + (uint64_t)t.tv_nsec;
}

struct writer { char bytes[4096]; size_t used; };
static void put(struct writer *out, char value) {
    if (out->used == sizeof(out->bytes)) {
        const char failure[] = "LI2_DYNAMIC report_overflow\n";
        (void)raw(SYS_write, report_fd, (long)failure, sizeof(failure) - 1, 0, 0, 0);
        (void)raw(SYS_exit_group, 125, 0, 0, 0, 0, 0);
        __builtin_trap();
    }
    out->bytes[out->used++] = value;
}
static void text(struct writer *out, const char *s) {
    while (*s) put(out, *s++);
}

static void decimal(struct writer *out, uint64_t number) {
    char reversed[20];
    size_t used = 0;
    do { reversed[used++] = (char)('0' + number % 10); number /= 10; } while (number);
    while (used) put(out, reversed[--used]);
}

static void field(struct writer *out, const char *name, uint64_t value) {
    text(out, name);
    decimal(out, value);
}

static void report(int status, unsigned reason, long detail) {
    if (reported) return;
    reported = 1;
    struct writer line = {.used = 0};
    struct timespec t = {0, 0};
    long timed = raw(SYS_clock_gettime, CLOCK_MONOTONIC, (long)&t, 0, 0, 0, 0);
    uint64_t ended = timed == 0 ? (uint64_t)t.tv_sec * 1000000000ULL + (uint64_t)t.tv_nsec : 0;
    text(&line, "LI2_DYNAMIC {\"version\":1,\"scope\":\"post_constructor\",\"source_patches\":0");
    field(&line, ",\"status\":", (unsigned)status);
    field(&line, ",\"failure_code\":", reason);
    field(&line, ",\"failure_detail_abs\":", detail < 0 ? 0ULL - (uint64_t)detail : (uint64_t)detail);
    field(&line, ",\"gated_pages\":", page_count);
    field(&line, ",\"main_pages\":", main_pages);
    field(&line, ",\"nx_faults\":", nx_faults);
    field(&line, ",\"nx_service_ns_total\":", nx_total_ns);
    field(&line, ",\"nx_service_ns_max\":", nx_max_ns);
    field(&line, ",\"cpuid_traps\":", cpuid_traps);
    field(&line, ",\"rdtsc_traps\":", rdtsc_traps);
    field(&line, ",\"rdtscp_traps\":", rdtscp_traps);
    field(&line, ",\"selfcheck_cpuid\":", self_cpuid);
    field(&line, ",\"selfcheck_rdtsc\":", self_rdtsc);
    field(&line, ",\"selfcheck_syscall\":", self_syscall);
    field(&line, ",\"capability_checks\":", capability_checks);
    field(&line, ",\"syscall_traps\":", syscall_traps);
    field(&line, ",\"forwarded_syscalls\":", forwarded);
    field(&line, ",\"mmap_calls\":", mmap_calls);
    field(&line, ",\"mprotect_calls\":", mprotect_calls);
    field(&line, ",\"munmap_calls\":", munmap_calls);
    if (timed == 0 && started_ns && ended >= started_ns)
        field(&line, ",\"active_ns\":", ended - started_ns);
    else
        text(&line, ",\"active_ns\":null");
    if (li2_lifecycle_enabled()) {
        struct li2_lifecycle_counts lc;
        li2_lifecycle_snapshot(&lc);
        field(&line, ",\"lifecycle_transactions\":", lc.transactions);
        field(&line, ",\"lifecycle_mappings\":", lc.mappings);
        field(&line, ",\"lifecycle_generations\":", lc.generations);
        field(&line, ",\"lifecycle_retired\":", lc.retired);
        field(&line, ",\"lifecycle_admissions\":", lc.admissions);
        field(&line, ",\"lifecycle_kernel_errors\":", lc.kernel_errors);
        field(&line, ",\"lifecycle_partial_errors\":", lc.partial_errors);
        field(&line, ",\"lifecycle_materialized\":", lc.materialized);
        field(&line, ",\"lifecycle_sync_core\":", lc.sync_core);
        field(&line, ",\"lifecycle_live_pages\":", lc.live_pages);
        field(&line, ",\"lifecycle_records\":", lc.retained_records);
        field(&line, ",\"lifecycle_last_operation\":", lc.last_operation);
        field(&line, ",\"lifecycle_last_syscall\":", lc.last_syscall);
        field(&line, ",\"lifecycle_last_errno\":", lc.last_result_negative ? lc.last_result_abs : 0);
        field(&line, ",\"lifecycle_last_result_negative\":", lc.last_result_negative);
        field(&line, ",\"lifecycle_last_phase\":", lc.last_phase);
    }
    text(&line, "}\n");
    (void)raw(SYS_write, report_fd, (long)line.bytes, line.used, 0, 0, 0);
}

static void fail(unsigned code, long detail) {
    li2_lifecycle_abort();
    report(125, code, detail);
    (void)raw(SYS_exit_group, 125, 0, 0, 0, 0, 0);
    __builtin_trap();
}

static int covers(const struct range *r, uintptr_t first, size_t bytes) {
    return first >= r->first && first <= r->end && bytes <= r->end - first;
}

static int known_code(uintptr_t first, size_t bytes) {
    for (size_t i = 0; i < executable_count; ++i)
        if (covers(&executable[i], first, bytes)) return 1;
    return li2_lifecycle_known_code(first, bytes);
}

static int intersects(uintptr_t first, size_t bytes) {
    if (!bytes || bytes > UINTPTR_MAX - first) return 1;
    uintptr_t end = first + bytes;
    for (size_t i = 0; i < protected_count; ++i)
        if (first < protected[i].end && protected[i].first < end) return 1;
    return 0;
}

static void add_range(struct range *out, size_t *count, uintptr_t first, uintptr_t end) {
    if (first >= end || *count == MAX_RANGES) fail(2, 0);
    out[*count].first = first;
    out[*count].end = end;
    ++*count;
}

static int vdso_name(const char *name) {
    const char prefix[] = "linux-vdso";
    for (size_t i = 0; i < sizeof(prefix) - 1; ++i)
        if (name[i] != prefix[i]) return 0;
    return 1;
}

static int collect(struct dl_phdr_info *info, size_t size, void *unused) {
    (void)size; (void)unused;
    int own = 0, main = info->dlpi_name[0] == 0, vdso = vdso_name(info->dlpi_name);
    for (size_t i = 0; i < info->dlpi_phnum; ++i) {
        const ElfW(Phdr) *p = &info->dlpi_phdr[i];
        uintptr_t first = info->dlpi_addr + p->p_vaddr;
        if (p->p_type == PT_LOAD && (uintptr_t)&activate >= first && (uintptr_t)&activate - first < p->p_memsz) own = 1;
    }
    for (size_t i = 0; i < info->dlpi_phnum; ++i) {
        const ElfW(Phdr) *p = &info->dlpi_phdr[i];
        if (p->p_type != PT_LOAD || !p->p_memsz) continue;
        uintptr_t first = info->dlpi_addr + p->p_vaddr;
        if (first < info->dlpi_addr || p->p_memsz > UINTPTR_MAX - first - (PAGE - 1)) fail(3, 0);
        uintptr_t end = (first + p->p_memsz + PAGE - 1) & ~(PAGE - 1);
        first &= ~(PAGE - 1);
        if (own || (p->p_flags & PF_X)) add_range(protected, &protected_count, first, end);
        if (!(p->p_flags & PF_X)) continue;
        if ((p->p_flags & (PF_R | PF_W)) != PF_R) fail(4, p->p_flags);
        add_range(executable, &executable_count, first, end);
        if (own || vdso) continue;
        for (uintptr_t address = first; address < end; address += PAGE) {
            int duplicate = 0;
            for (size_t j = 0; j < page_count; ++j) if (pages[j].address == address) duplicate = 1;
            if (duplicate) continue;
            if (page_count == MAX_PAGES) fail(5, 0);
            pages[page_count++].address = address;
            if (main) ++main_pages;
        }
    }
    return 0;
}

static void single_thread(void) {
    if (raw(SYS_getpid, 0, 0, 0, 0, 0, 0) != raw(SYS_gettid, 0, 0, 0, 0, 0, 0)) fail(6, 0);
    const char path[] = "/proc/self/task";
    long fd = raw(SYS_openat, -100, (long)path, 0x90000, 0, 0, 0);
    if (fd < 0) fail(7, fd);
    _Alignas(8) char buffer[4096];
    unsigned count = 0;
    for (;;) {
        long got = raw(SYS_getdents64, fd, (long)buffer, sizeof(buffer), 0, 0, 0);
        if (got < 0) fail(8, got);
        if (got == 0) break;
        size_t at = 0;
        while (at < (size_t)got) {
            struct linux_dirent64 *d = (void *)(buffer + at);
            if ((size_t)got - at < offsetof(struct linux_dirent64, name) + 1 ||
                d->length < offsetof(struct linux_dirent64, name) + 1 || d->length > (size_t)got - at) fail(9, 0);
            if (d->name[0] >= '0' && d->name[0] <= '9') ++count;
            at += d->length;
        }
    }
    if (raw(SYS_close, fd, 0, 0, 0, 0, 0) != 0 || count != 1) fail(10, count);
}

static int ordinary_syscall(long n) {
    switch (n) {
    case SYS_read: case SYS_write: case SYS_readv: case SYS_writev:
    case SYS_openat: case SYS_close: case SYS_fstat: case SYS_newfstatat:
    case SYS_statx: case SYS_lseek: case SYS_pread64: case SYS_getdents64:
    case SYS_access: case SYS_faccessat: case SYS_faccessat2:
    case SYS_readlink: case SYS_readlinkat: case SYS_getcwd:
    case SYS_getuid: case SYS_geteuid: case SYS_getgid: case SYS_getegid:
    case SYS_getpid: case SYS_gettid: case SYS_uname: case SYS_sysinfo:
    case SYS_getrandom: case SYS_clock_gettime: case SYS_gettimeofday:
    case SYS_getxattr: case SYS_lgetxattr: case SYS_fgetxattr:
    case SYS_listxattr: case SYS_llistxattr: case SYS_flistxattr:
    case SYS_brk: case SYS_futex: case SYS_fcntl: case SYS_prlimit64:
        return 1;
    default: return 0;
    }
}

static void dispatch(siginfo_t *info, ucontext_t *uc) {
    greg_t *g = uc->uc_mcontext.gregs;
    uintptr_t next = (uintptr_t)g[REG_RIP];
    long n = info->si_syscall;
    if (info->si_code != USER_DISPATCH || info->si_arch != AUDIT_ARCH_X86_64 ||
        (uintptr_t)info->si_call_addr != next || next < 2 || !known_code(next - 2, 2) ||
        *(const uint16_t *)(next - 2) != 0x050f || g[REG_RAX] != n || (uintptr_t)g[REG_RCX] != next) fail(20, n);
    if (selfcheck) ++self_syscall; else ++syscall_traps;
    long a = g[REG_RDI], b = g[REG_RSI], c = g[REG_RDX];
    long d = g[REG_R10], e = g[REG_R8], f = g[REG_R9];
    if (n == SYS_exit || n == SYS_exit_group) {
        ++forwarded;
        report((int)a, 0, 0);
        (void)raw(n, a, b, c, d, e, f);
        fail(21, n);
    }
    if (n == SYS_close && a == report_fd) fail(31, n);
    long arguments[6] = {a,b,c,d,e,f}, lifecycle_result;
    li2_lifecycle_before_other(n, arguments);
    if (li2_lifecycle_dispatch(n, arguments, &lifecycle_result)) {
        if (n == SYS_mmap) ++mmap_calls;
        if (n == SYS_mprotect) ++mprotect_calls;
        if (n == SYS_munmap) ++munmap_calls;
        ++forwarded;
        g[REG_RAX] = lifecycle_result;
        g[REG_RCX] = (greg_t)next;
        g[REG_R11] = g[REG_EFL];
        return;
    }
    if (n == SYS_mmap) {
        if ((c & PROT_EXEC) || (d & (MAP_FIXED | MAP_FIXED_NOREPLACE))) fail(22, n);
        ++mmap_calls;
    } else if (n == SYS_mprotect) {
        if ((c & PROT_EXEC) || intersects((uintptr_t)a, (size_t)b)) fail(23, n);
        ++mprotect_calls;
    } else if (n == SYS_munmap) {
        if (intersects((uintptr_t)a, (size_t)b)) fail(24, n);
        ++munmap_calls;
    } else if (n == SYS_madvise) {
        if (intersects((uintptr_t)a, (size_t)b)) fail(25, n);
    } else if (n == SYS_arch_prctl) {
        if (a != ARCH_SET_FS && a != ARCH_SET_GS && a != ARCH_GET_FS && a != ARCH_GET_GS) fail(26, n);
    } else if (n == SYS_rt_sigaction || n == SYS_rt_sigprocmask) {
        if (b != 0) fail(27, n); /* Queries retain genuine kernel output. */
    } else if (n == SYS_sigaltstack) {
        if (a != 0) fail(28, n);
    } else if (n == SYS_ioctl) {
        if (b != 0x5401 && b != 0x5413 && b != 0x541b) fail(29, b); /* TCGETS, TIOCGWINSZ, FIONREAD */
    } else if (!ordinary_syscall(n)) {
        fail(30, n);
    }
    if (!selfcheck) ++forwarded;
    long result = raw(n, a, b, c, d, e, f);
    g[REG_RAX] = result;
    g[REG_RCX] = (greg_t)next;
    g[REG_R11] = g[REG_EFL];
}

static void fault(siginfo_t *info, ucontext_t *uc) {
    greg_t *g = uc->uc_mcontext.gregs;
    uintptr_t pc = (uintptr_t)g[REG_RIP];
    if (g[REG_TRAPNO] == 14 && (g[REG_ERR] & 0x17) == 0x15 && info->si_code == SEGV_ACCERR) {
        uint64_t begin = now();
        uintptr_t address = (uintptr_t)info->si_addr;
        if (!known_code(pc, 1) || address < pc || address - pc > 14) fail(40, 0);
        uintptr_t page = address & ~(PAGE - 1);
        for (size_t i = 0; i < page_count; ++i) {
            if (pages[i].address != page) continue;
            if (pages[i].admitted) fail(41, 0);
            long result = raw(SYS_mprotect, page, PAGE, PROT_READ | PROT_EXEC, 0, 0, 0);
            if (result != 0) fail(42, result);
            pages[i].admitted = 1;
            ++nx_faults;
            uint64_t elapsed = now() - begin;
            nx_total_ns += elapsed;
            if (elapsed > nx_max_ns) nx_max_ns = elapsed;
            return;
        }
        if (li2_lifecycle_admit(pc, address)) {
            ++nx_faults;
            uint64_t elapsed = now() - begin;
            nx_total_ns += elapsed;
            if (elapsed > nx_max_ns) nx_max_ns = elapsed;
            return;
        }
        fail(43, 0);
    }
    if (g[REG_TRAPNO] != 13 || g[REG_ERR] != 0 || info->si_code != SI_KERNEL || !known_code(pc, 2)) fail(44, g[REG_TRAPNO]);
    const unsigned char *opcode = (const void *)pc;
    if (opcode[0] == 0x0f && opcode[1] == 0xa2) {
        long result = raw(SYS_arch_prctl, ARCH_SET_CPUID, 1, 0, 0, 0, 0);
        if (result != 0) fail(45, result);
        uint32_t a = (uint32_t)g[REG_RAX], b, c = (uint32_t)g[REG_RCX], d;
        __asm__ volatile("cpuid" : "+a"(a), "=b"(b), "+c"(c), "=d"(d) :: "memory");
        result = raw(SYS_arch_prctl, ARCH_SET_CPUID, 0, 0, 0, 0, 0);
        if (result != 0) fail(46, result);
        g[REG_RAX] = a; g[REG_RBX] = b; g[REG_RCX] = c; g[REG_RDX] = d;
        g[REG_RIP] += 2;
        if (selfcheck) ++self_cpuid; else ++cpuid_traps;
        return;
    }
    int rdtscp = opcode[0] == 0x0f && opcode[1] == 0x01 && known_code(pc, 3) && opcode[2] == 0xf9;
    if ((opcode[0] == 0x0f && opcode[1] == 0x31) || rdtscp) {
        long result = raw(SYS_prctl, PR_SET_TSC, PR_TSC_ENABLE, 0, 0, 0, 0);
        if (result != 0) fail(47, result);
        uint32_t a, d, c = 0;
        if (rdtscp) __asm__ volatile("rdtscp" : "=a"(a), "=d"(d), "=c"(c) :: "memory");
        else __asm__ volatile("rdtsc" : "=a"(a), "=d"(d) :: "memory");
        result = raw(SYS_prctl, PR_SET_TSC, PR_TSC_SIGSEGV, 0, 0, 0, 0);
        if (result != 0) fail(48, result);
        g[REG_RAX] = a; g[REG_RDX] = d;
        if (rdtscp) g[REG_RCX] = c;
        g[REG_RIP] += rdtscp ? 3 : 2;
        if (selfcheck) ++self_rdtsc; else if (rdtscp) ++rdtscp_traps; else ++rdtsc_traps;
        return;
    }
    fail(49, 0);
}

static void handler(int signal, siginfo_t *info, void *context) {
    if (in_handler) fail(50, signal);
    in_handler = 1;
    if (signal == SIGSYS) dispatch(info, context);
    else if (signal == SIGSEGV) fault(info, context);
    else fail(51, signal);
    in_handler = 0;
}

static void activate(void) {
    if (getauxval(AT_PAGESZ) != PAGE || getauxval(AT_MINSIGSTKSZ) + 16384 > ALT_BYTES) fail(60, 0);
    single_thread();
    long diagnostic = raw(SYS_fcntl, 2, 1030, 100, 0, 0, 0); /* F_DUPFD_CLOEXEC */
    if (diagnostic < 0) fail(73, diagnostic);
    report_fd = (int)diagnostic;
    unsigned long cet = 0;
    long result = raw(SYS_arch_prctl, 0x5005, (long)&cet, 0, 0, 0, 0);
    if (result == 0 && cet != 0) fail(61, cet);
    if (result != 0 && result != -22 && result != -38) fail(62, result);
    uint64_t mask = 0;
    result = raw(SYS_rt_sigprocmask, 0, 0, (long)&mask, 8, 0, 0);
    if (result != 0 || (mask & ((1ULL << (SIGSEGV - 1)) | (1ULL << (SIGSYS - 1))))) fail(63, result);
    struct kernel_action old;
    for (int signal = 1; signal <= 64; ++signal) {
        if (signal == SIGKILL || signal == SIGSTOP) continue;
        result = raw(SYS_rt_sigaction, signal, 0, (long)&old, 8, 0, 0);
        if (result != 0 || (uintptr_t)old.handler > 1) fail(64, signal);
    }
    if (dl_iterate_phdr(collect, 0) != 0 || !page_count || !main_pages) fail(65, 0);
    long storage = raw(SYS_mmap, 0, ALT_BYTES + 2 * PAGE, PROT_NONE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (storage < 0 && storage >= -4095) fail(74, storage);
    alternate_stack = (void *)((uintptr_t)storage + PAGE);
    if (raw(SYS_mprotect, (long)alternate_stack, ALT_BYTES, PROT_READ | PROT_WRITE, 0, 0, 0) != 0) fail(75, 0);
    add_range(protected, &protected_count, (uintptr_t)storage, (uintptr_t)storage + ALT_BYTES + 2 * PAGE);
    stack_t stack = {.ss_sp = alternate_stack, .ss_flags = 0, .ss_size = ALT_BYTES};
    if (raw(SYS_sigaltstack, (long)&stack, 0, 0, 0, 0, 0) != 0) fail(66, 0);
    struct kernel_action action = {
        .handler = handler,
        .flags = SA_SIGINFO | SA_ONSTACK | SA_NODEFER | RESTORER_FLAG,
        .restorer = li2_restorer,
        .mask = UINT64_MAX & ~(1ULL << (SIGSEGV - 1)) & ~(1ULL << (SIGSYS - 1)),
    };
    if (raw(SYS_rt_sigaction, SIGSEGV, (long)&action, 0, 8, 0, 0) != 0 ||
        raw(SYS_rt_sigaction, SIGSYS, (long)&action, 0, 8, 0, 0) != 0) fail(67, 0);
    if (raw(SYS_arch_prctl, ARCH_GET_CPUID, 0, 0, 0, 0, 0) != 1) fail(76, 0);
    int tsc_mode = 0;
    if (raw(SYS_prctl, PR_GET_TSC, (long)&tsc_mode, 0, 0, 0, 0) != 0 || tsc_mode != PR_TSC_ENABLE) fail(77, 0);
    const char *lifecycle_fd = getenv("LI2_LIFECYCLE_FD");
    if (lifecycle_fd) {
        unsigned fd = 0;
        if (!*lifecycle_fd) fail(84, 0);
        for (const char *p = lifecycle_fd; *p; ++p) {
            if (*p < '0' || *p > '9' || fd > 100000) fail(84, 0);
            fd = fd * 10 + (unsigned)(*p - '0');
        }
        const struct li2_lifecycle_hooks callbacks = {raw, fail, intersects};
        li2_lifecycle_initialize((int)fd, &callbacks);
        const char *fault_control = getenv("LI2_LIFECYCLE_FAIL_AFTER_MPROTECT");
        if (fault_control) {
            if (fault_control[0] != '1' || fault_control[1]) fail(85, 0);
            li2_lifecycle_fault_control(1);
        }
    }
    uint32_t native_a = 0, native_b, native_c = 0, native_d;
    __asm__ volatile("cpuid" : "+a"(native_a), "=b"(native_b), "+c"(native_c), "=d"(native_d) :: "memory");
    long native_pid = raw(SYS_getpid, 0, 0, 0, 0, 0, 0);
    uint32_t before_low, before_high;
    __asm__ volatile("rdtsc" : "=a"(before_low), "=d"(before_high) :: "memory");
    uint64_t before_tsc = (uint64_t)before_low | (uint64_t)before_high << 32;
    started_ns = now();
    result = raw(SYS_arch_prctl, ARCH_SET_CPUID, 0, 0, 0, 0, 0);
    if (result != 0) fail(68, result);
    result = raw(SYS_prctl, PR_SET_TSC, PR_TSC_SIGSEGV, 0, 0, 0, 0);
    if (result != 0) fail(69, result);
    result = raw(SYS_prctl, PR_SET_SYSCALL_USER_DISPATCH, PR_SYS_DISPATCH_ON,
                 (long)li2_gateway_start, li2_gateway_end - li2_gateway_start, 0, 0);
    if (result != 0) fail(70, result);
    for (size_t i = 0; i < page_count; ++i)
        if (raw(SYS_mprotect, pages[i].address, PAGE, PROT_READ, 0, 0, 0) != 0) fail(71, 0);
    /* Separate explicit capability probes; never counted as application use. */
    selfcheck = 1;
    uint64_t a = 0xffffffff00000000ULL, b, c = 0xffffffff00000000ULL, d;
    __asm__ volatile("cpuid" : "+a"(a), "=b"(b), "+c"(c), "=d"(d) :: "memory");
    if (a != native_a || b != native_b || c != native_c || d != native_d) fail(78, 0);
    __asm__ volatile("rdtsc" : "=a"(a), "=d"(d) :: "memory");
    if (a >> 32 || d >> 32) fail(79, 0);
    uint64_t observed_tsc = a | d << 32;
    long actual_pid = SYS_getpid;
    uint64_t actual_rcx, original_flags, expected_rcx;
    register uint64_t actual_r11 __asm__("r11");
    __asm__ volatile("pushfq; pop %[flags]; lea 1f(%%rip), %[next]; syscall; 1:"
                     : "+a"(actual_pid), "=c"(actual_rcx), "=r"(actual_r11),
                       [flags] "=&r"(original_flags), [next] "=&r"(expected_rcx)
                     :: "memory", "cc");
    if (actual_pid != native_pid || actual_rcx != expected_rcx || actual_r11 != original_flags) fail(80, 0);
    selfcheck = 0;
    if (raw(SYS_prctl, PR_SET_TSC, PR_TSC_ENABLE, 0, 0, 0, 0) != 0) fail(81, 0);
    uint32_t after_low, after_high;
    __asm__ volatile("rdtsc" : "=a"(after_low), "=d"(after_high) :: "memory");
    if (raw(SYS_prctl, PR_SET_TSC, PR_TSC_SIGSEGV, 0, 0, 0, 0) != 0) fail(82, 0);
    uint64_t after_tsc = (uint64_t)after_low | (uint64_t)after_high << 32;
    if (observed_tsc < before_tsc || observed_tsc > after_tsc) fail(83, 0);
    if (self_cpuid != 1 || self_rdtsc != 1 || self_syscall != 1) fail(72, 0);
    capability_checks = 1;
}
