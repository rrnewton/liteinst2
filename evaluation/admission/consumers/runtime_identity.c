/* Finite freestanding consumer. C computes the dependency between real results. */
__attribute__((noreturn, used)) void _start(void) {
    long pid;
    __asm__ volatile ("syscall" : "=a"(pid) : "a"(39L)
                      : "rcx", "r11", "memory");
    long tid;
    __asm__ volatile ("syscall" : "=a"(tid) : "a"(186L)
                      : "rcx", "r11", "memory");
    unsigned long status = ((unsigned long)pid ^ (unsigned long)tid) + 7UL;
    __asm__ volatile ("syscall" : : "a"(231L), "D"(status)
                      : "rcx", "r11", "memory");
    __builtin_unreachable();
}
