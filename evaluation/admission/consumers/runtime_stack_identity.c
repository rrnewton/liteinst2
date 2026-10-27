__attribute__((noinline, used))
static unsigned long add_seven(unsigned long value) {
    return value + 7UL;
}

__attribute__((noreturn, used)) void _start(void) {
    unsigned long pid;
    __asm__ volatile ("syscall" : "=a"(pid) : "a"(39UL)
                      : "rcx", "r11", "memory");
    unsigned long changed = add_seven(pid);
    unsigned long tid;
    __asm__ volatile ("syscall" : "=a"(tid) : "a"(186UL)
                      : "rcx", "r11", "memory");
    unsigned long status = changed - tid;
    __asm__ volatile ("syscall" : : "a"(231UL), "D"(status)
                      : "rcx", "r11", "memory");
    __builtin_unreachable();
}
