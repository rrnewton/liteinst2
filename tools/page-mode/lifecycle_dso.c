/* A real ELF DSO, with no extra dependencies or writable globals. */
__attribute__((visibility("default")))
int lifecycle_value(int input) { return input * 3 + 7; }
