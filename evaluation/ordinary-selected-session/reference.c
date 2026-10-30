/* Separate ordinary C calls to the actual unmodified DSO; scalar reference only.
 * The owner must independently trust and retain the complete DSO/lifetime/ABI.
 * This is not the installed Rust caller's architectural-state qualification. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
typedef uint64_t (*leaf)(const unsigned char *, size_t);
static int refused(void) { fputs("SELECTED_REFERENCE_REFUSED\n", stderr); return 1; }
static leaf symbol(void *owner, const char *name) {
    void *address = dlsym(owner, name);
    leaf function = NULL;
    _Static_assert(sizeof function == sizeof address, "x86-64 POSIX function pointer");
    memcpy(&function, &address, sizeof function);
    return function;
}
__attribute__((noinline, noclone))
static uint64_t invoke(leaf function, const unsigned char *bytes, size_t length) {
    volatile uint64_t result = function(bytes, length);
    return result;
}
/* Independent bounded CSV grammar: printable bytes were checked by the reader. */
static int csv_valid(const unsigned char *bytes, size_t length) {
    enum { START, PLAIN, QUOTED, CLOSED } state = START;
    for (size_t i = 0; i < length; ++i) {
        unsigned char c = bytes[i];
        if (state == QUOTED) {
            if (c == '"') state = CLOSED;
        } else if (state == CLOSED) {
            if (c == '"') state = QUOTED;
            else if (c == ',') state = START;
            else return 0;
        } else if (c == ',') state = START;
        else if (c == '"') {
            if (state != START) return 0;
            state = QUOTED;
        } else state = PLAIN;
    }
    return state != QUOTED;
}
int main(int argc, char **argv) {
    if (argc != 3 || argv[1][0] != '/' || !argv[2][0] || argv[2][0] == '0') return refused();
    unsigned records = 0;
    for (const char *p = argv[2]; *p; ++p) {
        if (*p < '0' || *p > '9' || records > 2048) return refused();
        records = records * 10 + (unsigned)(*p - '0');
    }
    if (!records || records > 2048) return refused();
    void *owner = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!owner) return refused();
    leaf first = symbol(owner, "first_equal"), upper = symbol(owner, "uppercase_count");
    if (!first || !upper) return refused();
    for (unsigned id = 1; id <= records; ++id) {
        unsigned char bytes[64]; size_t length = 0;
        for (;;) {
            int c = getchar();
            if (c == '\n') break;
            if (c < 0x20 || c > 0x7e || length == sizeof bytes) return refused();
            bytes[length++] = (unsigned char)c;
        }
        if (!csv_valid(bytes, length)) return refused();
        uint64_t a = invoke(first, bytes, length);
        uint64_t b = invoke(upper, bytes, length);
        if (printf("ORIGINAL,%u,%" PRIu64 ",%" PRIu64 "\n", id, a, b) < 0) return refused();
    }
    if (getchar() != EOF || ferror(stdin)) return refused();
    if (printf("ORIGINAL_DONE,%u,%u\n", records, records * 2) < 0 || fflush(stdout)) return refused();
    /* Keep the normal-loader owner alive until process exit. */
    return 0;
}
