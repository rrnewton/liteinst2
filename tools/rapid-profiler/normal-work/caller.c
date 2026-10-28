/* Ordinary application callsites. No profiler ABI, TLS, assembly or SDK call. */
typedef unsigned long (*normal_target)(const unsigned char *, unsigned long);

struct normal_request {
    const unsigned char *data;
    unsigned long bound;
};

_Static_assert(sizeof(unsigned long) == 8, "LP64 caller");
_Static_assert(sizeof(void *) == 8, "64-bit caller");
_Static_assert(sizeof(struct normal_request) == 16, "request ABI");

__attribute__((visibility("default"), noinline))
unsigned long normal_caller(normal_target target,
                            const struct normal_request requests[2],
                            unsigned long results[2]) {
    unsigned long first = target(requests[0].data, requests[0].bound);
    results[0] = first;
    unsigned long second = target(requests[1].data, requests[1].bound);
    results[1] = second;
    return first + second;
}
