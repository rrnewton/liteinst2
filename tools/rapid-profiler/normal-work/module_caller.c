/* Four ordinary calls in one architectural interval. All stores and the final
 * unsigned sum occur in this caller; no SDK operation wraps individual calls. */
typedef unsigned long (*normal_target)(const unsigned char *, unsigned long);
struct normal_request {
    const unsigned char *data;
    unsigned long bound;
};
__attribute__((visibility("default"), noinline))
unsigned long normal_module_caller(const normal_target targets[2],
                                  const struct normal_request requests[2],
                                  unsigned long results[4]) {
    unsigned long first = targets[0](requests[0].data, requests[0].bound);
    results[0] = first;
    unsigned long second = targets[1](requests[1].data, requests[1].bound);
    results[1] = second;
    unsigned long third = targets[0](requests[0].data, requests[0].bound);
    results[2] = third;
    unsigned long fourth = targets[1](requests[1].data, requests[1].bound);
    results[3] = fourth;
    return first + second + third + fourth;
}
