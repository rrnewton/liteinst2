/* Shared exact Linux/x86-64 full signal-frame shape. */
#ifndef LI2_NATIVE_PROBE_FRAME_H
#define LI2_NATIVE_PROBE_FRAME_H
struct frame {
    uint64_t h[16];
    int64_t greg[23];
    unsigned char mask[128],info[128],context[968],fp[FP_BYTES];
};
#endif
