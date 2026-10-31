#ifndef LI2_CAPTURE_RLE_H
#define LI2_CAPTURE_RLE_H
#include <stddef.h>
#include <stdint.h>

#define LI2_CAPTURE_RLE_LIMIT (4U*1024U*1024U)
#define LI2_CAPTURE_RLE_HEADER 64U
#define LI2_CAPTURE_RLE_FOOTER 64U
#define LI2_CAPTURE_RLE_MAGIC UINT64_C(0x314838454c52324c)
#define LI2_CAPTURE_RLE_END UINT64_C(0x314638454c52324c)
#define LI2_CAPTURE_RLE_VERSION UINT64_C(1)
#define LI2_CAPTURE_RLE_LITERAL 65536U
#define LI2_CAPTURE_RLE_RUN 8U

enum li2_capture_rle_result {
    LI2_CAPTURE_RLE_OK=0, LI2_CAPTURE_RLE_ARGUMENT=1, LI2_CAPTURE_RLE_CAPACITY=2,
    LI2_CAPTURE_RLE_CHANGED=3, LI2_CAPTURE_RLE_WRITE=4
};
typedef long (*li2_capture_rle_write_fn)(void *,const void *,size_t);

/* Caller owns a complete immutable raw snapshot and disjoint protected output.
   The exact raw extent/schema comes from the independently checked C layout.
   Capture callbacks must fail terminally before any store while frozen/busy.
   This codec does not establish those owner/lifetime/permission premises. */
int li2_capture_rle_prepare(const void *raw,size_t raw_bytes,uint64_t schema_version,
    void *body,size_t capacity,size_t *body_bytes);

/* Body includes the 64-byte header. The footer records ONLY actual body writes;
   its own complete arrival is checked by exact stream length. Caller performs
   the original sink identity/flags/empty-size checks before this operation.
   Both write loops retain the original maximum of 64 calls; no retry on error. */
int li2_capture_rle_write(const void *body,size_t body_bytes,size_t raw_bytes,
    uint64_t schema_version,uint64_t status,uint64_t code,
    li2_capture_rle_write_fn write_fn,void *context);
#endif
