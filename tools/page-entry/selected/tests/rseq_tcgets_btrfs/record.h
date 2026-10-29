#ifndef LI2_RSEQ_TCGETS_FIXTURE_RECORD_H
#define LI2_RSEQ_TCGETS_FIXTURE_RECORD_H
#include "../rseq_native/record.h"
#include <linux/btrfs.h>
#include <linux/stat.h>
#include <sys/stat.h>
#include <sys/vfs.h>
/* Kept in each actual ELF solely for file-only DWARF/UAPI inspection. */
struct rtc_query_layout {
 struct stat stat;
 struct statx statx;
 struct statfs statfs;
 struct btrfs_ioctl_get_subvol_info_args subvolume;
};
static struct rtc_query_layout rtc_query_layout __attribute__((used));
const unsigned long rtc_subvol_command __attribute__((used,visibility("hidden")))=BTRFS_IOC_GET_SUBVOL_INFO;
#define RTC_MAGIC UINT64_C(0x3153544547435452)
#define RTC_ROWS 2U
#define RTC_PRIVATE_BYTES (16U*4096U)
struct rtc_native_row {
 uint64_t h[32];
 struct rn_frame before,after;
 unsigned char siginfo_before[128],siginfo_after[128];
 unsigned char private_before[RTC_PRIVATE_BYTES],private_after[RTC_PRIVATE_BYTES];
};
struct rtc_native_record {
 uint64_t h[64],xstate[4][4],startup[256];
 struct rtc_native_row rows[RTC_ROWS];
};
#endif
