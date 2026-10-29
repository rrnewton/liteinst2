#ifndef LI2_RSEQ_TCGETS_BTRFS_H
#define LI2_RSEQ_TCGETS_BTRFS_H
#if LI2_RSEQ_TCGETS_BTRFS != 1 || !defined(LI2_RSEQ_NATIVE_BOUNDARY)
#error "TCGETS requires the explicit registered native-boundary capture profile"
#endif
#if defined(LI2_ONESHOT_PUBLICATION) || defined(LI2_SELECTED_PROVIDER)
#error "The capture TCGETS profile has no one-shot or provider composition"
#endif
#include <linux/stat.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#define LI2_TCGETS_MOUNT_BYTES (256UL*1024)
#define LI2_TCGETS_MOUNT_ROWS 2048U
enum li2_tcgets_phase { LI2_TCGETS_EMPTY,LI2_TCGETS_BINDING,LI2_TCGETS_IDLE,
    LI2_TCGETS_CHECKING,LI2_TCGETS_PERMITTED,LI2_TCGETS_ISSUED,
    LI2_TCGETS_RETURNED,LI2_TCGETS_COMPLETE,LI2_TCGETS_FAILED };
/* The normal parent open/dup/exec route is an explicit trusted launch
   contract. These actual identities bind that inherited FD, not arbitrary
   kernel-created/imported file_operations. No application pointer is read. */
struct li2_tcgets_identity {
    uint64_t device,inode,mount_id,major,minor;
    uint32_t mode;
    long flags;
};
struct li2_tcgets_state {
    volatile sig_atomic_t phase;
    unsigned initialized,invalidated,first_error,query_attempted,query_returned;
    unsigned mount_opened,mount_eof,mount_close_started,mount_closed,mount_complete;
    long first_detail,invalidated_number,query_number,query_result,mount_fd,mount_close_result,result;
    uint64_t attempts,permitted,issued,returned,completed,queries,mount_bytes,mount_rows,mount_matches;
    uint64_t registration_epoch,syscall_check;
    long args[6];
    struct li2_tcgets_identity launch,current;
    struct li2_rseq_data data;
    struct stat stat,proc_stat;
    struct statx statx;
    struct statfs filesystem,proc_filesystem;
    uint64_t mount_ids[LI2_TCGETS_MOUNT_ROWS];
    char mountinfo[LI2_TCGETS_MOUNT_BYTES];
#ifdef LI2_RSEQ_TIOCGWINSZ_BTRFS
    uint64_t command_completed[2]; /* exact TCGETS, exact TIOCGWINSZ */
#endif
};
const struct li2_tcgets_state *li2_rseq_tcgets_snapshot(void);
int li2_rseq_tcgets_initialize(void);
int li2_rseq_tcgets_issuing(long,const long[6]);
int li2_rseq_tcgets_result(long,const long[6],long);
#endif
