/* Pure buffer controls for the production mount parser; no procfs or targets. */
#define main original_application_main
#include "original.c"
#undef main

static void check(bool condition) { if (!condition) _exit(1); }
static bool info(const char *s, uint64_t *id) {
    return fd_mount_id((const unsigned char *)s, strlen(s), id);
}
static bool table(const char *s, uint64_t id, struct mount_identity *mount) {
    return mount_device_text((const unsigned char *)s, strlen(s), id, mount);
}
static void test_fdinfo_exact_identity_and_uint64_limit(void) {
    uint64_t id = 0;
    check(info("pos:\t0\nflags:\t02100000\nmnt_id:\t42\nino:\t901\n", &id) && id == 42);
    check(info("mnt_id:\t18446744073709551615\n", &id) && id == UINT64_MAX);
}
static void test_fdinfo_missing_duplicate_malformed_and_overflow(void) {
    static const char *bad[] = {
        "", "ino:\t42\n", "mnt_id:\t42\nmnt_id:\t42\n", "mnt_id:\t42\nmnt_id:\t43\n",
        "mnt_id: 42\n", "mnt_id:\t\n", "mnt_id:\t0\n", "mnt_id:\t042\n", "mnt_id:\t-42\n",
        "mnt_id:\t+42\n", "mnt_id:\t42 \n", "mnt_id:\t42\r\n", "mnt_id:\t42",
        "mnt_id:\t18446744073709551616\n", "mnt_id:\t42\nmalformed\n"
    };
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; ++i) { uint64_t id = 99; check(!info(bad[i], &id) && id == 99); }
    const unsigned char nul[] = "mnt_id:\t42\0\n"; uint64_t id = 99;
    check(!fd_mount_id(nul, sizeof nul - 1, &id) && id == 99);
}
static void test_mountinfo_selects_fd_id_not_path_or_file_device(void) {
    static const char rows[] =
        "7 7 8:1 / /same rw - ext4 /source rw\n"
        "42 7 0:99 / /same rw shared:1 master:2 - overlay /source rw\n";
    struct mount_identity m = {0};
    check(table(rows, 42, &m) && m.id == 42 && m.major == 0 && m.minor == 99);
    check(table(rows, 7, &m) && m.id == 7 && m.major == 8 && m.minor == 1);
    check(table("18446744073709551615 1 4294967295:4294967295 / / rw - x y z\n", UINT64_MAX, &m));
    check(m.id == UINT64_MAX && m.major == UINT32_MAX && m.minor == UINT32_MAX);
    check(table("42 7 0:99 / / rw - x - z\n", 42, &m));
}
static void test_mountinfo_duplicate_missing_malformed_and_overflow(void) {
    static const char *bad[] = {
        "", "7 7 8:1 / / rw - ext4 /source rw\n",
        "42 7 0:99 / / rw - x y z\n42 7 0:99 / / rw - x y z\n",
        "42 7 0:99 / / rw - x y z\n7 7 8:1 / / rw - x y z\n7 7 8:1 / / rw - x y z\n",
        "042 7 0:99 / / rw - x y z\n", "42 0 0:99 / / rw - x y z\n",
        "42 7 00:99 / / rw - x y z\n", "42 7 0:099 / / rw - x y z\n",
        "42 7 0:99:1 / / rw - x y z\n", "42 7 0: / / rw - x y z\n",
        "42 7 -1:99 / / rw - x y z\n", "42 7 0:+99 / / rw - x y z\n",
        "42 18446744073709551616 0:99 / / rw - x y z\n",
        "18446744073709551616 7 0:99 / / rw - x y z\n",
        "18446744073709551658 7 0:99 / / rw - x y z\n",
        "42 7 4294967296:99 / / rw - x y z\n", "42 7 0:4294967296 / / rw - x y z\n",
        "42 7 0:99 relative / rw - x y z\n", "42 7 0:99 / relative rw - x y z\n",
        "42 7 0:99 / / rw x y z\n", "42 7 0:99 / / rw - x y\n",
        "42 7 0:99 / / rw - x y z extra\n",
        "42 7 0:99 / / rw - x y z \n", "42  7 0:99 / / rw - x y z\n",
        "42\t7 0:99 / / rw - x y z\n", "42 7 0:99 / / rw - x y z",
        "42 7 0:99 / / rw - x y z\r\n", "42 7 0:99 / / rw - x y z\n\n",
        "42 7 0:99 / / rw - x y z\nmalformed\n"
    };
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; ++i) {
        struct mount_identity m = {123, 4, 5};
        check(!table(bad[i], 42, &m) && m.id == 123 && m.major == 4 && m.minor == 5);
    }
    struct mount_identity m = {123, 4, 5};
    const unsigned char nul[] = "42 7 0:99 / / rw - x y z\0\n";
    check(!mount_device_text(nul, sizeof nul - 1, 42, &m));
    check(!table("42 7 0:99 / / rw - x y z\n", 0, &m));
}
static void test_mount_parsers_exact_caps_and_excess_data(void) {
    static unsigned char bytes[MOUNTINFO_CAP + 1];
    const char *head = "mnt_id:\t42\nextra:\t"; size_t n = strlen(head); memcpy(bytes, head, n);
    memset(bytes + n, 'x', FDINFO_CAP - n - 1); bytes[FDINFO_CAP - 1] = '\n';
    uint64_t id = 0; check(fd_mount_id(bytes, FDINFO_CAP, &id) && id == 42);
    bytes[FDINFO_CAP - 1] = 'x'; bytes[FDINFO_CAP] = '\n'; check(!fd_mount_id(bytes, FDINFO_CAP + 1, &id));
    head = "42 7 0:99 / /"; const char *tail = " rw - x y z\n";
    n = strlen(head); size_t t = strlen(tail); memcpy(bytes, head, n);
    memset(bytes + n, 'x', MOUNTINFO_CAP - n - t); memcpy(bytes + MOUNTINFO_CAP - t, tail, t);
    struct mount_identity m = {0}; check(mount_device_text(bytes, MOUNTINFO_CAP, 42, &m) && m.id == 42);
    memmove(bytes + MOUNTINFO_CAP - t + 1, bytes + MOUNTINFO_CAP - t, t); bytes[MOUNTINFO_CAP - t] = 'x';
    check(!mount_device_text(bytes, MOUNTINFO_CAP + 1, 42, &m));
}
static void test_mount_identity_recheck_keeps_id_and_both_components(void) {
    const struct mount_identity m = {42, 0, 99};
    check(mount_identity_equal(m, m));
    check(!mount_identity_equal(m, (struct mount_identity){43, 0, 99}));
    check(!mount_identity_equal(m, (struct mount_identity){42, 8, 99}));
    check(!mount_identity_equal(m, (struct mount_identity){42, 0, 1}));
}
int main(void) {
    test_fdinfo_exact_identity_and_uint64_limit();
    test_fdinfo_missing_duplicate_malformed_and_overflow();
    test_mountinfo_selects_fd_id_not_path_or_file_device();
    test_mountinfo_duplicate_missing_malformed_and_overflow();
    test_mount_parsers_exact_caps_and_excess_data();
    test_mount_identity_recheck_keeps_id_and_both_components();
    static const char done[] = "ORIGINAL_MOUNT_CONTROLS_PASS controls=6\n";
    check(write(STDOUT_FILENO, done, sizeof done - 1) == (ssize_t)(sizeof done - 1));
    return 0;
}
