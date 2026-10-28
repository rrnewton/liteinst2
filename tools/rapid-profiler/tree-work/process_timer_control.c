/* Real-child timer controls and the actual C arithmetic helper. */
#ifdef NDEBUG
#error "timer controls require assertions"
#endif
#define main process_timer_main
#include "process_timer.c"
#undef main
#include <assert.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    assert(argc == 2);
    if (!strcmp(argv[1], "converters")) {
        uint64_t value = 91;
        assert(scaled(-1, 0, 1000000000, &value) == -1 && value == 91);
        assert(scaled(0, -1, 1000000000, &value) == -1);
        assert(scaled(0, 1000000000, 1000000000, &value) == -1);
        assert(scaled(INT64_MAX, 0, 1000000000, &value) == -1);
        assert(scaled(18446744073, 709551615, 1000000000, &value) == 0 && value == UINT64_MAX);
        assert(scaled(18446744073, 709551616, 1000000000, &value) == -1);
        assert(scaled(0, 0, 1000000, &value) == 0 && value == 0);
        assert(scaled(4, 999999, 1000000, &value) == 0 && value == 4999999);
        assert(scaled(0, 1000000, 1000000, &value) == -1);
        puts("converters PASS");
    } else if (!strcmp(argv[1], "zero")) {
        printf("child_pid=%jd\n", (intmax_t)getpid());
    } else if (!strcmp(argv[1], "quiet")) {
        return 0;
    } else if (!strcmp(argv[1], "nonzero")) {
        return 7;
    } else if (!strcmp(argv[1], "signal")) {
        assert(kill(getpid(), SIGTERM) == 0);
        abort();
    } else if (!strcmp(argv[1], "closed-output")) {
        close(STDOUT_FILENO); close(STDERR_FILENO);
        for (;;) pause();
    } else if (!strcmp(argv[1], "kill-timer")) {
        assert(kill(getppid(), SIGKILL) == 0);
        for (;;) pause();
    } else if (!strcmp(argv[1], "descendant")) {
        int ready[2]; assert(pipe2(ready, O_CLOEXEC) == 0);
        pid_t child = fork(); assert(child >= 0);
        if (!child) {
            close(ready[0]);
            assert(setsid() >= 0);
            assert(write_all(ready[1], "R", 1) == 0);
            close(ready[1]);
            for (;;) pause();
        }
        close(ready[1]);
        char ack = 0;
        assert(read(ready[0], &ack, 1) == 1 && ack == 'R');
        close(ready[0]);
    } else if (!strcmp(argv[1], "output")) {
        char data[4096]; memset(data, 'x', sizeof(data));
        for (;;) if (write_all(STDOUT_FILENO, data, sizeof(data))) return 3;
    } else {
        return 2;
    }
    return 0;
}
