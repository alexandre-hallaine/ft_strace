#pragma once

#include "types.h"

#define X64_SYSCALLS { \
    [0] = { "read", { INT, STR, INT }, INT }, \
    [1] = { "write", { INT, STR, INT }, INT }, \
    [2] = { "open", { STR, INT, INT }, INT }, \
    [3] = { "close", { INT }, INT }, \
    [9] = { "mmap", { PTR, LONG, LONG, LONG, INT, PTR }, PTR }, \
    [10] = { "mprotect", { PTR, LONG, LONG }, INT }, \
    [11] = { "munmap", { PTR, LONG }, INT }, \
    [12] = { "brk", { PTR }, PTR }, \
    [13] = { "rt_sigaction", { INT, PTR, PTR, INT }, INT }, \
    [14] = { "rt_sigprocmask", { INT, PTR, PTR, INT }, INT }, \
    [15] = { "rt_sigreturn", { PTR }, INT }, \
    [16] = { "ioctl", { INT, INT, PTR }, INT }, \
    [17] = { "pread64", { INT, STR, INT, LONG }, INT }, \
    [18] = { "pwrite64", { INT, PTR, INT, LONG }, INT }, \
    [19] = { "readv", { INT, PTR, INT }, INT }, \
    [20] = { "writev", { INT, PTR, INT }, INT }, \
    [21] = { "access", { STR, INT }, INT }, \
    [22] = { "pipe", { PTR }, INT }, \
    [23] = { "select", { INT, PTR, PTR, PTR, PTR }, INT }, \
    [24] = { "sched_yield", { NONE }, INT }, \
    [25] = { "mremap", { PTR, LONG, LONG, LONG, PTR }, PTR }, \
    [26] = { "msync", { PTR, LONG, INT }, INT }, \
    [27] = { "mincore", { PTR, LONG, PTR }, INT }, \
    [28] = { "madvise", { PTR, LONG, INT }, INT }, \
    [29] = { "shmget", { INT, LONG, INT }, INT }, \
    [30] = { "shmat", { INT, PTR, INT }, PTR }, \
    [31] = { "shmctl", { INT, INT, PTR }, INT }, \
    [32] = { "dup", { INT }, INT }, \
    [33] = { "dup2", { INT, INT }, INT }, \
    [34] = { "pause", { NONE }, INT }, \
    [35] = { "nanosleep", { PTR, PTR }, INT }, \
    [36] = { "getitimer", { INT, PTR }, INT }, \
    [37] = { "alarm", { INT }, INT }, \
    [38] = { "setitimer", { INT, PTR, PTR }, INT }, \
    [39] = { "getpid", { NONE }, INT }, \
    [40] = { "sendfile", { INT, INT, PTR, LONG }, INT }, \
    [41] = { "socket", { INT, INT, INT }, INT }, \
    [42] = { "connect", { INT, PTR, INT }, INT }, \
    [43] = { "accept", { INT, PTR, PTR }, INT }, \
    [44] = { "sendto", { INT, PTR, INT, INT, PTR, INT }, INT }, \
    [45] = { "recvfrom", { INT, PTR, INT, INT, PTR, PTR }, INT }, \
    [46] = { "sendmsg", { INT, PTR, INT }, INT }, \
    [47] = { "recvmsg", { INT, PTR, INT }, INT }, \
    [48] = { "shutdown", { INT, INT }, INT }, \
    [49] = { "bind", { INT, PTR, INT }, INT }, \
    [50] = { "listen", { INT, INT }, INT }, \
    [51] = { "getsockname", { INT, PTR, PTR }, INT }, \
    [52] = { "getpeername", { INT, PTR, PTR }, INT }, \
    [53] = { "socketpair", { INT, INT, INT, PTR }, INT }, \
    [54] = { "setsockopt", { INT, INT, INT, PTR, INT }, INT }, \
    [55] = { "getsockopt", { INT, INT, INT, PTR, PTR }, INT }, \
    [56] = { "clone", { INT, PTR, INT, PTR, PTR, INT }, INT }, \
    [57] = { "fork", { NONE }, INT }, \
    [58] = { "vfork", { NONE }, INT }, \
    [59] = { "execve", { STR, ARRAY | STR, ARRAY | PTR }, INT }, \
    [60] = { "exit", { INT }, NONE }, \
    [61] = { "wait4", { INT, PTR, INT, PTR }, INT }, \
    [62] = { "kill", { INT, INT }, INT }, \
    [63] = { "uname", { PTR }, INT }, \
    [64] = { "semget", { INT, INT, INT }, INT }, \
    [65] = { "semop", { INT, PTR, INT }, INT }, \
    [66] = { "semctl", { INT, INT, INT, PTR }, INT }, \
    [67] = { "shmdt", { PTR }, INT }, \
    [68] = { "msgget", { INT, INT }, INT }, \
    [69] = { "msgsnd", { INT, PTR, INT, INT }, INT }, \
    [70] = { "msgrcv", { INT, PTR, INT, LONG, INT }, INT }, \
    [71] = { "msgctl", { INT, INT, PTR }, INT }, \
    [72] = { "fcntl", { INT, INT, LONG }, INT }, \
    [73] = { "flock", { INT, INT }, INT }, \
    [74] = { "fsync", { INT }, INT }, \
    [75] = { "fdatasync", { INT }, INT }, \
    [76] = { "truncate", { STR, LONG }, INT }, \
    [77] = { "ftruncate", { INT, LONG }, INT }, \
    [78] = { "getdents", { INT, PTR, INT }, INT }, \
    [79] = { "getcwd", { STR, INT }, PTR }, \
    [80] = { "chdir", { STR }, INT }, \
    [81] = { "fchdir", { INT }, INT }, \
    [82] = { "rename", { STR, STR }, INT }, \
    [83] = { "mkdir", { STR, INT }, INT }, \
    [84] = { "rmdir", { STR }, INT }, \
    [85] = { "creat", { STR, INT }, INT }, \
    [86] = { "link", { STR, STR }, INT }, \
    [87] = { "unlink", { STR }, INT }, \
    [88] = { "symlink", { STR, STR }, INT }, \
    [89] = { "readlink", { STR, STR, INT }, INT }, \
    [90] = { "chmod", { STR, INT }, INT }, \
    [91] = { "fchmod", { INT, INT }, INT }, \
    [92] = { "chown", { STR, INT, INT }, INT }, \
    [93] = { "fchown", { INT, INT, INT }, INT }, \
    [94] = { "lchown", { STR, INT, INT }, INT }, \
    [95] = { "umask", { INT }, INT }, \
    [96] = { "gettimeofday", { PTR, PTR }, INT }, \
    [97] = { "getrlimit", { INT, PTR }, INT }, \
    [98] = { "getrusage", { INT, PTR }, INT }, \
    [99] = { "sysinfo", { PTR }, INT }, \
    [100] = { "times", { PTR }, INT }, \
    [101] = { "ptrace", { INT, INT, PTR, PTR }, INT }, \
    [102] = { "getuid", { NONE }, INT }, \
    [103] = { "syslog", { INT, STR, INT }, INT }, \
    [104] = { "getgid", { NONE }, INT }, \
    [105] = { "setuid", { INT }, INT }, \
    [106] = { "setgid", { INT }, INT }, \
    [107] = { "geteuid", { NONE }, INT }, \
    [108] = { "getegid", { NONE }, INT }, \
    [109] = { "setpgid", { INT, INT }, INT }, \
    [110] = { "getppid", { NONE }, INT }, \
    [111] = { "getpgrp", { NONE }, INT }, \
    [112] = { "setsid", { NONE }, INT }, \
    [113] = { "setreuid", { INT, INT }, INT }, \
    [114] = { "setregid", { INT, INT }, INT }, \
    [115] = { "getgroups", { INT, PTR }, INT }, \
    [116] = { "setgroups", { INT, PTR }, INT }, \
    [117] = { "setresuid", { PTR, PTR, PTR }, INT }, \
    [118] = { "getresuid", { PTR, PTR, PTR }, INT }, \
    [119] = { "setresgid", { INT, INT, INT }, INT }, \
    [120] = { "getresgid", { INT, INT, INT }, INT }, \
    [121] = { "getpgid", { INT }, INT }, \
    [122] = { "setfsuid", { INT }, INT }, \
    [123] = { "setfsgid", { INT }, INT }, \
    [124] = { "getsid", { INT }, INT }, \
    [125] = { "capget", { PTR, PTR }, INT }, \
    [126] = { "capset", { PTR, PTR }, INT }, \
    [127] = { "rt_sigpending", { PTR }, INT }, \
    [128] = { "rt_sigtimedwait", { PTR, PTR, PTR, INT }, INT }, \
    [129] = { "rt_sigqueueinfo", { INT, INT, PTR }, INT }, \
    [130] = { "rt_sigsuspend", { PTR, INT }, INT }, \
    [131] = { "sigaltstack", { PTR, PTR }, INT }, \
    [132] = { "utime", { STR, PTR }, INT }, \
    [133] = { "mknod", { STR, INT, INT }, INT }, \
    [134] = { "uselib", { STR }, INT }, \
    [135] = { "personality", { INT }, INT }, \
    [136] = { "ustat", { INT, PTR }, INT }, \
    [137] = { "statfs", { STR, PTR }, INT }, \
    [138] = { "fstatfs", { INT, PTR }, INT }, \
    [139] = { "sysfs", { INT, INT, INT }, INT }, \
    [140] = { "getpriority", { INT, INT }, INT }, \
    [141] = { "setpriority", { INT, INT }, INT }, \
    [142] = { "sched_setparam", { INT, PTR }, INT }, \
    [143] = { "sched_getparam", { INT, PTR }, INT }, \
    [144] = { "sched_setscheduler", { INT, INT, PTR }, INT }, \
    [145] = { "sched_getscheduler", { INT }, INT }, \
    [146] = { "sched_get_priority_max", { INT }, INT }, \
    [147] = { "sched_get_priority_min", { INT }, INT }, \
    [148] = { "sched_rr_get_interval", { INT, PTR }, INT }, \
    [149] = { "mlock", { PTR, LONG }, INT }, \
    [150] = { "munlock", { PTR, LONG }, INT }, \
    [151] = { "mlockall", { INT }, INT }, \
    [152] = { "munlockall", { NONE }, INT }, \
    [153] = { "vhangup", { NONE }, INT }, \
    [154] = { "modify_ldt", { INT, PTR, LONG }, INT }, \
    [155] = { "pivot_root", { STR, STR }, INT }, \
    [156] = { "_sysctl", { PTR }, INT }, \
    [157] = { "prctl", { INT, LONG, LONG, LONG, LONG }, INT }, \
    [158] = { "arch_prctl", { PTR, PTR }, INT }, \
    [159] = { "adjtimex", { PTR }, INT }, \
    [160] = { "setrlimit", { INT, PTR }, INT }, \
    [161] = { "chroot", { STR }, INT }, \
    [162] = { "sync", { NONE }, NONE }, \
    [163] = { "acct", { STR }, INT }, \
    [164] = { "settimeofday", { PTR, PTR }, INT }, \
    [165] = { "mount", { STR, STR, STR, LONG, PTR }, INT }, \
    [166] = { "umount2", { STR, INT }, INT }, \
    [167] = { "swapon", { STR, INT }, INT }, \
    [168] = { "swapoff", { STR }, INT }, \
    [169] = { "reboot", { INT, INT, INT, PTR }, INT }, \
    [170] = { "sethostname", { STR, INT }, INT }, \
    [171] = { "setdomainname", { STR, INT }, INT }, \
    [172] = { "iopl", { INT }, INT }, \
    [173] = { "ioperm", { LONG, LONG, INT }, INT }, \
    [174] = { "create_module", { STR, LONG }, PTR }, \
    [175] = { "init_module", { PTR, LONG, STR }, INT }, \
    [176] = { "delete_module", { STR, INT }, INT }, \
    [177] = { "get_kernel_syms", { PTR }, INT }, \
    [178] = { "query_module", { STR, INT, PTR, LONG, LONG }, INT }, \
    [179] = { "quotactl", { INT, STR, INT, PTR }, INT }, \
    [180] = { "nfsservctl", { INT, PTR, PTR }, INT }, \
    [181] = { "getpmsg", { PTR, PTR, INT, INT }, INT }, \
    [182] = { "putpmsg", { PTR, PTR, INT, INT }, INT }, \
    [183] = { "afs_syscall", { INT, PTR, INT, PTR, INT }, INT }, \
    [184] = { "tuxcall", { NONE }, INT }, \
    [185] = { "security", { NONE }, INT }, \
    [186] = { "gettid", { NONE }, INT }, \
    [187] = { "readahead", { INT, LONG, LONG }, INT }, \
    [188] = { "setxattr", { STR, STR, PTR, LONG, INT }, INT }, \
    [189] = { "lsetxattr", { STR, STR, PTR, LONG, INT }, INT }, \
    [190] = { "fsetxattr", { INT, STR, PTR, LONG, INT }, INT }, \
    [191] = { "getxattr", { STR, STR, PTR, LONG }, INT }, \
    [192] = { "lgetxattr", { STR, STR, PTR, LONG }, INT }, \
    [193] = { "fgetxattr", { INT, STR, PTR, LONG }, INT }, \
    [194] = { "listxattr", { STR, STR, LONG }, INT }, \
    [195] = { "llistxattr", { STR, STR, LONG }, INT }, \
    [196] = { "flistxattr", { INT, STR, LONG }, INT }, \
    [197] = { "removexattr", { STR, STR }, INT }, \
    [198] = { "lremovexattr", { STR, STR }, INT }, \
    [199] = { "fremovexattr", { INT, STR }, INT }, \
    [200] = { "tkill", { INT, INT }, INT }, \
    [201] = { "time", { PTR }, LONG }, \
    [202] = { "futex", { PTR, INT, INT, PTR, PTR, INT }, INT }, \
    [203] = { "sched_setaffinity", { INT, LONG, PTR }, INT }, \
    [204] = { "sched_getaffinity", { INT, LONG, PTR }, INT }, \
    [205] = { "set_thread_area", { PTR }, INT }, \
    [206] = { "io_setup", { INT, PTR }, INT }, \
    [207] = { "io_destroy", { INT }, INT }, \
    [208] = { "io_getevents", { INT, INT, INT, PTR, PTR }, INT }, \
    [209] = { "io_submit", { INT, INT, PTR }, INT }, \
    [210] = { "io_cancel", { INT, PTR, PTR }, INT }, \
    [211] = { "get_thread_area", { PTR }, INT }, \
    [212] = { "lookup_dcookie", { LONG, STR, INT }, INT }, \
    [213] = { "epoll_create", { INT }, INT }, \
    [214] = { "epoll_ctl_old", { INT, INT, INT, PTR }, INT }, \
    [215] = { "epoll_wait_old", { INT, PTR, INT, INT }, INT }, \
    [216] = { "remap_file_pages", { PTR, LONG, INT, LONG, INT }, INT }, \
    [217] = { "getdents64", { INT, PTR, INT }, INT }, \
    [218] = { "set_tid_address", { PTR }, LONG }, \
    [219] = { "restart_syscall", { NONE }, INT }, \
    [220] = { "semtimedop", { INT, PTR, INT, PTR }, INT }, \
    [221] = { "fadvise64", { INT, LONG, LONG, INT }, INT }, \
    [222] = { "timer_create", { INT, PTR, PTR }, INT }, \
    [223] = { "timer_settime", { INT, INT, PTR, PTR }, INT }, \
    [224] = { "timer_gettime", { INT, PTR }, INT }, \
    [225] = { "timer_getoverrun", { INT }, INT }, \
    [226] = { "timer_delete", { INT }, INT }, \
    [227] = { "clock_settime", { INT, PTR }, INT }, \
    [228] = { "clock_gettime", { INT, PTR }, INT }, \
    [229] = { "clock_getres", { INT, PTR }, INT }, \
    [230] = { "clock_nanosleep", { INT, INT, PTR, PTR }, INT }, \
    [231] = { "exit_group", { INT }, NONE }, \
    [232] = { "epoll_wait", { INT, PTR, INT, INT }, INT }, \
    [233] = { "epoll_ctl", { INT, INT, INT, PTR }, INT }, \
    [234] = { "tgkill", { INT, INT, INT }, INT }, \
    [235] = { "utimes", { STR, PTR }, INT }, \
    [236] = { "vserver", { NONE }, INT }, \
    [237] = { "mbind", { PTR, LONG, INT, PTR, LONG, LONG }, INT }, \
    [238] = { "set_mempolicy", { INT, PTR, LONG }, INT }, \
    [239] = { "get_mempolicy", { PTR, PTR, LONG, LONG, LONG }, INT }, \
    [240] = { "mq_open", { STR, INT, INT, PTR }, INT }, \
    [241] = { "mq_unlink", { STR }, INT }, \
    [242] = { "mq_timedsend", { INT, STR, LONG, INT, PTR }, INT }, \
    [243] = { "mq_timedreceive", { INT, STR, LONG, INT, PTR }, INT }, \
    [244] = { "mq_notify", { INT, PTR }, INT }, \
    [245] = { "mq_getsetattr", { INT, PTR, PTR }, INT }, \
    [246] = { "kexec_load", { LONG, LONG, PTR, LONG }, INT }, \
    [247] = { "waitid", { INT, INT, PTR, INT, PTR }, INT }, \
    [248] = { "add_key", { STR, STR, PTR, LONG, INT }, INT }, \
    [249] = { "request_key", { STR, STR, STR, INT }, INT }, \
    [250] = { "keyctl", { INT, INT, INT, INT, INT }, INT }, \
    [251] = { "ioprio_set", { INT, INT, INT }, INT }, \
    [252] = { "ioprio_get", { INT, INT }, INT }, \
    [253] = { "inotify_init", { NONE }, INT }, \
    [254] = { "inotify_add_watch", { INT, STR, INT }, INT }, \
    [255] = { "inotify_rm_watch", { INT, INT }, INT }, \
    [256] = { "migrate_pages", { INT, LONG, PTR, PTR }, INT }, \
    [257] = { "openat", { INT, STR, INT, INT }, INT }, \
    [258] = { "mkdirat", { INT, STR, INT }, INT }, \
    [259] = { "mknodat", { INT, STR, INT, INT }, INT }, \
    [260] = { "fchownat", { INT, STR, INT, INT, INT }, INT }, \
    [261] = { "futimesat", { INT, STR, PTR }, INT }, \
    [262] = { "newfstatat", { INT, STR, PTR, INT }, INT }, \
    [263] = { "unlinkat", { INT, STR, INT }, INT }, \
    [264] = { "renameat", { INT, STR, INT, STR }, INT }, \
    [265] = { "linkat", { INT, STR, INT, STR, INT }, INT }, \
    [266] = { "symlinkat", { STR, INT, STR }, INT }, \
    [267] = { "readlinkat", { INT, STR, STR, INT }, INT }, \
    [268] = { "fchmodat", { INT, STR, INT }, INT }, \
    [269] = { "faccessat", { INT, STR, INT }, INT }, \
    [270] = { "pselect6", { INT, PTR, PTR, PTR, PTR, PTR }, INT }, \
    [271] = { "ppoll", { PTR, INT, PTR, PTR }, INT }, \
    [272] = { "unshare", { INT }, INT }, \
    [273] = { "set_robust_list", { PTR, LONG }, INT }, \
    [274] = { "get_robust_list", { INT, PTR, PTR }, INT }, \
    [275] = { "splice", { INT, PTR, INT, PTR, INT, INT }, INT }, \
    [276] = { "tee", { INT, INT, INT, INT }, INT }, \
    [277] = { "sync_file_range", { INT, LONG, LONG, INT }, INT }, \
    [278] = { "vmsplice", { INT, PTR, INT, INT }, INT }, \
    [279] = { "move_pages", { INT, LONG, PTR, PTR, PTR, INT }, INT }, \
    [280] = { "utimensat", { INT, STR, PTR, INT }, INT }, \
    [281] = { "epoll_pwait", { INT, PTR, INT, INT, PTR }, INT }, \
    [282] = { "signalfd", { INT, PTR, INT }, INT }, \
    [283] = { "timerfd_create", { INT, INT }, INT }, \
    [284] = { "eventfd", { INT }, INT }, \
    [285] = { "fallocate", { INT, INT, LONG, LONG }, INT }, \
    [286] = { "timerfd_settime", { INT, INT, PTR }, INT }, \
    [287] = { "timerfd_gettime", { INT, PTR }, INT }, \
    [288] = { "accept4", { INT, PTR, PTR, INT }, INT }, \
    [289] = { "signalfd4", { INT, PTR, INT }, INT }, \
    [290] = { "eventfd2", { INT, INT }, INT }, \
    [291] = { "epoll_create1", { INT }, INT }, \
    [292] = { "dup3", { INT, INT, INT }, INT }, \
    [293] = { "pipe2", { PTR, INT }, INT }, \
    [294] = { "inotify_init1", { INT }, INT }, \
    [295] = { "preadv", { INT, PTR, INT, LONG, LONG }, INT }, \
    [296] = { "pwritev", { INT, PTR, INT, LONG, LONG }, INT }, \
    [297] = { "rt_tgsigqueueinfo", { INT, INT, INT, PTR }, INT }, \
    [298] = { "perf_event_open", { PTR, INT, INT, INT, LONG, INT }, INT }, \
    [299] = { "recvmmsg", { INT, PTR, INT, INT, PTR }, INT }, \
    [300] = { "fanotify_init", { INT, INT }, INT }, \
    [301] = { "fanotify_mark", { INT, INT, LONG, INT, STR }, INT }, \
    [302] = { "prlimit64", { INT, INT, PTR, PTR }, INT }, \
    [303] = { "name_to_handle_at", { INT, STR, PTR, PTR, INT }, INT }, \
    [304] = { "open_by_handle_at", { INT, PTR, INT }, INT }, \
    [305] = { "clock_adjtime", { INT, PTR }, INT }, \
    [306] = { "syncfs", { INT }, INT }, \
    [307] = { "sendmmsg", { INT, PTR, INT, INT }, INT }, \
    [308] = { "setns", { INT, INT }, INT }, \
    [309] = { "getcpu", { PTR, PTR, PTR }, INT }, \
    [310] = { "process_vm_readv", { INT, PTR, INT, PTR, INT, INT }, LONG }, \
    [311] = { "process_vm_writev", { INT, PTR, INT, PTR, INT, INT }, LONG }, \
    [312] = { "kcmp", { INT, INT, INT, LONG, LONG }, INT }, \
    [313] = { "finit_module", { INT, STR, INT }, INT }, \
    [314] = { "sched_setattr", { INT, PTR, INT }, INT }, \
    [315] = { "sched_getattr", { INT, PTR, INT, INT }, INT }, \
    [316] = { "renameat2", { INT, STR, INT, STR, INT }, INT }, \
    [317] = { "seccomp", { INT, INT, STR }, INT }, \
    [318] = { "getrandom", { STR, LONG, INT }, INT }, \
    [319] = { "memfd_create", { STR, INT }, INT }, \
    [320] = { "kexec_file_load", { INT, INT, INT, STR, INT }, INT }, \
    [321] = { "bpf", { INT, PTR, INT }, INT }, \
    [322] = { "execveat", { INT, STR, ARRAY | STR, ARRAY | PTR, INT }, INT }, \
    [323] = { "userfaultfd", { INT }, INT }, \
    [324] = { "membarrier", { INT, INT }, INT }, \
    [325] = { "mlock2", { PTR, LONG, INT }, INT }, \
    [326] = { "copy_file_range", { INT, PTR, INT, PTR, INT, INT }, LONG }, \
    [327] = { "preadv2", { INT, PTR, INT, PTR, INT, INT }, INT }, \
    [328] = { "pwritev2", { INT, PTR, INT, PTR, INT, INT }, INT }, \
    [329] = { "pkey_mprotect", { PTR, LONG, INT, INT }, INT }, \
    [330] = { "pkey_alloc", { LONG, LONG }, INT }, \
    [331] = { "pkey_free", { INT }, INT }, \
    [332] = { "statx", { INT, STR, INT, INT, INT, PTR }, INT }, \
    [333] = { "io_pgetevents", { INT, INT, INT, PTR, PTR, INT }, INT }, \
    [334] = { "rseq", { PTR, INT }, INT }, \
}
