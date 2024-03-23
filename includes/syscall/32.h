#pragma once
#include "types.h"

#define SYSCALL_TABLE_32 { \
/*        long restart_syscall(void); */ \
[0] = { "restart_syscall", { UNKNOWN }, UNKNOWN }, \
/*        void _exit(int status); */ \
[1] = { "exit", { UNKNOWN }, UNKNOWN }, \
/*        pid_t fork(void); */ \
[2] = { "fork", { UNKNOWN }, UNKNOWN }, \
/*        ssize_t read(int fd, void *buf, size_t count); */ \
[3] = { "read", { UNKNOWN }, UNKNOWN }, \
/*        ssize_t write(int fd, const void *buf, size_t count); */ \
[4] = { "write", { UNKNOWN }, UNKNOWN }, \
/*        int open(const char *pathname, int flags);
       int open(const char *pathname, int flags, mode_t mode);
       int openat(int dirfd, const char *pathname, int flags);
       int openat(int dirfd, const char *pathname, int flags, mode_t mode); */ \
[5] = { "open", { UNKNOWN }, UNKNOWN }, \
/*        int close(int fd); */ \
[6] = { "close", { UNKNOWN }, UNKNOWN }, \
/*        pid_t waitpid(pid_t pid, int *wstatus, int options); */ \
[7] = { "waitpid", { UNKNOWN }, UNKNOWN }, \
/*        int creat(const char *pathname, mode_t mode); */ \
[8] = { "creat", { UNKNOWN }, UNKNOWN }, \
/*        int link(const char *oldpath, const char *newpath); */ \
[9] = { "link", { UNKNOWN }, UNKNOWN }, \
/*        int unlink(const char *pathname);
       int unlinkat(int dirfd, const char *pathname, int flags); */ \
[10] = { "unlink", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[11] = { "execve", { UNKNOWN }, UNKNOWN }, \
/*        int chdir(const char *path);
       int fchdir(int fd); */ \
[12] = { "chdir", { UNKNOWN }, UNKNOWN }, \
/*        time_t time(time_t *tloc); */ \
[13] = { "time", { UNKNOWN }, UNKNOWN }, \
/*        int mknod(const char *pathname, mode_t mode, dev_t dev);
       int mknodat(int dirfd, const char *pathname, mode_t mode, dev_t dev); */ \
[14] = { "mknod", { UNKNOWN }, UNKNOWN }, \
/*        int chmod(const char *pathname, mode_t mode);
       int fchmod(int fd, mode_t mode);
       int fchmodat(int dirfd, const char *pathname, mode_t mode, int flags); */ \
[15] = { "chmod", { UNKNOWN }, UNKNOWN }, \
/*        int lchown(const char *pathname, uid_t owner, gid_t group); */ \
[16] = { "lchown", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[17] = { "break", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[18] = { "oldstat", { UNKNOWN }, UNKNOWN }, \
/*        off_t lseek(int fd, off_t offset, int whence); */ \
[19] = { "lseek", { UNKNOWN }, UNKNOWN }, \
/*        pid_t getpid(void); */ \
[20] = { "getpid", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[21] = { "mount", { UNKNOWN }, UNKNOWN }, \
/*        int umount(const char *target); */ \
[22] = { "umount", { UNKNOWN }, UNKNOWN }, \
/*        int setuid(uid_t uid); */ \
[23] = { "setuid", { UNKNOWN }, UNKNOWN }, \
/*        uid_t getuid(void); */ \
[24] = { "getuid", { UNKNOWN }, UNKNOWN }, \
/*        int stime(const time_t *t); */ \
[25] = { "stime", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[26] = { "ptrace", { UNKNOWN }, UNKNOWN }, \
/*        unsigned int alarm(unsigned int seconds); */ \
[27] = { "alarm", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[28] = { "oldfstat", { UNKNOWN }, UNKNOWN }, \
/*        int pause(void); */ \
[29] = { "pause", { UNKNOWN }, UNKNOWN }, \
/*        int utime(const char *filename, const struct utimbuf *times);
       int utimes(const char *filename, const struct timeval times[2]); */ \
[30] = { "utime", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[31] = { "stty", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[32] = { "gtty", { UNKNOWN }, UNKNOWN }, \
/*        int access(const char *pathname, int mode);
       int faccessat(int dirfd, const char *pathname, int mode, int flags); */ \
[33] = { "access", { UNKNOWN }, UNKNOWN }, \
/*        int nice(int inc); */ \
[34] = { "nice", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[35] = { "ftime", { UNKNOWN }, UNKNOWN }, \
/*        void sync(void);
       int syncfs(int fd); */ \
[36] = { "sync", { UNKNOWN }, UNKNOWN }, \
/*        int kill(pid_t pid, int sig); */ \
[37] = { "kill", { UNKNOWN }, UNKNOWN }, \
/*        int rename(const char *oldpath, const char *newpath); */ \
[38] = { "rename", { UNKNOWN }, UNKNOWN }, \
/*        int mkdir(const char *pathname, mode_t mode);
       int mkdirat(int dirfd, const char *pathname, mode_t mode); */ \
[39] = { "mkdir", { UNKNOWN }, UNKNOWN }, \
/*        int rmdir(const char *pathname); */ \
[40] = { "rmdir", { UNKNOWN }, UNKNOWN }, \
/*        int dup(int oldfd); */ \
[41] = { "dup", { UNKNOWN }, UNKNOWN }, \
/*        struct fd_pair pipe();
       int pipe(int pipefd[2]); */ \
[42] = { "pipe", { UNKNOWN }, UNKNOWN }, \
/*        clock_t times(struct tms *buf); */ \
[43] = { "times", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[44] = { "prof", { UNKNOWN }, UNKNOWN }, \
/*        int brk(void *addr);
       void *sbrk(intptr_t increment); */ \
[45] = { "brk", { UNKNOWN }, UNKNOWN }, \
/*        int setgid(gid_t gid); */ \
[46] = { "setgid", { UNKNOWN }, UNKNOWN }, \
/*        gid_t getgid(void); */ \
[47] = { "getgid", { UNKNOWN }, UNKNOWN }, \
/*        sighandler_t signal(int signum, sighandler_t handler); */ \
[48] = { "signal", { UNKNOWN }, UNKNOWN }, \
/*        uid_t geteuid(void); */ \
[49] = { "geteuid", { UNKNOWN }, UNKNOWN }, \
/*        gid_t getegid(void); */ \
[50] = { "getegid", { UNKNOWN }, UNKNOWN }, \
/*        int acct(const char *filename); */ \
[51] = { "acct", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[52] = { "umount2", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[53] = { "lock", { UNKNOWN }, UNKNOWN }, \
/*        int ioctl(int fd, unsigned long request, ...); */ \
[54] = { "ioctl", { UNKNOWN }, UNKNOWN }, \
/*        int fcntl(int fd, int cmd, ...  ); */ \
[55] = { "fcntl", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[56] = { "mpx", { UNKNOWN }, UNKNOWN }, \
/*        int setpgid(pid_t pid, pid_t pgid); */ \
[57] = { "setpgid", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[58] = { "ulimit", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[59] = { "oldolduname", { UNKNOWN }, UNKNOWN }, \
/*        mode_t umask(mode_t mask); */ \
[60] = { "umask", { UNKNOWN }, UNKNOWN }, \
/*        int chroot(const char *path); */ \
[61] = { "chroot", { UNKNOWN }, UNKNOWN }, \
/*        int ustat(dev_t dev, struct ustat *ubuf); */ \
[62] = { "ustat", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[63] = { "dup2", { UNKNOWN }, UNKNOWN }, \
/*        pid_t getppid(void); */ \
[64] = { "getppid", { UNKNOWN }, UNKNOWN }, \
/*        pid_t getpgrp(void);                 
       pid_t getpgrp(pid_t pid);             */ \
[65] = { "getpgrp", { UNKNOWN }, UNKNOWN }, \
/*        pid_t setsid(void); */ \
[66] = { "setsid", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[67] = { "sigaction", { UNKNOWN }, UNKNOWN }, \
/*        long sgetmask(void); */ \
[68] = { "sgetmask", { UNKNOWN }, UNKNOWN }, \
/*        long ssetmask(long newmask); */ \
[69] = { "ssetmask", { UNKNOWN }, UNKNOWN }, \
/*        int setreuid(uid_t ruid, uid_t euid); */ \
[70] = { "setreuid", { UNKNOWN }, UNKNOWN }, \
/*        int setregid(gid_t rgid, gid_t egid); */ \
[71] = { "setregid", { UNKNOWN }, UNKNOWN }, \
/*        int sigsuspend(const sigset_t *mask); */ \
[72] = { "sigsuspend", { UNKNOWN }, UNKNOWN }, \
/*        int sigpending(sigset_t *set); */ \
[73] = { "sigpending", { UNKNOWN }, UNKNOWN }, \
/*        int sethostname(const char *name, size_t len); */ \
[74] = { "sethostname", { UNKNOWN }, UNKNOWN }, \
/*        int setrlimit(int resource, const struct rlimit *rlim); */ \
[75] = { "setrlimit", { UNKNOWN }, UNKNOWN }, \
/*        int getrlimit(int resource, struct rlimit *rlim); */ \
[76] = { "getrlimit", { UNKNOWN }, UNKNOWN }, \
/*        int getrusage(int who, struct rusage *usage); */ \
[77] = { "getrusage", { UNKNOWN }, UNKNOWN }, \
/*        int gettimeofday(struct timeval *tv, struct timezone *tz); */ \
[78] = { "gettimeofday", { UNKNOWN }, UNKNOWN }, \
/*        int settimeofday(const struct timeval *tv, const struct timezone *tz); */ \
[79] = { "settimeofday", { UNKNOWN }, UNKNOWN }, \
/*        int getgroups(int size, gid_t list[]); */ \
[80] = { "getgroups", { UNKNOWN }, UNKNOWN }, \
/*        int setgroups(size_t size, const gid_t *list); */ \
[81] = { "setgroups", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[82] = { "select", { UNKNOWN }, UNKNOWN }, \
/*        int symlink(const char *target, const char *linkpath);
       int symlinkat(const char *target, int newdirfd, const char *linkpath); */ \
[83] = { "symlink", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[84] = { "oldlstat", { UNKNOWN }, UNKNOWN }, \
/*        ssize_t readlink(const char *pathname, char *buf, size_t bufsiz); */ \
[85] = { "readlink", { UNKNOWN }, UNKNOWN }, \
/*        int uselib(const char *library); */ \
[86] = { "uselib", { UNKNOWN }, UNKNOWN }, \
/*        int swapon(const char *path, int swapflags); */ \
[87] = { "swapon", { UNKNOWN }, UNKNOWN }, \
/*        int reboot(int magic, int magic2, int cmd, void *arg);
       int reboot(int cmd); */ \
[88] = { "reboot", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[89] = { "readdir", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[90] = { "mmap", { UNKNOWN }, UNKNOWN }, \
/*        int munmap(void *addr, size_t length); */ \
[91] = { "munmap", { UNKNOWN }, UNKNOWN }, \
/*        int truncate(const char *path, off_t length);
       int ftruncate(int fd, off_t length); */ \
[92] = { "truncate", { UNKNOWN }, UNKNOWN }, \
/*        int ftruncate(int fd, off_t length); */ \
[93] = { "ftruncate", { UNKNOWN }, UNKNOWN }, \
/*        int fchmod(int fd, mode_t mode);
       int fchmodat(int dirfd, const char *pathname, mode_t mode, int flags); */ \
[94] = { "fchmod", { UNKNOWN }, UNKNOWN }, \
/*        int fchown(int fd, uid_t owner, gid_t group); */ \
[95] = { "fchown", { UNKNOWN }, UNKNOWN }, \
/*        int getpriority(int which, id_t who); */ \
[96] = { "getpriority", { UNKNOWN }, UNKNOWN }, \
/*        int setpriority(int which, id_t who, int prio); */ \
[97] = { "setpriority", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[98] = { "profil", { UNKNOWN }, UNKNOWN }, \
/*        int statfs(const char *path, struct statfs *buf);
       int fstatfs(int fd, struct statfs *buf); */ \
[99] = { "statfs", { UNKNOWN }, UNKNOWN }, \
/*        int fstatfs(int fd, struct statfs *buf); */ \
[100] = { "fstatfs", { UNKNOWN }, UNKNOWN }, \
/*        int ioperm(unsigned long from, unsigned long num, int turn_on); */ \
[101] = { "ioperm", { UNKNOWN }, UNKNOWN }, \
/*        int socketcall(int call, unsigned long *args); */ \
[102] = { "socketcall", { UNKNOWN }, UNKNOWN }, \
/*        int syslog(int type, char *bufp, int len); */ \
[103] = { "syslog", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[104] = { "setitimer", { UNKNOWN }, UNKNOWN }, \
/*        int getitimer(int which, struct itimerval *curr_value); */ \
[105] = { "getitimer", { UNKNOWN }, UNKNOWN }, \
/*        int stat(const char *pathname, struct stat *statbuf);
       int fstat(int fd, struct stat *statbuf);
       int lstat(const char *pathname, struct stat *statbuf); */ \
[106] = { "stat", { UNKNOWN }, UNKNOWN }, \
/*        int lstat(const char *pathname, struct stat *statbuf); */ \
[107] = { "lstat", { UNKNOWN }, UNKNOWN }, \
/*        int fstat(int fd, struct stat *statbuf); */ \
[108] = { "fstat", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[109] = { "olduname", { UNKNOWN }, UNKNOWN }, \
/*        int iopl(int level); */ \
[110] = { "iopl", { UNKNOWN }, UNKNOWN }, \
/*        int vhangup(void); */ \
[111] = { "vhangup", { UNKNOWN }, UNKNOWN }, \
/*        int idle(void); */ \
[112] = { "idle", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[113] = { "vm86old", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[114] = { "wait4", { UNKNOWN }, UNKNOWN }, \
/*        int swapoff(const char *path); */ \
[115] = { "swapoff", { UNKNOWN }, UNKNOWN }, \
/*        int sysinfo(struct sysinfo *info); */ \
[116] = { "sysinfo", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[117] = { "ipc", { UNKNOWN }, UNKNOWN }, \
/*        int fsync(int fd); */ \
[118] = { "fsync", { UNKNOWN }, UNKNOWN }, \
/*        int sigreturn(...); */ \
[119] = { "sigreturn", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[120] = { "clone", { UNKNOWN }, UNKNOWN }, \
/*        int setdomainname(const char *name, size_t len); */ \
[121] = { "setdomainname", { UNKNOWN }, UNKNOWN }, \
/*        int uname(struct utsname *buf); */ \
[122] = { "uname", { UNKNOWN }, UNKNOWN }, \
/*        int modify_ldt(int func, void *ptr, unsigned long bytecount); */ \
[123] = { "modify_ldt", { UNKNOWN }, UNKNOWN }, \
/*        int adjtimex(struct timex *buf); */ \
[124] = { "adjtimex", { UNKNOWN }, UNKNOWN }, \
/*        int mprotect(void *addr, size_t len, int prot);
       int pkey_mprotect(void *addr, size_t len, int prot, int pkey); */ \
[125] = { "mprotect", { UNKNOWN }, UNKNOWN }, \
/*        int sigprocmask(int how, const sigset_t *set, sigset_t *oldset); */ \
[126] = { "sigprocmask", { UNKNOWN }, UNKNOWN }, \
/*        caddr_t create_module(const char *name, size_t size); */ \
[127] = { "create_module", { UNKNOWN }, UNKNOWN }, \
/*        Note: glibc provides no header file declaration of init_module() and no wrapper function for finit_module(); see NOTES. */ \
[128] = { "init_module", { UNKNOWN }, UNKNOWN }, \
/*        int delete_module(const char *name, int flags); */ \
[129] = { "delete_module", { UNKNOWN }, UNKNOWN }, \
/*        int get_kernel_syms(struct kernel_sym *table); */ \
[130] = { "get_kernel_syms", { UNKNOWN }, UNKNOWN }, \
/*        int quotactl(int cmd, const char *special, int id, caddr_t addr); */ \
[131] = { "quotactl", { UNKNOWN }, UNKNOWN }, \
/*        pid_t getpgid(pid_t pid); */ \
[132] = { "getpgid", { UNKNOWN }, UNKNOWN }, \
/*        int fchdir(int fd); */ \
[133] = { "fchdir", { UNKNOWN }, UNKNOWN }, \
/*        int bdflush(int func, long *address);
       int bdflush(int func, long data); */ \
[134] = { "bdflush", { UNKNOWN }, UNKNOWN }, \
/*        int sysfs(int option, const char *fsname);
       int sysfs(int option, unsigned int fs_index, char *buf);
       int sysfs(int option); */ \
[135] = { "sysfs", { UNKNOWN }, UNKNOWN }, \
/*        int personality(unsigned long persona); */ \
[136] = { "personality", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[137] = { "afs_syscall", { UNKNOWN }, UNKNOWN }, \
/*        int setfsuid(uid_t fsuid); */ \
[138] = { "setfsuid", { UNKNOWN }, UNKNOWN }, \
/*        int setfsgid(uid_t fsgid); */ \
[139] = { "setfsgid", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[140] = { "_llseek", { UNKNOWN }, UNKNOWN }, \
/*        Note: There is no glibc wrapper for getdents(); see NOTES. */ \
[141] = { "getdents", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[142] = { "_newselect", { UNKNOWN }, UNKNOWN }, \
/*        int flock(int fd, int operation); */ \
[143] = { "flock", { UNKNOWN }, UNKNOWN }, \
/*        int msync(void *addr, size_t length, int flags); */ \
[144] = { "msync", { UNKNOWN }, UNKNOWN }, \
/*        ssize_t readv(int fd, const struct iovec *iov, int iovcnt); */ \
[145] = { "readv", { UNKNOWN }, UNKNOWN }, \
/*        ssize_t writev(int fd, const struct iovec *iov, int iovcnt); */ \
[146] = { "writev", { UNKNOWN }, UNKNOWN }, \
/*        pid_t getsid(pid_t pid); */ \
[147] = { "getsid", { UNKNOWN }, UNKNOWN }, \
/*        int fdatasync(int fd); */ \
[148] = { "fdatasync", { UNKNOWN }, UNKNOWN }, \
/*        int _sysctl(struct __sysctl_args *args); */ \
[149] = { "_sysctl", { UNKNOWN }, UNKNOWN }, \
/*        int mlock(const void *addr, size_t len);
       int mlockall(int flags); */ \
[150] = { "mlock", { UNKNOWN }, UNKNOWN }, \
/*        int munlock(const void *addr, size_t len);
       int munlockall(void); */ \
[151] = { "munlock", { UNKNOWN }, UNKNOWN }, \
/*        int mlockall(int flags); */ \
[152] = { "mlockall", { UNKNOWN }, UNKNOWN }, \
/*        int munlockall(void); */ \
[153] = { "munlockall", { UNKNOWN }, UNKNOWN }, \
/*        int sched_setparam(pid_t pid, const struct sched_param *param); */ \
[154] = { "sched_setparam", { UNKNOWN }, UNKNOWN }, \
/*        int sched_getparam(pid_t pid, struct sched_param *param); */ \
[155] = { "sched_getparam", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[156] = { "sched_setscheduler", { UNKNOWN }, UNKNOWN }, \
/*        int sched_getscheduler(pid_t pid); */ \
[157] = { "sched_getscheduler", { UNKNOWN }, UNKNOWN }, \
/*        int sched_yield(void); */ \
[158] = { "sched_yield", { UNKNOWN }, UNKNOWN }, \
/*        int sched_get_priority_max(int policy); */ \
[159] = { "sched_get_priority_max", { UNKNOWN }, UNKNOWN }, \
/*        int sched_get_priority_min(int policy); */ \
[160] = { "sched_get_priority_min", { UNKNOWN }, UNKNOWN }, \
/*        int sched_rr_get_interval(pid_t pid, struct timespec *tp); */ \
[161] = { "sched_rr_get_interval", { UNKNOWN }, UNKNOWN }, \
/*        int nanosleep(const struct timespec *req, struct timespec *rem); */ \
[162] = { "nanosleep", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[163] = { "mremap", { UNKNOWN }, UNKNOWN }, \
/*        int setresuid(uid_t ruid, uid_t euid, uid_t suid); */ \
[164] = { "setresuid", { UNKNOWN }, UNKNOWN }, \
/*        int getresuid(uid_t *ruid, uid_t *euid, uid_t *suid); */ \
[165] = { "getresuid", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[166] = { "vm86", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[167] = { "query_module", { UNKNOWN }, UNKNOWN }, \
/*        int poll(struct pollfd *fds, nfds_t nfds, int timeout); */ \
[168] = { "poll", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[169] = { "nfsservctl", { UNKNOWN }, UNKNOWN }, \
/*        int setresgid(gid_t rgid, gid_t egid, gid_t sgid); */ \
[170] = { "setresgid", { UNKNOWN }, UNKNOWN }, \
/*        int getresgid(gid_t *rgid, gid_t *egid, gid_t *sgid); */ \
[171] = { "getresgid", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[172] = { "prctl", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[173] = { "rt_sigreturn", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[174] = { "rt_sigaction", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[175] = { "rt_sigprocmask", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[176] = { "rt_sigpending", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[177] = { "rt_sigtimedwait", { UNKNOWN }, UNKNOWN }, \
/*        int rt_sigqueueinfo(pid_t tgid, int sig, siginfo_t *info); */ \
[178] = { "rt_sigqueueinfo", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[179] = { "rt_sigsuspend", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[180] = { "pread64", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[181] = { "pwrite64", { UNKNOWN }, UNKNOWN }, \
/*        int chown(const char *pathname, uid_t owner, gid_t group);
       int fchown(int fd, uid_t owner, gid_t group);
       int lchown(const char *pathname, uid_t owner, gid_t group); */ \
[182] = { "chown", { UNKNOWN }, UNKNOWN }, \
/*        char *getcwd(char *buf, size_t size); */ \
[183] = { "getcwd", { UNKNOWN }, UNKNOWN }, \
/*        int capget(cap_user_header_t hdrp, cap_user_data_t datap); */ \
[184] = { "capget", { UNKNOWN }, UNKNOWN }, \
/*        int capset(cap_user_header_t hdrp, const cap_user_data_t datap); */ \
[185] = { "capset", { UNKNOWN }, UNKNOWN }, \
/*        int sigaltstack(const stack_t *ss, stack_t *old_ss); */ \
[186] = { "sigaltstack", { UNKNOWN }, UNKNOWN }, \
/*        ssize_t sendfile(int out_fd, int in_fd, off_t *offset, size_t count); */ \
[187] = { "sendfile", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[188] = { "getpmsg", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[189] = { "putpmsg", { UNKNOWN }, UNKNOWN }, \
/*        pid_t vfork(void); */ \
[190] = { "vfork", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[191] = { "ugetrlimit", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[192] = { "mmap2", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[193] = { "truncate64", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[194] = { "ftruncate64", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[195] = { "stat64", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[196] = { "lstat64", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[197] = { "fstat64", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[198] = { "lchown32", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[199] = { "getuid32", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[200] = { "getgid32", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[201] = { "geteuid32", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[202] = { "getegid32", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[203] = { "setreuid32", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[204] = { "setregid32", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[205] = { "getgroups32", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[206] = { "setgroups32", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[207] = { "fchown32", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[208] = { "setresuid32", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[209] = { "getresuid32", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[210] = { "setresgid32", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[211] = { "getresgid32", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[212] = { "chown32", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[213] = { "setuid32", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[214] = { "setgid32", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[215] = { "setfsuid32", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[216] = { "setfsgid32", { UNKNOWN }, UNKNOWN }, \
/*        int pivot_root(const char *new_root, const char *put_old); */ \
[217] = { "pivot_root", { UNKNOWN }, UNKNOWN }, \
/*        int mincore(void *addr, size_t length, unsigned char *vec); */ \
[218] = { "mincore", { UNKNOWN }, UNKNOWN }, \
/*        int madvise(void *addr, size_t length, int advice); */ \
[219] = { "madvise", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[220] = { "getdents64", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[221] = { "fcntl64", { UNKNOWN }, UNKNOWN }, \
/*        pid_t gettid(void); */ \
[224] = { "gettid", { UNKNOWN }, UNKNOWN }, \
/*        ssize_t readahead(int fd, off64_t offset, size_t count); */ \
[225] = { "readahead", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[226] = { "setxattr", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[227] = { "lsetxattr", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[228] = { "fsetxattr", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[229] = { "getxattr", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[230] = { "lgetxattr", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[231] = { "fgetxattr", { UNKNOWN }, UNKNOWN }, \
/*        ssize_t listxattr(const char *path, char *list, size_t size);
       ssize_t llistxattr(const char *path, char *list, size_t size);
       ssize_t flistxattr(int fd, char *list, size_t size); */ \
[232] = { "listxattr", { UNKNOWN }, UNKNOWN }, \
/*        ssize_t llistxattr(const char *path, char *list, size_t size); */ \
[233] = { "llistxattr", { UNKNOWN }, UNKNOWN }, \
/*        ssize_t flistxattr(int fd, char *list, size_t size); */ \
[234] = { "flistxattr", { UNKNOWN }, UNKNOWN }, \
/*        int removexattr(const char *path, const char *name);
       int lremovexattr(const char *path, const char *name);
       int fremovexattr(int fd, const char *name); */ \
[235] = { "removexattr", { UNKNOWN }, UNKNOWN }, \
/*        int lremovexattr(const char *path, const char *name); */ \
[236] = { "lremovexattr", { UNKNOWN }, UNKNOWN }, \
/*        int fremovexattr(int fd, const char *name); */ \
[237] = { "fremovexattr", { UNKNOWN }, UNKNOWN }, \
/*        int tkill(int tid, int sig);
       Note: There is no glibc wrapper for tkill(); see NOTES. */ \
[238] = { "tkill", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[239] = { "sendfile64", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[240] = { "futex", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[241] = { "sched_setaffinity", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[242] = { "sched_getaffinity", { UNKNOWN }, UNKNOWN }, \
/*        int set_thread_area(struct user_desc *u_info);
       int set_thread_area(unsigned long tp);
       int set_thread_area(unsigned long addr); */ \
[243] = { "set_thread_area", { UNKNOWN }, UNKNOWN }, \
/*        int get_thread_area(struct user_desc *u_info);
       int get_thread_area(void); */ \
[244] = { "get_thread_area", { UNKNOWN }, UNKNOWN }, \
/*        long io_setup(unsigned nr_events, aio_context_t *ctx_idp); */ \
[245] = { "io_setup", { UNKNOWN }, UNKNOWN }, \
/*        int io_destroy(aio_context_t ctx_id); */ \
[246] = { "io_destroy", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[247] = { "io_getevents", { UNKNOWN }, UNKNOWN }, \
/*        int io_submit(aio_context_t ctx_id, long nr, struct iocb **iocbpp); */ \
[248] = { "io_submit", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[249] = { "io_cancel", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[250] = { "fadvise64", { UNKNOWN }, UNKNOWN }, \
/*        void exit_group(int status); */ \
[252] = { "exit_group", { UNKNOWN }, UNKNOWN }, \
/*        int lookup_dcookie(u64 cookie, char *buffer, size_t len); */ \
[253] = { "lookup_dcookie", { UNKNOWN }, UNKNOWN }, \
/*        int epoll_create(int size); */ \
[254] = { "epoll_create", { UNKNOWN }, UNKNOWN }, \
/*        int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event); */ \
[255] = { "epoll_ctl", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[256] = { "epoll_wait", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[257] = { "remap_file_pages", { UNKNOWN }, UNKNOWN }, \
/*        pid_t set_tid_address(int *tidptr); */ \
[258] = { "set_tid_address", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[259] = { "timer_create", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[260] = { "timer_settime", { UNKNOWN }, UNKNOWN }, \
/*        int timer_gettime(timer_t timerid, struct itimerspec *curr_value); */ \
[261] = { "timer_gettime", { UNKNOWN }, UNKNOWN }, \
/*        int timer_getoverrun(timer_t timerid); */ \
[262] = { "timer_getoverrun", { UNKNOWN }, UNKNOWN }, \
/*        int timer_delete(timer_t timerid); */ \
[263] = { "timer_delete", { UNKNOWN }, UNKNOWN }, \
/*        int clock_settime(clockid_t clockid, const struct timespec *tp); */ \
[264] = { "clock_settime", { UNKNOWN }, UNKNOWN }, \
/*        int clock_gettime(clockid_t clockid, struct timespec *tp); */ \
[265] = { "clock_gettime", { UNKNOWN }, UNKNOWN }, \
/*        int clock_getres(clockid_t clockid, struct timespec *res); */ \
[266] = { "clock_getres", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[267] = { "clock_nanosleep", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[268] = { "statfs64", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[269] = { "fstatfs64", { UNKNOWN }, UNKNOWN }, \
/*        int tgkill(int tgid, int tid, int sig); */ \
[270] = { "tgkill", { UNKNOWN }, UNKNOWN }, \
/*        int utimes(const char *filename, const struct timeval times[2]); */ \
[271] = { "utimes", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[272] = { "fadvise64_64", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[273] = { "vserver", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[274] = { "mbind", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[275] = { "get_mempolicy", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[276] = { "set_mempolicy", { UNKNOWN }, UNKNOWN }, \
/*        mqd_t mq_open(const char *name, int oflag); */ \
[277] = { "mq_open", { UNKNOWN }, UNKNOWN }, \
/*        int mq_unlink(const char *name); */ \
[278] = { "mq_unlink", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[279] = { "mq_timedsend", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[280] = { "mq_timedreceive", { UNKNOWN }, UNKNOWN }, \
/*        int mq_notify(mqd_t mqdes, const struct sigevent *sevp); */ \
[281] = { "mq_notify", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[282] = { "mq_getsetattr", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[283] = { "kexec_load", { UNKNOWN }, UNKNOWN }, \
/*        int waitid(idtype_t idtype, id_t id, siginfo_t *infop, int options); */ \
[284] = { "waitid", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[286] = { "add_key", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[287] = { "request_key", { UNKNOWN }, UNKNOWN }, \
/*        long keyctl(int operation, ...); */ \
[288] = { "keyctl", { UNKNOWN }, UNKNOWN }, \
/*        int ioprio_set(int which, int who, int ioprio); */ \
[289] = { "ioprio_set", { UNKNOWN }, UNKNOWN }, \
/*        int ioprio_get(int which, int who); */ \
[290] = { "ioprio_get", { UNKNOWN }, UNKNOWN }, \
/*        int inotify_init(void); */ \
[291] = { "inotify_init", { UNKNOWN }, UNKNOWN }, \
/*        int inotify_add_watch(int fd, const char *pathname, uint32_t mask); */ \
[292] = { "inotify_add_watch", { UNKNOWN }, UNKNOWN }, \
/*        int inotify_rm_watch(int fd, int wd); */ \
[293] = { "inotify_rm_watch", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[294] = { "migrate_pages", { UNKNOWN }, UNKNOWN }, \
/*        int openat(int dirfd, const char *pathname, int flags);
       int openat(int dirfd, const char *pathname, int flags, mode_t mode); */ \
[295] = { "openat", { UNKNOWN }, UNKNOWN }, \
/*        int mkdirat(int dirfd, const char *pathname, mode_t mode); */ \
[296] = { "mkdirat", { UNKNOWN }, UNKNOWN }, \
/*        int mknodat(int dirfd, const char *pathname, mode_t mode, dev_t dev); */ \
[297] = { "mknodat", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[298] = { "fchownat", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[299] = { "futimesat", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[300] = { "fstatat64", { UNKNOWN }, UNKNOWN }, \
/*        int unlinkat(int dirfd, const char *pathname, int flags); */ \
[301] = { "unlinkat", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[302] = { "renameat", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[303] = { "linkat", { UNKNOWN }, UNKNOWN }, \
/*        int symlinkat(const char *target, int newdirfd, const char *linkpath); */ \
[304] = { "symlinkat", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[305] = { "readlinkat", { UNKNOWN }, UNKNOWN }, \
/*        int fchmodat(int dirfd, const char *pathname, mode_t mode, int flags); */ \
[306] = { "fchmodat", { UNKNOWN }, UNKNOWN }, \
/*        int faccessat(int dirfd, const char *pathname, int mode, int flags); */ \
[307] = { "faccessat", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[308] = { "pselect6", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[309] = { "ppoll", { UNKNOWN }, UNKNOWN }, \
/*        int unshare(int flags); */ \
[310] = { "unshare", { UNKNOWN }, UNKNOWN }, \
/*        long set_robust_list(struct robust_list_head *head, size_t len); */ \
[311] = { "set_robust_list", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[312] = { "get_robust_list", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[313] = { "splice", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[314] = { "sync_file_range", { UNKNOWN }, UNKNOWN }, \
/*        ssize_t tee(int fd_in, int fd_out, size_t len, unsigned int flags); */ \
[315] = { "tee", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[316] = { "vmsplice", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[317] = { "move_pages", { UNKNOWN }, UNKNOWN }, \
/*        int getcpu(unsigned *cpu, unsigned *node, struct getcpu_cache *tcache); */ \
[318] = { "getcpu", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[319] = { "epoll_pwait", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[320] = { "utimensat", { UNKNOWN }, UNKNOWN }, \
/*        int signalfd(int fd, const sigset_t *mask, int flags); */ \
[321] = { "signalfd", { UNKNOWN }, UNKNOWN }, \
/*        int timerfd_create(int clockid, int flags); */ \
[322] = { "timerfd_create", { UNKNOWN }, UNKNOWN }, \
/*        int eventfd(unsigned int initval, int flags); */ \
[323] = { "eventfd", { UNKNOWN }, UNKNOWN }, \
/*        int fallocate(int fd, int mode, off_t offset, off_t len); */ \
[324] = { "fallocate", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[325] = { "timerfd_settime", { UNKNOWN }, UNKNOWN }, \
/*        int timerfd_gettime(int fd, struct itimerspec *curr_value); */ \
[326] = { "timerfd_gettime", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[327] = { "signalfd4", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[328] = { "eventfd2", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[329] = { "epoll_create1", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[330] = { "dup3", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[331] = { "pipe2", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[332] = { "inotify_init1", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[333] = { "preadv", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[334] = { "pwritev", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[335] = { "rt_tgsigqueueinfo", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[336] = { "perf_event_open", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[337] = { "recvmmsg", { UNKNOWN }, UNKNOWN }, \
/*        int fanotify_init(unsigned int flags, unsigned int event_f_flags); */ \
[338] = { "fanotify_init", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[339] = { "fanotify_mark", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[340] = { "prlimit64", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[341] = { "name_to_handle_at", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[342] = { "open_by_handle_at", { UNKNOWN }, UNKNOWN }, \
/*        int clock_adjtime(clockid_t clk_id, struct timex *buf); */ \
[343] = { "clock_adjtime", { UNKNOWN }, UNKNOWN }, \
/*        int syncfs(int fd); */ \
[344] = { "syncfs", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[345] = { "sendmmsg", { UNKNOWN }, UNKNOWN }, \
/*        int setns(int fd, int nstype); */ \
[346] = { "setns", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[347] = { "process_vm_readv", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[348] = { "process_vm_writev", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[349] = { "kcmp", { UNKNOWN }, UNKNOWN }, \
/*        Note: glibc provides no header file declaration of init_module() and no wrapper function for finit_module(); see NOTES. */ \
[350] = { "finit_module", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[351] = { "sched_setattr", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[352] = { "sched_getattr", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[353] = { "renameat2", { UNKNOWN }, UNKNOWN }, \
/*        int seccomp(unsigned int operation, unsigned int flags, void *args); */ \
[354] = { "seccomp", { UNKNOWN }, UNKNOWN }, \
/*        ssize_t getrandom(void *buf, size_t buflen, unsigned int flags); */ \
[355] = { "getrandom", { UNKNOWN }, UNKNOWN }, \
/*        int memfd_create(const char *name, unsigned int flags); */ \
[356] = { "memfd_create", { UNKNOWN }, UNKNOWN }, \
/*        int bpf(int cmd, union bpf_attr *attr, unsigned int size); */ \
[357] = { "bpf", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[358] = { "execveat", { UNKNOWN }, UNKNOWN }, \
/*        int socket(int domain, int type, int protocol); */ \
[359] = { "socket", { UNKNOWN }, UNKNOWN }, \
/*        int socketpair(int domain, int type, int protocol, int sv[2]); */ \
[360] = { "socketpair", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[361] = { "bind", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[362] = { "connect", { UNKNOWN }, UNKNOWN }, \
/*        int listen(int sockfd, int backlog); */ \
[363] = { "listen", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[364] = { "accept4", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[365] = { "getsockopt", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[366] = { "setsockopt", { UNKNOWN }, UNKNOWN }, \
/*        int getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen); */ \
[367] = { "getsockname", { UNKNOWN }, UNKNOWN }, \
/*        int getpeername(int sockfd, struct sockaddr *addr, socklen_t *addrlen); */ \
[368] = { "getpeername", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[369] = { "sendto", { UNKNOWN }, UNKNOWN }, \
/*        ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags); */ \
[370] = { "sendmsg", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[371] = { "recvfrom", { UNKNOWN }, UNKNOWN }, \
/*        ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags); */ \
[372] = { "recvmsg", { UNKNOWN }, UNKNOWN }, \
/*        int shutdown(int sockfd, int how); */ \
[373] = { "shutdown", { UNKNOWN }, UNKNOWN }, \
/*        int userfaultfd(int flags); */ \
[374] = { "userfaultfd", { UNKNOWN }, UNKNOWN }, \
/*        int membarrier(int cmd, unsigned int flags, int cpu_id); */ \
[375] = { "membarrier", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[376] = { "mlock2", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[377] = { "copy_file_range", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[378] = { "preadv2", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[379] = { "pwritev2", { UNKNOWN }, UNKNOWN }, \
/*        int pkey_mprotect(void *addr, size_t len, int prot, int pkey); */ \
[380] = { "pkey_mprotect", { UNKNOWN }, UNKNOWN }, \
/*        int pkey_alloc(unsigned int flags, unsigned int access_rights); */ \
[381] = { "pkey_alloc", { UNKNOWN }, UNKNOWN }, \
/*        int pkey_free(int pkey); */ \
[382] = { "pkey_free", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[383] = { "statx", { UNKNOWN }, UNKNOWN }, \
/*        int arch_prctl(int code, unsigned long addr);
       int arch_prctl(int code, unsigned long *addr); */ \
[384] = { "arch_prctl", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[385] = { "io_pgetevents", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[386] = { "rseq", { UNKNOWN }, UNKNOWN }, \
/*        int semget(key_t key, int nsems, int semflg); */ \
[393] = { "semget", { UNKNOWN }, UNKNOWN }, \
/*        int semctl(int semid, int semnum, int cmd, ...); */ \
[394] = { "semctl", { UNKNOWN }, UNKNOWN }, \
/*        int shmget(key_t key, size_t size, int shmflg); */ \
[395] = { "shmget", { UNKNOWN }, UNKNOWN }, \
/*        int shmctl(int shmid, int cmd, struct shmid_ds *buf); */ \
[396] = { "shmctl", { UNKNOWN }, UNKNOWN }, \
/*        void *shmat(int shmid, const void *shmaddr, int shmflg); */ \
[397] = { "shmat", { UNKNOWN }, UNKNOWN }, \
/*        int shmdt(const void *shmaddr); */ \
[398] = { "shmdt", { UNKNOWN }, UNKNOWN }, \
/*        int msgget(key_t key, int msgflg); */ \
[399] = { "msgget", { UNKNOWN }, UNKNOWN }, \
/*        int msgsnd(int msqid, const void *msgp, size_t msgsz, int msgflg); */ \
[400] = { "msgsnd", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[401] = { "msgrcv", { UNKNOWN }, UNKNOWN }, \
/*        int msgctl(int msqid, int cmd, struct msqid_ds *buf); */ \
[402] = { "msgctl", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[403] = { "clock_gettime64", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[404] = { "clock_settime64", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[405] = { "clock_adjtime64", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[406] = { "clock_getres_time64", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[407] = { "clock_nanosleep_time64", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[408] = { "timer_gettime64", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[409] = { "timer_settime64", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[410] = { "timerfd_gettime64", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[411] = { "timerfd_settime64", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[412] = { "utimensat_time64", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[413] = { "pselect6_time64", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[414] = { "ppoll_time64", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[416] = { "io_pgetevents_time64", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[417] = { "recvmmsg_time64", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[418] = { "mq_timedsend_time64", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[419] = { "mq_timedreceive_time64", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[420] = { "semtimedop_time64", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[421] = { "rt_sigtimedwait_time64", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[422] = { "futex_time64", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[423] = { "sched_rr_get_interval_time64", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[424] = { "pidfd_send_signal", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[425] = { "io_uring_setup", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[426] = { "io_uring_enter", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[427] = { "io_uring_register", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[428] = { "open_tree", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[429] = { "move_mount", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[430] = { "fsopen", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[431] = { "fsconfig", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[432] = { "fsmount", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[433] = { "fspick", { UNKNOWN }, UNKNOWN }, \
/*        int pidfd_open(pid_t pid, unsigned int flags); */ \
[434] = { "pidfd_open", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[435] = { "clone3", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[436] = { "close_range", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[437] = { "openat2", { UNKNOWN }, UNKNOWN }, \
/*        int pidfd_getfd(int pidfd, int targetfd, unsigned int flags); */ \
[438] = { "pidfd_getfd", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[439] = { "faccessat2", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[440] = { "process_madvise", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[441] = { "epoll_pwait2", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[442] = { "mount_setattr", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[443] = { "quotactl_fd", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[444] = { "landlock_create_ruleset", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[445] = { "landlock_add_rule", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[446] = { "landlock_restrict_self", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[447] = { "memfd_secret", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[448] = { "process_mrelease", { UNKNOWN }, UNKNOWN }, \
}
