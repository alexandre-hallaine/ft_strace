#pragma once
#include "types.h"

#define SYSCALL_TABLE_32 { \
/*        long restart_syscall(void); */ \
[0] = { "restart_syscall", { }, LONG }, \
/*        void _exit(int status); */ \
[1] = { "_exit", { INT } }, \
/*        pid_t fork(void); */ \
[2] = { "fork", { }, ID }, \
/*        ssize_t read(int fd, void *buf, size_t count); */ \
[3] = { "read", { INT, PTR, LONG }, LONG }, \
/*        ssize_t write(int fd, const void *buf, size_t count); */ \
[4] = { "write", { INT, PTR, LONG }, LONG }, \
/*        int open(const char *pathname, int flags, mode_t mode); */ \
[5] = { "open", { STR, INT, MODE }, INT }, \
/*        int close(int fd); */ \
[6] = { "close", { INT }, INT }, \
/*        pid_t waitpid(pid_t pid, int *wstatus, int options); */ \
[7] = { "waitpid", { ID, PTR, INT }, ID }, \
/*        int creat(const char *pathname, mode_t mode); */ \
[8] = { "creat", { STR, MODE }, INT }, \
/*        int link(const char *oldpath, const char *newpath); */ \
[9] = { "link", { STR, STR }, INT }, \
/*        int unlink(const char *pathname); */ \
[10] = { "unlink", { STR }, INT }, \
/*        int execve(const char *pathname, char *const argv[], char *const envp[]) */ \
[11] = { "execve", { STR, ARRAY | STR, ARRAY | STR }, INT }, \
/*        int chdir(const char *path); */ \
[12] = { "chdir", { STR }, INT }, \
/*        time_t time(time_t *tloc); */ \
[13] = { "time", { PTR }, TIME }, \
/*        int mknod(const char *pathname, mode_t mode, dev_t dev); */ \
[14] = { "mknod", { STR, MODE, DEV }, INT }, \
/*        int chmod(const char *pathname, mode_t mode); */ \
[15] = { "chmod", { STR, MODE }, INT }, \
/*        int lchown(const char *pathname, uid_t owner, gid_t group); */ \
[16] = { "lchown", { STR, ID, ID }, INT }, \
/* UNKNOWN PROTOTYPE */ \
[17] = { "break", { UNKNOWN }, UNKNOWN }, \
/*        int stat(const char *pathname, struct stat *statbuf); */ \
[18] = { "oldstat", { STR, PTR }, INT }, \
/*        off_t lseek(int fd, off_t offset, int whence); */ \
[19] = { "lseek", { INT, OFF, INT }, OFF }, \
/*        pid_t getpid(void); */ \
[20] = { "getpid", { }, ID }, \
/*        int mount(const char *source, const char *target, const char *filesystemtype, unsigned long mountflags, const void *data); */ \
[21] = { "mount", { STR, STR, STR, LONG, PTR }, INT }, \
/*        int umount(const char *target); */ \
[22] = { "umount", { STR }, INT }, \
/*        int setuid(uid_t uid); */ \
[23] = { "setuid", { ID }, INT }, \
/*        uid_t getuid(void); */ \
[24] = { "getuid", { }, ID }, \
/*        int stime(const time_t *t); */ \
[25] = { "stime", { PTR }, INT }, \
/*        long ptrace(enum __ptrace_request request, pid_t pid, void *addr, void *data); */ \
[26] = { "ptrace", { INT, ID, PTR, PTR }, LONG }, \
/*        unsigned int alarm(unsigned int seconds); */ \
[27] = { "alarm", { INT }, INT }, \
/*        int fstat(int fd, struct stat *statbuf); */ \
[28] = { "oldfstat", { INT, PTR }, INT }, \
/*        int pause(void); */ \
[29] = { "pause", { }, INT }, \
/*        int utime(const char *filename, const struct utimbuf *times); */ \
[30] = { "utime", { STR, PTR }, INT }, \
/* UNKNOWN PROTOTYPE */ \
[31] = { "stty", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[32] = { "gtty", { UNKNOWN }, UNKNOWN }, \
/*        int access(const char *pathname, int mode); */ \
[33] = { "access", { STR, INT }, INT }, \
/*        int nice(int inc); */ \
[34] = { "nice", { INT }, INT }, \
/*        int ftime(struct timeb *tp); */ \
[35] = { "ftime", { PTR }, INT }, \
/*        void sync(void); */ \
[36] = { "sync", { }, }, \
/*        int kill(pid_t pid, int sig); */ \
[37] = { "kill", { ID, INT }, INT }, \
/*        int rename(const char *oldpath, const char *newpath); */ \
[38] = { "rename", { STR, STR }, INT }, \
/*        int mkdir(const char *pathname, mode_t mode); */ \
[39] = { "mkdir", { STR, MODE }, INT }, \
/*        int rmdir(const char *pathname); */ \
[40] = { "rmdir", { STR }, INT }, \
/*        int dup(int oldfd); */ \
[41] = { "dup", { INT }, INT }, \
/*        int pipe(int pipefd[2]); */ \
[42] = { "pipe", { ARRAY | INT }, INT }, \
/*        clock_t times(struct tms *buf); */ \
[43] = { "times", { PTR }, UNKNOWN_STRUCT }, \
/* UNKNOWN PROTOTYPE */ \
[44] = { "prof", { UNKNOWN }, UNKNOWN }, \
/*        int brk(void *addr); */ \
[45] = { "brk", { PTR }, INT }, \
/*        int setgid(gid_t gid); */ \
[46] = { "setgid", { ID }, INT }, \
/*        gid_t getgid(void); */ \
[47] = { "getgid", { }, ID }, \
/*        sighandler_t signal(int signum, sighandler_t handler); */ \
[48] = { "signal", { INT, UNKNOWN_STRUCT }, UNKNOWN_STRUCT }, \
/*        uid_t geteuid(void); */ \
[49] = { "geteuid", { }, ID }, \
/*        gid_t getegid(void); */ \
[50] = { "getegid", { }, ID }, \
/*        int acct(const char *filename); */ \
[51] = { "acct", { STR }, INT }, \
/*        int umount2(const char *target, int flags); */ \
[52] = { "umount2", { STR, INT }, INT }, \
/* UNKNOWN PROTOTYPE */ \
[53] = { "lock", { UNKNOWN }, UNKNOWN }, \
/*        int ioctl(int fd, unsigned long request, ...); */ \
[54] = { "ioctl", { INT, LONG, UNKNOWN }, INT }, \
/*        int fcntl(int fd, int cmd, ...  ); */ \
[55] = { "fcntl", { INT, INT, UNKNOWN }, INT }, \
/* UNKNOWN PROTOTYPE */ \
[56] = { "mpx", { UNKNOWN }, UNKNOWN }, \
/*        int setpgid(pid_t pid, pid_t pgid); */ \
[57] = { "setpgid", { ID, ID }, INT }, \
/*        long ulimit(int cmd, long newlimit); */ \
[58] = { "ulimit", { INT, LONG }, LONG }, \
/*        int uname(struct utsname *buf); */ \
[59] = { "oldolduname", { PTR }, INT }, \
/*        mode_t umask(mode_t mask); */ \
[60] = { "umask", { MODE }, MODE }, \
/*        int chroot(const char *path); */ \
[61] = { "chroot", { STR }, INT }, \
/*        int ustat(dev_t dev, struct ustat *ubuf); */ \
[62] = { "ustat", { DEV, PTR }, INT }, \
/*        int dup2(int oldfd, int newfd); */ \
[63] = { "dup2", { INT, INT }, INT }, \
/*        pid_t getppid(void); */ \
[64] = { "getppid", { }, ID }, \
/*        pid_t getpgrp(void); */ \
[65] = { "getpgrp", { }, ID }, \
/*        pid_t setsid(void); */ \
[66] = { "setsid", { }, ID }, \
/*        int sigaction(int signum, const struct sigaction *act, struct sigaction *oldact); */ \
[67] = { "sigaction", { INT, PTR, PTR }, INT }, \
/*        long sgetmask(void); */ \
[68] = { "sgetmask", { }, LONG }, \
/*        long ssetmask(long newmask); */ \
[69] = { "ssetmask", { LONG }, LONG }, \
/*        int setreuid(uid_t ruid, uid_t euid); */ \
[70] = { "setreuid", { ID, ID }, INT }, \
/*        int setregid(gid_t rgid, gid_t egid); */ \
[71] = { "setregid", { ID, ID }, INT }, \
/*        int sigsuspend(const sigset_t *mask); */ \
[72] = { "sigsuspend", { PTR }, INT }, \
/*        int sigpending(sigset_t *set); */ \
[73] = { "sigpending", { PTR }, INT }, \
/*        int sethostname(const char *name, size_t len); */ \
[74] = { "sethostname", { STR, LONG }, INT }, \
/*        int setrlimit(int resource, const struct rlimit *rlim); */ \
[75] = { "setrlimit", { INT, PTR }, INT }, \
/*        int getrlimit(int resource, struct rlimit *rlim); */ \
[76] = { "getrlimit", { INT, PTR }, INT }, \
/*        int getrusage(int who, struct rusage *usage); */ \
[77] = { "getrusage", { INT, PTR }, INT }, \
/*        int gettimeofday(struct timeval *tv, struct timezone *tz); */ \
[78] = { "gettimeofday", { PTR, PTR }, INT }, \
/*        int settimeofday(const struct timeval *tv, const struct timezone *tz); */ \
[79] = { "settimeofday", { PTR, PTR }, INT }, \
/*        int getgroups(int size, gid_t list[]); */ \
[80] = { "getgroups", { INT, ARRAY | ID }, INT }, \
/*        int setgroups(size_t size, const gid_t *list); */ \
[81] = { "setgroups", { INT, ARRAY | ID }, INT }, \
/*        int select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout); */ \
[82] = { "select", { INT, PTR, PTR, PTR, PTR }, INT }, \
/*        int symlink(const char *target, const char *linkpath); */ \
[83] = { "symlink", { STR, STR }, INT }, \
/*        int lstat(const char *pathname, struct stat *statbuf); */ \
[84] = { "oldlstat", { STR, PTR }, INT }, \
/*        ssize_t readlink(const char *pathname, char *buf, size_t bufsiz); */ \
[85] = { "readlink", { STR, STR, LONG }, LONG }, \
/*        int uselib(const char *library); */ \
[86] = { "uselib", { STR }, INT }, \
/*        int swapon(const char *path, int swapflags); */ \
[87] = { "swapon", { STR, INT }, INT }, \
/*        int reboot(int magic, int magic2, int cmd, void *arg); */ \
[88] = { "reboot", { INT, INT, INT, PTR }, INT }, \
/*        struct dirent *readdir(DIR *dirp); */ \
[89] = { "readdir", { PTR }, PTR }, \
/*        void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset); */ \
[90] = { "mmap", { PTR, LONG, INT, INT, INT, OFF }, PTR }, \
/*        int munmap(void *addr, size_t length); */ \
[91] = { "munmap", { PTR, LONG }, INT }, \
/*        int truncate(const char *path, off_t length); */ \
[92] = { "truncate", { STR, OFF }, INT }, \
/*        int ftruncate(int fd, off_t length); */ \
[93] = { "ftruncate", { INT, OFF }, INT }, \
/*        int fchmod(int fd, mode_t mode); */ \
[94] = { "fchmod", { INT, MODE }, INT }, \
/*        int fchown(int fd, uid_t owner, gid_t group); */ \
[95] = { "fchown", { INT, ID, ID }, INT }, \
/*        int getpriority(int which, id_t who); */ \
[96] = { "getpriority", { INT, ID }, INT }, \
/*        int setpriority(int which, id_t who, int prio); */ \
[97] = { "setpriority", { INT, ID, INT }, INT }, \
/*        int profil(unsigned short *buf, size_t bufsiz, size_t offset, unsigned int scale); */ \
[98] = { "profil", { PTR, LONG, LONG, INT }, INT }, \
/*        int statfs(const char *path, struct statfs *buf); */ \
[99] = { "statfs", { STR, PTR }, INT }, \
/*        int fstatfs(int fd, struct statfs *buf); */ \
[100] = { "fstatfs", { INT, PTR }, INT }, \
/*        int ioperm(unsigned long from, unsigned long num, int turn_on); */ \
[101] = { "ioperm", { LONG, LONG, INT }, INT }, \
/*        int socketcall(int call, unsigned long *args); */ \
[102] = { "socketcall", { INT, PTR }, INT }, \
/*        int syslog(int type, char *bufp, int len); */ \
[103] = { "syslog", { INT, STR, INT }, INT }, \
/*         int setitimer(int which, const struct itimerval *new_value, struct itimerval *old_value); */ \
[104] = { "setitimer", { INT, PTR, PTR }, INT }, \
/*        int getitimer(int which, struct itimerval *curr_value); */ \
[105] = { "getitime", { INT, PTR }, INT }, \
/*        int stat(const char *pathname, struct stat *statbuf); */ \
[106] = { "stat", { STR, PTR }, INT }, \
/*        int lstat(const char *pathname, struct stat *statbuf); */ \
[107] = { "lstat", { STR, PTR }, INT }, \
/*        int fstat(int fd, struct stat *statbuf); */ \
[108] = { "fstat", { INT, PTR }, INT }, \
/*        int uname(struct utsname *buf); */ \
[109] = { "olduname", { PTR }, INT }, \
/*        int iopl(int level); */ \
[110] = { "iopl", { INT }, INT }, \
/*        int vhangup(void); */ \
[111] = { "vhangup", { }, INT }, \
/*        int idle(void); */ \
[112] = { "idle", { }, INT }, \
/*        int vm86old(struct vm86_struct *info); */ \
[113] = { "vm86old", { PTR }, INT }, \
/*        pid_t wait4(pid_t pid, int *wstatus, int options, struct rusage *rusage); */ \
[114] = { "wait4", { ID, PTR, INT, PTR }, ID }, \
/*        int swapoff(const char *path); */ \
[115] = { "swapoff", { STR }, INT }, \
/*        int sysinfo(struct sysinfo *info); */ \
[116] = { "sysinfo", { PTR }, INT }, \
/*        int ipc(unsigned int call, int first, int second, int third, void *ptr, long fifth); */ \
[117] = { "ipc", { INT, INT, INT, INT, PTR, LONG }, INT }, \
/*        int fsync(int fd); */ \
[118] = { "fsync", { INT }, INT }, \
/*        int sigreturn(...); */ \
[119] = { "sigreturn", { UNKNOWN }, INT }, \
/*        int clone(int (*fn)(void *), void *stack, int flags, void *arg, ...); */ \
[120] = { "clone", { PTR, PTR, INT, PTR, UNKNOWN }, INT }, \
/*        int setdomainname(const char *name, size_t len); */ \
[121] = { "setdomainname", { STR, LONG }, INT }, \
/*        int uname(struct utsname *buf); */ \
[122] = { "uname", { PTR }, INT }, \
/*        int modify_ldt(int func, void *ptr, unsigned long bytecount); */ \
[123] = { "modify_ldt", { INT, PTR, LONG }, INT }, \
/*        int adjtimex(struct timex *buf); */ \
[124] = { "adjtimex", { PTR }, INT }, \
/*        int mprotect(void *addr, size_t len, int prot); */ \
[125] = { "mprotect", { PTR, LONG, INT }, INT }, \
/*        int sigprocmask(int how, const sigset_t *set, sigset_t *oldset); */ \
[126] = { "sigprocmask", { INT, PTR, PTR }, INT }, \
/*        caddr_t create_module(const char *name, size_t size); */ \
[127] = { "create_module", { STR, LONG }, UNKNOWN_STRUCT }, \
/*        int init_module(void *module_image, unsigned long len, const char *param_values); */ \
[128] = { "init_module", { PTR, LONG, STR }, INT }, \
/*        int delete_module(const char *name, int flags); */ \
[129] = { "delete_module", { STR, INT }, INT }, \
/*        int get_kernel_syms(struct kernel_sym *table); */ \
[130] = { "get_kernel_syms", { PTR }, INT }, \
/*        int quotactl(int cmd, const char *special, int id, caddr_t addr); */ \
[131] = { "quotactl", { INT, STR, INT, UNKNOWN_STRUCT }, INT }, \
/*        pid_t getpgid(pid_t pid); */ \
[132] = { "getpgid", { ID }, ID }, \
/*        int fchdir(int fd); */ \
[133] = { "fchdir", { INT }, INT }, \
/*        int bdflush(int func, long data); */ \
[134] = { "bdflush", { INT, LONG }, INT }, \
/*        int sysfs(int option, unsigned int fs_index, char *buf); */ \
[135] = { "sysfs", { INT, INT, STR }, INT }, \
/*        int personality(unsigned long persona); */ \
[136] = { "personality", { LONG }, INT }, \
/* UNKNOWN PROTOTYPE */ \
[137] = { "afs_syscall", { UNKNOWN }, UNKNOWN }, \
/*        int setfsuid(uid_t fsuid); */ \
[138] = { "setfsuid", { ID }, INT }, \
/*        int setfsgid(uid_t fsgid); */ \
[139] = { "setfsgid", { ID }, INT }, \
/*        int _llseek(unsigned int fd, unsigned long offset_high, unsigned long offset_low, loff_t *result, unsigned int whence); */ \
[140] = { "_llseek", { INT, LONG, LONG, PTR, INT }, INT }, \
/*        ssize_t getdents64(int fd, void *dirp, size_t count); */ \
[141] = { "getdents", { INT, PTR, LONG }, LONG }, \
/*        int select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout); */ \
[142] = { "_newselect", { INT, PTR, PTR, PTR, PTR }, INT }, \
/*        int flock(int fd, int operation); */ \
[143] = { "flock", { INT, INT }, INT }, \
/*        int msync(void *addr, size_t length, int flags); */ \
[144] = { "msync", { PTR, LONG, INT }, INT }, \
/*        ssize_t readv(int fd, const struct iovec *iov, int iovcnt); */ \
[145] = { "readv", { INT, PTR, INT }, LONG }, \
/*        ssize_t writev(int fd, const struct iovec *iov, int iovcnt); */ \
[146] = { "writev", { INT, PTR, INT }, LONG }, \
/*        pid_t getsid(pid_t pid); */ \
[147] = { "getsid", { ID }, ID }, \
/*        int fdatasync(int fd); */ \
[148] = { "fdatasync", { INT }, INT }, \
/*        int _sysctl(struct __sysctl_args *args); */ \
[149] = { "_sysctl", { PTR }, INT }, \
/*        int mlock(const void *addr, size_t len); */ \
[150] = { "mlock", { PTR, LONG }, INT }, \
/*        int munlock(const void *addr, size_t len); */ \
[151] = { "munlock", { PTR, LONG }, INT }, \
/*        int mlockall(int flags); */ \
[152] = { "mlockall", { INT }, INT }, \
/*        int munlockall(void); */ \
[153] = { "munlockall", { }, INT }, \
/*        int sched_setparam(pid_t pid, const struct sched_param *param); */ \
[154] = { "sched_setparam", { ID, PTR }, INT }, \
/*        int sched_getparam(pid_t pid, struct sched_param *param); */ \
[155] = { "sched_getparam", { ID, PTR }, INT }, \
/*        int sched_setscheduler(pid_t pid, int policy, const struct sched_param *param); */ \
[156] = { "sched_setscheduler", { ID, INT, PTR }, INT }, \
/*        int sched_getscheduler(pid_t pid); */ \
[157] = { "sched_getscheduler", { ID }, INT }, \
/*        int sched_yield(void); */ \
[158] = { "sched_yield", { }, INT }, \
/*        int sched_get_priority_max(int policy); */ \
[159] = { "sched_get_priority_max", { INT }, INT }, \
/*        int sched_get_priority_min(int policy); */ \
[160] = { "sched_get_priority_min", { INT }, INT }, \
/*        int sched_rr_get_interval(pid_t pid, struct timespec *tp); */ \
[161] = { "sched_rr_get_interval", { ID, PTR }, INT }, \
/*        int nanosleep(const struct timespec *req, struct timespec *rem); */ \
[162] = { "nanosleep", { PTR, PTR }, INT }, \
/*        void *mremap(void *old_address, size_t old_size, size_t new_size, int flags, ...); */ \
[163] = { "mremap", { PTR, LONG, LONG, INT, UNKNOWN }, PTR }, \
/*        int setresuid(uid_t ruid, uid_t euid, uid_t suid); */ \
[164] = { "setresuid", { ID, ID, ID }, INT }, \
/*        int getresuid(uid_t *ruid, uid_t *euid, uid_t *suid); */ \
[165] = { "getresuid", { PTR, PTR, PTR }, INT }, \
/*        int vm86(unsigned long fn, struct vm86plus_struct *v86); */ \
[166] = { "vm86", { LONG, PTR }, INT }, \
/*        int query_module(const char *name, int which, void *buf, size_t bufsize, size_t *ret); */ \
[167] = { "query_module", { STR, INT, PTR, LONG, PTR }, INT }, \
/*        int poll(struct pollfd *fds, nfds_t nfds, int timeout); */ \
[168] = { "poll", { PTR, INT, INT }, INT }, \
/*        long nfsservctl(int cmd, struct nfsctl_arg *argp, union nfsctl_res *resp); */ \
[169] = { "nfsservctl", { INT, PTR, PTR }, LONG }, \
/*        int setresgid(gid_t rgid, gid_t egid, gid_t sgid); */ \
[170] = { "setresgid", { ID, ID, ID }, INT }, \
/*        int getresgid(gid_t *rgid, gid_t *egid, gid_t *sgid); */ \
[171] = { "getresgid", { PTR, PTR, PTR }, INT }, \
/*        int prctl(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5); */ \
[172] = { "prctl", { INT, LONG, LONG, LONG, LONG }, INT }, \
/*        int sigreturn(...); */ \
[173] = { "rt_sigreturn", { UNKNOWN }, INT }, \
/*        int sigaction(int signum, const struct sigaction *act, struct sigaction *oldact); */ \
[174] = { "rt_sigaction", { INT, PTR, PTR }, INT }, \
/*        int rt_sigprocmask(int how, const kernel_sigset_t *set, kernel_sigset_t *oldset, size_t sigsetsize); */ \
[175] = { "rt_sigprocmask", { INT, PTR, PTR, LONG }, INT }, \
/*        int sigpending(sigset_t *set); */ \
[176] = { "rt_sigpending", { PTR }, INT }, \
/*        int sigtimedwait(const sigset_t *set, siginfo_t *info, const struct timespec *timeout); */ \
[177] = { "rt_sigtimedwait", { PTR, PTR, PTR }, INT }, \
/*        int rt_sigqueueinfo(pid_t tgid, int sig, siginfo_t *info); */ \
[178] = { "rt_sigqueueinfo", { ID, INT, PTR }, INT }, \
/*        int sigsuspend(const sigset_t *mask); */ \
[179] = { "rt_sigsuspend", { PTR }, INT }, \
/*        ssize_t pread(int fd, void *buf, size_t count, off_t offset); */ \
[180] = { "pread64", { INT, PTR, LONG, OFF }, LONG }, \
/*        pwrite(int fd, const void *buf, size_t count, off_t offset); */ \
[181] = { "pwrite64", { INT, PTR, LONG, OFF }, LONG }, \
/*        int chown(const char *pathname, uid_t owner, gid_t group); */ \
[182] = { "chown", { STR, ID, ID }, INT }, \
/*        char *getcwd(char *buf, size_t size); */ \
[183] = { "getcwd", { STR, LONG }, STR }, \
/*        int capget(cap_user_header_t hdrp, cap_user_data_t datap); */ \
[184] = { "capget", { PTR, PTR }, INT }, \
/*        int capset(cap_user_header_t hdrp, const cap_user_data_t datap); */ \
[185] = { "capset", { PTR, PTR }, INT }, \
/*        int sigaltstack(const stack_t *ss, stack_t *old_ss); */ \
[186] = { "sigaltstack", { PTR, PTR }, INT }, \
/*        ssize_t sendfile(int out_fd, int in_fd, off_t *offset, size_t count); */ \
[187] = { "sendfile", { INT, INT, PTR, LONG }, LONG }, \
/* UNKNOWN PROTOTYPE */ \
[188] = { "getpmsg", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[189] = { "putpmsg", { UNKNOWN }, UNKNOWN }, \
/*        pid_t vfork(void); */ \
[190] = { "vfork", { }, ID }, \
/*        int getrlimit(int resource, struct rlimit *rlim); */ \
[191] = { "ugetrlimit", { INT, PTR }, INT }, \
/*        void *mmap2(void *addr, size_t length, int prot, int flags, int fd, off_t pgoffset); */ \
[192] = { "mmap2", { PTR, LONG, INT, INT, INT, OFF }, PTR }, \
/*        int truncate(const char *path, off_t length); */ \
[193] = { "truncate64", { STR, OFF }, INT }, \
/*        int ftruncate(int fd, off_t length); */ \
[194] = { "ftruncate64", { INT, OFF }, INT }, \
/*        int stat(const char *pathname, struct stat *statbuf); */ \
[195] = { "stat64", { STR, PTR }, INT }, \
/*        int lstat(const char *pathname, struct stat *statbuf); */ \
[196] = { "lstat64", { STR, PTR }, INT }, \
/*        int fstat(int fd, struct stat *statbuf); */ \
[197] = { "fstat64", { INT, PTR }, INT }, \
/*        int lchown(const char *pathname, uid_t owner, gid_t group); */ \
[198] = { "lchown32", { STR, ID, ID }, INT }, \
/*        uid_t getuid(void); */ \
[199] = { "getuid32", { }, ID }, \
/*        gid_t getgid(void); */ \
[200] = { "getgid32", { }, ID }, \
/*        uid_t geteuid(void); */ \
[201] = { "geteuid32", { }, ID }, \
/*        gid_t getegid(void); */ \
[202] = { "getegid32", { }, ID }, \
/*        int setreuid(uid_t ruid, uid_t euid); */ \
[203] = { "setreuid32", { ID, ID }, INT }, \
/*        int setregid(gid_t rgid, gid_t egid); */ \
[204] = { "setregid32", { ID, ID }, INT }, \
/*        int getgroups(int size, gid_t list[]); */ \
[205] = { "getgroups32", { INT, ARRAY | ID }, INT }, \
/*        int setgroups(size_t size, const gid_t *list); */ \
[206] = { "setgroups32", { INT, ARRAY | ID }, INT }, \
/*        int fchown(int fd, uid_t owner, gid_t group); */ \
[207] = { "fchown32", { INT, ID, ID }, INT }, \
/*        int setresuid(uid_t ruid, uid_t euid, uid_t suid); */ \
[208] = { "setresuid32", { ID, ID, ID }, INT }, \
/*        int getresuid(uid_t *ruid, uid_t *euid, uid_t *suid); */ \
[209] = { "getresuid32", { PTR, PTR, PTR }, INT }, \
/*        int setresgid(gid_t rgid, gid_t egid, gid_t sgid); */ \
[210] = { "setresgid32", { ID, ID, ID }, INT }, \
/*        int getresgid(gid_t *rgid, gid_t *egid, gid_t *sgid); */ \
[211] = { "getresgid32", { PTR, PTR, PTR }, INT }, \
/*        int chown(const char *pathname, uid_t owner, gid_t group); */ \
[212] = { "chown32", { STR, ID, ID }, INT }, \
/*        int setuid(uid_t uid); */ \
[213] = { "setuid32", { ID }, INT }, \
/*        int setgid(gid_t gid); */ \
[214] = { "setgid32", { ID }, INT }, \
/*        int setfsuid(uid_t fsuid); */ \
[215] = { "setfsuid32", { ID }, INT }, \
/*        int setfsgid(uid_t fsgid); */ \
[216] = { "setfsgid32", { ID }, INT }, \
/*        int pivot_root(const char *new_root, const char *put_old); */ \
[217] = { "pivot_root", { STR, STR }, INT }, \
/*        int mincore(void *addr, size_t length, unsigned char *vec); */ \
[218] = { "mincore", { PTR, LONG, STR }, INT }, \
/*        int madvise(void *addr, size_t length, int advice); */ \
[219] = { "madvise", { PTR, LONG, INT }, INT }, \
/*        ssize_t getdents64(int fd, void *dirp, size_t count); */ \
[220] = { "getdents64", { INT, PTR, LONG }, LONG }, \
/*        int fcntl(int fd, int cmd, ...); */ \
[221] = { "fcntl64", { INT, INT, UNKNOWN }, INT }, \
/*        pid_t gettid(void); */ \
[224] = { "gettid", { }, ID }, \
/*        ssize_t readahead(int fd, off64_t offset, size_t count); */ \
[225] = { "readahead", { INT, OFF, LONG }, LONG }, \
/*        int setxattr(const char *path, const char *name, const void *value, size_t size, int flags); */ \
[226] = { "setxattr", { STR, STR, PTR, LONG, INT }, INT }, \
/*        int lsetxattr(const char *path, const char *name, const void *value, size_t size, int flags); */ \
[227] = { "lsetxattr", { STR, STR, PTR, LONG, INT }, INT }, \
/*        int fsetxattr(int fd, const char *name, const void *value, size_t size, int flags); */ \
[228] = { "fsetxattr", { INT, STR, PTR, LONG, INT }, INT }, \
/*        ssize_t getxattr(const char *path, const char *name, void *value, size_t size); */ \
[229] = { "getxattr", { STR, STR, PTR, LONG }, LONG }, \
/*        ssize_t lgetxattr(const char *path, const char *name, void *value, size_t size); */ \
[230] = { "lgetxattr", { STR, STR, PTR, LONG }, LONG }, \
/*        ssize_t fgetxattr(int fd, const char *name, void *value, size_t size); */ \
[231] = { "fgetxattr", { INT, STR, PTR, LONG }, LONG }, \
/*        ssize_t listxattr(const char *path, char *list, size_t size); */ \
[232] = { "listxattr", { STR, STR, LONG }, LONG }, \
/*        ssize_t llistxattr(const char *path, char *list, size_t size); */ \
[233] = { "llistxattr", { STR, STR, LONG }, LONG }, \
/*        ssize_t flistxattr(int fd, char *list, size_t size); */ \
[234] = { "flistxattr", { INT, STR, LONG }, LONG }, \
/*        int removexattr(const char *path, const char *name); */ \
[235] = { "removexattr", { STR, STR }, INT }, \
/*        int lremovexattr(const char *path, const char *name); */ \
[236] = { "lremovexattr", { STR, STR }, INT }, \
/*        int fremovexattr(int fd, const char *name); */ \
[237] = { "fremovexattr", { INT, STR }, INT }, \
/*        int tkill(int tid, int sig); */ \
[238] = { "tkill", { INT, INT }, INT }, \
/*        ssize_t sendfile(int out_fd, int in_fd, off_t *offset, size_t count); */ \
[239] = { "sendfile64", { INT, INT, PTR, LONG }, LONG }, \
/*        long futex(uint32_t *uaddr, int futex_op, uint32_t val, const struct timespec *timeout, uint32_t *uaddr2, uint32_t val3); */ \
[240] = { "futex", { PTR, INT, INT, PTR, PTR, INT }, LONG }, \
/*        int sched_setaffinity(pid_t pid, size_t cpusetsize, const cpu_set_t *mask); */ \
[241] = { "sched_setaffinity", { ID, LONG, PTR }, INT }, \
/*        int sched_getaffinity(pid_t pid, size_t cpusetsize, cpu_set_t *mask); */ \
[242] = { "sched_getaffinity", { ID, LONG, PTR }, INT }, \
/*        int set_thread_area(struct user_desc *u_info); */ \
[243] = { "set_thread_area", { PTR }, INT }, \
/*        int get_thread_area(struct user_desc *u_info); */ \
[244] = { "get_thread_area", { PTR }, INT }, \
/*        long io_setup(unsigned nr_events, aio_context_t *ctx_idp); */ \
[245] = { "io_setup", { LONG, PTR }, LONG }, \
/*        int io_destroy(aio_context_t ctx_id); */ \
[246] = { "io_destroy", { UNKNOWN_STRUCT }, INT }, \
/*        int io_getevents(aio_context_t ctx_id, long min_nr, long nr, struct io_event *events, struct timespec *timeout); */ \
[247] = { "io_getevents", { UNKNOWN_STRUCT, LONG, LONG, PTR, PTR }, INT }, \
/*        int io_submit(aio_context_t ctx_id, long nr, struct iocb **iocbpp); */ \
[248] = { "io_submit", { UNKNOWN_STRUCT, LONG, PTR }, INT }, \
/*        int io_cancel(aio_context_t ctx_id, struct iocb *iocb, struct io_event *result); */ \
[249] = { "io_cancel", { UNKNOWN_STRUCT, PTR, PTR }, INT }, \
/*        int posix_fadvise(int fd, off_t offset, off_t len, int advice); */ \
[250] = { "fadvise64", { INT, OFF, OFF, INT }, INT }, \
/*        void exit_group(int status); */ \
[252] = { "exit_group", { INT } }, \
/*        int lookup_dcookie(u64 cookie, char *buffer, size_t len); */ \
[253] = { "lookup_dcookie", { LONG, STR, LONG }, INT }, \
/*        int epoll_create(int size); */ \
[254] = { "epoll_create", { INT }, INT }, \
/*        int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event); */ \
[255] = { "epoll_ctl", { INT, INT, INT, PTR }, INT }, \
/*        int epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout); */ \
[256] = { "epoll_wait", { INT, PTR, INT, INT }, INT }, \
/*        int remap_file_pages(void *addr, size_t size, int prot, size_t pgoff, int flags); */ \
[257] = { "remap_file_pages", { PTR, LONG, INT, LONG, INT }, INT }, \
/*        pid_t set_tid_address(int *tidptr); */ \
[258] = { "set_tid_address", { PTR }, ID }, \
/*        int timer_create(clockid_t clockid, struct sigevent *sevp, timer_t *timerid); */ \
[259] = { "timer_create", { UNKNOWN_STRUCT, PTR, PTR }, INT }, \
/*        int timer_settime(timer_t timerid, int flags, const struct itimerspec *new_value, struct itimerspec *old_value); */ \
[260] = { "timer_settime", { UNKNOWN_STRUCT, INT, PTR, PTR }, INT }, \
/*        int timer_gettime(timer_t timerid, struct itimerspec *curr_value); */ \
[261] = { "timer_gettime", { UNKNOWN_STRUCT, PTR }, INT }, \
/*        int timer_getoverrun(timer_t timerid); */ \
[262] = { "timer_getoverrun", { UNKNOWN_STRUCT }, INT }, \
/*        int timer_delete(timer_t timerid); */ \
[263] = { "timer_delete", { UNKNOWN_STRUCT }, INT }, \
/*        int clock_settime(clockid_t clockid, const struct timespec *tp); */ \
[264] = { "clock_settime", { UNKNOWN_STRUCT, PTR }, INT }, \
/*        int clock_gettime(clockid_t clockid, struct timespec *tp); */ \
[265] = { "clock_gettime", { UNKNOWN_STRUCT, PTR }, INT }, \
/*        int clock_getres(clockid_t clockid, struct timespec *res); */ \
[266] = { "clock_getres", { UNKNOWN_STRUCT, PTR }, INT }, \
/*        int clock_nanosleep(clockid_t clockid, int flags, const struct timespec *request, struct timespec *remain); */ \
[267] = { "clock_nanosleep", { UNKNOWN_STRUCT, INT, PTR, PTR }, INT }, \
/*        int statfs(const char *path, struct statfs *buf); */ \
[268] = { "statfs64", { STR, PTR }, INT }, \
/*        int fstatfs(int fd, struct statfs *buf); */ \
[269] = { "fstatfs64", { INT, PTR }, INT }, \
/*        int tgkill(int tgid, int tid, int sig); */ \
[270] = { "tgkill", { INT, INT, INT }, INT }, \
/*        int utimes(const char *filename, const struct timeval times[2]); */ \
[271] = { "utimes", { STR, ARRAY | PTR }, INT }, \
/*        int posix_fadvise(int fd, off_t offset, off_t len, int advice); */ \
[272] = { "fadvise64_64", { INT, OFF, OFF, INT }, INT }, \
/* UNKNOWN PROTOTYPE */ \
[273] = { "vserver", { UNKNOWN }, UNKNOWN }, \
/*        long mbind(void *addr, unsigned long len, int mode, const unsigned long *nodemask, unsigned long maxnode, unsigned flags); */ \
[274] = { "mbind", { PTR, LONG, INT, PTR, LONG, INT }, LONG }, \
/*        long get_mempolicy(int *mode, unsigned long *nodemask, unsigned long maxnode, void *addr, unsigned long flags); */ \
[275] = { "get_mempolicy", { PTR, PTR, LONG, PTR, LONG }, LONG }, \
/*        long set_mempolicy(int mode, const unsigned long *nodemask, unsigned long maxnode); */ \
[276] = { "set_mempolicy", { INT, PTR, LONG }, LONG }, \
/*        mqd_t mq_open(const char *name, int oflag); */ \
[277] = { "mq_open", { STR, INT }, UNKNOWN_STRUCT }, \
/*        int mq_unlink(const char *name); */ \
[278] = { "mq_unlink", { STR }, INT }, \
/*        int mq_timedsend(mqd_t mqdes, const char *msg_ptr, size_t msg_len, unsigned int msg_prio, const struct timespec *abs_timeout); */ \
[279] = { "mq_timedsend", { UNKNOWN_STRUCT, STR, LONG, INT, PTR }, INT }, \
/*        ssize_t mq_timedreceive(mqd_t mqdes, char *msg_ptr, size_t msg_len, unsigned int *msg_prio, const struct timespec *abs_timeout); */ \
[280] = { "mq_timedreceive", { UNKNOWN_STRUCT, STR, LONG, PTR, PTR }, LONG }, \
/*        int mq_notify(mqd_t mqdes, const struct sigevent *sevp); */ \
[281] = { "mq_notify", { UNKNOWN_STRUCT, PTR }, INT }, \
/*        int mq_getsetattr(mqd_t mqdes, const struct mq_attr *newattr, struct mq_attr *oldattr); */ \
[282] = { "mq_getsetattr", { UNKNOWN_STRUCT, PTR, PTR }, INT }, \
/*        long kexec_load(unsigned long entry, unsigned long nr_segments, struct kexec_segment *segments, unsigned long flags); */ \
[283] = { "kexec_load", { LONG, LONG, PTR, LONG }, LONG }, \
/*        int waitid(idtype_t idtype, id_t id, siginfo_t *infop, int options); */ \
[284] = { "waitid", { UNKNOWN_STRUCT, ID, PTR, INT }, INT }, \
/*        key_serial_t add_key(const char *type, const char *description, const void *payload, size_t plen, key_serial_t keyring); */ \
[286] = { "add_key", { STR, STR, PTR, LONG, UNKNOWN_STRUCT }, UNKNOWN_STRUCT }, \
/*        key_serial_t request_key(const char *type, const char *description, const char *callout_info, key_serial_t dest_keyring); */ \
[287] = { "request_key", { STR, STR, STR, UNKNOWN_STRUCT }, UNKNOWN_STRUCT }, \
/*        long keyctl(int operation, ...); */ \
[288] = { "keyctl", { INT, UNKNOWN }, LONG }, \
/*        int ioprio_set(int which, int who, int ioprio); */ \
[289] = { "ioprio_set", { INT, INT, INT }, INT }, \
/*        int ioprio_get(int which, int who); */ \
[290] = { "ioprio_get", { INT, INT }, INT }, \
/*        int inotify_init(void); */ \
[291] = { "inotify_init", { }, INT }, \
/*        int inotify_add_watch(int fd, const char *pathname, uint32_t mask); */ \
[292] = { "inotify_add_watch", { INT, STR, INT }, INT }, \
/*        int inotify_rm_watch(int fd, int wd); */ \
[293] = { "inotify_rm_watch", { INT, INT }, INT }, \
/*        long migrate_pages(int pid, unsigned long maxnode, const unsigned long *old_nodes, const unsigned long *new_nodes); */ \
[294] = { "migrate_pages", { INT, LONG, PTR, PTR }, LONG }, \
/*        int openat(int dirfd, const char *pathname, int flags, mode_t mode); */ \
[295] = { "openat", { INT, STR, INT, MODE }, INT }, \
/*        int mkdirat(int dirfd, const char *pathname, mode_t mode); */ \
[296] = { "mkdirat", { INT, STR, MODE }, INT }, \
/*        int mknodat(int dirfd, const char *pathname, mode_t mode, dev_t dev); */ \
[297] = { "mknodat", { INT, STR, MODE, DEV }, INT }, \
/*        int fchownat(int dirfd, const char *pathname, uid_t owner, gid_t group, int flags); */ \
[298] = { "fchownat", { INT, STR, ID, ID, INT }, INT }, \
/*        int futimesat(int dirfd, const char *pathname, const struct timeval times[2]); */ \
[299] = { "futimesat", { INT, STR, ARRAY | UNKNOWN_STRUCT }, INT }, \
/*        int fstatat(int dirfd, const char *pathname, struct stat *statbuf, int flags); */ \
[300] = { "fstatat64", { INT, STR, PTR, INT }, INT }, \
/*        int unlinkat(int dirfd, const char *pathname, int flags); */ \
[301] = { "unlinkat", { INT, STR, INT }, INT }, \
/*        int renameat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath); */ \
[302] = { "renameat", { INT, STR, INT, STR }, INT }, \
/*        int linkat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, int flags); */ \
[303] = { "linkat", { INT, STR, INT, STR, INT }, INT }, \
/*        int symlinkat(const char *target, int newdirfd, const char *linkpath); */ \
[304] = { "symlinkat", { STR, INT, STR }, INT }, \
/*        ssize_t readlinkat(int dirfd, const char *pathname, char *buf, size_t bufsiz); */ \
[305] = { "readlinkat", { INT, STR, STR, LONG }, LONG }, \
/*        int fchmodat(int dirfd, const char *pathname, mode_t mode, int flags); */ \
[306] = { "fchmodat", { INT, STR, MODE, INT }, INT }, \
/*        int faccessat(int dirfd, const char *pathname, int mode, int flags); */ \
[307] = { "faccessat", { INT, STR, INT, INT }, INT }, \
/*        int pselect(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, const struct timespec *timeout, const sigset_t *sigmask); */ \
[308] = { "pselect6", { INT, PTR, PTR, PTR, PTR, PTR, PTR }, INT }, \
/*        int ppoll(struct pollfd *fds, nfds_t nfds, const struct timespec *tmo_p, const sigset_t *sigmask); */ \
[309] = { "ppoll", { PTR, UNKNOWN_STRUCT, PTR, PTR }, INT }, \
/*        int unshare(int flags); */ \
[310] = { "unshare", { INT }, INT }, \
/*        long set_robust_list(struct robust_list_head *head, size_t len); */ \
[311] = { "set_robust_list", { PTR, LONG }, LONG }, \
/*        long get_robust_list(int pid, struct robust_list_head **head_ptr, size_t *len_ptr); */ \
[312] = { "get_robust_list", { INT, PTR, PTR }, LONG }, \
/*        ssize_t splice(int fd_in, loff_t *off_in, int fd_out, loff_t *off_out, size_t len, unsigned int flags); */ \
[313] = { "splice", { INT, PTR, INT, PTR, LONG, INT }, LONG }, \
/*        int sync_file_range(int fd, off64_t offset, off64_t nbytes, unsigned int flags); */ \
[314] = { "sync_file_range", { INT, OFF, OFF, INT }, INT }, \
/*        ssize_t tee(int fd_in, int fd_out, size_t len, unsigned int flags); */ \
[315] = { "tee", { INT, INT, LONG, INT }, LONG }, \
/*        ssize_t vmsplice(int fd, const struct iovec *iov, unsigned long nr_segs, unsigned int flags); */ \
[316] = { "vmsplice", { INT, PTR, LONG, INT }, LONG }, \
/*        long move_pages(int pid, unsigned long count, void **pages, const int *nodes, int *status, int flags); */ \
[317] = { "move_pages", { INT, LONG, PTR, PTR, PTR, INT }, LONG }, \
/*        int getcpu(unsigned *cpu, unsigned *node, struct getcpu_cache *tcache); */ \
[318] = { "getcpu", { PTR, PTR, PTR }, INT }, \
/*        int epoll_pwait(int epfd, struct epoll_event *events, int maxevents, int timeout, const sigset_t *sigmask); */ \
[319] = { "epoll_pwait", { INT, PTR, INT, INT, PTR }, INT }, \
/*        int utimensat(int dirfd, const char *pathname, const struct timespec times[2], int flags); */ \
[320] = { "utimensat", { INT, STR, ARRAY | UNKNOWN_STRUCT, INT }, INT }, \
/*        int signalfd(int fd, const sigset_t *mask, int flags); */ \
[321] = { "signalfd", { INT, PTR, INT }, INT }, \
/*        int timerfd_create(int clockid, int flags); */ \
[322] = { "timerfd_create", { INT, INT }, INT }, \
/*        int eventfd(unsigned int initval, int flags); */ \
[323] = { "eventfd", { INT, INT }, INT }, \
/*        int fallocate(int fd, int mode, off_t offset, off_t len); */ \
[324] = { "fallocate", { INT, INT, OFF, OFF }, INT }, \
/*        int timerfd_settime(int fd, int flags, const struct itimerspec *new_value, struct itimerspec *old_value); */ \
[325] = { "timerfd_settime", { INT, INT, PTR, PTR }, INT }, \
/*        int timerfd_gettime(int fd, struct itimerspec *curr_value); */ \
[326] = { "timerfd_gettime", { INT, PTR }, INT }, \
/*        int signalfd(int fd, const sigset_t *mask, int flags); */ \
[327] = { "signalfd4", { INT, PTR, INT }, INT }, \
/*        int eventfd(unsigned int initval, int flags); */ \
[328] = { "eventfd2", { INT, INT }, INT }, \
/*        int epoll_create1(int flags); */ \
[329] = { "epoll_create1", { INT }, INT }, \
/*        int dup3(int oldfd, int newfd, int flags); */ \
[330] = { "dup3", { INT, INT, INT }, INT }, \
/*        int pipe2(int pipefd[2], int flags); */ \
[331] = { "pipe2", { ARRAY | INT, INT }, INT }, \
/*        int inotify_init1(int flags); */ \
[332] = { "inotify_init1", { INT }, INT }, \
/*        ssize_t preadv(int fd, const struct iovec *iov, int iovcnt, off_t offset); */ \
[333] = { "preadv", { INT, PTR, INT, OFF }, LONG }, \
/*        ssize_t pwritev(int fd, const struct iovec *iov, int iovcnt, off_t offset); */ \
[334] = { "pwritev", { INT, PTR, INT, OFF }, LONG }, \
/*        int rt_tgsigqueueinfo(pid_t tgid, pid_t tid, int sig, siginfo_t *info); */ \
[335] = { "rt_tgsigqueueinfo", { ID, ID, INT, PTR }, INT }, \
/*        int perf_event_open(struct perf_event_attr *attr, pid_t pid, int cpu, int group_fd, unsigned long flags); */ \
[336] = { "perf_event_open", { PTR, ID, INT, INT, LONG }, INT }, \
/*        int recvmmsg(int sockfd, struct mmsghdr *msgvec, unsigned int vlen, int flags, struct timespec *timeout); */ \
[337] = { "recvmmsg", { INT, PTR, INT, INT, PTR }, INT }, \
/*        int fanotify_init(unsigned int flags, unsigned int event_f_flags); */ \
[338] = { "fanotify_init", { INT, INT }, INT }, \
/*        int fanotify_mark(int fanotify_fd, unsigned int flags, uint64_t mask, int dirfd, const char *pathname); */ \
[339] = { "fanotify_mark", { INT, INT, INT, INT, STR }, INT }, \
/*        int prlimit(pid_t pid, int resource, const struct rlimit *new_limit, struct rlimit *old_limit); */ \
[340] = { "prlimit64", { ID, INT, PTR, PTR }, INT }, \
/*        int name_to_handle_at(int dirfd, const char *pathname, struct file_handle *handle, int *mount_id, int flags); */ \
[341] = { "name_to_handle_at", { INT, STR, PTR, PTR, INT }, INT }, \
/*        int open_by_handle_at(int mount_fd, struct file_handle *handle, int flags); */ \
[342] = { "open_by_handle_at", { INT, PTR, INT }, INT }, \
/*        int clock_adjtime(clockid_t clk_id, struct timex *buf); */ \
[343] = { "clock_adjtime", { UNKNOWN_STRUCT, PTR }, INT }, \
/*        int syncfs(int fd); */ \
[344] = { "syncfs", { INT }, INT }, \
/*        int sendmmsg(int sockfd, struct mmsghdr *msgvec, unsigned int vlen, int flags); */ \
[345] = { "sendmmsg", { INT, PTR, INT, INT }, INT }, \
/*        int setns(int fd, int nstype); */ \
[346] = { "setns", { INT, INT }, INT }, \
/*        ssize_t process_vm_readv(pid_t pid, const struct iovec *local_iov, unsigned long liovcnt, const struct iovec *remote_iov, unsigned long riovcnt, unsigned long flags); */ \
[347] = { "process_vm_readv", { ID, PTR, LONG, PTR, LONG, LONG }, LONG }, \
/*        ssize_t process_vm_writev(pid_t pid, const struct iovec *local_iov, unsigned long liovcnt, const struct iovec *remote_iov, unsigned long riovcnt, unsigned long flags); */ \
[348] = { "process_vm_writev", { ID, PTR, LONG, PTR, LONG, LONG }, LONG }, \
/*        int kcmp(pid_t pid1, pid_t pid2, int type, unsigned long idx1, unsigned long idx2); */ \
[349] = { "kcmp", { ID, ID, INT, LONG, LONG }, INT }, \
/*        int finit_module(int fd, const char *param_values, int flags); */ \
[350] = { "finit_module", { INT, STR, INT }, INT }, \
/*        int sched_setattr(pid_t pid, struct sched_attr *attr, unsigned int flags); */ \
[351] = { "sched_setattr", { ID, PTR, INT }, INT }, \
/*        int sched_getattr(pid_t pid, struct sched_attr *attr, unsigned int size, unsigned int flags); */ \
[352] = { "sched_getattr", { ID, PTR, INT, INT }, INT }, \
/*        int renameat2(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, unsigned int flags); */ \
[353] = { "renameat2", { INT, STR, INT, STR, INT }, INT }, \
/*        int seccomp(unsigned int operation, unsigned int flags, void *args); */ \
[354] = { "seccomp", { INT, INT, PTR }, INT }, \
/*        ssize_t getrandom(void *buf, size_t buflen, unsigned int flags); */ \
[355] = { "getrandom", { PTR, LONG, INT }, LONG }, \
/*        int memfd_create(const char *name, unsigned int flags); */ \
[356] = { "memfd_create", { STR, INT }, INT }, \
/*        int bpf(int cmd, union bpf_attr *attr, unsigned int size); */ \
[357] = { "bpf", { INT, PTR, INT }, INT }, \
/*        int execveat(int dirfd, const char *pathname, char *const argv[], char *const envp[], int flags); */ \
[358] = { "execveat", { INT, STR, ARRAY | STR, ARRAY | STR, INT }, INT }, \
/*        int socket(int domain, int type, int protocol); */ \
[359] = { "socket", { INT, INT, INT }, INT }, \
/*        int socketpair(int domain, int type, int protocol, int sv[2]); */ \
[360] = { "socketpair", { INT, INT, INT, ARRAY | INT }, INT }, \
/*        int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen); */ \
[361] = { "bind", { INT, PTR, UNKNOWN_STRUCT }, INT }, \
/*        int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen); */ \
[362] = { "connect", { INT, PTR, UNKNOWN_STRUCT }, INT }, \
/*        int listen(int sockfd, int backlog); */ \
[363] = { "listen", { INT, INT }, INT }, \
/*        int accept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags); */ \
[364] = { "accept4", { INT, PTR, PTR, INT }, INT }, \
/*        int getsockopt(int sockfd, int level, int optname, void *optval, socklen_t *optlen); */ \
[365] = { "getsockopt", { INT, INT, INT, PTR, PTR }, INT }, \
/*        int setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen); */ \
[366] = { "setsockopt", { INT, INT, INT, PTR, UNKNOWN_STRUCT }, INT }, \
/*        int getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen); */ \
[367] = { "getsockname", { INT, PTR, PTR }, INT }, \
/*        int getpeername(int sockfd, struct sockaddr *addr, socklen_t *addrlen); */ \
[368] = { "getpeername", { INT, PTR, PTR }, INT }, \
/*        ssize_t sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen); */ \
[369] = { "sendto", { INT, PTR, LONG, INT, PTR, UNKNOWN_STRUCT }, LONG }, \
/*        ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags); */ \
[370] = { "sendmsg", { INT, PTR, INT }, LONG }, \
/*        ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen); */ \
[371] = { "recvfrom", { INT, PTR, LONG, INT, PTR, PTR }, LONG }, \
/*        ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags); */ \
[372] = { "recvmsg", { INT, PTR, INT }, LONG }, \
/*        int shutdown(int sockfd, int how); */ \
[373] = { "shutdown", { INT, INT }, INT }, \
/*        int userfaultfd(int flags); */ \
[374] = { "userfaultfd", { INT }, INT }, \
/*        int membarrier(int cmd, unsigned int flags, int cpu_id); */ \
[375] = { "membarrier", { INT, INT, INT }, INT }, \
/*        int mlock2(const void *addr, size_t len, int flags); */ \
[376] = { "mlock2", { PTR, LONG, INT }, INT }, \
/*        ssize_t copy_file_range(int fd_in, loff_t *off_in, int fd_out, loff_t *off_out, size_t len, unsigned int flags); */ \
[377] = { "copy_file_range", { INT, PTR, INT, PTR, LONG, INT }, LONG }, \
/*        ssize_t preadv2(int fd, const struct iovec *iov, int iovcnt, off_t offset, int flags); */ \
[378] = { "preadv2", { INT, PTR, INT, OFF, INT }, LONG }, \
/*        ssize_t pwritev2(int fd, const struct iovec *iov, int iovcnt, off_t offset, int flags); */ \
[379] = { "pwritev2", { INT, PTR, INT, OFF, INT }, LONG }, \
/*        int pkey_mprotect(void *addr, size_t len, int prot, int pkey); */ \
[380] = { "pkey_mprotect", { PTR, LONG, INT, INT }, INT }, \
/*        int pkey_alloc(unsigned int flags, unsigned int access_rights); */ \
[381] = { "pkey_alloc", { INT, INT }, INT }, \
/*        int pkey_free(int pkey); */ \
[382] = { "pkey_free", { INT }, INT }, \
/*        int statx(int dirfd, const char *pathname, int flags, unsigned int mask, struct statx *statxbuf); */ \
[383] = { "statx", { INT, STR, INT, INT, PTR }, INT }, \
/*        int arch_prctl(int code, unsigned long *addr); */ \
[384] = { "arch_prctl", { INT, PTR }, INT }, \
/* UNKNOWN PROTOTYPE */ \
[385] = { "io_pgetevents", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[386] = { "rseq", { UNKNOWN }, UNKNOWN }, \
/*        int semget(key_t key, int nsems, int semflg); */ \
[393] = { "semget", { UNKNOWN_STRUCT, INT, INT }, INT }, \
/*        int semctl(int semid, int semnum, int cmd, ...); */ \
[394] = { "semctl", { INT, INT, INT, UNKNOWN }, INT }, \
/*        int shmget(key_t key, size_t size, int shmflg); */ \
[395] = { "shmget", { UNKNOWN_STRUCT, LONG, INT }, INT }, \
/*        int shmctl(int shmid, int cmd, struct shmid_ds *buf); */ \
[396] = { "shmctl", { INT, INT, PTR }, INT }, \
/*        void *shmat(int shmid, const void *shmaddr, int shmflg); */ \
[397] = { "shmat", { INT, PTR, INT }, PTR }, \
/*        int shmdt(const void *shmaddr); */ \
[398] = { "shmdt", { PTR }, INT }, \
/*        int msgget(key_t key, int msgflg); */ \
[399] = { "msgget", { UNKNOWN_STRUCT, INT }, INT }, \
/*        int msgsnd(int msqid, const void *msgp, size_t msgsz, int msgflg); */ \
[400] = { "msgsnd", { INT, PTR, LONG, INT }, INT }, \
/*        ssize_t msgrcv(int msqid, void *msgp, size_t msgsz, long msgtyp, int msgflg); */ \
[401] = { "msgrcv", { INT, PTR, LONG, LONG, INT }, LONG }, \
/*        int msgctl(int msqid, int cmd, struct msqid_ds *buf); */ \
[402] = { "msgctl", { INT, INT, PTR }, INT }, \
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
/*        int pidfd_send_signal(int pidfd, int sig, siginfo_t *info, unsigned int flags); */ \
[424] = { "pidfd_send_signal", { INT, INT, PTR, INT }, INT }, \
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
[434] = { "pidfd_open", { ID, INT }, INT }, \
/*        long clone3(struct clone_args *cl_args, size_t size); */ \
[435] = { "clone3", { PTR, LONG }, LONG }, \
/* UNKNOWN PROTOTYPE */ \
[436] = { "close_range", { UNKNOWN }, UNKNOWN }, \
/*        long openat2(int dirfd, const char *pathname, struct open_how *how, size_t size); */ \
[437] = { "openat2", { INT, STR, PTR, LONG }, LONG }, \
/*        int pidfd_getfd(int pidfd, int targetfd, unsigned int flags); */ \
[438] = { "pidfd_getfd", { INT, INT, INT }, INT }, \
/*        int faccessat2(int dirfd, const char *pathname, int mode, int flags); */ \
[439] = { "faccessat2", { INT, STR, INT, INT }, INT }, \
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
