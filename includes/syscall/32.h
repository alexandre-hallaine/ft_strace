#pragma once
#include "types.h"

#define SYSCALL_TABLE_32 { \
/* restart_syscall(void); */ \
[0] = { "restart_syscall", { UNKNOWN }, UNKNOWN }, \
/* _exit(int status); */ \
[1] = { "exit", { UNKNOWN }, UNKNOWN }, \
/* fork(void); */ \
[2] = { "fork", { UNKNOWN }, UNKNOWN }, \
/* read(int fd, void *buf, size_t count); */ \
[3] = { "read", { UNKNOWN }, UNKNOWN }, \
/* write(int fd, const void *buf, size_t count); */ \
[4] = { "write", { UNKNOWN }, UNKNOWN }, \
/* open(const char *pathname, int flags);
open(const char *pathname, int flags, mode_t mode);
openat(int dirfd, const char *pathname, int flags);
openat(int dirfd, const char *pathname, int flags, mode_t mode); */ \
[5] = { "open", { UNKNOWN }, UNKNOWN }, \
/* close(int fd); */ \
[6] = { "close", { UNKNOWN }, UNKNOWN }, \
/* waitpid(pid_t pid, int *wstatus, int options); */ \
[7] = { "waitpid", { UNKNOWN }, UNKNOWN }, \
/* creat(const char *pathname, mode_t mode); */ \
[8] = { "creat", { UNKNOWN }, UNKNOWN }, \
/* link(const char *oldpath, const char *newpath); */ \
[9] = { "link", { UNKNOWN }, UNKNOWN }, \
/* unlink(const char *pathname);
unlinkat(int dirfd, const char *pathname, int flags); */ \
[10] = { "unlink", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[11] = { "execve", { UNKNOWN }, UNKNOWN }, \
/* chdir(const char *path);
fchdir(int fd); */ \
[12] = { "chdir", { UNKNOWN }, UNKNOWN }, \
/* time(time_t *tloc); */ \
[13] = { "time", { UNKNOWN }, UNKNOWN }, \
/* mknod(const char *pathname, mode_t mode, dev_t dev);
mknodat(int dirfd, const char *pathname, mode_t mode, dev_t dev); */ \
[14] = { "mknod", { UNKNOWN }, UNKNOWN }, \
/* chmod(const char *pathname, mode_t mode);
fchmod(int fd, mode_t mode);
fchmodat(int dirfd, const char *pathname, mode_t mode, int flags); */ \
[15] = { "chmod", { UNKNOWN }, UNKNOWN }, \
/* lchown(const char *pathname, uid_t owner, gid_t group); */ \
[16] = { "lchown", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[17] = { "break", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[18] = { "oldstat", { UNKNOWN }, UNKNOWN }, \
/* lseek(int fd, off_t offset, int whence); */ \
[19] = { "lseek", { UNKNOWN }, UNKNOWN }, \
/* getpid(void); */ \
[20] = { "getpid", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[21] = { "mount", { UNKNOWN }, UNKNOWN }, \
/* umount(const char *target); */ \
[22] = { "umount", { UNKNOWN }, UNKNOWN }, \
/* setuid(uid_t uid); */ \
[23] = { "setuid", { UNKNOWN }, UNKNOWN }, \
/* getuid(void); */ \
[24] = { "getuid", { UNKNOWN }, UNKNOWN }, \
/* stime(const time_t *t); */ \
[25] = { "stime", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[26] = { "ptrace", { UNKNOWN }, UNKNOWN }, \
/* alarm(unsigned int seconds); */ \
[27] = { "alarm", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[28] = { "oldfstat", { UNKNOWN }, UNKNOWN }, \
/* pause(void); */ \
[29] = { "pause", { UNKNOWN }, UNKNOWN }, \
/* utime(const char *filename, const struct utimbuf *times);
utimes(const char *filename, const struct timeval times[2]); */ \
[30] = { "utime", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[31] = { "stty", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[32] = { "gtty", { UNKNOWN }, UNKNOWN }, \
/* access(const char *pathname, int mode);
faccessat(int dirfd, const char *pathname, int mode, int flags); */ \
[33] = { "access", { UNKNOWN }, UNKNOWN }, \
/* nice(int inc); */ \
[34] = { "nice", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[35] = { "ftime", { UNKNOWN }, UNKNOWN }, \
/* sync(void);
syncfs(int fd); */ \
[36] = { "sync", { UNKNOWN }, UNKNOWN }, \
/* kill(pid_t pid, int sig); */ \
[37] = { "kill", { UNKNOWN }, UNKNOWN }, \
/* rename(const char *oldpath, const char *newpath); */ \
[38] = { "rename", { UNKNOWN }, UNKNOWN }, \
/* mkdir(const char *pathname, mode_t mode);
mkdirat(int dirfd, const char *pathname, mode_t mode); */ \
[39] = { "mkdir", { UNKNOWN }, UNKNOWN }, \
/* rmdir(const char *pathname); */ \
[40] = { "rmdir", { UNKNOWN }, UNKNOWN }, \
/* dup(int oldfd); */ \
[41] = { "dup", { UNKNOWN }, UNKNOWN }, \
/* pipe();
pipe(int pipefd[2]); */ \
[42] = { "pipe", { UNKNOWN }, UNKNOWN }, \
/* times(struct tms *buf); */ \
[43] = { "times", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[44] = { "prof", { UNKNOWN }, UNKNOWN }, \
/* brk(void *addr);
sbrk(intptr_t increment); */ \
[45] = { "brk", { UNKNOWN }, UNKNOWN }, \
/* setgid(gid_t gid); */ \
[46] = { "setgid", { UNKNOWN }, UNKNOWN }, \
/* getgid(void); */ \
[47] = { "getgid", { UNKNOWN }, UNKNOWN }, \
/* signal(int signum, sighandler_t handler); */ \
[48] = { "signal", { UNKNOWN }, UNKNOWN }, \
/* geteuid(void); */ \
[49] = { "geteuid", { UNKNOWN }, UNKNOWN }, \
/* getegid(void); */ \
[50] = { "getegid", { UNKNOWN }, UNKNOWN }, \
/* acct(const char *filename); */ \
[51] = { "acct", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[52] = { "umount2", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[53] = { "lock", { UNKNOWN }, UNKNOWN }, \
/* ioctl(int fd, unsigned long request, ...); */ \
[54] = { "ioctl", { UNKNOWN }, UNKNOWN }, \
/* fcntl(int fd, int cmd, ...  ); */ \
[55] = { "fcntl", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[56] = { "mpx", { UNKNOWN }, UNKNOWN }, \
/* setpgid(pid_t pid, pid_t pgid); */ \
[57] = { "setpgid", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[58] = { "ulimit", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[59] = { "oldolduname", { UNKNOWN }, UNKNOWN }, \
/* umask(mode_t mask); */ \
[60] = { "umask", { UNKNOWN }, UNKNOWN }, \
/* chroot(const char *path); */ \
[61] = { "chroot", { UNKNOWN }, UNKNOWN }, \
/* ustat(dev_t dev, struct ustat *ubuf); */ \
[62] = { "ustat", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[63] = { "dup2", { UNKNOWN }, UNKNOWN }, \
/* getppid(void); */ \
[64] = { "getppid", { UNKNOWN }, UNKNOWN }, \
/* getpgrp(void);
getpgrp(pid_t pid); */ \
[65] = { "getpgrp", { UNKNOWN }, UNKNOWN }, \
/* setsid(void); */ \
[66] = { "setsid", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[67] = { "sigaction", { UNKNOWN }, UNKNOWN }, \
/* sgetmask(void); */ \
[68] = { "sgetmask", { UNKNOWN }, UNKNOWN }, \
/* ssetmask(long newmask); */ \
[69] = { "ssetmask", { UNKNOWN }, UNKNOWN }, \
/* setreuid(uid_t ruid, uid_t euid); */ \
[70] = { "setreuid", { UNKNOWN }, UNKNOWN }, \
/* setregid(gid_t rgid, gid_t egid); */ \
[71] = { "setregid", { UNKNOWN }, UNKNOWN }, \
/* sigsuspend(const sigset_t *mask); */ \
[72] = { "sigsuspend", { UNKNOWN }, UNKNOWN }, \
/* sigpending(sigset_t *set); */ \
[73] = { "sigpending", { UNKNOWN }, UNKNOWN }, \
/* sethostname(const char *name, size_t len); */ \
[74] = { "sethostname", { UNKNOWN }, UNKNOWN }, \
/* setrlimit(int resource, const struct rlimit *rlim); */ \
[75] = { "setrlimit", { UNKNOWN }, UNKNOWN }, \
/* getrlimit(int resource, struct rlimit *rlim); */ \
[76] = { "getrlimit", { UNKNOWN }, UNKNOWN }, \
/* getrusage(int who, struct rusage *usage); */ \
[77] = { "getrusage", { UNKNOWN }, UNKNOWN }, \
/* gettimeofday(struct timeval *tv, struct timezone *tz); */ \
[78] = { "gettimeofday", { UNKNOWN }, UNKNOWN }, \
/* settimeofday(const struct timeval *tv, const struct timezone *tz); */ \
[79] = { "settimeofday", { UNKNOWN }, UNKNOWN }, \
/* getgroups(int size, gid_t list[]); */ \
[80] = { "getgroups", { UNKNOWN }, UNKNOWN }, \
/* setgroups(size_t size, const gid_t *list); */ \
[81] = { "setgroups", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[82] = { "select", { UNKNOWN }, UNKNOWN }, \
/* symlink(const char *target, const char *linkpath);
symlinkat(const char *target, int newdirfd, const char *linkpath); */ \
[83] = { "symlink", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[84] = { "oldlstat", { UNKNOWN }, UNKNOWN }, \
/* readlink(const char *pathname, char *buf, size_t bufsiz); */ \
[85] = { "readlink", { UNKNOWN }, UNKNOWN }, \
/* uselib(const char *library); */ \
[86] = { "uselib", { UNKNOWN }, UNKNOWN }, \
/* swapon(const char *path, int swapflags); */ \
[87] = { "swapon", { UNKNOWN }, UNKNOWN }, \
/* reboot(int magic, int magic2, int cmd, void *arg);
reboot(int cmd); */ \
[88] = { "reboot", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[89] = { "readdir", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[90] = { "mmap", { UNKNOWN }, UNKNOWN }, \
/* munmap(void *addr, size_t length); */ \
[91] = { "munmap", { UNKNOWN }, UNKNOWN }, \
/* truncate(const char *path, off_t length);
ftruncate(int fd, off_t length); */ \
[92] = { "truncate", { UNKNOWN }, UNKNOWN }, \
/* ftruncate(int fd, off_t length); */ \
[93] = { "ftruncate", { UNKNOWN }, UNKNOWN }, \
/* fchmod(int fd, mode_t mode);
fchmodat(int dirfd, const char *pathname, mode_t mode, int flags); */ \
[94] = { "fchmod", { UNKNOWN }, UNKNOWN }, \
/* fchown(int fd, uid_t owner, gid_t group); */ \
[95] = { "fchown", { UNKNOWN }, UNKNOWN }, \
/* getpriority(int which, id_t who); */ \
[96] = { "getpriority", { UNKNOWN }, UNKNOWN }, \
/* setpriority(int which, id_t who, int prio); */ \
[97] = { "setpriority", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[98] = { "profil", { UNKNOWN }, UNKNOWN }, \
/* statfs(const char *path, struct statfs *buf);
fstatfs(int fd, struct statfs *buf); */ \
[99] = { "statfs", { UNKNOWN }, UNKNOWN }, \
/* fstatfs(int fd, struct statfs *buf); */ \
[100] = { "fstatfs", { UNKNOWN }, UNKNOWN }, \
/* ioperm(unsigned long from, unsigned long num, int turn_on); */ \
[101] = { "ioperm", { UNKNOWN }, UNKNOWN }, \
/* socketcall(int call, unsigned long *args); */ \
[102] = { "socketcall", { UNKNOWN }, UNKNOWN }, \
/* syslog(int type, char *bufp, int len); */ \
[103] = { "syslog", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[104] = { "setitimer", { UNKNOWN }, UNKNOWN }, \
/* getitimer(int which, struct itimerval *curr_value); */ \
[105] = { "getitimer", { UNKNOWN }, UNKNOWN }, \
/* stat(const char *pathname, struct stat *statbuf);
fstat(int fd, struct stat *statbuf);
lstat(const char *pathname, struct stat *statbuf); */ \
[106] = { "stat", { UNKNOWN }, UNKNOWN }, \
/* lstat(const char *pathname, struct stat *statbuf); */ \
[107] = { "lstat", { UNKNOWN }, UNKNOWN }, \
/* fstat(int fd, struct stat *statbuf); */ \
[108] = { "fstat", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[109] = { "olduname", { UNKNOWN }, UNKNOWN }, \
/* iopl(int level); */ \
[110] = { "iopl", { UNKNOWN }, UNKNOWN }, \
/* vhangup(void); */ \
[111] = { "vhangup", { UNKNOWN }, UNKNOWN }, \
/* idle(void); */ \
[112] = { "idle", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[113] = { "vm86old", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[114] = { "wait4", { UNKNOWN }, UNKNOWN }, \
/* swapoff(const char *path); */ \
[115] = { "swapoff", { UNKNOWN }, UNKNOWN }, \
/* sysinfo(struct sysinfo *info); */ \
[116] = { "sysinfo", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[117] = { "ipc", { UNKNOWN }, UNKNOWN }, \
/* fsync(int fd); */ \
[118] = { "fsync", { UNKNOWN }, UNKNOWN }, \
/* sigreturn(...); */ \
[119] = { "sigreturn", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[120] = { "clone", { UNKNOWN }, UNKNOWN }, \
/* setdomainname(const char *name, size_t len); */ \
[121] = { "setdomainname", { UNKNOWN }, UNKNOWN }, \
/* uname(struct utsname *buf); */ \
[122] = { "uname", { UNKNOWN }, UNKNOWN }, \
/* modify_ldt(int func, void *ptr, unsigned long bytecount); */ \
[123] = { "modify_ldt", { UNKNOWN }, UNKNOWN }, \
/* adjtimex(struct timex *buf); */ \
[124] = { "adjtimex", { UNKNOWN }, UNKNOWN }, \
/* mprotect(void *addr, size_t len, int prot);
pkey_mprotect(void *addr, size_t len, int prot, int pkey); */ \
[125] = { "mprotect", { UNKNOWN }, UNKNOWN }, \
/* sigprocmask(int how, const sigset_t *set, sigset_t *oldset); */ \
[126] = { "sigprocmask", { UNKNOWN }, UNKNOWN }, \
/* create_module(const char *name, size_t size); */ \
[127] = { "create_module", { UNKNOWN }, UNKNOWN }, \
/* finit_module(); */ \
[128] = { "init_module", { UNKNOWN }, UNKNOWN }, \
/* delete_module(const char *name, int flags); */ \
[129] = { "delete_module", { UNKNOWN }, UNKNOWN }, \
/* get_kernel_syms(struct kernel_sym *table); */ \
[130] = { "get_kernel_syms", { UNKNOWN }, UNKNOWN }, \
/* quotactl(int cmd, const char *special, int id, caddr_t addr); */ \
[131] = { "quotactl", { UNKNOWN }, UNKNOWN }, \
/* getpgid(pid_t pid); */ \
[132] = { "getpgid", { UNKNOWN }, UNKNOWN }, \
/* fchdir(int fd); */ \
[133] = { "fchdir", { UNKNOWN }, UNKNOWN }, \
/* bdflush(int func, long *address);
bdflush(int func, long data); */ \
[134] = { "bdflush", { UNKNOWN }, UNKNOWN }, \
/* sysfs(int option, const char *fsname);
sysfs(int option, unsigned int fs_index, char *buf);
sysfs(int option); */ \
[135] = { "sysfs", { UNKNOWN }, UNKNOWN }, \
/* personality(unsigned long persona); */ \
[136] = { "personality", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[137] = { "afs_syscall", { UNKNOWN }, UNKNOWN }, \
/* setfsuid(uid_t fsuid); */ \
[138] = { "setfsuid", { UNKNOWN }, UNKNOWN }, \
/* setfsgid(uid_t fsgid); */ \
[139] = { "setfsgid", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[140] = { "_llseek", { UNKNOWN }, UNKNOWN }, \
/* getdents(); */ \
[141] = { "getdents", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[142] = { "_newselect", { UNKNOWN }, UNKNOWN }, \
/* flock(int fd, int operation); */ \
[143] = { "flock", { UNKNOWN }, UNKNOWN }, \
/* msync(void *addr, size_t length, int flags); */ \
[144] = { "msync", { UNKNOWN }, UNKNOWN }, \
/* readv(int fd, const struct iovec *iov, int iovcnt); */ \
[145] = { "readv", { UNKNOWN }, UNKNOWN }, \
/* writev(int fd, const struct iovec *iov, int iovcnt); */ \
[146] = { "writev", { UNKNOWN }, UNKNOWN }, \
/* getsid(pid_t pid); */ \
[147] = { "getsid", { UNKNOWN }, UNKNOWN }, \
/* fdatasync(int fd); */ \
[148] = { "fdatasync", { UNKNOWN }, UNKNOWN }, \
/* _sysctl(struct __sysctl_args *args); */ \
[149] = { "_sysctl", { UNKNOWN }, UNKNOWN }, \
/* mlock(const void *addr, size_t len);
mlockall(int flags); */ \
[150] = { "mlock", { UNKNOWN }, UNKNOWN }, \
/* munlock(const void *addr, size_t len);
munlockall(void); */ \
[151] = { "munlock", { UNKNOWN }, UNKNOWN }, \
/* mlockall(int flags); */ \
[152] = { "mlockall", { UNKNOWN }, UNKNOWN }, \
/* munlockall(void); */ \
[153] = { "munlockall", { UNKNOWN }, UNKNOWN }, \
/* sched_setparam(pid_t pid, const struct sched_param *param); */ \
[154] = { "sched_setparam", { UNKNOWN }, UNKNOWN }, \
/* sched_getparam(pid_t pid, struct sched_param *param); */ \
[155] = { "sched_getparam", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[156] = { "sched_setscheduler", { UNKNOWN }, UNKNOWN }, \
/* sched_getscheduler(pid_t pid); */ \
[157] = { "sched_getscheduler", { UNKNOWN }, UNKNOWN }, \
/* sched_yield(void); */ \
[158] = { "sched_yield", { UNKNOWN }, UNKNOWN }, \
/* sched_get_priority_max(int policy); */ \
[159] = { "sched_get_priority_max", { UNKNOWN }, UNKNOWN }, \
/* sched_get_priority_min(int policy); */ \
[160] = { "sched_get_priority_min", { UNKNOWN }, UNKNOWN }, \
/* sched_rr_get_interval(pid_t pid, struct timespec *tp); */ \
[161] = { "sched_rr_get_interval", { UNKNOWN }, UNKNOWN }, \
/* nanosleep(const struct timespec *req, struct timespec *rem); */ \
[162] = { "nanosleep", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[163] = { "mremap", { UNKNOWN }, UNKNOWN }, \
/* setresuid(uid_t ruid, uid_t euid, uid_t suid); */ \
[164] = { "setresuid", { UNKNOWN }, UNKNOWN }, \
/* getresuid(uid_t *ruid, uid_t *euid, uid_t *suid); */ \
[165] = { "getresuid", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[166] = { "vm86", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[167] = { "query_module", { UNKNOWN }, UNKNOWN }, \
/* poll(struct pollfd *fds, nfds_t nfds, int timeout); */ \
[168] = { "poll", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[169] = { "nfsservctl", { UNKNOWN }, UNKNOWN }, \
/* setresgid(gid_t rgid, gid_t egid, gid_t sgid); */ \
[170] = { "setresgid", { UNKNOWN }, UNKNOWN }, \
/* getresgid(gid_t *rgid, gid_t *egid, gid_t *sgid); */ \
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
/* rt_sigqueueinfo(pid_t tgid, int sig, siginfo_t *info); */ \
[178] = { "rt_sigqueueinfo", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[179] = { "rt_sigsuspend", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[180] = { "pread64", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[181] = { "pwrite64", { UNKNOWN }, UNKNOWN }, \
/* chown(const char *pathname, uid_t owner, gid_t group);
fchown(int fd, uid_t owner, gid_t group);
lchown(const char *pathname, uid_t owner, gid_t group); */ \
[182] = { "chown", { UNKNOWN }, UNKNOWN }, \
/* getcwd(char *buf, size_t size); */ \
[183] = { "getcwd", { UNKNOWN }, UNKNOWN }, \
/* capget(cap_user_header_t hdrp, cap_user_data_t datap); */ \
[184] = { "capget", { UNKNOWN }, UNKNOWN }, \
/* capset(cap_user_header_t hdrp, const cap_user_data_t datap); */ \
[185] = { "capset", { UNKNOWN }, UNKNOWN }, \
/* sigaltstack(const stack_t *ss, stack_t *old_ss); */ \
[186] = { "sigaltstack", { UNKNOWN }, UNKNOWN }, \
/* sendfile(int out_fd, int in_fd, off_t *offset, size_t count); */ \
[187] = { "sendfile", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[188] = { "getpmsg", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[189] = { "putpmsg", { UNKNOWN }, UNKNOWN }, \
/* vfork(void); */ \
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
/* pivot_root(const char *new_root, const char *put_old); */ \
[217] = { "pivot_root", { UNKNOWN }, UNKNOWN }, \
/* mincore(void *addr, size_t length, unsigned char *vec); */ \
[218] = { "mincore", { UNKNOWN }, UNKNOWN }, \
/* madvise(void *addr, size_t length, int advice); */ \
[219] = { "madvise", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[220] = { "getdents64", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[221] = { "fcntl64", { UNKNOWN }, UNKNOWN }, \
/* gettid(void); */ \
[224] = { "gettid", { UNKNOWN }, UNKNOWN }, \
/* readahead(int fd, off64_t offset, size_t count); */ \
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
/* listxattr(const char *path, char *list, size_t size);
llistxattr(const char *path, char *list, size_t size);
flistxattr(int fd, char *list, size_t size); */ \
[232] = { "listxattr", { UNKNOWN }, UNKNOWN }, \
/* llistxattr(const char *path, char *list, size_t size); */ \
[233] = { "llistxattr", { UNKNOWN }, UNKNOWN }, \
/* flistxattr(int fd, char *list, size_t size); */ \
[234] = { "flistxattr", { UNKNOWN }, UNKNOWN }, \
/* removexattr(const char *path, const char *name);
lremovexattr(const char *path, const char *name);
fremovexattr(int fd, const char *name); */ \
[235] = { "removexattr", { UNKNOWN }, UNKNOWN }, \
/* lremovexattr(const char *path, const char *name); */ \
[236] = { "lremovexattr", { UNKNOWN }, UNKNOWN }, \
/* fremovexattr(int fd, const char *name); */ \
[237] = { "fremovexattr", { UNKNOWN }, UNKNOWN }, \
/* tkill(int tid, int sig);
tkill(); */ \
[238] = { "tkill", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[239] = { "sendfile64", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[240] = { "futex", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[241] = { "sched_setaffinity", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[242] = { "sched_getaffinity", { UNKNOWN }, UNKNOWN }, \
/* set_thread_area(struct user_desc *u_info);
set_thread_area(unsigned long tp);
set_thread_area(unsigned long addr); */ \
[243] = { "set_thread_area", { UNKNOWN }, UNKNOWN }, \
/* get_thread_area(struct user_desc *u_info);
get_thread_area(void); */ \
[244] = { "get_thread_area", { UNKNOWN }, UNKNOWN }, \
/* io_setup(unsigned nr_events, aio_context_t *ctx_idp); */ \
[245] = { "io_setup", { UNKNOWN }, UNKNOWN }, \
/* io_destroy(aio_context_t ctx_id); */ \
[246] = { "io_destroy", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[247] = { "io_getevents", { UNKNOWN }, UNKNOWN }, \
/* io_submit(aio_context_t ctx_id, long nr, struct iocb **iocbpp); */ \
[248] = { "io_submit", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[249] = { "io_cancel", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[250] = { "fadvise64", { UNKNOWN }, UNKNOWN }, \
/* exit_group(int status); */ \
[252] = { "exit_group", { UNKNOWN }, UNKNOWN }, \
/* lookup_dcookie(u64 cookie, char *buffer, size_t len); */ \
[253] = { "lookup_dcookie", { UNKNOWN }, UNKNOWN }, \
/* epoll_create(int size); */ \
[254] = { "epoll_create", { UNKNOWN }, UNKNOWN }, \
/* epoll_ctl(int epfd, int op, int fd, struct epoll_event *event); */ \
[255] = { "epoll_ctl", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[256] = { "epoll_wait", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[257] = { "remap_file_pages", { UNKNOWN }, UNKNOWN }, \
/* set_tid_address(int *tidptr); */ \
[258] = { "set_tid_address", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[259] = { "timer_create", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[260] = { "timer_settime", { UNKNOWN }, UNKNOWN }, \
/* timer_gettime(timer_t timerid, struct itimerspec *curr_value); */ \
[261] = { "timer_gettime", { UNKNOWN }, UNKNOWN }, \
/* timer_getoverrun(timer_t timerid); */ \
[262] = { "timer_getoverrun", { UNKNOWN }, UNKNOWN }, \
/* timer_delete(timer_t timerid); */ \
[263] = { "timer_delete", { UNKNOWN }, UNKNOWN }, \
/* clock_settime(clockid_t clockid, const struct timespec *tp); */ \
[264] = { "clock_settime", { UNKNOWN }, UNKNOWN }, \
/* clock_gettime(clockid_t clockid, struct timespec *tp); */ \
[265] = { "clock_gettime", { UNKNOWN }, UNKNOWN }, \
/* clock_getres(clockid_t clockid, struct timespec *res); */ \
[266] = { "clock_getres", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[267] = { "clock_nanosleep", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[268] = { "statfs64", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[269] = { "fstatfs64", { UNKNOWN }, UNKNOWN }, \
/* tgkill(int tgid, int tid, int sig); */ \
[270] = { "tgkill", { UNKNOWN }, UNKNOWN }, \
/* utimes(const char *filename, const struct timeval times[2]); */ \
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
/* mq_open(const char *name, int oflag); */ \
[277] = { "mq_open", { UNKNOWN }, UNKNOWN }, \
/* mq_unlink(const char *name); */ \
[278] = { "mq_unlink", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[279] = { "mq_timedsend", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[280] = { "mq_timedreceive", { UNKNOWN }, UNKNOWN }, \
/* mq_notify(mqd_t mqdes, const struct sigevent *sevp); */ \
[281] = { "mq_notify", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[282] = { "mq_getsetattr", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[283] = { "kexec_load", { UNKNOWN }, UNKNOWN }, \
/* waitid(idtype_t idtype, id_t id, siginfo_t *infop, int options); */ \
[284] = { "waitid", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[286] = { "add_key", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[287] = { "request_key", { UNKNOWN }, UNKNOWN }, \
/* keyctl(int operation, ...); */ \
[288] = { "keyctl", { UNKNOWN }, UNKNOWN }, \
/* ioprio_set(int which, int who, int ioprio); */ \
[289] = { "ioprio_set", { UNKNOWN }, UNKNOWN }, \
/* ioprio_get(int which, int who); */ \
[290] = { "ioprio_get", { UNKNOWN }, UNKNOWN }, \
/* inotify_init(void); */ \
[291] = { "inotify_init", { UNKNOWN }, UNKNOWN }, \
/* inotify_add_watch(int fd, const char *pathname, uint32_t mask); */ \
[292] = { "inotify_add_watch", { UNKNOWN }, UNKNOWN }, \
/* inotify_rm_watch(int fd, int wd); */ \
[293] = { "inotify_rm_watch", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[294] = { "migrate_pages", { UNKNOWN }, UNKNOWN }, \
/* openat(int dirfd, const char *pathname, int flags);
openat(int dirfd, const char *pathname, int flags, mode_t mode); */ \
[295] = { "openat", { UNKNOWN }, UNKNOWN }, \
/* mkdirat(int dirfd, const char *pathname, mode_t mode); */ \
[296] = { "mkdirat", { UNKNOWN }, UNKNOWN }, \
/* mknodat(int dirfd, const char *pathname, mode_t mode, dev_t dev); */ \
[297] = { "mknodat", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[298] = { "fchownat", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[299] = { "futimesat", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[300] = { "fstatat64", { UNKNOWN }, UNKNOWN }, \
/* unlinkat(int dirfd, const char *pathname, int flags); */ \
[301] = { "unlinkat", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[302] = { "renameat", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[303] = { "linkat", { UNKNOWN }, UNKNOWN }, \
/* symlinkat(const char *target, int newdirfd, const char *linkpath); */ \
[304] = { "symlinkat", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[305] = { "readlinkat", { UNKNOWN }, UNKNOWN }, \
/* fchmodat(int dirfd, const char *pathname, mode_t mode, int flags); */ \
[306] = { "fchmodat", { UNKNOWN }, UNKNOWN }, \
/* faccessat(int dirfd, const char *pathname, int mode, int flags); */ \
[307] = { "faccessat", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[308] = { "pselect6", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[309] = { "ppoll", { UNKNOWN }, UNKNOWN }, \
/* unshare(int flags); */ \
[310] = { "unshare", { UNKNOWN }, UNKNOWN }, \
/* set_robust_list(struct robust_list_head *head, size_t len); */ \
[311] = { "set_robust_list", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[312] = { "get_robust_list", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[313] = { "splice", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[314] = { "sync_file_range", { UNKNOWN }, UNKNOWN }, \
/* tee(int fd_in, int fd_out, size_t len, unsigned int flags); */ \
[315] = { "tee", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[316] = { "vmsplice", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[317] = { "move_pages", { UNKNOWN }, UNKNOWN }, \
/* getcpu(unsigned *cpu, unsigned *node, struct getcpu_cache *tcache); */ \
[318] = { "getcpu", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[319] = { "epoll_pwait", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[320] = { "utimensat", { UNKNOWN }, UNKNOWN }, \
/* signalfd(int fd, const sigset_t *mask, int flags); */ \
[321] = { "signalfd", { UNKNOWN }, UNKNOWN }, \
/* timerfd_create(int clockid, int flags); */ \
[322] = { "timerfd_create", { UNKNOWN }, UNKNOWN }, \
/* eventfd(unsigned int initval, int flags); */ \
[323] = { "eventfd", { UNKNOWN }, UNKNOWN }, \
/* fallocate(int fd, int mode, off_t offset, off_t len); */ \
[324] = { "fallocate", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[325] = { "timerfd_settime", { UNKNOWN }, UNKNOWN }, \
/* timerfd_gettime(int fd, struct itimerspec *curr_value); */ \
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
/* fanotify_init(unsigned int flags, unsigned int event_f_flags); */ \
[338] = { "fanotify_init", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[339] = { "fanotify_mark", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[340] = { "prlimit64", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[341] = { "name_to_handle_at", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[342] = { "open_by_handle_at", { UNKNOWN }, UNKNOWN }, \
/* clock_adjtime(clockid_t clk_id, struct timex *buf); */ \
[343] = { "clock_adjtime", { UNKNOWN }, UNKNOWN }, \
/* syncfs(int fd); */ \
[344] = { "syncfs", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[345] = { "sendmmsg", { UNKNOWN }, UNKNOWN }, \
/* setns(int fd, int nstype); */ \
[346] = { "setns", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[347] = { "process_vm_readv", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[348] = { "process_vm_writev", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[349] = { "kcmp", { UNKNOWN }, UNKNOWN }, \
/* finit_module(); */ \
[350] = { "finit_module", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[351] = { "sched_setattr", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[352] = { "sched_getattr", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[353] = { "renameat2", { UNKNOWN }, UNKNOWN }, \
/* seccomp(unsigned int operation, unsigned int flags, void *args); */ \
[354] = { "seccomp", { UNKNOWN }, UNKNOWN }, \
/* getrandom(void *buf, size_t buflen, unsigned int flags); */ \
[355] = { "getrandom", { UNKNOWN }, UNKNOWN }, \
/* memfd_create(const char *name, unsigned int flags); */ \
[356] = { "memfd_create", { UNKNOWN }, UNKNOWN }, \
/* bpf(int cmd, union bpf_attr *attr, unsigned int size); */ \
[357] = { "bpf", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[358] = { "execveat", { UNKNOWN }, UNKNOWN }, \
/* socket(int domain, int type, int protocol); */ \
[359] = { "socket", { UNKNOWN }, UNKNOWN }, \
/* socketpair(int domain, int type, int protocol, int sv[2]); */ \
[360] = { "socketpair", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[361] = { "bind", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[362] = { "connect", { UNKNOWN }, UNKNOWN }, \
/* listen(int sockfd, int backlog); */ \
[363] = { "listen", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[364] = { "accept4", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[365] = { "getsockopt", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[366] = { "setsockopt", { UNKNOWN }, UNKNOWN }, \
/* getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen); */ \
[367] = { "getsockname", { UNKNOWN }, UNKNOWN }, \
/* getpeername(int sockfd, struct sockaddr *addr, socklen_t *addrlen); */ \
[368] = { "getpeername", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[369] = { "sendto", { UNKNOWN }, UNKNOWN }, \
/* sendmsg(int sockfd, const struct msghdr *msg, int flags); */ \
[370] = { "sendmsg", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[371] = { "recvfrom", { UNKNOWN }, UNKNOWN }, \
/* recvmsg(int sockfd, struct msghdr *msg, int flags); */ \
[372] = { "recvmsg", { UNKNOWN }, UNKNOWN }, \
/* shutdown(int sockfd, int how); */ \
[373] = { "shutdown", { UNKNOWN }, UNKNOWN }, \
/* userfaultfd(int flags); */ \
[374] = { "userfaultfd", { UNKNOWN }, UNKNOWN }, \
/* membarrier(int cmd, unsigned int flags, int cpu_id); */ \
[375] = { "membarrier", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[376] = { "mlock2", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[377] = { "copy_file_range", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[378] = { "preadv2", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[379] = { "pwritev2", { UNKNOWN }, UNKNOWN }, \
/* pkey_mprotect(void *addr, size_t len, int prot, int pkey); */ \
[380] = { "pkey_mprotect", { UNKNOWN }, UNKNOWN }, \
/* pkey_alloc(unsigned int flags, unsigned int access_rights); */ \
[381] = { "pkey_alloc", { UNKNOWN }, UNKNOWN }, \
/* pkey_free(int pkey); */ \
[382] = { "pkey_free", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[383] = { "statx", { UNKNOWN }, UNKNOWN }, \
/* arch_prctl(int code, unsigned long addr);
arch_prctl(int code, unsigned long *addr); */ \
[384] = { "arch_prctl", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[385] = { "io_pgetevents", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[386] = { "rseq", { UNKNOWN }, UNKNOWN }, \
/* semget(key_t key, int nsems, int semflg); */ \
[393] = { "semget", { UNKNOWN }, UNKNOWN }, \
/* semctl(int semid, int semnum, int cmd, ...); */ \
[394] = { "semctl", { UNKNOWN }, UNKNOWN }, \
/* shmget(key_t key, size_t size, int shmflg); */ \
[395] = { "shmget", { UNKNOWN }, UNKNOWN }, \
/* shmctl(int shmid, int cmd, struct shmid_ds *buf); */ \
[396] = { "shmctl", { UNKNOWN }, UNKNOWN }, \
/* shmat(int shmid, const void *shmaddr, int shmflg); */ \
[397] = { "shmat", { UNKNOWN }, UNKNOWN }, \
/* shmdt(const void *shmaddr); */ \
[398] = { "shmdt", { UNKNOWN }, UNKNOWN }, \
/* msgget(key_t key, int msgflg); */ \
[399] = { "msgget", { UNKNOWN }, UNKNOWN }, \
/* msgsnd(int msqid, const void *msgp, size_t msgsz, int msgflg); */ \
[400] = { "msgsnd", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[401] = { "msgrcv", { UNKNOWN }, UNKNOWN }, \
/* msgctl(int msqid, int cmd, struct msqid_ds *buf); */ \
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
/* pidfd_open(pid_t pid, unsigned int flags); */ \
[434] = { "pidfd_open", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[435] = { "clone3", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[436] = { "close_range", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[437] = { "openat2", { UNKNOWN }, UNKNOWN }, \
/* pidfd_getfd(int pidfd, int targetfd, unsigned int flags); */ \
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
