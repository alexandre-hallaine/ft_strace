#pragma once
#include "types.h"

#define SYSCALL_TABLE_64 { \
/* read(int fd, void *buf, size_t count); */ \
[0] = { "read", { UNKNOWN }, UNKNOWN }, \
/* write(int fd, const void *buf, size_t count); */ \
[1] = { "write", { UNKNOWN }, UNKNOWN }, \
/* open(const char *pathname, int flags);
open(const char *pathname, int flags, mode_t mode);
openat(int dirfd, const char *pathname, int flags);
openat(int dirfd, const char *pathname, int flags, mode_t mode); */ \
[2] = { "open", { UNKNOWN }, UNKNOWN }, \
/* close(int fd); */ \
[3] = { "close", { UNKNOWN }, UNKNOWN }, \
/* stat(const char *pathname, struct stat *statbuf);
fstat(int fd, struct stat *statbuf);
lstat(const char *pathname, struct stat *statbuf); */ \
[4] = { "stat", { UNKNOWN }, UNKNOWN }, \
/* fstat(int fd, struct stat *statbuf); */ \
[5] = { "fstat", { UNKNOWN }, UNKNOWN }, \
/* lstat(const char *pathname, struct stat *statbuf); */ \
[6] = { "lstat", { UNKNOWN }, UNKNOWN }, \
/* poll(struct pollfd *fds, nfds_t nfds, int timeout); */ \
[7] = { "poll", { UNKNOWN }, UNKNOWN }, \
/* lseek(int fd, off_t offset, int whence); */ \
[8] = { "lseek", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[9] = { "mmap", { UNKNOWN }, UNKNOWN }, \
/* mprotect(void *addr, size_t len, int prot);
pkey_mprotect(void *addr, size_t len, int prot, int pkey); */ \
[10] = { "mprotect", { UNKNOWN }, UNKNOWN }, \
/* munmap(void *addr, size_t length); */ \
[11] = { "munmap", { UNKNOWN }, UNKNOWN }, \
/* brk(void *addr);
sbrk(intptr_t increment); */ \
[12] = { "brk", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[13] = { "rt_sigaction", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[14] = { "rt_sigprocmask", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[15] = { "rt_sigreturn", { UNKNOWN }, UNKNOWN }, \
/* ioctl(int fd, unsigned long request, ...); */ \
[16] = { "ioctl", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[17] = { "pread64", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[18] = { "pwrite64", { UNKNOWN }, UNKNOWN }, \
/* readv(int fd, const struct iovec *iov, int iovcnt); */ \
[19] = { "readv", { UNKNOWN }, UNKNOWN }, \
/* writev(int fd, const struct iovec *iov, int iovcnt); */ \
[20] = { "writev", { UNKNOWN }, UNKNOWN }, \
/* access(const char *pathname, int mode);
faccessat(int dirfd, const char *pathname, int mode, int flags); */ \
[21] = { "access", { UNKNOWN }, UNKNOWN }, \
/* pipe();
pipe(int pipefd[2]); */ \
[22] = { "pipe", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[23] = { "select", { UNKNOWN }, UNKNOWN }, \
/* sched_yield(void); */ \
[24] = { "sched_yield", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[25] = { "mremap", { UNKNOWN }, UNKNOWN }, \
/* msync(void *addr, size_t length, int flags); */ \
[26] = { "msync", { UNKNOWN }, UNKNOWN }, \
/* mincore(void *addr, size_t length, unsigned char *vec); */ \
[27] = { "mincore", { UNKNOWN }, UNKNOWN }, \
/* madvise(void *addr, size_t length, int advice); */ \
[28] = { "madvise", { UNKNOWN }, UNKNOWN }, \
/* shmget(key_t key, size_t size, int shmflg); */ \
[29] = { "shmget", { UNKNOWN }, UNKNOWN }, \
/* shmat(int shmid, const void *shmaddr, int shmflg); */ \
[30] = { "shmat", { UNKNOWN }, UNKNOWN }, \
/* shmctl(int shmid, int cmd, struct shmid_ds *buf); */ \
[31] = { "shmctl", { UNKNOWN }, UNKNOWN }, \
/* dup(int oldfd); */ \
[32] = { "dup", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[33] = { "dup2", { UNKNOWN }, UNKNOWN }, \
/* pause(void); */ \
[34] = { "pause", { UNKNOWN }, UNKNOWN }, \
/* nanosleep(const struct timespec *req, struct timespec *rem); */ \
[35] = { "nanosleep", { UNKNOWN }, UNKNOWN }, \
/* getitimer(int which, struct itimerval *curr_value); */ \
[36] = { "getitimer", { UNKNOWN }, UNKNOWN }, \
/* alarm(unsigned int seconds); */ \
[37] = { "alarm", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[38] = { "setitimer", { UNKNOWN }, UNKNOWN }, \
/* getpid(void); */ \
[39] = { "getpid", { UNKNOWN }, UNKNOWN }, \
/* sendfile(int out_fd, int in_fd, off_t *offset, size_t count); */ \
[40] = { "sendfile", { UNKNOWN }, UNKNOWN }, \
/* socket(int domain, int type, int protocol); */ \
[41] = { "socket", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[42] = { "connect", { UNKNOWN }, UNKNOWN }, \
/* accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen); */ \
[43] = { "accept", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[44] = { "sendto", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[45] = { "recvfrom", { UNKNOWN }, UNKNOWN }, \
/* sendmsg(int sockfd, const struct msghdr *msg, int flags); */ \
[46] = { "sendmsg", { UNKNOWN }, UNKNOWN }, \
/* recvmsg(int sockfd, struct msghdr *msg, int flags); */ \
[47] = { "recvmsg", { UNKNOWN }, UNKNOWN }, \
/* shutdown(int sockfd, int how); */ \
[48] = { "shutdown", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[49] = { "bind", { UNKNOWN }, UNKNOWN }, \
/* listen(int sockfd, int backlog); */ \
[50] = { "listen", { UNKNOWN }, UNKNOWN }, \
/* getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen); */ \
[51] = { "getsockname", { UNKNOWN }, UNKNOWN }, \
/* getpeername(int sockfd, struct sockaddr *addr, socklen_t *addrlen); */ \
[52] = { "getpeername", { UNKNOWN }, UNKNOWN }, \
/* socketpair(int domain, int type, int protocol, int sv[2]); */ \
[53] = { "socketpair", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[54] = { "setsockopt", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[55] = { "getsockopt", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[56] = { "clone", { UNKNOWN }, UNKNOWN }, \
/* fork(void); */ \
[57] = { "fork", { UNKNOWN }, UNKNOWN }, \
/* vfork(void); */ \
[58] = { "vfork", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[59] = { "execve", { UNKNOWN }, UNKNOWN }, \
/* _exit(int status); */ \
[60] = { "exit", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[61] = { "wait4", { UNKNOWN }, UNKNOWN }, \
/* kill(pid_t pid, int sig); */ \
[62] = { "kill", { UNKNOWN }, UNKNOWN }, \
/* uname(struct utsname *buf); */ \
[63] = { "uname", { UNKNOWN }, UNKNOWN }, \
/* semget(key_t key, int nsems, int semflg); */ \
[64] = { "semget", { UNKNOWN }, UNKNOWN }, \
/* semop(int semid, struct sembuf *sops, size_t nsops); */ \
[65] = { "semop", { UNKNOWN }, UNKNOWN }, \
/* semctl(int semid, int semnum, int cmd, ...); */ \
[66] = { "semctl", { UNKNOWN }, UNKNOWN }, \
/* shmdt(const void *shmaddr); */ \
[67] = { "shmdt", { UNKNOWN }, UNKNOWN }, \
/* msgget(key_t key, int msgflg); */ \
[68] = { "msgget", { UNKNOWN }, UNKNOWN }, \
/* msgsnd(int msqid, const void *msgp, size_t msgsz, int msgflg); */ \
[69] = { "msgsnd", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[70] = { "msgrcv", { UNKNOWN }, UNKNOWN }, \
/* msgctl(int msqid, int cmd, struct msqid_ds *buf); */ \
[71] = { "msgctl", { UNKNOWN }, UNKNOWN }, \
/* fcntl(int fd, int cmd, ...  ); */ \
[72] = { "fcntl", { UNKNOWN }, UNKNOWN }, \
/* flock(int fd, int operation); */ \
[73] = { "flock", { UNKNOWN }, UNKNOWN }, \
/* fsync(int fd); */ \
[74] = { "fsync", { UNKNOWN }, UNKNOWN }, \
/* fdatasync(int fd); */ \
[75] = { "fdatasync", { UNKNOWN }, UNKNOWN }, \
/* truncate(const char *path, off_t length);
ftruncate(int fd, off_t length); */ \
[76] = { "truncate", { UNKNOWN }, UNKNOWN }, \
/* ftruncate(int fd, off_t length); */ \
[77] = { "ftruncate", { UNKNOWN }, UNKNOWN }, \
/* getdents(); */ \
[78] = { "getdents", { UNKNOWN }, UNKNOWN }, \
/* getcwd(char *buf, size_t size); */ \
[79] = { "getcwd", { UNKNOWN }, UNKNOWN }, \
/* chdir(const char *path);
fchdir(int fd); */ \
[80] = { "chdir", { UNKNOWN }, UNKNOWN }, \
/* fchdir(int fd); */ \
[81] = { "fchdir", { UNKNOWN }, UNKNOWN }, \
/* rename(const char *oldpath, const char *newpath); */ \
[82] = { "rename", { UNKNOWN }, UNKNOWN }, \
/* mkdir(const char *pathname, mode_t mode);
mkdirat(int dirfd, const char *pathname, mode_t mode); */ \
[83] = { "mkdir", { UNKNOWN }, UNKNOWN }, \
/* rmdir(const char *pathname); */ \
[84] = { "rmdir", { UNKNOWN }, UNKNOWN }, \
/* creat(const char *pathname, mode_t mode); */ \
[85] = { "creat", { UNKNOWN }, UNKNOWN }, \
/* link(const char *oldpath, const char *newpath); */ \
[86] = { "link", { UNKNOWN }, UNKNOWN }, \
/* unlink(const char *pathname);
unlinkat(int dirfd, const char *pathname, int flags); */ \
[87] = { "unlink", { UNKNOWN }, UNKNOWN }, \
/* symlink(const char *target, const char *linkpath);
symlinkat(const char *target, int newdirfd, const char *linkpath); */ \
[88] = { "symlink", { UNKNOWN }, UNKNOWN }, \
/* readlink(const char *pathname, char *buf, size_t bufsiz); */ \
[89] = { "readlink", { UNKNOWN }, UNKNOWN }, \
/* chmod(const char *pathname, mode_t mode);
fchmod(int fd, mode_t mode);
fchmodat(int dirfd, const char *pathname, mode_t mode, int flags); */ \
[90] = { "chmod", { UNKNOWN }, UNKNOWN }, \
/* fchmod(int fd, mode_t mode);
fchmodat(int dirfd, const char *pathname, mode_t mode, int flags); */ \
[91] = { "fchmod", { UNKNOWN }, UNKNOWN }, \
/* chown(const char *pathname, uid_t owner, gid_t group);
fchown(int fd, uid_t owner, gid_t group);
lchown(const char *pathname, uid_t owner, gid_t group); */ \
[92] = { "chown", { UNKNOWN }, UNKNOWN }, \
/* fchown(int fd, uid_t owner, gid_t group); */ \
[93] = { "fchown", { UNKNOWN }, UNKNOWN }, \
/* lchown(const char *pathname, uid_t owner, gid_t group); */ \
[94] = { "lchown", { UNKNOWN }, UNKNOWN }, \
/* umask(mode_t mask); */ \
[95] = { "umask", { UNKNOWN }, UNKNOWN }, \
/* gettimeofday(struct timeval *tv, struct timezone *tz); */ \
[96] = { "gettimeofday", { UNKNOWN }, UNKNOWN }, \
/* getrlimit(int resource, struct rlimit *rlim); */ \
[97] = { "getrlimit", { UNKNOWN }, UNKNOWN }, \
/* getrusage(int who, struct rusage *usage); */ \
[98] = { "getrusage", { UNKNOWN }, UNKNOWN }, \
/* sysinfo(struct sysinfo *info); */ \
[99] = { "sysinfo", { UNKNOWN }, UNKNOWN }, \
/* times(struct tms *buf); */ \
[100] = { "times", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[101] = { "ptrace", { UNKNOWN }, UNKNOWN }, \
/* getuid(void); */ \
[102] = { "getuid", { UNKNOWN }, UNKNOWN }, \
/* syslog(int type, char *bufp, int len); */ \
[103] = { "syslog", { UNKNOWN }, UNKNOWN }, \
/* getgid(void); */ \
[104] = { "getgid", { UNKNOWN }, UNKNOWN }, \
/* setuid(uid_t uid); */ \
[105] = { "setuid", { UNKNOWN }, UNKNOWN }, \
/* setgid(gid_t gid); */ \
[106] = { "setgid", { UNKNOWN }, UNKNOWN }, \
/* geteuid(void); */ \
[107] = { "geteuid", { UNKNOWN }, UNKNOWN }, \
/* getegid(void); */ \
[108] = { "getegid", { UNKNOWN }, UNKNOWN }, \
/* setpgid(pid_t pid, pid_t pgid); */ \
[109] = { "setpgid", { UNKNOWN }, UNKNOWN }, \
/* getppid(void); */ \
[110] = { "getppid", { UNKNOWN }, UNKNOWN }, \
/* getpgrp(void);
getpgrp(pid_t pid); */ \
[111] = { "getpgrp", { UNKNOWN }, UNKNOWN }, \
/* setsid(void); */ \
[112] = { "setsid", { UNKNOWN }, UNKNOWN }, \
/* setreuid(uid_t ruid, uid_t euid); */ \
[113] = { "setreuid", { UNKNOWN }, UNKNOWN }, \
/* setregid(gid_t rgid, gid_t egid); */ \
[114] = { "setregid", { UNKNOWN }, UNKNOWN }, \
/* getgroups(int size, gid_t list[]); */ \
[115] = { "getgroups", { UNKNOWN }, UNKNOWN }, \
/* setgroups(size_t size, const gid_t *list); */ \
[116] = { "setgroups", { UNKNOWN }, UNKNOWN }, \
/* setresuid(uid_t ruid, uid_t euid, uid_t suid); */ \
[117] = { "setresuid", { UNKNOWN }, UNKNOWN }, \
/* getresuid(uid_t *ruid, uid_t *euid, uid_t *suid); */ \
[118] = { "getresuid", { UNKNOWN }, UNKNOWN }, \
/* setresgid(gid_t rgid, gid_t egid, gid_t sgid); */ \
[119] = { "setresgid", { UNKNOWN }, UNKNOWN }, \
/* getresgid(gid_t *rgid, gid_t *egid, gid_t *sgid); */ \
[120] = { "getresgid", { UNKNOWN }, UNKNOWN }, \
/* getpgid(pid_t pid); */ \
[121] = { "getpgid", { UNKNOWN }, UNKNOWN }, \
/* setfsuid(uid_t fsuid); */ \
[122] = { "setfsuid", { UNKNOWN }, UNKNOWN }, \
/* setfsgid(uid_t fsgid); */ \
[123] = { "setfsgid", { UNKNOWN }, UNKNOWN }, \
/* getsid(pid_t pid); */ \
[124] = { "getsid", { UNKNOWN }, UNKNOWN }, \
/* capget(cap_user_header_t hdrp, cap_user_data_t datap); */ \
[125] = { "capget", { UNKNOWN }, UNKNOWN }, \
/* capset(cap_user_header_t hdrp, const cap_user_data_t datap); */ \
[126] = { "capset", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[127] = { "rt_sigpending", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[128] = { "rt_sigtimedwait", { UNKNOWN }, UNKNOWN }, \
/* rt_sigqueueinfo(pid_t tgid, int sig, siginfo_t *info); */ \
[129] = { "rt_sigqueueinfo", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[130] = { "rt_sigsuspend", { UNKNOWN }, UNKNOWN }, \
/* sigaltstack(const stack_t *ss, stack_t *old_ss); */ \
[131] = { "sigaltstack", { UNKNOWN }, UNKNOWN }, \
/* utime(const char *filename, const struct utimbuf *times);
utimes(const char *filename, const struct timeval times[2]); */ \
[132] = { "utime", { UNKNOWN }, UNKNOWN }, \
/* mknod(const char *pathname, mode_t mode, dev_t dev);
mknodat(int dirfd, const char *pathname, mode_t mode, dev_t dev); */ \
[133] = { "mknod", { UNKNOWN }, UNKNOWN }, \
/* uselib(const char *library); */ \
[134] = { "uselib", { UNKNOWN }, UNKNOWN }, \
/* personality(unsigned long persona); */ \
[135] = { "personality", { UNKNOWN }, UNKNOWN }, \
/* ustat(dev_t dev, struct ustat *ubuf); */ \
[136] = { "ustat", { UNKNOWN }, UNKNOWN }, \
/* statfs(const char *path, struct statfs *buf);
fstatfs(int fd, struct statfs *buf); */ \
[137] = { "statfs", { UNKNOWN }, UNKNOWN }, \
/* fstatfs(int fd, struct statfs *buf); */ \
[138] = { "fstatfs", { UNKNOWN }, UNKNOWN }, \
/* sysfs(int option, const char *fsname);
sysfs(int option, unsigned int fs_index, char *buf);
sysfs(int option); */ \
[139] = { "sysfs", { UNKNOWN }, UNKNOWN }, \
/* getpriority(int which, id_t who); */ \
[140] = { "getpriority", { UNKNOWN }, UNKNOWN }, \
/* setpriority(int which, id_t who, int prio); */ \
[141] = { "setpriority", { UNKNOWN }, UNKNOWN }, \
/* sched_setparam(pid_t pid, const struct sched_param *param); */ \
[142] = { "sched_setparam", { UNKNOWN }, UNKNOWN }, \
/* sched_getparam(pid_t pid, struct sched_param *param); */ \
[143] = { "sched_getparam", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[144] = { "sched_setscheduler", { UNKNOWN }, UNKNOWN }, \
/* sched_getscheduler(pid_t pid); */ \
[145] = { "sched_getscheduler", { UNKNOWN }, UNKNOWN }, \
/* sched_get_priority_max(int policy); */ \
[146] = { "sched_get_priority_max", { UNKNOWN }, UNKNOWN }, \
/* sched_get_priority_min(int policy); */ \
[147] = { "sched_get_priority_min", { UNKNOWN }, UNKNOWN }, \
/* sched_rr_get_interval(pid_t pid, struct timespec *tp); */ \
[148] = { "sched_rr_get_interval", { UNKNOWN }, UNKNOWN }, \
/* mlock(const void *addr, size_t len);
mlockall(int flags); */ \
[149] = { "mlock", { UNKNOWN }, UNKNOWN }, \
/* munlock(const void *addr, size_t len);
munlockall(void); */ \
[150] = { "munlock", { UNKNOWN }, UNKNOWN }, \
/* mlockall(int flags); */ \
[151] = { "mlockall", { UNKNOWN }, UNKNOWN }, \
/* munlockall(void); */ \
[152] = { "munlockall", { UNKNOWN }, UNKNOWN }, \
/* vhangup(void); */ \
[153] = { "vhangup", { UNKNOWN }, UNKNOWN }, \
/* modify_ldt(int func, void *ptr, unsigned long bytecount); */ \
[154] = { "modify_ldt", { UNKNOWN }, UNKNOWN }, \
/* pivot_root(const char *new_root, const char *put_old); */ \
[155] = { "pivot_root", { UNKNOWN }, UNKNOWN }, \
/* _sysctl(struct __sysctl_args *args); */ \
[156] = { "_sysctl", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[157] = { "prctl", { UNKNOWN }, UNKNOWN }, \
/* arch_prctl(int code, unsigned long addr);
arch_prctl(int code, unsigned long *addr); */ \
[158] = { "arch_prctl", { UNKNOWN }, UNKNOWN }, \
/* adjtimex(struct timex *buf); */ \
[159] = { "adjtimex", { UNKNOWN }, UNKNOWN }, \
/* setrlimit(int resource, const struct rlimit *rlim); */ \
[160] = { "setrlimit", { UNKNOWN }, UNKNOWN }, \
/* chroot(const char *path); */ \
[161] = { "chroot", { UNKNOWN }, UNKNOWN }, \
/* sync(void);
syncfs(int fd); */ \
[162] = { "sync", { UNKNOWN }, UNKNOWN }, \
/* acct(const char *filename); */ \
[163] = { "acct", { UNKNOWN }, UNKNOWN }, \
/* settimeofday(const struct timeval *tv, const struct timezone *tz); */ \
[164] = { "settimeofday", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[165] = { "mount", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[166] = { "umount2", { UNKNOWN }, UNKNOWN }, \
/* swapon(const char *path, int swapflags); */ \
[167] = { "swapon", { UNKNOWN }, UNKNOWN }, \
/* swapoff(const char *path); */ \
[168] = { "swapoff", { UNKNOWN }, UNKNOWN }, \
/* reboot(int magic, int magic2, int cmd, void *arg);
reboot(int cmd); */ \
[169] = { "reboot", { UNKNOWN }, UNKNOWN }, \
/* sethostname(const char *name, size_t len); */ \
[170] = { "sethostname", { UNKNOWN }, UNKNOWN }, \
/* setdomainname(const char *name, size_t len); */ \
[171] = { "setdomainname", { UNKNOWN }, UNKNOWN }, \
/* iopl(int level); */ \
[172] = { "iopl", { UNKNOWN }, UNKNOWN }, \
/* ioperm(unsigned long from, unsigned long num, int turn_on); */ \
[173] = { "ioperm", { UNKNOWN }, UNKNOWN }, \
/* create_module(const char *name, size_t size); */ \
[174] = { "create_module", { UNKNOWN }, UNKNOWN }, \
/* finit_module(); */ \
[175] = { "init_module", { UNKNOWN }, UNKNOWN }, \
/* delete_module(const char *name, int flags); */ \
[176] = { "delete_module", { UNKNOWN }, UNKNOWN }, \
/* get_kernel_syms(struct kernel_sym *table); */ \
[177] = { "get_kernel_syms", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[178] = { "query_module", { UNKNOWN }, UNKNOWN }, \
/* quotactl(int cmd, const char *special, int id, caddr_t addr); */ \
[179] = { "quotactl", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[180] = { "nfsservctl", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[181] = { "getpmsg", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[182] = { "putpmsg", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[183] = { "afs_syscall", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[184] = { "tuxcall", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[185] = { "security", { UNKNOWN }, UNKNOWN }, \
/* gettid(void); */ \
[186] = { "gettid", { UNKNOWN }, UNKNOWN }, \
/* readahead(int fd, off64_t offset, size_t count); */ \
[187] = { "readahead", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[188] = { "setxattr", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[189] = { "lsetxattr", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[190] = { "fsetxattr", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[191] = { "getxattr", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[192] = { "lgetxattr", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[193] = { "fgetxattr", { UNKNOWN }, UNKNOWN }, \
/* listxattr(const char *path, char *list, size_t size);
llistxattr(const char *path, char *list, size_t size);
flistxattr(int fd, char *list, size_t size); */ \
[194] = { "listxattr", { UNKNOWN }, UNKNOWN }, \
/* llistxattr(const char *path, char *list, size_t size); */ \
[195] = { "llistxattr", { UNKNOWN }, UNKNOWN }, \
/* flistxattr(int fd, char *list, size_t size); */ \
[196] = { "flistxattr", { UNKNOWN }, UNKNOWN }, \
/* removexattr(const char *path, const char *name);
lremovexattr(const char *path, const char *name);
fremovexattr(int fd, const char *name); */ \
[197] = { "removexattr", { UNKNOWN }, UNKNOWN }, \
/* lremovexattr(const char *path, const char *name); */ \
[198] = { "lremovexattr", { UNKNOWN }, UNKNOWN }, \
/* fremovexattr(int fd, const char *name); */ \
[199] = { "fremovexattr", { UNKNOWN }, UNKNOWN }, \
/* tkill(int tid, int sig);
tkill(); */ \
[200] = { "tkill", { UNKNOWN }, UNKNOWN }, \
/* time(time_t *tloc); */ \
[201] = { "time", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[202] = { "futex", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[203] = { "sched_setaffinity", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[204] = { "sched_getaffinity", { UNKNOWN }, UNKNOWN }, \
/* set_thread_area(struct user_desc *u_info);
set_thread_area(unsigned long tp);
set_thread_area(unsigned long addr); */ \
[205] = { "set_thread_area", { UNKNOWN }, UNKNOWN }, \
/* io_setup(unsigned nr_events, aio_context_t *ctx_idp); */ \
[206] = { "io_setup", { UNKNOWN }, UNKNOWN }, \
/* io_destroy(aio_context_t ctx_id); */ \
[207] = { "io_destroy", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[208] = { "io_getevents", { UNKNOWN }, UNKNOWN }, \
/* io_submit(aio_context_t ctx_id, long nr, struct iocb **iocbpp); */ \
[209] = { "io_submit", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[210] = { "io_cancel", { UNKNOWN }, UNKNOWN }, \
/* get_thread_area(struct user_desc *u_info);
get_thread_area(void); */ \
[211] = { "get_thread_area", { UNKNOWN }, UNKNOWN }, \
/* lookup_dcookie(u64 cookie, char *buffer, size_t len); */ \
[212] = { "lookup_dcookie", { UNKNOWN }, UNKNOWN }, \
/* epoll_create(int size); */ \
[213] = { "epoll_create", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[214] = { "epoll_ctl_old", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[215] = { "epoll_wait_old", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[216] = { "remap_file_pages", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[217] = { "getdents64", { UNKNOWN }, UNKNOWN }, \
/* set_tid_address(int *tidptr); */ \
[218] = { "set_tid_address", { UNKNOWN }, UNKNOWN }, \
/* restart_syscall(void); */ \
[219] = { "restart_syscall", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[220] = { "semtimedop", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[221] = { "fadvise64", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[222] = { "timer_create", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[223] = { "timer_settime", { UNKNOWN }, UNKNOWN }, \
/* timer_gettime(timer_t timerid, struct itimerspec *curr_value); */ \
[224] = { "timer_gettime", { UNKNOWN }, UNKNOWN }, \
/* timer_getoverrun(timer_t timerid); */ \
[225] = { "timer_getoverrun", { UNKNOWN }, UNKNOWN }, \
/* timer_delete(timer_t timerid); */ \
[226] = { "timer_delete", { UNKNOWN }, UNKNOWN }, \
/* clock_settime(clockid_t clockid, const struct timespec *tp); */ \
[227] = { "clock_settime", { UNKNOWN }, UNKNOWN }, \
/* clock_gettime(clockid_t clockid, struct timespec *tp); */ \
[228] = { "clock_gettime", { UNKNOWN }, UNKNOWN }, \
/* clock_getres(clockid_t clockid, struct timespec *res); */ \
[229] = { "clock_getres", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[230] = { "clock_nanosleep", { UNKNOWN }, UNKNOWN }, \
/* exit_group(int status); */ \
[231] = { "exit_group", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[232] = { "epoll_wait", { UNKNOWN }, UNKNOWN }, \
/* epoll_ctl(int epfd, int op, int fd, struct epoll_event *event); */ \
[233] = { "epoll_ctl", { UNKNOWN }, UNKNOWN }, \
/* tgkill(int tgid, int tid, int sig); */ \
[234] = { "tgkill", { UNKNOWN }, UNKNOWN }, \
/* utimes(const char *filename, const struct timeval times[2]); */ \
[235] = { "utimes", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[236] = { "vserver", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[237] = { "mbind", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[238] = { "set_mempolicy", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[239] = { "get_mempolicy", { UNKNOWN }, UNKNOWN }, \
/* mq_open(const char *name, int oflag); */ \
[240] = { "mq_open", { UNKNOWN }, UNKNOWN }, \
/* mq_unlink(const char *name); */ \
[241] = { "mq_unlink", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[242] = { "mq_timedsend", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[243] = { "mq_timedreceive", { UNKNOWN }, UNKNOWN }, \
/* mq_notify(mqd_t mqdes, const struct sigevent *sevp); */ \
[244] = { "mq_notify", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[245] = { "mq_getsetattr", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[246] = { "kexec_load", { UNKNOWN }, UNKNOWN }, \
/* waitid(idtype_t idtype, id_t id, siginfo_t *infop, int options); */ \
[247] = { "waitid", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[248] = { "add_key", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[249] = { "request_key", { UNKNOWN }, UNKNOWN }, \
/* keyctl(int operation, ...); */ \
[250] = { "keyctl", { UNKNOWN }, UNKNOWN }, \
/* ioprio_set(int which, int who, int ioprio); */ \
[251] = { "ioprio_set", { UNKNOWN }, UNKNOWN }, \
/* ioprio_get(int which, int who); */ \
[252] = { "ioprio_get", { UNKNOWN }, UNKNOWN }, \
/* inotify_init(void); */ \
[253] = { "inotify_init", { UNKNOWN }, UNKNOWN }, \
/* inotify_add_watch(int fd, const char *pathname, uint32_t mask); */ \
[254] = { "inotify_add_watch", { UNKNOWN }, UNKNOWN }, \
/* inotify_rm_watch(int fd, int wd); */ \
[255] = { "inotify_rm_watch", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[256] = { "migrate_pages", { UNKNOWN }, UNKNOWN }, \
/* openat(int dirfd, const char *pathname, int flags);
openat(int dirfd, const char *pathname, int flags, mode_t mode); */ \
[257] = { "openat", { UNKNOWN }, UNKNOWN }, \
/* mkdirat(int dirfd, const char *pathname, mode_t mode); */ \
[258] = { "mkdirat", { UNKNOWN }, UNKNOWN }, \
/* mknodat(int dirfd, const char *pathname, mode_t mode, dev_t dev); */ \
[259] = { "mknodat", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[260] = { "fchownat", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[261] = { "futimesat", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[262] = { "newfstatat", { UNKNOWN }, UNKNOWN }, \
/* unlinkat(int dirfd, const char *pathname, int flags); */ \
[263] = { "unlinkat", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[264] = { "renameat", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[265] = { "linkat", { UNKNOWN }, UNKNOWN }, \
/* symlinkat(const char *target, int newdirfd, const char *linkpath); */ \
[266] = { "symlinkat", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[267] = { "readlinkat", { UNKNOWN }, UNKNOWN }, \
/* fchmodat(int dirfd, const char *pathname, mode_t mode, int flags); */ \
[268] = { "fchmodat", { UNKNOWN }, UNKNOWN }, \
/* faccessat(int dirfd, const char *pathname, int mode, int flags); */ \
[269] = { "faccessat", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[270] = { "pselect6", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[271] = { "ppoll", { UNKNOWN }, UNKNOWN }, \
/* unshare(int flags); */ \
[272] = { "unshare", { UNKNOWN }, UNKNOWN }, \
/* set_robust_list(struct robust_list_head *head, size_t len); */ \
[273] = { "set_robust_list", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[274] = { "get_robust_list", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[275] = { "splice", { UNKNOWN }, UNKNOWN }, \
/* tee(int fd_in, int fd_out, size_t len, unsigned int flags); */ \
[276] = { "tee", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[277] = { "sync_file_range", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[278] = { "vmsplice", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[279] = { "move_pages", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[280] = { "utimensat", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[281] = { "epoll_pwait", { UNKNOWN }, UNKNOWN }, \
/* signalfd(int fd, const sigset_t *mask, int flags); */ \
[282] = { "signalfd", { UNKNOWN }, UNKNOWN }, \
/* timerfd_create(int clockid, int flags); */ \
[283] = { "timerfd_create", { UNKNOWN }, UNKNOWN }, \
/* eventfd(unsigned int initval, int flags); */ \
[284] = { "eventfd", { UNKNOWN }, UNKNOWN }, \
/* fallocate(int fd, int mode, off_t offset, off_t len); */ \
[285] = { "fallocate", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[286] = { "timerfd_settime", { UNKNOWN }, UNKNOWN }, \
/* timerfd_gettime(int fd, struct itimerspec *curr_value); */ \
[287] = { "timerfd_gettime", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[288] = { "accept4", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[289] = { "signalfd4", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[290] = { "eventfd2", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[291] = { "epoll_create1", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[292] = { "dup3", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[293] = { "pipe2", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[294] = { "inotify_init1", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[295] = { "preadv", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[296] = { "pwritev", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[297] = { "rt_tgsigqueueinfo", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[298] = { "perf_event_open", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[299] = { "recvmmsg", { UNKNOWN }, UNKNOWN }, \
/* fanotify_init(unsigned int flags, unsigned int event_f_flags); */ \
[300] = { "fanotify_init", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[301] = { "fanotify_mark", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[302] = { "prlimit64", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[303] = { "name_to_handle_at", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[304] = { "open_by_handle_at", { UNKNOWN }, UNKNOWN }, \
/* clock_adjtime(clockid_t clk_id, struct timex *buf); */ \
[305] = { "clock_adjtime", { UNKNOWN }, UNKNOWN }, \
/* syncfs(int fd); */ \
[306] = { "syncfs", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[307] = { "sendmmsg", { UNKNOWN }, UNKNOWN }, \
/* setns(int fd, int nstype); */ \
[308] = { "setns", { UNKNOWN }, UNKNOWN }, \
/* getcpu(unsigned *cpu, unsigned *node, struct getcpu_cache *tcache); */ \
[309] = { "getcpu", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[310] = { "process_vm_readv", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[311] = { "process_vm_writev", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[312] = { "kcmp", { UNKNOWN }, UNKNOWN }, \
/* finit_module(); */ \
[313] = { "finit_module", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[314] = { "sched_setattr", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[315] = { "sched_getattr", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[316] = { "renameat2", { UNKNOWN }, UNKNOWN }, \
/* seccomp(unsigned int operation, unsigned int flags, void *args); */ \
[317] = { "seccomp", { UNKNOWN }, UNKNOWN }, \
/* getrandom(void *buf, size_t buflen, unsigned int flags); */ \
[318] = { "getrandom", { UNKNOWN }, UNKNOWN }, \
/* memfd_create(const char *name, unsigned int flags); */ \
[319] = { "memfd_create", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[320] = { "kexec_file_load", { UNKNOWN }, UNKNOWN }, \
/* bpf(int cmd, union bpf_attr *attr, unsigned int size); */ \
[321] = { "bpf", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[322] = { "execveat", { UNKNOWN }, UNKNOWN }, \
/* userfaultfd(int flags); */ \
[323] = { "userfaultfd", { UNKNOWN }, UNKNOWN }, \
/* membarrier(int cmd, unsigned int flags, int cpu_id); */ \
[324] = { "membarrier", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[325] = { "mlock2", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[326] = { "copy_file_range", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[327] = { "preadv2", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[328] = { "pwritev2", { UNKNOWN }, UNKNOWN }, \
/* pkey_mprotect(void *addr, size_t len, int prot, int pkey); */ \
[329] = { "pkey_mprotect", { UNKNOWN }, UNKNOWN }, \
/* pkey_alloc(unsigned int flags, unsigned int access_rights); */ \
[330] = { "pkey_alloc", { UNKNOWN }, UNKNOWN }, \
/* pkey_free(int pkey); */ \
[331] = { "pkey_free", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[332] = { "statx", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[333] = { "io_pgetevents", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[334] = { "rseq", { UNKNOWN }, UNKNOWN }, \
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
