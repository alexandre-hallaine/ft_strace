#pragma once
#include "types.h"

#define SYSCALL_TABLE_64 { \
/*        ssize_t read(int fd, void *buf, size_t count); */ \
[0] = { "read", { INT, PTR, LONG }, LONG }, \
/*        ssize_t write(int fd, const void *buf, size_t count); */ \
[1] = { "write", { INT, PTR, LONG }, LONG }, \
/*        int open(const char *pathname, int flags, mode_t mode); */ \
[2] = { "open", { STR, INT, MODE }, INT }, \
/*        int close(int fd); */ \
[3] = { "close", { INT }, INT }, \
/*        int stat(const char *pathname, struct stat *statbuf); */ \
[4] = { "stat", { STR, PTR }, INT }, \
/*        int fstat(int fd, struct stat *statbuf); */ \
[5] = { "fstat", { INT, PTR }, INT }, \
/*        int lstat(const char *pathname, struct stat *statbuf); */ \
[6] = { "lstat", { STR, PTR }, INT }, \
/*        int poll(struct pollfd *fds, nfds_t nfds, int timeout); */ \
[7] = { "poll", { PTR, UNKNOWN_STRUCT, INT }, INT }, \
/*        off_t lseek(int fd, off_t offset, int whence); */ \
[8] = { "lseek", { INT, OFF, INT }, OFF }, \
/*        void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset); */ \
[9] = { "mmap", { PTR, LONG, INT, INT, INT, OFF }, PTR }, \
/*        int mprotect(void *addr, size_t len, int prot); */ \
[10] = { "mprotect", { PTR, LONG, INT }, INT }, \
/*        int munmap(void *addr, size_t length); */ \
[11] = { "munmap", { PTR, LONG }, INT }, \
/*        int brk(void *addr); */ \
[12] = { "brk", { PTR }, INT }, \
/*        int sigaction(int signum, const struct sigaction *act, struct sigaction *oldact); */ \
[13] = { "rt_sigaction", { INT, PTR, PTR }, INT }, \
/*        int rt_sigprocmask(int how, const kernel_sigset_t *set, kernel_sigset_t *oldset, size_t sigsetsize); */ \
[14] = { "rt_sigprocmask", { INT, PTR, PTR, LONG }, INT }, \
/*        int sigreturn(...); */ \
[15] = { "rt_sigreturn", { UNKNOWN }, INT }, \
/*        int ioctl(int fd, unsigned long request, ...); */ \
[16] = { "ioctl", { INT, LONG, UNKNOWN }, INT }, \
/*        ssize_t pread(int fd, void *buf, size_t count, off_t offset); */ \
[17] = { "pread64", { INT, PTR, LONG, OFF }, LONG }, \
/*        ssize_t pwrite(int fd, const void *buf, size_t count, off_t offset); */ \
[18] = { "pwrite64", { INT, PTR, LONG, OFF }, LONG }, \
/*        ssize_t readv(int fd, const struct iovec *iov, int iovcnt); */ \
[19] = { "readv", { INT, PTR, INT }, LONG }, \
/*        ssize_t writev(int fd, const struct iovec *iov, int iovcnt); */ \
[20] = { "writev", { INT, PTR, INT }, LONG }, \
/*        int access(const char *pathname, int mode); */ \
[21] = { "access", { STR, INT }, INT }, \
/*        int pipe(int pipefd[2]); */ \
[22] = { "pipe", { UNKNOWN_STRUCT }, INT }, \
/*        int select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout); */ \
[23] = { "select", { INT, PTR, PTR, PTR, PTR }, INT }, \
/*        int sched_yield(void); */ \
[24] = { "sched_yield", { }, INT }, \
/*        void *mremap(void *old_address, size_t old_size, size_t new_size, int flags, ...); */ \
[25] = { "mremap", { PTR, LONG, LONG, INT, UNKNOWN }, PTR }, \
/*        int msync(void *addr, size_t length, int flags); */ \
[26] = { "msync", { PTR, LONG, INT }, INT }, \
/*        int mincore(void *addr, size_t length, unsigned char *vec); */ \
[27] = { "mincore", { PTR, LONG, STR }, INT }, \
/*        int madvise(void *addr, size_t length, int advice); */ \
[28] = { "madvise", { PTR, LONG, INT }, INT }, \
/*        int shmget(key_t key, size_t size, int shmflg); */ \
[29] = { "shmget", { UNKNOWN_STRUCT, LONG, INT }, INT }, \
/*        void *shmat(int shmid, const void *shmaddr, int shmflg); */ \
[30] = { "shmat", { INT, PTR, INT }, PTR }, \
/*        int shmctl(int shmid, int cmd, struct shmid_ds *buf); */ \
[31] = { "shmctl", { INT, INT, PTR }, INT }, \
/*        int dup(int oldfd); */ \
[32] = { "dup", { INT }, INT }, \
/*        int dup2(int oldfd, int newfd); */ \
[33] = { "dup2", { INT, INT }, INT }, \
/*        int pause(void); */ \
[34] = { "pause", { }, INT }, \
/*        int nanosleep(const struct timespec *req, struct timespec *rem); */ \
[35] = { "nanosleep", { PTR, PTR }, INT }, \
/*        int getitimer(int which, struct itimerval *curr_value); */ \
[36] = { "getitimer", { INT, PTR }, INT }, \
/*        unsigned int alarm(unsigned int seconds); */ \
[37] = { "alarm", { INT }, INT }, \
/*        int setitimer(int which, const struct itimerval *new_value, struct itimerval *old_value); */ \
[38] = { "setitimer", { INT, PTR, PTR }, INT }, \
/*        pid_t getpid(void); */ \
[39] = { "getpid", { }, ID }, \
/*        ssize_t sendfile(int out_fd, int in_fd, off_t *offset, size_t count); */ \
[40] = { "sendfile", { INT, INT, PTR, LONG }, LONG }, \
/*        int socket(int domain, int type, int protocol); */ \
[41] = { "socket", { INT, INT, INT }, INT }, \
/*        int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen); */ \
[42] = { "connect", { INT, PTR, UNKNOWN_STRUCT }, INT }, \
/*        int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen); */ \
[43] = { "accept", { INT, PTR, PTR }, INT }, \
/*        ssize_t sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen); */ \
[44] = { "sendto", { INT, PTR, LONG, INT, PTR, UNKNOWN_STRUCT }, LONG }, \
/*        ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen); */ \
[45] = { "recvfrom", { INT, PTR, LONG, INT, PTR, PTR }, LONG }, \
/*        ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags); */ \
[46] = { "sendmsg", { INT, PTR, INT }, LONG }, \
/*        ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags); */ \
[47] = { "recvmsg", { INT, PTR, INT }, LONG }, \
/*        int shutdown(int sockfd, int how); */ \
[48] = { "shutdown", { INT, INT }, INT }, \
/*        int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen); */ \
[49] = { "bind", { INT, PTR, UNKNOWN_STRUCT }, INT }, \
/*        int listen(int sockfd, int backlog); */ \
[50] = { "listen", { INT, INT }, INT }, \
/*        int getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen); */ \
[51] = { "getsockname", { INT, PTR, PTR }, INT }, \
/*        int getpeername(int sockfd, struct sockaddr *addr, socklen_t *addrlen); */ \
[52] = { "getpeername", { INT, PTR, PTR }, INT }, \
/*        int socketpair(int domain, int type, int protocol, int sv[2]); */ \
[53] = { "socketpair", { INT, INT, INT, ARRAY | INT }, INT }, \
/*        int setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen); */ \
[54] = { "setsockopt", { INT, INT, INT, PTR, UNKNOWN_STRUCT }, INT }, \
/*        int getsockopt(int sockfd, int level, int optname, void *optval, socklen_t *optlen); */ \
[55] = { "getsockopt", { INT, INT, INT, PTR, PTR }, INT }, \
/*        int clone(int (*fn)(void *), void *stack, int flags, void *arg, ...); */ \
[56] = { "clone", { UNKNOWN_STRUCT, PTR, INT, PTR, UNKNOWN }, INT }, \
/*        pid_t fork(void); */ \
[57] = { "fork", { }, ID }, \
/*        pid_t vfork(void); */ \
[58] = { "vfork", { }, ID }, \
/*        int execve(const char *pathname, char *const argv[], char *const envp[]); */ \
[59] = { "execve", { STR, ARRAY | STR, ARRAY | STR }, INT }, \
/*        void _exit(int status); */ \
[60] = { "exit", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[61] = { "wait4", { UNKNOWN }, UNKNOWN }, \
/*        int kill(pid_t pid, int sig); */ \
[62] = { "kill", { UNKNOWN }, UNKNOWN }, \
/*        int uname(struct utsname *buf); */ \
[63] = { "uname", { UNKNOWN }, UNKNOWN }, \
/*        int semget(key_t key, int nsems, int semflg); */ \
[64] = { "semget", { UNKNOWN }, UNKNOWN }, \
/*        int semop(int semid, struct sembuf *sops, size_t nsops); */ \
[65] = { "semop", { UNKNOWN }, UNKNOWN }, \
/*        int semctl(int semid, int semnum, int cmd, ...); */ \
[66] = { "semctl", { UNKNOWN }, UNKNOWN }, \
/*        int shmdt(const void *shmaddr); */ \
[67] = { "shmdt", { UNKNOWN }, UNKNOWN }, \
/*        int msgget(key_t key, int msgflg); */ \
[68] = { "msgget", { UNKNOWN }, UNKNOWN }, \
/*        int msgsnd(int msqid, const void *msgp, size_t msgsz, int msgflg); */ \
[69] = { "msgsnd", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[70] = { "msgrcv", { UNKNOWN }, UNKNOWN }, \
/*        int msgctl(int msqid, int cmd, struct msqid_ds *buf); */ \
[71] = { "msgctl", { UNKNOWN }, UNKNOWN }, \
/*        int fcntl(int fd, int cmd, ...  ); */ \
[72] = { "fcntl", { UNKNOWN }, UNKNOWN }, \
/*        int flock(int fd, int operation); */ \
[73] = { "flock", { UNKNOWN }, UNKNOWN }, \
/*        int fsync(int fd); */ \
[74] = { "fsync", { UNKNOWN }, UNKNOWN }, \
/*        int fdatasync(int fd); */ \
[75] = { "fdatasync", { UNKNOWN }, UNKNOWN }, \
/*        int truncate(const char *path, off_t length);
       int ftruncate(int fd, off_t length); */ \
[76] = { "truncate", { UNKNOWN }, UNKNOWN }, \
/*        int ftruncate(int fd, off_t length); */ \
[77] = { "ftruncate", { UNKNOWN }, UNKNOWN }, \
/*        Note: There is no glibc wrapper for getdents(); see NOTES. */ \
[78] = { "getdents", { UNKNOWN }, UNKNOWN }, \
/*        char *getcwd(char *buf, size_t size); */ \
[79] = { "getcwd", { UNKNOWN }, UNKNOWN }, \
/*        int chdir(const char *path);
       int fchdir(int fd); */ \
[80] = { "chdir", { UNKNOWN }, UNKNOWN }, \
/*        int fchdir(int fd); */ \
[81] = { "fchdir", { UNKNOWN }, UNKNOWN }, \
/*        int rename(const char *oldpath, const char *newpath); */ \
[82] = { "rename", { UNKNOWN }, UNKNOWN }, \
/*        int mkdir(const char *pathname, mode_t mode);
       int mkdirat(int dirfd, const char *pathname, mode_t mode); */ \
[83] = { "mkdir", { UNKNOWN }, UNKNOWN }, \
/*        int rmdir(const char *pathname); */ \
[84] = { "rmdir", { UNKNOWN }, UNKNOWN }, \
/*        int creat(const char *pathname, mode_t mode); */ \
[85] = { "creat", { UNKNOWN }, UNKNOWN }, \
/*        int link(const char *oldpath, const char *newpath); */ \
[86] = { "link", { UNKNOWN }, UNKNOWN }, \
/*        int unlink(const char *pathname);
       int unlinkat(int dirfd, const char *pathname, int flags); */ \
[87] = { "unlink", { UNKNOWN }, UNKNOWN }, \
/*        int symlink(const char *target, const char *linkpath);
       int symlinkat(const char *target, int newdirfd, const char *linkpath); */ \
[88] = { "symlink", { UNKNOWN }, UNKNOWN }, \
/*        ssize_t readlink(const char *pathname, char *buf, size_t bufsiz); */ \
[89] = { "readlink", { UNKNOWN }, UNKNOWN }, \
/*        int chmod(const char *pathname, mode_t mode);
       int fchmod(int fd, mode_t mode);
       int fchmodat(int dirfd, const char *pathname, mode_t mode, int flags); */ \
[90] = { "chmod", { UNKNOWN }, UNKNOWN }, \
/*        int fchmod(int fd, mode_t mode);
       int fchmodat(int dirfd, const char *pathname, mode_t mode, int flags); */ \
[91] = { "fchmod", { UNKNOWN }, UNKNOWN }, \
/*        int chown(const char *pathname, uid_t owner, gid_t group);
       int fchown(int fd, uid_t owner, gid_t group);
       int lchown(const char *pathname, uid_t owner, gid_t group); */ \
[92] = { "chown", { UNKNOWN }, UNKNOWN }, \
/*        int fchown(int fd, uid_t owner, gid_t group); */ \
[93] = { "fchown", { UNKNOWN }, UNKNOWN }, \
/*        int lchown(const char *pathname, uid_t owner, gid_t group); */ \
[94] = { "lchown", { UNKNOWN }, UNKNOWN }, \
/*        mode_t umask(mode_t mask); */ \
[95] = { "umask", { UNKNOWN }, UNKNOWN }, \
/*        int gettimeofday(struct timeval *tv, struct timezone *tz); */ \
[96] = { "gettimeofday", { UNKNOWN }, UNKNOWN }, \
/*        int getrlimit(int resource, struct rlimit *rlim); */ \
[97] = { "getrlimit", { UNKNOWN }, UNKNOWN }, \
/*        int getrusage(int who, struct rusage *usage); */ \
[98] = { "getrusage", { UNKNOWN }, UNKNOWN }, \
/*        int sysinfo(struct sysinfo *info); */ \
[99] = { "sysinfo", { UNKNOWN }, UNKNOWN }, \
/*        clock_t times(struct tms *buf); */ \
[100] = { "times", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[101] = { "ptrace", { UNKNOWN }, UNKNOWN }, \
/*        uid_t getuid(void); */ \
[102] = { "getuid", { UNKNOWN }, UNKNOWN }, \
/*        int syslog(int type, char *bufp, int len); */ \
[103] = { "syslog", { UNKNOWN }, UNKNOWN }, \
/*        gid_t getgid(void); */ \
[104] = { "getgid", { UNKNOWN }, UNKNOWN }, \
/*        int setuid(uid_t uid); */ \
[105] = { "setuid", { UNKNOWN }, UNKNOWN }, \
/*        int setgid(gid_t gid); */ \
[106] = { "setgid", { UNKNOWN }, UNKNOWN }, \
/*        uid_t geteuid(void); */ \
[107] = { "geteuid", { UNKNOWN }, UNKNOWN }, \
/*        gid_t getegid(void); */ \
[108] = { "getegid", { UNKNOWN }, UNKNOWN }, \
/*        int setpgid(pid_t pid, pid_t pgid); */ \
[109] = { "setpgid", { UNKNOWN }, UNKNOWN }, \
/*        pid_t getppid(void); */ \
[110] = { "getppid", { UNKNOWN }, UNKNOWN }, \
/*        pid_t getpgrp(void);                 
       pid_t getpgrp(pid_t pid);             */ \
[111] = { "getpgrp", { UNKNOWN }, UNKNOWN }, \
/*        pid_t setsid(void); */ \
[112] = { "setsid", { UNKNOWN }, UNKNOWN }, \
/*        int setreuid(uid_t ruid, uid_t euid); */ \
[113] = { "setreuid", { UNKNOWN }, UNKNOWN }, \
/*        int setregid(gid_t rgid, gid_t egid); */ \
[114] = { "setregid", { UNKNOWN }, UNKNOWN }, \
/*        int getgroups(int size, gid_t list[]); */ \
[115] = { "getgroups", { UNKNOWN }, UNKNOWN }, \
/*        int setgroups(size_t size, const gid_t *list); */ \
[116] = { "setgroups", { UNKNOWN }, UNKNOWN }, \
/*        int setresuid(uid_t ruid, uid_t euid, uid_t suid); */ \
[117] = { "setresuid", { UNKNOWN }, UNKNOWN }, \
/*        int getresuid(uid_t *ruid, uid_t *euid, uid_t *suid); */ \
[118] = { "getresuid", { UNKNOWN }, UNKNOWN }, \
/*        int setresgid(gid_t rgid, gid_t egid, gid_t sgid); */ \
[119] = { "setresgid", { UNKNOWN }, UNKNOWN }, \
/*        int getresgid(gid_t *rgid, gid_t *egid, gid_t *sgid); */ \
[120] = { "getresgid", { UNKNOWN }, UNKNOWN }, \
/*        pid_t getpgid(pid_t pid); */ \
[121] = { "getpgid", { UNKNOWN }, UNKNOWN }, \
/*        int setfsuid(uid_t fsuid); */ \
[122] = { "setfsuid", { UNKNOWN }, UNKNOWN }, \
/*        int setfsgid(uid_t fsgid); */ \
[123] = { "setfsgid", { UNKNOWN }, UNKNOWN }, \
/*        pid_t getsid(pid_t pid); */ \
[124] = { "getsid", { UNKNOWN }, UNKNOWN }, \
/*        int capget(cap_user_header_t hdrp, cap_user_data_t datap); */ \
[125] = { "capget", { UNKNOWN }, UNKNOWN }, \
/*        int capset(cap_user_header_t hdrp, const cap_user_data_t datap); */ \
[126] = { "capset", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[127] = { "rt_sigpending", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[128] = { "rt_sigtimedwait", { UNKNOWN }, UNKNOWN }, \
/*        int rt_sigqueueinfo(pid_t tgid, int sig, siginfo_t *info); */ \
[129] = { "rt_sigqueueinfo", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[130] = { "rt_sigsuspend", { UNKNOWN }, UNKNOWN }, \
/*        int sigaltstack(const stack_t *ss, stack_t *old_ss); */ \
[131] = { "sigaltstack", { UNKNOWN }, UNKNOWN }, \
/*        int utime(const char *filename, const struct utimbuf *times);
       int utimes(const char *filename, const struct timeval times[2]); */ \
[132] = { "utime", { UNKNOWN }, UNKNOWN }, \
/*        int mknod(const char *pathname, mode_t mode, dev_t dev);
       int mknodat(int dirfd, const char *pathname, mode_t mode, dev_t dev); */ \
[133] = { "mknod", { UNKNOWN }, UNKNOWN }, \
/*        int uselib(const char *library); */ \
[134] = { "uselib", { UNKNOWN }, UNKNOWN }, \
/*        int personality(unsigned long persona); */ \
[135] = { "personality", { UNKNOWN }, UNKNOWN }, \
/*        int ustat(dev_t dev, struct ustat *ubuf); */ \
[136] = { "ustat", { UNKNOWN }, UNKNOWN }, \
/*        int statfs(const char *path, struct statfs *buf);
       int fstatfs(int fd, struct statfs *buf); */ \
[137] = { "statfs", { UNKNOWN }, UNKNOWN }, \
/*        int fstatfs(int fd, struct statfs *buf); */ \
[138] = { "fstatfs", { UNKNOWN }, UNKNOWN }, \
/*        int sysfs(int option, const char *fsname);
       int sysfs(int option, unsigned int fs_index, char *buf);
       int sysfs(int option); */ \
[139] = { "sysfs", { UNKNOWN }, UNKNOWN }, \
/*        int getpriority(int which, id_t who); */ \
[140] = { "getpriority", { UNKNOWN }, UNKNOWN }, \
/*        int setpriority(int which, id_t who, int prio); */ \
[141] = { "setpriority", { UNKNOWN }, UNKNOWN }, \
/*        int sched_setparam(pid_t pid, const struct sched_param *param); */ \
[142] = { "sched_setparam", { UNKNOWN }, UNKNOWN }, \
/*        int sched_getparam(pid_t pid, struct sched_param *param); */ \
[143] = { "sched_getparam", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[144] = { "sched_setscheduler", { UNKNOWN }, UNKNOWN }, \
/*        int sched_getscheduler(pid_t pid); */ \
[145] = { "sched_getscheduler", { UNKNOWN }, UNKNOWN }, \
/*        int sched_get_priority_max(int policy); */ \
[146] = { "sched_get_priority_max", { UNKNOWN }, UNKNOWN }, \
/*        int sched_get_priority_min(int policy); */ \
[147] = { "sched_get_priority_min", { UNKNOWN }, UNKNOWN }, \
/*        int sched_rr_get_interval(pid_t pid, struct timespec *tp); */ \
[148] = { "sched_rr_get_interval", { UNKNOWN }, UNKNOWN }, \
/*        int mlock(const void *addr, size_t len);
       int mlockall(int flags); */ \
[149] = { "mlock", { UNKNOWN }, UNKNOWN }, \
/*        int munlock(const void *addr, size_t len);
       int munlockall(void); */ \
[150] = { "munlock", { UNKNOWN }, UNKNOWN }, \
/*        int mlockall(int flags); */ \
[151] = { "mlockall", { UNKNOWN }, UNKNOWN }, \
/*        int munlockall(void); */ \
[152] = { "munlockall", { UNKNOWN }, UNKNOWN }, \
/*        int vhangup(void); */ \
[153] = { "vhangup", { UNKNOWN }, UNKNOWN }, \
/*        int modify_ldt(int func, void *ptr, unsigned long bytecount); */ \
[154] = { "modify_ldt", { UNKNOWN }, UNKNOWN }, \
/*        int pivot_root(const char *new_root, const char *put_old); */ \
[155] = { "pivot_root", { UNKNOWN }, UNKNOWN }, \
/*        int _sysctl(struct __sysctl_args *args); */ \
[156] = { "_sysctl", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[157] = { "prctl", { UNKNOWN }, UNKNOWN }, \
/*        int arch_prctl(int code, unsigned long addr);
       int arch_prctl(int code, unsigned long *addr); */ \
[158] = { "arch_prctl", { UNKNOWN }, UNKNOWN }, \
/*        int adjtimex(struct timex *buf); */ \
[159] = { "adjtimex", { UNKNOWN }, UNKNOWN }, \
/*        int setrlimit(int resource, const struct rlimit *rlim); */ \
[160] = { "setrlimit", { UNKNOWN }, UNKNOWN }, \
/*        int chroot(const char *path); */ \
[161] = { "chroot", { UNKNOWN }, UNKNOWN }, \
/*        void sync(void);
       int syncfs(int fd); */ \
[162] = { "sync", { UNKNOWN }, UNKNOWN }, \
/*        int acct(const char *filename); */ \
[163] = { "acct", { UNKNOWN }, UNKNOWN }, \
/*        int settimeofday(const struct timeval *tv, const struct timezone *tz); */ \
[164] = { "settimeofday", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[165] = { "mount", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[166] = { "umount2", { UNKNOWN }, UNKNOWN }, \
/*        int swapon(const char *path, int swapflags); */ \
[167] = { "swapon", { UNKNOWN }, UNKNOWN }, \
/*        int swapoff(const char *path); */ \
[168] = { "swapoff", { UNKNOWN }, UNKNOWN }, \
/*        int reboot(int magic, int magic2, int cmd, void *arg);
       int reboot(int cmd); */ \
[169] = { "reboot", { UNKNOWN }, UNKNOWN }, \
/*        int sethostname(const char *name, size_t len); */ \
[170] = { "sethostname", { UNKNOWN }, UNKNOWN }, \
/*        int setdomainname(const char *name, size_t len); */ \
[171] = { "setdomainname", { UNKNOWN }, UNKNOWN }, \
/*        int iopl(int level); */ \
[172] = { "iopl", { UNKNOWN }, UNKNOWN }, \
/*        int ioperm(unsigned long from, unsigned long num, int turn_on); */ \
[173] = { "ioperm", { UNKNOWN }, UNKNOWN }, \
/*        caddr_t create_module(const char *name, size_t size); */ \
[174] = { "create_module", { UNKNOWN }, UNKNOWN }, \
/*        Note: glibc provides no header file declaration of init_module() and no wrapper function for finit_module(); see NOTES. */ \
[175] = { "init_module", { UNKNOWN }, UNKNOWN }, \
/*        int delete_module(const char *name, int flags); */ \
[176] = { "delete_module", { UNKNOWN }, UNKNOWN }, \
/*        int get_kernel_syms(struct kernel_sym *table); */ \
[177] = { "get_kernel_syms", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[178] = { "query_module", { UNKNOWN }, UNKNOWN }, \
/*        int quotactl(int cmd, const char *special, int id, caddr_t addr); */ \
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
/*        pid_t gettid(void); */ \
[186] = { "gettid", { UNKNOWN }, UNKNOWN }, \
/*        ssize_t readahead(int fd, off64_t offset, size_t count); */ \
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
/*        ssize_t listxattr(const char *path, char *list, size_t size);
       ssize_t llistxattr(const char *path, char *list, size_t size);
       ssize_t flistxattr(int fd, char *list, size_t size); */ \
[194] = { "listxattr", { UNKNOWN }, UNKNOWN }, \
/*        ssize_t llistxattr(const char *path, char *list, size_t size); */ \
[195] = { "llistxattr", { UNKNOWN }, UNKNOWN }, \
/*        ssize_t flistxattr(int fd, char *list, size_t size); */ \
[196] = { "flistxattr", { UNKNOWN }, UNKNOWN }, \
/*        int removexattr(const char *path, const char *name);
       int lremovexattr(const char *path, const char *name);
       int fremovexattr(int fd, const char *name); */ \
[197] = { "removexattr", { UNKNOWN }, UNKNOWN }, \
/*        int lremovexattr(const char *path, const char *name); */ \
[198] = { "lremovexattr", { UNKNOWN }, UNKNOWN }, \
/*        int fremovexattr(int fd, const char *name); */ \
[199] = { "fremovexattr", { UNKNOWN }, UNKNOWN }, \
/*        int tkill(int tid, int sig);
       Note: There is no glibc wrapper for tkill(); see NOTES. */ \
[200] = { "tkill", { UNKNOWN }, UNKNOWN }, \
/*        time_t time(time_t *tloc); */ \
[201] = { "time", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[202] = { "futex", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[203] = { "sched_setaffinity", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[204] = { "sched_getaffinity", { UNKNOWN }, UNKNOWN }, \
/*        int set_thread_area(struct user_desc *u_info);
       int set_thread_area(unsigned long tp);
       int set_thread_area(unsigned long addr); */ \
[205] = { "set_thread_area", { UNKNOWN }, UNKNOWN }, \
/*        long io_setup(unsigned nr_events, aio_context_t *ctx_idp); */ \
[206] = { "io_setup", { UNKNOWN }, UNKNOWN }, \
/*        int io_destroy(aio_context_t ctx_id); */ \
[207] = { "io_destroy", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[208] = { "io_getevents", { UNKNOWN }, UNKNOWN }, \
/*        int io_submit(aio_context_t ctx_id, long nr, struct iocb **iocbpp); */ \
[209] = { "io_submit", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[210] = { "io_cancel", { UNKNOWN }, UNKNOWN }, \
/*        int get_thread_area(struct user_desc *u_info);
       int get_thread_area(void); */ \
[211] = { "get_thread_area", { UNKNOWN }, UNKNOWN }, \
/*        int lookup_dcookie(u64 cookie, char *buffer, size_t len); */ \
[212] = { "lookup_dcookie", { UNKNOWN }, UNKNOWN }, \
/*        int epoll_create(int size); */ \
[213] = { "epoll_create", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[214] = { "epoll_ctl_old", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[215] = { "epoll_wait_old", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[216] = { "remap_file_pages", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[217] = { "getdents64", { UNKNOWN }, UNKNOWN }, \
/*        pid_t set_tid_address(int *tidptr); */ \
[218] = { "set_tid_address", { UNKNOWN }, UNKNOWN }, \
/*        long restart_syscall(void); */ \
[219] = { "restart_syscall", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[220] = { "semtimedop", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[221] = { "fadvise64", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[222] = { "timer_create", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[223] = { "timer_settime", { UNKNOWN }, UNKNOWN }, \
/*        int timer_gettime(timer_t timerid, struct itimerspec *curr_value); */ \
[224] = { "timer_gettime", { UNKNOWN }, UNKNOWN }, \
/*        int timer_getoverrun(timer_t timerid); */ \
[225] = { "timer_getoverrun", { UNKNOWN }, UNKNOWN }, \
/*        int timer_delete(timer_t timerid); */ \
[226] = { "timer_delete", { UNKNOWN }, UNKNOWN }, \
/*        int clock_settime(clockid_t clockid, const struct timespec *tp); */ \
[227] = { "clock_settime", { UNKNOWN }, UNKNOWN }, \
/*        int clock_gettime(clockid_t clockid, struct timespec *tp); */ \
[228] = { "clock_gettime", { UNKNOWN }, UNKNOWN }, \
/*        int clock_getres(clockid_t clockid, struct timespec *res); */ \
[229] = { "clock_getres", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[230] = { "clock_nanosleep", { UNKNOWN }, UNKNOWN }, \
/*        void exit_group(int status); */ \
[231] = { "exit_group", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[232] = { "epoll_wait", { UNKNOWN }, UNKNOWN }, \
/*        int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event); */ \
[233] = { "epoll_ctl", { UNKNOWN }, UNKNOWN }, \
/*        int tgkill(int tgid, int tid, int sig); */ \
[234] = { "tgkill", { UNKNOWN }, UNKNOWN }, \
/*        int utimes(const char *filename, const struct timeval times[2]); */ \
[235] = { "utimes", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[236] = { "vserver", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[237] = { "mbind", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[238] = { "set_mempolicy", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[239] = { "get_mempolicy", { UNKNOWN }, UNKNOWN }, \
/*        mqd_t mq_open(const char *name, int oflag); */ \
[240] = { "mq_open", { UNKNOWN }, UNKNOWN }, \
/*        int mq_unlink(const char *name); */ \
[241] = { "mq_unlink", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[242] = { "mq_timedsend", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[243] = { "mq_timedreceive", { UNKNOWN }, UNKNOWN }, \
/*        int mq_notify(mqd_t mqdes, const struct sigevent *sevp); */ \
[244] = { "mq_notify", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[245] = { "mq_getsetattr", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[246] = { "kexec_load", { UNKNOWN }, UNKNOWN }, \
/*        int waitid(idtype_t idtype, id_t id, siginfo_t *infop, int options); */ \
[247] = { "waitid", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[248] = { "add_key", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[249] = { "request_key", { UNKNOWN }, UNKNOWN }, \
/*        long keyctl(int operation, ...); */ \
[250] = { "keyctl", { UNKNOWN }, UNKNOWN }, \
/*        int ioprio_set(int which, int who, int ioprio); */ \
[251] = { "ioprio_set", { UNKNOWN }, UNKNOWN }, \
/*        int ioprio_get(int which, int who); */ \
[252] = { "ioprio_get", { UNKNOWN }, UNKNOWN }, \
/*        int inotify_init(void); */ \
[253] = { "inotify_init", { UNKNOWN }, UNKNOWN }, \
/*        int inotify_add_watch(int fd, const char *pathname, uint32_t mask); */ \
[254] = { "inotify_add_watch", { UNKNOWN }, UNKNOWN }, \
/*        int inotify_rm_watch(int fd, int wd); */ \
[255] = { "inotify_rm_watch", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[256] = { "migrate_pages", { UNKNOWN }, UNKNOWN }, \
/*        int openat(int dirfd, const char *pathname, int flags);
       int openat(int dirfd, const char *pathname, int flags, mode_t mode); */ \
[257] = { "openat", { UNKNOWN }, UNKNOWN }, \
/*        int mkdirat(int dirfd, const char *pathname, mode_t mode); */ \
[258] = { "mkdirat", { UNKNOWN }, UNKNOWN }, \
/*        int mknodat(int dirfd, const char *pathname, mode_t mode, dev_t dev); */ \
[259] = { "mknodat", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[260] = { "fchownat", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[261] = { "futimesat", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[262] = { "newfstatat", { UNKNOWN }, UNKNOWN }, \
/*        int unlinkat(int dirfd, const char *pathname, int flags); */ \
[263] = { "unlinkat", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[264] = { "renameat", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[265] = { "linkat", { UNKNOWN }, UNKNOWN }, \
/*        int symlinkat(const char *target, int newdirfd, const char *linkpath); */ \
[266] = { "symlinkat", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[267] = { "readlinkat", { UNKNOWN }, UNKNOWN }, \
/*        int fchmodat(int dirfd, const char *pathname, mode_t mode, int flags); */ \
[268] = { "fchmodat", { UNKNOWN }, UNKNOWN }, \
/*        int faccessat(int dirfd, const char *pathname, int mode, int flags); */ \
[269] = { "faccessat", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[270] = { "pselect6", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[271] = { "ppoll", { UNKNOWN }, UNKNOWN }, \
/*        int unshare(int flags); */ \
[272] = { "unshare", { UNKNOWN }, UNKNOWN }, \
/*        long set_robust_list(struct robust_list_head *head, size_t len); */ \
[273] = { "set_robust_list", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[274] = { "get_robust_list", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[275] = { "splice", { UNKNOWN }, UNKNOWN }, \
/*        ssize_t tee(int fd_in, int fd_out, size_t len, unsigned int flags); */ \
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
/*        int signalfd(int fd, const sigset_t *mask, int flags); */ \
[282] = { "signalfd", { UNKNOWN }, UNKNOWN }, \
/*        int timerfd_create(int clockid, int flags); */ \
[283] = { "timerfd_create", { UNKNOWN }, UNKNOWN }, \
/*        int eventfd(unsigned int initval, int flags); */ \
[284] = { "eventfd", { UNKNOWN }, UNKNOWN }, \
/*        int fallocate(int fd, int mode, off_t offset, off_t len); */ \
[285] = { "fallocate", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[286] = { "timerfd_settime", { UNKNOWN }, UNKNOWN }, \
/*        int timerfd_gettime(int fd, struct itimerspec *curr_value); */ \
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
/*        int fanotify_init(unsigned int flags, unsigned int event_f_flags); */ \
[300] = { "fanotify_init", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[301] = { "fanotify_mark", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[302] = { "prlimit64", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[303] = { "name_to_handle_at", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[304] = { "open_by_handle_at", { UNKNOWN }, UNKNOWN }, \
/*        int clock_adjtime(clockid_t clk_id, struct timex *buf); */ \
[305] = { "clock_adjtime", { UNKNOWN }, UNKNOWN }, \
/*        int syncfs(int fd); */ \
[306] = { "syncfs", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[307] = { "sendmmsg", { UNKNOWN }, UNKNOWN }, \
/*        int setns(int fd, int nstype); */ \
[308] = { "setns", { UNKNOWN }, UNKNOWN }, \
/*        int getcpu(unsigned *cpu, unsigned *node, struct getcpu_cache *tcache); */ \
[309] = { "getcpu", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[310] = { "process_vm_readv", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[311] = { "process_vm_writev", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[312] = { "kcmp", { UNKNOWN }, UNKNOWN }, \
/*        Note: glibc provides no header file declaration of init_module() and no wrapper function for finit_module(); see NOTES. */ \
[313] = { "finit_module", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[314] = { "sched_setattr", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[315] = { "sched_getattr", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[316] = { "renameat2", { UNKNOWN }, UNKNOWN }, \
/*        int seccomp(unsigned int operation, unsigned int flags, void *args); */ \
[317] = { "seccomp", { UNKNOWN }, UNKNOWN }, \
/*        ssize_t getrandom(void *buf, size_t buflen, unsigned int flags); */ \
[318] = { "getrandom", { UNKNOWN }, UNKNOWN }, \
/*        int memfd_create(const char *name, unsigned int flags); */ \
[319] = { "memfd_create", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[320] = { "kexec_file_load", { UNKNOWN }, UNKNOWN }, \
/*        int bpf(int cmd, union bpf_attr *attr, unsigned int size); */ \
[321] = { "bpf", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[322] = { "execveat", { UNKNOWN }, UNKNOWN }, \
/*        int userfaultfd(int flags); */ \
[323] = { "userfaultfd", { UNKNOWN }, UNKNOWN }, \
/*        int membarrier(int cmd, unsigned int flags, int cpu_id); */ \
[324] = { "membarrier", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[325] = { "mlock2", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[326] = { "copy_file_range", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[327] = { "preadv2", { UNKNOWN }, UNKNOWN }, \
/* UNKNOWN PROTOTYPE */ \
[328] = { "pwritev2", { UNKNOWN }, UNKNOWN }, \
/*        int pkey_mprotect(void *addr, size_t len, int prot, int pkey); */ \
[329] = { "pkey_mprotect", { UNKNOWN }, UNKNOWN }, \
/*        int pkey_alloc(unsigned int flags, unsigned int access_rights); */ \
[330] = { "pkey_alloc", { UNKNOWN }, UNKNOWN }, \
/*        int pkey_free(int pkey); */ \
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
