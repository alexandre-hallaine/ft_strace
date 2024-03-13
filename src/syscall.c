#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>

int wait_for_syscall(pid_t child) {
    int status;
    while (1) {
        ptrace(PTRACE_SYSCALL, child, NULL, NULL);
        waitpid(child, &status, 0);

        if (WIFSTOPPED(status) && WSTOPSIG(status) & (SIGTRAP | 0x80))
            return 0;
        if (WIFEXITED(status))
            return 1;
    }
}

void enter_syscall(pid_t child_pid) {
    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);
    printf("syscall(%lld)", regs.orig_rax);
}

void exit_syscall(pid_t child_pid) {
    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);
    printf(" = %lld\n", regs.rax);
}
