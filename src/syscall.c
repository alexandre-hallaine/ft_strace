#include "types.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/uio.h>

#include <linux/elf.h>

t_syscall x64_syscalls[] = X64_SYSCALLS;

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

struct user_regs_struct get_regs(pid_t child_pid) {
    struct user_regs_struct regs;
    struct iovec io = { &regs, sizeof(regs) };
    ptrace(PTRACE_GETREGSET, child_pid, NT_PRSTATUS, &io);
    return regs;
}

void print_syscall(struct user_regs_struct *before, struct user_regs_struct *after) {
    t_syscall *syscall = x64_syscalls + before->orig_rax;
    printf("%s()", syscall->name);

    if (after)
        printf(" = %lld\n", after->rax);
    else
        printf(" = ?\n");
}
