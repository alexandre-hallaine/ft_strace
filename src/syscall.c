#include "x86_64.h"
#include "functions.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/uio.h>

#include <linux/elf.h>

t_syscall x64_syscalls[] = X64_SYSCALLS;

int wait_for_syscall(pid_t child) {
    int status;
    while (1) {
        ptrace(PTRACE_SYSCALL, child, NULL, NULL);
        waitpid(child, &status, 0);

        if (WIFSTOPPED(status) && WSTOPSIG(status) & (SIGTRAP | 0x80)) // PTRACE_O_TRACESYSGOOD
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

void print_syscall_args(t_syscall *syscall, void *args[]) {
    if (syscall->args[0] == NONE)
        printf("NULL");
    else
    {
        int i = 0;
        do {
            print_value(syscall->args[i], args[i]);
            if (i < 6 - 1 && syscall->args[++i])
                printf(", ");
            else
                break;
        } while (1);
    }
}

void print_syscall(struct user_regs_struct *before, struct user_regs_struct *after) {
    t_syscall *syscall = x64_syscalls + before->orig_rax;

    printf("%s(", syscall->name);
    fflush(stdout);
    print_syscall_args(syscall, (void *[]){ &before->rdi, &before->rsi, &before->rdx, &before->r10, &before->r8, &before->r9 });
    printf(") = ");
    if (after)
        print_value(syscall->ret, &after->rax);
    else
        printf("?");
    printf("\n");
}
