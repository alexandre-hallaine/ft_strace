#include "syscall/64.h"
#include "syscall/32.h"
#include "functions.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/uio.h>

#include <linux/elf.h>

t_syscall syscall_64[] = SYSCALL_TABLE_64;
t_syscall syscall_32[] = SYSCALL_TABLE_32;

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
    for (int i = 0; syscall->args[i]; i++) {
        if (i > 0)
            printf(", ");
        print_value(syscall->args[i], args[i]);
    }
}

void print_syscall(struct user_regs_struct *before, struct user_regs_struct *after) {
    t_syscall *syscall = syscall_64 + before->orig_rax;

    printf("%s(", syscall->name);
    print_syscall_args(syscall, (void *[]){ &before->rdi, &before->rsi, &before->rdx, &before->r10, &before->r8, &before->r9 });
    printf(") = ");
    if (after)
        print_value(syscall->ret, &after->rax);
    else
        printf("?");
    printf("\n");
}
