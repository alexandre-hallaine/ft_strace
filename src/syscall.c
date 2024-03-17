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

int wait_for_syscall() {
    int status;
    while (1) {
        ptrace(PTRACE_SYSCALL, g_data.child_pid, NULL, NULL);
        waitpid(g_data.child_pid, &status, 0);

        if (WIFSTOPPED(status) && WSTOPSIG(status) & (SIGTRAP | 0x80)) // PTRACE_O_TRACESYSGOOD
            return 0;
        if (WIFEXITED(status))
            return 1;
    }
}

t_regs get_regs() {
    t_regs regs;
    struct iovec io = { &regs, sizeof(regs) };

    ptrace(PTRACE_GETREGSET, g_data.child_pid, NT_PRSTATUS, &io);
    g_data.arch = io.iov_len == sizeof(struct user_regs_struct_64) ? ARCH_64 : ARCH_32;

    return regs;
}

void print_syscall_algo(t_syscall *syscall, void *args[], void *ret) {
    printf("%s(", syscall->name);

    for (int i = 0; syscall->args[i]; i++) {
        if (i > 0)
            printf(", ");
        print_value(syscall->args[i], args[i]);
    }
    printf(") = ");

    if (ret)
        print_value(syscall->ret, ret);
    else
        printf("?");

    printf("\n");
}

void print_syscall(t_regs *before, t_regs *after) {
    if (g_data.arch == ARCH_32) {
        if (before->regs_32.orig_eax > 0 && before->regs_32.orig_eax <= SYSCALL_TABLE_32_MAX)
            print_syscall_algo(syscall_32 + before->regs_32.orig_eax,
                                       (void *[]) {&before->regs_32.ebx, &before->regs_32.ecx, &before->regs_32.edx,
                                                   &before->regs_32.esi, &before->regs_32.edi, &before->regs_32.ebp},
                                       after == NULL ? NULL : &after->regs_32.eax);
    } else {
        if (before->regs_64.orig_rax > 0 && before->regs_64.orig_rax <= SYSCALL_TABLE_64_MAX)
            print_syscall_algo(syscall_64 + before->regs_64.orig_rax,
                                       (void *[]) {&before->regs_64.rdi, &before->regs_64.rsi, &before->regs_64.rdx,
                                                   &before->regs_64.r10, &before->regs_64.r8, &before->regs_64.r9},
                                       after == NULL ? NULL : &after->regs_64.rax);
    }
}
