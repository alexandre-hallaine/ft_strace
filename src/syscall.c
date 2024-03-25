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
        ptrace(PTRACE_SYSCALL, child_pid, NULL, NULL);
        waitpid(child_pid, &status, 0);

        if (WIFSTOPPED(status) && WSTOPSIG(status) & (SIGTRAP | 0x80)) // PTRACE_O_TRACESYSGOOD
            return 0;
        if (WIFEXITED(status))
            return 1;
    }
}

t_stop get_stop() {
    union {
        struct user_regs_struct_64 regs_64;
        struct user_regs_struct_32 regs_32;
    } regs;

    struct iovec io = { &regs, sizeof(regs) };
    ptrace(PTRACE_GETREGSET, child_pid, NT_PRSTATUS, &io);

    if (io.iov_len == sizeof(struct user_regs_struct_64))
        return (t_stop) {
            .arch = ARCH_64,
            .syscall = syscall_64 + regs.regs_64.orig_rax,
            .args = {
                regs.regs_64.rdi,
                regs.regs_64.rsi,
                regs.regs_64.rdx,
                regs.regs_64.r10,
                regs.regs_64.r8,
                regs.regs_64.r9,
            },
            .ret = regs.regs_64.rax,
        };
    else
        return (t_stop) {
            .arch = ARCH_32,
            .syscall = syscall_32 + regs.regs_32.orig_eax,
            .args = {
                regs.regs_32.ebx,
                regs.regs_32.ecx,
                regs.regs_32.edx,
                regs.regs_32.esi,
                regs.regs_32.edi,
                regs.regs_32.ebp,
            },
            .ret = regs.regs_32.eax,
        };
}

void print_syscall(t_stop *before, t_stop *after) {
    if (after != NULL && before->arch != after->arch)
        printf("Architecture switched to %s\n", after->arch == ARCH_64 ? "x86_64" : "x86");

    printf("%s(", before->syscall->name);

    for (int i = 0; before->syscall->args[i]; i++) {
        if (i > 0)
            printf(", ");
        print_value(before->syscall->args[i], before->args[i], before->arch);
    }

    printf(") = ");

    if (after != NULL)
        print_value(after->syscall->ret, after->ret, after->arch);
    else
        printf("?");

    printf("\n");
}
