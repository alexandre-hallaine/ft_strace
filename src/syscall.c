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

t_stop *get_stop() {
    union {
        struct user_regs_struct_64 regs_64;
        struct user_regs_struct_32 regs_32;
    } regs;

    struct iovec io = { &regs, sizeof(regs) };
    t_stop *stop = malloc(sizeof(t_stop));
    
    if (stop == NULL || ptrace(PTRACE_GETREGSET, child_pid, NT_PRSTATUS, &io) == -1)
        return NULL;

    if (io.iov_len == sizeof(struct user_regs_struct_64)) {
        stop->arch = ARCH_64;
        stop->syscall = syscall_64 + regs.regs_64.orig_rax;
        stop->args[0] = regs.regs_64.rdi;
        stop->args[1] = regs.regs_64.rsi;
        stop->args[2] = regs.regs_64.rdx;
        stop->args[3] = regs.regs_64.r10;
        stop->args[4] = regs.regs_64.r8;
        stop->args[5] = regs.regs_64.r9;
        stop->ret = regs.regs_64.rax;
    } else {
        stop->arch = ARCH_32;
        stop->syscall = syscall_32 + regs.regs_32.orig_eax;
        stop->args[0] = regs.regs_32.ebx;
        stop->args[1] = regs.regs_32.ecx;
        stop->args[2] = regs.regs_32.edx;
        stop->args[3] = regs.regs_32.esi;
        stop->args[4] = regs.regs_32.edi;
        stop->args[5] = regs.regs_32.ebp;
        stop->ret = regs.regs_32.eax;
    }

    return stop;
}

t_stop *wait_syscall(int *status) {
    if (WIFEXITED(*status))
        return NULL;

    while (1) {
        ptrace(PTRACE_SYSCALL, child_pid, NULL, NULL);
        waitpid(child_pid, status, 0);

        if (WIFSTOPPED(*status) && WSTOPSIG(*status) & (SIGTRAP | 0x80)) // PTRACE_O_TRACESYSGOOD
            return get_stop();
        if (WIFEXITED(*status))
            return NULL;
    }
}

void print_syscall(t_stop *before, t_stop *after) {
    if (before == NULL) return;
    if (after != NULL && before->arch != after->arch)
        printf("Architecture switched to %s\n", after->arch == ARCH_64 ? "x86_64" : "x86");

    printf("%s(", before->syscall->name);

    for (int i = 0; before->syscall->args[i]; i++) {
        if (i > 0) printf(", ");
        print_value(before->syscall->args[i], before->args[i], before->arch);
    }

    printf(") = ");

    if (after != NULL)
        print_value(after->syscall->ret, after->ret, after->arch);
    else
        printf("?");

    printf("\n");

    free(before);
    if (after != NULL)
        free(after); 
}
