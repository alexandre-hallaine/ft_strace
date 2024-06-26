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

t_stop stop_64(struct user_regs_struct_64 *regs) {
    return (t_stop) {
            .arch = ARCH_64,
            .syscall = syscall_64 + regs->orig_rax,
            .args = { regs->rdi, regs->rsi, regs->rdx, regs->r10, regs->r8, regs->r9 },
            .ret = regs->rax
    };
}

t_stop stop_32(struct user_regs_struct_32 *regs) {
    return (t_stop) {
            .arch = ARCH_32,
            .syscall = syscall_32 + regs->orig_eax,
            .args = { regs->ebx, regs->ecx, regs->edx, regs->esi, regs->edi, regs->ebp },
            .ret = regs->eax
    };
}

void populate_stop(t_stop *stop) {
    union {
        struct user_regs_struct_64 regs_64;
        struct user_regs_struct_32 regs_32;
    } regs;

    struct iovec io = { &regs, sizeof(regs) };
    if (ptrace(PTRACE_GETREGSET, child_pid, NT_PRSTATUS, &io) == -1)
        return;

    if (io.iov_len == sizeof(struct user_regs_struct_64))
        *stop = stop_64(&regs.regs_64);
    else
        *stop = stop_32(&regs.regs_32);
}

t_stop wait_syscall() {
    t_stop stop = {0};
    int status;
    siginfo_t info;

    ptrace(PTRACE_SYSCALL, child_pid, NULL, NULL);
    waitpid(child_pid, &status, 0);
    ptrace(PTRACE_GETSIGINFO, child_pid, NULL, &info);

    if (WIFEXITED(status)) {
        stop.status = EXIT;
        stop.ret = WEXITSTATUS(status);
    } else if (WIFSIGNALED(status)) {
        stop.status = SIGNAL;
        stop.ret = WTERMSIG(status);
    } else if (info.si_signo != SIGTRAP) {
        stop.status = SIGNAL;
        stop.ret = info.si_signo;
        kill(child_pid, SIGKILL);
    } else {
        stop.status = RUN;
        populate_stop(&stop);
    }

    return stop;
}

void print_syscall(t_stop *before, t_stop *after) {
    if (before->status != RUN) return;
    if (after->status == RUN && before->arch != after->arch)
        printf("Architecture switched to %s\n", after->arch == ARCH_64 ? "x86_64" : "x86");

    printf("%s(", before->syscall->name);

    for (int i = 0; before->syscall->args[i]; i++) {
        if (i > 0) printf(", ");
        print_value(before->syscall->args[i], before->args[i], before->arch);
    }

    printf(") = ");
    if (after->status == RUN)
        print_value(after->syscall->ret, after->ret, after->arch);
    else
        printf("?");
    printf("\n");
}
