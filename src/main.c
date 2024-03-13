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

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <program> [args...]\n", argv[0]);
        exit(1);
    }

    pid_t child = fork();
    if (child == 0)
        return execvp(argv[1], argv + 1);

    ptrace(PTRACE_SEIZE, child, NULL, NULL);
    ptrace(PTRACE_INTERRUPT, child, NULL, NULL);
    waitpid(child, NULL, 0);

    struct user_regs_struct regs;
    ptrace(PTRACE_SETOPTIONS, child, NULL, PTRACE_O_TRACESYSGOOD);
    while (1) {
        if (wait_for_syscall(child) != 0)
            break;

        // Get the system call number
        ptrace(PTRACE_GETREGS, child, NULL, &regs);
        printf("syscall(%lld)", regs.orig_rax);

        if (wait_for_syscall(child) != 0)
            break;

        // Get the return value of the system call
        ptrace(PTRACE_GETREGS, child, NULL, &regs);
        printf(" = %lld\n", regs.rax);
    }

    return 0;
}
