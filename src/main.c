#include "functions.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/ptrace.h>
#include <sys/wait.h>

int child(char *file, char *argv[])
{
    kill(getpid(), SIGSTOP);
    return execvp(file, argv);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <program> [args...]\n", argv[0]);
        exit(1);
    }

    pid_t child_pid = fork();
    if (child_pid == 0)
        return child(argv[1], argv + 1);

    ptrace(PTRACE_SEIZE, child_pid, NULL, NULL);
    waitpid(child_pid, NULL, 0);

    ptrace(PTRACE_SETOPTIONS, child_pid, NULL, PTRACE_O_TRACESYSGOOD);
    while (1) {
        if (wait_for_syscall(child_pid) != 0) break;
        enter_syscall(child_pid);
        if (wait_for_syscall(child_pid) != 0) break;
        exit_syscall(child_pid);
    }

    siginfo_t info;
    ptrace(PTRACE_GETSIGINFO, child_pid, NULL, &info);
    printf("\nStopped by signal %d\n", info.si_signo);
}
