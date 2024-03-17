#include "functions.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/ptrace.h>
#include <sys/wait.h>

t_data g_data = {0};

int child(char *file, char *argv[])
{
    kill(getpid(), SIGSTOP); // make an interupt
    return execvp(file, argv);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <program> [args...]\n", argv[0]);
        exit(1);
    }

    pid_t child_pid = g_data.child_pid = fork();
    if (child_pid == 0)
        return child(argv[1], argv + 1);

    ptrace(PTRACE_SEIZE, child_pid, NULL, NULL); // take control of the child
    waitpid(child_pid, NULL, 0); // wait the kill
    ptrace(PTRACE_SETOPTIONS, child_pid, NULL, PTRACE_O_TRACESYSGOOD);

    t_regs regs[2];
    for (int index = 0;; index = 0) {
        if (wait_for_syscall() == 0)
            regs[index++] = get_regs(); // syscall entry
        if (wait_for_syscall() == 0)
            regs[index++] = get_regs(); // syscall exit

        if (index == 1)
            print_syscall(regs, NULL);
        if (index == 2)
            print_syscall(regs, regs + 1);
        else break;
    }

    siginfo_t info;
    ptrace(PTRACE_GETSIGINFO, child_pid, NULL, &info);
    printf("+++ exited with %d +++\n", info.si_status);
}
