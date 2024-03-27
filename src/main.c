#include "functions.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <sys/ptrace.h>
#include <sys/wait.h>

pid_t child_pid = 0;

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

    child_pid = fork();
    if (child_pid == 0)
        return child(argv[1], argv + 1);

    ptrace(PTRACE_SEIZE, child_pid, NULL, PTRACE_O_TRACESYSGOOD); // take control of the child
    waitpid(child_pid, NULL, 0); // wait the kill

    sigset_t mask;
    sigfillset(&mask);
    sigprocmask(SIG_SETMASK, &mask, NULL);

    int index = 0;
    t_stop tmp[2] = {0};

    while (1) {
        tmp[index] = wait_syscall();
        if (index) print_syscall(tmp, tmp + 1);
        if (tmp[index].status != RUN) break;
        index = !index;
    }

    if (tmp[index].status == EXIT)
        printf("+++ exited with %ld +++\n", tmp[index].ret);
    else
        printf("+++ killed by %s +++\n", strsignal((int)tmp[index].ret));
}
