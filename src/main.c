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

    sigset_t mask;
    sigfillset(&mask);
    sigprocmask(SIG_SETMASK, &mask, NULL);

    ptrace(PTRACE_SEIZE, child_pid, NULL, PTRACE_O_TRACESYSGOOD); // take control of the child
    waitpid(child_pid, NULL, 0); // wait the kill

    t_stop *tmp = NULL;
    for (bool first = true;; first = !first) {
        t_stop *current = wait_syscall();
        if (!first)
            print_syscall(tmp, current);

        if (tmp != NULL)
            free(tmp);
        tmp = current;

        if (current->status != RUN)
            break;
    }

    if (tmp->status == EXIT)
        printf("+++ exited with %ld +++\n", tmp->ret);
    else
        printf("+++ killed by %s +++\n", strsignal((int)tmp->ret));
    free(tmp);
}
