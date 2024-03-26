#include "functions.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>

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

    ptrace(PTRACE_SEIZE, child_pid, NULL, NULL); // take control of the child
    waitpid(child_pid, NULL, 0); // wait the kill
    ptrace(PTRACE_SETOPTIONS, child_pid, NULL, PTRACE_O_TRACESYSGOOD);

    int status = -1;
    while (!WIFEXITED(status)) {
        t_stop *first_stop = wait_syscall(&status); // enter the syscall
        t_stop *second_stop = wait_syscall(&status); // exit the syscall
        print_syscall(first_stop, second_stop);
    }
    printf("+++ exited with %d +++\n", WEXITSTATUS(status));
}
