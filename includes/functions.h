#pragma once

#include <sys/types.h>

int wait_for_syscall(pid_t child);
void enter_syscall(pid_t child_pid);
void exit_syscall(pid_t child_pid);
