#pragma once

#include <sys/types.h>
#include <sys/user.h>

int wait_for_syscall(pid_t child);
struct user_regs_struct get_regs(pid_t child_pid);
void print_syscall(struct user_regs_struct *before, struct user_regs_struct *after);
