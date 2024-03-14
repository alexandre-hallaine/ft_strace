#pragma once

#include "types.h"

#include <sys/types.h>
#include <sys/user.h>

// syscall.c
int wait_for_syscall(pid_t child);
struct user_regs_struct get_regs(pid_t child_pid);
void print_syscall(struct user_regs_struct *before, struct user_regs_struct *after);

// value.c
unsigned long print_value(t_type type, void *value);
