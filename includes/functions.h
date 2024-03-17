#pragma once

#include "types.h"

// syscall.c
int wait_for_syscall();
t_regs get_regs();
void print_syscall(t_regs *before, t_regs *after);

// value.c
void print_value(t_type type, void *value);
