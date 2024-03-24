#pragma once

#include "types.h"

// syscall.c
int wait_for_syscall();
t_stop get_stop();
void print_syscall(t_stop *before, t_stop *after);

// value.c
void print_value(t_type type, long value, t_arch arch);
