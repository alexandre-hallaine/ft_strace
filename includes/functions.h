#pragma once

#include "types.h"

// syscall.c
t_stop wait_syscall();
void print_syscall(t_stop *before, t_stop *after);

// value.c
void print_value(t_type type, long value, t_arch arch);
