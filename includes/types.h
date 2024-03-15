#pragma once

#include <sys/types.h>

extern pid_t child_pid;

typedef enum e_type {
    UNKNOWN = 0,

    PTR,

    CHAR,
    STR,

    SHORT,
    INT,
    LONG,

    ARRAY = 1 << 3,
} t_type;

typedef struct s_syscall {
    char *name;
    t_type args[7];
    t_type ret;
} t_syscall;
