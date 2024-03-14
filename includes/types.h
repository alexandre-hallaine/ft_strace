#pragma once

typedef enum e_type {
    NONE,

    PTR = 1 << 0,

    CHAR = 1 << 1,
    STR = 1 << 5,

    SHORT = 1 << 2,
    INT = 1 << 3,
    LONG = 1 << 4,

    ARRAY = 1 << 6,
} t_type;

typedef struct s_syscall {
    char *name;
    t_type args[6];
    t_type ret;
} t_syscall;
