#include "types.h"

#include <stdio.h>
#include <string.h>

unsigned long print_type(t_type type, void *value) {
    switch (type) {
        case PTR:
            printf("%p", *(void **)value);
            return 1;

        case CHAR:
            printf("%c", *(char *)value);
            return 1;
        case STR:
            printf("\"%s\"", *(char **)value);
            return 8;

        case SHORT:
            printf("%hd", *(short *)value);
            return 2;
        case INT:
            printf("%d", *(int *)value);
            return 4;
        case LONG:
            printf("%ld", *(long *)value);
            return 8;

        default:
            printf("?");
            return 0;
    }
}

unsigned long print_value(t_type type, void *value) {
    if (!(type & ARRAY))
        return print_type(type, value);

    type &= ~ARRAY;
    value = *(void **)value;
    unsigned long i = 0;
    printf("[");

    for (; *(void **)(value + i);) {
        if (i)
            printf(", ");
        i += print_type(type, value + i);
    }

    printf("]");
    return i;
}
