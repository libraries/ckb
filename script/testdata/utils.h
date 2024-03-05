
#ifndef __UTILS_H__
#define __UTILS_H__

#include <stdio.h>

#define CHECK2(cond, code)                                                     \
    do {                                                                       \
        if (!(cond)) {                                                         \
            printf("error at %s:%d, error code %d", __FILE__, __LINE__, code); \
            err = code;                                                        \
            goto exit;                                                         \
        }                                                                      \
    } while (0)

#define CHECK(_code)                                                           \
    do {                                                                       \
        int code = (_code);                                                    \
        if (code != 0) {                                                       \
            printf("error at %s:%d, error code %d", __FILE__, __LINE__, code); \
            err = code;                                                        \
            goto exit;                                                         \
        }                                                                      \
    } while (0)
#endif

#define countof(array) (sizeof(array)/sizeof(array[0]))

// conventions
#define CKB_STDIN (0)
#define CKB_STDOUT (1)

