#ifndef ALGORITHM_H
#define ALGORITHM_H

typedef enum { MODE_ENCRYPT, MODE_DECRYPT } mode_t;

typedef int (*crypt_func)(const char *input, const char *key, int shift, mode_t mode, int otp, char *output);

typedef struct {
    const char *name;
    const char *description;
    crypt_func crypt;
} algorithm_t;

#endif

