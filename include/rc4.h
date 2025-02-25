#ifndef RC4_H
#define RC4_H

#include "algorithm.h"

int rc4_crypt(const char *input, const char *key, int shift, mode_t mode, int otp, char *output);

#endif

