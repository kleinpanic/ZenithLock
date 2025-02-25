#ifndef ATBASH_H
#define ATBASH_H

#include "algorithm.h"

int atbash_crypt(const char *input, const char *key, int shift, mode_t mode, int otp, char *output);

#endif

