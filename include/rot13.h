#ifndef ROT13_H
#define ROT13_H

#include "algorithm.h"

/* ROT13 is a symmetric substitution cipher that shifts letters by 13.
   It ignores key, shift, and OTP flags. */
int rot13_crypt(const char *input, const char *key, int shift, mode_t mode, int otp, char *output);

#endif

