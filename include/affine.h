#ifndef AFFINE_H
#define AFFINE_H

#include "algorithm.h"

/* Affine cipher encryption/decryption.
   The key must be provided in the format "a,b" (for example, "5,8"),
   where 'a' (multiplicative factor) must be coprime with 26 and 'b' is the additive offset.
   The shift and OTP flags are ignored.
*/
int affine_crypt(const char *input, const char *key, int shift, mode_t mode, int otp, char *output);

#endif

