#ifndef AFFINE_H
#define AFFINE_H

#include "algorithm.h"

/*
 * Affine cipher:
 *   E(x) = (a*x + b) mod 26
 *   D(x) = a_inv * (x - b) mod 26
 *
 * - key must be "a,b" where 0<=b<26 and gcd(a,26)==1.
 * - shift and otp parameters are ignored, but otp will cause an error.
 */
int affine_crypt(const char *input,
                 const char *key,
                 int shift,
                 mode_t mode,
                 int otp,
                 char *output);

#endif /* AFFINE_H */

