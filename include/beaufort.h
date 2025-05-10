#ifndef BEAUFORT_H
#define BEAUFORT_H

#include "algorithm.h"

/*
 * Beaufort cipher (involutive polyalphabetic substitution):
 *
 *   C[i] = (K_i - P_i) mod 26
 *
 * Parameters:
 *   input : NUL-terminated plaintext or ciphertext.
 *   key   : string of letters; in non-OTP mode it repeats cyclically,
 *           in OTP mode (otp==1) must be the same length as input.
 *   shift : ignored.
 *   mode  : ignored (same operation for encrypt/decrypt).
 *   otp   : if 1, enforces key length == input length.
 *   output: buffer of at least strlen(input)+1 bytes.
 *
 * Returns  0 on success,
 *         -1 on error (null pointers, empty key, invalid key chars,
 *                    key-length mismatch in OTP mode).
 */
int beaufort_crypt(const char *input,
                   const char *key,
                   int shift,
                   mode_t mode,
                   int otp,
                   char *output);

#endif /* BEAUFORT_H */

