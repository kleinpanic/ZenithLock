#ifndef ATBASH_H
#define ATBASH_H

#include "algorithm.h"

/*
 * Atbash cipher (involutive substitution):
 *   - 'a' <-> 'z', 'b' <-> 'y', ..., 'A' <-> 'Z'
 *   - Non-letters are passed through.
 *
 * Parameters:
 *   input  : NUL-terminated plaintext or ciphertext.
 *   key    : ignored (pass NULL or "").
 *   shift  : ignored.
 *   mode   : ignored (same operation for encrypt/decrypt).
 *   otp    : must be 0 (OTP mode unsupported).
 *   output : buffer at least strlen(input)+1 bytes.
 *
 * Returns 0 on success, -1 on error (null pointers or unsupported otp).
 */
int atbash_crypt(const char *input,
                 const char *key,
                 int shift,
                 mode_t mode,
                 int otp,
                 char *output);

#endif /* ATBASH_H */

