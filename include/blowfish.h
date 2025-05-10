#ifndef BLOWFISH_H
#define BLOWFISH_H

#include "algorithm.h"
#include "blowfish_tables.h"

/*
 * Blowfish-64 in ECB mode with PKCS#7 padding.
 *
 * - Key length: 4–56 bytes
 * - Block size: 8 bytes
 * - Encryption outputs hex-encoded ciphertext.
 * - Decryption parses hex, strips PKCS#7, and null-terminates.
 *
 * Parameters:
 *   input  : NUL-terminated plaintext (or hex ciphertext if decrypting)
 *   key    : binary-safe key, length [4..56].
 *   shift  : unused (set 0).
 *   mode   : MODE_ENCRYPT or MODE_DECRYPT.
 *   otp    : unused (must be 0).
 *   output : buffer large enough for result.
 *
 * Returns 0 on success, -1 on error.
 */
int blowfish_crypt(const char *input,
                   const char *key,
                   int shift,
                   mode_t mode,
                   int otp,
                   char *output);

#endif /* BLOWFISH_H */

