#ifndef AES_H
#define AES_H

#include "algorithm.h"
#include <stdint.h>

/*
 * AES-128 ECB mode encryption/decryption.
 *
 * - The key must be exactly 16 bytes (128 bits).
 * - Encryption pads plaintext with PKCS#7 to a multiple of 16 bytes and
 *   outputs a hex string (2× binary length + '\0').
 * - Decryption takes a hex string, converts to binary, decrypts each 16-byte block,
 *   removes PKCS#7 padding, and writes plaintext plus '\0'.
 *
 * WARNING: ECB mode is **not** semantically secure for structured or repeated data.
 */
int aes_crypt(const char *input,
              const char *key,
              int shift,
              mode_t mode,
              int otp,
              char *output);

#endif /* AES_H */

