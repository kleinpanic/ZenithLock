#ifndef BLOWFISH_H
#define BLOWFISH_H

#include <stdint.h>

/* how many P‐subkeys and S‐boxes we have */
#define BLOWFISH_SUBKEYS        18
#define BLOWFISH_SBOXES          4
#define BLOWFISH_SBOX_ENTRIES  256

/* allowed key lengths */
#define BLOWFISH_MIN_KEY_LENGTH  4
#define BLOWFISH_MAX_KEY_LENGTH 56

/**
 * @brief  Encrypt or decrypt a NUL-terminated buffer with Blowfish-ECB + PKCS#7.
 *
 * @param  input   plaintext (encrypt) or hex string (decrypt)
 * @param  key     4–56 byte NUL-terminated key
 * @param  shift   unused (for API conformance)
 * @param  mode    0 = encrypt, 1 = decrypt (your MODE_ENCRYPT/MODE_DECRYPT)
 * @param  otp     unused
 * @param  output  caller-provided buffer to receive a NUL-terminated result
 * @return 0 on success, –1 on failure
 */
int blowfish_crypt(const char *input,
                   const char *key,
                   int         shift,
                   int         mode,
                   int         otp,
                   char       *output);

#endif /* BLOWFISH_H */

