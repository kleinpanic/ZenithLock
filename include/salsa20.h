#ifndef SALSA20_H
#define SALSA20_H

#include "algorithm.h"

/*
   Salsa20 stream cipher.
   - Processes data in 64-byte blocks.
   - Expects a key in the format "64char,16char", where:
       * The first 64 characters are a hex-encoded 32-byte key.
       * The next 16 characters (after a comma) are a hex-encoded 8-byte nonce.
   - Encryption and decryption are identical.
   - Outputs raw text (or can be used with additional encoding).
*/
int salsa20_crypt(const char *input, const char *key, int shift, mode_t mode, int otp, char *output);

#endif

