#ifndef AES_H
#define AES_H

#include "algorithm.h"

/*
   AES-128 ECB mode encryption/decryption (simplified demo).
   - The key must be exactly 16 characters.
   - Encryption pads the plaintext using PKCS#7 to a multiple of 16 bytes and
     outputs a hex string.
   - Decryption expects a hex string, converts it to binary,
     decrypts each 16-byte block, and removes padding.
   (This is a basic implementation and not hardened for production use.)
*/
int aes_crypt(const char *input, const char *key, int shift, mode_t mode, int otp, char *output);

#endif

