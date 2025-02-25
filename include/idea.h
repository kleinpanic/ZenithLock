#ifndef IDEA_H
#define IDEA_H

#include "algorithm.h"

/*
   IDEA block cipher in ECB mode.
   - 64-bit block size, 128-bit key.
   - Implements key expansion (producing 52 16-bit subkeys) and 8 rounds
     plus a final transformation.
   - Uses modular multiplication modulo 0x10001 (i.e. 65537, with 0 interpreted as 0x10000),
     addition modulo 0x10000, and XOR.
   - Uses PKCS#7 padding; on encryption, outputs a hex-encoded string.
   - On decryption, expects a hex-encoded ciphertext.
*/
int idea_crypt(const char *input, const char *key, int shift, mode_t mode, int otp, char *output);

#endif

