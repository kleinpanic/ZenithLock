#ifndef CAST5_H
#define CAST5_H

#include "algorithm.h"

/*
   CAST5 (CAST-128) block cipher in ECB mode.
   - Block size: 64 bits.
   - Key size: fixed to 16 characters (128 bits) for this implementation.
   - Implements a simple Feistel network with 16 rounds.
   - Uses PKCS#7 padding.
   - On encryption, outputs a hex‑encoded string; on decryption, expects a hex‑encoded ciphertext.
*/
int cast5_crypt(const char *input, const char *key, int shift, mode_t mode, int otp, char *output);

#endif

