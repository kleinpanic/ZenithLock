#ifndef CHACHA20_H
#define CHACHA20_H

#include "algorithm.h"

/*
   ChaCha20 stream cipher.
   The key must be provided in the format "32char,12char" (32‑character key and 12‑character nonce).
   This implementation uses 20 rounds.
   Encryption and decryption are identical.
*/
int chacha20_crypt(const char *input, const char *key, int shift, mode_t mode, int otp, char *output);

#endif

