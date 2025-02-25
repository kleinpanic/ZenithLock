#ifndef SHA256HASH_H
#define SHA256HASH_H

#include "algorithm.h"

/*
   SHA‑256 hash function.
   – Since it is not keyed, decryption is not applicable.
   – In “encryption” mode, it computes the SHA‑256 hash of the input and outputs a hex string.
*/
int sha256hash_crypt(const char *input, const char *key, int shift, mode_t mode, int otp, char *output);

#endif

