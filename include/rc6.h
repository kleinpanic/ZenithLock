#ifndef RC6_H
#define RC6_H

#include "algorithm.h"

/*
   RC6 block cipher in ECB mode.
   - 128-bit block size.
   - Uses 20 rounds.
   - Accepts a 16-character key (raw key) or a 32-character hex-encoded key.
   - Uses PKCS#7 padding.
   - On encryption, outputs a hex-encoded string; on decryption, expects hex.
*/
int rc6_crypt(const char *input, const char *key, int shift, mode_t mode, int otp, char *output);

#endif

