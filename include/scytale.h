#ifndef SCYTALE_H
#define SCYTALE_H

#include "algorithm.h"

/*
   Scytale cipher:
   - The shift parameter indicates the number of rows.
   - Encryption: fill matrix column-wise then read row-wise.
   - Decryption: reverse the process.
   - Key and OTP flags are ignored.
*/
int scytale_crypt(const char *input, const char *key, int shift, mode_t mode, int otp, char *output);

#endif

