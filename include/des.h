#ifndef DES_H
#define DES_H

#include "algorithm.h"

/*
   DES encryption/decryption in ECB mode (simplified demo).
   - Key must be exactly 8 characters.
   - Pads plaintext using PKCS#7 to a multiple of 8 bytes.
   - For encryption, outputs a hex string; for decryption, expects a hex string,
     converts to binary, decrypts, and removes padding.
   NOTE: This implementation is for demonstration purposes only.
*/
int des_crypt(const char *input, const char *key, int shift, mode_t mode, int otp, char *output);

#endif

