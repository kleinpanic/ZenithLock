#ifndef XTEA_H
#define XTEA_H

#include "algorithm.h"

/*
   XTEA block cipher.
   Key: Must be exactly 16 characters (128 bits).
   Operates on 64-bit blocks (8 bytes).
   Encryption:
     - Pads input with zeros to a multiple of 8 bytes.
     - Encrypts each block and outputs a hex string.
   Decryption:
     - Expects a hex string, converts it to binary,
     - Decrypts each block, and outputs the plaintext.
   (The shift and OTP flags are ignored.)
*/
int xtea_crypt(const char *input, const char *key, int shift, mode_t mode, int otp, char *output);

#endif

