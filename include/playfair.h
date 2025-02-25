#ifndef PLAYFAIR_H
#define PLAYFAIR_H

#include "algorithm.h"

/* 
   Playfair cipher:
   - The key is used to build a 5x5 matrix (treating I/J as the same).
   - Non-alphabetic characters are ignored.
   - For encryption, duplicate letters in a digraph are separated by an 'X'.
   - Decryption reverses the process.
   Note: The shift and OTP flags are ignored.
*/
int playfair_crypt(const char *input, const char *key, int shift, mode_t mode, int otp, char *output);

#endif

