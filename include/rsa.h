#ifndef RSA_H
#define RSA_H

#include "algorithm.h"

/*
   RSA encryption/decryption (simplified demo).
   The key must be provided in the format "x,y" where:
     - For encryption, x = public exponent e and y = modulus n.
     - For decryption, x = private exponent d and y = modulus n.
   (A real RSA implementation uses proper padding schemes and separate public/private keys.)
   Encryption converts each character’s byte value via modular exponentiation,
   outputting a space‐separated list of numbers.
   Decryption expects that list as input.
*/
int rsa_crypt(const char *input, const char *key, int shift, mode_t mode, int otp, char *output);

#endif

