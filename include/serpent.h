#ifndef SERPENT_H
#define SERPENT_H

#include "algorithm.h"

/*
   Serpent block cipher in ECB mode.
   - 128-bit block size.
   - Key size: 128, 192, or 256 bits.
   - Implements 32 rounds of S-box substitution, linear transformation, and whitening.
   - Uses PKCS#7 padding.
   - On encryption, outputs a hex string; on decryption, expects hex input.
   
   This is a skeleton reference implementation outline. A production‑grade implementation
   would require constant‑time S‑box lookups, careful key schedule implementation, and
   rigorous side‑channel resistance.
*/
int serpent_crypt(const char *input, const char *key, int shift, mode_t mode, int otp, char *output);

#endif

