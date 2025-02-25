#ifndef TWOFISH_H
#define TWOFISH_H

#include "algorithm.h"

/*
   Twofish block cipher in ECB mode.
   - 128‑bit block size.
   - Key sizes of 128, 192, or 256 bits are supported.
   - Implements key schedule (including key‑dependent S‑boxes, MDS matrix multiplication,
     and the pseudo‑Hadamard transform) and 16 rounds of Feistel structure.
   - Provides encryption and decryption with PKCS#7 padding.
   
   This is a reference “from‑scratch” implementation following the Twofish specification.
   Achieving production‑grade security requires constant‑time coding, careful side‑channel
   resistance (possibly with inline assembly), and extensive testing.
*/
int twofish_crypt(const char *input, const char *key, int shift, mode_t mode, int otp, char *output);

#endif

