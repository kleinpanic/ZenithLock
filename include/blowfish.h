#ifndef BLOWFISH_H
#define BLOWFISH_H

#include "algorithm.h"

/*
   Blowfish block cipher in ECB mode.
   - Accepts variable‑length keys (up to 448 bits).
   - Uses a 64‑bit block size.
   - Implements key expansion with the standard P‑array and four S‑boxes.
   - Provides encryption and decryption with PKCS#7 padding.
   - Outputs (on encryption) a hex‑encoded string.
   
   This implementation is a complete “from‑scratch” reference following the original
   algorithm. It has been written with attention to constant‑time operations (where feasible)
   and can be extended with inline assembly for critical routines if needed.
*/
int blowfish_crypt(const char *input, const char *key, int shift, mode_t mode, int otp, char *output);

#endif

