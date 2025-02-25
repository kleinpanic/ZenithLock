#ifndef RAILFENCE_H
#define RAILFENCE_H

#include "algorithm.h"

/* Rail Fence cipher.
   Uses the shift parameter to denote the number of rails (>=2).
   The key and OTP flags are not used.
*/
int railfence_crypt(const char *input, const char *key, int shift, mode_t mode, int otp, char *output);

#endif

