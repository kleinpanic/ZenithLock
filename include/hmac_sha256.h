#ifndef HMAC_SHA256_H
#define HMAC_SHA256_H

#include "algorithm.h"

/*
   HMAC‑SHA256 implementation.
   – Computes the HMAC using SHA‑256 as the underlying hash.
   – Only supports “encryption” mode (i.e. computing the HMAC).
   – Outputs a hex string representing the HMAC.
*/
int hmac_sha256_crypt(const char *input, const char *key, int shift, mode_t mode, int otp, char *output);

#endif

