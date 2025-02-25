#ifndef COLUMNAR_H
#define COLUMNAR_H

#include "algorithm.h"

/*
   Columnar Transposition cipher:
   - The shift parameter indicates the number of columns.
   - The key and OTP flags are ignored.
   - For encryption, text is written row-wise and read column-wise.
   - For decryption, the process is reversed.
*/
int columnar_crypt(const char *input, const char *key, int shift, mode_t mode, int otp, char *output);

#endif

