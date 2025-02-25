#ifndef VIGENERE_H
#define VIGENERE_H

#include "algorithm.h"

int vigenere_crypt(const char *input, const char *key, int shift, mode_t mode, int otp, char *output);

#endif

