#ifndef ENCODING_H
#define ENCODING_H

#include <stddef.h>

int base64_encode(const char *input, char *output, size_t out_size);
int base64_decode(const char *input, char *output, size_t out_size);

#endif

