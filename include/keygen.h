#ifndef KEYGEN_H
#define KEYGEN_H

/* generate_key() returns a newly allocated key string for the given algorithm.
   The msg_len parameter may be used by algorithms (such as XOR) that depend on
   the input size. For most symmetric block ciphers a fixed key length is used.
   The caller must free() the returned string.
*/
#include <stddef.h>
char* generate_key(const char *alg_name, size_t msg_len);

#endif

