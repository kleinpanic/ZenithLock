#include "atbash.h"
#include <string.h>
#include <stdio.h>

/*
 * Atbash cipher implementation.
 */
int atbash_crypt(const char *input,
                 const char *key,
                 int shift,
                 mode_t mode,
                 int otp,
                 char *output)
{
    (void) key;
    (void) shift;
    (void) mode;

    if (otp) {
        fprintf(stderr, "Atbash: OTP mode not supported\n");
        return -1;
    }
    if (!input || !output) {
        fprintf(stderr, "Atbash: null parameter supplied\n");
        return -1;
    }

    size_t len = strlen(input);
    for (size_t i = 0; i < len; i++) {
        char c = input[i];
        if (c >= 'a' && c <= 'z') {
            output[i] = (char)('z' - (c - 'a'));
        } else if (c >= 'A' && c <= 'Z') {
            output[i] = (char)('Z' - (c - 'A'));
        } else {
            output[i] = c;
        }
    }
    output[len] = '\0';
    return 0;
}

