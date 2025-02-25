#include <string.h>
#include "atbash.h"

int atbash_crypt(const char *input, const char *key, int shift, mode_t mode, int otp, char *output) {
    (void) key;    // Not used
    (void) shift;  // Not used
    (void) mode;   // Atbash is symmetric
    (void) otp;    // OTP mode not applicable

    size_t len = strlen(input);
    for (size_t i = 0; i < len; i++) {
        char c = input[i];
        if (c >= 'a' && c <= 'z')
            output[i] = 'z' - (c - 'a');
        else if (c >= 'A' && c <= 'Z')
            output[i] = 'Z' - (c - 'A');
        else
            output[i] = c;
    }
    output[len] = '\0';
    return 0;
}

