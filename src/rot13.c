#include <string.h>
#include "rot13.h"

int rot13_crypt(const char *input, const char *key, int shift, mode_t mode, int otp, char *output) {
    (void) key;   // not used
    (void) shift; // fixed shift of 13
    (void) mode;  // encryption and decryption are identical
    (void) otp;   // OTP mode not applicable

    size_t len = strlen(input);
    for (size_t i = 0; i < len; i++) {
        char c = input[i];
        if (c >= 'a' && c <= 'z')
            output[i] = 'a' + ((c - 'a' + 13) % 26);
        else if (c >= 'A' && c <= 'Z')
            output[i] = 'A' + ((c - 'A' + 13) % 26);
        else
            output[i] = c;
    }
    output[len] = '\0';
    return 0;
}

