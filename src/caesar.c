#include <string.h>
#include "caesar.h"

int caesar_crypt(const char *input, const char *key, int shift, mode_t mode, int otp, char *output) {
    (void) key;
    (void) otp;
    if (shift < 1)
        return -1;
    size_t i;
    int actual_shift = shift;
    if (mode == MODE_DECRYPT)
        actual_shift = 26 - (shift % 26);
    for (i = 0; i < strlen(input); i++) {
        char c = input[i];
        if (c >= 'a' && c <= 'z')
            output[i] = 'a' + ((c - 'a' + actual_shift) % 26);
        else if (c >= 'A' && c <= 'Z')
            output[i] = 'A' + ((c - 'A' + actual_shift) % 26);
        else
            output[i] = c;
    }
    output[i] = '\0';
    return 0;
}

