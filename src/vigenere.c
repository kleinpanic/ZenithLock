#include <string.h>
#include "vigenere.h"

int vigenere_crypt(const char *input, const char *key, int shift, mode_t mode, int otp, char *output) {
    (void) shift;
    size_t key_len = strlen(key);
    if (key_len == 0)
        return -1;
    if (otp && key_len != strlen(input))
        return -1;
    size_t input_len = strlen(input);
    for (size_t i = 0; i < input_len; i++) {
        char c = input[i];
        char k = key[i % key_len];
        int key_shift = (k >= 'a' && k <= 'z') ? k - 'a' : (k >= 'A' && k <= 'Z') ? k - 'A' : 0;
        if (mode == MODE_DECRYPT) {
            key_shift = 26 - key_shift;
        }
        if (c >= 'a' && c <= 'z')
            output[i] = 'a' + ((c - 'a' + key_shift) % 26);
        else if (c >= 'A' && c <= 'Z')
            output[i] = 'A' + ((c - 'A' + key_shift) % 26);
        else
            output[i] = c;
    }
    output[input_len] = '\0';
    return 0;
}

