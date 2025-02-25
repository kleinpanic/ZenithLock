#include <string.h>
#include "xor.h"

int xor_crypt(const char *input, const char *key, int shift, mode_t mode, int otp, char *output) {
    // XOR is symmetric; encryption and decryption are identical.
    (void) shift;
    (void) mode; // No difference between encryption and decryption
    size_t input_len = strlen(input);
    size_t key_len = strlen(key);
    if (otp) {
        if (key_len != input_len)
            return -1; // OTP mode requires key length equal to input length
    } else {
        if (key_len == 0)
            return -1;
    }
    for (size_t i = 0; i < input_len; i++) {
        output[i] = input[i] ^ key[i % key_len];
    }
    output[input_len] = '\0';
    return 0;
}

