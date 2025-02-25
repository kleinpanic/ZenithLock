#include <string.h>
#include "rc4.h"

int rc4_crypt(const char *input, const char *key, int shift, mode_t mode, int otp, char *output) {
    (void) shift;
    (void) mode;
    (void) otp; // OTP mode isn’t applicable for RC4
    size_t key_len = strlen(key);
    if (key_len == 0)
        return -1;
    unsigned char S[256];
    unsigned char K[256];
    int i, j = 0, t;
    size_t input_len = strlen(input);
    for (i = 0; i < 256; i++) {
        S[i] = i;
        K[i] = key[i % key_len];
    }
    for (i = 0; i < 256; i++) {
        j = (j + S[i] + K[i]) % 256;
        unsigned char temp = S[i];
        S[i] = S[j];
        S[j] = temp;
    }
    i = j = 0;
    for (size_t n = 0; n < input_len; n++) {
        i = (i + 1) % 256;
        j = (j + S[i]) % 256;
        unsigned char temp = S[i];
        S[i] = S[j];
        S[j] = temp;
        t = (S[i] + S[j]) % 256;
        output[n] = input[n] ^ S[t];
    }
    output[input_len] = '\0';
    return 0;
}

