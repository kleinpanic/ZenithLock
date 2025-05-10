#include "beaufort.h"
#include <string.h>
#include <stdio.h>
#include <ctype.h>

int beaufort_crypt(const char *input,
                   const char *key,
                   int shift,
                   mode_t mode,
                   int otp,
                   char *output)
{
    (void) shift;
    (void) mode;

    if (!input || !key || !output) {
        fprintf(stderr, "Beaufort: null parameter supplied\n");
        return -1;
    }

    size_t key_len   = strlen(key);
    size_t input_len = strlen(input);

    if (key_len == 0) {
        fprintf(stderr, "Beaufort: key must not be empty\n");
        return -1;
    }
    if (otp && key_len != input_len) {
        fprintf(stderr,
            "Beaufort: OTP mode requires key length == input length (%zu)\n",
            input_len);
        return -1;
    }
    /* Validate key characters */
    for (size_t i = 0; i < key_len; i++) {
        if (!isalpha((unsigned char)key[i])) {
            fprintf(stderr,
                "Beaufort: key contains non-alphabetic character at pos %zu\n",
                i);
            return -1;
        }
    }

    for (size_t i = 0; i < input_len; i++) {
        char c = input[i];
        /* Select key char: either one-time (otp) or repeating */
        char k = key[ otp ? i : (i % key_len) ];
        int key_val = isupper((unsigned char)k)
                    ? (k - 'A')
                    : (k - 'a');

        if (c >= 'A' && c <= 'Z') {
            int p_val   = c - 'A';
            int out_val = (key_val - p_val + 26) % 26;
            output[i]   = (char)('A' + out_val);
        }
        else if (c >= 'a' && c <= 'z') {
            int p_val   = c - 'a';
            int out_val = (key_val - p_val + 26) % 26;
            output[i]   = (char)('a' + out_val);
        }
        else {
            /* Non-letters pass through unchanged */
            output[i] = c;
        }
    }

    output[input_len] = '\0';
    return 0;
}

