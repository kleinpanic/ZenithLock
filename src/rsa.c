#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "rsa.h"

/* Modular exponentiation: calculates (base^exp) mod mod */
static unsigned long long modexp(unsigned long long base, unsigned long long exp, unsigned long long mod) {
    unsigned long long result = 1;
    base %= mod;
    while(exp > 0) {
        if(exp & 1)
            result = (result * base) % mod;
        exp >>= 1;
        base = (base * base) % mod;
    }
    return result;
}

int rsa_crypt(const char *input, const char *key, int shift, mode_t mode, int otp, char *output) {
    (void) shift;
    (void) otp;
    /* Parse key in the format "x,y" */
    unsigned long long exp = 0, mod = 0;
    if (sscanf(key, "%llu,%llu", &exp, &mod) != 2) {
        fprintf(stderr, "RSA key must be in the format \"x,y\" (e.g., \"65537,3233\")\n");
        return -1;
    }
    if (mod == 0) {
        fprintf(stderr, "Modulus must be nonzero.\n");
        return -1;
    }
    if (mode == MODE_ENCRYPT) {
        size_t len = strlen(input);
        char buffer[32];
        output[0] = '\0';
        for (size_t i = 0; i < len; i++) {
            unsigned long long m = (unsigned char) input[i];
            unsigned long long c = modexp(m, exp, mod);
            snprintf(buffer, sizeof(buffer), "%llu ", c);
            strcat(output, buffer);
        }
    } else { /* MODE_DECRYPT */
        char *temp = strdup(input);
        if (!temp) return -1;
        char *token = strtok(temp, " ");
        size_t pos = 0;
        while(token) {
            unsigned long long c = strtoull(token, NULL, 10);
            unsigned long long m = modexp(c, exp, mod);
            output[pos++] = (char) m;
            token = strtok(NULL, " ");
        }
        output[pos] = '\0';
        free(temp);
    }
    return 0;
}

