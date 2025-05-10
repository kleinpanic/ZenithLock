#include "affine.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

/* Compute gcd(a,b) */
static int gcd(int a, int b) {
    while (b) {
        int t = b;
        b = a % b;
        a = t;
    }
    return a < 0 ? -a : a;
}

/* Compute modular inverse of a mod m, or -1 if none */
static int mod_inverse(int a, int m) {
    a %= m;
    for (int x = 1; x < m; x++) {
        if ((a * x) % m == 1) return x;
    }
    return -1;
}

/* Validate and parse key "a,b"; returns 0 on success */
static int parse_key(const char *keystr, int *a, int *b) {
    if (!keystr || sscanf(keystr, "%d,%d", a, b) != 2) {
        fprintf(stderr,
            "Affine: key must be in format \"a,b\" (e.g. \"5,8\").\n");
        return -1;
    }
    *b %= 26;
    if (*b < 0) *b += 26;
    if (gcd(*a, 26) != 1) {
        fprintf(stderr,
            "Affine: multiplicative key a=%d is not coprime with 26.\n", *a);
        return -1;
    }
    return 0;
}

int affine_crypt(const char *input,
                 const char *key,
                 int shift,
                 mode_t mode,
                 int otp,
                 char *output)
{
    (void) shift;
    if (!input || !key || !output) {
        fprintf(stderr, "Affine: null parameter supplied.\n");
        return -1;
    }
    if (otp) {
        fprintf(stderr, "Affine: OTP mode not supported for affine cipher.\n");
        return -1;
    }

    int a, b;
    if (parse_key(key, &a, &b) != 0) {
        return -1;
    }

    size_t len = strlen(input);
    for (size_t i = 0; i < len; i++) {
        char c = input[i];
        if (isalpha((unsigned char)c)) {
            char base = isupper((unsigned char)c) ? 'A' : 'a';
            int x = c - base;
            int y;
            if (mode == MODE_ENCRYPT) {
                y = (a * x + b) % 26;
            } else {
                int a_inv = mod_inverse(a, 26);  /* guaranteed to exist */
                y = (a_inv * ((x - b + 26) % 26)) % 26;
            }
            output[i] = base + y;
        } else {
            output[i] = c;
        }
    }
    output[len] = '\0';
    return 0;
}

