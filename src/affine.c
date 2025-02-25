#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "affine.h"

/* Helper: Compute modular inverse of a modulo m.
   Returns -1 if no inverse exists. */
static int mod_inverse(int a, int m) {
    a = a % m;
    for (int x = 1; x < m; x++) {
        if ((a * x) % m == 1)
            return x;
    }
    return -1;
}

int affine_crypt(const char *input, const char *key, int shift, mode_t mode, int otp, char *output) {
    (void) shift;
    (void) otp;
    int a, b;
    if (sscanf(key, "%d,%d", &a, &b) != 2) {
        fprintf(stderr, "Affine cipher key must be in the format a,b (e.g., \"5,8\")\n");
        return -1;
    }
    
    size_t len = strlen(input);
    if (mode == MODE_ENCRYPT) {
        for (size_t i = 0; i < len; i++) {
            char c = input[i];
            if (c >= 'a' && c <= 'z') {
                int x = c - 'a';
                output[i] = 'a' + ((a * x + b) % 26);
            } else if (c >= 'A' && c <= 'Z') {
                int x = c - 'A';
                output[i] = 'A' + ((a * x + b) % 26);
            } else {
                output[i] = c;
            }
        }
    } else { // MODE_DECRYPT
        int a_inv = mod_inverse(a, 26);
        if (a_inv == -1) {
            fprintf(stderr, "Key 'a' value %d has no modular inverse mod 26\n", a);
            return -1;
        }
        for (size_t i = 0; i < len; i++) {
            char c = input[i];
            if (c >= 'a' && c <= 'z') {
                int x = c - 'a';
                int dec = a_inv * ((x - b) + 26);
                output[i] = 'a' + (dec % 26);
            } else if (c >= 'A' && c <= 'Z') {
                int x = c - 'A';
                int dec = a_inv * ((x - b) + 26);
                output[i] = 'A' + (dec % 26);
            } else {
                output[i] = c;
            }
        }
    }
    output[len] = '\0';
    return 0;
}

