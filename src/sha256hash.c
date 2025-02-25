#include "sha256hash.h"
#include "sha256.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int sha256hash_crypt(const char *input, const char *key, int shift, mode_t mode, int otp, char *output) {
    (void) key; (void) shift; (void) otp;
    if (mode == MODE_DECRYPT) {
        fprintf(stderr, "SHA-256 hash is one-way and does not support decryption.\n");
        return -1;
    }
    SHA256_CTX ctx;
    uint8_t hash[SHA256_BLOCK_SIZE];
    sha256_init(&ctx);
    sha256_update(&ctx, (const uint8_t*)input, strlen(input));
    sha256_final(&ctx, hash);
    for (int i = 0; i < SHA256_BLOCK_SIZE; i++) {
        sprintf(output + i*2, "%02x", hash[i]);
    }
    output[SHA256_BLOCK_SIZE*2] = '\0';
    return 0;
}

