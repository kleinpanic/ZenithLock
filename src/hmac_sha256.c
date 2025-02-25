#include "hmac_sha256.h"
#include "sha256.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int hmac_sha256_crypt(const char *input, const char *key, int shift, mode_t mode, int otp, char *output) {
    if (mode == MODE_DECRYPT) {
        fprintf(stderr, "HMAC-SHA256 does not support decryption mode.\n");
        return -1;
    }
    (void) shift; (void) otp;
    size_t key_len = strlen(key);
    uint8_t key_block[64] = {0};
    if (key_len > 64) key_len = 64;
    memcpy(key_block, key, key_len);
    uint8_t o_key_pad[64], i_key_pad[64];
    for (int i = 0; i < 64; i++) {
        o_key_pad[i] = key_block[i] ^ 0x5c;
        i_key_pad[i] = key_block[i] ^ 0x36;
    }
    SHA256_CTX ctx;
    uint8_t inner_hash[SHA256_BLOCK_SIZE];
    sha256_init(&ctx);
    sha256_update(&ctx, i_key_pad, 64);
    sha256_update(&ctx, (const uint8_t*)input, strlen(input));
    sha256_final(&ctx, inner_hash);

    sha256_init(&ctx);
    sha256_update(&ctx, o_key_pad, 64);
    sha256_update(&ctx, inner_hash, SHA256_BLOCK_SIZE);
    uint8_t final_hash[SHA256_BLOCK_SIZE];
    sha256_final(&ctx, final_hash);

    for (int i = 0; i < SHA256_BLOCK_SIZE; i++) {
        sprintf(output + i*2, "%02x", final_hash[i]);
    }
    output[SHA256_BLOCK_SIZE*2] = '\0';
    return 0;
}

