#include "chacha20.h"
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#define CHACHA20_BLOCK_SIZE 64
#define CHACHA20_ROUNDS 20

static inline uint32_t rotl(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

static inline void quarterround(uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d) {
    *a += *b; *d ^= *a; *d = rotl(*d, 16);
    *c += *d; *b ^= *c; *b = rotl(*b, 12);
    *a += *b; *d ^= *a; *d = rotl(*d, 8);
    *c += *d; *b ^= *c; *b = rotl(*b, 7);
}

static void chacha20_block(const uint32_t key[8], const uint32_t nonce[3], uint32_t counter, uint32_t output[16]) {
    uint32_t state[16] = {
        0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
        key[0], key[1], key[2], key[3],
        key[4], key[5], key[6], key[7],
        counter, nonce[0], nonce[1], nonce[2]
    };
    memcpy(output, state, sizeof(state));
    for (int i = 0; i < CHACHA20_ROUNDS/2; i++) {
        quarterround(&output[0], &output[4], &output[8], &output[12]);
        quarterround(&output[1], &output[5], &output[9], &output[13]);
        quarterround(&output[2], &output[6], &output[10], &output[14]);
        quarterround(&output[3], &output[7], &output[11], &output[15]);
        quarterround(&output[0], &output[5], &output[10], &output[15]);
        quarterround(&output[1], &output[6], &output[11], &output[12]);
        quarterround(&output[2], &output[7], &output[8], &output[13]);
        quarterround(&output[3], &output[4], &output[9], &output[14]);
    }
    for (int i = 0; i < 16; i++) {
        output[i] += state[i];
    }
}

int chacha20_crypt(const char *input, const char *key_nonce, int shift, mode_t mode, int otp, char *output) {
    (void) shift; (void) mode; (void) otp;
    // Expect key_nonce format: "32char,12char"
    char key_str[33] = {0};
    char nonce_str[13] = {0};
    const char *comma = strchr(key_nonce, ',');
    if (!comma || (comma - key_nonce) != 32 || strlen(comma+1) != 12) {
        fprintf(stderr, "ChaCha20 key must be in format \"32char,12char\".\n");
        return -1;
    }
    memcpy(key_str, key_nonce, 32);
    strcpy(nonce_str, comma+1);
    uint32_t key[8];
    uint32_t nonce[3];
    for (int i = 0; i < 8; i++) {
        key[i] = ((uint32_t)key_str[i*4]) | ((uint32_t)key_str[i*4+1] << 8) |
                 ((uint32_t)key_str[i*4+2] << 16) | ((uint32_t)key_str[i*4+3] << 24);
    }
    for (int i = 0; i < 3; i++) {
        nonce[i] = ((uint32_t)nonce_str[i*4]) | ((uint32_t)nonce_str[i*4+1] << 8) |
                   ((uint32_t)nonce_str[i*4+2] << 16) | ((uint32_t)nonce_str[i*4+3] << 24);
    }
    size_t input_len = strlen(input);
    uint8_t *inbuf = (uint8_t *)input;
    uint8_t *outbuf = malloc(input_len);
    if (!outbuf) return -1;
    uint32_t block[16];
    uint8_t keystream[CHACHA20_BLOCK_SIZE];
    uint32_t counter = 0;
    size_t offset = 0;
    while (offset < input_len) {
        chacha20_block(key, nonce, counter, block);
        for (int i = 0; i < CHACHA20_BLOCK_SIZE; i++) {
            keystream[i] = (block[i/4] >> (8 * (i % 4))) & 0xFF;
        }
        counter++;
        size_t block_size = (input_len - offset < CHACHA20_BLOCK_SIZE) ? (input_len - offset) : CHACHA20_BLOCK_SIZE;
        for (size_t i = 0; i < block_size; i++) {
            outbuf[offset + i] = inbuf[offset + i] ^ keystream[i];
        }
        offset += block_size;
    }
    memcpy(output, outbuf, input_len);
    output[input_len] = '\0';
    free(outbuf);
    return 0;
}

