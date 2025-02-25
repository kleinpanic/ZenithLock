#include "rc6.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#define RC6_BLOCK_SIZE 16
#define RC6_ROUNDS 20
#define T (2*RC6_ROUNDS + 4)
#define P32 0xB7E15163
#define Q32 0x9E3779B9

static inline uint32_t rotl32(uint32_t x, uint32_t n) {
    return (x << n) | (x >> (32 - n));
}
static inline uint32_t rotr32(uint32_t x, uint32_t n) {
    return (x >> n) | (x << (32 - n));
}

static void rc6_key_schedule(const uint8_t *K, int keyLen, uint32_t S[T]) {
    int i, j, v;
    int c = keyLen / 4;
    uint32_t L[4] = {0};
    for (i = 0; i < keyLen; i++) {
        L[i/4] |= ((uint32_t)K[i]) << (8 * (i % 4));
    }
    S[0] = P32;
    for (i = 1; i < T; i++) {
        S[i] = S[i-1] + Q32;
    }
    uint32_t A = 0, B = 0;
    i = j = 0;
    int n = 3 * ((T > c) ? T : c);
    for (v = 0; v < n; v++) {
        A = S[i] = rotl32(S[i] + A + B, 3);
        B = L[j] = rotl32(L[j] + A + B, (A+B) % 32);
        i = (i + 1) % T;
        j = (j + 1) % c;
    }
}

static void rc6_encrypt_block(uint32_t S[T], const uint8_t in[RC6_BLOCK_SIZE], uint8_t out[RC6_BLOCK_SIZE]) {
    uint32_t A, B, C, D;
    memcpy(&A, in, 4);
    memcpy(&B, in+4, 4);
    memcpy(&C, in+8, 4);
    memcpy(&D, in+12, 4);
    B = B + S[0];
    D = D + S[1];
    for (int i = 1; i <= RC6_ROUNDS; i++) {
        uint32_t t = rotl32(B * (2*B + 1), 5);
        uint32_t u = rotl32(D * (2*D + 1), 5);
        A = rotl32(A ^ t, u & 31) + S[2*i];
        C = rotl32(C ^ u, t & 31) + S[2*i+1];
        uint32_t temp = A;
        A = B; B = C; C = D; D = temp;
    }
    A = A + S[2*RC6_ROUNDS+2];
    C = C + S[2*RC6_ROUNDS+3];
    memcpy(out, &A, 4);
    memcpy(out+4, &B, 4);
    memcpy(out+8, &C, 4);
    memcpy(out+12, &D, 4);
}

static void rc6_decrypt_block(uint32_t S[T], const uint8_t in[RC6_BLOCK_SIZE], uint8_t out[RC6_BLOCK_SIZE]) {
    uint32_t A, B, C, D;
    memcpy(&A, in, 4);
    memcpy(&B, in+4, 4);
    memcpy(&C, in+8, 4);
    memcpy(&D, in+12, 4);
    C = C - S[2*RC6_ROUNDS+3];
    A = A - S[2*RC6_ROUNDS+2];
    for (int i = RC6_ROUNDS; i >= 1; i--) {
        uint32_t temp = D;
        D = C; C = B; B = A; A = temp;
        uint32_t u = rotl32(D * (2*D + 1), 5);
        uint32_t t = rotl32(B * (2*B + 1), 5);
        C = rotr32(C - S[2*i+1], t & 31) ^ u;
        A = rotr32(A - S[2*i], u & 31) ^ t;
    }
    D = D - S[1];
    B = B - S[0];
    memcpy(out, &A, 4);
    memcpy(out+4, &B, 4);
    memcpy(out+8, &C, 4);
    memcpy(out+12, &D, 4);
}

static void bin_to_hex_rc6(const uint8_t *bin, size_t bin_len, char *hex) {
    const char *hex_chars = "0123456789ABCDEF";
    for (size_t i = 0; i < bin_len; i++) {
        hex[i*2] = hex_chars[(bin[i] >> 4) & 0xF];
        hex[i*2+1] = hex_chars[bin[i] & 0xF];
    }
    hex[bin_len*2] = '\0';
}

static int hex_to_bin_rc6(const char *hex, uint8_t *bin, size_t bin_size) {
    size_t hex_len = strlen(hex);
    if (hex_len % 2 != 0) return -1;
    size_t out_len = hex_len / 2;
    if (out_len > bin_size) return -1;
    for (size_t i = 0; i < out_len; i++) {
        char byte_str[3] = { hex[i*2], hex[i*2+1], '\0' };
        bin[i] = (uint8_t) strtol(byte_str, NULL, 16);
    }
    return out_len;
}

int rc6_crypt(const char *input, const char *key, int shift, mode_t mode, int otp, char *output) {
    (void) shift; (void) otp;
    uint8_t binary_key[16];
    size_t key_len = strlen(key);
    if (key_len == 16) {
        memcpy(binary_key, key, 16);
    } else if (key_len == 32) {
        for (int i = 0; i < 16; i++) {
            char byte_str[3] = { key[i*2], key[i*2+1], '\0' };
            binary_key[i] = (uint8_t)strtol(byte_str, NULL, 16);
        }
    } else {
        fprintf(stderr, "RC6 requires a 16-character raw key or 32-character hex key.\n");
        return -1;
    }
    uint32_t S[T];
    rc6_key_schedule(binary_key, 16, S);
    if (mode == MODE_ENCRYPT) {
        size_t in_len = strlen(input);
        size_t pad = RC6_BLOCK_SIZE - (in_len % RC6_BLOCK_SIZE);
        size_t total = in_len + pad;
        uint8_t *buffer = calloc(total, 1);
        if (!buffer) return -1;
        memcpy(buffer, input, in_len);
        for (size_t i = in_len; i < total; i++) {
            buffer[i] = (uint8_t) pad;
        }
        for (size_t i = 0; i < total; i += RC6_BLOCK_SIZE) {
            uint8_t block[RC6_BLOCK_SIZE];
            rc6_encrypt_block(S, buffer + i, block);
            memcpy(buffer + i, block, RC6_BLOCK_SIZE);
        }
        bin_to_hex_rc6(buffer, total, output);
        free(buffer);
    } else {
        size_t hex_len = strlen(input);
        size_t total = hex_len / 2;
        uint8_t *buffer = malloc(total);
        if (!buffer) return -1;
        if (hex_to_bin_rc6(input, buffer, total) != total) {
            free(buffer);
            return -1;
        }
        for (size_t i = 0; i < total; i += RC6_BLOCK_SIZE) {
            uint8_t block[RC6_BLOCK_SIZE];
            rc6_decrypt_block(S, buffer + i, block);
            memcpy(buffer + i, block, RC6_BLOCK_SIZE);
        }
        uint8_t pad = buffer[total - 1];
        size_t out_len = total - pad;
        memcpy(output, buffer, out_len);
        output[out_len] = '\0';
        free(buffer);
    }
    return 0;
}

