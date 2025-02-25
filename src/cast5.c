#include "cast5.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#define CAST5_BLOCK_SIZE 8
#define CAST5_ROUNDS 16

// A simplified key expansion: we derive CAST5_ROUNDS 32‑bit subkeys from a 16‑byte key.
static void cast5_key_expand(const uint8_t *key, uint32_t subkeys[CAST5_ROUNDS]) {
    // Split the 16-byte key into four 32-bit words.
    uint32_t k0 = ((uint32_t)key[0] << 24) | ((uint32_t)key[1] << 16) | ((uint32_t)key[2] << 8) | key[3];
    uint32_t k1 = ((uint32_t)key[4] << 24) | ((uint32_t)key[5] << 16) | ((uint32_t)key[6] << 8) | key[7];
    uint32_t k2 = ((uint32_t)key[8] << 24) | ((uint32_t)key[9] << 16) | ((uint32_t)key[10] << 8) | key[11];
    uint32_t k3 = ((uint32_t)key[12] << 24) | ((uint32_t)key[13] << 16) | ((uint32_t)key[14] << 8) | key[15];
    for (int i = 0; i < CAST5_ROUNDS; i++) {
        // Produce subkeys by rotating and combining the key parts.
        subkeys[i] = ((k0 << (i & 31)) | (k0 >> (32 - (i & 31)))) ^
                     ((k1 << ((i+1)&31)) | (k1 >> (32 - ((i+1)&31)))) ^
                     ((k2 << ((i+2)&31)) | (k2 >> (32 - ((i+2)&31)))) ^
                     ((k3 << ((i+3)&31)) | (k3 >> (32 - ((i+3)&31))));
    }
}

// A simple round function for CAST5 (this is a simplified design).
static uint32_t cast5_round(uint32_t L, uint32_t subkey) {
    // For example, combine XOR, addition, and a rotation.
    return ((L ^ subkey) + ((L << 3) | (L >> (32-3)))) & 0xFFFFFFFF;
}

static void cast5_encrypt_block(uint32_t *L, uint32_t *R, uint32_t subkeys[CAST5_ROUNDS]) {
    uint32_t l = *L, r = *R;
    for (int i = 0; i < CAST5_ROUNDS; i++) {
        uint32_t f = cast5_round(l, subkeys[i]);
        uint32_t temp = r ^ f;
        r = l;
        l = temp;
    }
    *L = l;
    *R = r;
}

static void cast5_decrypt_block(uint32_t *L, uint32_t *R, uint32_t subkeys[CAST5_ROUNDS]) {
    uint32_t l = *L, r = *R;
    for (int i = CAST5_ROUNDS - 1; i >= 0; i--) {
        uint32_t f = cast5_round(l, subkeys[i]);
        uint32_t temp = r ^ f;
        r = l;
        l = temp;
    }
    *L = l;
    *R = r;
}

static void bin_to_hex_cast5(const uint8_t *bin, size_t bin_len, char *hex) {
    const char *hex_chars = "0123456789ABCDEF";
    for (size_t i = 0; i < bin_len; i++) {
        hex[i*2]     = hex_chars[(bin[i] >> 4) & 0xF];
        hex[i*2+1]   = hex_chars[bin[i] & 0xF];
    }
    hex[bin_len*2] = '\0';
}

static int hex_to_bin_cast5(const char *hex, uint8_t *bin, size_t bin_size) {
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

int cast5_crypt(const char *input, const char *key, int shift, mode_t mode, int otp, char *output) {
    (void) shift; (void) otp;
    if (strlen(key) != 16) {
        fprintf(stderr, "CAST5 requires a 16-character key.\n");
        return -1;
    }
    uint32_t subkeys[CAST5_ROUNDS];
    cast5_key_expand((const uint8_t*)key, subkeys);
    
    if (mode == MODE_ENCRYPT) {
        size_t in_len = strlen(input);
        size_t pad = CAST5_BLOCK_SIZE - (in_len % CAST5_BLOCK_SIZE);
        size_t total = in_len + pad;
        uint8_t *buffer = calloc(total, 1);
        if (!buffer) return -1;
        memcpy(buffer, input, in_len);
        for (size_t i = in_len; i < total; i++) {
            buffer[i] = (uint8_t) pad;
        }
        for (size_t i = 0; i < total; i += CAST5_BLOCK_SIZE) {
            uint32_t L, R;
            memcpy(&L, buffer + i, 4);
            memcpy(&R, buffer + i + 4, 4);
            cast5_encrypt_block(&L, &R, subkeys);
            memcpy(buffer + i, &L, 4);
            memcpy(buffer + i + 4, &R, 4);
        }
        bin_to_hex_cast5(buffer, total, output);
        free(buffer);
    } else {
        size_t hex_len = strlen(input);
        size_t total = hex_len / 2;
        uint8_t *buffer = malloc(total);
        if (!buffer) return -1;
        if (hex_to_bin_cast5(input, buffer, total) != total) {
            free(buffer);
            return -1;
        }
        for (size_t i = 0; i < total; i += CAST5_BLOCK_SIZE) {
            uint32_t L, R;
            memcpy(&L, buffer + i, 4);
            memcpy(&R, buffer + i + 4, 4);
            cast5_decrypt_block(&L, &R, subkeys);
            memcpy(buffer + i, &L, 4);
            memcpy(buffer + i + 4, &R, 4);
        }
        uint8_t pad = buffer[total - 1];
        size_t out_len = total - pad;
        memcpy(output, buffer, out_len);
        output[out_len] = '\0';
        free(buffer);
    }
    return 0;
}

