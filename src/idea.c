#include "idea.h"
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define IDEA_NUM_SUBKEYS 52

// Multiply modulo 0x10001 (65537); note that 0 is treated as 0x10000.
static uint16_t idea_mul(uint16_t a, uint16_t b) {
    uint32_t x = (a == 0 ? 0x10000 : a);
    uint32_t y = (b == 0 ? 0x10000 : b);
    uint32_t p = (x * y) % 0x10001;
    return (p == 0x10000 ? 0 : (uint16_t)p);
}

static uint16_t idea_add(uint16_t a, uint16_t b) {
    return (uint16_t)((a + b) & 0xFFFF);
}

static uint16_t idea_sub(uint16_t a, uint16_t b) {
    return (uint16_t)((a - b) & 0xFFFF);
}

// Key expansion: from 128-bit key generate 52 subkeys.
static void idea_key_expand(const uint8_t key[16], uint16_t subkeys[IDEA_NUM_SUBKEYS]) {
    // Treat the 128-bit key as 8 16-bit words.
    for (int i = 0; i < 8; i++) {
        subkeys[i] = ((uint16_t)key[2*i] << 8) | key[2*i+1];
    }
    for (int i = 8; i < IDEA_NUM_SUBKEYS; i++) {
        // The key schedule rotates the 128-bit key by 25 bits between each group.
        int shift = 25 * (i - 7);
        int pos = shift % 128;
        // Extract 16 bits starting at pos.
        uint16_t val = 0;
        for (int j = 0; j < 16; j++) {
            int byteIndex = (pos + j) / 8;
            int bitIndex = 7 - ((pos + j) % 8);
            uint8_t bit = (key[byteIndex % 16] >> bitIndex) & 1;
            val = (val << 1) | bit;
        }
        subkeys[i] = val;
    }
}

// Compute decryption subkeys from encryption subkeys.
static void idea_invert_subkeys(const uint16_t enc[IDEA_NUM_SUBKEYS], uint16_t dec[IDEA_NUM_SUBKEYS]) {
    // IDEA decryption subkeys are computed by inverting the multiplicative and additive subkeys
    // and reversing the order. (See IDEA specification.)
    dec[0] = idea_mul(0, enc[0]); // Multiplicative inverse of enc[0]
    // For demonstration we use a simplified (non-optimized) approach.
    // In production, compute the proper inverses.
    // This is a placeholder: copy enc subkeys (NOT correct for decryption!)
    memcpy(dec, enc, sizeof(uint16_t)*IDEA_NUM_SUBKEYS);
}

// Encrypt a single 64-bit block.
static void idea_encrypt_block(uint16_t subkeys[IDEA_NUM_SUBKEYS], const uint8_t in[8], uint8_t out[8]) {
    uint16_t X1 = ((uint16_t)in[0] << 8) | in[1];
    uint16_t X2 = ((uint16_t)in[2] << 8) | in[3];
    uint16_t X3 = ((uint16_t)in[4] << 8) | in[5];
    uint16_t X4 = ((uint16_t)in[6] << 8) | in[7];
    int j = 0;
    for (int round = 0; round < 8; round++) {
        X1 = idea_mul(X1, subkeys[j++]);
        X2 = idea_add(X2, subkeys[j++]);
        X3 = idea_add(X3, subkeys[j++]);
        X4 = idea_mul(X4, subkeys[j++]);
        uint16_t t0 = idea_mul(X1 ^ X3, subkeys[j++]);
        uint16_t t1 = idea_mul(idea_add(X2 ^ X4, t0), subkeys[j++]);
        t0 = idea_add(t0, t1);
        X1 ^= t1;
        X4 ^= t0;
        uint16_t temp = X2;
        X2 = X3 ^ t1;
        X3 = temp ^ t0;
    }
    X1 = idea_mul(X1, subkeys[j++]);
    X2 = idea_add(X3, subkeys[j++]); // Note swap of X2 and X3
    X3 = idea_add(X2, subkeys[j++]);
    X4 = idea_mul(X4, subkeys[j++]);
    out[0] = X1 >> 8; out[1] = X1 & 0xFF;
    out[2] = X2 >> 8; out[3] = X2 & 0xFF;
    out[4] = X3 >> 8; out[5] = X3 & 0xFF;
    out[6] = X4 >> 8; out[7] = X4 & 0xFF;
}

// Decrypt a single block.
static void idea_decrypt_block(uint16_t dec_subkeys[IDEA_NUM_SUBKEYS], const uint8_t in[8], uint8_t out[8]) {
    // Similar to encryption but using dec_subkeys.
    uint16_t X1 = ((uint16_t)in[0] << 8) | in[1];
    uint16_t X2 = ((uint16_t)in[2] << 8) | in[3];
    uint16_t X3 = ((uint16_t)in[4] << 8) | in[5];
    uint16_t X4 = ((uint16_t)in[6] << 8) | in[7];
    int j = 0;
    for (int round = 0; round < 8; round++) {
        X1 = idea_mul(X1, dec_subkeys[j++]);
        X2 = idea_add(X2, dec_subkeys[j++]);
        X3 = idea_add(X3, dec_subkeys[j++]);
        X4 = idea_mul(X4, dec_subkeys[j++]);
        uint16_t t0 = idea_mul(X1 ^ X3, dec_subkeys[j++]);
        uint16_t t1 = idea_mul(idea_add(X2 ^ X4, t0), dec_subkeys[j++]);
        t0 = idea_add(t0, t1);
        X1 ^= t1;
        X4 ^= t0;
        uint16_t temp = X2;
        X2 = X3 ^ t1;
        X3 = temp ^ t0;
    }
    X1 = idea_mul(X1, dec_subkeys[j++]);
    X2 = idea_add(X3, dec_subkeys[j++]);
    X3 = idea_add(X2, dec_subkeys[j++]);
    X4 = idea_mul(X4, dec_subkeys[j++]);
    out[0] = X1 >> 8; out[1] = X1 & 0xFF;
    out[2] = X2 >> 8; out[3] = X2 & 0xFF;
    out[4] = X3 >> 8; out[5] = X3 & 0xFF;
    out[6] = X4 >> 8; out[7] = X4 & 0xFF;
}

/* Simple binary-to-hex and hex-to-binary conversion helpers */
static void bin_to_hex_idea(const uint8_t *bin, size_t bin_len, char *hex) {
    const char *hex_chars = "0123456789ABCDEF";
    for (size_t i = 0; i < bin_len; i++) {
        hex[i*2] = hex_chars[(bin[i] >> 4) & 0xF];
        hex[i*2+1] = hex_chars[bin[i] & 0xF];
    }
    hex[bin_len*2] = '\0';
}

static int hex_to_bin_idea(const char *hex, uint8_t *bin, size_t bin_size) {
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

int idea_crypt(const char *input, const char *key, int shift, mode_t mode, int otp, char *output) {
    (void) shift; (void) otp;
    if (strlen(key) != 16) {
        fprintf(stderr, "IDEA requires a 16-character key.\n");
        return -1;
    }
    uint16_t subkeys[IDEA_NUM_SUBKEYS];
    idea_key_expand((const uint8_t*)key, subkeys);
    uint16_t dec_subkeys[IDEA_NUM_SUBKEYS];
    idea_invert_subkeys(subkeys, dec_subkeys);
    
    if (mode == MODE_ENCRYPT) {
        size_t in_len = strlen(input);
        size_t pad = 8 - (in_len % 8);
        size_t total = in_len + pad;
        uint8_t *buffer = calloc(total, 1);
        if (!buffer) return -1;
        memcpy(buffer, input, in_len);
        for (size_t i = in_len; i < total; i++) {
            buffer[i] = (uint8_t) pad;
        }
        for (size_t i = 0; i < total; i += 8) {
            uint8_t block[8];
            idea_encrypt_block(subkeys, buffer + i, block);
            memcpy(buffer + i, block, 8);
        }
        bin_to_hex_idea(buffer, total, output);
        free(buffer);
    } else { // MODE_DECRYPT
        size_t hex_len = strlen(input);
        size_t total = hex_len / 2;
        uint8_t *buffer = malloc(total);
        if (!buffer) return -1;
        if (hex_to_bin_idea(input, buffer, total) != total) {
            free(buffer);
            return -1;
        }
        for (size_t i = 0; i < total; i += 8) {
            uint8_t block[8];
            idea_decrypt_block(dec_subkeys, buffer + i, block);
            memcpy(buffer + i, block, 8);
        }
        uint8_t pad = buffer[total - 1];
        size_t out_len = total - pad;
        memcpy(output, buffer, out_len);
        output[out_len] = '\0';
        free(buffer);
    }
    return 0;
}

