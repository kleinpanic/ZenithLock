#include "salsa20.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define SALSA20_BLOCK_SIZE 64
#define SALSA20_ROUNDS 20

static inline uint32_t rotl32_salsa(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

static void salsa20_quarterround(uint32_t *y0, uint32_t *y1, uint32_t *y2, uint32_t *y3) {
    *y1 ^= rotl32_salsa(*y0 + *y3, 7);
    *y2 ^= rotl32_salsa(*y1 + *y0, 9);
    *y3 ^= rotl32_salsa(*y2 + *y1, 13);
    *y0 ^= rotl32_salsa(*y3 + *y2, 18);
}

static void salsa20_rowround(uint32_t y[16]) {
    salsa20_quarterround(&y[0], &y[1], &y[2], &y[3]);
    salsa20_quarterround(&y[5], &y[6], &y[7], &y[4]);
    salsa20_quarterround(&y[10], &y[11], &y[8], &y[9]);
    salsa20_quarterround(&y[15], &y[12], &y[13], &y[14]);
}

static void salsa20_columnround(uint32_t x[16]) {
    salsa20_quarterround(&x[0], &x[4], &x[8], &x[12]);
    salsa20_quarterround(&x[5], &x[9], &x[13], &x[1]);
    salsa20_quarterround(&x[10], &x[14], &x[2], &x[6]);
    salsa20_quarterround(&x[15], &x[3], &x[7], &x[11]);
}

static void salsa20_doubleround(uint32_t x[16]) {
    salsa20_columnround(x);
    salsa20_rowround(x);
}

static void salsa20_hash(const uint32_t in[16], uint32_t out[16]) {
    int i;
    memcpy(out, in, 16 * sizeof(uint32_t));
    for (i = 0; i < SALSA20_ROUNDS/2; i++) {
        salsa20_doubleround(out);
    }
    for (i = 0; i < 16; i++) {
        out[i] += in[i];
    }
}

static void salsa20_wordtobyte(uint8_t output[64], const uint32_t input[16]) {
    for (int i = 0; i < 16; i++) {
        output[i*4] = input[i] & 0xFF;
        output[i*4+1] = (input[i] >> 8) & 0xFF;
        output[i*4+2] = (input[i] >> 16) & 0xFF;
        output[i*4+3] = (input[i] >> 24) & 0xFF;
    }
}

/* Convert a hex string to binary; expects exact length. */
static int hex_to_bin_salsa(const char *hex, uint8_t *bin, size_t bin_len) {
    size_t hex_len = strlen(hex);
    if (hex_len != bin_len * 2) return -1;
    for (size_t i = 0; i < bin_len; i++) {
        char byte_str[3] = { hex[i*2], hex[i*2+1], '\0' };
        bin[i] = (uint8_t)strtol(byte_str, NULL, 16);
    }
    return 0;
}

/* Parse Salsa20 key: expects "64char,16char" format */
static int parse_salsa20_key(const char *keystr, uint8_t key[32], uint8_t nonce[8]) {
    const char *comma = strchr(keystr, ',');
    if (!comma) return -1;
    size_t key_hex_len = comma - keystr;
    if (key_hex_len != 64) return -1;
    if (hex_to_bin_salsa(keystr, key, 32) != 0) return -1;
    if (strlen(comma+1) != 16) return -1;
    if (hex_to_bin_salsa(comma+1, nonce, 8) != 0) return -1;
    return 0;
}

int salsa20_crypt(const char *input, const char *keystr, int shift, mode_t mode, int otp, char *output) {
    (void) shift; (void) mode; (void) otp; // encryption and decryption are identical
    uint8_t key[32], nonce[8];
    if (parse_salsa20_key(keystr, key, nonce) != 0) {
        fprintf(stderr, "Salsa20 key must be in format \"64char,16char\" (hex values).\n");
        return -1;
    }
    size_t input_len = strlen(input);
    uint8_t *inbuf = (uint8_t *)input;
    uint8_t *outbuf = malloc(input_len);
    if (!outbuf) return -1;
    uint32_t state[16];
    // Setup initial state as per Salsa20 specification.
    // Use the constant "expand 32-byte k":
    const uint32_t sigma[4] = { 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574 };
    state[0] = sigma[0];
    state[1] = ((uint32_t)key[0] << 24) | ((uint32_t)key[1] << 16) | ((uint32_t)key[2] << 8) | key[3];
    state[2] = ((uint32_t)key[4] << 24) | ((uint32_t)key[5] << 16) | ((uint32_t)key[6] << 8) | key[7];
    state[3] = ((uint32_t)key[8] << 24) | ((uint32_t)key[9] << 16) | ((uint32_t)key[10] << 8) | key[11];
    state[4] = ((uint32_t)key[12] << 24) | ((uint32_t)key[13] << 16) | ((uint32_t)key[14] << 8) | key[15];
    state[5] = sigma[1];
    // For nonce, use first 8 bytes:
    state[6] = ((uint32_t)nonce[0] << 24) | ((uint32_t)nonce[1] << 16) | ((uint32_t)nonce[2] << 8) | nonce[3];
    state[7] = ((uint32_t)nonce[4] << 24) | ((uint32_t)nonce[5] << 16) | ((uint32_t)nonce[6] << 8) | nonce[7];
    state[8] = 0; // block counter low
    state[9] = 0; // block counter high (unused)
    state[10] = sigma[2];
    state[11] = ((uint32_t)key[0] << 24) | ((uint32_t)key[1] << 16) | ((uint32_t)key[2] << 8) | key[3];
    state[12] = ((uint32_t)key[4] << 24) | ((uint32_t)key[5] << 16) | ((uint32_t)key[6] << 8) | key[7];
    state[13] = ((uint32_t)key[8] << 24) | ((uint32_t)key[9] << 16) | ((uint32_t)key[10] << 8) | key[11];
    state[14] = ((uint32_t)key[12] << 24) | ((uint32_t)key[13] << 16) | ((uint32_t)key[14] << 8) | key[15];
    state[15] = sigma[3];
    
    size_t offset = 0;
    while (offset < input_len) {
        uint32_t output_state[16];
        memcpy(output_state, state, sizeof(output_state));
        salsa20_hash(output_state, output_state);
        uint8_t keystream[SALSA20_BLOCK_SIZE];
        salsa20_wordtobyte(keystream, output_state);
        size_t block_size = (input_len - offset < SALSA20_BLOCK_SIZE) ? (input_len - offset) : SALSA20_BLOCK_SIZE;
        for (size_t i = 0; i < block_size; i++) {
            outbuf[offset + i] = inbuf[offset + i] ^ keystream[i];
        }
        offset += block_size;
        state[8]++; // Increment block counter
    }
    memcpy(output, outbuf, input_len);
    output[input_len] = '\0';
    free(outbuf);
    return 0;
}

