#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "xtea.h"

#define XTEA_DELTA 0x9E3779B9
#define XTEA_NUM_ROUNDS 32

/* Encrypt one 8-byte block using XTEA */
static void xtea_encrypt_block(unsigned int v[2], unsigned int key[4]) {
    unsigned int sum = 0;
    for (int i = 0; i < XTEA_NUM_ROUNDS; i++) {
        v[0] += (((v[1] << 4) ^ (v[1] >> 5)) + v[1]) ^ (sum + key[sum & 3]);
        sum += XTEA_DELTA;
        v[1] += (((v[0] << 4) ^ (v[0] >> 5)) + v[0]) ^ (sum + key[(sum >> 11) & 3]);
    }
}

/* Decrypt one 8-byte block using XTEA */
static void xtea_decrypt_block(unsigned int v[2], unsigned int key[4]) {
    unsigned int sum = XTEA_DELTA * XTEA_NUM_ROUNDS;
    for (int i = 0; i < XTEA_NUM_ROUNDS; i++) {
        v[1] -= (((v[0] << 4) ^ (v[0] >> 5)) + v[0]) ^ (sum + key[(sum >> 11) & 3]);
        sum -= XTEA_DELTA;
        v[0] -= (((v[1] << 4) ^ (v[1] >> 5)) + v[1]) ^ (sum + key[sum & 3]);
    }
}

/* Convert binary data to a hex string */
static void bin_to_hex(const unsigned char *bin, size_t bin_len, char *hex) {
    const char *hex_chars = "0123456789ABCDEF";
    for (size_t i = 0; i < bin_len; i++) {
        hex[i*2]     = hex_chars[(bin[i] >> 4) & 0xF];
        hex[i*2 + 1] = hex_chars[bin[i] & 0xF];
    }
    hex[bin_len * 2] = '\0';
}

/* Convert a hex string to binary data */
static int hex_to_bin(const char *hex, unsigned char *bin, size_t bin_size) {
    size_t hex_len = strlen(hex);
    if (hex_len % 2 != 0) return -1;
    size_t expected = hex_len / 2;
    if (expected > bin_size) return -1;
    for (size_t i = 0; i < expected; i++) {
        char byte_str[3] = { hex[i*2], hex[i*2+1], '\0' };
        bin[i] = (unsigned char) strtoul(byte_str, NULL, 16);
    }
    return expected;
}

int xtea_crypt(const char *input, const char *key_str, int shift, mode_t mode, int otp, char *output) {
    (void) shift;
    (void) otp;
    if (strlen(key_str) != 16) {
        fprintf(stderr, "XTEA requires a 16-character key.\n");
        return -1;
    }
    unsigned int key[4];
    for (int i = 0; i < 4; i++) {
        key[i] = ((unsigned int)key_str[i*4] << 24) | ((unsigned int)key_str[i*4+1] << 16) | 
                 ((unsigned int)key_str[i*4+2] << 8) | ((unsigned int)key_str[i*4+3]);
    }
    
    if (mode == MODE_ENCRYPT) {
        size_t input_len = strlen(input);
        size_t padded_len = ((input_len + 7) / 8) * 8;
        unsigned char *inbuf = calloc(padded_len, 1);
        if (!inbuf) return -1;
        memcpy(inbuf, input, input_len);
        
        unsigned char *outbuf = malloc(padded_len);
        if (!outbuf) { free(inbuf); return -1; }
        for (size_t i = 0; i < padded_len; i += 8) {
            unsigned int v[2];
            v[0] = ((unsigned int)inbuf[i] << 24) | ((unsigned int)inbuf[i+1] << 16) |
                   ((unsigned int)inbuf[i+2] << 8) | ((unsigned int)inbuf[i+3]);
            v[1] = ((unsigned int)inbuf[i+4] << 24) | ((unsigned int)inbuf[i+5] << 16) |
                   ((unsigned int)inbuf[i+6] << 8) | ((unsigned int)inbuf[i+7]);
            xtea_encrypt_block(v, key);
            outbuf[i]   = (v[0] >> 24) & 0xFF;
            outbuf[i+1] = (v[0] >> 16) & 0xFF;
            outbuf[i+2] = (v[0] >> 8)  & 0xFF;
            outbuf[i+3] = v[0] & 0xFF;
            outbuf[i+4] = (v[1] >> 24) & 0xFF;
            outbuf[i+5] = (v[1] >> 16) & 0xFF;
            outbuf[i+6] = (v[1] >> 8)  & 0xFF;
            outbuf[i+7] = v[1] & 0xFF;
        }
        bin_to_hex(outbuf, padded_len, output);
        free(inbuf);
        free(outbuf);
    } else { /* MODE_DECRYPT */
        size_t hex_len = strlen(input);
        size_t bin_len = hex_len / 2;
        unsigned char *inbuf = malloc(bin_len);
        if (!inbuf) return -1;
        if (hex_to_bin(input, inbuf, bin_len) != bin_len) {
            free(inbuf);
            return -1;
        }
        unsigned char *outbuf = malloc(bin_len);
        if (!outbuf) { free(inbuf); return -1; }
        for (size_t i = 0; i < bin_len; i += 8) {
            unsigned int v[2];
            v[0] = ((unsigned int)inbuf[i] << 24) | ((unsigned int)inbuf[i+1] << 16) |
                   ((unsigned int)inbuf[i+2] << 8) | ((unsigned int)inbuf[i+3]);
            v[1] = ((unsigned int)inbuf[i+4] << 24) | ((unsigned int)inbuf[i+5] << 16) |
                   ((unsigned int)inbuf[i+6] << 8) | ((unsigned int)inbuf[i+7]);
            xtea_decrypt_block(v, key);
            outbuf[i]   = (v[0] >> 24) & 0xFF;
            outbuf[i+1] = (v[0] >> 16) & 0xFF;
            outbuf[i+2] = (v[0] >> 8)  & 0xFF;
            outbuf[i+3] = v[0] & 0xFF;
            outbuf[i+4] = (v[1] >> 24) & 0xFF;
            outbuf[i+5] = (v[1] >> 16) & 0xFF;
            outbuf[i+6] = (v[1] >> 8)  & 0xFF;
            outbuf[i+7] = v[1] & 0xFF;
        }
        memcpy(output, outbuf, bin_len);
        output[bin_len] = '\0';
        free(inbuf);
        free(outbuf);
    }
    return 0;
}

