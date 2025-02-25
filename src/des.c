#include "des.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define DES_BLOCK_SIZE 8

/* DES static tables */
static const int IP[64] = {
    58,50,42,34,26,18,10,2, 60,52,44,36,28,20,12,4,
    62,54,46,38,30,22,14,6, 64,56,48,40,32,24,16,8,
    57,49,41,33,25,17,9,1, 59,51,43,35,27,19,11,3,
    61,53,45,37,29,21,13,5, 63,55,47,39,31,23,15,7
};

static const int FP[64] = {
    40,8,48,16,56,24,64,32, 39,7,47,15,55,23,63,31,
    38,6,46,14,54,22,62,30, 37,5,45,13,53,21,61,29,
    36,4,44,12,52,20,60,28, 35,3,43,11,51,19,59,27,
    34,2,42,10,50,18,58,26, 33,1,41,9,49,17,57,25
};

static const int E[48] = {
    32,1,2,3,4,5, 4,5,6,7,8,9,
    8,9,10,11,12,13, 12,13,14,15,16,17,
    16,17,18,19,20,21, 20,21,22,23,24,25,
    24,25,26,27,28,29, 28,29,30,31,32,1
};

static const int P[32] = {
    16,7,20,21,29,12,28,17,
    1,15,23,26,5,18,31,10,
    2,8,24,14,32,27,3,9,
    19,13,30,6,22,11,4,25
};

static const int S_BOX[8][4][16] = {
    { {14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7},
      {0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8},
      {4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0},
      {15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13} },
    { {15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10},
      {3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5},
      {0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15},
      {13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9} },
    { {10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8},
      {13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1},
      {13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7},
      {1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12} },
    { {7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15},
      {13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9},
      {10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4},
      {3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14} },
    { {2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9},
      {14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6},
      {4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14},
      {11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3} },
    { {12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11},
      {10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8},
      {9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6},
      {4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13} },
    { {4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1},
      {13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6},
      {1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2},
      {6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12} },
    { {13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7},
      {1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2},
      {7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8},
      {2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11} }
};

static const int PC1[56] = {
    57,49,41,33,25,17,9,
    1,58,50,42,34,26,18,
    10,2,59,51,43,35,27,
    19,11,3,60,52,44,36,
    63,55,47,39,31,23,15,
    7,62,54,46,38,30,22,
    14,6,61,53,45,37,29,
    21,13,5,28,20,12,4
};

static const int PC2[48] = {
    14,17,11,24,1,5,
    3,28,15,6,21,10,
    23,19,12,4,26,8,
    16,7,27,20,13,2,
    41,52,31,37,47,55,
    30,40,51,45,33,48,
    44,49,39,56,34,53,
    46,42,50,36,29,32
};

static const int LS[16] = {
    1,1,2,2,2,2,2,2,
    1,2,2,2,2,2,2,1
};

/* --- Helper functions for bit permutations --- */
static void permute(const uint8_t *in, uint8_t *out, const int *table, int n) {
    memset(out, 0, (n+7)/8);
    for (int i = 0; i < n; i++) {
        int pos = table[i] - 1;
        int byte_in = pos / 8;
        int bit_in = pos % 8;
        int byte_out = i / 8;
        int bit_out = i % 8;
        if (in[byte_in] & (1 << (7 - bit_in)))
            out[byte_out] |= (1 << (7 - bit_out));
    }
}

/* --- Key schedule --- */
static void generate_round_keys(const uint8_t key[8], uint8_t round_keys[16][6]) {
    uint8_t permuted[7]; // 56 bits
    permute(key, permuted, PC1, 56);
    // Split into C (first 28 bits) and D (last 28 bits) as 28-bit numbers in 32-bit ints
    unsigned int C = ((unsigned int)permuted[0] << 20) | ((unsigned int)permuted[1] << 12) | ((unsigned int)permuted[2] << 4) | (permuted[3] >> 4);
    unsigned int D = (((unsigned int)permuted[3] & 0x0F) << 24) | ((unsigned int)permuted[4] << 16) | ((unsigned int)permuted[5] << 8) | permuted[6];
    for (int round = 0; round < 16; round++) {
        int shifts = LS[round];
        C = ((C << shifts) | (C >> (28 - shifts))) & 0x0FFFFFFF;
        D = ((D << shifts) | (D >> (28 - shifts))) & 0x0FFFFFFF;
        // Combine C and D into 56 bits stored in 7 bytes
        uint8_t CD[7];
        CD[0] = (C >> 20) & 0xFF;
        CD[1] = (C >> 12) & 0xFF;
        CD[2] = (C >> 4) & 0xFF;
        CD[3] = ((C & 0x0F) << 4) | ((D >> 24) & 0x0F);
        CD[4] = (D >> 16) & 0xFF;
        CD[5] = (D >> 8) & 0xFF;
        CD[6] = D & 0xFF;
        permute(CD, round_keys[round], PC2, 48);
    }
}

/* --- DES Round Function --- */
static void des_round(uint8_t *L, uint8_t *R, const uint8_t round_key[6]) {
    uint8_t expanded_R[6] = {0};
    permute(R, expanded_R, E, 48);
    for (int i = 0; i < 6; i++)
        expanded_R[i] ^= round_key[i];
    uint8_t s_output[4] = {0};
    int bit_pos = 0;
    for (int i = 0; i < 8; i++) {
        int byte_index = (i * 6) / 8;
        int bit_offset = (i * 6) % 8;
        uint8_t six_bits;
        if (bit_offset <= 2)
            six_bits = (expanded_R[byte_index] >> (2 - bit_offset)) & 0x3F;
        else {
            six_bits = ((expanded_R[byte_index] & ((1 << (8 - bit_offset)) - 1)) << (bit_offset - 2)) |
                        (expanded_R[byte_index+1] >> (10 - bit_offset));
            six_bits &= 0x3F;
        }
        int row = ((six_bits & 0x20) >> 4) | (six_bits & 0x01);
        int col = (six_bits >> 1) & 0x0F;
        uint8_t s_val = S_BOX[i][row][col];
        int out_byte = bit_pos / 8;
        int out_offset = bit_pos % 8;
        if (out_offset <= 4)
            s_output[out_byte] |= s_val << (4 - out_offset);
        else {
            s_output[out_byte] |= s_val >> (out_offset - 4);
            s_output[out_byte+1] |= s_val << (12 - out_offset);
        }
        bit_pos += 4;
    }
    uint8_t f_output[4] = {0};
    permute(s_output, f_output, P, 32);
    uint8_t new_R[4];
    for (int i = 0; i < 4; i++)
        new_R[i] = L[i] ^ f_output[i];
    memcpy(L, R, 4);
    memcpy(R, new_R, 4);
}

/* Process a single 64-bit block */
static void des_process_block(const uint8_t in[8], uint8_t out[8], const uint8_t round_keys[16][6], int mode) {
    uint8_t block[8];
    permute(in, block, IP, 64);
    uint8_t L[4], R[4];
    memcpy(L, block, 4);
    memcpy(R, block+4, 4);
    if (mode == MODE_ENCRYPT) {
        for (int round = 0; round < 16; round++)
            des_round(L, R, round_keys[round]);
    } else {
        for (int round = 15; round >= 0; round--)
            des_round(L, R, round_keys[round]);
    }
    uint8_t preoutput[8];
    memcpy(preoutput, R, 4);
    memcpy(preoutput+4, L, 4);
    permute(preoutput, out, FP, 64);
}

/* PKCS#7 padding for DES block */
static void pkcs7_pad_des(uint8_t *block, size_t data_len) {
    uint8_t pad = DES_BLOCK_SIZE - data_len;
    for (size_t i = data_len; i < DES_BLOCK_SIZE; i++)
        block[i] = pad;
}

/* Remove PKCS#7 padding; returns number of padding bytes */
static int pkcs7_unpad_des(uint8_t *block) {
    uint8_t pad = block[DES_BLOCK_SIZE - 1];
    if (pad < 1 || pad > DES_BLOCK_SIZE)
        return -1;
    for (size_t i = DES_BLOCK_SIZE - pad; i < DES_BLOCK_SIZE; i++) {
        if (block[i] != pad)
            return -1;
    }
    return pad;
}

/* Convert binary to hex string */
static void bin_to_hex_des(const uint8_t *bin, size_t bin_len, char *hex) {
    const char *hex_chars = "0123456789ABCDEF";
    for (size_t i = 0; i < bin_len; i++) {
        hex[i*2] = hex_chars[(bin[i] >> 4) & 0xF];
        hex[i*2+1] = hex_chars[bin[i] & 0xF];
    }
    hex[bin_len*2] = '\0';
}

/* Convert hex string to binary */
static int hex_to_bin_des(const char *hex, uint8_t *bin, size_t bin_size) {
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

int des_crypt(const char *input, const char *key, int shift, mode_t mode, int otp, char *output) {
    (void) shift; (void) otp;
    if (strlen(key) != 8) {
        fprintf(stderr, "DES requires an 8-character key.\n");
        return -1;
    }
    uint8_t key_bytes[8];
    memcpy(key_bytes, key, 8);
    uint8_t round_keys[16][6];
    generate_round_keys(key_bytes, round_keys);
    if (mode == MODE_ENCRYPT) {
        size_t input_len = strlen(input);
        size_t num_blocks = (input_len / DES_BLOCK_SIZE) + 1;
        size_t padded_len = num_blocks * DES_BLOCK_SIZE;
        uint8_t *buffer = calloc(padded_len, 1);
        if (!buffer) return -1;
        memcpy(buffer, input, input_len);
        size_t last_block = input_len % DES_BLOCK_SIZE;
        pkcs7_pad_des(buffer + (num_blocks - 1) * DES_BLOCK_SIZE, last_block);
        for (size_t i = 0; i < padded_len; i += DES_BLOCK_SIZE) {
            uint8_t block_out[DES_BLOCK_SIZE];
            des_process_block(buffer + i, block_out, round_keys, MODE_ENCRYPT);
            memcpy(buffer + i, block_out, DES_BLOCK_SIZE);
        }
        bin_to_hex_des(buffer, padded_len, output);
        free(buffer);
    } else {
        size_t hex_len = strlen(input);
        size_t bin_len = hex_len / 2;
        uint8_t *buffer = malloc(bin_len);
        if (!buffer) return -1;
        if (hex_to_bin_des(input, buffer, bin_len) != bin_len) {
            free(buffer);
            return -1;
        }
        for (size_t i = 0; i < bin_len; i += DES_BLOCK_SIZE) {
            uint8_t block_out[DES_BLOCK_SIZE];
            des_process_block(buffer + i, block_out, round_keys, MODE_DECRYPT);
            memcpy(buffer + i, block_out, DES_BLOCK_SIZE);
        }
        int pad = pkcs7_unpad_des(buffer + bin_len - DES_BLOCK_SIZE);
        if (pad < 0) {
            free(buffer);
            return -1;
        }
        size_t out_len = bin_len - pad;
        memcpy(output, buffer, out_len);
        output[out_len] = '\0';
        free(buffer);
    }
    return 0;
}

