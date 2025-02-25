#include "aes.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

// --- AES-128 ECB Mode Implementation (Simplified) ---
// This implementation is adapted from public-domain tiny-AES-c code.
// Note: For a full-featured and secure AES implementation, use a proven library.

#define AES_BLOCKLEN 16  // Block length in bytes
#define AES_KEYLEN 16    // Key length in bytes for AES-128
#define AES_NB 4
#define AES_NK 4
#define AES_NR 10

typedef uint8_t state_t[4][4];

/* S-box */
static const uint8_t sbox[256] = {
    /* 0x00 */ 0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    /* 0x10 */ 0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    /* 0x20 */ 0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    /* 0x30 */ 0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    /* 0x40 */ 0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    /* 0x50 */ 0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    /* 0x60 */ 0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    /* 0x70 */ 0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    /* 0x80 */ 0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    /* 0x90 */ 0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    /* 0xA0 */ 0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    /* 0xB0 */ 0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    /* 0xC0 */ 0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    /* 0xD0 */ 0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    /* 0xE0 */ 0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    /* 0xF0 */ 0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

/* (For brevity, inverse S-box and full InvMixColumns/InvShiftRows are omitted;
   in a real implementation they must be provided.) */

/* Round constant array */
static const uint8_t Rcon[11] = { 0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36 };

/* Key expansion: expands 16-byte key into 176-byte round key */
static void KeyExpansion(const uint8_t* Key, uint8_t* RoundKey) {
    memcpy(RoundKey, Key, AES_KEYLEN);
    uint32_t bytesGenerated = AES_KEYLEN;
    uint32_t rconIteration = 1;
    uint8_t temp[4];

    while (bytesGenerated < 176) {
        for (int i = 0; i < 4; i++) {
            temp[i] = RoundKey[bytesGenerated - 4 + i];
        }
        if (bytesGenerated % AES_KEYLEN == 0) {
            // Rotate left
            uint8_t t = temp[0];
            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = t;
            // Apply sbox
            for (int i = 0; i < 4; i++) {
                temp[i] = sbox[temp[i]];
            }
            temp[0] ^= Rcon[rconIteration++];
        }
        for (int i = 0; i < 4; i++) {
            RoundKey[bytesGenerated] = RoundKey[bytesGenerated - AES_KEYLEN] ^ temp[i];
            bytesGenerated++;
        }
    }
}

/* AddRoundKey transformation */
static void AddRoundKey(uint8_t round, state_t state, const uint8_t* RoundKey) {
    for (int c = 0; c < 4; c++) {
        for (int r = 0; r < 4; r++) {
            state[r][c] ^= RoundKey[round * AES_BLOCKLEN + c * 4 + r];
        }
    }
}

/* SubBytes transformation */
static void SubBytes(state_t state) {
    for (int r = 0; r < 4; r++)
        for (int c = 0; c < 4; c++)
            state[r][c] = sbox[state[r][c]];
}

/* ShiftRows transformation */
static void ShiftRows(state_t state) {
    uint8_t temp;
    // Row 1
    temp = state[1][0];
    state[1][0] = state[1][1];
    state[1][1] = state[1][2];
    state[1][2] = state[1][3];
    state[1][3] = temp;
    // Row 2
    temp = state[2][0];
    state[2][0] = state[2][2];
    state[2][2] = temp;
    temp = state[2][1];
    state[2][1] = state[2][3];
    state[2][3] = temp;
    // Row 3
    temp = state[3][3];
    state[3][3] = state[3][2];
    state[3][2] = state[3][1];
    state[3][1] = state[3][0];
    state[3][0] = temp;
}

/* xtime helper */
static uint8_t xtime(uint8_t x) {
    return (x << 1) ^ ((x >> 7) & 1 ? 0x1b : 0);
}

/* MixColumns transformation */
static void MixColumns(state_t state) {
    for (int c = 0; c < 4; c++) {
        uint8_t a0 = state[0][c], a1 = state[1][c],
                a2 = state[2][c], a3 = state[3][c];
        state[0][c] = xtime(a0) ^ a1 ^ xtime(a1) ^ a2 ^ a3;
        state[1][c] = a0 ^ xtime(a1) ^ a2 ^ xtime(a2) ^ a3;
        state[2][c] = a0 ^ a1 ^ xtime(a2) ^ a3 ^ xtime(a3);
        state[3][c] = a0 ^ xtime(a0) ^ a1 ^ a2 ^ xtime(a3);
    }
}

/* For brevity, the inverse transformations (InvSubBytes, InvShiftRows, InvMixColumns, InvCipher)
   are omitted. In a complete implementation, they must be provided. */

static void Cipher(state_t state, const uint8_t* RoundKey) {
    AddRoundKey(0, state, RoundKey);
    for (int round = 1; round < AES_NR; round++) {
        SubBytes(state);
        ShiftRows(state);
        MixColumns(state);
        AddRoundKey(round, state, RoundKey);
    }
    SubBytes(state);
    ShiftRows(state);
    AddRoundKey(AES_NR, state, RoundKey);
}

static void InvCipher(state_t state, const uint8_t* RoundKey) {
    // A proper implementation of InvCipher is required.
    // For this demo, assume decryption is the inverse of encryption.
    // (Not implemented here for brevity.)
}

/* PKCS#7 padding: pad a block of size 16 */
static void pkcs7_pad(uint8_t *block, size_t data_len) {
    uint8_t pad = AES_BLOCKLEN - data_len;
    for (size_t i = data_len; i < AES_BLOCKLEN; i++) {
        block[i] = pad;
    }
}

/* Remove PKCS#7 padding; returns number of padding bytes, or -1 on error */
static int pkcs7_unpad(uint8_t *block) {
    uint8_t pad = block[AES_BLOCKLEN - 1];
    if (pad < 1 || pad > AES_BLOCKLEN)
        return -1;
    for (size_t i = AES_BLOCKLEN - pad; i < AES_BLOCKLEN; i++) {
        if (block[i] != pad)
            return -1;
    }
    return pad;
}

/* Convert binary data to hex string */
static void bin_to_hex_aes(const uint8_t *bin, size_t bin_len, char *hex) {
    const char *hex_chars = "0123456789ABCDEF";
    for (size_t i = 0; i < bin_len; i++) {
        hex[i*2]     = hex_chars[(bin[i] >> 4) & 0xF];
        hex[i*2 + 1] = hex_chars[bin[i] & 0xF];
    }
    hex[bin_len * 2] = '\0';
}

/* Convert hex string to binary */
static int hex_to_bin_aes(const char *hex, uint8_t *bin, size_t bin_size) {
    size_t hex_len = strlen(hex);
    if (hex_len % 2 != 0)
        return -1;
    size_t out_len = hex_len / 2;
    if (out_len > bin_size)
        return -1;
    for (size_t i = 0; i < out_len; i++) {
        char byte_str[3] = { hex[i*2], hex[i*2+1], '\0' };
        bin[i] = (uint8_t) strtol(byte_str, NULL, 16);
    }
    return out_len;
}

int aes_crypt(const char *input, const char *key_str, int shift, mode_t mode, int otp, char *output) {
    (void) shift;
    (void) otp;
    if (strlen(key_str) != 16) {
        fprintf(stderr, "AES requires a 16-character key.\n");
        return -1;
    }
    uint8_t key[AES_KEYLEN];
    memcpy(key, key_str, AES_KEYLEN);
    uint8_t RoundKey[176];
    KeyExpansion(key, RoundKey);

    if (mode == MODE_ENCRYPT) {
        size_t input_len = strlen(input);
        // Calculate padded length (always at least one block)
        size_t num_blocks = (input_len / AES_BLOCKLEN) + 1;
        size_t padded_len = num_blocks * AES_BLOCKLEN;
        uint8_t *buffer = calloc(padded_len, 1);
        if (!buffer) return -1;
        memcpy(buffer, input, input_len);
        size_t last_block = input_len % AES_BLOCKLEN;
        pkcs7_pad(buffer + (num_blocks - 1) * AES_BLOCKLEN, last_block);
        for (size_t i = 0; i < padded_len; i += AES_BLOCKLEN) {
            state_t state;
            memcpy(state, buffer + i, AES_BLOCKLEN);
            Cipher(state, RoundKey);
            memcpy(buffer + i, state, AES_BLOCKLEN);
        }
        bin_to_hex_aes(buffer, padded_len, output);
        free(buffer);
    } else { // MODE_DECRYPT
        size_t hex_len = strlen(input);
        size_t bin_len = hex_len / 2;
        uint8_t *buffer = malloc(bin_len);
        if (!buffer) return -1;
        if (hex_to_bin_aes(input, buffer, bin_len) != bin_len) {
            free(buffer);
            return -1;
        }
        for (size_t i = 0; i < bin_len; i += AES_BLOCKLEN) {
            state_t state;
            memcpy(state, buffer + i, AES_BLOCKLEN);
            InvCipher(state, RoundKey);
            memcpy(buffer + i, state, AES_BLOCKLEN);
        }
        int pad = pkcs7_unpad(buffer + bin_len - AES_BLOCKLEN);
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

