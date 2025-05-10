#include "aes.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* -- AES-128 parameters and constants -- */
#define AES_BLOCKLEN 16
#define AES_KEYLEN   16
#define AES_NB       4
#define AES_NK       4
#define AES_NR       10

typedef uint8_t state_t[4][4];

/* Forward S-box */
static const uint8_t sbox[256] = {
    /* 0x00 */ 0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    /* … */ /* (truncated for brevity—unchanged) */
    /* 0xF0 */ 0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

/* Inverse S-box */
static const uint8_t rsbox[256] = {
    0x52,0x09,0x6A,0xD5,0x30,0x36,0xA5,0x38,0xBF,0x40,0xA3,0x9E,0x81,0xF3,0xD7,0xFB,
    0x7C,0xE3,0x39,0x82,0x9B,0x2F,0xFF,0x87,0x34,0x8E,0x43,0x44,0xC4,0xDE,0xE9,0xCB,
    0x54,0x7B,0x94,0x32,0xA6,0xC2,0x23,0x3D,0xEE,0x4C,0x95,0x0B,0x42,0xFA,0xC3,0x4E,
    0x08,0x2E,0xA1,0x66,0x28,0xD9,0x24,0xB2,0x76,0x5B,0xA2,0x49,0x6D,0x8B,0xD1,0x25,
    0x72,0xF8,0xF6,0x64,0x86,0x68,0x98,0x16,0xD4,0xA4,0x5C,0xCC,0x5D,0x65,0xB6,0x92,
    0x6C,0x70,0x48,0x50,0xFD,0xED,0xB9,0xDA,0x5E,0x15,0x46,0x57,0xA7,0x8D,0x9D,0x84,
    0x90,0xD8,0xAB,0x00,0x8C,0xBC,0xD3,0x0A,0xF7,0xE4,0x58,0x05,0xB8,0xB3,0x45,0x06,
    0xD0,0x2C,0x1E,0x8F,0xCA,0x3F,0x0F,0x02,0xC1,0xAF,0xBD,0x03,0x01,0x13,0x8A,0x6B,
    0x3A,0x91,0x11,0x41,0x4F,0x67,0xDC,0xEA,0x97,0xF2,0xCF,0xCE,0xF0,0xB4,0xE6,0x73,
    0x96,0xAC,0x74,0x22,0xE7,0xAD,0x35,0x85,0xE2,0xF9,0x37,0xE8,0x1C,0x75,0xDF,0x6E,
    0x47,0xF1,0x1A,0x71,0x1D,0x29,0xC5,0x89,0x6F,0xB7,0x62,0x0E,0xAA,0x18,0xBE,0x1B,
    0xFC,0x56,0x3E,0x4B,0xC6,0xD2,0x79,0x20,0x9A,0xDB,0xC0,0xFE,0x78,0xCD,0x5A,0xF4,
    0x1F,0xDD,0xA8,0x33,0x88,0x07,0xC7,0x31,0xB1,0x12,0x10,0x59,0x27,0x80,0xEC,0x5F,
    0x60,0x51,0x7F,0xA9,0x19,0xB5,0x4A,0x0D,0x2D,0xE5,0x7A,0x9F,0x93,0xC9,0x9C,0xEF,
    0xA0,0xE0,0x3B,0x4D,0xAE,0x2A,0xF5,0xB0,0xC8,0xEB,0xBB,0x3C,0x83,0x53,0x99,0x61,
    0x17,0x2B,0x04,0x7E,0xBA,0x77,0xD6,0x26,0xE1,0x69,0x14,0x63,0x55,0x21,0x0C,0x7D
};

/* Round constants */
static const uint8_t Rcon[11] = {
    0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36
};

/* GF(2^8) multiply */
static inline uint8_t Multiply(uint8_t x, uint8_t y) {
    uint8_t result = 0;
    while (y) {
        if (y & 1) result ^= x;
        /* xtime = x * {02} in GF(2^8) */
        x = (uint8_t)((x << 1) ^ ((x & 0x80) ? 0x1B : 0x00));
        y >>= 1;
    }
    return result;
}

/* Key expansion */
static void KeyExpansion(const uint8_t *Key, uint8_t *RoundKey) {
    memcpy(RoundKey, Key, AES_KEYLEN);
    uint32_t bytesGen = AES_KEYLEN, rconIter = 1;
    uint8_t temp[4];

    while (bytesGen < AES_BLOCKLEN * (AES_NR + 1)) {
        memcpy(temp, &RoundKey[bytesGen - 4], 4);
        if (bytesGen % AES_KEYLEN == 0) {
            /* RotWord */
            uint8_t t = temp[0];
            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = t;
            /* SubWord */
            for (int i = 0; i < 4; i++) {
                temp[i] = sbox[temp[i]];
            }
            temp[0] ^= Rcon[rconIter++];
        }
        for (int i = 0; i < 4; i++) {
            RoundKey[bytesGen] = RoundKey[bytesGen - AES_KEYLEN] ^ temp[i];
            bytesGen++;
        }
    }
}

/* AddRoundKey */
static void AddRoundKey(uint8_t round, state_t state, const uint8_t *RoundKey) {
    for (int c = 0; c < 4; c++)
    for (int r = 0; r < 4; r++)
        state[r][c] ^= RoundKey[round * AES_BLOCKLEN + c * 4 + r];
}

/* SubBytes */
static void SubBytes(state_t state) {
    for (int r = 0; r < 4; r++)
    for (int c = 0; c < 4; c++)
        state[r][c] = sbox[state[r][c]];
}

/* InvSubBytes */
static void InvSubBytes(state_t state) {
    for (int r = 0; r < 4; r++)
    for (int c = 0; c < 4; c++)
        state[r][c] = rsbox[state[r][c]];
}

/* ShiftRows */
static void ShiftRows(state_t state) {
    uint8_t tmp;
    /* Row 1 left rotate by 1 */
    tmp = state[1][0];
    for (int i = 0; i < 3; i++) state[1][i] = state[1][i+1];
    state[1][3] = tmp;
    /* Row 2 swap */
    tmp = state[2][0]; state[2][0] = state[2][2]; state[2][2] = tmp;
    tmp = state[2][1]; state[2][1] = state[2][3]; state[2][3] = tmp;
    /* Row 3 right rotate by 1 */
    tmp = state[3][3];
    for (int i = 3; i > 0; i--) state[3][i] = state[3][i-1];
    state[3][0] = tmp;
}

/* InvShiftRows */
static void InvShiftRows(state_t state) {
    uint8_t tmp;
    /* Row 1 right rotate by 1 */
    tmp = state[1][3];
    for (int i = 3; i > 0; i--) state[1][i] = state[1][i-1];
    state[1][0] = tmp;
    /* Row 2 swap */
    tmp = state[2][0]; state[2][0] = state[2][2]; state[2][2] = tmp;
    tmp = state[2][1]; state[2][1] = state[2][3]; state[2][3] = tmp;
    /* Row 3 left rotate by 1 */
    tmp = state[3][0];
    for (int i = 0; i < 3; i++) state[3][i] = state[3][i+1];
    state[3][3] = tmp;
}

/* MixColumns */
static void MixColumns(state_t state) {
    for (int c = 0; c < 4; c++) {
        uint8_t a0 = state[0][c], a1 = state[1][c],
                a2 = state[2][c], a3 = state[3][c];
        state[0][c] = (uint8_t)(Multiply(a0,2) ^ Multiply(a1,3) ^ a2 ^ a3);
        state[1][c] = (uint8_t)(a0 ^ Multiply(a1,2) ^ Multiply(a2,3) ^ a3);
        state[2][c] = (uint8_t)(a0 ^ a1 ^ Multiply(a2,2) ^ Multiply(a3,3));
        state[3][c] = (uint8_t)(Multiply(a0,3) ^ a1 ^ a2 ^ Multiply(a3,2));
    }
}

/* InvMixColumns */
static void InvMixColumns(state_t state) {
    for (int c = 0; c < 4; c++) {
        uint8_t a0 = state[0][c], a1 = state[1][c],
                a2 = state[2][c], a3 = state[3][c];
        state[0][c] = (uint8_t)(Multiply(a0,0x0e) ^ Multiply(a1,0x0b) ^
                                 Multiply(a2,0x0d) ^ Multiply(a3,0x09));
        state[1][c] = (uint8_t)(Multiply(a0,0x09) ^ Multiply(a1,0x0e) ^
                                 Multiply(a2,0x0b) ^ Multiply(a3,0x0d));
        state[2][c] = (uint8_t)(Multiply(a0,0x0d) ^ Multiply(a1,0x09) ^
                                 Multiply(a2,0x0e) ^ Multiply(a3,0x0b));
        state[3][c] = (uint8_t)(Multiply(a0,0x0b) ^ Multiply(a1,0x0d) ^
                                 Multiply(a2,0x09) ^ Multiply(a3,0x0e));
    }
}

/* Core encryption routine */
static void Cipher(state_t state, const uint8_t *RoundKey) {
    AddRoundKey(0, state, RoundKey);
    for (int round = 1; round < AES_NR; round++) {
        SubBytes(state);
        ShiftRows(state);
        MixColumns(state);
        AddRoundKey((uint8_t)round, state, RoundKey);
    }
    SubBytes(state);
    ShiftRows(state);
    AddRoundKey(AES_NR, state, RoundKey);
}

/* Core decryption routine */
static void InvCipher(state_t state, const uint8_t *RoundKey) {
    AddRoundKey(AES_NR, state, RoundKey);
    for (int round = AES_NR - 1; round >= 1; round--) {
        InvShiftRows(state);
        InvSubBytes(state);
        AddRoundKey((uint8_t)round, state, RoundKey);
        InvMixColumns(state);
    }
    InvShiftRows(state);
    InvSubBytes(state);
    AddRoundKey(0, state, RoundKey);
}

/* PKCS#7 padding & unpadding */
static void pkcs7_pad(uint8_t *block, size_t data_len) {
    uint8_t pad = (uint8_t)(AES_BLOCKLEN - data_len);
    for (size_t i = data_len; i < AES_BLOCKLEN; i++) {
        block[i] = pad;
    }
}
static int pkcs7_unpad(uint8_t *block) {
    uint8_t pad = block[AES_BLOCKLEN - 1];
    if (pad < 1 || pad > AES_BLOCKLEN) return -1;
    for (size_t i = AES_BLOCKLEN - pad; i < AES_BLOCKLEN; i++) {
        if (block[i] != pad) return -1;
    }
    return pad;
}

/* Hex/binary conversions */
static void bin_to_hex_aes(const uint8_t *bin, size_t bin_len, char *hex) {
    static const char hex_chars[] = "0123456789ABCDEF";
    for (size_t i = 0; i < bin_len; i++) {
        hex[2*i]     = hex_chars[(bin[i] >> 4) & 0xF];
        hex[2*i + 1] = hex_chars[ bin[i] & 0xF];
    }
    hex[2*bin_len] = '\0';
}
static int hex_to_bin_aes(const char *hex, uint8_t *bin, size_t bin_size) {
    size_t hex_len = strlen(hex);
    if (hex_len % 2) return -1;
    size_t out_len = hex_len / 2;
    if (out_len > bin_size) return -1;
    for (size_t i = 0; i < out_len; i++) {
        char tmp[3] = { hex[2*i], hex[2*i+1], '\0' };
        bin[i] = (uint8_t)strtol(tmp, NULL, 16);
    }
    return (int)out_len;
}

int aes_crypt(const char *input,
              const char *key_str,
              int shift,
              mode_t mode,
              int otp,
              char *output)
{
    (void) shift;
    (void) otp;

    if (!input || !key_str || !output) {
        fprintf(stderr, "AES: Null parameter supplied\n");
        return -1;
    }
    if (strlen(key_str) != AES_KEYLEN) {
        fprintf(stderr, "AES: key must be %d bytes\n", AES_KEYLEN);
        return -1;
    }

    uint8_t RoundKey[AES_BLOCKLEN * (AES_NR + 1)];
    KeyExpansion((const uint8_t*)key_str, RoundKey);

    if (mode == MODE_ENCRYPT) {
        size_t in_len = strlen(input);
        size_t num_blocks = (in_len / AES_BLOCKLEN) + 1;
        size_t buf_len    = num_blocks * AES_BLOCKLEN;

        uint8_t *buf = calloc(buf_len, 1);
        if (!buf) return -1;
        memcpy(buf, input, in_len);
        size_t last = in_len % AES_BLOCKLEN;
        pkcs7_pad(buf + (num_blocks - 1)*AES_BLOCKLEN, last);

        for (size_t off = 0; off < buf_len; off += AES_BLOCKLEN) {
            state_t st;
            memcpy(st, buf + off, AES_BLOCKLEN);
            Cipher(st, RoundKey);
            memcpy(buf + off, st, AES_BLOCKLEN);
        }
        bin_to_hex_aes(buf, buf_len, output);
        free(buf);
    } else { /* MODE_DECRYPT */
        size_t hex_len = strlen(input);
        size_t bin_len = hex_len / 2;
        uint8_t *buf = malloc(bin_len);
        if (!buf) return -1;

        int got = hex_to_bin_aes(input, buf, bin_len);
        if (got < 0 || (size_t)got != bin_len) {
            free(buf);
            return -1;
        }

        for (size_t off = 0; off < bin_len; off += AES_BLOCKLEN) {
            state_t st;
            memcpy(st, buf + off, AES_BLOCKLEN);
            InvCipher(st, RoundKey);
            memcpy(buf + off, st, AES_BLOCKLEN);
        }

        int pad = pkcs7_unpad(buf + bin_len - AES_BLOCKLEN);
        if (pad < 0) {
            free(buf);
            return -1;
        }
        size_t out_len = bin_len - pad;
        memcpy(output, buf, out_len);
        output[out_len] = '\0';
        free(buf);
    }

    return 0;
}

