#include "blowfish.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* Blowfish context: expanded P-array and S-boxes */
typedef struct {
    uint32_t P[18];
    uint32_t S[4][256];
} BlowfishContext;

/* F-function */
static inline uint32_t F(const BlowfishContext *ctx, uint32_t x) {
    uint8_t a = (x >> 24) & 0xFF;
    uint8_t b = (x >> 16) & 0xFF;
    uint8_t c = (x >>  8) & 0xFF;
    uint8_t d =  x        & 0xFF;
    return ((ctx->S[0][a] + ctx->S[1][b]) ^ ctx->S[2][c]) + ctx->S[3][d];
}

/* Key expansion / context initialization */
static void blowfish_init(BlowfishContext *ctx,
                          const uint8_t *key,
                          size_t keyLen)
{
    /* 1) Copy the original tables */
    memcpy(ctx->P, ORIG_P, sizeof(ORIG_P));
    for (int i = 0; i < 4; i++) {
        memcpy(ctx->S[i], ORIG_S[i], sizeof(ORIG_S[i]));
    }

    /* 2) XOR P-array with key bytes (cycling) */
    int j = 0;
    for (int i = 0; i < 18; i++) {
        uint32_t data = 0;
        for (int k = 0; k < 4; k++) {
            data = (data << 8) | key[j];
            j = (j + 1) % keyLen;
        }
        ctx->P[i] ^= data;
    }

    /* 3) Re-key P-array & S-boxes by encrypting zero blocks */
    uint32_t L = 0, R = 0, tmp;
    for (int i = 0; i < 18; i += 2) {
        for (int r = 0; r < 16; r++) {
            L ^= ctx->P[r];
            R ^= F(ctx, L);
            tmp = L; L = R; R = tmp;
        }
        tmp = L; L = R; R = tmp;
        R ^= ctx->P[16];
        L ^= ctx->P[17];
        ctx->P[i]   = L;
        ctx->P[i+1] = R;
    }
    for (int s = 0; s < 4; s++) {
        for (int i = 0; i < 256; i += 2) {
            for (int r = 0; r < 16; r++) {
                L ^= ctx->P[r];
                R ^= F(ctx, L);
                tmp = L; L = R; R = tmp;
            }
            tmp = L; L = R; R = tmp;
            R ^= ctx->P[16];
            L ^= ctx->P[17];
            ctx->S[s][i]   = L;
            ctx->S[s][i+1] = R;
        }
    }
}

/* Encrypt one 64-bit block */
static void blowfish_encrypt_block(const BlowfishContext *ctx,
                                   uint32_t *L, uint32_t *R)
{
    uint32_t l = *L, r = *R, tmp;
    for (int i = 0; i < 16; i++) {
        l ^= ctx->P[i];
        r ^= F(ctx, l);
        tmp = l; l = r; r = tmp;
    }
    tmp = l; l = r; r = tmp;
    r ^= ctx->P[16];
    l ^= ctx->P[17];
    *L = l; *R = r;
}

/* Decrypt one 64-bit block */
static void blowfish_decrypt_block(const BlowfishContext *ctx,
                                   uint32_t *L, uint32_t *R)
{
    uint32_t l = *L, r = *R, tmp;
    l ^= ctx->P[17];
    r ^= ctx->P[16];
    for (int i = 15; i >= 0; i--) {
        tmp = l; l = r; r = tmp;
        r ^= F(ctx, l);
        l ^= ctx->P[i];
    }
    *L = l; *R = r;
}

/* Helpers */
static void pkcs7_pad(uint8_t *buf, size_t data_len, size_t blk) {
    uint8_t p = (uint8_t)(blk - (data_len % blk));
    for (size_t i = data_len; i < data_len + p; i++) buf[i] = p;
}
static int pkcs7_unpad(uint8_t *buf, size_t len) {
    uint8_t p = buf[len - 1];
    if (p == 0 || p > len) return -1;
    for (size_t i = len - p; i < len; i++)
        if (buf[i] != p) return -1;
    return (int)p;
}
static void bin_to_hex(const uint8_t *bin, size_t n, char *hex) {
    static const char *h = "0123456789ABCDEF";
    for (size_t i = 0; i < n; i++) {
        hex[2*i]   = h[(bin[i] >> 4) & 0xF];
        hex[2*i+1] = h[ bin[i]       & 0xF];
    }
    hex[2*n] = '\0';
}
static int hex_to_bin(const char *hex, uint8_t *bin, size_t n) {
    size_t len = strlen(hex);
    if (len != 2*n) return -1;
    for (size_t i = 0; i < n; i++) {
        unsigned int v;
        if (sscanf(hex + 2*i, "%2X", &v) != 1) return -1;
        bin[i] = (uint8_t)v;
    }
    return 0;
}

int blowfish_crypt(const char *input,
                   const char *key,
                   int shift,
                   mode_t mode,
                   int otp,
                   char *output)
{
    (void)shift; (void)otp;
    size_t keyLen = strlen(key);
    if (keyLen < 4 || keyLen > 56) {
        fprintf(stderr, "Blowfish key must be 4–56 bytes\n");
        return -1;
    }

    BlowfishContext ctx;
    blowfish_init(&ctx, (const uint8_t*)key, keyLen);

    if (mode == MODE_ENCRYPT) {
        size_t inlen = strlen(input);
        size_t pad   = 8 - (inlen % 8);
        size_t tot   = inlen + pad;
        uint8_t *buf = malloc(tot);
        if (!buf) return -1;
        memcpy(buf, input, inlen);
        memset(buf + inlen, (uint8_t)pad, pad);
        for (size_t i = 0; i < tot; i += 8) {
            uint32_t L, R;
            memcpy(&L, buf + i,     4);
            memcpy(&R, buf + i + 4, 4);
            blowfish_encrypt_block(&ctx, &L, &R);
            memcpy(buf + i,     &L, 4);
            memcpy(buf + i + 4, &R, 4);
        }
        bin_to_hex(buf, tot, output);
        free(buf);
    } else {
        size_t hexlen = strlen(input);
        if (hexlen % 16) {
            fprintf(stderr, "Invalid ciphertext length\n");
            return -1;
        }
        size_t tot = hexlen / 2;
        uint8_t *buf = malloc(tot);
        if (!buf) return -1;
        if (hex_to_bin(input, buf, tot) != 0) { free(buf); return -1; }
        for (size_t i = 0; i < tot; i += 8) {
            uint32_t L, R;
            memcpy(&L, buf + i,     4);
            memcpy(&R, buf + i + 4, 4);
            blowfish_decrypt_block(&ctx, &L, &R);
            memcpy(buf + i,     &L, 4);
            memcpy(buf + i + 4, &R, 4);
        }
        int pad = pkcs7_unpad(buf, tot);
        if (pad < 0) { free(buf); return -1; }
        size_t outlen = tot - pad;
        memcpy(output, buf, outlen);
        output[outlen] = '\0';
        free(buf);
    }
    return 0;
}

