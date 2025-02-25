#include "encoding.h"
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

static const char b64chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const char b64pad = '=';
static const int mod_table[] = {0, 2, 1};

int base64_encode(const char *input, char *output, size_t out_size) {
    size_t input_len = strlen(input);
    size_t output_len = 4 * ((input_len + 2) / 3);
    if (output_len + 1 > out_size)
        return -1;

    size_t i, j;
    for (i = 0, j = 0; i < input_len;) {
        uint32_t octet_a = i < input_len ? (unsigned char) input[i++] : 0;
        uint32_t octet_b = i < input_len ? (unsigned char) input[i++] : 0;
        uint32_t octet_c = i < input_len ? (unsigned char) input[i++] : 0;

        uint32_t triple = (octet_a << 16) | (octet_b << 8) | octet_c;

        output[j++] = b64chars[(triple >> 18) & 0x3F];
        output[j++] = b64chars[(triple >> 12) & 0x3F];
        output[j++] = b64chars[(triple >> 6) & 0x3F];
        output[j++] = b64chars[triple & 0x3F];
    }

    for (i = 0; i < mod_table[input_len % 3]; i++) {
        output[output_len - 1 - i] = b64pad;
    }
    output[output_len] = '\0';
    return 0;
}

static int b64_decode_value(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

int base64_decode(const char *input, char *output, size_t out_size) {
    size_t input_len = strlen(input);
    if (input_len % 4 != 0)
        return -1;
    size_t output_len = input_len / 4 * 3;
    if (input[input_len - 1] == b64pad) output_len--;
    if (input[input_len - 2] == b64pad) output_len--;

    if (output_len + 1 > out_size)
        return -1;

    size_t i, j;
    for (i = 0, j = 0; i < input_len;) {
        int sextet_a = input[i] == b64pad ? 0 : b64_decode_value(input[i]);
        i++;
        int sextet_b = input[i] == b64pad ? 0 : b64_decode_value(input[i]);
        i++;
        int sextet_c = input[i] == b64pad ? 0 : b64_decode_value(input[i]);
        i++;
        int sextet_d = input[i] == b64pad ? 0 : b64_decode_value(input[i]);
        i++;

        uint32_t triple = (sextet_a << 18) | (sextet_b << 12) | (sextet_c << 6) | sextet_d;

        if (j < output_len) output[j++] = (triple >> 16) & 0xFF;
        if (j < output_len) output[j++] = (triple >> 8) & 0xFF;
        if (j < output_len) output[j++] = triple & 0xFF;
    }
    output[output_len] = '\0';
    return 0;
}

