#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "playfair.h"

#define MATRIX_SIZE 5

/* Helper: Build the 5x5 table from the key (combine I and J) */
static void build_table(const char *key, char table[MATRIX_SIZE][MATRIX_SIZE]) {
    int used[26] = {0};
    used['J' - 'A'] = 1; // treat I/J as same
    char temp[26];
    int idx = 0;
    // Process key: uppercase letters, skip non-alpha, and avoid duplicates.
    for (size_t i = 0; key[i] && idx < 25; i++) {
        char c = toupper((unsigned char) key[i]);
        if (!isalpha(c))
            continue;
        if (c == 'J')
            c = 'I';
        if (!used[c - 'A']) {
            used[c - 'A'] = 1;
            temp[idx++] = c;
        }
    }
    // Fill remaining letters
    for (char c = 'A'; c <= 'Z' && idx < 25; c++) {
        if (c == 'J') continue;
        if (!used[c - 'A']) {
            used[c - 'A'] = 1;
            temp[idx++] = c;
        }
    }
    // Copy into 5x5 matrix
    idx = 0;
    for (int r = 0; r < MATRIX_SIZE; r++) {
        for (int c = 0; c < MATRIX_SIZE; c++) {
            table[r][c] = temp[idx++];
        }
    }
}

/* Helper: Find letter position in table */
static void find_position(char table[MATRIX_SIZE][MATRIX_SIZE], char letter, int *row, int *col) {
    if (letter == 'J') letter = 'I';
    for (int r = 0; r < MATRIX_SIZE; r++) {
        for (int c = 0; c < MATRIX_SIZE; c++) {
            if (table[r][c] == letter) {
                *row = r;
                *col = c;
                return;
            }
        }
    }
}

/* Prepare plaintext: uppercase, remove non-letters, replace J with I */
static char *prepare_text(const char *input) {
    size_t len = strlen(input);
    char *clean = malloc(len + 1);
    if (!clean) return NULL;
    size_t j = 0;
    for (size_t i = 0; i < len; i++) {
        if (isalpha((unsigned char) input[i])) {
            char c = toupper((unsigned char) input[i]);
            if (c == 'J') c = 'I';
            clean[j++] = c;
        }
    }
    clean[j] = '\0';
    return clean;
}

/* Process digraphs and apply Playfair rules */
int playfair_crypt(const char *input, const char *key, int shift, mode_t mode, int otp, char *output) {
    (void) shift;
    (void) otp;
    char table[MATRIX_SIZE][MATRIX_SIZE];
    build_table(key, table);

    char *clean = prepare_text(input);
    if (!clean) return -1;
    size_t len = strlen(clean);

    /* Insert filler 'X' between duplicate letters and pad if needed */
    char *processed = malloc(len * 2 + 1);
    if (!processed) { free(clean); return -1; }
    size_t p = 0;
    for (size_t i = 0; i < len; i++) {
        processed[p++] = clean[i];
        if (i + 1 < len && clean[i] == clean[i + 1]) {
            processed[p++] = 'X';
        }
    }
    if (p % 2 != 0) {
        processed[p++] = 'X';
    }
    processed[p] = '\0';
    free(clean);

    /* Process digraphs */
    for (size_t i = 0; i < p; i += 2) {
        char a = processed[i], b = processed[i + 1];
        int r1, c1, r2, c2;
        find_position(table, a, &r1, &c1);
        find_position(table, b, &r2, &c2);
        if (r1 == r2) {
            /* Same row: shift right for encryption, left for decryption */
            if (mode == MODE_ENCRYPT) {
                output[i] = table[r1][(c1 + 1) % MATRIX_SIZE];
                output[i + 1] = table[r2][(c2 + 1) % MATRIX_SIZE];
            } else {
                output[i] = table[r1][(c1 + MATRIX_SIZE - 1) % MATRIX_SIZE];
                output[i + 1] = table[r2][(c2 + MATRIX_SIZE - 1) % MATRIX_SIZE];
            }
        } else if (c1 == c2) {
            /* Same column: shift down for encryption, up for decryption */
            if (mode == MODE_ENCRYPT) {
                output[i] = table[(r1 + 1) % MATRIX_SIZE][c1];
                output[i + 1] = table[(r2 + 1) % MATRIX_SIZE][c2];
            } else {
                output[i] = table[(r1 + MATRIX_SIZE - 1) % MATRIX_SIZE][c1];
                output[i + 1] = table[(r2 + MATRIX_SIZE - 1) % MATRIX_SIZE][c2];
            }
        } else {
            /* Rectangle: swap columns */
            output[i] = table[r1][c2];
            output[i + 1] = table[r2][c1];
        }
    }
    output[p] = '\0';
    free(processed);
    return 0;
}

