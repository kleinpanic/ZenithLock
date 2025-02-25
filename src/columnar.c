#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "columnar.h"

int columnar_crypt(const char *input, const char *key, int shift, mode_t mode, int otp, char *output) {
    (void) key;
    (void) otp;
    if (shift < 2) {
        fprintf(stderr, "Columnar cipher requires at least 2 columns (use -s accordingly).\n");
        return -1;
    }
    size_t len = strlen(input);
    int cols = shift;
    int rows = (len + cols - 1) / cols;
    char *matrix = calloc(rows * cols, sizeof(char));
    if (!matrix) return -1;
    // Fill matrix with input and pad with spaces if needed.
    for (size_t i = 0; i < rows * cols; i++) {
        matrix[i] = (i < len) ? input[i] : ' ';
    }
    if (mode == MODE_ENCRYPT) {
        size_t pos = 0;
        for (int c = 0; c < cols; c++) {
            for (int r = 0; r < rows; r++) {
                output[pos++] = matrix[r * cols + c];
            }
        }
        output[pos] = '\0';
    } else { // MODE_DECRYPT
        // For decryption, determine number of full columns.
        int full_cols = len % cols;
        if (full_cols == 0) full_cols = cols;
        char *temp = calloc(rows * cols, sizeof(char));
        if (!temp) { free(matrix); return -1; }
        size_t pos = 0;
        // Fill temp by reading column-wise from input.
        for (int c = 0; c < cols; c++) {
            for (int r = 0; r < rows; r++) {
                if ((c < full_cols) || (r < rows - 1)) {
                    if (pos < len)
                        temp[r * cols + c] = input[pos++];
                }
            }
        }
        strncpy(output, temp, len);
        output[len] = '\0';
        free(temp);
    }
    free(matrix);
    return 0;
}

