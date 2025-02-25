#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "scytale.h"

int scytale_crypt(const char *input, const char *key, int shift, mode_t mode, int otp, char *output) {
    (void) key;
    (void) otp;
    if (shift < 2) {
        fprintf(stderr, "Scytale cipher requires at least 2 rows (use -s accordingly).\n");
        return -1;
    }
    size_t len = strlen(input);
    int rows = shift;
    int cols = (len + rows - 1) / rows;
    char *matrix = calloc(rows * cols, sizeof(char));
    if (!matrix) return -1;
    if (mode == MODE_ENCRYPT) {
        // Fill matrix column-wise.
        size_t pos = 0;
        for (int c = 0; c < cols; c++) {
            for (int r = 0; r < rows; r++) {
                if (pos < len)
                    matrix[r * cols + c] = input[pos++];
                else
                    matrix[r * cols + c] = ' ';
            }
        }
        // Read row-wise.
        pos = 0;
        for (int r = 0; r < rows; r++) {
            for (int c = 0; c < cols; c++) {
                output[pos++] = matrix[r * cols + c];
            }
        }
        output[pos] = '\0';
    } else { // MODE_DECRYPT
        // Fill matrix row-wise.
        strncpy(matrix, input, len);
        // Read column-wise.
        size_t pos = 0;
        for (int c = 0; c < cols; c++) {
            for (int r = 0; r < rows; r++) {
                output[pos++] = matrix[r * cols + c];
            }
        }
        output[pos] = '\0';
    }
    free(matrix);
    return 0;
}

