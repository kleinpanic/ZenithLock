#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "railfence.h"

int railfence_crypt(const char *input, const char *key, int shift, mode_t mode, int otp, char *output) {
    (void) key;
    (void) otp;
    int rails = shift;
    if (rails < 2) {
        fprintf(stderr, "Rail Fence cipher requires a rail count >= 2\n");
        return -1;
    }
    
    size_t len = strlen(input);
    if (len == 0) {
        output[0] = '\0';
        return 0;
    }
    
    /* Create an array to store the rail index for each character in the zigzag pattern */
    int *pattern = (int *)malloc(len * sizeof(int));
    if (!pattern) return -1;
    int rail = 0, direction = 1;
    for (size_t i = 0; i < len; i++) {
        pattern[i] = rail;
        rail += direction;
        if (rail == rails) {
            rail = rails - 2;
            direction = -1;
        } else if (rail < 0) {
            rail = 1;
            direction = 1;
        }
    }
    
    if (mode == MODE_ENCRYPT) {
        /* Encryption: Read characters row-by-row based on the pattern */
        size_t pos = 0;
        for (int r = 0; r < rails; r++) {
            for (size_t i = 0; i < len; i++) {
                if (pattern[i] == r) {
                    output[pos++] = input[i];
                }
            }
        }
        output[pos] = '\0';
    } else { // MODE_DECRYPT
        /* Decryption: Reverse the process.
           1. Count how many characters are in each rail.
           2. Determine the starting index for each rail in the ciphertext.
           3. Reconstruct plaintext by iterating over the pattern. */
        int *rail_count = (int *)calloc(rails, sizeof(int));
        if (!rail_count) { free(pattern); return -1; }
        for (size_t i = 0; i < len; i++) {
            rail_count[ pattern[i] ]++;
        }
        
        int *rail_index = (int *)malloc(rails * sizeof(int));
        if (!rail_index) { free(pattern); free(rail_count); return -1; }
        rail_index[0] = 0;
        for (int r = 1; r < rails; r++) {
            rail_index[r] = rail_index[r - 1] + rail_count[r - 1];
        }
        
        char *decrypted = (char *)malloc(len + 1);
        if (!decrypted) { free(pattern); free(rail_count); free(rail_index); return -1; }
        for (size_t i = 0; i < len; i++) {
            int r = pattern[i];
            decrypted[i] = input[ rail_index[r] ];
            rail_index[r]++;
        }
        decrypted[len] = '\0';
        strcpy(output, decrypted);
        free(decrypted);
        free(rail_count);
        free(rail_index);
    }
    
    free(pattern);
    return 0;
}

