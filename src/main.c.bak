#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "algorithm.h"
#include "xor.h"
#include "caesar.h"
#include "vigenere.h"
#include "beaufort.h"
#include "rc4.h"
#include "atbash.h"
#include "rot13.h"
#include "affine.h"
#include "railfence.h"
#include "playfair.h"
#include "columnar.h"
#include "scytale.h"
#include "rsa.h"
#include "xtea.h"
#include "aes.h"
#include "des.h"
#include "chacha20.h"
#include "idea.h"
#include "serpent.h"
#include "blowfish.h"
#include "twofish.h"
#include "sha256hash.h"    // New: SHA-256 hash function
#include "hmac_sha256.h"   // New: HMAC-SHA256
#include "keygen.h"        // New: Key generation module
#include "encoding.h"
#include "cast5.h"
#include "rc6.h"
#include "salsa20.h"

#define MAX_BUFFER_SIZE 8192

typedef struct {
    const char *name;
    crypt_func crypt;
    const char *description;
} algorithm_entry_t;

/* Generic placeholder for algorithms not implemented */
static int not_implemented_crypt(const char *input, const char *key, int shift, mode_t mode, int otp, char *output) {
    (void)input; (void)key; (void)shift; (void)mode; (void)otp; (void)output;
    fprintf(stderr, "Error: This algorithm is not implemented yet.\n");
    return -1;
}

/* Updated algorithms array with new modules */
algorithm_entry_t algorithms[] = {
    {"xor", xor_crypt, "XOR cipher (requires -k key; use -p for OTP mode)"},
    {"caesar", caesar_crypt, "Caesar cipher (requires -s shift)"},
    {"vigenere", vigenere_crypt, "Vigenère cipher (requires -k key; use -p for OTP mode)"},
    {"beaufort", beaufort_crypt, "Beaufort cipher (requires -k key; use -p for OTP mode)"},
    {"rc4", rc4_crypt, "RC4 stream cipher (requires -k key)"},
    {"atbash", atbash_crypt, "Atbash cipher (no key required)"},
    {"rot13", rot13_crypt, "ROT13 cipher (no key required)"},
    {"affine", affine_crypt, "Affine cipher (requires -k key in format a,b)"},
    {"railfence", railfence_crypt, "Rail Fence cipher (requires -s rails, rails>=2)"},
    {"playfair", playfair_crypt, "Playfair cipher (requires -k key)"},
    {"columnar", columnar_crypt, "Columnar Transposition cipher (requires -s columns)"},
    {"scytale", scytale_crypt, "Scytale cipher (requires -s rows)"},
    {"rsa", rsa_crypt, "RSA encryption/decryption (requires -k key in format x,y)"},
    {"xtea", xtea_crypt, "XTEA block cipher (requires 16-character key)"},
    {"aes", aes_crypt, "AES-128 ECB mode (requires 16-character key)"},
    {"des", des_crypt, "DES-ECB mode (requires 8-character key)"},
    {"chacha20", chacha20_crypt, "ChaCha20 stream cipher (requires key in format \"32char,12char\")"},
    {"idea", idea_crypt, "IDEA block cipher (64-bit block, 16-char key)"},
    {"serpent", serpent_crypt, "Serpent block cipher (128-bit block, 16/24/32-char key)"},
    {"blowfish", blowfish_crypt, "Blowfish cipher (full implementation, variable key length)"},
    {"twofish", twofish_crypt, "Twofish cipher (full implementation skeleton)"},
    {"hmac_sha256", hmac_sha256_crypt, "HMAC-SHA256 (computes HMAC; use -k for key)"},
    {"sha256", sha256hash_crypt, "SHA-256 hash (one-way; no key required)"},
    {"rc6", rc6_crypt, "RC6 block cipher (requires 16-character key or 32-character hex key)"},
    {"salsa20", salsa20_crypt, "Salsa20 stream cipher (requires key in format \"64char,16char\")"},
    {"cast5", cast5_crypt, "CAST5 cipher (requires 16-character key)"}

};

#define NUM_ALGORITHMS (sizeof(algorithms) / sizeof(algorithms[0]))

void usage(const char *prog_name) {
    fprintf(stderr, "Usage: %s -a algorithm -i input -o output [-k key] [-s shift] [-d] [-p] [-e encoding] [-G]\n", prog_name);
    fprintf(stderr, "  -a algorithm : Choose algorithm (");
    for (size_t i = 0; i < NUM_ALGORITHMS; i++) {
        fprintf(stderr, "%s%s", algorithms[i].name, i < NUM_ALGORITHMS - 1 ? ", " : "");
    }
    fprintf(stderr, ")\n");
    fprintf(stderr, "  -i input     : Input text (plaintext for encryption, encoded ciphertext for decryption if -e is used)\n");
    fprintf(stderr, "  -o output    : Output file (or key file when using -G)\n");
    fprintf(stderr, "  -k key       : Key (if required)\n");
    fprintf(stderr, "  -s shift     : Shift value or rail/column count (if required)\n");
    fprintf(stderr, "  -d           : Decryption mode (default is encryption)\n");
    fprintf(stderr, "  -p           : One-Time Pad (OTP) mode (key must equal input length)\n");
    fprintf(stderr, "  -e encoding  : Encoding type (e.g., base64)\n");
    fprintf(stderr, "  -G           : Key Generation mode (generate a key for the chosen algorithm)\n");
}

int main(int argc, char *argv[]) {
    char *algorithm_name = NULL;
    char *input = NULL;
    char *output_filename = NULL;
    char *key = "";
    int shift = 0;
    mode_t mode = MODE_ENCRYPT;
    int otp = 0;
    char *encoding = NULL;
    int gen_key_mode = 0;   /* Declare the key generation flag */
    int opt;

    while ((opt = getopt(argc, argv, "a:i:o:k:s:dp:e:G")) != -1) {
        switch(opt) {
            case 'a': algorithm_name = optarg; break;
            case 'i': input = optarg; break;
            case 'o': output_filename = optarg; break;
            case 'k': key = optarg; break;
            case 's': shift = atoi(optarg); break;
            case 'd': mode = MODE_DECRYPT; break;
            case 'p': otp = 1; break;
            case 'e': encoding = optarg; break;
            case 'G': gen_key_mode = 1; break;
            default:
                usage(argv[0]);
                return EXIT_FAILURE;
        }
    }

    if (!algorithm_name) {
        usage(argv[0]);
        return EXIT_FAILURE;
    }

    /* Locate the chosen algorithm */
    crypt_func chosen_crypt = NULL;
    for (size_t i = 0; i < NUM_ALGORITHMS; i++) {
        if (strcmp(algorithm_name, algorithms[i].name) == 0) {
            chosen_crypt = algorithms[i].crypt;
            break;
        }
    }
    if (!chosen_crypt) {
        fprintf(stderr, "Algorithm '%s' not found.\n", algorithm_name);
        usage(argv[0]);
        return EXIT_FAILURE;
    }

    /* Key Generation mode: if -G is specified, generate a key */
    if (gen_key_mode) {
        char *gen_key = generate_key(algorithm_name, (input ? strlen(input) : 0));
        if (!gen_key) {
            fprintf(stderr, "Key generation failed.\n");
            return EXIT_FAILURE;
        }
        if (output_filename) {
            FILE *kf = fopen(output_filename, "w");
            if (!kf) {
                perror("fopen");
                free(gen_key);
                return EXIT_FAILURE;
            }
            fprintf(kf, "%s", gen_key);
            fclose(kf);
            printf("Generated key saved to %s\n", output_filename);
        } else {
            printf("Generated key: %s\n", gen_key);
        }
        free(gen_key);
        return EXIT_SUCCESS;
    }

    if (!input || !output_filename) {
        usage(argv[0]);
        return EXIT_FAILURE;
    }

    /* Process input and perform encryption/decryption */
    char raw_input[MAX_BUFFER_SIZE];
    memset(raw_input, 0, sizeof(raw_input));
    if (mode == MODE_DECRYPT && encoding) {
        if (strcmp(encoding, "base64") == 0) {
            if (base64_decode(input, raw_input, sizeof(raw_input)) != 0) {
                fprintf(stderr, "Base64 decoding failed.\n");
                return EXIT_FAILURE;
            }
        } else {
            fprintf(stderr, "Encoding '%s' not supported for decryption.\n", encoding);
            return EXIT_FAILURE;
        }
    } else {
        strncpy(raw_input, input, sizeof(raw_input)-1);
    }

    char crypt_output[MAX_BUFFER_SIZE];
    memset(crypt_output, 0, sizeof(crypt_output));
    if (chosen_crypt(raw_input, key, shift, mode, otp, crypt_output) != 0) {
        fprintf(stderr, "Operation failed for algorithm '%s'.\n", algorithm_name);
        return EXIT_FAILURE;
    }

    char final_output[MAX_BUFFER_SIZE];
    memset(final_output, 0, sizeof(final_output));
    if (mode == MODE_ENCRYPT && encoding) {
        if (strcmp(encoding, "base64") == 0) {
            if (base64_encode(crypt_output, final_output, sizeof(final_output)) != 0) {
                fprintf(stderr, "Base64 encoding failed.\n");
                return EXIT_FAILURE;
            }
        } else {
            fprintf(stderr, "Encoding '%s' not supported for encryption.\n", encoding);
            return EXIT_FAILURE;
        }
    } else {
        strncpy(final_output, crypt_output, sizeof(final_output)-1);
    }

    FILE *fp = fopen(output_filename, "w");
    if (!fp) {
        perror("fopen");
        return EXIT_FAILURE;
    }
    fprintf(fp, "%s", final_output);
    fclose(fp);

    printf("Operation successful. Output written to %s\n", output_filename);
    return EXIT_SUCCESS;
}

