#include "keygen.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

/* For cryptographic randomness, try /dev/urandom */
static void get_random_bytes(uint8_t *buf, size_t len) {
    FILE *f = fopen("/dev/urandom", "rb");
    if (f) {
        fread(buf, 1, len, f);
        fclose(f);
    } else {
        for (size_t i = 0; i < len; i++) {
            buf[i] = rand() & 0xFF;
        }
    }
}

/*
   generate_key() returns a newly allocated key string for the given algorithm.
   For symmetric block ciphers (AES, IDEA, Blowfish, Twofish, Serpent, etc.), 
   it now returns a 16-character key by selecting random characters from a 
   predefined charset. For ChaCha20, it returns a key in the format "32char,12char".
   For classical ciphers, it may return an 8-character key (or, for Caesar, a numeric string).
   The caller must free() the returned string.
*/
char* generate_key(const char *alg_name, size_t msg_len) {
    size_t key_bytes = 0;
    /* Determine key length based on algorithm name. */
    if (strcmp(alg_name, "aes") == 0 ||
        strcmp(alg_name, "idea") == 0 ||
        strcmp(alg_name, "blowfish") == 0 ||
        strcmp(alg_name, "twofish") == 0 ||
        strcmp(alg_name, "serpent") == 0) {
        key_bytes = 16;  // We now generate a 16-character key
    } else if (strcmp(alg_name, "chacha20") == 0) {
        size_t key_part = 32;
        size_t nonce_part = 12;
        char *key_str = malloc(key_part + 1 + nonce_part + 1);
        if (!key_str) return NULL;
        const char charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        for (size_t i = 0; i < key_part; i++) {
            key_str[i] = charset[rand() % (sizeof(charset) - 1)];
        }
        key_str[key_part] = ',';
        for (size_t i = 0; i < nonce_part; i++) {
            key_str[key_part + 1 + i] = charset[rand() % (sizeof(charset) - 1)];
        }
        key_str[key_part + 1 + nonce_part] = '\0';
        return key_str;
    } else if (strcmp(alg_name, "rc4") == 0 ||
               strcmp(alg_name, "xor") == 0) {
        key_bytes = 16;  // default 16-character key
    } else if (strcmp(alg_name, "vigenere") == 0 ||
               strcmp(alg_name, "atbash") == 0 ||
               strcmp(alg_name, "rot13") == 0) {
        /* For classical ciphers, choose a human‐readable key.
           For Caesar, we generate a random shift between 1 and 25.
           For Vigenere, generate an 8-character key.
        */
        if (strcmp(alg_name, "caesar") == 0) {
            char *key_str = malloc(4);
            if (!key_str) return NULL;
            int shift_val = (rand() % 25) + 1;
            sprintf(key_str, "%d", shift_val);
            return key_str;
        } else {
            key_bytes = 8;
        }
    } else {
        // Default to 16 characters if algorithm not explicitly mapped.
        key_bytes = 16;
    }

    /* For symmetric ciphers, generate a printable key by selecting characters from a charset */
    char charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    char *key_str = malloc(key_bytes + 1);
    if (!key_str) return NULL;
    srand((unsigned)time(NULL));
    for (size_t i = 0; i < key_bytes; i++) {
        key_str[i] = charset[rand() % (sizeof(charset) - 1)];
    }
    key_str[key_bytes] = '\0';
    return key_str;
}

