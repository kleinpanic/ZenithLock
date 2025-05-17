// tests/blowfish_test.c

#include <stdio.h>
#include <string.h>
#include "blowfish.h"
#include "algorithm.h"   // for MODE_ENCRYPT / MODE_DECRYPT

int main(void) {
    const char *key = "mySecretKey";
    const char *tests[] = {
        "Hello, Blowfish!",
        "12345678",           // exactly 8 bytes
        "A bit longer test",  // needs PKCS#7 padding
        ""
    };

    char cipher[1024];
    char plain[1024];

    for (int i = 0; tests[i][0] || i == 3; i++) {
        const char *pt = tests[i];
        int r;

        // encrypt into hex string
        r = blowfish_crypt(pt, key, 0, MODE_ENCRYPT, 0, cipher);
        if (r) {
            fprintf(stderr, "✗ Encryption failed on \"%s\"\n", pt);
            return 1;
        }

        // decrypt back into plaintext
        r = blowfish_crypt(cipher, key, 0, MODE_DECRYPT, 0, plain);
        if (r) {
            fprintf(stderr, "✗ Decryption failed on \"%s\"\n", cipher);
            return 1;
        }

        // compare
        if (strcmp(pt, plain) != 0) {
            fprintf(stderr,
                "✗ MISMATCH:\n"
                "    original: \"%s\"\n"
                "    decrypted:\"%s\"\n",
                pt, plain);
            return 1;
        }

        printf("✔ Test %d passed: \"%s\" → \"%s\" → \"%s\"\n",
               i+1, pt, cipher, plain);
    }

    printf("All Blowfish encrypt/decrypt self-tests passed ✅\n");
    return 0;
}

