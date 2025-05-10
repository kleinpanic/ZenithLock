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
#include "sha256hash.h"
#include "hmac_sha256.h"
#include "keygen.h"
#include "encoding.h"
#include "cast5.h"
#include "rc6.h"
#include "salsa20.h"

#define MAX_BUFFER_SIZE 8192

typedef struct {
    const char *name;
    crypt_func    crypt;
    const char   *description;
} algorithm_entry_t;

/* Placeholder for algorithms not yet implemented */
static int not_implemented_crypt(const char *input, const char *key,
                                 int shift, mode_t mode,
                                 int otp, char *output)
{
    (void)input; (void)key; (void)shift;
    (void)mode;  (void)otp; (void)output;
    fprintf(stderr, "Error: This algorithm is not implemented yet.\n");
    return -1;
}

/* Algorithm registration */
static algorithm_entry_t algorithms[] = {
    {"xor",        xor_crypt,         "XOR cipher (use -p for OTP mode)"},
    {"caesar",     caesar_crypt,      "Caesar cipher (-s shift)"},
    {"vigenere",   vigenere_crypt,    "Vigenère cipher (use -p for OTP mode)"},
    {"beaufort",   beaufort_crypt,    "Beaufort cipher (use -p for OTP mode)"},
    {"rc4",        rc4_crypt,         "RC4 stream cipher"},
    {"atbash",     atbash_crypt,      "Atbash cipher"},
    {"rot13",      rot13_crypt,       "ROT13 cipher"},
    {"affine",     affine_crypt,      "Affine cipher (-k \"a,b\")"},
    {"railfence",  railfence_crypt,   "Rail Fence cipher (-s rails)"},
    {"playfair",   playfair_crypt,    "Playfair cipher"},
    {"columnar",   columnar_crypt,    "Columnar Transposition (-s cols)"},
    {"scytale",    scytale_crypt,     "Scytale cipher (-s rows)"},
    {"rsa",        rsa_crypt,         "RSA (requires key file)"},
    {"xtea",       xtea_crypt,        "XTEA (16-byte key)"},
    {"aes",        aes_crypt,         "AES-128 ECB (16-byte key)"},
    {"des",        des_crypt,         "DES-ECB (8-byte key)"},
    {"chacha20",   chacha20_crypt,    "ChaCha20 (32-byte key,12-byte nonce)"},
    {"idea",       idea_crypt,        "IDEA (16-byte key)"},
    {"serpent",    serpent_crypt,     "Serpent (16/24/32-byte key)"},
    {"blowfish",   blowfish_crypt,    "Blowfish (4–56-byte key)"},
    {"twofish",    twofish_crypt,     "Twofish (skeleton)"},
    {"hmac_sha256",hmac_sha256_crypt, "HMAC-SHA256"},
    {"sha256",     sha256hash_crypt,  "SHA-256 hash"},
    {"rc6",        rc6_crypt,         "RC6 (16 or 32-byte key)"},
    {"salsa20",    salsa20_crypt,     "Salsa20 (32-byte key, 8-byte nonce)"},
    {"cast5",      cast5_crypt,       "CAST5 (8 or 16-byte key)"}
};
#define NUM_ALGORITHMS (sizeof(algorithms)/sizeof(algorithms[0]))

void usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s -a algorithm -i input_string -o output_file\n"
        "       %s -a algorithm -G [-i input_for_length] [-o keyfile]\n"
        "  -a algorithm : one of ",
        prog, prog);
    for (size_t i = 0; i < NUM_ALGORITHMS; i++) {
        fprintf(stderr, "%s%s",
                algorithms[i].name,
                (i+1<NUM_ALGORITHMS)?", ":"\n");
    }
    fprintf(stderr,
        "  -i input     : input text (plaintext or base64 for -d -e base64)\n"
        "  -o output    : output file (or key file for -G)\n"
        "  -k key       : key string (if required)\n"
        "  -s shift     : shift/rails/columns (for caesar, railfence...)\n"
        "  -d           : decryption mode (default: encrypt)\n"
        "  -p           : OTP mode (key length must equal input length)\n"
        "  -e encoding  : base64 encoding/decoding\n"
        "  -G           : generate key for algorithm\n");
}

int main(int argc, char *argv[]) {
    char *alg_name = NULL;
    char *inp      = NULL;
    char *outfile  = NULL;
    char *key      = NULL;
    char *encoding = NULL;
    int   shift    = 0;
    int   mode     = MODE_ENCRYPT;
    int   otp      = 0;
    int   gen_key  = 0;
    int   opt;

    /* Fix: p is now a flag, not expecting an argument */
    while ((opt = getopt(argc, argv, "a:i:o:k:s:dpe:G")) != -1) {
        switch (opt) {
            case 'a': alg_name = optarg; break;
            case 'i': inp      = optarg; break;
            case 'o': outfile  = optarg; break;
            case 'k': key      = optarg; break;
            case 's': shift    = atoi(optarg); break;
            case 'd': mode     = MODE_DECRYPT; break;
            case 'p': otp      = 1;           break;
            case 'e': encoding = optarg;      break;
            case 'G': gen_key  = 1;           break;
            default:
                usage(argv[0]);
                return EXIT_FAILURE;
        }
    }

    if (!alg_name) {
        fprintf(stderr, "Error: Algorithm must be specified with -a\n");
        usage(argv[0]);
        return EXIT_FAILURE;
    }

    /* Find the algorithm */
    crypt_func runner = NULL;
    for (size_t i = 0; i < NUM_ALGORITHMS; i++) {
        if (strcmp(alg_name, algorithms[i].name) == 0) {
            runner = algorithms[i].crypt;
            break;
        }
    }
    if (!runner) {
        fprintf(stderr, "Error: Unknown algorithm '%s'\n", alg_name);
        usage(argv[0]);
        return EXIT_FAILURE;
    }

    /* Key‐generation mode */
    if (gen_key) {
        /* Allow optional -i to control OTP length; else algorithms pick defaults */
        size_t inlen = inp ? strlen(inp) : 0;
        char *newkey = generate_key(alg_name, inlen);
        if (!newkey) {
            fprintf(stderr, "Error: Key generation failed\n");
            return EXIT_FAILURE;
        }
        if (outfile) {
            FILE *kf = fopen(outfile, "w");
            if (!kf) { perror("fopen"); free(newkey); return EXIT_FAILURE; }
            fprintf(kf, "%s", newkey);
            fclose(kf);
            printf("Key saved to %s\n", outfile);
        } else {
            printf("%s\n", newkey);
        }
        free(newkey);
        return EXIT_SUCCESS;
    }

    /* Encryption/decryption mode requires input + output */
    if (!inp || !outfile) {
        fprintf(stderr, "Error: -i and -o are required unless using -G\n");
        usage(argv[0]);
        return EXIT_FAILURE;
    }

    size_t inlen = strlen(inp);
    if (inlen + 1 > MAX_BUFFER_SIZE) {
        fprintf(stderr, "Error: input length %zu exceeds %d bytes\n",
                inlen, MAX_BUFFER_SIZE - 1);
        return EXIT_FAILURE;
    }
    if (otp && (!key || (size_t)strlen(key) != inlen)) {
        fprintf(stderr, "Error: OTP mode requires key length == input length (%zu)\n",
                inlen);
        return EXIT_FAILURE;
    }

    /* Warn on insecure ECB mode */
    if (strcmp(alg_name, "aes") == 0 || strcmp(alg_name, "des") == 0) {
        fprintf(stderr,
            "Warning: %s uses ECB mode, which is insecure for large or structured data.\n",
            alg_name);
    }

    /* Block‐size alignment checks */
    int block_size = 0;
    if (strcmp(alg_name, "aes") == 0 || strcmp(alg_name, "rc6") == 0) {
        block_size = 16;
    } else if (strcmp(alg_name, "des") == 0
            || strcmp(alg_name, "xtea") == 0
            || strcmp(alg_name, "idea") == 0
            || strcmp(alg_name, "cast5") == 0) {
        block_size = 8;
    }
    if (block_size && (inlen % block_size) != 0) {
        fprintf(stderr,
            "Error: input length %zu not a multiple of %d (required by %s)\n",
            inlen, block_size, alg_name);
        return EXIT_FAILURE;
    }

    /* Prepare raw input buffer */
    char raw[MAX_BUFFER_SIZE] = {0};
    if (mode == MODE_DECRYPT && encoding) {
        if (strcmp(encoding, "base64") == 0) {
            if (base64_decode(inp, raw, sizeof(raw)) != 0) {
                fprintf(stderr, "Error: Base64 decode failed\n");
                return EXIT_FAILURE;
            }
        } else {
            fprintf(stderr, "Error: Unsupported encoding '%s'\n", encoding);
            return EXIT_FAILURE;
        }
    } else {
        memcpy(raw, inp, inlen);
    }

    /* Run the cipher */
    char crypted[MAX_BUFFER_SIZE] = {0};
    if (runner(raw, key ? key : "", shift, mode, otp, crypted) != 0) {
        fprintf(stderr, "Error: %s operation failed\n", alg_name);
        return EXIT_FAILURE;
    }

    /* Handle post‐processing (base64 on encrypt) */
    char final[MAX_BUFFER_SIZE] = {0};
    if (mode == MODE_ENCRYPT && encoding) {
        if (strcmp(encoding, "base64") == 0) {
            if (base64_encode(crypted, final, sizeof(final)) != 0) {
                fprintf(stderr, "Error: Base64 encode failed\n");
                return EXIT_FAILURE;
            }
        } else {
            fprintf(stderr, "Error: Unsupported encoding '%s'\n", encoding);
            return EXIT_FAILURE;
        }
    } else {
        strcpy(final, crypted);
    }

    /* Write out */
    FILE *outf = fopen(outfile, "w");
    if (!outf) {
        perror("fopen");
        return EXIT_FAILURE;
    }
    fprintf(outf, "%s", final);
    fclose(outf);

    printf("Success: output written to %s\n", outfile);
    return EXIT_SUCCESS;
}

