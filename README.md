# ZenithLock

**ZenithLock** is an advanced, modular cryptographic toolkit written entirely in C. Designed to be a one-stop command‑line solution for a wide array of cryptographic algorithms—from classical ciphers (such as XOR, Caesar, Vigenère, etc.) to modern symmetric algorithms (AES, DES, IDEA, RC6, ChaCha20, Salsa20, CAST5) and even hash/HMAC functions (SHA‑256, HMAC‑SHA256)—this project is intended as both a research/development platform and a learning resource for cryptographic programming in C.

> **Disclaimer:**  
> Although every effort has been made to implement each algorithm according to its published specification and with attention to constant‑time techniques and security best practices, producing production‑grade cryptography requires rigorous testing, formal verification, and external audits. This project is provided as an educational tool and reference framework.

---

## Table of Contents

1. [Project Overview](#project-overview)
2. [Architecture and Design](#architecture-and-design)
3. [Supported Algorithms](#supported-algorithms)
   - [Classical Ciphers](#classical-ciphers)
   - [Modern Symmetric Block & Stream Ciphers](#modern-symmetric-block--stream-ciphers)
   - [Hash Functions and HMAC](#hash-functions-and-hmac)
   - [Algorithms Planned for Future Implementation](#algorithms-planned-for-future-implementation)
4. [Key Generation and Key Management](#key-generation-and-key-management)
5. [Usage and Examples](#usage-and-examples)
   - [Encryption and Decryption](#encryption-and-decryption)
   - [Key Generation Mode](#key-generation-mode)
6. [Dependencies and Build Instructions](#dependencies-and-build-instructions)
7. [Future Work and Roadmap](#future-work-and-roadmap)
8. [Contributing and Licensing](#contributing-and-licensing)

---

## Project Overview

*ZenithLock* is a command‑line tool that allows the user to encrypt, decrypt, and generate keys for a variety of cryptographic algorithms. The tool is modular in design—each algorithm is implemented in its own module, with a common interface to ease integration. The goal is to eventually support nearly every algorithm listed in the [Wikipedia Cryptographic Algorithms category](https://en.wikipedia.org/wiki/Category:Cryptographic_algorithms).

---

## Architecture and Design

The project is organized into three main directories:

- **include/** – Contains all header files for each cryptographic algorithm and common modules (e.g., key generation, encoding).
- **src/** – Contains the source (.c) files, one per algorithm or module.
- **obj/** – Compiled object files (created during build).

The core design principle is to use a common function signature for each algorithm:

```c
int algo_crypt(const char *input, const char *key, int shift, mode_t mode, int otp, char *output);
```

This allows the main CLI driver to select the algorithm based on a command‑line flag and then pass along any parameters (such as key, shift value, OTP mode, and encoding) in a consistent manner.
Supported Algorithms
Classical Ciphers

    XOR Cipher:
    A simple stream cipher that XORs each byte of the input with a repeating key. Supports OTP (One-Time Pad) mode if the key length exactly matches the input length.

    Caesar Cipher:
    A substitution cipher that shifts letters by a specified number. The shift is provided using the -s flag.

    Vigenère Cipher:
    A polyalphabetic cipher that uses a key (provided with -k) to shift letters based on the key’s characters.

    Beaufort Cipher:
    Similar to Vigenère but with a different mathematical formulation. Requires a key.

    Atbash Cipher:
    A simple substitution cipher that reverses the alphabet. Does not require a key.

    ROT13:
    A special case of the Caesar cipher with a fixed shift of 13.

    Affine Cipher:
    A cipher that applies a linear function (ax + b mod 26) to letters. Requires a key in the form a,b.

    Rail Fence Cipher:
    A transposition cipher that writes the message in a zigzag pattern across a specified number of rails (-s denotes the number of rails).

    Playfair Cipher:
    A digraph substitution cipher that uses a 5x5 matrix generated from a key.

    Columnar Transposition Cipher:
    A transposition cipher that arranges the message into a matrix and reads it column‑by‑column. The number of columns is given by the -s flag.

    Scytale Cipher:
    An ancient transposition cipher that “wraps” the message around a rod; the number of rows is specified with -s.

Modern Symmetric Block & Stream Ciphers

    RC4:
    A stream cipher that uses a variable-length key.

    XTEA:
    A lightweight block cipher with a 64-bit block size.

    AES‑128:
    The Advanced Encryption Standard in ECB mode. Requires a 16‑byte key; keys can be provided as raw 16‑character strings or as a 32‑character hex string.

    DES:
    The Data Encryption Standard (ECB mode). Requires an 8‑character key.

    ChaCha20:
    A modern stream cipher that uses a 32‑byte key and a 12‑byte nonce, provided as a combined key string in the format "32char,12char".

    IDEA:
    The International Data Encryption Algorithm, a 64‑bit block cipher using a 16‑byte key.

    Serpent:
    A block cipher finalist in the AES competition with a 128‑bit block size. Supports 16, 24, or 32‑character keys. (Current implementation is a skeleton.)

    Blowfish:
    A block cipher with variable‑length keys (4 to 56 characters). Our implementation currently uses a 16‑character key by default.

    Twofish:
    A block cipher finalist for AES. Our implementation is provided as a skeleton outlining the key schedule and block processing.

    RC6:
    A block cipher with a 128‑bit block size and 20 rounds. Supports keys provided as raw 16‑character strings or 32‑character hex strings.

    CAST5:
    A block cipher with a 64‑bit block size. Our implementation uses a 16‑character key (raw or as a 32‑character hex string).

    Salsa20:
    A stream cipher similar to ChaCha20. Expects a key in the format "64char,16char" (a 32‑byte key and an 8‑byte nonce, both hex‑encoded).

Hash Functions and HMAC

    SHA‑256:
    A cryptographic hash function that produces a 256‑bit digest. This module is used for one‑way hashing and does not support decryption.

    HMAC‑SHA256:
    A keyed-hash message authentication code (HMAC) using SHA‑256. This module computes the HMAC for a given message and key.

Key Generation and Key Management

The tool includes a dedicated key generation module. When you run the program with the -G flag, it generates a random key suitable for the selected algorithm based on a predefined mapping:

    Symmetric Block Ciphers (e.g., AES, IDEA, Blowfish, Twofish, Serpent, CAST5):
    A 16‑character printable key is generated (selected from uppercase, lowercase letters, and digits).
    Note: This approach yields a key with lower entropy than raw binary (approximately 95 bits instead of 128 bits), but it satisfies the requirement for a 16‑character key.

    ChaCha20:
    Generates a key in the format "32char,12char", where the 32‑character portion is the hex-encoded key (32 bytes) and the 12‑character portion is the hex-encoded nonce (8 bytes).

    Classical Ciphers:
    For ciphers such as Vigenère, an 8‑character key is generated; for Caesar, a numeric string representing a shift is generated.

How to Use a Generated Key:

    Generate the key for your algorithm. For example, for AES:

./encryptor -a aes -G -o aes_key.txt

This command creates a file aes_key.txt containing a 16‑character key (e.g., A1b2C3d4E5f6G7h8).

Encrypt or decrypt using the key:

    ./encryptor -a aes -i "Secret Message" -o cipher.txt -k $(cat aes_key.txt)

    The tool reads the key from the file and uses it for encryption or decryption.

For algorithms that require no key (e.g., SHA‑256) or those with complex key requirements (e.g., RSA, which requires key‑pair generation), the key generation feature is either not applicable or must be implemented separately.
Usage and Examples
Building the Project

Ensure you have a C99-compatible compiler (GCC recommended) and a POSIX environment. From the project’s root directory, run:

make

This will compile all modules and produce the encryptor executable.
Command-Line Syntax

The general usage of the tool is:

./encryptor -a algorithm -i input -o output [-k key] [-s shift] [-d] [-p] [-e encoding] [-G]

Where:

    -a algorithm selects the encryption algorithm (e.g., aes, rc6, salsa20, etc.).
    -i input provides the input text. For encryption, this is plaintext; for decryption, this is typically a hex‑ or base64‑encoded ciphertext.
    -o output specifies the output file. In key generation mode (-G), this is where the generated key will be saved.
    -k key supplies the key for algorithms that require one.
    -s shift is used for algorithms that require a shift value (e.g., Caesar) or for specifying rail/column counts in transposition ciphers.
    -d indicates decryption mode (default mode is encryption).
    -p enables One-Time Pad (OTP) mode, meaning the key must be the same length as the input.
    -e encoding specifies an additional encoding (for example, base64) to be applied to the ciphertext.
    -G triggers key generation mode.

Examples for Each Category
Classical Ciphers

    XOR Cipher:
    Encryption:

./encryptor -a xor -i "Secret Message" -o xor_cipher.txt -k "mysecretkey"

Decryption:

./encryptor -a xor -d -i "EncryptedText" -o plain.txt -k "mysecretkey"

Caesar Cipher:
Encryption:

./encryptor -a caesar -i "Secret Message" -o caesar_cipher.txt -s 3

Decryption:

./encryptor -a caesar -d -i "Vhfuhw Phvvdjh" -o plain.txt -s 3

Vigenère Cipher:
Encryption:

./encryptor -a vigenere -i "Secret Message" -o vigenere_cipher.txt -k "KEYWORD"

Decryption:

./encryptor -a vigenere -d -i "EncryptedText" -o plain.txt -k "KEYWORD"

Playfair Cipher:
Encryption:

./encryptor -a playfair -i "Secret Message" -o playfair_cipher.txt -k "PLAYFAIRKEY"

Decryption:

    ./encryptor -a playfair -d -i "EncryptedText" -o plain.txt -k "PLAYFAIRKEY"

Modern Symmetric Ciphers

    AES‑128:
    Key Generation:

./encryptor -a aes -G -o aes_key.txt

Encryption:

./encryptor -a aes -i "Secret Message" -o aes_cipher.txt -k $(cat aes_key.txt)

Decryption:

./encryptor -a aes -d -i "EncryptedHexText" -o plain.txt -k $(cat aes_key.txt)

DES:
Encryption:

./encryptor -a des -i "Secret Message" -o des_cipher.txt -k "8ChKey!!"

ChaCha20:
Encryption:

./encryptor -a chacha20 -i "Secret Message" -o chacha_cipher.txt -k "32charKeyInHex,12charNonceHex"

RC6:
Encryption:

./encryptor -a rc6 -i "Secret Message" -o rc6_cipher.txt -k $(cat rc6_key.txt)

(Generate key using -G if needed.)

Salsa20:
Encryption:

./encryptor -a salsa20 -i "Secret Message" -o salsa_cipher.txt -k "64charKeyHex,16charNonceHex"

CAST5:
Key Generation:

./encryptor -a cast5 -G -o cast5_key.txt

Encryption:

    ./encryptor -a cast5 -i "Secret Message" -o cast5_cipher.txt -k $(cat cast5_key.txt)

Hash Functions and HMAC

    SHA‑256 Hash:
    Usage (only encryption mode):

./encryptor -a sha256 -i "Secret Message" -o hash.txt

HMAC‑SHA256:
Key Generation:

./encryptor -a hmac_sha256 -G -o hmac_key.txt

Compute HMAC:

    ./encryptor -a hmac_sha256 -i "Secret Message" -o hmac.txt -k $(cat hmac_key.txt)

Future and Planned Algorithms

This project aims to eventually support additional algorithms from the comprehensive Wikipedia list. Notably missing or planned future implementations include:

    Asymmetric-key algorithms:
        RSA (complete key‑pair generation and cryptography)
        Elliptic Curve Cryptography (ECC)
    Broken cryptography algorithms (for academic study):
        Beaufort, Kochanski multiplication, etc.
    Cryptographic hash functions:
        SHA‑3, BLAKE2
    Cryptographically secure PRNGs:
        Fortuna, Yarrow
    Padding algorithms:
        ISO/IEC 9797‑1 Padding
    Type 1, 2, 3 encryption algorithms:
        Various specialized protocols and modes
    Additional symmetric ciphers:
        Camellia, RC6 (if further refined), SM4
    Quantum-resistant algorithms:
        Lattice-based schemes, Supersingular Isogeny Key Exchange
    Cryptographic agility frameworks and key schedule algorithms:
        Key wrap, cryptographic agility protocols

Dependencies and Build Instructions
Dependencies

    Compiler: A C99‑compliant compiler such as GCC.
    POSIX Environment: The code uses POSIX features like getopt and reads from /dev/urandom for randomness.
    Standard Libraries: <stdlib.h>, <stdio.h>, <string.h>, <stdint.h>, etc.

Building

From the project root, simply run:

make

This will compile all modules and link them to create the encryptor executable.
Future Work and Roadmap

The following enhancements are planned:

    Implement Full RSA: Develop a complete RSA module with public–private key pair generation, proper padding schemes (e.g., OAEP), and constant‑time arithmetic.
    Expand Asymmetric Cryptography: Add ECC and other modern public‑key algorithms.
    Complete Skeleton Implementations: Fully implement Twofish and Serpent with constant‑time optimizations and inline assembly as needed.
    Add More Algorithms: Incorporate Camellia, RC6 (refined), Salsa20 (further optimizations), SM4, and other modern algorithms.
    Security Audits and Constant‑Time Improvements: Invest in formal audits, constant‑time coding across all modules, and side‑channel mitigation.
    Enhanced Key Management: Expand key generation to support multiple key sizes and algorithms, with secure key storage options.
    Improved Documentation and Man Pages: Develop full manual pages and online documentation.

Contributing and Licensing

Contributions to ZenithLock are welcome. Due to the sensitive nature of cryptographic code, all contributions must adhere to strict coding standards and undergo rigorous testing and peer review.
This project is licensed under the MIT License. See the LICENSE file for details.

Happy coding and secure cryptographing!
— Kleinpanic and the ZenithLock Suite Team

---
