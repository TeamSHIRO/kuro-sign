#include <openssl/sha.h>
#include <stdint.h>

#ifndef MAIN_H
#define MAIN_H

#define SEED_SIZE 32
#define PUBLIC_KEY_SIZE 32
#define PRIVATE_KEY_SIZE 64
#define PATH_SIZE 64
#define SIGNATURE_SIZE 64

#define PATH_PREFIX "./"
#define HEX_COLS 5
// clang-format off
#define KURO_ASCII                                                                                                     \
    "                            ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\n"                                                                         \
    "                            ⠀⠀⠀⣄⠀⣤⡤⠀⠀⠀\n"                                                                         \
    "                            ⠀⠀⠀⣿⣷⣏⠀⠀⠀⠀\n"                                                                         \
    "                            ⠀⠀⠀⠛⠛⠛⠓⠀S⠀\n"                                                                         \
    "                            ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀"
// clang-format on

#define K_MAGIC0 0x7F
#define K_MAGIC1 0x4B // K
#define K_MAGIC2 0x55 // U
#define K_MAGIC3 0x52 // R
#define K_MAGIC4 0x4F // O

#define MAGIC_SIZE 5
#define K_CURRENT_VERSION 1

typedef struct {
    uint8_t kernel_hash[SHA256_DIGEST_LENGTH]; // SHA-256
    uint64_t kernel_size;
    uint64_t entry_point;
    uint32_t version;
} KernelSignatureBlock;

typedef struct {
    char k_magic0;
    char k_magic1;
    char k_magic2;
    char k_magic3;
    char k_magic4;
    uint8_t k_version;
    uint16_t k_reserved;
} KuroIdentifier;

typedef struct {
    KuroIdentifier k_identifier;
    char k_signature[SIGNATURE_SIZE];
} KuroFooter;

#endif // MAIN_H
