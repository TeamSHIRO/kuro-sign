#include <openssl/sha.h>
#include <stdint.h>

#ifndef MAIN_H
#define MAIN_H

#define SEED_SIZE 32
#define PUBLIC_KEY_SIZE 32
#define PRIVATE_KEY_SIZE 64
#define PATH_SIZE 64

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

typedef struct {
    uint8_t kernel_hash[SHA256_DIGEST_LENGTH]; // SHA-256
    uint64_t kernel_size;
    uint64_t entry_point;
    uint32_t version;
} KernelSignatureBlock;

#endif // MAIN_H
