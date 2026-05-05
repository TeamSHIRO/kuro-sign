/*
    ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
    ⠀⠀⠀⣄⠀⣤⡤⠀⠀⠀
    ⠀⠀⠀⣿⣷⣏⠀⠀⠀⠀
    ⠀⠀⠀⠛⠛⠛⠓⠀⠀⠀
    ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀

    KURO-SIGN

    A tool for signing securely KURO-compliant kernels.
    More details on KURO can be found at: https://github.com/TeamSHIRO/KURO

    Made with <3 by Ellicode
*/

#include "main.h"

#include <curl/curl.h>
#include <ed25519.h>
#include <errno.h>
#include <getopt.h>
#include <openssl/sha.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "ansi.h"
#include "file.h"
#include "gh.h"
#include "logger.h"
#include "kuro.h"
#include "kuro_footer.h"

int generate_keys(const char *output) {
    unsigned char seed[SEED_SIZE];
    unsigned char public_key[PUBLIC_KEY_SIZE];
    unsigned char private_key[PRIVATE_KEY_SIZE];

    k_info("Generating key pair \"%s\"", output);

    ed25519_create_seed(seed);
    ed25519_create_keypair(public_key, private_key, seed);

    char public_key_path[PATH_SIZE];
    if (snprintf(public_key_path, sizeof(public_key_path), "%s%s%s", PATH_PREFIX, output, ".pub") < 0) {
        k_error("Failed to create public key path");
        return 1;
    }
    char private_key_path[PATH_SIZE];
    if (snprintf(private_key_path, sizeof(private_key_path), "%s%s%s", PATH_PREFIX, output, ".priv") < 0) {
        k_error("Failed to create private key path");
        return 1;
    }

    // Write to the public key file
    if (write_file(public_key_path, public_key, PUBLIC_KEY_SIZE) != 0) {
        k_error("Failed to write public key to \"%s\"", public_key_path);
        return 1;
    }

    // Write to the private key file
    if (write_file(private_key_path, private_key, PRIVATE_KEY_SIZE) != 0) {
        k_error("Failed to write private key to \"%s\"", private_key_path);
        return 1;
    }

    k_success("Successfully generated key pair \"%s\"", output);

    return 0;
}

int get_kuro_footer(const char *kernel_path, KuroFooter *footer) {
    FILE *fptr = fopen(kernel_path, "rb");

    if (fptr == NULL) {
        k_error("Failed to open kernel binary \"%s\": %s (Error code: %d)", kernel_path, strerror(errno), errno);
        return 1;
    }

    if (fseek(fptr, -(long) sizeof(KuroFooter), SEEK_END) != 0) {
        k_error("Failed to seek in kernel binary \"%s\": %s (Error code: %d)", kernel_path, strerror(errno), errno);
        (void) fclose(fptr);
        return 1;
    }

    if (fread(footer, sizeof(KuroFooter), 1, fptr) != 1) {
        k_error("Failed to read footer from kernel binary \"%s\": %s (Error code: %d)", kernel_path, strerror(errno),
                errno);
        (void) fclose(fptr);
        return 1;
    }

    return 0;
}

int sign_kernel(const char *kernel_path, const char *public_key_path, const char *private_key_path, // NOLINT
                const char *output_path, int footer_only, int version_override) { // NOLINT
    if (footer_only == 0 && (public_key_path == NULL || private_key_path == NULL)) {
        k_error("Public key and private key paths are required arguments!");
        printf(A_DIM "     > Tip! Retry again with `kuro-sign %s -p {public_key} -s {private_key}`\n" A_RESET,
               kernel_path);
        return 1;
    }

    if (version_override != 0 && version_override < KURO_VERSION_1) {
        k_warn("You're using a legacy or unsupported version of KURO! Things may break");
    }

    KuroFooter footer = {.k_identifier = {.k_magic = KURO_MAGIC,
                                          .k_version = version_override != 0 ? version_override : KURO_VERSION_1,
                                          .k_reserved = 0},
                         .k_signature = ""};

    const unsigned char *public_key_buffer;
    const unsigned char *private_key_buffer;

    if (footer_only == 0) {
        k_info("Signing kernel \"%s\" with public key \"%s\" and private key \"%s\"", kernel_path, public_key_path,
               private_key_path);

        unsigned char signature[KURO_SIGNATURE_SIZE];
        size_t kernel_size = 0;
        const char *kernel_buffer = read_whole_file(kernel_path, &kernel_size);
        if (kernel_buffer == NULL) {
            k_error("Failed to read kernel file \"%s\": %s (Error code: %d)", kernel_path, strerror(errno), errno);
            return 1;
        }

        // Check if there's an existing footer and exclude it from hashing
        KuroFooter existing_footer;
        const char K_MAGIC[KURO_MAGIC_LEN] = KURO_MAGIC;
        size_t effective_size = kernel_size;
        if (kernel_size >= sizeof(KuroFooter)) {
            memcpy(&existing_footer, kernel_buffer + kernel_size - sizeof(KuroFooter), sizeof(KuroFooter));
            if (memcmp(existing_footer.k_identifier.k_magic, K_MAGIC, KURO_MAGIC_LEN) == 0) {
                effective_size = kernel_size - sizeof(KuroFooter);
            }
        }

        unsigned char kernel_hash[SHA256_DIGEST_LENGTH];
        SHA256((unsigned char *) kernel_buffer, effective_size, kernel_hash);

        if (output_path != NULL) {
            FILE *copyptr;
            copyptr = fopen(output_path, "wb");
            size_t copy_size = fwrite(kernel_buffer, 1, effective_size, copyptr);
            if (copy_size != effective_size) {
                k_error("Failed to write kernel to \"%s\": %s (Error code: %d)", output_path, strerror(errno), errno);
                (void) fclose(copyptr);
                return 1;
            }
            if (fclose(copyptr) != 0) {
                k_error("Failed to close kernel binary \"%s\": %s (Error code: %d)", output_path, strerror(errno),
                        errno);
                return 1;
            }
        }

        free((void *) kernel_buffer);

        size_t public_key_size = 0;
        public_key_buffer = (const unsigned char *) read_whole_file(public_key_path, &public_key_size);
        size_t private_key_size = 0;
        private_key_buffer = (const unsigned char *) read_whole_file(private_key_path, &private_key_size);

        ed25519_sign(signature, kernel_hash, SHA256_DIGEST_LENGTH, public_key_buffer, private_key_buffer);

        memcpy(footer.k_signature, signature, KURO_SIGNATURE_SIZE);
        int verification_result = ed25519_verify(signature, kernel_hash, SHA256_DIGEST_LENGTH, public_key_buffer);
        if (verification_result == 0) {
            k_error("Signature verification failed.");
            return 1;
        } else { // NOLINT
            k_success("Generated a valid signature for the kernel.");
        }
    } else {
        const unsigned char EMPTY_SIGNATURE[KURO_SIGNATURE_SIZE] = {0};
        memcpy(footer.k_signature, EMPTY_SIGNATURE, KURO_SIGNATURE_SIZE);
    }

    KuroFooter kernel_footer;
    get_kuro_footer(kernel_path, &kernel_footer);

    const char K_MAGIC[KURO_MAGIC_LEN] = KURO_MAGIC;
    const char *target_path = output_path != NULL ? output_path : kernel_path;
    int has_existing_footer = memcmp(kernel_footer.k_identifier.k_magic, K_MAGIC, KURO_MAGIC_LEN) == 0;

    if (has_existing_footer) {
        k_warn("The kernel already has a KURO footer. Overwriting...");

        FILE *fptr = fopen(target_path, "r+b");
        if (fptr == NULL) {
            k_error("Failed to open kernel binary \"%s\" for writing: %s (Error code: %d)", target_path,
                    strerror(errno), errno);
            return 1;
        }
        if (fseek(fptr, -(long) sizeof(KuroFooter), SEEK_END) != 0) {
            k_error("Failed to seek in kernel binary \"%s\": %s (Error code: %d)", target_path, strerror(errno), errno);
            (void) fclose(fptr);
            return 1;
        }
        if (fwrite(&footer, sizeof(KuroFooter), 1, fptr) != 1) {
            k_error("Failed to overwrite footer in kernel binary \"%s\": %s (Error code: %d)", target_path,
                    strerror(errno), errno);
            (void) fclose(fptr);
            return 1;
        }
        if (fclose(fptr) != 0) {
            k_error("Failed to close kernel binary \"%s\": %s (Error code: %d)", target_path, strerror(errno), errno);
            return 1;
        }
    } else {
        FILE *fptr = fopen(target_path, "ab");
        if (fptr == NULL) {
            k_error("Failed to open kernel binary \"%s\" for writing: %s (Error code: %d)", target_path,
                    strerror(errno), errno);
            return 1;
        }
        if (fwrite(&footer, sizeof(KuroFooter), 1, fptr) != 1) {
            k_error("Failed to write footer to kernel binary \"%s\": %s (Error code: %d)", target_path, strerror(errno),
                    errno);
            (void) fclose(fptr);
            return 1;
        }
        if (fclose(fptr) != 0) {
            k_error("Failed to close kernel binary \"%s\": %s (Error code: %d)", target_path, strerror(errno), errno);
            return 1;
        }
    }

    k_success("KURO Footer written to \"%s\"", target_path);

    if (footer_only == 0) {
        free((void *) public_key_buffer);
        free((void *) private_key_buffer);
    }

    return 0;
}

void print_version() {
    int out_of_date = 0;
    char *latest = NULL;
    gh_get_latest_published_version(&out_of_date, &latest);

    printf("\n");
    printf("🭌🬿🭠🭗  kuro-sign version " A_BOLD PROJECT_VERSION A_RESET "\n");
    printf("██🭏🬼  ");

    if (out_of_date) {
        printf(T_YELLOW A_BOLD "⬤ new version available! (%s)" A_RESET "\n", latest);
    } else {
        printf(T_GREEN A_BOLD "⬤ up to date" A_RESET "\n");
    }

    free(latest);
    printf("\n");
}

// NOLINTNEXTLINE
int parse_args(int argc, char *argv[], char **output, char **public_key, char **private_key, int *no_sign,
               int *show_version, int *version_override) {
    int opt;
    static struct option long_options[] = {
            {"output", required_argument, 0, 'o'},      {"public-key", required_argument, 0, 'k'},
            {"private-key", required_argument, 0, 's'}, {"footer-only", no_argument, 0, 'f'},
            {"version", no_argument, 0, 'v'},           {"version-override", required_argument, 0, 'V'}};
    int option_index = 0;
    while ((opt = getopt_long(argc, argv, ":o:k:s:fvV:", long_options, &option_index)) != -1) {
        switch (opt) { // NOLINT
            case 'o':
                *output = optarg;
                break;
            case 'k':
                *public_key = optarg;
                break;
            case 's':
                *private_key = optarg;
                break;
            case 'f':
                *no_sign = 1;
                break;
            case 'v':
                *show_version = 1;
                break;
            case 'V':
                *version_override = (int) strtol(optarg, NULL, DECIMAL_BASE);
                break;
            case ':':
                k_error("Option -%c requires an argument", optopt);
                return 1;
            case '?':
            default:
                k_error("Unknown option -%c", optopt);
                return 1;
        }
    }
    return 0;
}

int read_kernel(const char *kernel_path, const char *public_key_path) { // NOLINT
    KuroFooter kernel_footer;

    if (get_kuro_footer(kernel_path, &kernel_footer) != 0) {
        k_error("Failed to read KURO footer from kernel file \"%s\"", kernel_path);
        return 1;
    }

    printf("KURO Footer:\n");
    printf("  Magic:              ");
    
    for (int i = 0; i < KURO_MAGIC_LEN; i++) {
        printf("%02X ", ((uint8_t *) &kernel_footer.k_identifier)[i]);
    }

    const char K_MAGIC[KURO_MAGIC_LEN] = KURO_MAGIC;

    if (memcmp(kernel_footer.k_identifier.k_magic, K_MAGIC, KURO_MAGIC_LEN) == 0) {
        printf(T_GREEN A_BOLD "  ⬤ valid" A_RESET);
    } else {
        printf(T_RED A_BOLD "  ⬤ invalid" A_RESET);
    }
    printf("\n");

    printf("  Version:            %d", kernel_footer.k_identifier.k_version);
    if (kernel_footer.k_identifier.k_version == KURO_VERSION_1) {
        printf(T_GREEN A_BOLD "                ⬤ stable" A_RESET);
    } else {
        printf(T_RED A_BOLD "                ⬤ invalid" A_RESET);
    }
    printf("\n");

    printf("  Reserved:           %s\n", kernel_footer.k_identifier.k_reserved);

    printf("  Signature:          ");
    int verification_result = 0;
    for (int i = 0; i < KURO_SIGNATURE_SIZE; i++) {
        if (i > 0 && i % HEX_COLS == 0) {
            printf("\n                      ");
        }
        printf("%02X ", ((uint8_t *) &kernel_footer.k_signature)[i]);

        if (public_key_path != NULL && i == HEX_COLS - 1) {
            size_t kernel_size = 0;
            const char *kernel_buffer = read_whole_file(kernel_path, &kernel_size);
            if (kernel_buffer == NULL) {
                k_error("Failed to read kernel file \"%s\": %s (Error code: %d)", kernel_path, strerror(errno), errno);
                return 1;
            }
            unsigned char kernel_hash[SHA256_DIGEST_LENGTH];

            // Hash only the kernel content, excluding the appended KuroFooter
            SHA256((unsigned char *) kernel_buffer, kernel_size - sizeof(KuroFooter), kernel_hash);

            free((void *) kernel_buffer);

            size_t public_key_size = 0;
            const unsigned char *public_key_buffer =
                    (const unsigned char *) read_whole_file(public_key_path, &public_key_size);

            verification_result = ed25519_verify((const unsigned char *) kernel_footer.k_signature, kernel_hash,
                                                 SHA256_DIGEST_LENGTH, public_key_buffer);

            if (verification_result == 1) {
                printf(T_GREEN A_BOLD "  ⬤ valid" A_RESET);
            } else {
                printf(T_RED A_BOLD "  ⬤ invalid" A_RESET);
            }
            free((void *) public_key_buffer);
        }
    }
    printf("\n\n");

    if (memcmp(kernel_footer.k_identifier.k_magic, K_MAGIC, KURO_MAGIC_LEN) == 0 && (public_key_path == NULL || verification_result == 1)) {
        printf(T_GREEN A_BOLD "✓ This kernel is a valid KURO-compliant kernel. \n" A_RESET);
    } else {
        printf(T_RED A_BOLD "✗ This kernel is not a valid KURO-compliant kernel. \n" A_RESET);
    }

    return 0;
}

void print_usage() {
    printf(A_BOLD KURO_ASCII A_RESET "\n");
    printf(A_BOLD "                             KURO-SIGN\n" A_RESET);
    printf("         A tool for signing securely KURO-compliant kernels.\n");
    printf(A_DIM "More details on KURO can be found at: https://github.com/TeamSHIRO/KURO\n\n" A_RESET);
    printf(A_BOLD "Usage:\n" A_RESET);
    printf("  kuro-sign <command> [options]\n\n");
    printf(A_BOLD "Commands:\n" A_RESET);
    printf("  keygen    Generate a new key pair using the ed25519 algorithm\n");
    printf("  sign      Sign a kernel with a key pair\n");
    printf("  read      Read and verify a kernel\n");
    printf("  help      Display this help message\n\n");
    printf(A_BOLD "Options:\n" A_RESET);
    printf("  -o --output      <file>    Specify the output file name\n");
    printf("  -k --public-key  <file>    Specify the public key file (required in the 'sign' command)\n");
    printf("  -s --private-key <file>    Specify the private key file (required in the 'sign' command)\n");
    printf("  -f --footer-only           Generate only the footer without signing the kernel\n");
    printf("  -V --version-override <n>  Override the KURO version (use with caution)\n");
    printf("  -v --version               Display the version information\n");
    printf("\n");
}

// NOLINTNEXTLINE
int main(int argc, char *argv[]) {
    char *output = "kuro";
    char *public_key = NULL;
    char *private_key = NULL;
    int footer_only = 0;
    int show_version = 0;
    int version_override = 0;

    if (parse_args(argc, argv, &output, &public_key, &private_key, &footer_only, &show_version, &version_override) !=
        0) {
        return 1;
    }

    if (show_version) {
        print_version();
        return 0;
    }

    if (optind < argc) {
        char *command = argv[optind];
        char *kernel_path = (optind + 1 < argc) ? argv[optind + 1] : NULL;

        if (strcmp((const char *) command, "keygen") == 0) {
            generate_keys(output);
        } else if (strcmp((const char *) command, "sign") == 0) {
            if (kernel_path == NULL) {
                k_error("Sign command requires a kernel path argument");
            } else {
                if (sign_kernel(kernel_path, public_key, private_key, output, footer_only, version_override) != 0) {
                    return 1;
                }
            }
        } else if (strcmp((const char *) command, "read") == 0) {
            if (kernel_path == NULL) {
                k_error("Read command requires a kernel path argument");
            } else {
                if (read_kernel(kernel_path, public_key) != 0) {
                    return 1;
                }
            }
        } else if (strcmp((const char *) command, "help") == 0) {
            print_usage();
        } else {
            k_error("Unknown command: %s \n", command);
            print_usage();
        }
    } else {
        print_usage();
    }

    return 0;
}
