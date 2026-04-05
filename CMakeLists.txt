#
# KURO - A minimal monolithic UEFI bootloader
# =========================================
# Sign the KURO UEFI bootloader and enroll the signing key in the system firmware
#
# Build options:
# Name - Description

cmake_minimum_required(VERSION 3.26 FATAL_ERROR)

project(KURO_SIGNER
        VERSION 0.1.2
        DESCRIPTION "A signer for the KURO UEFI bootloader"
        HOMEPAGE_URL "https://oshub.org/projects/kuro"
        LANGUAGES C
)

set(CMAKE_C_STANDARD 17)

# ── Fetch ed25519 (orlp/ed25519) ───────────────────────────────────────────────
include(FetchContent)
FetchContent_Declare(
        ed25519
        GIT_REPOSITORY https://github.com/orlp/ed25519.git
        GIT_TAG        master
)
FetchContent_MakeAvailable(ed25519)

set(ED25519_SOURCES
        ${ed25519_SOURCE_DIR}/src/add_scalar.c
        ${ed25519_SOURCE_DIR}/src/fe.c
        ${ed25519_SOURCE_DIR}/src/ge.c
        ${ed25519_SOURCE_DIR}/src/sc.c
        ${ed25519_SOURCE_DIR}/src/sha512.c
        ${ed25519_SOURCE_DIR}/src/sign.c
        ${ed25519_SOURCE_DIR}/src/verify.c
        ${ed25519_SOURCE_DIR}/src/keypair.c
        ${ed25519_SOURCE_DIR}/src/seed.c
)

set(KURO_SIGNER_SOURCES
        src/main.c
        src/file.c
        src/logger.c
        src/gh.c
        ${ED25519_SOURCES}
)

add_executable(kuro-sign
        ${KURO_SIGNER_SOURCES}
)

target_include_directories(kuro-sign PRIVATE ${ed25519_SOURCE_DIR}/src)
target_compile_definitions(kuro-sign PRIVATE PROJECT_VERSION="${CMAKE_PROJECT_VERSION}")

find_package(OpenSSL REQUIRED)
find_package(CURL REQUIRED)
target_link_libraries(kuro-sign PRIVATE OpenSSL::Crypto CURL::libcurl)