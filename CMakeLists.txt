#
# KURO - A minimal monolithic UEFI bootloader
# =========================================
# Sign the KURO UEFI bootloader and enroll the signing key in the system firmware
#
# Build options:
# Name - Description

cmake_minimum_required(VERSION 3.26 FATAL_ERROR)

project(KURO_SIGNER
        VERSION 0.1.0
        DESCRIPTION "A signer for the KURO UEFI bootloader"
        HOMEPAGE_URL "https://oshub.org/projects/kuro"
        LANGUAGES C
)

set(CMAKE_C_STANDARD 17)

set(KURO_SIGNER_SOURCES
        src/main.c
        src/file.c
        src/logger.c
        _deps/ed25519/add_scalar.c
        _deps/ed25519/fe.c
        _deps/ed25519/ge.c
        _deps/ed25519/sc.c
        _deps/ed25519/sha512.c
        _deps/ed25519/sign.c
        _deps/ed25519/verify.c
        _deps/ed25519/keypair.c
        _deps/ed25519/seed.c
)

add_executable(kuro-sign
        ${KURO_SIGNER_SOURCES}
)

target_include_directories(kuro-sign PRIVATE _deps/ed25519)

find_package(OpenSSL REQUIRED)
target_link_libraries(kuro-sign PRIVATE OpenSSL::Crypto)