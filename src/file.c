#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int write_file(const char *path, const unsigned char *data, size_t size) {
    FILE *fptr = fopen(path, "wb");
    if (fptr == NULL) {
        printf("Failed to open file \"%s\": %s (Error code: %d)\n", path, strerror(errno), errno);
        return 1;
    }

    size_t response = fwrite(data, 1, size, fptr);
    if (response != size) {
        printf("Failed to write to file \"%s\": %s (Error code: %d)\n", path, strerror(errno), errno);
        if (fclose(fptr) != 0) {
            printf("Failed to close file \"%s\": %s (Error code: %d)\n", path, strerror(errno), errno);
        }
        return 1;
    }

    if (fclose(fptr) != 0) {
        printf("Failed to close file \"%s\": %s (Error code: %d)\n", path, strerror(errno), errno);
        return 1;
    }

    return 0;
}

unsigned char *read_whole_file(const char *path, size_t *out_size) {
    // 1. Open the file in binary mode ("rb") to prevent newline conversions
    FILE *f = fopen(path, "rb");
    if (!f) {
        return NULL;
    }

    // 2. Seek to the end to find the size
    if (fseek(f, 0, SEEK_END) != 0) {
        printf("Failed to seek in file \"%s\": %s (Error code: %d)\n", path, strerror(errno), errno);
        (void) fclose(f);
        return NULL;
    }

    long fsize = ftell(f);
    if (fsize == -1) {
        printf("Failed to get file size for \"%s\": %s (Error code: %d)\n", path, strerror(errno), errno);
        (void) fclose(f);
        return NULL;
    }
    if (fseek(f, 0, SEEK_SET) != 0) {
        printf("Failed to seek in file \"%s\": %s (Error code: %d)\n", path, strerror(errno), errno);
        (void) fclose(f);
        return NULL;
    }

    // 3. Allocate memory (+1 for null terminator if treating as a string)
    unsigned char *buffer = malloc(fsize + 1);
    if (!buffer) {
        (void) fclose(f);
        return NULL;
    }

    // 4. Read the entire content into the buffer
    size_t read_size = fread(buffer, 1, fsize, f);
    buffer[read_size] = '\0';

    if (fclose(f) != 0) {
        printf("Failed to close file \"%s\": %s (Error code: %d)\n", path, strerror(errno), errno);
        free(buffer);
        return NULL;
    }
    if (out_size != NULL) {
        *out_size = read_size;
    }
    return buffer;
}
