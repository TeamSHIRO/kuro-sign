#include <stddef.h>

#ifndef FILE_H
#define FILE_H

int write_file(const char *path, const unsigned char *data, size_t size);
char *read_whole_file(const char *path, size_t *out_size);

#endif // FILE_H
