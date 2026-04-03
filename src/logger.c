#include "logger.h"

#include <stdarg.h>
#include <stdio.h>
#include "ansi.h"
void k_warn(const char *message, ...) {
    printf(B_YELLOW A_BOLD WARNING_TEXT A_RESET " ");
    va_list args;
    va_start(args, message);
    vprintf(message, args);
    va_end(args);
    printf("\n");
}

void k_error(const char *message, ...) {
    printf(B_RED A_BOLD ERROR_TEXT A_RESET " ");
    va_list args;
    va_start(args, message);
    vprintf(message, args);
    va_end(args);
    printf("\n");
}

void k_info(const char *message, ...) {
    printf(B_BLUE A_BOLD INFO_TEXT A_RESET " ");
    va_list args;
    va_start(args, message);
    vprintf(message, args);
    va_end(args);
    printf("\n");
}

void k_success(const char *message, ...) {
    printf(B_GREEN A_BOLD SUCCESS_TEXT A_RESET " ");
    va_list args;
    va_start(args, message);
    vprintf(message, args);
    va_end(args);
    printf("\n");
}
