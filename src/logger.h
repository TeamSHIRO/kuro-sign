#ifndef LOGGER_H
#define LOGGER_H

#define WARNING_TEXT " WARN "
#define SUCCESS_TEXT "  OK  "
#define ERROR_TEXT " ERR! "
#define INFO_TEXT " INFO "

void k_warn(const char *message, ...);
void k_error(const char *message, ...);
void k_info(const char *message, ...);
void k_success(const char *message, ...);

#endif // LOGGER_H
