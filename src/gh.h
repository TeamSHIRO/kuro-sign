#include <curl/curl.h>
#include <stddef.h>

#ifndef GITHUB_H
#define GITHUB_H

#define GITHUB_REPO "TeamSHIRO/kuro-sign"
#define GITHUB_API_LATEST_RELEASE "https://api.github.com/repos/" GITHUB_REPO "/releases/latest"

#define VERSION_BUFFER_SIZE 32
#define VERSION_SEMVER_SCALE 100
#define DECIMAL_BASE 10

typedef struct {
    char *data;
    size_t size;
} CurlBuffer;

static size_t curl_write_cb(void *contents, size_t size, size_t nmemb, void *userp);
static int gh_fetch_json(CurlBuffer *buf);
static int gh_parse_tag_version(const char *json, char *out, size_t max_len);
static int semver_to_int(const char *version);
void gh_get_latest_published_version(int *out_of_date, char **latest_ver);

#endif // GITHUB_H
