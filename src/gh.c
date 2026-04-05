#include "gh.h"

#include <curl/curl.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "logger.h"

static size_t curl_write_cb(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t real_size = size * nmemb;
    CurlBuffer *buf = (CurlBuffer *) userp;
    char *ptr = realloc(buf->data, buf->size + real_size + 1);
    if (ptr == NULL) {
        return 0;
    }
    buf->data = ptr;
    memcpy(&(buf->data[buf->size]), contents, real_size);
    buf->size += real_size;
    buf->data[buf->size] = '\0';
    return real_size;
}

// NOLINTNEXTLINE
static int gh_fetch_json(CurlBuffer *buf) {
    CURL *curl = curl_easy_init();
    if (curl == NULL) {
        k_warn("Failed to initialize CURL for update check.");
        return 1;
    }

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "User-Agent: kuro-sign/" PROJECT_VERSION);
    headers = curl_slist_append(headers, "Accept: application/vnd.github+json");

    curl_easy_setopt(curl, CURLOPT_URL, GITHUB_API_LATEST_RELEASE);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, buf);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);

    CURLcode res = curl_easy_perform(curl);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
        k_warn("Update check failed: %s", curl_easy_strerror(res));
        return 1;
    }
    return 0;
}

static int gh_parse_tag_version(const char *json, char *out, size_t max_len) {
    const char *tag_key = "\"tag_name\":\"";
    const char *pos = strstr(json, tag_key);
    if (pos == NULL) {
        return 1;
    }
    pos += strlen(tag_key);
    if (*pos == 'v' || *pos == 'V') {
        pos++;
    }
    size_t i = 0;
    while (*pos != '\0' && *pos != '"' && i < max_len - 1) {
        out[i++] = *pos++;
    }
    out[i] = '\0';
    return 0;
}

static int semver_to_int(const char *version) {
    char *p = (char *) version; // strtol won't modify the string; cast is safe
    int maj = (int) strtol(p, &p, DECIMAL_BASE);
    if (*p == '.') {
        p++;
    }
    int min = (int) strtol(p, &p, DECIMAL_BASE);
    if (*p == '.') {
        p++;
    }
    int patch = (int) strtol(p, NULL, DECIMAL_BASE);
    return (((maj * VERSION_SEMVER_SCALE) + min) * VERSION_SEMVER_SCALE) + patch;
}

void gh_get_latest_published_version(int *out_of_date, char **latest_ver) {
    CurlBuffer buf = {.data = malloc(1), .size = 0};
    if (buf.data == NULL) {
        return;
    }
    buf.data[0] = '\0';

    if (gh_fetch_json(&buf) != 0) {
        free(buf.data);
        return;
    }

    char latest[VERSION_BUFFER_SIZE];
    if (gh_parse_tag_version(buf.data, latest, sizeof(latest)) != 0) {
        k_warn("Failed to check for updates.");
        free(buf.data);
        return;
    }

    *latest_ver = latest;

    free(buf.data);

    if (semver_to_int(latest) > semver_to_int(PROJECT_VERSION)) {
        *out_of_date = 1;
    } else {
        *out_of_date = 0;
    }
}
