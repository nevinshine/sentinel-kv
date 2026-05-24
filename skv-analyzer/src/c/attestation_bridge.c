#include "attestation_bridge.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static int parse_ring(const char *line, int *out_ring) {
    const char *prefix = "ring:";
    size_t n = strlen(prefix);
    if (strncmp(line, prefix, n) != 0) {
        return 0;
    }
    char *end = NULL;
    long val = strtol(line + n, &end, 10);
    if (end == line + n) {
        return 0;
    }
    *out_ring = (int)val;
    return 1;
}

static int parse_attested(const char *line, int *out_attested) {
    const char *prefix = "attested:";
    size_t n = strlen(prefix);
    if (strncmp(line, prefix, n) != 0) {
        return 0;
    }
    const char *v = line + n;
    if (strncmp(v, "true", 4) == 0 || strncmp(v, "1", 1) == 0) {
        *out_attested = 1;
        return 1;
    }
    if (strncmp(v, "false", 5) == 0 || strncmp(v, "0", 1) == 0) {
        *out_attested = 0;
        return 1;
    }
    return 0;
}

static int parse_root_attested(const char *line, int *out_attested) {
    const char *prefix = "root_attested:";
    size_t n = strlen(prefix);
    if (strncmp(line, prefix, n) != 0) {
        return 0;
    }
    const char *v = line + n;
    if (strncmp(v, "true", 4) == 0 || strncmp(v, "1", 1) == 0) {
        *out_attested = 1;
        return 1;
    }
    if (strncmp(v, "false", 5) == 0 || strncmp(v, "0", 1) == 0) {
        *out_attested = 0;
        return 1;
    }
    return 0;
}

static int parse_i64_field(const char *line, const char *prefix, long long *out_val) {
    size_t n = strlen(prefix);
    if (strncmp(line, prefix, n) != 0) {
        return 0;
    }
    char *end = NULL;
    long long val = strtoll(line + n, &end, 10);
    if (end == line + n) {
        return 0;
    }
    *out_val = val;
    return 1;
}

static int parse_string_field(const char *line, const char *prefix, char *out, size_t out_len) {
    size_t n = strlen(prefix);
    if (strncmp(line, prefix, n) != 0) {
        return 0;
    }
    const char *v = line + n;
    if (v[0] == '\0') {
        return 0;
    }
    size_t len = strlen(v);
    if (len + 1 > out_len) {
        return 0;
    }
    memcpy(out, v, len + 1);
    return 1;
}

int skv_validate_attestation_token(
    const char *token_path,
    int required_ring,
    long max_age_sec,
    const char *expected_nonce,
    const char *replay_state_path
) {
    if (token_path == NULL || token_path[0] == '\0') {
        return 0;
    }

    struct stat st;
    if (lstat(token_path, &st) != 0) {
        return 0;
    }
    if (!S_ISREG(st.st_mode)) {
        return 0;
    }
    if (st.st_uid != geteuid()) {
        return 0;
    }
    if ((st.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
        return 0;
    }
    FILE *f = fopen(token_path, "r");
    if (f == NULL) {
        return 0;
    }

    char buf[256];
    int found_ring = 0;
    int found_attested = 0;
    int found_timestamp = 0;
    int found_nonce = 0;
    int found_counter = 0;
    int found_root_attested = 0;
    int token_ring = 0;
    int token_attested = 0;
    int token_root_attested = 0;
    long long token_ts = 0;
    long long token_counter = 0;
    char token_nonce[256];
    token_nonce[0] = '\0';

    while (fgets(buf, sizeof(buf), f) != NULL) {
        char *nl = strchr(buf, '\n');
        if (nl) {
            *nl = '\0';
        }
        if (!found_ring && parse_ring(buf, &token_ring)) {
            found_ring = 1;
            continue;
        }
        if (!found_attested && parse_attested(buf, &token_attested)) {
            found_attested = 1;
            continue;
        }
        if (!found_timestamp && parse_i64_field(buf, "timestamp:", &token_ts)) {
            found_timestamp = 1;
            continue;
        }
        if (!found_nonce && parse_string_field(buf, "nonce:", token_nonce, sizeof(token_nonce))) {
            found_nonce = 1;
            continue;
        }
        if (!found_counter && parse_i64_field(buf, "counter:", &token_counter)) {
            found_counter = 1;
            continue;
        }
        if (!found_root_attested && parse_root_attested(buf, &token_root_attested)) {
            found_root_attested = 1;
            continue;
        }
    }

    fclose(f);

    if (!found_ring || !found_attested || !found_timestamp || !found_counter) {
        return 0;
    }
    if (!token_attested) {
        return 0;
    }
    if (token_ring != required_ring) {
        return 0;
    }
    if (required_ring == -2) {
        if (!found_root_attested || !token_root_attested) {
            return 0;
        }
    }
    if (max_age_sec <= 0) {
        return 0;
    }
    time_t now = time(NULL);
    if (now == (time_t)-1) {
        return 0;
    }
    if (token_ts > (long long)now) {
        return 0;
    }
    if (((long long)now - token_ts) > (long long)max_age_sec) {
        return 0;
    }
    if (expected_nonce != NULL) {
        if (!found_nonce) {
            return 0;
        }
        if (strcmp(expected_nonce, token_nonce) != 0) {
            return 0;
        }
    }
    if (replay_state_path == NULL || replay_state_path[0] == '\0') {
        return 0;
    }

    int state_fd = open(replay_state_path, O_RDWR | O_CREAT | O_CLOEXEC, S_IRUSR | S_IWUSR);
    if (state_fd < 0) {
        return 0;
    }

    struct flock lock;
    memset(&lock, 0, sizeof(lock));
    lock.l_type = F_WRLCK;
    lock.l_whence = SEEK_SET;
    lock.l_start = 0;
    lock.l_len = 0;
    if (fcntl(state_fd, F_SETLKW, &lock) != 0) {
        close(state_fd);
        return 0;
    }

    struct stat sst;
    if (fstat(state_fd, &sst) != 0) {
        close(state_fd);
        return 0;
    }
    if (!S_ISREG(sst.st_mode)) {
        close(state_fd);
        return 0;
    }
    if (sst.st_uid != geteuid()) {
        close(state_fd);
        return 0;
    }
    if ((sst.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
        close(state_fd);
        return 0;
    }

    long long last_counter = -1;
    char sbuf[128];
    ssize_t nread = pread(state_fd, sbuf, sizeof(sbuf) - 1, 0);
    if (nread > 0) {
        sbuf[nread] = '\0';
        char *end = NULL;
        long long parsed = strtoll(sbuf, &end, 10);
        if (end != sbuf) {
            last_counter = parsed;
        }
    }

    if (token_counter <= last_counter) {
        close(state_fd);
        return 0;
    }

    if (ftruncate(state_fd, 0) != 0) {
        close(state_fd);
        return 0;
    }
    if (lseek(state_fd, 0, SEEK_SET) < 0) {
        close(state_fd);
        return 0;
    }
    char outbuf[128];
    int outlen = snprintf(outbuf, sizeof(outbuf), "%lld\n", token_counter);
    if (outlen <= 0 || outlen >= (int)sizeof(outbuf)) {
        close(state_fd);
        return 0;
    }
    ssize_t nwritten = write(state_fd, outbuf, (size_t)outlen);
    if (nwritten != outlen) {
        close(state_fd);
        return 0;
    }
    if (fsync(state_fd) != 0) {
        close(state_fd);
        return 0;
    }
    if (chmod(replay_state_path, S_IRUSR | S_IWUSR) != 0) {
        close(state_fd);
        return 0;
    }
    close(state_fd);
    return 1;
}
