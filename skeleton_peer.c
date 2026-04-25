#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <process.h>
#include <stdint.h>
#include <time.h>
#include <io.h>
#include <errno.h>
#include <ctype.h>

/* Link with Winsock library when using MSVC.
 * With MinGW, the Makefile links using -lws2_32. */
#ifdef _MSC_VER
#pragma comment(lib, "Ws2_32.lib")
#endif

/* ---------------------------------------------------------------------------
 * CS 4390 — Course project (see project description PDF, “Project Specification”):
 * - Central tracker keeps .track files; protocol: LIST, GET, createtracker, updatetracker.
 * - Tracker file layout: filename/size/description/MD5 (with comments/peer list lines).
 * - Peers: max P2P chunk 1024 bytes; after a successful GET of a .track from the tracker,
 *   verify the MD5 in <REP …>, cache the tracker data, then download file bytes from peers.
 *   Choose segments sequentially; prefer the peer with the newest timestamp for a segment
 *   (per spec); call updatetracker after each complete segment. Resume partial downloads
 *   from shared storage; delete the cached .track on successful full data transfer.
 * -------------------------------------------------------------------------- */

typedef SOCKET socket_t;
#define CLOSESOCK(s) closesocket(s)
#define MAX_P2P_CHUNK 1024
#define MAX_TRACK_PEERS 64
#define P2P_DOWNLOAD_WORKERS 4

/* Configuration values */
#define MAX_PATH_LEN 260
char shared_folder[MAX_PATH_LEN] = "./sharedFolder";
char tracker_ip[64] = "127.0.0.1";
int  tracker_port = 5000;
int  refresh_interval = 900; 
int peer_listen_port = 6000;

/* P2P server: accept thread + one worker thread per incoming peer connection. */
static volatile LONG g_peer_server_stop = 0;
static socket_t g_listen_sock = INVALID_SOCKET;
static HANDLE g_accept_thread = NULL;

static int start_peer_server(void);
static void stop_peer_server(void);
static unsigned __stdcall peer_accept_loop(void *unused);
static unsigned __stdcall peer_client_thread(void *arg);
static int connect_to_tracker(socket_t *sock_out);

// Removes comments from a line
static void strip_comment(char *line) {
    char *hash = strchr(line, '#');
    if (hash) *hash = '\0';
}

static int first_token_as_string(const char *line, char *out, size_t out_sz) {
    while (*line == ' ' || *line == '\t' || *line == '\r' || *line == '\n') line++;
    if (*line == '\0') return 0;
    size_t i = 0;
    while (*line && *line != ' ' && *line != '\t' && *line != '\r' && *line != '\n' && i + 1 < out_sz) {
        out[i++] = *line++;
    }
    out[i] = '\0';
    return i > 0;
}

static int first_token_as_int(const char *line, int *out_val) {
    char buf[64];
    if (!first_token_as_string(line, buf, sizeof(buf))) return 0;
    *out_val = atoi(buf);
    return 1;
}

// Loads the client configuration from the clientThreadConfig.cfg file
static void load_client_config(void) {
    FILE *f = fopen("clientThreadConfig.cfg", "r");
    char line[256];
    if (!f) {
        fprintf(stderr, "Warning: cannot open clientThreadConfig.cfg, defaulting.\n");
        return;
    }
    if (fgets(line, sizeof(line), f)) {
        strip_comment(line);
        first_token_as_string(line, tracker_ip, sizeof(tracker_ip)); // Gets tracker IP
    }
    if (fgets(line, sizeof(line), f)) {
        strip_comment(line);
        first_token_as_int(line, &tracker_port); // Gets tracker port
    }
    if (fgets(line, sizeof(line), f)) {
        strip_comment(line);
        int tmp;
        if (first_token_as_int(line, &tmp) && tmp > 0) // Gets refresh interval
            refresh_interval = tmp;
    }
    fclose(f);
}

// Loads the server configuration from the serverThreadConfig.cfg file
static void load_server_config(void) {
    FILE *f = fopen("serverThreadConfig.cfg", "r");
    char line[256];

    if (!f) {
        fprintf(stderr, "Warning: cannot open serverThreadConfig.cfg, defaulting.\n");
        return;
    }

    if (fgets(line, sizeof(line), f)) {
        strip_comment(line);
        first_token_as_int(line, &peer_listen_port); // Gets peer listen port
    }

    if (fgets(line, sizeof(line), f)) {
        strip_comment(line);
        first_token_as_string(line, shared_folder, sizeof(shared_folder)); // Gets shared folder
    }

    fclose(f);
}

static int send_all(socket_t sock, const char *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        int n = send(sock, buf + off, (int)(len - off), 0);
        if (n <= 0) return -1;
        off += (size_t)n;
    }
    return 0;
}

static int recv_line(socket_t sock, char *out, size_t cap) {
    size_t used = 0;
    while (used + 1 < cap) {
        char ch;
        int n = recv(sock, &ch, 1, 0);
        if (n <= 0) break;
        out[used++] = ch;
        if (ch == '\n') break;
    }
    out[used] = '\0';
    return (int)used;
}

static int parse_nonneg_long(const char *tok, long *out) {
    char *endp = NULL;
    long v;
    if (!tok || !*tok) return 0;
    v = strtol(tok, &endp, 10);
    if (*endp != '\0' || v < 0) return 0;
    *out = v;
    return 1;
}

static int filename_is_safe_token(const char *name) {
    if (!name || !*name) return 0;
    if (strchr(name, '/') || strchr(name, '\\')) return 0;
    if (strstr(name, "..")) return 0;
    if (strchr(name, ' ')) return 0;
    return 1;
}

/*
 * Accepted P2P request forms (single line):
 *   <GET filename start end>
 *   <GET filename start +chunksize>
 *
 * Notes:
 * - Indices are byte offsets, inclusive of both start and end.
 * - "+chunksize" form starts at "start" and returns exactly chunksize bytes.
 * - Any requested size > MAX_P2P_CHUNK is rejected with "<GET invalid>\n".
 */
static int parse_peer_get_request(const char *line, char *filename, size_t filename_sz,
                                  long *start_out, long *size_out, int *size_too_large) {
    char cmd[16], file_tok[256], tok3[64], tok4[64], extra[8];
    long start, end_or_size, req_size;
    int fields;

    *size_too_large = 0;
    fields = sscanf(line, " <%15s %255s %63s %63s %7s", cmd, file_tok, tok3, tok4, extra);
    if (fields != 4) return -1;
    {
        size_t n4 = strlen(tok4);
        if (n4 > 0 && tok4[n4 - 1] == '>') tok4[n4 - 1] = '\0';
    }
    if (strcmp(cmd, "GET") != 0) return -1;
    if (!filename_is_safe_token(file_tok)) return -1;
    if (!parse_nonneg_long(tok3, &start)) return -1;

    if (tok4[0] == '+') {
        if (!parse_nonneg_long(tok4 + 1, &end_or_size) || end_or_size <= 0) return -1;
        req_size = end_or_size;
    } else {
        if (!parse_nonneg_long(tok4, &end_or_size)) return -1;
        if (end_or_size < start) return -1;
        req_size = (end_or_size - start) + 1;
    }

    if (req_size > MAX_P2P_CHUNK) {
        *size_too_large = 1;
        return -1;
    }

    strncpy(filename, file_tok, filename_sz - 1);
    filename[filename_sz - 1] = '\0';
    *start_out = start;
    *size_out = req_size;
    return 0;
}

static void trim_eol(char *s) {
    size_t n = strlen(s);
    while (n > 0 && (s[n - 1] == '\n' || s[n - 1] == '\r')) {
        s[n - 1] = '\0';
        n--;
    }
}

static void get_local_ip_for_socket(socket_t sock, char *out, size_t out_sz) {
    struct sockaddr_in local_addr;
    int len = (int)sizeof(local_addr);
    if (getsockname(sock, (struct sockaddr *)&local_addr, &len) == 0) {
        if (inet_ntop(AF_INET, &local_addr.sin_addr, out, (DWORD)out_sz) != NULL) {
            return;
        }
    }
    strncpy(out, "127.0.0.1", out_sz - 1);
    out[out_sz - 1] = '\0';
}

/* Auto mode data structures */
struct TrackFile {
    char name[256];
    char md5[33];
    long size;
};

struct LocalFile {
    char path[MAX_PATH_LEN];
    char md5[33];
    long size;
    time_t timestamp;
};

static struct TrackFile available_files[100];
static int num_available_files = 0;
static struct LocalFile local_files[50];
static int num_local_files = 0;
static char g_local_ip[64] = "127.0.0.1";
static volatile LONG g_auto_stop = 0;
static HANDLE g_refresh_thread = NULL;
static HANDLE g_monitor_thread = NULL;

/* --- Minimal MD5 implementation --- */
typedef uint32_t md5_u32;
typedef struct {
    md5_u32 h[4];
    md5_u32 len_lo, len_hi;
    unsigned char buf[64];
    md5_u32 buf_used;
} md5_ctx;

static md5_u32 md5_rotl(md5_u32 x, md5_u32 n) { return (x << n) | (x >> (32 - n)); }
static md5_u32 md5_f(md5_u32 x, md5_u32 y, md5_u32 z) { return (x & y) | (~x & z); }
static md5_u32 md5_g(md5_u32 x, md5_u32 y, md5_u32 z) { return (x & z) | (y & ~z); }
static md5_u32 md5_h(md5_u32 x, md5_u32 y, md5_u32 z) { return x ^ y ^ z; }
static md5_u32 md5_i(md5_u32 x, md5_u32 y, md5_u32 z) { return y ^ (x | ~z); }
static md5_u32 md5_le32(const unsigned char *p) {
    return (md5_u32)p[0] | ((md5_u32)p[1] << 8) | ((md5_u32)p[2] << 16) | ((md5_u32)p[3] << 24);
}
static void md5_store_le32(unsigned char *p, md5_u32 v) {
    p[0] = (unsigned char)(v & 0xff);
    p[1] = (unsigned char)((v >> 8) & 0xff);
    p[2] = (unsigned char)((v >> 16) & 0xff);
    p[3] = (unsigned char)((v >> 24) & 0xff);
}

static void md5_transform(md5_ctx *c, const unsigned char block[64]) {
    static const md5_u32 k[64] = {
        0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,
        0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,0x6b901122,0xfd987193,0xa679438e,0x49b40821,
        0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,
        0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,
        0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,
        0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,
        0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,
        0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391
    };
    static const md5_u32 r[64] = {
        7,12,17,22, 7,12,17,22, 7,12,17,22, 7,12,17,22,
        5,9,14,20, 5,9,14,20, 5,9,14,20, 5,9,14,20,
        4,11,16,23, 4,11,16,23, 4,11,16,23, 4,11,16,23,
        6,10,15,21, 6,10,15,21, 6,10,15,21, 6,10,15,21
    };

    md5_u32 a = c->h[0], b = c->h[1], cc = c->h[2], d = c->h[3];
    md5_u32 w[16];
    for (int i = 0; i < 16; i++) w[i] = md5_le32(block + i * 4);

    for (int i = 0; i < 64; i++) {
        md5_u32 f, g;
        if (i < 16) { f = md5_f(b, cc, d); g = (md5_u32)i; }
        else if (i < 32) { f = md5_g(b, cc, d); g = (md5_u32)((5*i + 1) & 15); }
        else if (i < 48) { f = md5_h(b, cc, d); g = (md5_u32)((3*i + 5) & 15); }
        else { f = md5_i(b, cc, d); g = (md5_u32)((7*i) & 15); }
        md5_u32 tmp = d;
        d = cc;
        cc = b;
        b = b + md5_rotl(a + f + k[i] + w[g], r[i]);
        a = tmp;
    }

    c->h[0] += a;
    c->h[1] += b;
    c->h[2] += cc;
    c->h[3] += d;
}

static void md5_init(md5_ctx *c) {
    c->h[0] = 0x67452301;
    c->h[1] = 0xefcdab89;
    c->h[2] = 0x98badcfe;
    c->h[3] = 0x10325476;
    c->len_lo = c->len_hi = 0;
    c->buf_used = 0;
}

static void md5_update(md5_ctx *c, const void *data, size_t len) {
    const unsigned char *p = (const unsigned char *)data;
    md5_u32 bits_lo = (md5_u32)(len << 3);
    c->len_lo += bits_lo;
    if (c->len_lo < bits_lo) c->len_hi++;
    c->len_hi += (md5_u32)(len >> 29);

    while (len) {
        size_t take = 64 - c->buf_used;
        if (take > len) take = len;
        memcpy(c->buf + c->buf_used, p, take);
        c->buf_used += (md5_u32)take;
        p += take;
        len -= take;
        if (c->buf_used == 64) {
            md5_transform(c, c->buf);
            c->buf_used = 0;
        }
    }
}

static void md5_final(md5_ctx *c, unsigned char out[16]) {
    unsigned char pad[64] = {0x80};
    unsigned char lenb[8];
    md5_store_le32(lenb + 0, c->len_lo);
    md5_store_le32(lenb + 4, c->len_hi);

    size_t pad_len = (c->buf_used < 56) ? (56 - c->buf_used) : (120 - c->buf_used);
    md5_update(c, pad, pad_len);
    md5_update(c, lenb, 8);

    for (int i = 0; i < 4; i++) md5_store_le32(out + i * 4, c->h[i]);
}

static void md5_hex(const unsigned char digest[16], char hex_out[33]) {
    static const char *hex = "0123456789abcdef";
    for (int i = 0; i < 16; i++) {
        hex_out[i * 2]     = hex[(digest[i] >> 4) & 0xF];
        hex_out[i * 2 + 1] = hex[digest[i] & 0xF];
    }
    hex_out[32] = '\0';
}

static void md5_bytes_hex(const void *data, size_t len, char hex_out[33]) {
    md5_ctx c;
    unsigned char d[16];
    md5_init(&c);
    md5_update(&c, data, len);
    md5_final(&c, d);
    md5_hex(d, hex_out);
}

static const char *base_name(const char *path) {
    const char *p = strrchr(path, '\\');
    if (!p) p = strrchr(path, '/');
    return p ? p + 1 : path;
}

static int file_path_join(const char *dir, const char *file, char *out, size_t out_sz) {
    size_t dlen = strlen(dir);
    if (dlen + 1 + strlen(file) + 1 > out_sz) return 0;
    if (dlen > 0 && dir[dlen - 1] != '\\' && dir[dlen - 1] != '/')
        snprintf(out, out_sz, "%s\\%s", dir, file);
    else
        snprintf(out, out_sz, "%s%s", dir, file);
    return 1;
}

static int ensure_shared_folder(void) {
    DWORD attr = GetFileAttributesA(shared_folder);
    if (attr != INVALID_FILE_ATTRIBUTES) {
        return (attr & FILE_ATTRIBUTE_DIRECTORY) ? 0 : -1;
    }
    if (CreateDirectoryA(shared_folder, NULL) != 0) return 0;
    return (GetLastError() == ERROR_ALREADY_EXISTS) ? 0 : -1;
}

static int compute_file_md5(const char *path, char md5_out[33], long *size_out) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;

    md5_ctx ctx;
    unsigned char buf[4096];
    size_t n;
    long total = 0;

    md5_init(&ctx);
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) {
        md5_update(&ctx, buf, n);
        total += (long)n;
    }

    if (ferror(f)) {
        fclose(f);
        return -1;
    }

    unsigned char digest[16];
    md5_final(&ctx, digest);
    md5_hex(digest, md5_out);
    if (size_out) *size_out = total;
    fclose(f);
    return 0;
}

/* In-progress downloads and chunk maps live in sharedFolder; never register or updatetracker them. */
static int is_download_auxiliary_filename(const char *name) {
    size_t n;
    if (!name || !*name) return 1;
    n = strlen(name);
    if (n >= 5 && _stricmp(name + n - 5, ".part") == 0) return 1;
    if (n >= 9 && _stricmp(name + n - 9, ".chunkmap") == 0) return 1;
    return 0;
}

static int scan_shared_folder_to_list(struct LocalFile *files, int *count_out) {
    if (ensure_shared_folder() != 0) {
        fprintf(stderr, "[monitor] cannot access shared folder '%s'\n", shared_folder);
        *count_out = 0;
        return -1;
    }

    char pattern[MAX_PATH_LEN + 8];
    if (!file_path_join(shared_folder, "*", pattern, sizeof(pattern))) {
        fprintf(stderr, "[monitor] path too long\n");
        *count_out = 0;
        return -1;
    }

    WIN32_FIND_DATAA ffd;
    HANDLE h = FindFirstFileA(pattern, &ffd);
    if (h == INVALID_HANDLE_VALUE) {
        *count_out = 0;
        return 0;
    }

    int count = 0;
    do {
        if (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        if (is_download_auxiliary_filename(ffd.cFileName)) continue;
        if (count >= 50) break;

        if (!file_path_join(shared_folder, ffd.cFileName, files[count].path, sizeof(files[count].path))) {
            continue;
        }

        if (compute_file_md5(files[count].path, files[count].md5, &files[count].size) != 0) {
            fprintf(stderr, "[monitor] failed to hash %s\n", files[count].path);
            continue;
        }
        files[count].timestamp = time(NULL);
        count++;
    } while (FindNextFileA(h, &ffd));

    FindClose(h);
    *count_out = count;
    return 0;
}

static int find_local_file_by_name(const char *name, const struct LocalFile *files, int count) {
    for (int i = 0; i < count; i++) {
        if (strcmp(base_name(files[i].path), name) == 0) return i;
    }
    return -1;
}

static const char *peer_log_id(void);

static void sanitize_tracker_token(char *out, const char *in, size_t out_sz) {
    size_t i;
    for (i = 0; i + 1 < out_sz && *in; in++) {
        out[i++] = (*in == ' ') ? '_' : *in;
    }
    out[i] = '\0';
}

static int send_tracker_createtracker(const char *filename, long filesize, const char *md5, const char *local_ip) {
    socket_t sock;
    if (connect_to_tracker(&sock) != 0) return -1;

    char desc[256];
    sanitize_tracker_token(desc, filename, sizeof(desc));

    char req[1024];
    int len = snprintf(req, sizeof(req), "<createtracker %s %ld %s %s %s %d>\n",
                       filename, filesize, desc, md5, local_ip, peer_listen_port);
    if (len < 0 || len >= (int)sizeof(req) || send_all(sock, req, strlen(req)) != 0) {
        CLOSESOCK(sock);
        return -1;
    }

    char line[4096];
    int n = recv_line(sock, line, sizeof(line));
    CLOSESOCK(sock);
    if (n <= 0) return -1;
    trim_eol(line);

    if (strstr(line, "<createtracker succ>") || strstr(line, "<createtracker ferr>")) {
        /* Project spec style: Peer1: createtracker movie1.avi 10 description md5 ip port */
        printf("%s: createtracker %s %ld %s %s %s %d\n",
               peer_log_id(), filename, filesize, desc, md5, local_ip, peer_listen_port);
        return 0;
    }
    return -1;
}

static int send_tracker_updatetracker(const char *filename, long start_b, long end_b, const char *local_ip) {
    socket_t sock;
    if (connect_to_tracker(&sock) != 0) return -1;

    char req[1024];
    int len = snprintf(req, sizeof(req), "<updatetracker %s %ld %ld %s %d>\n",
                       filename, start_b, end_b, local_ip, peer_listen_port);
    if (len < 0 || len >= (int)sizeof(req) || send_all(sock, req, strlen(req)) != 0) {
        CLOSESOCK(sock);
        return -1;
    }

    char line[4096];
    int n = recv_line(sock, line, sizeof(line));
    CLOSESOCK(sock);
    if (n <= 0) return -1;
    trim_eol(line);
    return strstr(line, " succ>") != NULL ? 0 : -1;
}

static void register_local_files(void) {
    for (int i = 0; i < num_local_files; i++) {
        const char *name = base_name(local_files[i].path);
        if (strchr(name, ' ')) {
            printf("%s: createtracker skipped (spaces in name) %s\n", peer_log_id(), name);
            continue;
        }

        if (send_tracker_createtracker(name, local_files[i].size, local_files[i].md5, g_local_ip) != 0) {
            printf("%s: createtracker failed for %s\n", peer_log_id(), name);
        }
    }
}

static int local_files_equal(const struct LocalFile *a, const struct LocalFile *b) {
    return a->size == b->size && strcmp(a->md5, b->md5) == 0;
}

static void update_local_files_from_scan(void) {
    struct LocalFile new_files[50];
    int new_count = 0;
    if (scan_shared_folder_to_list(new_files, &new_count) != 0) {
        return;
    }

    for (int i = 0; i < new_count; i++) {
        const char *name = base_name(new_files[i].path);
        int idx = find_local_file_by_name(name, local_files, num_local_files);
        if (idx < 0) {
            printf("[monitor] new file detected: %s\n", name);
            if (strchr(name, ' ')) {
                printf("[monitor] skipping tracker registration for file with spaces: %s\n", name);
            } else if (send_tracker_createtracker(name, new_files[i].size, new_files[i].md5, g_local_ip) == 0) {
                /* createtracker line printed inside send_tracker_createtracker */
            } else {
                printf("%s: createtracker failed for %s\n", peer_log_id(), name);
            }
        } else if (!local_files_equal(&new_files[i], &local_files[idx])) {
            printf("[monitor] changed file detected: %s\n", name);
        }
    }

    memcpy(local_files, new_files, sizeof(new_files));
    num_local_files = new_count;
}

/*
 * Periodically refresh this peer's ownership ranges for all currently shared files.
 * We use the full-file range [0, size-1] for non-empty files, and [0,0] for empty files.
 */
static void send_periodic_updatetracker_for_local_files(void) {
    struct LocalFile snapshot[50];
    int snapshot_count = 0;
    if (scan_shared_folder_to_list(snapshot, &snapshot_count) != 0) return;

    for (int i = 0; i < snapshot_count; i++) {
        const char *name = base_name(snapshot[i].path);
        long start_b = 0;
        long end_b = (snapshot[i].size > 0) ? (snapshot[i].size - 1) : 0;
        if (strchr(name, ' ')) continue;

        if (send_tracker_updatetracker(name, start_b, end_b, g_local_ip) != 0) {
            printf("%s: updatetracker failed for %s\n", peer_log_id(), name);
        }
    }
}

static unsigned __stdcall monitor_thread(void *unused) {
    (void)unused;
    printf("[monitor] scanning shared folder every %d s\n", refresh_interval);

    while (!g_auto_stop) {
        update_local_files_from_scan();
        for (int i = 0; i < refresh_interval && !g_auto_stop; i++) {
            Sleep(1000);
        }
    }
    return 0;
}


static unsigned __stdcall peer_client_thread(void *arg) {
    socket_t client = *(socket_t *)arg;
    free(arg);

    struct sockaddr_in ca;
    int calen = (int)sizeof(ca);
    if (getpeername(client, (struct sockaddr *)&ca, &calen) == 0) {
        char peeraddr[64];
        if (inet_ntop(AF_INET, &ca.sin_addr, peeraddr, sizeof(peeraddr)) != NULL) {
            printf("[peer-server] connection from %s:%d\n", peeraddr, (int)ntohs(ca.sin_port));
        }
    }

    char line[4096];
    int n = recv_line(client, line, sizeof(line));
    if (n > 0) {
        char req_name[256];
        char full_path[MAX_PATH_LEN];
        char response[64];
        long start = 0;
        long req_size = 0;
        int too_large = 0;

        trim_eol(line);
        printf("[peer-server] request: %s\n", line);

        if (parse_peer_get_request(line, req_name, sizeof(req_name), &start, &req_size, &too_large) != 0) {
            if (too_large) {
                (void)send_all(client, "<GET invalid>\n", strlen("<GET invalid>\n"));
            } else {
                (void)send_all(client, "<GET error>\n", strlen("<GET error>\n"));
            }
            CLOSESOCK(client);
            return 0;
        }

        if (!file_path_join(shared_folder, req_name, full_path, sizeof(full_path))) {
            (void)send_all(client, "<GET error>\n", strlen("<GET error>\n"));
            CLOSESOCK(client);
            return 0;
        }

        FILE *f = fopen(full_path, "rb");
        if (!f) {
            (void)send_all(client, "<GET error>\n", strlen("<GET error>\n"));
            CLOSESOCK(client);
            return 0;
        }

        if (fseek(f, 0, SEEK_END) != 0) {
            fclose(f);
            (void)send_all(client, "<GET error>\n", strlen("<GET error>\n"));
            CLOSESOCK(client);
            return 0;
        }
        long file_size = ftell(f);
        if (file_size < 0 || start > file_size || req_size <= 0 || (start + req_size) > file_size) {
            fclose(f);
            (void)send_all(client, "<GET error>\n", strlen("<GET error>\n"));
            CLOSESOCK(client);
            return 0;
        }
        if (fseek(f, start, SEEK_SET) != 0) {
            fclose(f);
            (void)send_all(client, "<GET error>\n", strlen("<GET error>\n"));
            CLOSESOCK(client);
            return 0;
        }

        char chunk[MAX_P2P_CHUNK];
        size_t got = fread(chunk, 1, (size_t)req_size, f);
        fclose(f);
        if ((long)got != req_size) {
            (void)send_all(client, "<GET error>\n", strlen("<GET error>\n"));
            CLOSESOCK(client);
            return 0;
        }

        snprintf(response, sizeof(response), "<GET ok %ld>\n", req_size);
        if (send_all(client, response, strlen(response)) != 0 || send_all(client, chunk, got) != 0) {
            CLOSESOCK(client);
            return 0;
        }
    }

    CLOSESOCK(client);
    return 0;
}

static unsigned __stdcall peer_accept_loop(void *unused) {
    (void)unused;
    printf("[peer-server] accepting on port %d\n", peer_listen_port);

    for (;;) {
        if (g_peer_server_stop)
            break;

        struct sockaddr_in caddr;
        int clen = sizeof(caddr);
        socket_t c = accept(g_listen_sock, (struct sockaddr *)&caddr, &clen);
        if (c == INVALID_SOCKET) {
            if (g_peer_server_stop)
                break;
            continue;
        }

        socket_t *p = (socket_t *)malloc(sizeof(socket_t));
        if (!p) {
            CLOSESOCK(c);
            continue;
        }
        *p = c;
        uintptr_t th = _beginthreadex(NULL, 0, peer_client_thread, p, 0, NULL);
        if (th == 0) {
            free(p);
            CLOSESOCK(c);
            fprintf(stderr, "[peer-server] _beginthreadex failed\n");
            continue;
        }
        CloseHandle((HANDLE)th);
    }

    return 0;
}

static int start_peer_server(void) {
    g_peer_server_stop = 0;
    g_listen_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (g_listen_sock == INVALID_SOCKET) {
        fprintf(stderr, "[peer-server] socket() failed\n");
        return -1;
    }

    int one = 1;
    if (setsockopt(g_listen_sock, SOL_SOCKET, SO_REUSEADDR, (const char *)&one, sizeof(one)) == SOCKET_ERROR) {
        fprintf(stderr, "[peer-server] setsockopt(SO_REUSEADDR) failed\n");
    }

    struct sockaddr_in la;
    memset(&la, 0, sizeof(la));
    la.sin_family = AF_INET;
    la.sin_addr.s_addr = htonl(INADDR_ANY);
    la.sin_port = htons((unsigned short)peer_listen_port);

    if (bind(g_listen_sock, (struct sockaddr *)&la, sizeof(la)) == SOCKET_ERROR) {
        fprintf(stderr, "[peer-server] bind(port %d) failed — another peer using this port?\n", peer_listen_port);
        CLOSESOCK(g_listen_sock);
        g_listen_sock = INVALID_SOCKET;
        return -1;
    }

    if (listen(g_listen_sock, SOMAXCONN) == SOCKET_ERROR) {
        fprintf(stderr, "[peer-server] listen() failed\n");
        CLOSESOCK(g_listen_sock);
        g_listen_sock = INVALID_SOCKET;
        return -1;
    }

    uintptr_t th = _beginthreadex(NULL, 0, peer_accept_loop, NULL, 0, NULL);
    if (th == 0) {
        fprintf(stderr, "[peer-server] _beginthreadex(accept) failed\n");
        CLOSESOCK(g_listen_sock);
        g_listen_sock = INVALID_SOCKET;
        return -1;
    }
    g_accept_thread = (HANDLE)th;
    return 0;
}

static void stop_peer_server(void) {
    InterlockedExchange(&g_peer_server_stop, 1);

    if (g_listen_sock != INVALID_SOCKET) {
        CLOSESOCK(g_listen_sock);
        g_listen_sock = INVALID_SOCKET;
    }

    if (g_accept_thread) {
        WaitForSingleObject(g_accept_thread, 15000);
        CloseHandle(g_accept_thread);
        g_accept_thread = NULL;
    }
}

static int connect_to_tracker(socket_t *sock_out) {
    struct sockaddr_in server_addr;
    *sock_out = socket(AF_INET, SOCK_STREAM, 0);
    if (*sock_out == INVALID_SOCKET) return -1;

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(tracker_port);
    if (inet_pton(AF_INET, tracker_ip, &server_addr.sin_addr) <= 0) {
        CLOSESOCK(*sock_out);
        return -1;
    }

    if (connect(*sock_out, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        CLOSESOCK(*sock_out);
        return -1;
    }
    return 0;
}

/* --- Auto download (see project spec: GET .track, P2P chunks, updatetracker, resume) --- */

static const char *peer_log_id(void) {
    const char *e = getenv("PEER_ID");
    return (e && *e) ? e : "peer";
}

struct PeerInfo {
    char ip[64];
    int port;
    long start, end, ts;
};

static int read_full_tracker_response(socket_t s, char **buf_out, size_t *len_out) {
    size_t cap = 65536, len = 0;
    char *buf = (char *)malloc(cap + 1);
    if (!buf) return -1;
    for (;;) {
        if (len + 16384 > cap) {
            size_t ncap = cap * 2;
            char *nbuf = (char *)realloc(buf, ncap + 1);
            if (!nbuf) { free(buf); return -1; }
            buf = nbuf;
            cap = ncap;
        }
        size_t room = cap - len;
        int chunk = (int)((room < 16384) ? room : 16384);
        if (chunk <= 0) { free(buf); return -1; }
        int n = recv(s, buf + len, chunk, 0);
        if (n < 0) { free(buf); return -1; }
        if (n == 0) break;
        len += (size_t)n;
    }
    buf[len] = '\0';
    *buf_out = buf;
    *len_out = len;
    return 0;
}

/* Validate wire format from tracker (project spec: <REP GET BEGIN>, body, <REP END FileMD5>). */
static int parse_tracker_get_payload(const char *buf, char **body_out, size_t *body_len,
                                     char end_md5_hex[33]) {
    const char *begin_mark = "<REP GET BEGIN>\n";
    const char *h = strstr(buf, begin_mark);
    if (!h) return -1;
    const char *p = h + strlen(begin_mark); /* body starts immediately after this line */
    /* Trailer is "<REP GET END md5>\n" with no extra newline when the .track already ends in '\n',
     * so "\n<REP GET END " must not be used as the body boundary (it steals the file's final LF). */
    const char *endmark = NULL;
    for (const char *q = strstr(p, "<REP GET END "); q; q = strstr(q + 1, "<REP GET END "))
        endmark = q;
    if (!endmark) {
        return -1;
    }
    *body_len = (size_t)(endmark - p);
    *body_out = (char *)malloc(*body_len + 1);
    if (!*body_out) return -1;
    memcpy(*body_out, p, *body_len);
    (*body_out)[*body_len] = '\0';
    {
        if (sscanf(endmark, "<REP GET END %32[0-9a-fA-F]>", end_md5_hex) != 1) {
            free(*body_out);
            *body_out = NULL;
            return -1;
        }
    }
    {
        char calc[33];
        md5_bytes_hex(*body_out, *body_len, calc);
        for (int i = 0; i < 32; i++) {
            char a = (char)tolower((unsigned char)end_md5_hex[i]);
            char b = (char)tolower((unsigned char)calc[i]);
            if (a != b) {
                free(*body_out);
                *body_out = NULL;
                return -1;
            }
        }
    }
    end_md5_hex[32] = '\0';
    return 0;
}

static int get_tracker_file_via_get(const char *track_filename, char **body_out, size_t *body_len) {
    socket_t s;
    if (connect_to_tracker(&s) != 0) return -1;
    char req[600];
    int ln = snprintf(req, sizeof(req), "<GET %s >\n", track_filename);
    if (ln < 0 || ln >= (int)sizeof(req) || send_all(s, req, (size_t)ln) != 0) {
        CLOSESOCK(s);
        return -1;
    }
    char *raw = NULL;
    size_t rawlen = 0;
    if (read_full_tracker_response(s, &raw, &rawlen) != 0) {
        CLOSESOCK(s);
        return -1;
    }
    CLOSESOCK(s);
    char *body = NULL;
    size_t blen = 0;
    char endmd5[33];
    if (parse_tracker_get_payload(raw, &body, &blen, endmd5) != 0) {
        free(raw);
        fprintf(stderr, "[%s] GET %s: bad response or MD5 mismatch\n", peer_log_id(), track_filename);
        return -1;
    }
    free(raw);
    *body_out = body;
    *body_len = blen;
    return 0;
}

/* Tracker file: lines like "filename ...", "filesize ...", "md5 ...", "peer ..." (see project spec). */
static int parse_track_text(const char *text, char *filename_out, long *filesize_out,
                            char data_md5_out[33], struct PeerInfo *peers, int *npeers_out) {
    char copy[16000];
    if (strlen(text) >= sizeof(copy)) return -1;
    strncpy(copy, text, sizeof(copy) - 1);
    copy[sizeof(copy) - 1] = '\0';
    *npeers_out = 0;
    filename_out[0] = '\0';
    *filesize_out = 0;
    data_md5_out[0] = '\0';
    char *line = copy;
    while (line) {
        char *nl = strchr(line, '\n');
        if (nl) *nl = '\0';
        while (*line == ' ' || *line == '\t' || *line == '\r') line++;
        if (line[0] == '\0' || line[0] == '#') {
            if (nl) line = nl + 1; else break;
            continue;
        }
        if (_strnicmp(line, "filename", 8) == 0) {
            const char *v = line + 8;
            while (*v == ' ' || *v == '\t' || *v == ':') v++;
            strncpy(filename_out, v, 255);
            filename_out[255] = '\0';
        } else if (_strnicmp(line, "filesize", 8) == 0) {
            const char *v = line + 8;
            while (*v == ' ' || *v == '\t' || *v == ':') v++;
            *filesize_out = atol(v);
        } else if (_strnicmp(line, "md5", 3) == 0) {
            const char *v = line + 3;
            while (*v == ' ' || *v == '\t' || *v == ':') v++;
            char tok[64];
            if (sscanf(v, "%63s", tok) == 1) {
                if (strlen(tok) == 32) { memcpy(data_md5_out, tok, 32); data_md5_out[32] = '\0'; }
            }
        } else if (_strnicmp(line, "peer", 4) == 0) {
            if (*npeers_out < MAX_TRACK_PEERS) {
                const char *v = line + 4;
                while (*v == ' ' || *v == '\t') v++;
                int po;
                long st, en, tss;
                if (sscanf(v, " %63[^:]:%d:%ld:%ld:%ld", peers[*npeers_out].ip, &po, &st, &en, &tss) == 5) {
                    peers[*npeers_out].port = po;
                    peers[*npeers_out].start = st;
                    peers[*npeers_out].end = en;
                    peers[*npeers_out].ts = tss;
                    (*npeers_out)++;
                }
            }
        }
        if (nl) line = nl + 1; else break;
    }
    if (!filename_out[0] || *filesize_out < 0 || strlen(data_md5_out) != 32) return -1;
    return 0;
}

static int is_self_seeder(const char *ip, int port) {
    if (port != peer_listen_port) return 0;
    if (_stricmp(ip, g_local_ip) == 0) return 1;
    if (strcmp(g_local_ip, "127.0.0.1") == 0 && _stricmp(ip, "127.0.0.1") == 0) return 1;
    return 0;
}

static int best_peer_index(struct PeerInfo *peers, int n, long cstart, long cend) {
    int best = -1;
    long best_ts = -1;
    for (int i = 0; i < n; i++) {
        if (is_self_seeder(peers[i].ip, peers[i].port)) continue;
        if (peers[i].start > cstart || peers[i].end < cend) continue;
        if (peers[i].ts > best_ts) {
            best_ts = peers[i].ts;
            best = i;
        }
    }
    return best;
}

static int recv_exact(socket_t s, void *b, size_t n) {
    char *p = (char *)b;
    size_t o = 0;
    while (o < n) {
        int r = recv(s, p + o, (int)(n - o), 0);
        if (r <= 0) return -1;
        o += (size_t)r;
    }
    return 0;
}

static int p2p_get_chunk(const char *ip, int prt, const char *fname, long start, long clen, char *out) {
    struct sockaddr_in a;
    socket_t s = socket(AF_INET, SOCK_STREAM, 0);
    if (s == INVALID_SOCKET) return -1;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port = htons((unsigned short)prt);
    if (inet_pton(AF_INET, ip, &a.sin_addr) != 1) { CLOSESOCK(s); return -1; }
    if (connect(s, (struct sockaddr *)&a, sizeof(a)) < 0) { CLOSESOCK(s); return -1; }
    char req[512];
    int len = snprintf(req, sizeof(req), "<GET %s %ld +%ld>\n", fname, start, clen);
    if (len < 0 || len >= (int)sizeof(req) || send_all(s, req, (size_t)len) != 0) {
        CLOSESOCK(s);
        return -1;
    }
    char line[512];
    if (recv_line(s, line, sizeof(line)) <= 0) { CLOSESOCK(s); return -1; }
    trim_eol(line);
    long nexpect = 0;
    if (sscanf(line, "<GET ok %ld", &nexpect) != 1) { CLOSESOCK(s); return -1; }
    if (nexpect != (long)clen) { CLOSESOCK(s); return -1; }
    if (recv_exact(s, out, (size_t)clen) != 0) { CLOSESOCK(s); return -1; }
    CLOSESOCK(s);
    return 0;
}

static int ensure_track_cache_dir(char *out, size_t out_sz) {
    if (!file_path_join(shared_folder, "tracker_cache", out, out_sz)) return -1;
    if (GetFileAttributesA(out) == INVALID_FILE_ATTRIBUTES) {
        if (CreateDirectoryA(out, NULL) == 0 && GetLastError() != ERROR_ALREADY_EXISTS) return -1;
    }
    return 0;
}

static int chunk_bit_test(const unsigned char *map, int idx) {
    return (map[idx / 8] >> (idx % 8)) & 1;
}
static void chunk_bit_set(unsigned char *map, int idx) {
    map[idx / 8] |= (unsigned char)(1u << (idx % 8));
}
static int chunk_bytes(int nchunk) { return (nchunk + 7) / 8; }

static int save_map_file(const char *path, const unsigned char *map, int nbytes) {
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    if (fwrite(map, 1, (size_t)nbytes, f) != (size_t)nbytes) { fclose(f); return -1; }
    fclose(f);
    return 0;
}
static int load_map_file(const char *path, unsigned char *map, int nbytes) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    if (fread(map, 1, (size_t)nbytes, f) != (size_t)nbytes) { fclose(f); return -1; }
    fclose(f);
    return 0;
}

typedef struct {
    char fname[300];
    char part_path[MAX_PATH_LEN];
    char map_path[MAX_PATH_LEN];
    char track_cache_path[MAX_PATH_LEN];
    long filesize;
    int nchunks;
    unsigned char *map;
    int map_nbytes;
    struct PeerInfo peers[MAX_TRACK_PEERS];
    int npeers;
    char expect_md5[33];
    FILE *fpart;
    CRITICAL_SECTION cs;
    volatile int failed;
} DlState;

static unsigned __stdcall dl_worker(void *arg) {
    DlState *d = (DlState *)arg;
    for (;;) {
        int chunk = -1;
        EnterCriticalSection(&d->cs);
        for (int k = 0; k < d->nchunks; k++) {
            if (!chunk_bit_test(d->map, k)) {
                chunk = k;
                chunk_bit_set(d->map, k);
                break;
            }
        }
        LeaveCriticalSection(&d->cs);
        if (chunk < 0) return 0;
        if (d->failed) return 0;
        long start = (long)chunk * MAX_P2P_CHUNK;
        long clen = d->filesize - start;
        if (clen > MAX_P2P_CHUNK) clen = MAX_P2P_CHUNK;
        if (clen <= 0) { d->failed = 1; return 0; }
        long cend = start + clen - 1;
        int try_count = 0;
        int ok = 0;
        char buf[MAX_P2P_CHUNK];
        while (try_count < 8 && !ok) {
            int pi = best_peer_index(d->peers, d->npeers, start, cend);
            if (pi < 0) {
                Sleep(200);
                try_count++;
                continue;
            }
            if (p2p_get_chunk(d->peers[pi].ip, d->peers[pi].port, d->fname, start, clen, buf) == 0) {
                EnterCriticalSection(&d->cs);
                if (fseek(d->fpart, start, SEEK_SET) != 0) d->failed = 1;
                else if (fwrite(buf, 1, (size_t)clen, d->fpart) != (size_t)clen) d->failed = 1;
                else fflush(d->fpart);
                if (!d->failed) {
                    if (send_tracker_updatetracker(d->fname, start, cend, g_local_ip) != 0) {
                        fprintf(stderr, "[%s] updatetracker after chunk failed (non-fatal)\n", peer_log_id());
                    }
                    if (save_map_file(d->map_path, d->map, d->map_nbytes) != 0) d->failed = 1;
                }
                LeaveCriticalSection(&d->cs);
                /* Spec: "Peer5 downloading 1024 to 2048 bytes of movie1.avi from 124.24.124.24 6677" (no colon before downloading) */
                printf("%s downloading %ld to %ld bytes of %s from %s %d\n",
                    peer_log_id(), (long)start, (long)(start + clen - 1), d->fname, d->peers[pi].ip, d->peers[pi].port);
                ok = 1;
            } else {
                Sleep(100);
                try_count++;
            }
        }
        if (!ok) {
            EnterCriticalSection(&d->cs);
            d->map[chunk / 8] &= (unsigned char)~(1u << (unsigned)(chunk % 8));
            d->failed = 1;
            LeaveCriticalSection(&d->cs);
        }
    }
}

static int run_download_data_file(const char *data_fname, const char *track_name_for_log,
    long fsize, const char *expect_md5, struct PeerInfo *peers, int npeers) {
    if (fsize < 0) return -1;
    char tdir[MAX_PATH_LEN];
    if (ensure_track_cache_dir(tdir, sizeof(tdir)) != 0) return -1;
    if (strchr(data_fname, ' ')) { fprintf(stderr, "[%s] skip: spaces in name\n", peer_log_id()); return -1; }
    {
        char full[MAX_PATH_LEN];
        if (file_path_join(shared_folder, data_fname, full, sizeof(full))) {
            char m[33];
            long sz;
            if (compute_file_md5(full, m, &sz) == 0 && sz == fsize && _stricmp(m, expect_md5) == 0) {
                char tc[MAX_PATH_LEN];
                snprintf(tc, sizeof(tc), "%s\\%s", tdir, track_name_for_log);
                remove(tc);
                printf("[%s] already have %s; removed cached .track if any\n", peer_log_id(), data_fname);
                return 0;
            }
        }
    }
    if (fsize == 0) {
        char p[MAX_PATH_LEN];
        if (!file_path_join(shared_folder, data_fname, p, sizeof(p))) return -1;
        FILE *f = fopen(p, "wb");
        if (f) fclose(f);
        { char m[33]; long sz; if (compute_file_md5(p, m, &sz) != 0 || _stricmp(m, expect_md5) != 0) return -1; }
        { char tc[MAX_PATH_LEN]; snprintf(tc, sizeof(tc), "%s\\%s", tdir, track_name_for_log); remove(tc); }
        printf("[%s] file %s (empty) verified\n", peer_log_id(), data_fname);
        return 0;
    }
    DlState st;
    memset(&st, 0, sizeof(st));
    strncpy(st.fname, data_fname, sizeof(st.fname) - 1);
    snprintf(st.map_path, sizeof(st.map_path), "%s\\%s.chunkmap", tdir, data_fname);
    snprintf(st.track_cache_path, sizeof(st.track_cache_path), "%s\\%s", tdir, track_name_for_log);
    if (!file_path_join(shared_folder, data_fname, st.part_path, sizeof(st.part_path)))
        return -1;
    strncat(st.part_path, ".part", sizeof(st.part_path) - strlen(st.part_path) - 1);
    st.filesize = fsize;
    memcpy(st.expect_md5, expect_md5, 33);
    memcpy(st.peers, peers, (size_t)npeers * sizeof(struct PeerInfo));
    st.npeers = npeers;
    { int u = 0; for (int i = 0; i < npeers; i++) if (!is_self_seeder(peers[i].ip, peers[i].port)) u++; if (u < 1) { fprintf(stderr, "[%s] no remote peers in .track for %s\n", peer_log_id(), data_fname); return -1; } }
    st.nchunks = (int)((fsize + MAX_P2P_CHUNK - 1) / MAX_P2P_CHUNK);
    st.map_nbytes = chunk_bytes(st.nchunks);
    st.map = (unsigned char *)calloc(1, (size_t)st.map_nbytes);
    if (!st.map) return -1;
    st.fpart = fopen(st.part_path, "r+b");
    if (st.fpart) {
        if (fseek(st.fpart, 0, SEEK_END) == 0) {
            if (ftell(st.fpart) != fsize) { fclose(st.fpart); st.fpart = NULL; }
        } else { fclose(st.fpart); st.fpart = NULL; }
    }
    if (!st.fpart) {
        st.fpart = fopen(st.part_path, "w+b");
        if (!st.fpart) { free(st.map); return -1; }
        if (_chsize(_fileno(st.fpart), fsize) != 0) { fclose(st.fpart); free(st.map); return -1; }
    } else {
        if (_chsize(_fileno(st.fpart), fsize) != 0) { fclose(st.fpart); free(st.map); return -1; }
    }
    if (GetFileAttributesA(st.map_path) != INVALID_FILE_ATTRIBUTES) {
        if (load_map_file(st.map_path, st.map, st.map_nbytes) != 0) { memset(st.map, 0, (size_t)st.map_nbytes); }
    }
    InitializeCriticalSection(&st.cs);
    st.failed = 0;
    HANDLE w[P2P_DOWNLOAD_WORKERS];
    int nthr = (st.nchunks < P2P_DOWNLOAD_WORKERS) ? st.nchunks : P2P_DOWNLOAD_WORKERS;
    for (int t = 0; t < nthr; t++) {
        w[t] = (HANDLE)_beginthreadex(NULL, 0, dl_worker, &st, 0, NULL);
    }
    for (int t = 0; t < nthr; t++) {
        if (w[t]) { WaitForSingleObject(w[t], 600000); CloseHandle(w[t]); }
    }
    DeleteCriticalSection(&st.cs);
    fclose(st.fpart);
    st.fpart = NULL;
    int all_done = 1;
    for (int k = 0; k < st.nchunks; k++) {
        if (!chunk_bit_test(st.map, k)) { all_done = 0; break; }
    }
    free(st.map);
    if (!all_done || st.failed) {
        fprintf(stderr, "%s: download incomplete for %s\n", peer_log_id(), data_fname);
        return -1;
    }
    {
        char finalpath[MAX_PATH_LEN];
        if (!file_path_join(shared_folder, data_fname, finalpath, sizeof(finalpath))) return -1;
        remove(finalpath);
        if (rename(st.part_path, finalpath) != 0) { fprintf(stderr, "rename part failed err=%d\n", errno); return -1; }
    }
    {
        char m[33];
        long sz;
        char p[MAX_PATH_LEN];
        if (file_path_join(shared_folder, data_fname, p, sizeof(p)) && compute_file_md5(p, m, &sz) == 0) {
            if (_stricmp(m, expect_md5) == 0) {
                remove(st.map_path);
                remove(st.track_cache_path);
                printf("%s: file %s download complete, MD5 ok\n", peer_log_id(), data_fname);
            } else {
                fprintf(stderr, "[%s] MD5 mismatch after download for %s\n", peer_log_id(), data_fname);
                return -1;
            }
        }
    }
    return 0;
}

static void try_auto_downloads_from_list(void) {
    for (int i = 0; i < num_available_files; i++) {
        const char *tname = available_files[i].name;
        if (strstr(tname, ".track") == NULL) continue;
        char *body = NULL;
        size_t blen = 0;
        if (get_tracker_file_via_get(tname, &body, &blen) != 0) continue;
        char tdir[MAX_PATH_LEN];
        if (ensure_track_cache_dir(tdir, sizeof(tdir)) == 0) {
            char cache[MAX_PATH_LEN];
            if (file_path_join(tdir, tname, cache, sizeof(cache))) {
                FILE *c = fopen(cache, "wb");
                if (c) { fwrite(body, 1, blen, c); fclose(c); }
            }
        }
        char df[256], md5[33];
        long fsz;
        struct PeerInfo peers[MAX_TRACK_PEERS];
        int np = 0;
        if (parse_track_text(body, df, &fsz, md5, peers, &np) != 0) {
            free(body);
            continue;
        }
        free(body);
        /* Spec: "Peer3: Get movie1.avi" (data filename after resolving .track). */
        printf("%s: Get %s\n", peer_log_id(), df);
        run_download_data_file(df, tname, fsz, md5, peers, np);
    }
}

static unsigned __stdcall refresh_thread(void *unused) {
    (void)unused;

    for (;;) {
        if (g_auto_stop) break;

        socket_t sock;
        if (connect_to_tracker(&sock) != 0) {
            fprintf(stderr, "[%s] List (connect failed, retry later)\n", peer_log_id());
            Sleep(refresh_interval * 1000);
            continue;
        }

        /* Spec: "Peer4: List" */
        printf("%s: List\n", peer_log_id());

        const char *req = "<REQ LIST>\n";
        if (send_all(sock, req, strlen(req)) != 0) {
            CLOSESOCK(sock);
            Sleep(refresh_interval * 1000);
            continue;
        }

        num_available_files = 0;
        char line[4096];
        int expect_num = -1;
        int saw_end = 0;
        while (recv_line(sock, line, sizeof(line)) > 0) {
            trim_eol(line);
            if (strstr(line, "<REP LIST END>") == line) {
                saw_end = 1;
                break;
            } else if (strstr(line, "<REP LIST ") == line) {
                sscanf(line, "<REP LIST %d>", &expect_num);
            } else if (num_available_files < 100 && expect_num > 0 && sscanf(line, "<%*d %255s %ld %32s>", available_files[num_available_files].name, &available_files[num_available_files].size, available_files[num_available_files].md5) == 3) {
                num_available_files++;
            }
        }
        CLOSESOCK(sock);

        if (!saw_end) fprintf(stderr, "[%s] List incomplete response\n", peer_log_id());
        else {
            /* CS4390: after <REQ LIST>, for incomplete local files, GET latest .track and run P2P (project PDF). */
            try_auto_downloads_from_list();
        }
        send_periodic_updatetracker_for_local_files();

        Sleep(refresh_interval * 1000);
    }
    return 0;
}

static void stop_auto_threads(void) {
    InterlockedExchange(&g_auto_stop, 1);
    if (g_refresh_thread) {
        WaitForSingleObject(g_refresh_thread, 15000);
        CloseHandle(g_refresh_thread);
        g_refresh_thread = NULL;
    }
    if (g_monitor_thread) {
        WaitForSingleObject(g_monitor_thread, 15000);
        CloseHandle(g_monitor_thread);
        g_monitor_thread = NULL;
    }
}

static BOOL WINAPI console_ctrl_handler(DWORD ctrlType) {
    if (ctrlType == CTRL_C_EVENT || ctrlType == CTRL_CLOSE_EVENT || ctrlType == CTRL_BREAK_EVENT) {
        InterlockedExchange(&g_auto_stop, 1);
        stop_peer_server();
        stop_auto_threads();
        return TRUE;
    }
    return FALSE;
}

int main(int argc, char *argv[]) {
    char server_address[64];
    load_client_config(); // Laods info from clientThreadconfig.cfg
    load_server_config(); // Laods info from serverThreadconfig.cfg

    struct sockaddr_in server_addr;
    socket_t sockid;

    printf("Tracker: %s:%d, Peer listen: %d, Shared: %s, Interval: %d\n",
        tracker_ip, tracker_port, peer_listen_port, shared_folder, refresh_interval);

    /* Initialize Winsock once before using any socket API on Windows. */
    WSADATA wsa_data;
    int wsa_err = WSAStartup(MAKEWORD(2, 2), &wsa_data);
    if (wsa_err != 0) {
        fprintf(stderr, "WSAStartup failed with error %d\n", wsa_err);
        return EXIT_FAILURE;
    }

    if (start_peer_server() != 0) {
        fprintf(stderr, "Note: P2P listen server disabled; tracker-only mode for this run.\n");
    }

    /* Create a TCP socket (IPv4, stream). */
    sockid = socket(AF_INET, SOCK_STREAM, 0);
    if (sockid == INVALID_SOCKET) {
        fprintf(stderr, "socket cannot be created\n");
        stop_peer_server();
        WSACleanup();
        return EXIT_FAILURE;
    }

    /* Tracker address comes from clientThreadConfig.cfg */
    strncpy(server_address, tracker_ip, sizeof(server_address) - 1);
    server_address[sizeof(server_address) - 1] = '\0';

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;              /* IPv4 */
    server_addr.sin_port   = htons(tracker_port);  /* host to network byte order */

    if (inet_pton(AF_INET, server_address, &server_addr.sin_addr) <= 0) {
        fprintf(stderr, "Invalid server address: %s\n", server_address);
        CLOSESOCK(sockid);
        stop_peer_server();
        WSACleanup();
        return EXIT_FAILURE;
    }

    /* Connect to the tracker server. */
    if (connect(sockid, (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0) {
        fprintf(stderr, "Cannot connect to server\n");
        CLOSESOCK(sockid);
        stop_peer_server();
        WSACleanup();
        return EXIT_FAILURE;
    }

    char local_ip[64];
    get_local_ip_for_socket(sockid, local_ip, sizeof(local_ip));
    strncpy(g_local_ip, local_ip, sizeof(g_local_ip) - 1);
    g_local_ip[sizeof(g_local_ip) - 1] = '\0';
    CLOSESOCK(sockid);
    sockid = INVALID_SOCKET;

    /*
        Auto mode: scan the shared folder, register new files with the tracker,
        and keep refreshing the tracker list periodically.
    */
    if (argc == 1 || (argc > 1 && !strcmp(argv[1], "auto"))) {
        if (!SetConsoleCtrlHandler(console_ctrl_handler, TRUE)) {
            fprintf(stderr, "Warning: unable to install Ctrl-C handler\n");
        }

        num_local_files = 0;
        scan_shared_folder_to_list(local_files, &num_local_files);
        register_local_files();

        uintptr_t refresh_th = _beginthreadex(NULL, 0, refresh_thread, NULL, 0, NULL);
        if (refresh_th == 0) {
            fprintf(stderr, "[auto] refresh thread failed\n");
        } else {
            g_refresh_thread = (HANDLE)refresh_th;
        }

        uintptr_t monitor_th = _beginthreadex(NULL, 0, monitor_thread, NULL, 0, NULL);
        if (monitor_th == 0) {
            fprintf(stderr, "[auto] monitor thread failed\n");
        } else {
            g_monitor_thread = (HANDLE)monitor_th;
        }

        printf("Auto mode running. Press Ctrl-C to stop.\n");
        while (!g_auto_stop) {
            Sleep(1000);
        }

        stop_auto_threads();
        stop_peer_server();
        WSACleanup();
        return EXIT_SUCCESS;
    }

    /*
        The following are the manual commands
        TODO: Need to make them automatic.
    */
    if (connect_to_tracker(&sockid) != 0) {
        fprintf(stderr, "Cannot connect to server\n");
        stop_peer_server();
        WSACleanup();
        return EXIT_FAILURE;
    }

    if (argc > 1 && !strcmp(argv[1], "list")) {
        /* Send LIST request to the tracker. */
        printf("%s: List\n", peer_log_id());
        const char *req = "<REQ LIST>\n";
        if (send_all(sockid, req, strlen(req)) != 0) {
            fprintf(stderr, "Send <REQ LIST> failure\n");
            CLOSESOCK(sockid);
            stop_peer_server();
            WSACleanup();
            return EXIT_FAILURE;
        }

        /* Read and print lines until "<REP LIST END>". */
        char line[4096];
        for (;;) {
            int n = recv_line(sockid, line, sizeof(line));
            if (n <= 0) {
                fprintf(stderr, "Read LIST reply failure\n");
                CLOSESOCK(sockid);
                stop_peer_server();
                WSACleanup();
                return EXIT_FAILURE;
            }
            trim_eol(line);
            printf("%s\n", line);
            if (!strcmp(line, "<REP LIST END>")) break;
        }
    } else if (argc > 2 && !strcmp(argv[1], "get")) {
        printf("%s: Get %s\n", peer_log_id(), argv[2]);
        char req[512];
        snprintf(req, sizeof(req), "<GET %s >\n", argv[2]);
        if (send_all(sockid, req, strlen(req)) != 0) {
            fprintf(stderr, "Send GET failure\n");
            CLOSESOCK(sockid);
            stop_peer_server();
            WSACleanup();
            return EXIT_FAILURE;
        }

        /* Print GET response until REP GET END is received. */
        char line[4096];
        for (;;) {
            int n = recv_line(sockid, line, sizeof(line));
            if (n <= 0) {
                fprintf(stderr, "Read GET reply failure\n");
                CLOSESOCK(sockid);
                stop_peer_server();
                WSACleanup();
                return EXIT_FAILURE;
            }
            trim_eol(line);
            printf("%s\n", line);
            if (strstr(line, "<REP GET END ") == line) break;
        }
    } else if (argc > 5 && !strcmp(argv[1], "createtracker")) {
        /* Uses local peer_listen_port from serverThreadConfig.cfg as required by protocol. */
        char req[1024];
        snprintf(req, sizeof(req), "<createtracker %s %s %s %s %s %d>\n",
                 argv[2], argv[3], argv[4], argv[5], local_ip, peer_listen_port);
        if (send_all(sockid, req, strlen(req)) != 0) {
            fprintf(stderr, "Send createtracker failure\n");
            CLOSESOCK(sockid);
            stop_peer_server();
            WSACleanup();
            return EXIT_FAILURE;
        }

        char line[4096];
        int n = recv_line(sockid, line, sizeof(line));
        if (n <= 0) {
            fprintf(stderr, "Read createtracker reply failure\n");
            CLOSESOCK(sockid);
            stop_peer_server();
            WSACleanup();
            return EXIT_FAILURE;
        }
        trim_eol(line);
        if (strstr(line, "<createtracker succ>") || strstr(line, "<createtracker ferr>")) {
            printf("%s: createtracker %s %s %s %s %s %d\n",
                   peer_log_id(), argv[2], argv[3], argv[4], argv[5], local_ip, peer_listen_port);
        } else {
            printf("%s\n", line);
        }
    } else if (argc > 4 && !strcmp(argv[1], "updatetracker")) {
        char req[1024];
        snprintf(req, sizeof(req), "<updatetracker %s %s %s %s %d>\n",
                 argv[2], argv[3], argv[4], local_ip, peer_listen_port);
        if (send_all(sockid, req, strlen(req)) != 0) {
            fprintf(stderr, "Send updatetracker failure\n");
            CLOSESOCK(sockid);
            stop_peer_server();
            WSACleanup();
            return EXIT_FAILURE;
        }

        char line[4096];
        int n = recv_line(sockid, line, sizeof(line));
        if (n <= 0) {
            fprintf(stderr, "Read updatetracker reply failure\n");
            CLOSESOCK(sockid);
            stop_peer_server();
            WSACleanup();
            return EXIT_FAILURE;
        }
        trim_eol(line);
        printf("%s\n", line);
    }

    if (sockid != INVALID_SOCKET) {
        CLOSESOCK(sockid);
    }
    printf("Connection closed\n");

    stop_peer_server();
    WSACleanup();

    return EXIT_SUCCESS;
}
