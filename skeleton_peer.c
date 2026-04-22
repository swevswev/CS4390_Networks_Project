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

/* Link with Winsock library when using MSVC.
 * With MinGW, the Makefile links using -lws2_32. */
#ifdef _MSC_VER
#pragma comment(lib, "Ws2_32.lib")
#endif

typedef SOCKET socket_t;
#define CLOSESOCK(s) closesocket(s)

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
        return 0;
    }
    return -1;
}

static void register_local_files(void) {
    for (int i = 0; i < num_local_files; i++) {
        const char *name = base_name(local_files[i].path);
        if (strchr(name, ' ')) {
            printf("[auto] skipping file with spaces: %s\n", name);
            continue;
        }

        printf("[auto] registering %s size=%ld md5=%s\n", name, local_files[i].size, local_files[i].md5);
        if (send_tracker_createtracker(name, local_files[i].size, local_files[i].md5, g_local_ip) != 0) {
            printf("[auto] tracker registration failed for %s\n", name);
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
                printf("[monitor] registered new file %s with tracker\n", name);
            } else {
                printf("[monitor] failed to register new file %s\n", name);
            }
        } else if (!local_files_equal(&new_files[i], &local_files[idx])) {
            printf("[monitor] changed file detected: %s\n", name);
        }
    }

    memcpy(local_files, new_files, sizeof(new_files));
    num_local_files = new_count;
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
        trim_eol(line);
        printf("[peer-server] request: %s\n", line);
        /* Stub: real P2P chunk GET / 1024-byte limit comes later; keep connection protocol-friendly. */
        const char *stub = "<peer p2p stub: not implemented>\n";
        (void)send_all(client, stub, strlen(stub));
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

static unsigned __stdcall refresh_thread(void *unused) {
    (void)unused;
    printf("[refresh] Starting periodic tracker LIST every %d s\n", refresh_interval);

    for (;;) {
        if (g_auto_stop) break;

        socket_t sock;
        if (connect_to_tracker(&sock) != 0) {
            printf("[refresh] Connect failed, retry later\n");
            Sleep(refresh_interval * 1000);
            continue;
        }

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
            if (strstr(line, "<REP LIST ") == line) {
                sscanf(line, "<REP LIST %d>", &expect_num);
            } else if (strstr(line, "<REP LIST END>") == line) {
                saw_end = 1;
                break;
            } else if (num_available_files < 100 && expect_num > 0 && sscanf(line, "<%*d %255s %ld %32s>", available_files[num_available_files].name, &available_files[num_available_files].size, available_files[num_available_files].md5) == 3) {
                printf("[refresh] Found %s size=%ld md5=%s\n", available_files[num_available_files].name, available_files[num_available_files].size, available_files[num_available_files].md5);
                num_available_files++;
            }
        }
        CLOSESOCK(sock);

        if (!saw_end) printf("[refresh] Incomplete LIST response\n");

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

    if (argc > 1 && !strcmp(argv[1], "list")) {
        /* Send LIST request to the tracker. */
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
        printf("%s\n", line);
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

    CLOSESOCK(sockid);
    printf("Connection closed\n");

    stop_peer_server();
    WSACleanup();

    return EXIT_SUCCESS;
}
