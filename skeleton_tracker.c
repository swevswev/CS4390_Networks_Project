#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

/*
 * Cross‑platform socket includes and typedefs.
 * - On Linux / POSIX, we retain the original fork‑based, multi‑process skeleton.
 * - On Windows, this file currently only provides a stub main that tells you the
 *   tracker is not yet implemented; you can later replace it with a threaded
 *   implementation if desired.
 */
#ifdef _WIN32
  #ifndef WIN32_LEAN_AND_MEAN
    #define WIN32_LEAN_AND_MEAN
  #endif
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #include <direct.h>
  #include <windows.h>
  #include <stdint.h>

  typedef SOCKET socket_t;
  #define CLOSESOCK(s) closesocket(s)
#else
  #include <unistd.h>
  #include <errno.h>
  #include <sys/types.h>
  #include <sys/socket.h>
  #include <netinet/in.h>
  #include <arpa/inet.h>
  #include <dirent.h>

  typedef int socket_t;
  #define CLOSESOCK(s) close(s)
#endif

/* Placeholder values and buffers that the original skeleton assumed existed.
 */
#define MAXLINE 4096

static int server_port = 3490;   /* TODO: read from tracker config file. */
static char read_msg[MAXLINE];
static char fname[256];

static void strip_comment_line(char *line) {
    char *hash = strchr(line, '#');
    if (hash) *hash = '\0';
}

/* Parse the first integer found anywhere on the line. Returns 1 if found. */
static int first_int_in_line(const char *line, int *out_val) {
    while (*line) {
        if ((*line >= '0' && *line <= '9') || *line == '-' || *line == '+') {
            char *end = NULL;
            long v = strtol(line, &end, 10);
            if (end != line) {
                *out_val = (int)v;
                return 1;
            }
        }
        line++;
    }
    return 0;
}

/* Tracker listens on the same port your peer config uses (clientThreadConfig.cfg line 2). */
static int load_tracker_port_from_client_config(void) {
    FILE *f = fopen("clientThreadConfig.cfg", "r");
    char line[256];
    int port = 5000; /* default */
    if (!f) return port;

    /* Line 1: IP (ignored) */
    if (!fgets(line, sizeof(line), f)) { fclose(f); return port; }
    strip_comment_line(line);

    /* Line 2: port */
    if (fgets(line, sizeof(line), f)) {
        strip_comment_line(line);
        int tmp;
        if (first_int_in_line(line, &tmp) && tmp > 0) port = tmp;
    }

    fclose(f);
    return port;
}

/* Forward declaration of the per‑client handler for POSIX builds. */
static void peer_handler(int sock_child);


#ifdef _WIN32

static const char *TRACKER_DIR = "tracker_shared";

/* --- Minimal MD5 implementation (same as peer) --- */
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

static int send_all(socket_t s, const char *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        int n = send(s, buf + off, (int)(len - off), 0);
        if (n <= 0) return -1;
        off += (size_t)n;
    }
    return 0;
}

static int recv_line(socket_t s, char *out, size_t cap) {
    size_t used = 0;
    while (used + 1 < cap) {
        char ch;
        int n = recv(s, &ch, 1, 0);
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

static void trim_angle(char *s) {
    trim_eol(s);
    /* Trim leading spaces */
    while (*s == ' ' || *s == '\t') memmove(s, s + 1, strlen(s));
    if (s[0] == '<') memmove(s, s + 1, strlen(s));
    size_t n = strlen(s);
    if (n && s[n - 1] == '>') s[n - 1] = '\0';
}

static void ensure_tracker_dir(void) {
    _mkdir(TRACKER_DIR);
}

static int file_exists(const char *path) {
    FILE *f = fopen(path, "rb");
    if (f) { fclose(f); return 1; }
    return 0;
}

static void tracker_path_for(const char *track_name, char out[512]) {
    snprintf(out, 512, "%s\\%s", TRACKER_DIR, track_name);
}

static void handle_createtracker(socket_t client, char *line) {
    /* Expected: <createtracker filename filesize description md5 ip port>\n */
    trim_angle(line);

    /* Tokenize by spaces; we assume description has no spaces (use underscores). */
    char *tokens[32];
    int nt = 0;
    char *p = strtok(line, " ");
    while (p && nt < 32) { tokens[nt++] = p; p = strtok(NULL, " "); }

    if (nt < 7) {
        send_all(client, "<createtracker fail>\n", strlen("<createtracker fail>\n"));
        return;
    }

    const char *filename = tokens[1];
    const char *filesize = tokens[2];
    const char *desc = tokens[3];
    const char *md5 = tokens[4];
    const char *ip = tokens[5];
    const char *port = tokens[6];

    char track_name[300];
    /* If client already passed .track, keep it; otherwise append */
    size_t fl = strlen(filename);
    if (fl >= 6 && strcmp(filename + fl - 6, ".track") == 0) {
        snprintf(track_name, sizeof(track_name), "%s", filename);
    } else {
        snprintf(track_name, sizeof(track_name), "%s.track", filename);
    }

    ensure_tracker_dir();
    char path[512];
    tracker_path_for(track_name, path);

    if (file_exists(path)) {
        send_all(client, "<createtracker ferr>\n", strlen("<createtracker ferr>\n"));
        return;
    }

    FILE *f = fopen(path, "wb");
    if (!f) {
        send_all(client, "<createtracker fail>\n", strlen("<createtracker fail>\n"));
        return;
    }

    /* Minimal tracker file content (format can be adjusted later). */
    fprintf(f, "filename %s\n", filename);
    fprintf(f, "filesize %s\n", filesize);
    fprintf(f, "description %s\n", desc);
    fprintf(f, "md5 %s\n", md5);
    fprintf(f, "peer %s %s\n", ip, port);
    fclose(f);

    send_all(client, "<createtracker succ>\n", strlen("<createtracker succ>\n"));
}

static int read_entire_file(const char *path, char **out_buf, size_t *out_len) {
    FILE *f = fopen(path, "rb");
    long sz;
    size_t nread;
    char *buf;
    if (!f) return -1;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return -1; }
    sz = ftell(f);
    if (sz < 0) { fclose(f); return -1; }
    if (fseek(f, 0, SEEK_SET) != 0) { fclose(f); return -1; }
    buf = (char *)malloc((size_t)sz + 1);
    if (!buf) { fclose(f); return -1; }
    nread = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    if (nread != (size_t)sz) { free(buf); return -1; }
    buf[(size_t)sz] = '\0';
    *out_buf = buf;
    *out_len = (size_t)sz;
    return 0;
}

static void handle_list(socket_t client) {
    ensure_tracker_dir();

    char search[512];
    snprintf(search, sizeof(search), "%s\\*.track", TRACKER_DIR);

    WIN32_FIND_DATAA ffd;
    HANDLE h = FindFirstFileA(search, &ffd);

    int count = 0;
    if (h != INVALID_HANDLE_VALUE) {
        do {
            if (!(ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) count++;
        } while (FindNextFileA(h, &ffd));
        FindClose(h);
    }

    char header[64];
    snprintf(header, sizeof(header), "<REP LIST %d>\n", count);
    send_all(client, header, strlen(header));

    if (count > 0) {
        h = FindFirstFileA(search, &ffd);
        if (h != INVALID_HANDLE_VALUE) {
            int idx = 1;
            do {
                if (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
                char path[512];
                tracker_path_for(ffd.cFileName, path);
                char *content = NULL;
                size_t content_len = 0;
                if (read_entire_file(path, &content, &content_len) == 0) free(content);

                char md5hex[33] = "00000000000000000000000000000000";
                if (content) {
                    md5_bytes_hex(content, content_len, md5hex);
                }
                char line[1024];
                snprintf(line, sizeof(line), "<%d %s %lu %s>\n",
                         idx++, ffd.cFileName, (unsigned long)content_len, md5hex);
                send_all(client, line, strlen(line));
            } while (FindNextFileA(h, &ffd));
            FindClose(h);
        }
    }

    send_all(client, "<REP LIST END>\n", strlen("<REP LIST END>\n"));
}

static void handle_get(socket_t client, char *line) {
    /* Expected: <GET filename.track >\n */
    trim_angle(line);
    if (strncmp(line, "GET ", 4) != 0 && strncmp(line, "get ", 4) != 0) {
        send_all(client,
                 "<REP GET BEGIN>\n<REP GET END 00000000000000000000000000000000>\n",
                 strlen("<REP GET BEGIN>\n<REP GET END 00000000000000000000000000000000>\n"));
        return;
    }

    char *name = line + 4;
    while (*name == ' ') name++;
    for (int i = (int)strlen(name) - 1; i >= 0 && (name[i] == ' ' || name[i] == '\t'); i--) name[i] = '\0';

    ensure_tracker_dir();
    char path[512];
    tracker_path_for(name, path);

    char *content = NULL;
    size_t content_len = 0;
    if (read_entire_file(path, &content, &content_len) != 0) {
        send_all(client,
                 "<REP GET BEGIN>\n<REP GET END 00000000000000000000000000000000>\n",
                 strlen("<REP GET BEGIN>\n<REP GET END 00000000000000000000000000000000>\n"));
        return;
    }

    char md5hex[33];
    md5_bytes_hex(content, content_len, md5hex);

    send_all(client, "<REP GET BEGIN>\n", strlen("<REP GET BEGIN>\n"));
    send_all(client, content, content_len);
    if (content_len == 0 || content[content_len - 1] != '\n') send_all(client, "\n", 1);
    char endline[128];
    snprintf(endline, sizeof(endline), "<REP GET END %s>\n", md5hex);
    send_all(client, endline, strlen(endline));
    free(content);
}

int main(void) {
    WSADATA wsa;
    socket_t listen_sock, client_sock;
    struct sockaddr_in addr;
    int port = load_tracker_port_from_client_config(); /* must match clientThreadConfig.cfg */
    char line[4096];

    if (WSAStartup(MAKEWORD(2,2), &wsa) != 0) {
        fprintf(stderr, "WSAStartup failed\n");
        return EXIT_FAILURE;
    }

    listen_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_sock == INVALID_SOCKET) {
        fprintf(stderr, "socket() failed\n");
        WSACleanup();
        return EXIT_FAILURE;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(listen_sock, (struct sockaddr *)&addr, sizeof(addr)) == SOCKET_ERROR) {
        fprintf(stderr, "bind() failed\n");
        CLOSESOCK(listen_sock);
        WSACleanup();
        return EXIT_FAILURE;
    }

    if (listen(listen_sock, 5) == SOCKET_ERROR) {
        fprintf(stderr, "listen() failed\n");
        CLOSESOCK(listen_sock);
        WSACleanup();
        return EXIT_FAILURE;
    }

    printf("Tracker listening on port %d\n", port);

    for (;;) {
        struct sockaddr_in caddr;
        int clen = sizeof(caddr);
        client_sock = accept(listen_sock, (struct sockaddr *)&caddr, &clen);
        if (client_sock == INVALID_SOCKET) {
            fprintf(stderr, "accept() failed\n");
            continue;
        }

        int n = recv_line(client_sock, line, sizeof(line));
        if (n > 0) {
            if (strstr(line, "REQ LIST") != NULL) {
                handle_list(client_sock);
            } else if (strstr(line, "GET") != NULL || strstr(line, "get") != NULL) {
                handle_get(client_sock, line);
            } else if (strstr(line, "createtracker") != NULL || strstr(line, "CREATETRACKER") != NULL) {
                handle_createtracker(client_sock, line);
            }
        }

        CLOSESOCK(client_sock);
    }

    CLOSESOCK(listen_sock);
    WSACleanup();
    return EXIT_SUCCESS;
}

#else  /* POSIX implementation */

/*
 * POSIX tracker skeleton:
 *  - Creates a TCP listening socket.
 *  - Accepts incoming connections in a loop.
 *  - Forks a child process per client and dispatches to peer_handler().
 */
int main(void) {
    pid_t pid;
    struct sockaddr_in server_addr, client_addr;
    socket_t sockid, sock_child;
    socklen_t clilen = sizeof(client_addr);

    /* Create a TCP socket (IPv4, stream). */
    sockid = socket(AF_INET, SOCK_STREAM, 0);
    if (sockid < 0) {
        printf("socket cannot be created \n");
        exit(0);
    }

    /* Bind the socket to a local port to listen for incoming connections. */
    server_port = load_tracker_port_from_client_config();
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family      = AF_INET;               /* IPv4 */
    server_addr.sin_port        = htons(server_port);    /* host to network byte order */
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);     /* listen on all interfaces */

    if (bind(sockid, (struct sockaddr *) &server_addr, sizeof(server_addr)) == -1) {
        printf("bind  failure\n");
        exit(0);
    }

    printf("Tracker SERVER READY TO LISTEN INCOMING REQUEST.... \n");

    /* Start listening; backlog size is arbitrary here (10). */
    if (listen(sockid, 10) < 0) {
        printf(" Tracker  SERVER CANNOT LISTEN\n");
        exit(0);
    }

    /* Accept connections from clients in an infinite loop. */
    while (1) {
        sock_child = accept(sockid, (struct sockaddr *) &client_addr, &clilen);
        if (sock_child < 0) {
            printf("Tracker Cannot accept...\n");
            exit(0);
        }

        /* Fork a child process to handle this particular client. */
        pid = fork();
        if (pid == 0) {
            /* Child process: no need for the listening socket. */
            CLOSESOCK(sockid);
            peer_handler(sock_child);      /* Serve this client.           */
            CLOSESOCK(sock_child);
            exit(0);                       /* Child done.                  */
        }

        /* Parent process: close the connected socket, child is handling it. */
        CLOSESOCK(sock_child);
    }

    /* Not reached in this skeleton. */
    CLOSESOCK(sockid);
    return 0;
}


/*
 * peer_handler:
 *  Child process function to handle a single connected peer.
 *  It:
 *   - Reads a single line/command from the client.
 *   - Dispatches to appropriate handler based on the protocol.
 */
static void peer_handler(int sock_child) {
    int length;

    /* Read a command from the peer. */
    length = (int) read(sock_child, read_msg, MAXLINE - 1);
    if (length <= 0) {
        return;
    }
    read_msg[length] = '\0';

    /* LIST command received. */
    if ((!strcmp(read_msg, "REQ LIST")) ||
        (!strcmp(read_msg, "req list")) ||
        (!strcmp(read_msg, "<REQ LIST>")) ||
        (!strcmp(read_msg, "<REQ LIST>\n"))) {
        /* TODO: implement handle_list_req(sock_child) according to the spec. */
        /* handle_list_req(sock_child); */
        printf("list request handled (skeleton).\n");
    }
    /* GET command received. */
    else if ((strstr(read_msg, "get") != NULL) ||
             (strstr(read_msg, "GET") != NULL)) {
        /* TODO: xtrct_fname(read_msg, " ");              */
        /* TODO: handle_get_req(sock_child, fname);       */
    }
    /* createtracker command received. */
    else if ((strstr(read_msg, "createtracker")   != NULL) ||
             (strstr(read_msg, "Createtracker")   != NULL) ||
             (strstr(read_msg, "CREATETRACKER")   != NULL)) {
        /* TODO: tokenize_createmsg(read_msg);            */
        /* TODO: handle_createtracker_req(sock_child);    */
    }
    /* updatetracker command received. */
    else if ((strstr(read_msg, "updatetracker")   != NULL) ||
             (strstr(read_msg, "Updatetracker")   != NULL) ||
             (strstr(read_msg, "UPDATETRACKER")   != NULL)) {
        /* TODO: tokenize_updatemsg(read_msg);            */
        /* TODO: handle_updatetracker_req(sock_child);    */
    }
}

#endif  /* !_WIN32 */