#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * Cross‑platform socket includes and typedefs.
 * - On Windows (MinGW / MSVC), use Winsock2 and call WSAStartup/WSACleanup.
 * - On Linux / POSIX, use BSD socket headers.
 */
#ifdef _WIN32
  #ifndef WIN32_LEAN_AND_MEAN
    #define WIN32_LEAN_AND_MEAN
  #endif
  #include <winsock2.h>
  #include <ws2tcpip.h>

  /* Link with Winsock library when using MSVC.
   * With MinGW, the Makefile will add -lws2_32 instead. */
  #ifdef _MSC_VER
    #pragma comment(lib, "Ws2_32.lib")
  #endif

  typedef SOCKET socket_t;
  #define CLOSESOCK(s) closesocket(s)
#else
  #include <unistd.h>
  #include <sys/types.h>
  #include <sys/socket.h>
  #include <netinet/in.h>
  #include <arpa/inet.h>

  typedef int socket_t;
  #define CLOSESOCK(s) close(s)
#endif

/* NOTE:
 * The assignment skeleton assumes the existence of a LIST constant and a msg buffer to receive the server reply.
 * Here we declare minimal placeholders so the file compiles.
 * TODO: replace these with the real protocol structures that follow the project design.
 */
#ifndef LIST
#define LIST 1
#endif

static int msg = 0;

/* Configuration values */
#define MAX_PATH_LEN 260
char shared_folder[MAX_PATH_LEN] = "./sharedFolder";
char tracker_ip[64] = "127.0.0.1";
int  tracker_port = 5000;
int  refresh_interval = 900; 
int peer_listen_port = 6000;

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
        first_token_as_string(line, tracker_ip, sizeof(tracker_ip));
    }
    if (fgets(line, sizeof(line), f)) {
        strip_comment(line);
        first_token_as_int(line, &tracker_port);
    }
    if (fgets(line, sizeof(line), f)) {
        strip_comment(line);
        int tmp;
        if (first_token_as_int(line, &tmp) && tmp > 0)
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
        first_token_as_int(line, &peer_listen_port);
    }

    if (fgets(line, sizeof(line), f)) {
        strip_comment(line);
        first_token_as_string(line, shared_folder, sizeof(shared_folder));
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

int main(int argc, char *argv[]) {
    char server_address[64];
    load_client_config();
    load_server_config();

    struct sockaddr_in server_addr;
    socket_t sockid;

    printf("Tracker: %s:%d, Peer listen: %d, Shared: %s, Interval: %d\n",
        tracker_ip, tracker_port, peer_listen_port, shared_folder, refresh_interval);

#ifdef _WIN32
    /* Initialize Winsock once before using any socket API on Windows. */
    WSADATA wsa_data;
    int wsa_err = WSAStartup(MAKEWORD(2, 2), &wsa_data);
    if (wsa_err != 0) {
        fprintf(stderr, "WSAStartup failed with error %d\n", wsa_err);
        return EXIT_FAILURE;
    }
#endif

    /* Create a TCP socket (IPv4, stream). */
    sockid = socket(AF_INET, SOCK_STREAM, 0);
    if (sockid == (socket_t) -1
#ifdef _WIN32
        || sockid == INVALID_SOCKET
#endif
    ) {
        fprintf(stderr, "socket cannot be created\n");
#ifdef _WIN32
        WSACleanup();
#endif
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
#ifdef _WIN32
        WSACleanup();
#endif
        return EXIT_FAILURE;
    }

    /* Connect to the tracker server. */
    if (connect(sockid, (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0) {
        fprintf(stderr, "Cannot connect to server\n");
        CLOSESOCK(sockid);
#ifdef _WIN32
        WSACleanup();
#endif
        return EXIT_FAILURE;
    }

    if (argc > 1 && !strcmp(argv[1], "list")) {
        /* Send LIST request to the tracker. */
        const char *req = "<REQ LIST>\n";
        if (send_all(sockid, req, strlen(req)) != 0) {
            fprintf(stderr, "Send <REQ LIST> failure\n");
            CLOSESOCK(sockid);
#ifdef _WIN32
            WSACleanup();
#endif
            return EXIT_FAILURE;
        }

        /* Read and print lines until "<REP LIST END>". */
        char line[4096];
        for (;;) {
            int n = recv_line(sockid, line, sizeof(line));
            if (n <= 0) {
                fprintf(stderr, "Read LIST reply failure\n");
                CLOSESOCK(sockid);
#ifdef _WIN32
                WSACleanup();
#endif
                return EXIT_FAILURE;
            }
            trim_eol(line);
            printf("%s\n", line);
            if (!strcmp(line, "<REP LIST END>")) break;
        }
    }

    CLOSESOCK(sockid);
    printf("Connection closed\n");

#ifdef _WIN32
    WSACleanup();
#endif

    return EXIT_SUCCESS;
}
