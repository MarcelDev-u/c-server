#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>
#include <CommonCrypto/CommonDigest.h>

#define PORT 8080
#define REQUEST_BUF_SIZE 8192
#define MAX_ROUTES 128
#define MAX_PATH_LEN 512
#define MAX_WS_CLIENTS 128
#define MAX_NAME_LEN 64
#define MAX_WS_PAYLOAD 4096

// Route mapping loaded from config file:
//   url_path -> html file path inside ./public
typedef struct {
    char url_path[MAX_PATH_LEN];
    char file_path[MAX_PATH_LEN];
} Route;

// Connected WebSocket chat client.
typedef struct {
    int fd;
    char name[MAX_NAME_LEN];
} WsClient;

static const char *WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

static int send_all(int fd, const void *buf, size_t len) {
    const char *p = (const char *)buf;
    while (len > 0) {
        ssize_t n = send(fd, p, len, 0);
        if (n <= 0) {
            return -1;
        }
        p += n;
        len -= (size_t)n;
    }
    return 0;
}

static void send_error_response(int client_fd, int status_code, const char *reason, const char *message) {
    char body[256];
    int body_len = snprintf(body, sizeof(body), "%d %s\n%s\n", status_code, reason, message);
    if (body_len < 0) {
        return;
    }

    char header[512];
    int header_len = snprintf(
        header,
        sizeof(header),
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: text/plain; charset=utf-8\r\n"
        "Content-Length: %d\r\n"
        "Connection: close\r\n"
        "\r\n",
        status_code,
        reason,
        body_len
    );

    if (header_len > 0) {
        send_all(client_fd, header, (size_t)header_len);
        send_all(client_fd, body, (size_t)body_len);
    }
}

static int load_routes(const char *config_path, Route *routes, int max_routes) {
    FILE *f = fopen(config_path, "r");
    if (!f) {
        perror("fopen routes.conf");
        return -1;
    }

    char line[1024];
    int count = 0;

    while (fgets(line, sizeof(line), f)) {
        char *p = line;
        while (*p == ' ' || *p == '\t') {
            p++;
        }

        if (*p == '#' || *p == '\n' || *p == '\0') {
            continue;
        }

        char url[MAX_PATH_LEN];
        char file[MAX_PATH_LEN];

        if (sscanf(p, "%511s %511s", url, file) != 2) {
            continue;
        }

        if (count >= max_routes) {
            fprintf(stderr, "Too many routes (max %d)\n", max_routes);
            break;
        }

        if (url[0] != '/' || file[0] != '/' || strstr(file, "..") != NULL) {
            fprintf(stderr, "Ignoring invalid route: %s %s\n", url, file);
            continue;
        }

        strncpy(routes[count].url_path, url, sizeof(routes[count].url_path) - 1);
        routes[count].url_path[sizeof(routes[count].url_path) - 1] = '\0';

        strncpy(routes[count].file_path, file, sizeof(routes[count].file_path) - 1);
        routes[count].file_path[sizeof(routes[count].file_path) - 1] = '\0';

        count++;
    }

    fclose(f);
    return count;
}

static const char *find_route(const Route *routes, int route_count, const char *url_path) {
    for (int i = 0; i < route_count; i++) {
        if (strcmp(routes[i].url_path, url_path) == 0) {
            return routes[i].file_path;
        }
    }
    return NULL;
}

static int parse_request_line(const char *request, char *method, size_t method_size, char *path, size_t path_size) {
    char version[32];
    if (sscanf(request, "%15s %511s %31s", method, path, version) != 3) {
        return -1;
    }
    (void)method_size;
    (void)path_size;
    return 0;
}

static void strip_query_string(char *path) {
    char *q = strchr(path, '?');
    if (q) {
        *q = '\0';
    }
}

static int serve_html_file(int client_fd, const char *public_dir, const char *file_path) {
    const char *dot = strrchr(file_path, '.');
    if (!dot || (strcmp(dot, ".html") != 0 && strcmp(dot, ".htm") != 0)) {
        send_error_response(client_fd, 404, "Not Found", "Only .html files are served.");
        return -1;
    }

    char full_path[MAX_PATH_LEN * 2];
    int n = snprintf(full_path, sizeof(full_path), "%s%s", public_dir, file_path);
    if (n < 0 || n >= (int)sizeof(full_path)) {
        send_error_response(client_fd, 500, "Internal Server Error", "Path too long.");
        return -1;
    }

    FILE *f = fopen(full_path, "rb");
    if (!f) {
        send_error_response(client_fd, 404, "Not Found", "HTML file not found.");
        return -1;
    }

    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        send_error_response(client_fd, 500, "Internal Server Error", "fseek failed.");
        return -1;
    }

    long file_size = ftell(f);
    if (file_size < 0) {
        fclose(f);
        send_error_response(client_fd, 500, "Internal Server Error", "ftell failed.");
        return -1;
    }

    if (fseek(f, 0, SEEK_SET) != 0) {
        fclose(f);
        send_error_response(client_fd, 500, "Internal Server Error", "fseek reset failed.");
        return -1;
    }

    char *content = (char *)malloc((size_t)file_size);
    if (!content) {
        fclose(f);
        send_error_response(client_fd, 500, "Internal Server Error", "Out of memory.");
        return -1;
    }

    size_t read_bytes = fread(content, 1, (size_t)file_size, f);
    fclose(f);

    if (read_bytes != (size_t)file_size) {
        free(content);
        send_error_response(client_fd, 500, "Internal Server Error", "fread failed.");
        return -1;
    }

    char header[512];
    int header_len = snprintf(
        header,
        sizeof(header),
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/html; charset=utf-8\r\n"
        "Content-Length: %ld\r\n"
        "Connection: close\r\n"
        "\r\n",
        file_size
    );

    if (header_len < 0 || header_len >= (int)sizeof(header)) {
        free(content);
        send_error_response(client_fd, 500, "Internal Server Error", "Header build failed.");
        return -1;
    }

    int ok = 0;
    if (send_all(client_fd, header, (size_t)header_len) < 0 ||
        send_all(client_fd, content, (size_t)file_size) < 0) {
        perror("send");
        ok = -1;
    }

    free(content);
    return ok;
}

static int get_header_value(const char *request, const char *header_name, char *out, size_t out_size) {
    size_t name_len = strlen(header_name);
    const char *p = request;

    while (*p) {
        const char *line_end = strstr(p, "\r\n");
        if (!line_end) {
            break;
        }
        if (line_end == p) {
            break;
        }

        if (strncasecmp(p, header_name, name_len) == 0 && p[name_len] == ':') {
            const char *v = p + name_len + 1;
            while (*v == ' ' || *v == '\t') {
                v++;
            }
            size_t len = (size_t)(line_end - v);
            if (len >= out_size) {
                len = out_size - 1;
            }
            memcpy(out, v, len);
            out[len] = '\0';
            return 0;
        }

        p = line_end + 2;
    }

    return -1;
}

static int base64_encode(const unsigned char *in, size_t in_len, char *out, size_t out_size) {
    static const char tbl[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t i = 0;
    size_t j = 0;

    while (i < in_len) {
        unsigned int a = in[i++];
        unsigned int b = (i < in_len) ? in[i++] : 0;
        unsigned int c = (i < in_len) ? in[i++] : 0;

        if (j + 4 >= out_size) {
            return -1;
        }

        out[j++] = tbl[(a >> 2) & 0x3F];
        out[j++] = tbl[((a & 0x03) << 4) | ((b >> 4) & 0x0F)];
        out[j++] = (i - 1 <= in_len) ? tbl[((b & 0x0F) << 2) | ((c >> 6) & 0x03)] : '=';
        out[j++] = (i <= in_len) ? tbl[c & 0x3F] : '=';

        if (i == in_len + 1) {
            out[j - 1] = '=';
        }
        if (i == in_len) {
            out[j - 2] = '=';
            out[j - 1] = '=';
        }
    }

    out[j] = '\0';
    return 0;
}

static int compute_websocket_accept(const char *ws_key, char *out, size_t out_size) {
    char input[256];
    unsigned char sha1[CC_SHA1_DIGEST_LENGTH];

    int n = snprintf(input, sizeof(input), "%s%s", ws_key, WS_GUID);
    if (n < 0 || n >= (int)sizeof(input)) {
        return -1;
    }

    CC_SHA1((const unsigned char *)input, (CC_LONG)strlen(input), sha1);
    return base64_encode(sha1, sizeof(sha1), out, out_size);
}

static void url_decode_inplace(char *s) {
    char *src = s;
    char *dst = s;

    while (*src) {
        if (*src == '%' && src[1] && src[2]) {
            int hi = src[1];
            int lo = src[2];

            if (hi >= '0' && hi <= '9') hi -= '0';
            else if (hi >= 'A' && hi <= 'F') hi = hi - 'A' + 10;
            else if (hi >= 'a' && hi <= 'f') hi = hi - 'a' + 10;
            else hi = -1;

            if (lo >= '0' && lo <= '9') lo -= '0';
            else if (lo >= 'A' && lo <= 'F') lo = lo - 'A' + 10;
            else if (lo >= 'a' && lo <= 'f') lo = lo - 'a' + 10;
            else lo = -1;

            if (hi >= 0 && lo >= 0) {
                *dst++ = (char)((hi << 4) | lo);
                src += 3;
                continue;
            }
        }

        if (*src == '+') {
            *dst++ = ' ';
        } else {
            *dst++ = *src;
        }
        src++;
    }

    *dst = '\0';
}

static void extract_name_from_path(const char *raw_path, char *name_out, size_t name_out_size) {
    strncpy(name_out, "anon", name_out_size - 1);
    name_out[name_out_size - 1] = '\0';

    const char *q = strchr(raw_path, '?');
    if (!q) {
        return;
    }
    q++;

    char query[512];
    strncpy(query, q, sizeof(query) - 1);
    query[sizeof(query) - 1] = '\0';

    char *save = NULL;
    char *token = strtok_r(query, "&", &save);
    while (token) {
        if (strncmp(token, "name=", 5) == 0) {
            strncpy(name_out, token + 5, name_out_size - 1);
            name_out[name_out_size - 1] = '\0';
            url_decode_inplace(name_out);
            if (name_out[0] == '\0') {
                strncpy(name_out, "anon", name_out_size - 1);
                name_out[name_out_size - 1] = '\0';
            }
            return;
        }
        token = strtok_r(NULL, "&", &save);
    }
}

static int recv_exact(int fd, void *buf, size_t len) {
    unsigned char *p = (unsigned char *)buf;
    size_t got = 0;

    while (got < len) {
        ssize_t n = recv(fd, p + got, len - got, 0);
        if (n <= 0) {
            return -1;
        }
        got += (size_t)n;
    }

    return 0;
}

static int send_ws_text(int fd, const char *text) {
    size_t len = strlen(text);
    unsigned char header[10];
    size_t hlen = 0;

    header[0] = 0x81; // FIN + text frame

    if (len <= 125) {
        header[1] = (unsigned char)len;
        hlen = 2;
    } else if (len <= 65535) {
        header[1] = 126;
        header[2] = (unsigned char)((len >> 8) & 0xFF);
        header[3] = (unsigned char)(len & 0xFF);
        hlen = 4;
    } else {
        return -1;
    }

    if (send_all(fd, header, hlen) < 0) {
        return -1;
    }
    if (send_all(fd, text, len) < 0) {
        return -1;
    }
    return 0;
}

static void remove_ws_client(WsClient *clients, int idx) {
    if (clients[idx].fd >= 0) {
        close(clients[idx].fd);
        clients[idx].fd = -1;
        clients[idx].name[0] = '\0';
    }
}

static void broadcast_message(WsClient *clients, const char *text) {
    for (int i = 0; i < MAX_WS_CLIENTS; i++) {
        if (clients[i].fd >= 0) {
            if (send_ws_text(clients[i].fd, text) < 0) {
                remove_ws_client(clients, i);
            }
        }
    }
}

static int handle_ws_frame(WsClient *clients, int idx) {
    unsigned char h2[2];
    if (recv_exact(clients[idx].fd, h2, 2) < 0) {
        return -1;
    }

    unsigned char opcode = (unsigned char)(h2[0] & 0x0F);
    int masked = (h2[1] & 0x80) != 0;
    unsigned long long payload_len = (unsigned long long)(h2[1] & 0x7F);

    if (payload_len == 126) {
        unsigned char ext[2];
        if (recv_exact(clients[idx].fd, ext, 2) < 0) {
            return -1;
        }
        payload_len = ((unsigned long long)ext[0] << 8) | (unsigned long long)ext[1];
    } else if (payload_len == 127) {
        unsigned char ext[8];
        if (recv_exact(clients[idx].fd, ext, 8) < 0) {
            return -1;
        }
        payload_len =
            ((unsigned long long)ext[0] << 56) |
            ((unsigned long long)ext[1] << 48) |
            ((unsigned long long)ext[2] << 40) |
            ((unsigned long long)ext[3] << 32) |
            ((unsigned long long)ext[4] << 24) |
            ((unsigned long long)ext[5] << 16) |
            ((unsigned long long)ext[6] << 8) |
            (unsigned long long)ext[7];
    }

    if (!masked || payload_len > MAX_WS_PAYLOAD) {
        return -1;
    }

    unsigned char mask[4];
    if (recv_exact(clients[idx].fd, mask, 4) < 0) {
        return -1;
    }

    unsigned char *payload = (unsigned char *)malloc((size_t)payload_len + 1);
    if (!payload) {
        return -1;
    }

    if (recv_exact(clients[idx].fd, payload, (size_t)payload_len) < 0) {
        free(payload);
        return -1;
    }

    for (unsigned long long i = 0; i < payload_len; i++) {
        payload[i] = (unsigned char)(payload[i] ^ mask[i % 4]);
    }
    payload[payload_len] = '\0';

    if (opcode == 0x8) {
        free(payload);
        return -1; // close frame
    }

    if (opcode == 0x1) {
        // Text message: broadcast as "name: message" to every connected client.
        char out[MAX_NAME_LEN + 2 + MAX_WS_PAYLOAD + 1];
        snprintf(out, sizeof(out), "%s: %s", clients[idx].name, (char *)payload);
        broadcast_message(clients, out);
    }

    free(payload);
    return 0;
}

static int add_ws_client(WsClient *clients, int fd, const char *name) {
    for (int i = 0; i < MAX_WS_CLIENTS; i++) {
        if (clients[i].fd < 0) {
            clients[i].fd = fd;
            strncpy(clients[i].name, name, sizeof(clients[i].name) - 1);
            clients[i].name[sizeof(clients[i].name) - 1] = '\0';
            return 0;
        }
    }
    return -1;
}

static int is_websocket_upgrade_request(const char *request) {
    char upgrade[128];
    char key[256];

    if (get_header_value(request, "Upgrade", upgrade, sizeof(upgrade)) != 0) {
        return 0;
    }
    if (get_header_value(request, "Sec-WebSocket-Key", key, sizeof(key)) != 0) {
        return 0;
    }

    return strcasecmp(upgrade, "websocket") == 0;
}

static int handle_websocket_upgrade(int client_fd, const char *request, const char *raw_path, WsClient *clients) {
    char ws_key[256];
    if (get_header_value(request, "Sec-WebSocket-Key", ws_key, sizeof(ws_key)) != 0) {
        send_error_response(client_fd, 400, "Bad Request", "Missing Sec-WebSocket-Key.");
        return -1;
    }

    char accept_value[128];
    if (compute_websocket_accept(ws_key, accept_value, sizeof(accept_value)) != 0) {
        send_error_response(client_fd, 500, "Internal Server Error", "Handshake failed.");
        return -1;
    }

    char response[512];
    int n = snprintf(
        response,
        sizeof(response),
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Accept: %s\r\n"
        "\r\n",
        accept_value
    );

    if (n <= 0 || n >= (int)sizeof(response) || send_all(client_fd, response, (size_t)n) < 0) {
        return -1;
    }

    char name[MAX_NAME_LEN];
    extract_name_from_path(raw_path, name, sizeof(name));

    if (add_ws_client(clients, client_fd, name) != 0) {
        send_error_response(client_fd, 503, "Service Unavailable", "Too many WebSocket clients.");
        return -1;
    }

    return 0;
}

static void handle_http_or_ws(int client_fd, const Route *routes, int route_count, const char *public_dir, WsClient *clients) {
    char request[REQUEST_BUF_SIZE];
    ssize_t bytes = recv(client_fd, request, sizeof(request) - 1, 0);
    if (bytes <= 0) {
        close(client_fd);
        return;
    }
    request[bytes] = '\0';

    char method[16] = {0};
    char raw_path[MAX_PATH_LEN] = {0};

    if (parse_request_line(request, method, sizeof(method), raw_path, sizeof(raw_path)) != 0) {
        send_error_response(client_fd, 400, "Bad Request", "Invalid request line.");
        close(client_fd);
        return;
    }

    if (strcmp(method, "GET") != 0) {
        send_error_response(client_fd, 405, "Method Not Allowed", "Only GET is supported.");
        close(client_fd);
        return;
    }

    // WebSocket endpoint is /ws (query string may carry ?name=...)
    if (strncmp(raw_path, "/ws", 3) == 0 && is_websocket_upgrade_request(request)) {
        if (handle_websocket_upgrade(client_fd, request, raw_path, clients) != 0) {
            close(client_fd);
        }
        return;
    }

    char path[MAX_PATH_LEN];
    strncpy(path, raw_path, sizeof(path) - 1);
    path[sizeof(path) - 1] = '\0';
    strip_query_string(path);

    const char *file_path = find_route(routes, route_count, path);
    if (!file_path) {
        send_error_response(client_fd, 404, "Not Found", "No route matched this URL path.");
        close(client_fd);
        return;
    }

    serve_html_file(client_fd, public_dir, file_path);
    close(client_fd);
}

int main(void) {
    const char *public_dir = "./public";
    const char *routes_file = "./routes.conf";

    Route routes[MAX_ROUTES];
    int route_count = load_routes(routes_file, routes, MAX_ROUTES);
    if (route_count < 0) {
        fprintf(stderr, "Could not load routes from %s\n", routes_file);
        return 1;
    }

    WsClient clients[MAX_WS_CLIENTS];
    for (int i = 0; i < MAX_WS_CLIENTS; i++) {
        clients[i].fd = -1;
        clients[i].name[0] = '\0';
    }

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("socket");
        return 1;
    }

    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt");
        close(server_fd);
        return 1;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(server_fd);
        return 1;
    }

    if (listen(server_fd, 32) < 0) {
        perror("listen");
        close(server_fd);
        return 1;
    }

    printf("Server running at http://127.0.0.1:%d\n", PORT);
    printf("Routes loaded: %d\n", route_count);
    printf("WebSocket chat endpoint: ws://127.0.0.1:%d/ws?name=YOUR_NAME\n", PORT);
    printf("Press Ctrl+C to stop.\n");

    while (1) {
        fd_set readfds;
        FD_ZERO(&readfds);

        FD_SET(server_fd, &readfds);
        int maxfd = server_fd;

        for (int i = 0; i < MAX_WS_CLIENTS; i++) {
            if (clients[i].fd >= 0) {
                FD_SET(clients[i].fd, &readfds);
                if (clients[i].fd > maxfd) {
                    maxfd = clients[i].fd;
                }
            }
        }

        int ready = select(maxfd + 1, &readfds, NULL, NULL, NULL);
        if (ready < 0) {
            perror("select");
            continue;
        }

        if (FD_ISSET(server_fd, &readfds)) {
            int client_fd = accept(server_fd, NULL, NULL);
            if (client_fd >= 0) {
                handle_http_or_ws(client_fd, routes, route_count, public_dir, clients);
            }
        }

        for (int i = 0; i < MAX_WS_CLIENTS; i++) {
            if (clients[i].fd >= 0 && FD_ISSET(clients[i].fd, &readfds)) {
                if (handle_ws_frame(clients, i) != 0) {
                    remove_ws_client(clients, i);
                }
            }
        }
    }

    close(server_fd);
    return 0;
}
