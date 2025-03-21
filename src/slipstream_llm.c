#include "slipstream_llm.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>


typedef struct st_llm_connection_t {
    int sockfd;
    struct sockaddr_in addr;
} llm_connection_t;

typedef struct st_llm_request_t {
    uint8_t query_data_length;
    uint8_t should_decode;
    uint8_t query_data[255];
} llm_request_t;

ssize_t llm_create_connection(llm_connection_t** conn_p, int port) {
    llm_connection_t* conn = malloc(sizeof(llm_connection_t));
    if (conn == NULL) {
        return -1;
    }
    memset(conn, 0, sizeof(llm_connection_t));

    conn->sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (conn->sockfd < 0) {
        free(conn);
        return -1;
    }

    conn->addr.sin_family = AF_INET; // IPv4
    conn->addr.sin_port = htons(port); // port number
    conn->addr.sin_addr.s_addr = inet_addr("127.0.0.1"); // localhost

    *conn_p = conn;
    return 0;
}

ssize_t llm_send_recv(llm_connection_t* conn, char* dest, const size_t dest_len, const char* src, const size_t src_len, int should_decode) {
    llm_request_t req;
    req.query_data_length = src_len;
    req.should_decode = should_decode;
    memcpy(req.query_data, src, src_len);

    const size_t request_len = sizeof(req.query_data_length) + sizeof(req.should_decode) + req.query_data_length;
    ssize_t n = sendto(conn->sockfd, &req, request_len, 0, (const struct sockaddr*)&conn->addr, sizeof(conn->addr));
    if (n < 0) {
        return n;
    }

    socklen_t addr_len = sizeof(conn->addr);
    return recvfrom(conn->sockfd, dest, dest_len, 0, (struct sockaddr*)&conn->addr, &addr_len);
}

ssize_t llm_encode(llm_connection_t* conn, char* dest, const size_t dest_len, const char* src, const size_t src_len) {
    return llm_send_recv(conn, dest, dest_len, src, src_len, 0);
}

ssize_t llm_decode(llm_connection_t* conn, char* dest, const size_t dest_len, const char* src, const size_t src_len) {
    return llm_send_recv(conn, dest, dest_len, src, src_len, 1);
}
