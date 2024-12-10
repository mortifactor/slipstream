#include <stdint.h>
#include <stdio.h>
#include <picoquic.h>
#include <picoquic_utils.h>
#include <picosocks.h>
#include <autoqlog.h>
#include <picoquic_internal.h>
#include <pthread.h>
#include <stdbool.h>
#include <arpa/nameser.h>
#include <sys/ioctl.h>
#include <sys/param.h>
#include <sys/poll.h>

#include "picoquic_config.h"
#include "picoquic_packet_loop.h"
#include "slipstream.h"
#include "slipstream_inline_dots.h"

#include "lua-resty-base-encoding-base32.h"

#include "SPCDNS/src/dns.h"
#include "SPCDNS/src/mappings.h"

ssize_t client_encode_segment(dns_packet_t* packet, size_t* packet_len, const unsigned char* src_buf, size_t src_buf_len) {
    edns0_opt_t opt;
    dns_answer_t edns;

    char name[255];
    const size_t len = b32_encode(&name[0], (const char*) src_buf, src_buf_len, true, false);
    const size_t encoded_len = slipstream_inline_dotify(name, 255, len);
    name[encoded_len] = '.';

    const char* tld = "test.com.";
    const size_t tld_len = strlen(tld);
    memcpy(&name[encoded_len + 1], tld, tld_len);
    name[encoded_len + 1 + tld_len] = '\0';

    dns_question_t domain;
    domain.name = name;
    domain.type = RR_TXT;
    domain.class = CLASS_IN;

    dns_query_t query = {0};
    query.id = rand() % UINT16_MAX;
    query.query = true;
    query.opcode = OP_QUERY;
    query.rd = true;
    query.rcode = RCODE_OKAY;
    query.qdcount = 1;
    query.questions = &domain;
    query.arcount = 0; // TODO: set to 1 for EDNS0
    query.additional = NULL;

    // TODO: add EDNS0

    const dns_rcode_t rc = dns_encode(packet, packet_len, &query);
    if (rc != RCODE_OKAY) {
        fprintf(stderr, "dns_encode() = (%d) %s\n", rc, dns_rcode_text(rc));
        return -1;
    }

    return 0;
}

ssize_t client_encode(unsigned char** dest_buf, const unsigned char* src_buf, size_t src_buf_len, size_t* segment_len) {
    // optimize path for single segment
    if (src_buf_len <= *segment_len) {
        size_t packet_len = MAX_DNS_QUERY_SIZE;
        unsigned char* packet = malloc(packet_len);
        const ssize_t ret = client_encode_segment((dns_packet_t*) packet, &packet_len, src_buf, src_buf_len);
        if (ret < 0) {
            free(packet);
            return -1;
        }

        *dest_buf = packet;
        *segment_len = packet_len;
        return packet_len;
    }

    size_t num_segments = src_buf_len / *segment_len;
    unsigned char* packets = malloc(MAX_DNS_QUERY_SIZE * num_segments);
    unsigned char* current_packet = packets;

    const unsigned char* segment = src_buf;
    size_t first_packet_len = 0;
    for (size_t i = 0; i < num_segments; i++) {
        size_t packet_len = MAX_DNS_QUERY_SIZE;
        const ssize_t ret = client_encode_segment((dns_packet_t*) current_packet, &packet_len, segment, *segment_len);
        if (ret < 0) {
            free(packets);
            return -1;
        }

        if (first_packet_len == 0) {
            first_packet_len = packet_len;
        } else {
            if (packet_len > first_packet_len) {
                DBG_PRINTF("current encoded segment length %d > %d than first segment\n", packet_len, first_packet_len);
                free(packets);
                return -1;
            }
        }

        current_packet += packet_len;
        segment += *segment_len;
    }

    *dest_buf = packets;
    *segment_len = first_packet_len;


    return current_packet - packets;
}

ssize_t client_decode(const unsigned char** dest_buf, const unsigned char* src_buf, size_t src_buf_len, struct sockaddr_storage* from, struct sockaddr_storage* dest) {
    *dest_buf = NULL;

    size_t bufsize = DNS_DECODEBUF_4K * sizeof(dns_decoded_t);
    dns_decoded_t* decoded = malloc(bufsize);
    const dns_rcode_t rc = dns_decode(decoded, &bufsize, (const dns_packet_t*) src_buf, src_buf_len);
    if (rc != RCODE_OKAY) {
        fprintf(stderr, "dns_decode() = (%d) %s\n", rc, dns_rcode_text(rc));
        return -1;
    }

    const dns_query_t *query = (dns_query_t *)decoded;

    if (query->query == 1) {
        fprintf(stderr, "dns record is not a response\n");
        return -1;
    }

    if (query->ancount != 1) {
        fprintf(stderr, "dns record should contain exactly one answer\n");
        return -1;
    }

    dns_txt_t *answer_txt = (dns_txt_t*) &query->answers[0];
    if (answer_txt->type != RR_TXT) {
        fprintf(stderr, "answer type is not TXT\n");
        return -1;
    }

    *dest_buf = malloc(answer_txt->len);
    memcpy((void*)*dest_buf, answer_txt->text, answer_txt->len);

    return answer_txt->len;
}

typedef struct st_slipstream_client_stream_ctx_t {
    struct st_slipstream_client_stream_ctx_t* next_stream;
    int fd;
    uint64_t stream_id;
    volatile sig_atomic_t set_active;
} slipstream_client_stream_ctx_t;

typedef struct st_slipstream_client_ctx_t {
    picoquic_cnx_t* cnx;
    slipstream_client_stream_ctx_t* first_stream;
    slipstream_client_stream_ctx_t* last_stream;
    picoquic_network_thread_ctx_t* thread_ctx;
} slipstream_client_ctx_t;

slipstream_client_stream_ctx_t* slipstream_client_create_stream_ctx(picoquic_cnx_t* cnx,
                                           slipstream_client_ctx_t* client_ctx, int sock_fd) {
    slipstream_client_stream_ctx_t* stream_ctx = malloc(sizeof(slipstream_client_stream_ctx_t));

    if (stream_ctx == NULL) {
        fprintf(stdout, "Memory Error, cannot create stream for sock %d\n", sock_fd);
        return NULL;
    }

    memset(stream_ctx, 0, sizeof(slipstream_client_stream_ctx_t));
    if (client_ctx->first_stream == NULL) {
        client_ctx->first_stream = stream_ctx;
        client_ctx->last_stream = stream_ctx;
    }
    else {
        client_ctx->last_stream->next_stream = stream_ctx;
        client_ctx->last_stream = stream_ctx;
    }
    stream_ctx->fd = sock_fd;
    stream_ctx->stream_id = picoquic_get_next_local_stream_id(client_ctx->cnx, 0);

    return stream_ctx;
}

static void slipstream_client_free_context(slipstream_client_ctx_t* client_ctx) {
    slipstream_client_stream_ctx_t* stream_ctx;

    while ((stream_ctx = client_ctx->first_stream) != NULL) {
        client_ctx->first_stream = stream_ctx->next_stream;
        if (stream_ctx->fd != 0) {
            stream_ctx->fd = close(stream_ctx->fd);
        }
        free(stream_ctx);
    }
    client_ctx->last_stream = NULL;
}

void slipstream_client_mark_active_pass(slipstream_client_ctx_t* client_ctx) {
    slipstream_client_stream_ctx_t* stream_ctx = client_ctx->first_stream;

    while (stream_ctx != NULL) {
        if (stream_ctx->set_active) {
            stream_ctx->set_active = 0;
            printf("[%lu:%d] activate: stream\n", stream_ctx->stream_id, stream_ctx->fd);
            picoquic_mark_active_stream(client_ctx->cnx, stream_ctx->stream_id, 1, stream_ctx);
        }
        stream_ctx = stream_ctx->next_stream;
    }
}

int slipstream_client_sockloop_callback(picoquic_quic_t* quic, picoquic_packet_loop_cb_enum cb_mode,
                                   void* callback_ctx, void* callback_arg) {
    slipstream_client_ctx_t* client_ctx = callback_ctx;

    switch (cb_mode) {
    case picoquic_packet_loop_wake_up:
        slipstream_client_mark_active_pass(client_ctx);
        break;
    case picoquic_packet_loop_after_send:
        if (client_ctx->cnx->cnx_state == picoquic_state_disconnected) {
            printf("Terminate packet loop\n");
            return PICOQUIC_NO_ERROR_TERMINATE_PACKET_LOOP;
        }
    default:
        break;
    }

    return 0;
}

typedef struct st_slipstream_client_poller_args {
    int fd;
    picoquic_cnx_t* cnx;
    slipstream_client_ctx_t* client_ctx;
    slipstream_client_stream_ctx_t* stream_ctx;
} slipstream_client_poller_args;

void* slipstream_client_poller(void* arg) {
    slipstream_client_poller_args* args = arg;

    while (1) {
        struct pollfd fds;
        fds.fd = args->fd;
        fds.events = POLLIN;
        fds.revents = 0;

        /* add timeout handlilng */
        int ret = poll(&fds, 1, 1000);
        if (ret < 0) {
            perror("poll() failed");
            pthread_exit(NULL);
        }
        if (ret == 0) {
            continue;
        }

        args->stream_ctx->set_active = 1;

        ret = picoquic_wake_up_network_thread(args->client_ctx->thread_ctx);
        if (ret != 0) {
            fprintf(stderr, "poll: could not wake up network thread, ret = %d\n", ret);
        }

        pthread_exit(NULL);
    }
}

typedef struct st_slipstream_client_accepter_args {
    int fd;
    picoquic_cnx_t* cnx;
    slipstream_client_ctx_t* client_ctx;
    slipstream_client_stream_ctx_t* stream_ctx;
    picoquic_network_thread_ctx_t* thread_ctx;
} slipstream_client_accepter_args;

void* slipstream_client_accepter(void* arg) {
    slipstream_client_accepter_args* args = arg;

    while (1) {
        // Accept incoming client connection
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_sock = accept(args->fd, (struct sockaddr*)&client_addr, &client_len);
        if (client_sock < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("accept() failed");
            pthread_exit(NULL);
        }

        slipstream_client_stream_ctx_t* stream_ctx = slipstream_client_create_stream_ctx(args->cnx, args->client_ctx, client_sock);
        if (stream_ctx == NULL) {
            fprintf(stderr, "Could not initiate stream for %d", client_sock);
            pthread_exit(NULL);
        }

        stream_ctx->set_active = 1;

        int ret = picoquic_wake_up_network_thread(args->thread_ctx);
        if (ret != 0) {
            fprintf(stderr, "accept: could not wake up network thread, ret = %d\n", ret);
            pthread_exit(NULL);
        }

        printf("[?:%d] accept: connection\n[?:%d] wakeup\n", client_sock, client_sock);
    }
}

int slipstream_client_callback(picoquic_cnx_t* cnx,
                               uint64_t stream_id, uint8_t* bytes, size_t length,
                               picoquic_call_back_event_t fin_or_event, void* callback_ctx, void* v_stream_ctx) {
    int ret = 0;
    slipstream_client_ctx_t* client_ctx = (slipstream_client_ctx_t*)callback_ctx;
    slipstream_client_stream_ctx_t* stream_ctx = (slipstream_client_stream_ctx_t*)v_stream_ctx;

    if (client_ctx == NULL) {
        /* This should never happen, because the callback context for the client is initialized
         * when creating the client connection. */
        return -1;
    }

    switch (fin_or_event) {
    case picoquic_callback_stream_data:
    case picoquic_callback_stream_fin:
        /* Data arrival on stream #x, maybe with fin mark */
        if (stream_ctx == NULL) {
            /* This is unexpected, as all contexts were declared when initializing the
             * connection. */
            return 0;
        }

        // printf("[%lu:%d] quic_recv->send %lu bytes\n", stream_id, stream_ctx->fd, length);
        if (length > 0) {
            ssize_t bytes_sent = send(stream_ctx->fd, bytes, length, MSG_NOSIGNAL);
            if (bytes_sent < 0) {
                if (errno == EPIPE) {
                    /* Connection closed */
                    printf("[%lu:%d] send: closed stream\n", stream_id, stream_ctx->fd);

                    (void)picoquic_reset_stream(cnx, stream_id, SLIPSTREAM_FILE_CANCEL_ERROR);
                    return 0;
                }
                if (errno == EAGAIN) {
                    /* TODO: this is bad because we don't have a way to backpressure */
                }

                printf("[%lu:%d] send: error: %s (%d)\n", stream_id, stream_ctx->fd, strerror(errno), errno);
                (void)picoquic_reset_stream(cnx, stream_id, SLIPSTREAM_INTERNAL_ERROR);
                return 0;
            }
        }
        if (fin_or_event == picoquic_callback_stream_fin) {
            printf("[%lu:%d] fin\n", stream_id, stream_ctx->fd);
            /* Close the local_sock fd */
            close(stream_ctx->fd);
            stream_ctx->fd = -1;
            picoquic_unlink_app_stream_ctx(cnx, stream_id);
        }
        break;
    case picoquic_callback_stop_sending: /* Should not happen, treated as reset */
        /* Mark stream as abandoned, close the file, etc. */
        picoquic_reset_stream(cnx, stream_id, 0);
        /* Fall through */
    case picoquic_callback_stream_reset: /* Server reset stream #x */
        if (stream_ctx == NULL) {
            /* This is unexpected, as all contexts were declared when initializing the
             * connection. */
        }
        else {
            printf("[%lu:%d] stream reset\n", stream_id, stream_ctx->fd);

            /* Close the local_sock fd */
            stream_ctx->fd = close(stream_ctx->fd);
        }
        break;
    case picoquic_callback_stateless_reset:
    case picoquic_callback_close: /* Received connection close */
    case picoquic_callback_application_close: /* Received application close */
        printf("Connection closed (%d).\n", fin_or_event);
        /* Delete the server application context */
        slipstream_client_free_context(client_ctx);
        /* Remove the application callback */
        picoquic_set_callback(cnx, NULL, NULL);
        picoquic_delete_cnx(cnx);
        picoquic_close(cnx, 0);
        break;
    case picoquic_callback_prepare_to_send:
        /* Active sending API */
        if (stream_ctx == NULL) {
            /* This should never happen */
        }
        else {
            int length_available;
            ret = ioctl(stream_ctx->fd, FIONREAD, &length_available);
            // printf("[%lu:%d] recv->quic_send (available %d)\n", stream_id, stream_ctx->fd, length_available);
            if (ret < 0) {
                printf("[%lu:%d] ioctl error: %s (%d)\n", stream_id, stream_ctx->fd, strerror(errno), errno);
                /* TODO: why would it return an error? */
                (void)picoquic_reset_stream(cnx, stream_id, SLIPSTREAM_INTERNAL_ERROR);
                break;
            }
            ret = 0;

            int length_to_read = MIN(length, length_available);
            if (length_to_read == 0) {
                char a;
                ssize_t bytes_read = recv(stream_ctx->fd, &a, 1, MSG_PEEK | MSG_DONTWAIT);
                // printf("[%lu:%d] recv->quic_send empty read %d bytes\n", stream_id, stream_ctx->fd, bytes_read);
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    // printf("[%lu:%d] recv->quic_send empty errno set: %s\n", stream_id, stream_ctx->fd, strerror(errno));
                    /* No bytes available, wait for next event */
                    (void)picoquic_provide_stream_data_buffer(bytes, 0, 0, 0);
                    printf("[%lu:%d] recv->quic_send: empty, disactivate\n\n", stream_id, stream_ctx->fd);

                    slipstream_client_poller_args* args = malloc(sizeof(slipstream_client_poller_args));
                    args->fd = stream_ctx->fd;
                    args->cnx = cnx;
                    args->client_ctx = client_ctx;
                    args->stream_ctx = stream_ctx;

                    pthread_t thread;
                    if (pthread_create(&thread, NULL, slipstream_client_poller, args) != 0) {
                        perror("pthread_create() failed for thread1");
                        free(args);
                    }
                    pthread_setname_np(thread, "slipstream_server_poller");
                    pthread_detach(thread);
                }
                if (bytes_read == 0) {
                    printf("[%lu:%d] recv: closed stream\n", stream_id, stream_ctx->fd);
                    (void)picoquic_reset_stream(cnx, stream_id, SLIPSTREAM_FILE_CANCEL_ERROR);
                    return 0;
                }
                if (bytes_read > 0) {
                    /* send it in next loop iteration */
                    (void)picoquic_provide_stream_data_buffer(bytes, 0, 0, 1);
                    break;
                }
                return 0;
            }

            uint8_t* buffer = picoquic_provide_stream_data_buffer(bytes, length_to_read, 0, 1);
            if (buffer == NULL) {
                /* Should never happen according to callback spec. */
                break;
            }
            // printf("[%lu:%d] recv->quic_send recv %d bytes into quic\n", stream_id, stream_ctx->fd, length_to_read);
            ssize_t bytes_read = recv(stream_ctx->fd, buffer, length_to_read, MSG_DONTWAIT);
            // printf("[%lu:%d] recv->quic_send recv done %d bytes into quic\n", stream_id, stream_ctx->fd, bytes_read);
            if (bytes_read == 0) {
                printf("Closed connection on sock %d on recv", stream_ctx->fd);
                (void)picoquic_reset_stream(cnx, stream_id, SLIPSTREAM_FILE_CANCEL_ERROR);
                return 0;
            }
            if (bytes_read < 0) {
                fprintf(stderr, "recv: %s (%d)\n", strerror(errno), errno);
                /* There should be bytes available, so a return value of 0 is an error */
                (void)picoquic_reset_stream(cnx, stream_id, SLIPSTREAM_INTERNAL_ERROR);
                return 0;
            }
        }
        break;
    case picoquic_callback_almost_ready:
        fprintf(stdout, "Connection completed, almost ready.\n");
        break;
    case picoquic_callback_ready:
        fprintf(stdout, "Connection confirmed.\n");
        break;
    default:
        /* unexpected -- just ignore. */
        break;
    }

    return ret;
}

static int slipstream_connect(char const* server_name, int server_port,
                                  picoquic_quic_t* quic, picoquic_cnx_t** cnx,
                                  slipstream_client_ctx_t* client_ctx) {
    int ret = 0;
    char const* sni = SLIPSTREAM_SNI;
    uint64_t current_time = picoquic_current_time();
    struct sockaddr_storage server_address;

    *cnx = NULL;

    /* Get the server's address */
    int is_name = 0;
    ret = picoquic_get_server_address(server_name, server_port, &server_address, &is_name);
    if (ret != 0) {
        fprintf(stderr, "Cannot get the IP address for <%s> port <%d>", server_name, server_port);
        return -1;
    }
    sni = server_name;

    /* Initialize the callback context and create the connection context.
     * We use minimal options on the client side, keeping the transport
     * parameter values set by default for picoquic. This could be fixed later.
     */
    printf("Starting connection to %s, port %d\n", server_name, server_port);

    /* Create a client connection */
    *cnx = picoquic_create_cnx(quic, picoquic_null_connection_id, picoquic_null_connection_id,
        (struct sockaddr*)&server_address, current_time, 0, sni, SLIPSTREAM_ALPN, 1);
    if (*cnx == NULL) {
        fprintf(stderr, "Could not create connection context\n");
        return -1;
    }

    /* Document connection in client's context */
    client_ctx->cnx = *cnx;
    /* Set the client callback context */
    picoquic_set_callback(*cnx, slipstream_client_callback, client_ctx);
    /* Client connection parameters could be set here, before starting the connection. */
    ret = picoquic_start_client_cnx(*cnx);
    if (ret < 0) {
        fprintf(stderr, "Could not activate connection\n");
        return -1;
    }

    /* Printing out the initial CID, which is used to identify log files */
    picoquic_connection_id_t icid = picoquic_get_initial_cnxid(*cnx);
    printf("Initial connection ID: ");
    for (uint8_t i = 0; i < icid.id_len; i++) {
        printf("%02x", icid.id[i]);
    }
    printf("\n");

    return ret;
}

void client_sighandler(int signum) {
    printf("Signal %d received\n", signum);
}

int picoquic_slipstream_client(int listen_port, char const* server_name, int server_port) {
    /* Start: start the QUIC process */
    int ret = 0;
    picoquic_quic_t* quic = NULL;
    uint64_t current_time = 0;
    picoquic_cnx_t* cnx = NULL;
    slipstream_client_ctx_t client_ctx = {0};
    char const* ticket_store_filename = SLIPSTREAM_CLIENT_TICKET_STORE;
    char const* token_store_filename = SLIPSTREAM_CLIENT_TOKEN_STORE;

    int mtu = 146;
    // int mtu = 129;

    /* Create config */
    picoquic_quic_config_t config;
    picoquic_config_init(&config);
    config.nb_connections = 8;
    // config.log_file = "-";
#ifndef DISABLE_DEBUG_PRINTF
    config.qlog_dir = SLIPSTREAM_QLOG_DIR;
#endif
    config.server_port = server_port;
    config.mtu_max = mtu;
    config.initial_send_mtu_ipv4 = mtu;
    config.initial_send_mtu_ipv6 = mtu;
    config.cc_algo_id = "bbr1";
    config.multipath_option = 0;
    config.use_long_log = 1;
    config.do_preemptive_repeat = 1;
    config.disable_port_blocking = 1;
    config.enable_sslkeylog = 1;
    config.alpn = SLIPSTREAM_ALPN;
    config.token_file_name = token_store_filename;

    /* Create the QUIC context for the server */
    current_time = picoquic_current_time();
    /* Create QUIC context */
    quic = picoquic_create_and_configure(&config, slipstream_client_callback, &client_ctx, current_time, NULL);
    if (quic == NULL) {
        fprintf(stderr, "Could not create server context\n");
        return -1;
    }

    picoquic_set_cookie_mode(quic, 2);
    picoquic_set_qlog(quic, config.qlog_dir);
    picoquic_set_key_log_file_from_env(quic);;
    debug_printf_push_stream(stderr);

    ret = slipstream_connect(server_name, server_port, quic, &cnx, &client_ctx);
    if (ret != 0) {
        fprintf(stderr, "Could not connect to server\n");
        return -1;
    }

    // Create listening socket
    int listen_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_sock < 0) {
        perror("socket() failed");
        exit(EXIT_FAILURE);
    }

    int optval = 1;
    setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

    struct sockaddr_in listen_addr = {0};
    listen_addr.sin_family = AF_INET;
    listen_addr.sin_addr.s_addr = INADDR_ANY;
    listen_addr.sin_port = htons(listen_port);

    if (bind(listen_sock, (struct sockaddr*)&listen_addr, sizeof(listen_addr)) < 0) {
        perror("bind() failed");
        close(listen_sock);
        exit(EXIT_FAILURE);
    }

    if (listen(listen_sock, 5) < 0) {
        perror("listen() failed");
        close(listen_sock);
        exit(EXIT_FAILURE);
    }

    printf("Listening on port %d...\n", listen_port);

    picoquic_packet_loop_param_t param = {0};
    param.local_af = AF_INET;

    // For loopback testing, we need to disable hardware GSO since packets on loopback never reach a hardware NIC
    // $ ethtool -K lo tx-udp-segmentation off
    // And ensure that gso is on
    // $ ethtool -k lo | grep generic-segmentation-offload
    // generic-segmentation-offload: on
    param.do_not_use_gso = 0;

    param.is_client = 1;
    param.decode = client_decode;
    param.encode = client_encode;

    picoquic_network_thread_ctx_t thread_ctx = {0};
    thread_ctx.quic = quic;
    thread_ctx.param = &param;
    thread_ctx.loop_callback = slipstream_client_sockloop_callback;
    thread_ctx.loop_callback_ctx = &client_ctx;

    /* Open the wake up pipe or event */
    picoquic_open_network_wake_up(&thread_ctx, &ret);

    client_ctx.thread_ctx = &thread_ctx;

    slipstream_client_accepter_args* args = malloc(sizeof(slipstream_client_accepter_args));
    args->fd = listen_sock;
    args->cnx = cnx;
    args->client_ctx = &client_ctx;
    args->thread_ctx = &thread_ctx;

    pthread_t thread;
    if (pthread_create(&thread, NULL, slipstream_client_accepter, args) != 0) {
        perror("pthread_create() failed for thread");
        free(args);
    }

    signal(SIGTERM, client_sighandler);
    picoquic_packet_loop_v3(&thread_ctx);
    ret = thread_ctx.return_code;

    /* Save tickets and tokens, and free the QUIC context */
    if (picoquic_save_session_tickets(quic, ticket_store_filename) != 0) {
        fprintf(stderr, "Could not store the saved session tickets.\n");
    }
    if (picoquic_save_retry_tokens(quic, token_store_filename) != 0) {
        fprintf(stderr, "Could not save tokens to <%s>.\n", token_store_filename);
    }
    picoquic_free(quic);

    /* Free the Client context */
    slipstream_client_free_context(&client_ctx);

    return ret;
}
