#include <stdint.h>
#include <stdio.h>
#include <picoquic.h>
#include <picoquic_packet_loop.h>
#include <picosocks.h>
#ifdef BUILD_LOGLIB
#include <autoqlog.h>
#endif
#include <picohash.h>
#include <pthread.h>
#include <stdbool.h>
#include <arpa/nameser.h>
#include <sys/ioctl.h>
#include <sys/param.h>
#include <sys/poll.h>
#include <assert.h>

#include "lua-resty-base-encoding-base32.h"
#include "picoquic_config.h"
#include "slipstream.h"
#include "slipstream_inline_dots.h"
#include "slipstream_packet.h"
#include "slipstream_dns_request_buffer.h"
#include "slipstream_utils.h"
#include "SPCDNS/src/dns.h"
#include "SPCDNS/src/mappings.h"

char* server_domain_name = NULL;
size_t server_domain_name_len = 0;

slipstream_dns_request_buffer_t slipstream_server_dns_request_buffer;

ssize_t server_encode(picoquic_quic_t* quic, picoquic_cnx_t* cnx, unsigned char** dest_buf, const unsigned char* src_buf, size_t src_buf_len, size_t* segment_size, struct sockaddr_storage *peer_addr) {
    // we don't support segmentation in the server
    assert(segment_size == NULL || *segment_size == 0 || *segment_size == src_buf_len);

    picoquic_connection_id_t initial_cnxid = picoquic_get_initial_cnxid(cnx);

    slipstream_cnxid_dns_request_buffer_t* cnxid_buffer = slipstream_dns_request_buffer_get_cnxid_buffer(
        &slipstream_server_dns_request_buffer, &initial_cnxid, false);
    if (cnxid_buffer == NULL) {
        fprintf(stderr, "error getting cnxid buffer\n");
        return -1;
    }

    slot_t *slot = slipstream_dns_request_buffer_get_read_slot(&slipstream_server_dns_request_buffer, cnxid_buffer);
    if (slot == NULL) {
        fprintf(stderr, "no available DNS request to respond to\n");
        return -1;
    }
    dns_query_t *query = (dns_query_t *) slot->dns_decoded;

    if (query->questions == NULL) {
        fprintf(stderr, "no questions in DNS request\n");
        return -1;
    }

    const dns_question_t *question = &query->questions[0]; // assuming server_decode ensures there is exactly one question
    dns_txt_t answer_txt;
    answer_txt.name = question->name;
    answer_txt.type = question->type;
    answer_txt.class = question->class;
    answer_txt.ttl = 60;
    answer_txt.text = (char *)src_buf;
    answer_txt.len = src_buf_len;

    dns_query_t response = {0};
    response.id = query->id;
    response.query = false;
    response.opcode = OP_QUERY;
    response.rd = true;
    response.rcode = RCODE_OKAY;
    response.qdcount = 1;
    response.questions = query->questions;
    response.ancount = 1;
    response.answers = (dns_answer_t *)&answer_txt;
    response.arcount = 0; // TODO: set to 1 for EDNS0
    response.additional = NULL;

    dns_packet_t* packet = malloc(MAX_UDP_PACKET_SIZE);
    size_t packet_len = MAX_UDP_PACKET_SIZE;
    dns_rcode_t rc = dns_encode(packet, &packet_len, &response);
    if (rc != RCODE_OKAY) {
        free(packet);
        fprintf(stderr, "dns_encode() = (%d) %s\n", rc, dns_rcode_text(rc));
        return EXIT_FAILURE;
    }
    *dest_buf = (unsigned char*)packet;

    memcpy(peer_addr, &slot->peer_addr, sizeof(struct sockaddr_storage));

    return packet_len;
}

ssize_t server_decode(picoquic_quic_t* quic, unsigned char** dest_buf, const unsigned char* src_buf, size_t src_buf_len, struct sockaddr_storage *peer_addr) {
    *dest_buf = NULL;

    slot_t* slot = slipstream_dns_request_buffer_get_write_slot(&slipstream_server_dns_request_buffer);
    if (slot == NULL) {
        fprintf(stderr, "error getting write slot\n");
        sockaddr_dummy(peer_addr);
        return -1;
    }

    // DNS packets arrive from random source ports, so:
    // * save the original address in the dns query slot
    // * set the source address to a dummy address (to prevent QUIC from using it)
    memcpy(&slot->peer_addr, peer_addr, sizeof(struct sockaddr_storage));
    sockaddr_dummy(peer_addr);

    size_t packet_len = DNS_DECODEBUF_4K * sizeof(dns_decoded_t);
    dns_decoded_t* packet = slot->dns_decoded;
    const dns_rcode_t rc = dns_decode(packet, &packet_len, (const dns_packet_t*) src_buf, src_buf_len);
    if (rc != RCODE_OKAY) {
        fprintf(stderr, "dns_decode() = (%d) %s\n", rc, dns_rcode_text(rc));
        return -1;
    }

    const dns_query_t *query = (dns_query_t*) packet;

    if (!query->query) {
        fprintf(stderr, "dns record is not a query\n");
        return -1;
    }

    if (query->qdcount != 1) {
        fprintf(stderr, "dns record should contain exactly one query\n");
        return -1;
    }

    const dns_question_t *question = &query->questions[0];
    if (question->type != RR_TXT) {
        fprintf(stderr, "query type is not TXT\n");
        return -1;
    }

    const size_t data_len = strlen(question->name) - server_domain_name_len - 1 - 1;

    // copy the subdomain from name to a new buffer
    char data_buf[data_len];
    memcpy(data_buf, question->name, data_len);
    data_buf[data_len] = '\0';
    const size_t encoded_len = slipstream_inline_undotify(data_buf, data_len);

    char* decoded_buf = malloc(encoded_len);
    const size_t decoded_len = b32_decode(decoded_buf, data_buf, encoded_len, false);
    if (decoded_len == (size_t) -1) {
        free(decoded_buf);
        fprintf(stderr, "error decoding base32: %lu\n", decoded_len);
        return -1;
    }

    picoquic_connection_id_t incoming_src_connection_id = {0};
    picoquic_connection_id_t incoming_dest_connection_id; // sure to be set by parser
    bool is_poll_packet = false;
    // ReSharper disable once CppDFAUnreachableCode
    const int ret = slipstream_packet_parse(decoded_buf, decoded_len, PICOQUIC_SHORT_HEADER_CONNECTION_ID_SIZE,
        &incoming_src_connection_id, &incoming_dest_connection_id, &is_poll_packet);
    if (ret != 0) {
        free(decoded_buf);
        fprintf(stderr, "error parsing slipstream packet: %d\n", ret);
        return -1;
    }

    picoquic_cnx_t *cnx = picoquic_cnx_by_id_(quic, incoming_dest_connection_id);
    picoquic_connection_id_t initial_cnxid;
    if (cnx == NULL) {
        initial_cnxid = incoming_dest_connection_id;
    } else {
        initial_cnxid = picoquic_get_initial_cnxid(cnx);
    }

    slipstream_cnxid_dns_request_buffer_t* cnxid_buffer = slipstream_dns_request_buffer_get_cnxid_buffer(
        &slipstream_server_dns_request_buffer, &initial_cnxid, true);
    if (cnxid_buffer == NULL) {
        free(decoded_buf);
        fprintf(stderr, "error getting or creating cnxid buffer\n");
        return -1;
    }

    slipstream_dns_request_buffer_commit_slot_to_cnxid_buffer(&slipstream_server_dns_request_buffer, cnxid_buffer, slot);

    if (is_poll_packet) {
        free(decoded_buf);
        return 0;
    }

    *dest_buf = decoded_buf;

    return decoded_len;
}

typedef struct st_slipstream_server_stream_ctx_t {
    struct st_slipstream_server_stream_ctx_t* next_stream;
    struct st_slipstream_server_stream_ctx_t* previous_stream;
    int fd;
    uint64_t stream_id;
    volatile sig_atomic_t set_active;
} slipstream_server_stream_ctx_t;

typedef struct st_slipstream_server_ctx_t {
    picoquic_cnx_t* cnx;
    slipstream_server_stream_ctx_t* first_stream;
    picoquic_network_thread_ctx_t* thread_ctx;
    struct sockaddr_storage upstream_addr;
    struct st_slipstream_server_ctx_t* prev_ctx;
    struct st_slipstream_server_ctx_t* next_ctx;
} slipstream_server_ctx_t;

slipstream_server_stream_ctx_t* slipstream_server_create_stream_ctx(slipstream_server_ctx_t* server_ctx,
                                                                    uint64_t stream_id) {
    slipstream_server_stream_ctx_t* stream_ctx = malloc(sizeof(slipstream_server_stream_ctx_t));

    if (stream_ctx == NULL) {
        fprintf(stdout, "Memory Error, cannot create stream\n");
        return NULL;
    }

    int sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_fd < 0) {
        perror("socket() failed");
        return NULL;
    }

    if (connect(sock_fd, (struct sockaddr*)&server_ctx->upstream_addr, sizeof(server_ctx->upstream_addr)) < 0) {
        perror("connect() failed");
        return NULL;
    }

    memset(stream_ctx, 0, sizeof(slipstream_server_stream_ctx_t));
    if (server_ctx->first_stream == NULL) {
        server_ctx->first_stream = stream_ctx;
    } else {
        stream_ctx->next_stream = server_ctx->first_stream;
        stream_ctx->next_stream->previous_stream = stream_ctx;
        server_ctx->first_stream = stream_ctx;
    }
    stream_ctx->fd = sock_fd;
    stream_ctx->stream_id = stream_id;

    return stream_ctx;
}

static void slipstream_server_free_stream_context(slipstream_server_ctx_t* server_ctx,
                                             slipstream_server_stream_ctx_t* stream_ctx) {
    if (stream_ctx->previous_stream != NULL) {
        stream_ctx->previous_stream->next_stream = stream_ctx->next_stream;
    }
    if (stream_ctx->next_stream != NULL) {
        stream_ctx->next_stream->previous_stream = stream_ctx->previous_stream;
    }
    if (server_ctx->first_stream == stream_ctx) {
        server_ctx->first_stream = stream_ctx->next_stream;
    }

    stream_ctx->fd = close(stream_ctx->fd);

    free(stream_ctx);
}

static void slipstream_server_free_context(slipstream_server_ctx_t* server_ctx) {
    slipstream_server_stream_ctx_t* stream_ctx;

    /* Delete any remaining stream context */
    while ((stream_ctx = server_ctx->first_stream) != NULL) {
        slipstream_server_free_stream_context(server_ctx, stream_ctx);
    }

    /* release the memory */
    free(server_ctx);
}

void slipstream_server_mark_active_pass(slipstream_server_ctx_t* server_ctx) {
    slipstream_server_stream_ctx_t* stream_ctx = server_ctx->first_stream;

    while (stream_ctx != NULL) {
        if (stream_ctx->set_active) {
            stream_ctx->set_active = 0;
            printf("[%lu:%d] activate: stream\n", stream_ctx->stream_id, stream_ctx->fd);
            picoquic_mark_active_stream(server_ctx->cnx, stream_ctx->stream_id, 1, stream_ctx);
        }
        stream_ctx = stream_ctx->next_stream;
    }
}

int slipstream_server_sockloop_callback(picoquic_quic_t* quic, picoquic_packet_loop_cb_enum cb_mode,
                                   void* callback_ctx, void* callback_arg) {
    slipstream_server_ctx_t* server_ctx = callback_ctx;

    switch (cb_mode) {
    case picoquic_packet_loop_wake_up:
        if (callback_ctx == NULL) {
            return 0;
        }

        while (server_ctx->next_ctx != NULL) {
            /* skip default ctx */
            server_ctx = server_ctx->next_ctx;
            slipstream_server_mark_active_pass(server_ctx);
        }

        break;
    default:
        break;
    }

    return 0;
}

typedef struct st_slipstream_server_poller_args {
    int fd;
    picoquic_cnx_t* cnx;
    slipstream_server_ctx_t* server_ctx;
    slipstream_server_stream_ctx_t* stream_ctx;
} slipstream_server_poller_args;

void* slipstream_server_poller(void* arg) {
    slipstream_server_poller_args* args = arg;

    while (1) {
        struct pollfd fds;
        fds.fd = args->fd;
        fds.events = POLLIN;
        fds.revents = 0;

        /* add timeout handlilng */
        int ret = poll(&fds, 1, 1000);
        if (ret < 0) {
            perror("poll() failed");
            break;
        }
        if (ret == 0) {
            continue;
        }

        args->stream_ctx->set_active = 1;

        ret = picoquic_wake_up_network_thread(args->server_ctx->thread_ctx);
        if (ret != 0) {
            fprintf(stderr, "poll: could not wake up network thread, ret = %d\n", ret);
        }
        printf("[%lu:%d] wakeup\n", args->stream_ctx->stream_id, args->fd);

        break;
    }


    free(args);
    pthread_exit(NULL);
}

int slipstream_server_callback(picoquic_cnx_t* cnx,
                               uint64_t stream_id, uint8_t* bytes, size_t length,
                               picoquic_call_back_event_t fin_or_event, void* callback_ctx, void* v_stream_ctx) {
    int ret = 0;
    slipstream_server_ctx_t* server_ctx = (slipstream_server_ctx_t*)callback_ctx;
    slipstream_server_stream_ctx_t* stream_ctx = (slipstream_server_stream_ctx_t*)v_stream_ctx;

    /* If this is the first reference to the connection, the application context is set
     * to the default value defined for the server. This default value contains the pointer
     * to the file directory in which all files are defined.
     */
    if (callback_ctx == NULL || callback_ctx == picoquic_get_default_callback_context(picoquic_get_quic_ctx(cnx))) {
        server_ctx = (slipstream_server_ctx_t*)malloc(sizeof(slipstream_server_ctx_t));
        if (server_ctx == NULL) {
            /* cannot handle the connection */
            picoquic_close(cnx, PICOQUIC_ERROR_MEMORY);
            return -1;
        }
        slipstream_server_ctx_t* d_ctx = picoquic_get_default_callback_context(picoquic_get_quic_ctx(cnx));
        if (d_ctx != NULL) {
            memcpy(server_ctx, d_ctx, sizeof(slipstream_server_ctx_t));
        }
        else {
            /* This really is an error case: the default connection context should never be NULL */
            memset(server_ctx, 0, sizeof(slipstream_server_ctx_t));
        }
        server_ctx->cnx = cnx;
        picoquic_set_callback(cnx, slipstream_server_callback, server_ctx);

        if (d_ctx->next_ctx != NULL) {
            d_ctx->next_ctx->prev_ctx = server_ctx;
        }
        server_ctx->next_ctx = d_ctx->next_ctx;
        server_ctx->prev_ctx = d_ctx;
        d_ctx->next_ctx = server_ctx;

        printf("Created ctx\n");
    }

    switch (fin_or_event) {
    case picoquic_callback_stream_data:
    case picoquic_callback_stream_fin:
        /* Data arrival on stream #x, maybe with fin mark */
        if (stream_ctx == NULL) {
            /* Create and initialize stream context */
            stream_ctx = slipstream_server_create_stream_ctx(server_ctx, stream_id);
            if (stream_ctx == NULL || picoquic_set_app_stream_ctx(cnx, stream_id, stream_ctx) != 0) {
                /* Internal error */
                (void)picoquic_reset_stream(cnx, stream_id, SLIPSTREAM_INTERNAL_ERROR);
                return 0;
            }
            printf("[%lu:%d] connected\n", stream_id, stream_ctx->fd);
            picoquic_mark_active_stream(cnx, stream_id, 1, stream_ctx);
            printf("[%lu:%d] marked active\n", stream_id, stream_ctx->fd);
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

            slipstream_server_free_stream_context(server_ctx, stream_ctx);
            picoquic_reset_stream(cnx, stream_id, SLIPSTREAM_FILE_CANCEL_ERROR);
        }
        break;
    case picoquic_callback_stateless_reset:
    case picoquic_callback_close: /* Received connection close */
    case picoquic_callback_application_close: /* Received application close */
        printf("Connection closed.\n");
        if (server_ctx != NULL) {
            slipstream_server_free_context(server_ctx);
        }
        /* Remove the application callback */
        picoquic_set_callback(cnx, NULL, NULL);
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

                    slipstream_server_poller_args* args = malloc(sizeof(slipstream_server_poller_args));
                    args->fd = stream_ctx->fd;
                    args->cnx = cnx;
                    args->server_ctx = server_ctx;
                    args->stream_ctx = stream_ctx;

                    pthread_t thread;
                    if (pthread_create(&thread, NULL, slipstream_server_poller, args) != 0) {
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

void server_sighandler(int signum) {
    printf("Signal %d received\n", signum);
}

int picoquic_slipstream_server(int server_port, const char* server_cert, const char* server_key,
                               char const* upstream_name, int upstream_port, const char* domain_name) {
    /* Start: start the QUIC process with cert and key files */
    int ret = 0;
    uint64_t current_time = 0;
    slipstream_server_ctx_t default_context = {0};
    printf("Starting Picoquic Sample server on port %d\n", server_port);

    int is_name = 0;
    picoquic_get_server_address(upstream_name, upstream_port, &default_context.upstream_addr, &is_name);

    server_domain_name = strdup(domain_name);
    server_domain_name_len = strlen(domain_name);

    // int mtu = 250;
    int mtu = 900;

    /* Create config */
    picoquic_quic_config_t config;
    picoquic_config_init(&config);
    config.nb_connections = 8;
    config.server_cert_file = server_cert;
    config.server_key_file = server_key;
    // config.log_file = "-";
#ifdef BUILD_LOGLIB
    config.qlog_dir = SLIPSTREAM_QLOG_DIR;
#endif
    config.server_port = server_port;
    config.mtu_max = mtu;
    config.initial_send_mtu_ipv4 = mtu;
    config.initial_send_mtu_ipv6 = mtu;
    config.cc_algo_id = "cubic";
    config.multipath_option = 1;
    config.use_long_log = 1;
    config.do_preemptive_repeat = 1;
    config.disable_port_blocking = 1;
    config.enable_sslkeylog = 1;
    config.alpn = SLIPSTREAM_ALPN;


    /* Create the QUIC context for the server */
    current_time = picoquic_current_time();
    /* Create QUIC context */
    picoquic_quic_t* quic = picoquic_create_and_configure(&config, slipstream_server_callback, &default_context, current_time, NULL);
    if (quic == NULL) {
        fprintf(stderr, "Could not create server context\n");
        return -1;
    }

    picoquic_set_cookie_mode(quic, 2);
#ifdef BUILD_LOGLIB
    picoquic_set_qlog(quic, config.qlog_dir);
    debug_printf_push_stream(stderr);
#endif
    picoquic_set_key_log_file_from_env(quic);

    slipstream_dns_request_buffer_init(&slipstream_server_dns_request_buffer);

    picoquic_packet_loop_param_t param = {0};
    param.local_af = AF_INET;
    param.local_port = server_port;
    param.do_not_use_gso = 1; // can't use GSO since we're limited to responding to one DNS query at a time
    param.is_client = 0;
    param.decode = server_decode;
    param.encode = server_encode;
    // param.delay_max = 1;

    picoquic_network_thread_ctx_t thread_ctx = {0};
    thread_ctx.quic = quic;
    thread_ctx.param = &param;
    thread_ctx.loop_callback = slipstream_server_sockloop_callback;
    thread_ctx.loop_callback_ctx = &default_context;

    /* Open the wake up pipe or event */
    picoquic_open_network_wake_up(&thread_ctx, &ret);

    default_context.thread_ctx = &thread_ctx;

    signal(SIGTERM, server_sighandler);
    picoquic_packet_loop_v3(&thread_ctx);
    ret = thread_ctx.return_code;

    /* And finish. */
    printf("Server exit, ret = %d\n", ret);

    picoquic_free(quic);

    return ret;
}
