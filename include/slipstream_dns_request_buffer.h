#ifndef SLIPSTREAM_DNS_REQUEST_BUFFER
#define SLIPSTREAM_DNS_REQUEST_BUFFER

#include <stdbool.h>
#include <picohash.h>
#include "SPCDNS/src/dns.h"

#define GLOBAL_BUFFER_SIZE 32

typedef struct st_slipstream_cnxid_dns_request_buffer_t slipstream_cnxid_dns_request_buffer_t;

typedef struct st_element_t {
    dns_decoded_t dns_decoded[DNS_DECODEBUF_4K];
    struct sockaddr_storage peer_addr;
    struct sockaddr_storage local_addr;
    struct st_element_t* buffer_prev;
    struct st_element_t* buffer_next;
    struct st_element_t* cnxid_buffer_prev;
    struct st_element_t* cnxid_buffer_next;
    slipstream_cnxid_dns_request_buffer_t* cnxid_buffer;
    uint64_t created_time;
    int query_id;
} slot_t;

typedef struct st_slipstream_cnxid_dns_request_buffer_t {
    slot_t* head;
    slot_t* tail;
} slipstream_cnxid_dns_request_buffer_t;

typedef struct {
    slot_t slots[GLOBAL_BUFFER_SIZE];
    slot_t* head;
    slot_t* tail;
    slot_t* free;
    picohash_table* cnxid_to_cnxid_buffer;
    slipstream_cnxid_dns_request_buffer_t** cnxid_buffers;
    size_t cnxid_buffers_len;
} slipstream_dns_request_buffer_t;

typedef struct st_cnxid_to_cnxid_buffer_t {
    picoquic_connection_id_t cnx_id;
    slipstream_cnxid_dns_request_buffer_t* cnxid_buffer;
} cnxid_to_cnxid_buffer_t;


void slipstream_dns_request_buffer_init(slipstream_dns_request_buffer_t* buffer);

slipstream_cnxid_dns_request_buffer_t* slipstream_dns_request_buffer_get_cnxid_buffer(
    slipstream_dns_request_buffer_t* buffer, picoquic_connection_id_t* initial_cnxid, bool create);

void slipstream_dns_request_buffer_free_slot(slipstream_dns_request_buffer_t* buffer, slot_t* slot);

slot_t* slipstream_dns_request_buffer_get_write_slot(slipstream_dns_request_buffer_t* buffer);

void slipstream_dns_request_buffer_commit_slot_to_cnxid_buffer(slipstream_dns_request_buffer_t* buffer,
                                                               slipstream_cnxid_dns_request_buffer_t* cnxid_buffer,
                                                               slot_t* slot);

slot_t* slipstream_dns_request_buffer_get_read_slot(slipstream_dns_request_buffer_t* buffer,
                                                    slipstream_cnxid_dns_request_buffer_t* cnxid_buffer);

#endif //SLIPSTREAM_DNS_REQUEST_BUFFER
