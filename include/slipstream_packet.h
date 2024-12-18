#ifndef SLIPSTREAM_PACKET
#define SLIPSTREAM_PACKET

#include <stdbool.h>
#include "picoquic.h"

#define PICOQUIC_SHORT_HEADER_CONNECTION_ID_SIZE 8

bool slipstream_packet_is_long_header(const uint8_t first_byte);

int slipstream_packet_create_poll(uint8_t** dest_buf, size_t* dest_buf_len, picoquic_connection_id_t dst_connection_id);

int slipstream_packet_parse(uint8_t* src_buf, size_t src_buf_len, size_t short_header_conn_id_len, picoquic_connection_id_t* src_connection_id, picoquic_connection_id_t* dst_connection_id, bool* is_poll_packet);

#endif // SLIPSTREAM_PACKET
