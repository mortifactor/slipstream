#include <stdlib.h>
#include <string.h>

#include "slipstream_packet.h"
#include "picoquic_utils.h"

const int num_padding_for_poll = 5;

#define PICOQUIC_SHORT_HEADER_CONNECTION_ID_SIZE 8

bool slipstream_packet_is_long_header(const uint8_t first_byte) {
    return first_byte & 0x80;
}

int slipstream_packet_create_poll(uint8_t** dest_buf, size_t* dest_buf_len, picoquic_connection_id_t dst_connection_id) {
    *dest_buf = NULL;

    if (num_padding_for_poll < 5) {
        return -1;
    }

    // Allocate a num_padding_for_poll + dst_connection_id.id_len + len marker + dst_connection_id len marker
    size_t packet_len = num_padding_for_poll + dst_connection_id.id_len + 1 + 1;
    uint8_t* packet = malloc(packet_len);

    // Write random padding bytes to the entire packet
    for (int i = 0; i < packet_len; i++) {
        packet[i] = rand() % 256;
    }

    packet[0] |= 0x80; // Set bit 7 (long header format)

    // Write destination connection ID
    packet[5] = dst_connection_id.id_len;
    memcpy(&packet[6], dst_connection_id.id, dst_connection_id.id_len);

    // Ensure the source connection ID len marker byte is larger than PICOQUIC_CONNECTION_ID_MAX_SIZE
    int randomly_written_src_connection_id = packet[5+1+dst_connection_id.id_len];
    if (randomly_written_src_connection_id <= PICOQUIC_CONNECTION_ID_MAX_SIZE) {
        packet[5+1+dst_connection_id.id_len] = PICOQUIC_CONNECTION_ID_MAX_SIZE + 1;
    }

    // The rest of the payload (including pretend second connection ID) is random padding

    *dest_buf = packet;
    *dest_buf_len = packet_len;

    return packet_len;
}

int slipstream_packet_parse(uint8_t* src_buf, size_t src_buf_len, size_t short_header_conn_id_len, picoquic_connection_id_t* src_connection_id, picoquic_connection_id_t* dst_connection_id, bool* is_poll_packet) {
    if (src_buf_len < 1) {
        return -1;
    }

    // Short header packet
    if (!slipstream_packet_is_long_header(src_buf[0])) {
        // Short header packets can't be poll packets
        if (src_buf_len < short_header_conn_id_len + 1) {
            return -1;
        }

        picoquic_parse_connection_id(&src_buf[1], short_header_conn_id_len, dst_connection_id);
        return 0;
    }

    // Read destination connection ID
    if (src_buf_len < 5+1) {
        return -1;
    }
    const size_t dst_connection_id_len = src_buf[5];
    if (dst_connection_id_len > PICOQUIC_CONNECTION_ID_MAX_SIZE) {
        return -1;
    }
    if (src_buf_len < 5+1+dst_connection_id_len) {
        return -1;
    }
    picoquic_parse_connection_id(&src_buf[5+1], dst_connection_id_len, dst_connection_id);

    // Read source connection ID
    if (src_buf_len < 5+1+dst_connection_id_len+1) {
        return -1;
    }
    const size_t src_connection_id_len = src_buf[5+1+dst_connection_id_len];
    if (src_connection_id_len > PICOQUIC_CONNECTION_ID_MAX_SIZE) {
        *is_poll_packet = true;
        return 0;
    }
    if (src_buf_len < 5+1+dst_connection_id_len+1+src_connection_id_len) {
        return -1;
    }
    picoquic_parse_connection_id(&src_buf[5+1+dst_connection_id_len+1], src_connection_id_len, src_connection_id);

    return 0;
}
