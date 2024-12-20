#ifndef SLIPSTREAM_H
#define SLIPSTREAM_H
/* Header file for the picoquic sample project. 
 * It contains the definitions common to client and server */

#ifdef __cplusplus
extern "C" {
#endif

#define SLIPSTREAM_ALPN "picoquic_sample"
#define SLIPSTREAM_SNI "test.example.com"

#define SLIPSTREAM_NO_ERROR 0
#define SLIPSTREAM_INTERNAL_ERROR 0x101
#define SLIPSTREAM_FILE_CANCEL_ERROR 0x105

#define SLIPSTREAM_CLIENT_TICKET_STORE "sample_ticket_store.bin";
#define SLIPSTREAM_CLIENT_TOKEN_STORE "sample_token_store.bin";
#define SLIPSTREAM_QLOG_DIR "./qlog";



int picoquic_slipstream_client(int listen_port, char const* resolver_addresses_filename, const char* domain_name,
                               const char* cc_algo_id);

int picoquic_slipstream_server(int server_port, const char* pem_cert, const char* pem_key, char const* upstream_name,
                               int upstream_port, const char* domain_name, const char* cc_algo_id);

#ifdef __cplusplus
}
#endif

#endif
