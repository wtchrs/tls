#ifndef CORE_TLS12_TYPES_H
#define CORE_TLS12_TYPES_H


#include <cstddef>
#include <cstdint>
#include "core/tls12.h"


constexpr size_t RANDOM_SIZE = 32; // Size of client random and server random
constexpr size_t PUBKEY_SIZE = 69;
constexpr size_t MESSAGE_TO_HASH_SIZE = RANDOM_SIZE * 2 + PUBKEY_SIZE;
constexpr size_t RSA_SIG_SIZE = 256;


// Pack structs to 1 byte alignment to avoid padding
#pragma pack(push, 1)

struct TLS_header {
    /** 0x15: Alert, 0x16: Handshake, 0x17: Application data */
    uint8_t content_type = HANDSHAKE;
    /** 0x0303 for TLS 1.2 */
    uint8_t version[2] = {0x03, 0x03};
    uint8_t length[2] = {0, 4};

    void set_length(const size_t k) {
        length[0] = k / 0x100;
        length[1] = k % 0x100;
    }

    [[nodiscard]]
    size_t get_length() const {
        return length[0] * 0x100 + length[1];
    }
};

struct handshake_header {
    uint8_t handshake_type = HELLO_REQUEST;
    uint8_t length[3] = {0, 0, 0};

    void set_length(const size_t k) {
        length[0] = k / 0x10000;
        length[1] = k % 0x10000 / 0x100;
        length[2] = k % 0x100;
    }

    [[nodiscard]]
    size_t get_length() const {
        return length[0] * 0x10000 + length[1] * 0x100 + length[2];
    }
};

struct hello_common {
    /** 0x0303 for TLS 1.2 */
    uint8_t version[2] = {0x03, 0x03};
    /** Server random and client random */
    uint8_t random[32] = {};
    uint8_t session_id_length = 32;
    uint8_t session_id[32] = {};
};

struct client_hello_message {
    TLS_header tls;
    handshake_header handshake{CLIENT_HELLO};
    hello_common hello;

    /* length of cipher_suite. It should be even number. */
    uint8_t cipher_suite_length[2] = {0, 2};
    /**
     * Cipher suite list that client can accept.
     * In this implementation, only TLS_ECDHE_RSA_AES128_GCM_SHA256 cipher suite (0xc02f) is concidered.
     */
    uint8_t cipher_suite[2] = {0xc0, 0x2f};
    uint8_t compression_length = 1;
    uint8_t compression_method = 0; // None

    [[nodiscard]]
    int get_cipher_suite_length() const {
        return cipher_suite_length[0] * 0x100 + cipher_suite_length[1];
    }
};

struct server_hello_message {
    TLS_header tls{.length = {0, sizeof(server_hello_message) - sizeof(TLS_header)}};
    handshake_header handshake{
        .handshake_type = SERVER_HELLO,
        .length = {0, 0, sizeof(server_hello_message) - sizeof(TLS_header) - sizeof(handshake_header)},
    };
    hello_common hello;
    /**
     * Cipher suite that server chose.
     * In this implementation, only TLS_ECDHE_RSA_AES128_GCM_SHA256 cipher suite (0xc02f) is concidered.
     */
    uint8_t cipher_suite[2] = {0xc0, 0x2f};
    uint8_t compression = 0;
    uint8_t extension_length[2] = {0, 0};
};

// Used only on client-side for handling received certificate message.
// On the server-side, a pre-prepared certificate message is simply sent.
struct certificate_message {
    TLS_header tls;
    handshake_header handshake;

    /** Total length of all certificates and length of the first certificate */
    uint8_t certificate_length[2][3] = {};
    unsigned char certificate[];
};

struct server_key_exchange_message {
    TLS_header tls;
    handshake_header handshake;

    // ServerECDHParams params;
    uint8_t named_curve = 3;
    uint8_t secp256r1[2] = {0, 0x17};
    uint8_t key_length = 65;
    uint8_t uncompressed = 4;
    uint8_t x[32] = {}, y[32] = {};

    // SignatureAndHashAlgorithm
    /**
     * signature hash  value
     * NONE            0
     * MD5             1
     * SHA-1           2
     * SHA-224         3
     * SHA-256         4
     * SHA-384         5
     * SHA-512         6
     */
    uint8_t signature_hash = 4;
    /**
     * signature sign  value
     * anonymous       0
     * RSA             1
     * DSA             2
     * ECDSA           3
     */
    uint8_t signature_sign = 1;

    // Signature signed_params;
    uint8_t signature_length[2] = {1, 0}; // length: 256 (0x100)
    uint8_t sign[RSA_SIG_SIZE] = {};
};

struct server_hello_done_message {
    TLS_header tls;
    handshake_header handshake{.handshake_type = SERVER_DONE};
};

struct client_key_exchange_message {
    TLS_header tls;
    handshake_header handshake{.handshake_type = CLIENT_KEY_EXCHANGE};
    uint8_t len = 65;
    uint8_t uncompressed = 4;
    uint8_t x[32] = {}, y[32] = {};
};

struct change_cipher_spec_message {
    TLS_header tls{.content_type = CHANGE_CIPHER_SPEC};
    uint8_t spec = 1;
};

// For parsing received message.
struct received_message {
    TLS_header tls;
    uint8_t iv[8] = {};
    unsigned char m[];
};

// Header for sending message.
struct send_message_header {
    TLS_header tls;
    uint8_t iv[8] = {};
};

// For authentication tag.
struct auth_tag_data {
    uint8_t seq[8] = {};
    TLS_header tls;
};

struct alert_message {
    /** tls.content_type: 0x15, tls.length: 2 */
    TLS_header tls{.content_type = ALERT, .length = {0, 2}};
    uint8_t alert_level;
    uint8_t alert_desc;

    alert_message(const uint8_t alert_level, const uint8_t alert_desc) {
        this->alert_level = alert_level;
        this->alert_desc = alert_desc;
    }
};

#pragma pack(pop)


#endif
