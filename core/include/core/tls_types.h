#ifndef CORE_TLS_TYPES_H
#define CORE_TLS_TYPES_H


#include <array>
#include <cstdint>
#include <initializer_list>
#include <optional>
#include <string>
#include <variant>
#include <vector>

namespace tls {

// 1 byte
enum ContentType { CHANGE_CIPHER_SPEC = 0x14, ALERT = 0x15, HANDSHAKE = 0x16, APPLICATION_DATA = 0x17 };

// 2 bytes
enum ProtocolVersion { TLS_VERSION_12 = 0x0303, TLS_VERSION_13 = 0x0304 };

// 1 byte
enum HandshakeType {
    HELLO_REQUEST = 0x00,
    CLIENT_HELLO = 0x01,
    SERVER_HELLO = 0x02,
    CERTIFICATE = 0x0b,
    SERVER_KEY_EXCHANGE = 0x0c,
    CERTIFICATE_REQUEST = 0x0d,
    SERVER_DONE = 0x0e,
    CERTIFICATE_VERIFY = 0x0f,
    CLIENT_KEY_EXCHANGE = 0x10,
    FINISHED = 0x14
};

// 2 bytes
enum CipherSuite {
    // 2 cipher suites are currently supported.
    TLS_ECDHE_RSA_AES128_GCM_SHA256 = 0xc02f, // TLS 1.2
    TLS_AES_128_GCM_SHA256 = 0x1301, // TLS 1.3
};

// 2 bytes
enum ExtensionType {
    SERVER_NAME = 0,
    MAX_FRAGMENT_LENGTH = 1,
    STATUS_REQUEST = 5,
    SUPPORTED_GROUPS = 10,
    EC_POINT_FORMATS = 11,
    SIGNATURE_ALGORITHMS = 13,
    USE_SRTP = 14,
    HEARTBEAT = 15,
    APPLICATION_LAYER_PROTOCOL_NEGOTIATION = 16,
    SIGNED_CERTIFICATE_TIMESTAMP = 18,
    CLIENT_CERTIFICATE_TYPE = 19,
    SERVER_CERTIFICATE_TYPE = 20,
    PADDING = 21,
    PRE_SHARED_KEY = 41,
    EARLY_DATA = 42,
    SUPPORTED_VERSIONS = 43,
    COOKIE = 44,
    PSK_KEY_EXCHANGE_MODES = 45,
    CERTIFICATE_AUTHORITIES = 47,
    OID_FILTERS = 48,
    POST_HANDSHAKE_AUTH = 49,
    SIGNATURE_ALGORITHMS_CERT = 50,
    KEY_SHARE = 51,
};

// 2 bytes
enum NamedGroup {
    /* Elliptic Curve Groups (ECDHE) */
    SECP256R1 = 0x0017,
    SECP384R1 = 0x0018,
    SECP521R1 = 0x0019,
    X25519 = 0x001D,
    X448 = 0x001E,

    /* Finite Field Groups (DHE) */
    FFDHE2048 = 0x0100,
    FFDHE3072 = 0x0101,
    FFDHE4096 = 0x0102,
    FFDHE6144 = 0x0103,
    FFDHE8192 = 0x0104,

    /* Reserved Code Points */
    /* FFDHE_PRIVATE_USE(0x01FC..0x01FF) */
    /* ECDHE_PRIVATE_USE(0xFE00..0xFEFF) */
};

struct BaseMessage {
    virtual ~BaseMessage() {}
    virtual std::string serialize() const = 0;
};


/***** Extensions *****/

// TODO: Add other extensions and implement all needed extensions.

struct SupportedGroups : public BaseMessage {
    std::vector<NamedGroup> named_groups;

    ~SupportedGroups() {}

    static std::optional<SupportedGroups> parse(const std::string &raw);
    std::string serialize() const override;
};
/*
struct ECPointFormats : public BaseMessage {
    ~ECPointFormats() {}
    static std::optional<ECPointFormats> parse(const std::string &raw);
    std::string serialize() const override;
};
struct KeyShare : public BaseMessage {
    ~KeyShare() {}
    static std::optional<KeyShare> parse(const std::string &raw);
    std::string serialize() const override;
};
struct SupportedVersions : public BaseMessage {
    ~SupportedVersions() {}
    static std::optional<SupportedVersions> parse(const std::string &raw);
    std::string serialize() const override;
};
struct PskMode : public BaseMessage {
    ~PskMode() {}
    static std::optional<PskMode> parse(const std::string &raw);
    std::string serialize() const override;
};
struct SignatureAlgorithms : public BaseMessage {
    ~SignatureAlgorithms() {}
    static std::optional<SignatureAlgorithms> parse(const std::string &raw);
    std::string serialize() const override;
};
*/

using ExtensionMsg =
    std::variant<SupportedGroups /*, ECPointFormats, KeyShare, SupportedVersions, PskMode, SignatureAlgorithms*/>;

struct Extensions : public BaseMessage {
    std::vector<ExtensionMsg> extensions;

    ~Extensions() {}

    static std::optional<Extensions> parse(const std::string &raw);
    std::string serialize() const override;
};


/***** Handshakes *****/

// TODO: Implement all handshake structs.

struct ClientHello : BaseMessage {
    ProtocolVersion client_hello_version = TLS_VERSION_12;
    std::array<uint8_t, 32> client_random;
    std::vector<uint8_t> session_id;

    /** Cipher suite list that client can accept. */
    std::vector<CipherSuite> cipher_suites;
    std::vector<uint8_t> compression_methods;

    std::optional<Extensions> extensions;

    ClientHello() {}
    ClientHello(
        ProtocolVersion protocol_version,
        std::array<uint8_t, 32> &&client_random,
        std::vector<uint8_t> &&session_id,
        std::vector<CipherSuite> &&cipher_suite,
        std::vector<uint8_t> &&compression_methods
    );

    ~ClientHello() {}

    static std::optional<ClientHello> parse(const std::string &raw);
    std::string serialize() const override;
};

struct ServerHello : public BaseMessage {
    ProtocolVersion server_hello_version = TLS_VERSION_12;
    std::array<uint8_t, 32> server_random;
    std::vector<uint8_t> session_id;

    /** Cipher suite that server chose. */
    CipherSuite cipher_suite;
    /** Compression method that server chose. */
    uint8_t compression_method;

    std::optional<Extensions> extensions;

    ServerHello() {}
    ServerHello(
        ProtocolVersion protocol_version,
        std::array<uint8_t, 32> &&server_random,
        std::vector<uint8_t> &&session_id,
        CipherSuite cipher_suite,
        uint8_t compression_method
    );

    ~ServerHello() {}

    static std::optional<ServerHello> parse(const std::string &raw);
    std::string serialize() const override;
};

struct Certificate : public BaseMessage {
    std::vector<std::string> certificates;

    Certificate() {}
    Certificate(std::vector<std::string> &&certificates);

    ~Certificate() {}

    static std::optional<Certificate> parse(const std::string &raw);
    std::string serialize() const override;
};

/*
struct ServerKeyExchange : public BaseMessage {
    ~ServerKeyExchange() {}
    static std::optional<ServerKeyExchange> parse(const std::string &raw);
    std::string serialize() const override;
};
struct ServerHelloDone : public BaseMessage {
    ~ServerHelloDone() {}
    static std::optional<ServerHelloDone> parse(const std::string &raw);
    std::string serialize() const override;
};
struct ClientKeyExchange : public BaseMessage {
    ~ClientKeyExchange() {}
    static std::optional<ClientKeyExchange> parse(const std::string &raw);
    std::string serialize() const override;
};
struct Finished : public BaseMessage {
    ~Finished() {}
    static std::optional<Finished> parse(const std::string &raw);
    std::string serialize() const override;
};
*/

using HandshakeMsg = std::variant<
    ClientHello,
    ServerHello,
    Certificate /*, ServerKeyExchange, ServerHelloDone, ClientKeyExchange, Finished */>;

struct Handshake : public BaseMessage {
    HandshakeType handshake_type;
    // handshake length(3byte)
    HandshakeMsg message;

    Handshake() {}
    Handshake(HandshakeType handshake_type, HandshakeMsg message);

    ~Handshake() {}

    static std::optional<Handshake> parse(const std::string &raw);
    std::string serialize() const override;
};


// TODO: Add other types.
using Msg = std::variant<Handshake>;

struct Record : public BaseMessage {
    ContentType content_type;
    ProtocolVersion version;
    // length(2byte)

    std::vector<Msg> messages;

    Record() {}
    Record(ContentType content_type, ProtocolVersion protocol_version, std::initializer_list<Msg> messages);

    ~Record() {}

    static std::optional<Record> parse(const std::string &raw);
    std::string serialize() const override;
};


} // namespace tls


#endif
