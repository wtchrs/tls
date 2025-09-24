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

enum ContentType : uint8_t { CHANGE_CIPHER_SPEC = 0x14, ALERT = 0x15, HANDSHAKE = 0x16, APPLICATION_DATA = 0x17 };

enum ProtocolVersion : uint16_t { TLS_VERSION_12 = 0x0303, TLS_VERSION_13 = 0x0304 };

enum HandshakeType : uint8_t {
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

enum CipherSuite : uint16_t {
    // 2 cipher suites are currently supported in this implementation.
    TLS_ECDHE_RSA_AES128_GCM_SHA256 = 0xc02f, // TLS 1.2
    TLS_AES_128_GCM_SHA256 = 0x1301, // TLS 1.3
};

enum ECCurveType : uint8_t {
    EXPLICIT_PRIME = 1,
    EXPLICIT_CHAR2 = 2,
    NAMED_CURVE = 3,
    // reserved(248..255)
};

enum NamedCurve : uint16_t {
    NC_SECT163K1 = 1,
    NC_SECT163R1 = 2,
    NC_SECT163R2 = 3,
    NC_SECT193R1 = 4,
    NC_SECT193R2 = 5,
    NC_SECT233K1 = 6,
    NC_SECT233R1 = 7,
    NC_SECT239K1 = 8,
    NC_SECT283K1 = 9,
    NC_SECT283R1 = 10,
    NC_SECT409K1 = 11,
    NC_SECT409R1 = 12,
    NC_SECT571K1 = 13,
    NC_SECT571R1 = 14,
    NC_SECP160K1 = 15,
    NC_SECP160R1 = 16,
    NC_SECP160R2 = 17,
    NC_SECP192K1 = 18,
    NC_SECP192R1 = 19,
    NC_SECP224K1 = 20,
    NC_SECP224R1 = 21,
    NC_SECP256K1 = 22,
    NC_SECP256R1 = 23,
    NC_SECP384R1 = 24,
    NC_SECP521R1 = 25,
    // reserved (0xFE00..0xFEFF),
    NC_ARBITRARY_EXPLICIT_PRIME_CURVES = 0xFF01,
    NC_ARBITRARY_EXPLICIT_CHAR2_CURVES = 0xFF02,
    // (0xFFFF)
};

enum HashAlgorithm : uint8_t {
    NONE = 0,
    MD5 = 1,
    SHA1 = 2,
    SHA224 = 3,
    SHA256 = 4,
    SHA384 = 5,
    SHA512 = 6,
};

enum SignatureAlgorithm : uint8_t { ANONYMOUS = 0, RSA = 1, DSA = 2, ECDSA = 3 };

enum ExtensionType : uint16_t {
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

enum NamedGroup : uint16_t {
    /* Elliptic Curve Groups (ECDHE) */
    NG_SECP256R1 = 0x0017,
    NG_SECP384R1 = 0x0018,
    NG_SECP521R1 = 0x0019,
    NG_X25519 = 0x001D,
    NG_X448 = 0x001E,

    /* Finite Field Groups (DHE) */
    NG_FFDHE2048 = 0x0100,
    NG_FFDHE3072 = 0x0101,
    NG_FFDHE4096 = 0x0102,
    NG_FFDHE6144 = 0x0103,
    NG_FFDHE8192 = 0x0104,

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

// Currently implemented ECDHE_RSA NamedCurve Uncompressed format ServerKeyExchange message
// TODO: Extend this implementation to support all curve types and all ServerKeyExchange messages
// See more:
// - TLSECC(https://datatracker.ietf.org/doc/html/rfc4492)
// - TLS 1.2(https://datatracker.ietf.org/doc/html/rfc5246#section-7.4.3)
// - https://datatracker.ietf.org/doc/html/rfc8422#section-5.4
struct EcdheRsaServerKeyExchange : public BaseMessage {
    // ECParameters
    ECCurveType curve_type = NAMED_CURVE;
    NamedCurve named_curve = NC_SECP256R1;

    // ECPoint
    uint8_t point_format = 0x04; // uncompressed
    std::array<uint8_t, 32> x, y;

    // Digitally-signed signature
    HashAlgorithm hash;
    SignatureAlgorithm signature;
    std::vector<uint8_t> sign;

    EcdheRsaServerKeyExchange() = default;

    EcdheRsaServerKeyExchange(
        ECCurveType curve_type,
        NamedCurve named_curve,
        uint8_t point_format,
        std::array<uint8_t, 32> &&x,
        std::array<uint8_t, 32> &&y,
        HashAlgorithm hash,
        SignatureAlgorithm signature,
        std::vector<uint8_t> &&sign
    );

    ~EcdheRsaServerKeyExchange() = default;

    static std::optional<EcdheRsaServerKeyExchange> parse(const std::string &raw);
    std::string serialize() const override;
};

struct ServerHelloDone : public BaseMessage {
    ~ServerHelloDone() = default;

    static std::optional<ServerHelloDone> parse(const std::string &raw);
    std::string serialize() const override;
};

struct EcdheClientKeyExchange : public BaseMessage {
    uint8_t point_format = 0x04; // uncompressed
    std::array<uint8_t, 32> x, y;

    EcdheClientKeyExchange() = default;
    EcdheClientKeyExchange(uint8_t point_format, std::array<uint8_t, 32> &&x, std::array<uint8_t, 32> &&y);

    ~EcdheClientKeyExchange() = default;

    static std::optional<EcdheClientKeyExchange> parse(const std::string &raw);
    std::string serialize() const override;
};

struct Finished : public BaseMessage {
    std::array<uint8_t, 12> verify_data;

    Finished() = default;
    Finished(std::array<uint8_t, 12> &&verify_data);
    Finished(const std::vector<uint8_t> &data);

    ~Finished() = default;

    static std::optional<Finished> parse(const std::string &raw);
    std::string serialize() const override;
};

using HandshakeMsg = std::variant<
    ClientHello,
    ServerHello,
    Certificate,
    EcdheRsaServerKeyExchange,
    ServerHelloDone,
    EcdheClientKeyExchange,
    Finished>;

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

struct ChangeCipherSpec : public BaseMessage {
    enum ChangeCipherSpecType : uint8_t {
        CHANGE_CIPHER_SPEC = 1,
    };

    ChangeCipherSpecType type = CHANGE_CIPHER_SPEC;

    ChangeCipherSpec() = default;
    ChangeCipherSpec(ChangeCipherSpecType type);
    ~ChangeCipherSpec() = default;

    static std::optional<ChangeCipherSpec> parse(const std::string &raw);
    std::string serialize() const override;
};

/** Struct for AES-GSM Additional Authenticated Data */
struct AAD : BaseMessage {
    std::array<uint8_t, 8> seq;
    ContentType content_type;
    ProtocolVersion version;
    uint16_t length;

    AAD() = default;
    AAD(std::array<uint8_t, 8> seq, ContentType content_type, ProtocolVersion version, uint16_t length);
    ~AAD() = default;

    std::string serialize() const override;
};

struct EncodedMessage : public BaseMessage {
    std::array<uint8_t, 8> iv;
    std::string data;
    std::array<uint8_t, 16> auth_tag;

    EncodedMessage() = default;
    EncodedMessage(std::array<uint8_t, 8> &&iv, std::string &&data, std::array<uint8_t, 16> &&auth_tag);

    ~EncodedMessage() = default;

    static std::optional<EncodedMessage> parse(const std::string &raw);
    std::string serialize() const override;
};

// TODO: Add Alert message
using Msg = std::variant<Handshake, ChangeCipherSpec, EncodedMessage>;

struct Record : public BaseMessage {
    ContentType content_type;
    ProtocolVersion version;
    // length(2byte)

    std::vector<Msg> messages;

    Record() {}
    Record(ContentType content_type, ProtocolVersion protocol_version, std::initializer_list<Msg> messages);

    ~Record() {}

    static std::optional<Record> parse(const std::string &raw, bool encoded = false);
    std::string serialize() const override;
};


} // namespace tls


#endif
