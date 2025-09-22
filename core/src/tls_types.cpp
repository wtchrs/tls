#include "core/tls_types.h"
#include <algorithm>
#include <cassert>
#include <cstddef>
#include <functional>
#include <optional>
#include <string>
#include <unordered_map>
#include <variant>


const std::unordered_map< tls::ExtensionType, std::function<std::optional<tls::ExtensionMsg>(const std::string &)>>
    extension_parsing_handlers{
        {tls::SUPPORTED_GROUPS, tls::SupportedGroups::parse},
        /*
        {tls::EC_POINT_FORMATS, tls::ECPointFormats::parse},
        {tls::KEY_SHARE, tls::KeyShare::parse},
        {tls::SUPPORTED_VERSIONS, tls::SupportedVersions::parse},
        {tls::PSK_KEY_EXCHANGE_MODES, tls::PskMode::parse},
        {tls::SIGNATURE_ALGORITHMS, tls::SignatureAlgorithms::parse},
        */
    };

const std::unordered_map<tls::HandshakeType, std::function<std::optional<tls::HandshakeMsg>(const std::string &)>>
    handshake_parsing_handlers{
        {tls::CLIENT_HELLO, tls::ClientHello::parse},
        {tls::SERVER_HELLO, tls::ServerHello::parse},
        {tls::CERTIFICATE, tls::Certificate::parse},
        {tls::SERVER_KEY_EXCHANGE, tls::EcdheRsaServerKeyExchange::parse},
        {tls::SERVER_DONE, tls::ServerHelloDone::parse},
        /*
        {tls::CLIENT_KEY_EXCHANGE, tls::ClientKeyExchange::parse},
        {tls::FINISHED, tls::Finished::parse},
        */
    };


template<typename Msg>
static std::string serialize(const Msg &msg) {
    return msg.serialize();
}

template<typename Variant>
static std::string serialize_variant(const Variant &variant) {
    return std::visit([](const auto &m) { return serialize(m); }, variant);
}


namespace tls {

Record::Record(ContentType content_type, ProtocolVersion protocol_version, std::initializer_list<Msg> messages)
    : content_type{content_type}
    , version{protocol_version}
    , messages{messages} {}

std::optional<Record> Record::parse(const std::string &raw) {
    Record rec;
    rec.content_type = static_cast<ContentType>(static_cast<uint8_t>(raw[0]));
    auto ver = (static_cast<uint8_t>(raw[1]) << 8) + static_cast<uint8_t>(raw[2]);
    rec.version = static_cast<ProtocolVersion>(ver);
    size_t length = (static_cast<uint8_t>(raw[3]) << 8) + static_cast<uint8_t>(raw[4]);
    auto subraw = raw.substr(5, 5 + length);

    switch (rec.content_type) {
    // TODO: Implement each cases.
    case APPLICATION_DATA: break;
    case HANDSHAKE: {
        auto msg = Handshake::parse(subraw);
        if (!msg)
            return std::nullopt;
        rec.messages.push_back(*msg);
        break;
    }
    case CHANGE_CIPHER_SPEC: break;
    case ALERT: break;
    }

    return rec;
}

std::string Record::serialize() const {
    std::string messages;
    for (auto &msg : this->messages)
        messages.append(serialize_variant(msg));
    std::string r;
    r.append(1, static_cast<char>(this->content_type));
    auto version = static_cast<unsigned int>(this->version);
    r.append(1, static_cast<char>(version >> 8));
    r.append(1, static_cast<char>(version));
    auto length = messages.length();
    r.append(1, static_cast<char>(length >> 8));
    r.append(1, static_cast<char>(length));
    return r + messages;
}


Handshake::Handshake(HandshakeType handshake_type, HandshakeMsg message)
    : handshake_type{handshake_type}
    , message{message} {}

std::optional<Handshake> Handshake::parse(const std::string &raw) {
    Handshake handshake;
    handshake.handshake_type = static_cast<HandshakeType>(static_cast<uint8_t>(raw[0]));
    size_t length =
        (static_cast<uint8_t>(raw[1]) << 16) + (static_cast<uint8_t>(raw[2]) << 8) + static_cast<uint8_t>(raw[3]);
    auto subraw = raw.substr(4, 4 + length);

    const auto &handler = handshake_parsing_handlers.find(handshake.handshake_type);
    if (handler == handshake_parsing_handlers.end())
        return std::nullopt;
    auto res = handler->second(subraw);
    if (!res)
        return std::nullopt;
    handshake.message = *res;

    return handshake;
}

std::string Handshake::serialize() const {
    std::string message = serialize_variant(this->message);
    std::string r;
    r.append(1, static_cast<char>(this->handshake_type));
    size_t message_length = message.length();
    r.append(1, static_cast<char>(message_length >> 16));
    r.append(1, static_cast<char>(message_length >> 8));
    r.append(1, static_cast<char>(message_length));
    return r + message;
}

/***** Handshake Messages *****/

ClientHello::ClientHello(
    ProtocolVersion protocol_version,
    std::array<uint8_t, 32> &&client_random,
    std::vector<uint8_t> &&session_id,
    std::vector<CipherSuite> &&cipher_suite,
    std::vector<uint8_t> &&compression_methods
)
    : client_hello_version{protocol_version}
    , client_random{std::move(client_random)}
    , session_id{std::move(session_id)}
    , cipher_suites{std::move(cipher_suite)}
    , compression_methods{std::move(compression_methods)} {}

std::optional<ClientHello> ClientHello::parse(const std::string &raw) {
    ClientHello client_hello;
    client_hello.client_hello_version =
        static_cast<ProtocolVersion>((static_cast<uint8_t>(raw[0]) << 8) + static_cast<uint8_t>(raw[1]));
    std::copy_n(&raw[2], 32, client_hello.client_random.begin());
    size_t session_id_length = static_cast<uint8_t>(raw[34]);
    client_hello.session_id.resize(session_id_length);
    std::copy_n(&raw[35], session_id_length, client_hello.session_id.begin());
    size_t cipher_suite_pos = 35 + session_id_length;
    size_t cipher_suite_length =
        (static_cast<uint8_t>(raw[cipher_suite_pos]) << 8) + static_cast<uint8_t>(raw[cipher_suite_pos + 1]) + 2;
    for (auto pos = cipher_suite_pos + 2; pos < cipher_suite_pos + cipher_suite_length; pos += 2) {
        auto suite = (static_cast<uint8_t>(raw[pos]) << 8) + static_cast<uint8_t>(raw[pos + 1]);
        client_hello.cipher_suites.push_back(static_cast<CipherSuite>(suite));
    }
    size_t comp_pos = cipher_suite_pos + cipher_suite_length;
    size_t compression_length = static_cast<uint8_t>(raw[comp_pos]) + 1;
    for (auto pos = comp_pos + 1; pos < comp_pos + compression_length; ++pos) {
        client_hello.compression_methods.push_back(static_cast<uint8_t>(raw[pos]));
    }
    size_t ext_pos = comp_pos + compression_length;
    if (ext_pos < raw.size()) {
        auto ext = Extensions::parse(raw.substr(ext_pos));
        if (!ext)
            return std::nullopt;
        client_hello.extensions = std::move(ext);
    }
    return client_hello;
}

std::string ClientHello::serialize() const {
    std::string r;
    auto version_value = static_cast<int>(this->client_hello_version);
    r.append(1, static_cast<char>(version_value >> 8));
    r.append(1, static_cast<char>(version_value));
    r.append(reinterpret_cast<const char *>(this->client_random.data()), 32);
    size_t session_id_length = this->session_id.size();
    r.append(1, static_cast<char>(session_id_length));
    r.append(reinterpret_cast<const char *>(this->session_id.data()), session_id_length);
    size_t cipher_suite_length = this->cipher_suites.size() * 2;
    r.append(1, cipher_suite_length >> 8);
    r.append(1, cipher_suite_length);
    for (const auto &suite : this->cipher_suites) {
        r.append(1, static_cast<char>(suite >> 8));
        r.append(1, static_cast<char>(suite));
    }
    size_t compression_methods_length = this->compression_methods.size();
    r.append(1, compression_methods_length);
    for (const auto &comp : this->compression_methods) {
        r.append(1, static_cast<char>(comp));
    }
    if (extensions)
        r.append(extensions->serialize());
    return r;
}

ServerHello::ServerHello(
    ProtocolVersion protocol_version,
    std::array<uint8_t, 32> &&server_random,
    std::vector<uint8_t> &&session_id,
    CipherSuite cipher_suite,
    uint8_t compression_method
)
    : server_hello_version{protocol_version}
    , server_random{std::move(server_random)}
    , session_id{std::move(session_id)}
    , cipher_suite{cipher_suite}
    , compression_method{compression_method} {}

std::optional<ServerHello> ServerHello::parse(const std::string &raw) {
    ServerHello server_hello;
    server_hello.server_hello_version =
        static_cast<ProtocolVersion>((static_cast<uint8_t>(raw[0]) << 8) + static_cast<uint8_t>(raw[1]));
    std::copy_n(&raw[2], 32, server_hello.server_random.begin());
    size_t session_id_length = static_cast<uint8_t>(raw[34]);
    server_hello.session_id.resize(session_id_length);
    std::copy_n(&raw[35], session_id_length, server_hello.session_id.begin());
    size_t cs_pos = 35 + session_id_length;
    auto raw_cipher_suite = (static_cast<uint8_t>(raw[cs_pos]) << 8) + static_cast<uint8_t>(raw[cs_pos + 1]);
    server_hello.cipher_suite = static_cast<CipherSuite>(raw_cipher_suite);
    size_t comp_pos = cs_pos + 2;
    server_hello.compression_method = static_cast<uint8_t>(raw[comp_pos]);
    if (comp_pos + 1 < raw.length()) {
        auto ext = Extensions::parse(raw.substr(comp_pos + 1));
        if (!ext)
            return std::nullopt;
        server_hello.extensions = std::move(ext);
    }
    return server_hello;
}

std::string ServerHello::serialize() const {
    std::string msg;
    msg.append(1, this->server_hello_version >> 8);
    msg.append(1, this->server_hello_version);
    msg.append(this->server_random.begin(), this->server_random.end());
    auto session_id_length = this->session_id.size();
    msg.append(1, session_id_length);
    msg.append(this->session_id.begin(), this->session_id.end());
    msg.append(1, this->cipher_suite >> 8);
    msg.append(1, this->cipher_suite);
    msg.append(1, this->compression_method);
    if (this->extensions)
        msg.append(this->extensions->serialize());
    return msg;
}

Certificate::Certificate(std::vector<std::string> &&certificates)
    : certificates{std::move(certificates)} {}

std::optional<Certificate> Certificate::parse(const std::string &raw) {
    size_t total_len =
        (static_cast<uint8_t>(raw[0]) << 16) + (static_cast<uint8_t>(raw[1]) << 8) + static_cast<uint8_t>(raw[2]) + 3;
    Certificate certificate;
    for (size_t pos = 3; pos < total_len;) {
        size_t len = (static_cast<uint8_t>(raw[pos]) << 16) + (static_cast<uint8_t>(raw[pos + 1]) << 8) +
                     static_cast<uint8_t>(raw[pos + 2]);
        certificate.certificates.push_back(raw.substr(pos + 3, pos + 3 + len));
        pos += len + 3;
    }
    return certificate;
}

std::string Certificate::serialize() const {
    std::string msg;
    for (const auto &cert : this->certificates) {
        size_t len = cert.length();
        msg.append(1, len >> 16);
        msg.append(1, len >> 8);
        msg.append(1, len);
        msg.append(cert);
    }
    size_t total_len = msg.length();
    std::string r;
    r.append(1, total_len >> 16);
    r.append(1, total_len >> 8);
    r.append(1, total_len);
    return r + msg;
}

EcdheRsaServerKeyExchange::EcdheRsaServerKeyExchange(
    ECCurveType curve_type,
    NamedCurve named_curve,
    uint8_t point_format,
    std::array<uint8_t, 32> &&x,
    std::array<uint8_t, 32> &&y,
    HashAlgorithm hash,
    SignatureAlgorithm signature,
    std::vector<uint8_t> &&sign
)
    : curve_type{curve_type}
    , named_curve{named_curve}
    , point_format{point_format}
    , x{std::move(x)}
    , y{std::move(y)}
    , hash{hash}
    , signature{signature}
    , sign{std::move(sign)} {}

std::optional<EcdheRsaServerKeyExchange> EcdheRsaServerKeyExchange::parse(const std::string &raw) {
    EcdheRsaServerKeyExchange message;
    message.curve_type = static_cast<ECCurveType>(static_cast<uint8_t>(raw[0]));
    message.named_curve = static_cast<NamedCurve>((static_cast<uint8_t>(raw[1]) << 8) + static_cast<uint8_t>(raw[2]));
    if (message.curve_type != NAMED_CURVE || message.named_curve != NC_SECP256R1)
        return std::nullopt;
    size_t key_len = static_cast<uint8_t>(raw[3]);
    message.point_format = static_cast<uint8_t>(raw[4]);
    if (key_len != 65 || message.point_format != 4)
        return std::nullopt;
    std::copy_n(&raw[5], 32, message.x.begin());
    std::copy_n(&raw[37], 32, message.y.begin());
    message.hash = static_cast<HashAlgorithm>(static_cast<uint8_t>(raw[69]));
    message.signature = static_cast<SignatureAlgorithm>(static_cast<uint8_t>(raw[70]));
    size_t sign_len = (static_cast<uint8_t>(raw[71]) << 8) + static_cast<uint8_t>(raw[72]);
    message.sign.resize(sign_len);
    std::copy_n(&raw[73], sign_len, message.sign.begin());
    return message;
}

std::string EcdheRsaServerKeyExchange::serialize() const {
    std::string msg;
    msg.append(1, this->curve_type);
    msg.append(1, this->named_curve >> 8);
    msg.append(1, this->named_curve);
    size_t point_len = 1 + this->x.size() + this->y.size(); // point_format + x + y
    msg.append(1, point_len);
    msg.append(1, this->point_format);
    msg.append(this->x.begin(), this->x.end());
    msg.append(this->y.begin(), this->y.end());
    msg.append(1, this->hash);
    msg.append(1, this->signature);
    auto sign_len = this->sign.size();
    msg.append(1, sign_len >> 8);
    msg.append(1, sign_len);
    msg.append(this->sign.begin(), this->sign.end());
    return msg;
}

std::optional<ServerHelloDone> ServerHelloDone::parse(const std::string &raw) {
    if (!raw.empty())
        return std::nullopt;
    return ServerHelloDone{};
}

std::string ServerHelloDone::serialize() const {
    return "";
}


/***** Extension Messages *****/

std::optional<Extensions> Extensions::parse(const std::string &raw) {
    Extensions extensions;
    size_t total_length = (static_cast<uint8_t>(raw[0]) << 8) + static_cast<uint8_t>(raw[1]);
    size_t pos = 2;
    while (pos < total_length) {
        auto type =
            static_cast<ExtensionType>((static_cast<uint8_t>(raw[pos]) << 8) + static_cast<uint8_t>(raw[pos + 1]));
        size_t ext_length = (static_cast<uint8_t>(raw[pos + 2]) << 8) + static_cast<uint8_t>(raw[pos + 3]) + 4;
        auto handler = extension_parsing_handlers.find(type);
        if (handler == extension_parsing_handlers.end())
            return std::nullopt;
        auto res = handler->second(raw.substr(pos, pos + ext_length));
        if (!res)
            return std::nullopt;
        extensions.extensions.push_back(*res);
        pos += ext_length;
    }
    return extensions;
}

std::string Extensions::serialize() const {
    std::string contents;
    for (const auto &ext : this->extensions) {
        contents.append(serialize_variant(ext));
    }
    std::string r;
    size_t total_length = contents.length();
    r.append(1, total_length >> 8);
    r.append(1, total_length);
    return r + contents;
}

std::optional<SupportedGroups> SupportedGroups::parse(const std::string &raw) {
    size_t ext_len = (static_cast<uint8_t>(raw[2]) << 8) + static_cast<uint8_t>(raw[3]);
    size_t list_len = (static_cast<uint8_t>(raw[4]) << 8) + static_cast<uint8_t>(raw[5]);
    if (ext_len != list_len + 2)
        return std::nullopt;
    SupportedGroups ext;
    for (size_t pos = 6; pos < list_len + 6; pos += 2) {
        ext.named_groups.push_back(
            static_cast<NamedGroup>((static_cast<uint8_t>(raw[pos]) << 8) + static_cast<uint8_t>(raw[pos + 1]))
        );
    }
    return ext;
}

std::string SupportedGroups::serialize() const {
    std::string list;
    for (const auto &ng : this->named_groups) {
        list.append(1, static_cast<char>(ng >> 8));
        list.append(1, static_cast<char>(ng));
    }
    size_t list_len = list.length();
    size_t ext_len = list_len + 2;
    std::string r;
    r.append(1, static_cast<char>(SUPPORTED_GROUPS >> 8));
    r.append(1, static_cast<char>(SUPPORTED_GROUPS));
    r.append(1, static_cast<char>(ext_len >> 8));
    r.append(1, static_cast<char>(ext_len));
    r.append(1, static_cast<char>(list_len >> 8));
    r.append(1, static_cast<char>(list_len));
    return r + list;
}

} // namespace tls
