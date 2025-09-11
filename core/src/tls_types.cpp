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
    extension_parse_handlers{
        {tls::SUPPORTED_GROUPS, tls::SupportedGroups::parse},
        /*
        {tls::EC_POINT_FORMATS, tls::ECPointFormats::parse},
        {tls::KEY_SHARE, tls::KeyShare::parse},
        {tls::SUPPORTED_VERSIONS, tls::SupportedVersions::parse},
        {tls::PSK_KEY_EXCHANGE_MODES, tls::PskMode::parse},
        {tls::SIGNATURE_ALGORITHMS, tls::SignatureAlgorithms::parse},
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

    switch (handshake.handshake_type) {
    // TODO: Implement each cases.
    case HELLO_REQUEST: break;
    case CLIENT_HELLO: {
        auto msg = ClientHello::parse(subraw);
        if (!msg)
            return std::nullopt;
        handshake.message = *msg;
        break;
    }
    case SERVER_HELLO: break;
    case CERTIFICATE: break;
    case SERVER_KEY_EXCHANGE: break;
    case CERTIFICATE_REQUEST: break;
    case SERVER_DONE: break;
    case CERTIFICATE_VERIFY: break;
    case CLIENT_KEY_EXCHANGE: break;
    case FINISHED: break;
    }

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
    std::copy_n(&raw[2], 32, client_hello.client_random.data());
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

std::optional<Extensions> Extensions::parse(const std::string &raw) {
    Extensions extensions;
    size_t total_length = (static_cast<uint8_t>(raw[0]) << 8) + static_cast<uint8_t>(raw[1]);
    size_t pos = 2;
    while (pos < total_length) {
        auto type =
            static_cast<ExtensionType>((static_cast<uint8_t>(raw[pos]) << 8) + static_cast<uint8_t>(raw[pos + 1]));
        size_t ext_length = (static_cast<uint8_t>(raw[pos + 2]) << 8) + static_cast<uint8_t>(raw[pos + 3]) + 4;
        auto handler = extension_parse_handlers.find(type);
        if (handler == extension_parse_handlers.end())
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

/***** Extension Messages *****/

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
