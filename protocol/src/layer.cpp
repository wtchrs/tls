#include "protocol/layer.h"
#include <cstdint>
#include <regex>

// class TCPLayer

TCPLayer::TCPLayer(int socket_fd)
    : socket_fd_{socket_fd} {}

void TCPLayer::send(const std::string &s) {
    write(socket_fd_, s.data(), s.size());
}

std::optional<std::string> TCPLayer::recv() {
    if (size_t r = read(socket_fd_, buffer_, sizeof(buffer_)); r > 0) {
        return std::string{buffer_, r};
    }
    return std::nullopt;
}


// class VRecv

VRecv::VRecv(std::unique_ptr<Layer> lower)
    : lower_{std::move(lower)} {}

void VRecv::send(const std::string &s) {
    lower_->send(s);
}

std::optional<std::string> VRecv::recv() {
    size_t full_len;
    while ((full_len = get_full_length(received_)) <= 0 || received_.size() < full_len) {
        if (auto s = lower_->recv(); s) {
            received_ += *s;
        } else {
            return std::nullopt;
        }
    }
    auto r = received_.substr(0, full_len);
    received_ = received_.substr(full_len);
    return r;
}

size_t VRecv::get_full_length(const std::string &s) {
    return s.size();
}


// class HTTPLayer

HTTPLayer::HTTPLayer(std::unique_ptr<Layer> lower)
    : VRecv{std::move(lower)} {}

size_t HTTPLayer::get_full_length(const std::string &s) {
    std::smatch match;
    if (std::regex_match(s, match, std::regex{R"(Content-Length:\s*(\d+))"})) {
        if (auto header_length = s.find("\r\n\r\n"); header_length > 0) {
            return std::stoi(match[1].str()) + header_length + 4;
        }
        return -1;
    }
    return s.size();
}


// class BaseTLSLayer<bool>

template<bool SV>
BaseTLSLayer<SV>::BaseTLSLayer(std::unique_ptr<Layer> lower)
    : VRecv{std::move(lower)} {}

template<bool SV>
void BaseTLSLayer<SV>::send(const std::string &s) {
    VRecv::send(tls.encode(std::string{s}));
}

template<bool SV>
std::optional<std::string> BaseTLSLayer<SV>::recv() {
    if (auto r = VRecv::recv(); r) {
        return tls.decode(std::string{*r});
    }
    return std::nullopt;
}

template<bool SV>
void BaseTLSLayer<SV>::send_without_enc(const std::string &s) {
    VRecv::send(s);
}

template<bool SV>
std::optional<std::string> BaseTLSLayer<SV>::recv_without_enc() {
    return VRecv::recv();
}

template<bool SV>
size_t BaseTLSLayer<SV>::get_full_length(const std::string &s) {
    return s.size() < 5 ? 0 : static_cast<uint8_t>(s[3]) * 0x100 + static_cast<uint8_t>(s[4]) + 5;
}


// class TLSLayer<SV_SERVER>

TLSLayer<SV_SERVER>::TLSLayer(std::unique_ptr<Layer> lower)
    : BaseTLSLayer{std::move(lower)} {}

void TLSLayer<SV_SERVER>::handshake() {
    // TODO: Add error handling
    tls.client_hello(*recv_without_enc());
    auto server_hello = tls.server_hello();
    auto server_certificate = tls.server_certificate();
    auto server_key_exchange = tls.server_key_exchange();
    auto server_hello_done = tls.server_hello_done();
    send_without_enc(server_hello + server_certificate + server_key_exchange + server_hello_done);
    tls.client_key_exchange(*recv_without_enc());
    tls.change_cipher_spec(*recv_without_enc());
    tls.finished(*recv_without_enc());
    auto change_cipher_spec = tls.change_cipher_spec();
    auto finished = tls.finished();
    send_without_enc(change_cipher_spec + finished);
}


// class TLSLayer<SV_CLIENT>

TLSLayer<SV_CLIENT>::TLSLayer(std::unique_ptr<Layer> lower)
    : BaseTLSLayer{std::move(lower)} {}

void TLSLayer<SV_CLIENT>::handshake() {
    // TODO: Add error handling
    send_without_enc(tls.client_hello());
    tls.server_hello(*recv_without_enc());
    tls.server_certificate(*recv_without_enc());
    tls.server_key_exchange(*recv_without_enc());
    tls.server_hello_done(*recv_without_enc());
    auto client_key_exchange = tls.client_key_exchange();
    auto change_cipher_spec = tls.change_cipher_spec();
    auto finished = tls.finished();
    send_without_enc(client_key_exchange + change_cipher_spec + finished);
    tls.change_cipher_spec(*recv_without_enc());
    tls.finished(*recv_without_enc());
}
