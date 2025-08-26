#include "protocol/layer.h"
#include <cstdint>
#include <functional>
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


// class BaseTLS12Layer<bool>

template<bool SV>
BaseTLS12Layer<SV>::BaseTLS12Layer(std::unique_ptr<Layer> lower)
    : VRecv{std::move(lower)} {}

template<bool SV>
void BaseTLS12Layer<SV>::send(const std::string &s) {
    VRecv::send(tls.encode(std::string{s}));
}

template<bool SV>
std::optional<std::string> BaseTLS12Layer<SV>::recv() {
    if (auto r = VRecv::recv(); r) {
        return tls.decode(std::string{*r});
    }
    return std::nullopt;
}

template<bool SV>
void BaseTLS12Layer<SV>::send_without_enc(const std::string &s) {
    VRecv::send(s);
}

template<bool SV>
std::optional<std::string> BaseTLS12Layer<SV>::recv_without_enc() {
    return VRecv::recv();
}

template<bool SV>
size_t BaseTLS12Layer<SV>::get_full_length(const std::string &s) {
    return s.size() < 5 ? 0 : static_cast<uint8_t>(s[3]) * 0x100 + static_cast<uint8_t>(s[4]) + 5;
}


// class TLS12Layer<SV_SERVER>

TLS12LayerServer::TLS12LayerServer(std::unique_ptr<Layer> lower)
    : BaseTLS12Layer{std::move(lower)} {}

void TLS12LayerServer::handshake() {
    tls.handshake();
}


// class TLS12Layer<SV_CLIENT>

TLS12LayerClient::TLS12LayerClient(std::unique_ptr<Layer> lower)
    : BaseTLS12Layer{std::move(lower)} {}

void TLS12LayerClient::handshake() {
    tls.handshake();
}
