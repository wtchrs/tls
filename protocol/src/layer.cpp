#include "protocol/layer.h"
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

FramedReceive::FramedReceive(std::unique_ptr<Layer> lower)
    : lower_{std::move(lower)} {}

void FramedReceive::send(const std::string &s) {
    lower_->send(s);
}

std::optional<std::string> FramedReceive::recv() {
    size_t full_len;
    while ((full_len = get_frame_length(received_)) <= 0 || received_.size() < full_len) {
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

size_t FramedReceive::get_frame_length(const std::string &s) {
    return s.size();
}


// class HTTPLayer

HTTPLayer::HTTPLayer(std::unique_ptr<Layer> lower)
    : FramedReceive{std::move(lower)} {}

size_t HTTPLayer::get_frame_length(const std::string &s) {
    std::smatch match;
    if (std::regex_match(s, match, std::regex{R"(Content-Length:\s*(\d+))"})) {
        if (auto header_length = s.find("\r\n\r\n"); header_length > 0) {
            return std::stoi(match[1].str()) + header_length + 4;
        }
        return -1;
    }
    return s.size();
}
