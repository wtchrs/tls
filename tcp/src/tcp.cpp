#include "tcp/tcp.h"
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <optional>
#include <unistd.h>

Tcp::Tcp(uint16_t port) {
    std::fill_n(reinterpret_cast<uint8_t *>(&server_addr), sizeof(server_addr), 0);
    std::fill_n(reinterpret_cast<uint8_t *>(&client_addr), sizeof(client_addr), 0);
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    server_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    client_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
}

Tcp::~Tcp() {
    std::cout << "Destroying Tcp" << std::endl;
    if (client_fd) {
        close(client_fd);
    }
    if (server_fd) {
        close(server_fd);
    }
}

void Tcp::send(const std::string &s, int fd) {
    fd = !fd ? client_fd : fd;
    write(fd, s.data(), s.size());
}

std::optional<std::string> Tcp::recv(int fd) {
    fd = !fd ? client_fd : fd;
    if (size_t r = read(fd, buffer, BUF_SIZE); r > 0) {
        return std::string{buffer, r};
    }
    return std::nullopt;
}

Vrecv::Vrecv(uint16_t port)
    : Tcp{port} {}

std::optional<std::string> Vrecv::recv(int fd) {
    size_t len;
    static thread_local std::string trailing_string;
    while ((len = get_full_length(trailing_string)) <= 0 || len > trailing_string.size()) {
        if (auto s = Tcp::recv(fd)) {
            trailing_string += *s;
        } else {
            return std::nullopt;
        }
    }
    std::string r = trailing_string.substr(0, len);
    trailing_string = trailing_string.substr(len);
    return r;
}

size_t Vrecv::get_full_length(const std::string &s) {
    return s.size();
}
