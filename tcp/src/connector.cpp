#include "tcp/connector.h"
#include <spdlog/spdlog.h>
#include <sys/socket.h>
#include "tcp/address_util.h"

std::unique_ptr<Layer> Connector::connect_to(const std::string &host, const std::string &port) {
    sockaddr_storage addr{};
    resolve_addr(host, port, addr);
    int sock_fd = socket(addr.ss_family, SOCK_STREAM, IPPROTO_TCP);
    if (sock_fd == -1) {
        spdlog::error("Failed to create socket: {}", std::strerror(errno));
        return {};
    }
    if (connect(sock_fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) == -1) {
        spdlog::error("Failed to connect: {}", std::strerror(errno));
        return {};
    }
    spdlog::info("Connected to {}:{}", host, port);
    return layer_factory_(sock_fd);
}
