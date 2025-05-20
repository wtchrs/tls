#include "tcp/address_util.h"
#include <spdlog/spdlog.h>

bool resolve_addr(const std::string &host, const std::string &port, sockaddr_storage &out) {
    addrinfo hints{}, *result;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    if (int status = getaddrinfo(host.c_str(), port.c_str(), &hints, &result); status != 0) {
        spdlog::error("Failed to get address information: {}", gai_strerror(status));
        return false;
    }

    if (result->ai_addrlen > sizeof(out)) {
        spdlog::error("Resolved address too large for sockaddr_storage");
        freeaddrinfo(result);
        return false;
    }

    std::memcpy(&out, result->ai_addr, result->ai_addrlen);
    freeaddrinfo(result);
    return true;
}
