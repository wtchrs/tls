#ifndef PROTOCOL_ACCEPTOR_H
#define PROTOCOL_ACCEPTOR_H

#include <cstdint>
#include <functional>
#include <string>
#include <sys/socket.h>
#include "protocol/layer.h"

class ServerAcceptor {
    using LayerFactory = std::function<std::unique_ptr<Layer>(int)>;
    using Process = std::function<std::string(std::string &)>;

    const LayerFactory layer_factory_;
    int listening_sock_fd_;
    sockaddr_storage server_addr_;

public:
    explicit ServerAcceptor(LayerFactory layer_factory)
        : layer_factory_{layer_factory} {}

    void start(Process process) {
        start("", "80", 1, 10, process);
    }

    void
    start(const std::string &host, const std::string &port, uint32_t timeout, uint32_t queue_limit, Process process);
};


#endif
