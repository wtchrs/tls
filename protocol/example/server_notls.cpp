#include <memory>
#include <spdlog/spdlog.h>
#include <string>
#include "protocol/acceptor.h"
#include "protocol/layer.h"

std::unique_ptr<Layer> layer_factory(int fd) {
    auto tcp = std::make_unique<TCPLayer>(fd);
    auto http = std::make_unique<HTTPLayer>(std::move(tcp));
    return http;
}

int main() {
    ServerAcceptor acceptor{layer_factory};
    acceptor.start("0.0.0.0", "2002", 10000, 10, [](std::string &s) {
        spdlog::info("Received: {}", s);
        return "Learn cryptography by implementing TLS";
    });
}
