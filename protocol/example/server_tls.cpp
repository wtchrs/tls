#include <memory>
#include <spdlog/spdlog.h>
#include "protocol/acceptor.h"
#include "protocol/layer.h"

std::unique_ptr<Layer> https_layer_factory(int fd) {
    auto tcp = std::make_unique<TCPLayer>(fd);
    auto tls = std::make_unique<TLS12Layer<SV_SERVER>>(std::move(tcp));
    tls->handshake();
    auto http = std::make_unique<HTTPLayer>(std::move(tls));
    return http;
}

int main() {
    ServerAcceptor acceptor{https_layer_factory};
    acceptor.start("0.0.0.0", "2443", 1000, 10, [](auto &s) {
        spdlog::info("Received: {}", s);
        return "Learn cryptography by implementing TLS";
    });
}
