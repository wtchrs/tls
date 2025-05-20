#include <memory>
#include <spdlog/spdlog.h>
#include "tcp/connector.h"
#include "tcp/layer.h"

std::unique_ptr<Layer> https_layer_factory(int fd) {
    auto tcp = std::make_unique<TCPLayer>(fd);
    auto tls = std::make_unique<TLSLayer<SV_CLIENT>>(std::move(tcp));
    tls->handshake();
    auto http = std::make_unique<HTTPLayer>(std::move(tls));
    return http;
}

int main() {
    Connector connector{https_layer_factory};
    auto conn = connector.connect_to("localhost", "2443");
    conn->send("GET /");
    spdlog::info("Received: {}", *conn->recv());
}
