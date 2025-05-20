#include <memory>
#include <spdlog/spdlog.h>
#include "tcp/connector.h"
#include "tcp/layer.h"

std::unique_ptr<Layer> layer_factory(int fd) {
    auto tcp = std::make_unique<TCPLayer>(fd);
    auto http = std::make_unique<HTTPLayer>(std::move(tcp));
    return http;
}

int main(void) {
    Connector connector{layer_factory};
    auto layer = connector.connect_to("localhost", "2002");
    layer->send("GET /");
    spdlog::info("Received: {}", *layer->recv());
}
