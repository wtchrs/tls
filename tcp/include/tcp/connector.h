#ifndef TCP_CONNECTOR_H
#define TCP_CONNECTOR_H


#include <functional>
#include <memory>
#include <string>
#include "tcp/layer.h"

class Connector {
    using LayerFactory = std::function<std::unique_ptr<Layer>(int)>;

    const LayerFactory layer_factory_;

public:
    explicit Connector(LayerFactory layer_factory)
        : layer_factory_{layer_factory} {}

    std::unique_ptr<Layer> connect_to(const std::string &host, const std::string &port);
};


#endif
