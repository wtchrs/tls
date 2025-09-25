#ifndef PROTOCOL_TLS13_LAYER_H
#define PROTOCOL_TLS13_LAYER_H


#include "core/tls13.h"
#include "protocol/layer.h"


template<bool SV>
class BaseTLS13Layer : public FramedReceive {
protected:
    TLS13<SV> tls;

public:
    BaseTLS13Layer(std::unique_ptr<Layer> lower);

    /**
     * @brief Performs the TLS 1.3 handshake
     * @return True if the handshake was successful, false otherwise
     */
    bool handshake() override = 0;

    void send(const std::string &s) override;
    std::optional<std::string> recv() override;

protected:
    size_t get_frame_length(const std::string &s) override;

    void send_without_enc(const std::string &s);
    std::optional<std::string> recv_without_enc();
};


class TLS13LayerServer : public BaseTLS13Layer<SV_SERVER> {
public:
    TLS13LayerServer(std::unique_ptr<Layer> lower);
    bool handshake() override;
};


class TLS13LayerClient : public BaseTLS13Layer<SV_CLIENT> {
public:
    TLS13LayerClient(std::unique_ptr<Layer> lower);
    bool handshake() override;
};


#endif
