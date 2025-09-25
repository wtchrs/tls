#ifndef PROTOCOL_TLS12_LAYER_H
#define PROTOCOL_TLS12_LAYER_H


#include "core/tls12.h"
#include "protocol/layer.h"


template<bool SV>
class BaseTLS12Layer : public FramedReceive {
protected:
    TLS12<SV> tls;

public:
    BaseTLS12Layer(std::unique_ptr<Layer> lower);

    /**
     * @brief Performs the TLS 1.2 handshake
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


bool tls12_server_handshake_sub(FramedReceive &framed_receive, TLS12<SV_SERVER> &tls, const std::string &waiting_msg);
bool tls12_client_handshake_sub(FramedReceive &framed_receive, TLS12<SV_CLIENT> &tls, const std::string &waiting_msg);


class TLS12LayerServer : public BaseTLS12Layer<SV_SERVER> {
public:
    TLS12LayerServer(std::unique_ptr<Layer> lower);
    bool handshake() override;
};

class TLS12LayerClient : public BaseTLS12Layer<SV_CLIENT> {
public:
    TLS12LayerClient(std::unique_ptr<Layer> lower);
    bool handshake() override;
};


#endif
