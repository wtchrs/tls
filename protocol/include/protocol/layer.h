#ifndef PROTOCOL_LAYER_H
#define PROTOCOL_LAYER_H


#include <memory>
#include <optional>
#include <string>
#include "core/tls.h"

#define BUF_SIZE 4096

#define SV_SERVER true
#define SV_CLIENT false


class Layer {
public:
    virtual ~Layer() = default;
    virtual void handshake() {}
    virtual void send(const std::string &s) = 0;
    virtual std::optional<std::string> recv() = 0;
};


class TCPLayer : public Layer {
    const int socket_fd_;
    char buffer_[BUF_SIZE];

public:
    TCPLayer(int socket_fd);
    void send(const std::string &s) override;
    std::optional<std::string> recv() override;
};


class VRecv : public Layer {
protected:
    std::unique_ptr<Layer> lower_;
    std::string received_;

public:
    explicit VRecv(std::unique_ptr<Layer> lower);
    void send(const std::string &s) override;
    std::optional<std::string> recv() override;

protected:
    virtual size_t get_full_length(const std::string &s);
};


// Simplified implementation for demonstration/testing purposes only.
// TODO: Replace with a spec-compliant implementation.
class HTTPLayer : public VRecv {
public:
    explicit HTTPLayer(std::unique_ptr<Layer> lower);

protected:
    size_t get_full_length(const std::string &s) override;
};


template<bool SV>
class BaseTLSLayer : public VRecv {
protected:
    TLS<SV> tls{};

public:
    BaseTLSLayer(std::unique_ptr<Layer> lower);
    void send(const std::string &s) override;
    std::optional<std::string> recv() override;

protected:
    size_t get_full_length(const std::string &s) override;
    void send_without_enc(const std::string &s);
    std::optional<std::string> recv_without_enc();
};

template<bool SV>
class TLSLayer;

template<>
class TLSLayer<SV_SERVER> : public BaseTLSLayer<SV_SERVER> {
public:
    TLSLayer(std::unique_ptr<Layer> lower);
    void handshake() override;
};

template<>
class TLSLayer<SV_CLIENT> : public BaseTLSLayer<SV_CLIENT> {
public:
    TLSLayer(std::unique_ptr<Layer> lower);
    void handshake() override;
};


#endif
