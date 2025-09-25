#ifndef PROTOCOL_LAYER_H
#define PROTOCOL_LAYER_H


#include <memory>
#include <optional>
#include <string>

#define BUF_SIZE 4096


class Layer {
public:
    virtual ~Layer() = default;

    /**
     * @brief Performs the layer's handshake
     * @return True if the handshake was successful, false otherwise
     */
    virtual bool handshake() {
        return true;
    }

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


class FramedReceive : public Layer {
protected:
    std::unique_ptr<Layer> lower_;
    std::string received_;

public:
    explicit FramedReceive(std::unique_ptr<Layer> lower);
    void send(const std::string &s) override;
    std::optional<std::string> recv() override;

protected:
    virtual size_t get_frame_length(const std::string &s);
};


// Simplified implementation for demonstration/testing purposes only.
// TODO: Replace with a spec-compliant implementation.
class HTTPLayer : public FramedReceive {
public:
    explicit HTTPLayer(std::unique_ptr<Layer> lower);

protected:
    size_t get_frame_length(const std::string &s) override;
};


#endif
