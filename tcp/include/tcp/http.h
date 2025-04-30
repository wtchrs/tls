#ifndef HTTP_H
#define HTTP_H


#include <cstdint>
#include <functional>
#include "tcp/tcp.h"

/** Handles length of HTTP packet */
class Http : public Vrecv {
public:
    Http(uint16_t port);

protected:
    size_t get_full_length(const std::string &s) override;
};

class Client : public Http {
public:
    Client(std::string ip = "127.0.0.1", uint16_t port = 2001);

private:
    std::string get_addr(std::string host);
};

class Server : public Http {
protected:
    std::string end_string;
    uint32_t timeout;

public:
    Server(uint16_t port = 2001, uint32_t timeout = 600, uint32_t queue_limit = 10, std::string end_string = "end");
    void start(std::function<std::string(std::string)> f);
};

/** Handles length of TLS packet */
class TlsLayer : public Vrecv {
public:
    TlsLayer(uint16_t port);

protected:
    size_t get_full_length(const std::string &s) override;
};


#endif
