#ifndef TCP_TLS_H
#define TCP_TLS_H


#include <cstdint>
#include <optional>
#include <string>
#include "core/tls.h"
#include "tcp/http.h"

class TlsClient : public Client {
private:
    TLS<TLS_CLIENT> t;

public:
    TlsClient(std::string ip, uint16_t port);
    void encodeAndSend(std::string s);
    std::optional<std::string> recvAndDecode();

private:
    size_t get_full_length(const std::string &s) override;
};


#endif
