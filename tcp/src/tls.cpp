#include "tcp/tls.h"

// class TlsClient

TlsClient::TlsClient(std::string ip, uint16_t port)
    : Client{ip, port} {
    // Perform TLS handshaking
    send(t.client_hello());
    t.server_hello(*recv());
    t.server_certificate(*recv());
    t.server_key_exchange(*recv());
    t.server_hello_done(*recv());
    std::string a = t.client_key_exchange();
    std::string b = t.change_cipher_spec();
    std::string c = t.finished();
    send(a + b + c);
    t.change_cipher_spec(*recv());
    t.finished(*recv());
}

void TlsClient::encodeAndSend(std::string s) {
    send(t.encode(std::move(s)));
}

std::optional<std::string> TlsClient::recvAndDecode() {
    return t.decode(*recv());
}

size_t TlsClient::get_full_length(const std::string &s) {
    return s.size() < 5 ? 0 : static_cast<uint8_t>(s[3]) * 0x100 + static_cast<uint8_t>(s[4]) + 5;
}
