#include "protocol/tls12_layer.h"
#include "protocol/layer.h"

// class BaseTLS12Layer<bool>

template<bool SV>
BaseTLS12Layer<SV>::BaseTLS12Layer(std::unique_ptr<Layer> lower)
    : FramedReceive{std::move(lower)} {}

template<bool SV>
void BaseTLS12Layer<SV>::send(const std::string &s) {
    FramedReceive::send(tls.encode(std::string{s}));
}

template<bool SV>
std::optional<std::string> BaseTLS12Layer<SV>::recv() {
    if (auto r = FramedReceive::recv()) {
        return tls.decode(std::string{*r});
    }
    return std::nullopt;
}

template<bool SV>
void BaseTLS12Layer<SV>::send_without_enc(const std::string &s) {
    FramedReceive::send(s);
}

template<bool SV>
std::optional<std::string> BaseTLS12Layer<SV>::recv_without_enc() {
    return FramedReceive::recv();
}

template<bool SV>
size_t BaseTLS12Layer<SV>::get_frame_length(const std::string &s) {
    return s.size() < 5 ? 0 : static_cast<uint8_t>(s[3]) * 0x100 + static_cast<uint8_t>(s[4]) + 5;
}


// TLS 1.2 Layer Server-side Implementation

bool tls12_server_handshake_sub(FramedReceive &framed_receive, TLS12<SV_SERVER> &tls, const std::string &waiting_msg) {
    std::string s = waiting_msg;
    std::optional<std::string> a;

    s += tls.server_certificate();
    s += tls.server_key_exchange();
    s += tls.server_hello_done();
    framed_receive.send(s);

    s = tls.alert(tls::FATAL, tls::CLOSE_NOTIFY);
    if (!(a = framed_receive.recv()) || (s = tls.client_key_exchange(std ::move(*a))) != "") {
        framed_receive.send(s);
        return false;
    }

    s = tls.alert(tls::FATAL, tls::CLOSE_NOTIFY);
    if (!(a = framed_receive.recv()) || (s = tls.change_cipher_spec(std ::move(*a))) != "") {
        framed_receive.send(s);
        return false;
    }

    s = tls.alert(tls::FATAL, tls::CLOSE_NOTIFY);
    if (!(a = framed_receive.recv()) || (s = tls.finished(std ::move(*a))) != "") {
        framed_receive.send(s);
        return false;
    }

    s = tls.change_cipher_spec();
    s += tls.finished();
    framed_receive.send(s);

    return true;
}

TLS12LayerServer::TLS12LayerServer(std::unique_ptr<Layer> lower)
    : BaseTLS12Layer{std::move(lower)} {}

bool TLS12LayerServer::handshake() {
    // server-side
    std::string s;
    std::optional<std::string> a;

    s = tls.alert(tls::FATAL, tls::CLOSE_NOTIFY);
    if (!(a = FramedReceive::recv()) || (s = tls.client_hello(std ::move(*a))) != "") {
        FramedReceive::send(s);
        return false;
    }

    s = tls.server_hello();
    return tls12_server_handshake_sub(*this, tls, s);
}


// TLS 1.2 Layer Client-side Implementation

bool tls12_client_handshake_sub(FramedReceive &framed_receive, TLS12<SV_CLIENT> &tls, const std::string &waiting_msg) {
    std::string s = waiting_msg;
    std::optional<std::string> a;

    s = tls.alert(tls::FATAL, tls::CLOSE_NOTIFY);
    if (!(a = framed_receive.recv()) || (s = tls.server_certificate(std ::move(*a))) != "") {
        framed_receive.send(s);
        return false;
    }

    s = tls.alert(tls::FATAL, tls::CLOSE_NOTIFY);
    if (!(a = framed_receive.recv()) || (s = tls.server_key_exchange(std ::move(*a))) != "") {
        framed_receive.send(s);
        return false;
    }

    s = tls.alert(tls::FATAL, tls::CLOSE_NOTIFY);
    if (!(a = framed_receive.recv()) || (s = tls.server_hello_done(std ::move(*a))) != "") {
        framed_receive.send(s);
        return false;
    }

    s = tls.client_key_exchange();
    s += tls.change_cipher_spec();
    s += tls.finished();
    framed_receive.send(s);

    s = tls.alert(tls::FATAL, tls::CLOSE_NOTIFY);
    if (!(a = framed_receive.recv()) || (s = tls.change_cipher_spec(std ::move(*a))) != "") {
        framed_receive.send(s);
        return false;
    }

    s = tls.alert(tls::FATAL, tls::CLOSE_NOTIFY);
    if (!(a = framed_receive.recv()) || (s = tls.finished(std ::move(*a))) != "") {
        framed_receive.send(s);
        return false;
    }

    return true;
}

TLS12LayerClient::TLS12LayerClient(std::unique_ptr<Layer> lower)
    : BaseTLS12Layer{std::move(lower)} {}

bool TLS12LayerClient::handshake() {
    // client-side
    std::string s;
    std::optional<std::string> a;

    FramedReceive::send(tls.client_hello());
    s = tls.alert(tls::FATAL, tls::CLOSE_NOTIFY);
    if (!(a = FramedReceive ::recv()) || (s = tls.server_hello(std ::move(*a))) != "") {
        FramedReceive::send(s);
        return false;
    }

    return tls12_client_handshake_sub(*this, tls, "");
}
