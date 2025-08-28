#include "protocol/tls13_layer.h"
#include "protocol/layer.h"
#include "protocol/tls12_layer.h"

template<bool SV>
BaseTLS13Layer<SV>::BaseTLS13Layer(std::unique_ptr<Layer> lower)
    : FramedReceive{std::move(lower)} {}

template<bool SV>
void BaseTLS13Layer<SV>::send(const std::string &s) {
    FramedReceive::send(tls.encode(std::string{s}));
}

template<bool SV>
std::optional<std::string> BaseTLS13Layer<SV>::recv() {
    if (auto r = FramedReceive::recv()) {
        return tls.decode(std::string{*r});
    }
    return std::nullopt;
}

template<bool SV>
void BaseTLS13Layer<SV>::send_without_enc(const std::string &s) {
    FramedReceive::send(s);
}

template<bool SV>
std::optional<std::string> BaseTLS13Layer<SV>::recv_without_enc() {
    return FramedReceive::recv();
}

template<bool SV>
size_t BaseTLS13Layer<SV>::get_frame_length(const std::string &s) {
    return s.size() < 5 ? 0 : static_cast<uint8_t>(s[3]) * 0x100 + static_cast<uint8_t>(s[4]) + 5;
}


bool TLS13LayerServer::handshake() {
    // server-side
    std::string s;
    std::optional<std::string> a;

    s = tls.alert(2, 0);
    if (!(a = FramedReceive ::recv()) || (s = tls.client_hello(std ::move(*a))) != "") {
        FramedReceive::send(s);
        return false;
    }

    s = tls.server_hello();

    if (!tls.is_tls13()) {
        return tls12_server_handshake_sub(*this, tls, s);
    }

    // TLS 1.3
    tls.protect_handshake();
    s += tls.change_cipher_spec(); // not necessary. dummy record for compatibility.
    // Switched to Handshake Traffic Keys.
    std::string t = tls.encrypted_extension();
    t += tls.server_certificate13();
    t += tls.certificate_verify();
    t += tls.finished();
    s += tls.encode(std::move(t), HANDSHAKE);
    FramedReceive::send(s);

    s = tls.alert(2, 0);
    if (!(a = FramedReceive ::recv()) || (s = tls.change_cipher_spec(std ::move(*a))) != "") {
        FramedReceive::send(s);
        return false;
    }

    s = tls.alert(2, 0);
    if (!(a = FramedReceive::recv()) || !(a = tls.decode(std::move(*a)))) {
        FramedReceive::send(s);
        return false;
    }

    tls.protect_data();

    if ((s = tls.finished(std::move(*a))) != "") {
        FramedReceive::send(s);
        return false;
    }

    // Handshake finished. Switched to Application Traffic Keys.

    return true;
}

bool TLS13LayerClient::handshake() {
    // client-side
    std::string s;
    std::optional<std::string> a;

    FramedReceive::send(tls.client_hello());

    if (!(a = FramedReceive::recv()) || (s = tls.server_hello(std::move(*a))) != "") {
        FramedReceive::send(s);
        return false;
    }

    if (!tls.is_tls13()) {
        return tls12_client_handshake_sub(*this, tls, "");
    }

    // TLS 1.3
    tls.protect_handshake();

    s = tls.alert(2, 0);
    if (!(a = FramedReceive ::recv()) || (s = tls.change_cipher_spec(std ::move(*a))) != "") {
        FramedReceive::send(s);
        return false;
    }

    s = tls.alert(2, 0);
    // TODO: Why does not check received message?
    if (!(a = FramedReceive::recv()) || !(a = tls.decode(std::move(*a)))) {
        FramedReceive::send(s);
        return false;
    }

    // Switched to Handshake Traffic Keys.

    tls.accumulate_raw(*a);
    std::string temp = tls.get_accumulate();
    s = tls.change_cipher_spec(); // not necessary. dummy record for compatibility.
    s += tls.encode(tls.finished());
    FramedReceive::send(s);
    tls.set_accumulate(temp);
    tls.protect_data();
    // Handshake finished. Switched to Application Traffic Keys.

    return true;
}
