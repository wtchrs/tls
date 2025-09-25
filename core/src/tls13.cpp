#include "core/tls13.h"
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <gmpxx.h>
#include <nettle/curve25519.h>
#include <string>
#include <string_view>
#include <utility>
#include <vector>
#include "core/base64.h"
#include "core/cert.h"
#include "core/diffie_hellman.h"
#include "core/ecdsa.h"
#include "core/mpz.h"
#include "core/sha/sha2.h"
#include "core/tls12.h"
#include "core/tls_types.h"
#include "core/utils.h"


static std::string init_certificate() {
    constexpr int REQUEST_CONTEXT = 0;
    std::ifstream ecdsa_cert{"./cert/example/ec_cert.pem"};
    std::vector<uint8_t> r;
    for (std::string s; !(s = get_certificate_core(ecdsa_cert)).empty();) {
        auto v = base64_decode(s);
        // insert certificate length
        r.resize(v.size() + 3);
        mpz2bnd(v.size(), r.end() - 3, r.end());
        // insert DER certificate
        r.insert(r.end(), v.begin(), v.end());
    }
    r.resize(r.size() + 2, 0);

    std::vector<uint8_t> v = {0x16, 3, 3, 0, 0, CERTIFICATE, 0, 0, 0, REQUEST_CONTEXT, 0, 0, 0};
    mpz2bnd(r.size(), v.end() - 3, v.end());
    mpz2bnd(r.size() + 4, v.begin() + 6, v.begin() + 9);
    mpz2bnd(r.size() + 8, v.begin() + 3, v.begin() + 5);
    r.insert(r.begin(), v.begin(), v.end());

    return {r.begin(), r.end()};
}

static mpz_class init_prv_key() {
    std::ifstream prv_key_pem{"./cert/example/ec_key.pem"};
    get_certificate_core(prv_key_pem);
    return pem2json(prv_key_pem)
        .transform([](auto json_value) { return json_value[0][1].asString(); })
        .transform([](auto v) { return str2mpz(v); })
        .value();
}

template<bool SV>
std::string TLS13<SV>::ecdsa_certificate_ = init_certificate();

static mpz_class private_key = init_prv_key();


template<>
std::string TLS13<SV_SERVER>::client_hello(std::string &&s) {
    if (get_content_type(s) != std::pair<int, int>{HANDSHAKE, CLIENT_HELLO}) {
        return alert(tls::FATAL, tls::UNEXPECTED_MESSAGE);
    }
    size_t pos = 43; // starts from session id length position
    size_t session_id_len = s[pos];
    std::copy_n(&s[pos + 1], session_id_len, echo_id_);
    pos += session_id_len + 1;
    size_t cipher_suite_len = s[pos] * 0x100 + s[pos + 1];
    pos += cipher_suite_len + 2;
    size_t compression_len = s[pos];
    size_t ext_start = pos + compression_len + 1;
    auto ext_ptr = reinterpret_cast<uint8_t *>(&s[ext_start]);
    if (ext_start < s.size() && client_ext(ext_ptr)) {
        accumulate(s);
        return "";
    }
    return TLS12<SV_SERVER>::client_hello(std::move(s));
}

template<>
std::string TLS13<SV_CLIENT>::client_hello(std::string &&) {
    std::string hello = TLS12<SV_CLIENT>::client_hello();
    this->accumulated_handshakes_ = "";
    std::string ext = client_ext();
    int hello_size = hello[3] * 0x100 + hello[4] + ext.size();
    mpz2bnd(hello_size, &hello[3], &hello[5]);
    mpz2bnd(hello_size - 4, &hello[6], &hello[9]);
    return this->accumulate(hello + ext);
}

template<>
std::string TLS13<SV_SERVER>::server_hello(std::string &&) {
    std::string tmp = this->accumulated_handshakes_;
    std::string hello = TLS12<SV_SERVER>::server_hello();
    if (!shared_secret_) {
        return hello;
    }
    // Echo session id.
    std::copy_n(echo_id_, 32, &hello[44]);
    // cipher suite TLS_AES_128_GCM_SHA256
    hello[76] = 19; // 0x13
    hello[77] = 1;
    this->accumulated_handshakes_ = tmp;
    std::string ext = server_ext();
    int hello_size = hello[3] * 0x100 + hello[4] + ext.size();
    mpz2bnd(hello_size, &hello[3], &hello[5]);
    mpz2bnd(hello_size - 4, &hello[6], &hello[9]);
    return this->accumulate(hello + ext);
}

template<>
std::string TLS13<SV_CLIENT>::server_hello(std::string &&s) {
    if (get_content_type(s) != std::pair<int, int>{HANDSHAKE, SERVER_HELLO})
        return alert(tls::FATAL, tls::UNEXPECTED_MESSAGE);
    auto ext_ptr = reinterpret_cast<uint8_t *>(&s[79]);
    if (s.size() > 80 && server_ext(ext_ptr)) {
        accumulate(s);
        return "";
    }
    return TLS12<SV_CLIENT>::server_hello(std::move(s));
}


template<bool SV>
std::string TLS13<SV>::server_certificate13() {
    return this->accumulate(ecdsa_certificate_).substr(5);
}


#pragma pack(push, 1)

struct CertVerifyHeader {
    uint8_t type = CERTIFICATE_VERIFY; // 0x0f
    uint8_t length[3] = {0, 0, 74};
    uint8_t signature_alg[2] = {4, 3}; // 0x0403 = ecdsa_secp256r1_sha256, 0x0804 = rsa_pss_rsae_sha256
    uint8_t sig_len[2] = {0, 70};
    uint8_t der_len[2] = {0x30, 68}; // DER SEQUENCE tag + total signatures length

    // DER signatures will follow
};

#pragma pack(pop)

template<bool SV>
std::string TLS13<SV>::certificate_verify() {
    SHA256 sha;
    auto a = sha.hash(this->accumulated_handshakes_.cbegin(), this->accumulated_handshakes_.cend());
    std::string t{64, '\x20'};
    // TODO std::string t(64, '\x20');
    t += "TLS 1.3, server CertificateVerify";
    t += static_cast<uint8_t>(0);
    t.insert(t.end(), a.cbegin(), a.cend());
    a = sha.hash(t.begin(), t.end());

    CertVerifyHeader h;
    // pairs of (integer tag, length) for R, S
    uint8_t der1[2] = {2, 32}, der2[2] = {2, 32};
    std::vector<uint8_t> R(32), S(32);

    // Sign with ECDSA.
    // See https://www.secg.org/sec2-v2.pdf to get more informations for parameters of secp256r1 curve.
    ECDSA ecdsa{this->G_, 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551_mpz};
    auto [r, s] = ecdsa.sign(bnd2mpz(a.begin(), a.end()), private_key);
    mpz2bnd(r, R.begin(), R.end());
    mpz2bnd(s, S.begin(), S.end());
    // Insert a leading 0x00 byte if R or S starts with a 1-bit
    // in order to prevent it from being interpreted as a negative value.
    if (R[0] >= 0x80) {
        h.length[2]++, h.sig_len[1]++, h.der_len[1]++, der1[1]++;
        R.insert(R.begin(), 0);
    }
    if (S[0] >= 0x80) {
        h.length[2]++, h.sig_len[1]++, h.der_len[1]++, der2[1]++;
        S.insert(S.begin(), 0);
    }

    // clang-format off
    std::string msg = struct2str(h) +
        std::string{der1, der1 + 2} + std::string{R.cbegin(), R.cend()} +
        std::string{der2, der2 + 2} + std::string{S.cbegin(), S.cend()};
    // clang-format on
    this->accumulated_handshakes_ += msg;
    return msg;
}


#pragma pack(push, 1)

struct FinishHeader {
    uint8_t type = FINISHED; // 0x14
    uint8_t length[3] = {0, 0, 32};
};

#pragma pack(pop)

template<bool SV>
std::string TLS13<SV>::finished(std::string &&s) {
    FinishHeader h;
    hkdf_.salt(finished_key_[s == "" ? SV : !SV].data(), SHA256::output_size);
    SHA256 sha; // hash function of the cipher suite
    auto a = sha.hash(this->accumulated_handshakes_.cbegin(), this->accumulated_handshakes_.cend());
    a = hkdf_.get_hash_obj()->hash(a.cbegin(), a.cend()); // hash function of HKDF
    std::string msg = struct2str(h) + std::string{a.cbegin(), a.cend()};
    this->accumulated_handshakes_ += msg;

    if (s == "") {
        // Return generated finished message.
        return msg;
    }

    if (s == msg) {
        return "";
    }
    return this->alert(tls::FATAL, tls::DECRYPT_ERROR);
}


#pragma pack(push, 1)

struct TLS_header {
    /** 0x15: Alert, 0x16: Handshake, 0x17: Application data */
    uint8_t content_type = HANDSHAKE;
    /** 0x0303 for TLS 1.2 */
    uint8_t version[2] = {0x03, 0x03};
    uint8_t length[2] = {0, 4};

    void set_length(const size_t k) {
        length[0] = k / 0x100;
        length[1] = k % 0x100;
    }

    [[nodiscard]]
    size_t get_length() const {
        return length[0] * 0x100 + length[1];
    }
};

struct EncryptedMessage {
    TLS_header tls;
    uint8_t encrypted_msg[];
};

#pragma pack(pop)

template<bool SV>
std::optional<std::string> TLS13<SV>::decode13(std::string &&s) {
    EncryptedMessage *p = reinterpret_cast<EncryptedMessage *>(s.data());
    uint8_t seq[8] = {};
    if (int type = this->get_content_type(s).first; type != APPLICATION_DATA) {
        this->alert(this->alert(tls::FATAL, tls::UNEXPECTED_MESSAGE));
        return {};
    }
    mpz2bnd(this->dec_seq_num_++, seq, seq + sizeof(seq));
    int msg_len = p->tls.get_length() - 16; // Exclude the length of auth tag.

    this->aes_[!SV].set_aad(reinterpret_cast<uint8_t *>(p), sizeof(p->tls));
    this->aes_[!SV].xor_with_iv(seq);
    auto auth_tag = this->aes_[!SV].decrypt(p->encrypted_msg, msg_len);
    this->aes_[!SV].xor_with_iv(seq);

    if (std::equal(auth_tag.cbegin(), auth_tag.cend(), &p->encrypted_msg[msg_len])) {
        // auth tag checking successful
        std::string r{p->encrypted_msg, p->encrypted_msg + msg_len};
        while (r.back() == 0) {
            r.pop_back();
        }
        if (r.back() == ALERT) {
            this->alert(this->alert(static_cast<tls::AlertLevel>(r[0]), static_cast<tls::AlertDescription>(r[1])));
            return {};
        }
        r.pop_back();
        return r;
    }

    // failed (bad record mac)
    this->alert(this->alert(tls::FATAL, tls::BAD_RECORD_MAC));
    return {};
}

template<bool SV>
std::string TLS13<SV>::encode13(std::string &&s, int type) {
    constexpr size_t CHUNK_SIZE = (1 << 14) - 64; // maximum chunk size
    constexpr size_t AUTH_TAG_SIZE = 16;

    uint8_t seq[8] = {};
    TLS_header tls;
    // Use 0x17(APPLICATION_DATA) as the content type for all encoded messages in TLS 1.3.
    // The actual content type is inserted at the end of the messages to be encoded.
    tls.content_type = APPLICATION_DATA; // 0x17, 23

    mpz2bnd(this->enc_seq_num_++, seq, seq + sizeof(seq));
    std::string frag = s.substr(0, CHUNK_SIZE) + std::string{static_cast<char>(type)};
    tls.set_length(frag.size() + AUTH_TAG_SIZE);

    this->aes_[SV].set_aad(reinterpret_cast<uint8_t *>(&tls), sizeof(tls));
    this->aes_[SV].xor_with_iv(seq);
    uint8_t *p = reinterpret_cast<uint8_t *>(frag.data());
    auto tag = this->aes_[SV].encrypt(p, frag.size());
    this->aes_[SV].xor_with_iv(seq); // Restore iv value.
    frag += std::string{tag.cbegin(), tag.cend()};

    auto enc_msg = struct2str(tls) + frag;
    if (s.size() > CHUNK_SIZE) {
        enc_msg += encode(s.substr(CHUNK_SIZE));
    }
    return enc_msg;
}


template<bool SV>
std::optional<std::string> TLS13<SV>::decode(std::string &&s) {
    if (shared_secret_)
        return decode13(std::move(s));
    return TLS12<SV>::decode(std::move(s));
}

template<bool SV>
std::string TLS13<SV>::encode(std::string &&s, tls::ContentType type) {
    if (shared_secret_)
        return encode13(std::move(s), type);
    return TLS12<SV>::encode(std::move(s), type);
}


#pragma pack(push, 1)

struct ClientExt {
    uint8_t extension_length[2] = {sizeof(ClientExt) / 0x100, sizeof(ClientExt) % 0x100};

    uint8_t supported_group_type[2] = {0, 10};
    uint8_t supported_group_length[2] = {0, 6};
    uint8_t supported_group_list_length[2] = {0, 4};
    // NamedGroup[]
    uint8_t ng_secp256r1[2] = {0, 23}; // [0]
    uint8_t ng_x25519[2] = {0, 29}; // [1]

    uint8_t ec_point_format_type[2] = {0, 11};
    uint8_t ec_point_format_length[2] = {0, 2};
    uint8_t ec_length = 1;
    uint8_t ec_uncompressed = 0; // Notify server that uncompressed format can be parsed

    uint8_t key_share_type[2] = {0, 51};
    uint8_t key_share_length[2] = {0, 107};
    uint8_t client_key_share_len[2] = {0, 105};
    // secp256r1
    uint8_t secp256r1_key[2] = {0, 23};
    uint8_t secp256r1_key_length[2] = {0, 65};
    uint8_t secp256r1_type = 4; // Uncompressed format
    uint8_t secp256r1_x[32], secp256r1_y[32]; // Fill later
    // x25519
    uint8_t x25519_key[2] = {0, 29};
    uint8_t x25519_key_length[2] = {0, 32};
    uint8_t x25519_x[32]; // Fill later

    uint8_t supported_version_type[2] = {0, 0x2b};
    uint8_t supported_version_length[2] = {0, 5};
    uint8_t supported_version_list_length = 4;
    uint8_t supported_versions[4] = {3, 4, 3, 3}; // TLS 1.3, TLS 1.2

    uint8_t psk_mode_type[2] = {0, 0x2d};
    uint8_t psk_mode_length[2] = {0, 2};
    uint8_t psk_mode_internal_length = 1;
    uint8_t psk_with_ecdhe = 1;

    uint8_t signature_algorithm_type[2] = {0, 13};
    uint8_t signature_algorithm_length[2] = {0, 8};
    uint8_t signature_algorithm_internal_length[2] = {0, 6};
    uint8_t signature_algorithms[6] = {8, 4, 4, 1, 4, 3};
};

#pragma pack(pop)


template<bool SV>
std::string TLS13<SV>::client_ext() {
    ClientExt ext;
    mpz2bnd(this->P_.x_, ext.secp256r1_x, ext.secp256r1_x + sizeof(ext.secp256r1_x));
    mpz2bnd(this->P_.y_, ext.secp256r1_y, ext.secp256r1_y + sizeof(ext.secp256r1_y));
    mpz2bnd(this->prv_key_, prv_, prv_ + sizeof(prv_));
    curve25519_mul_g(ext.x25519_x, prv_); // Calculate and store `prv_ * G` into `ext.x25519_x`, using curve25519.
    return struct2str(ext);
}


template<bool SV>
bool TLS13<SV>::supported_group(unsigned char *p, size_t len) {
    for (size_t i = 2; i < len; i += 2) {
        // secp256r1
        if (p[i] == 0 && p[i + 1] == 23)
            return true;
    }
    return false;
}

template<bool SV>
bool TLS13<SV>::ec_point_format(unsigned char *p, size_t len) {
    for (size_t i = 1; i < len; ++i) {
        // Check if the elliptic curve point format is non-compressed.
        if (p[i] == 0)
            return true;
    }
    return false;
}

template<bool SV>
bool TLS13<SV>::sub_key_share(unsigned char *p) {
    if (p[0] == 0 && p[1] == 23 && p[4] == 4) {
        // secp256r1 with uncompressed option
        ECPoint Q{bnd2mpz(p + 5, p + 37), bnd2mpz(p + 37, p + 69), this->secp256r1_};
        shared_secret_ = (this->prv_key_ * Q).x_;
        return true;
    }
    if (p[0] == 0 && p[1] == 29) {
        // x25519
        uint8_t q[32] = {};
        curve25519_mul(q, prv_, p + 4);
        shared_secret_ = bnd2mpz(q, q + sizeof(q) / sizeof(q[0]));
        this->P_.x_ = -1;
        return true;
    }
    return false;
}

template<bool SV>
bool TLS13<SV>::key_share(unsigned char *p, size_t len) {
    for (size_t i = 0; i < len; i += p[i + 2] * 0x100 + p[i + 3]) {
        if (sub_key_share(&p[i]))
            return true;
    }
    return false;
}

template<bool SV>
bool TLS13<SV>::supported_version(unsigned char *p, size_t len) {
    for (size_t i = 1; i < len; i += 2) {
        // Check if TLS 1.3 is supported.
        if (p[i] == 3 && p[i + 1] == 4)
            return true;
    }
    return false;
}

template<bool SV>
bool TLS13<SV>::client_ext(unsigned char *p) {
    size_t total_len = p[0] * 0x100 + p[1] + 2;
    bool check_ext[5] = {};
    for (size_t i = 2; i < total_len;) {
        int type = p[i] * 0x100 + p[i + 1];
        size_t len = p[i + 2] * 0x100 + p[i + 3];
        i += 4;
        switch (type) {
        case 10: check_ext[0] = supported_group(&p[i], len); break;
        case 11: check_ext[1] = ec_point_format(&p[i], len); break;
        case 43: check_ext[2] = supported_version(&p[i], len); break;
        case 45: check_ext[3] = true; break; // What!?
        case 51: check_ext[4] = key_share(&p[i], len); break;
        }
        i += len;
    }
    for (auto &check : check_ext) {
        if (!check) {
            return false;
        }
    }
    return true;
}


#pragma pack(push, 1)

struct ServerExt {
    uint8_t extension_length[2] = {}; // Fill later

    uint8_t supported_version_type[2] = {0, 43};
    uint8_t supported_version_length[2] = {0, 2};
    uint8_t supported_versions[2] = {3, 4}; // TLS 1.3

    // secp256r1/x25519 key share extension will follow.
};

struct Secp256r1KeyShare {
    uint8_t key_share_type[2] = {0, 51};
    uint8_t key_share_length[2] = {0, 69};
    uint8_t key_type[2] = {0, 23};
    uint8_t key_length[2] = {0, 65};
    uint8_t point_type = 4; // uncompressed
    uint8_t x[32], y[32];
};

struct X25519KeyShare {
    uint8_t key_share_type[2] = {0, 51};
    uint8_t key_share_length[2] = {0, 36};
    uint8_t key_type[2] = {0, 29};
    uint8_t key_length[2] = {0, 32};
    uint8_t x[32];
};

#pragma pack(pop)

template<bool SV>
std::string TLS13<SV>::server_ext() {
    ServerExt ext;
    if (this->P_.x_ != -1) {
        // secp256r1
        Secp256r1KeyShare key_share;
        mpz2bnd(this->P_.x_, key_share.x, key_share.x + sizeof(key_share.x));
        mpz2bnd(this->P_.y_, key_share.y, key_share.y + sizeof(key_share.y));
        ext.extension_length[1] = 79;
        return struct2str(ext) + struct2str(key_share);
    } else {
        // x25519
        X25519KeyShare key_share;
        curve25519_mul_g(key_share.x, prv_);
        ext.extension_length[1] = 46;
        return struct2str(ext) + struct2str(key_share);
    }
}

template<bool SV>
bool TLS13<SV>::server_ext(unsigned char *p) {
    size_t total_len = p[0] * 0x100 + p[1];
    for (size_t i = 2; i < total_len + 2;) {
        int type = p[i] * 0x100 + p[i + 1];
        size_t len = p[i + 2] * 0x100 + p[i + 3];
        if (type == 51)
            return key_share(&p[i + 4], len);
        i += len + 4;
    }
    return false;
}


#pragma pack(push, 1)

struct EncryptedExt {
    uint8_t enc_ext_type = 8;
    uint8_t total_len[3] = {0, 0, 10};
    uint8_t ext_len[2] = {0, 8};
    uint8_t supported_group[2] = {0, 10};
    uint8_t len[2] = {0, 4};
    uint8_t group[4] = {0, 0x1d, 0, 0x17};
};

#pragma pack(pop)

template<bool SV>
std::string TLS13<SV>::encrypted_extension() {
    EncryptedExt ext;
    std::string r = struct2str(ext);
    this->accumulated_handshakes_ += r;
    return r;
}


template<bool SV>
void TLS13<SV>::protect_handshake() {
    // Called after SERVER_HELLO
    hkdf_.zero_salt();
    uint8_t psk[SHA256::output_size] = {};
    uint8_t pre[32];
    auto early_secret = hkdf_.extract(psk, SHA256::output_size);

    hkdf_.salt(&early_secret[0], early_secret.size());
    auto a = hkdf_.derive_secret(INTERMEDIATE_DERIVATION_LABEL, "");
    hkdf_.salt(&a[0], a.size());
    mpz2bnd(shared_secret_, pre, pre + sizeof(pre) / sizeof(uint8_t));
    auto handshake_secret = hkdf_.extract(pre, 32);

    finished_key_ = set_aes(handshake_secret, CLIENT_HANDSHAKE_TRAFFIC_LABEL, SERVER_HANDSHAKE_TRAFFIC_LABEL);
    hkdf_.salt(&handshake_secret[0], handshake_secret.size());
    a = hkdf_.derive_secret(INTERMEDIATE_DERIVATION_LABEL, "");
    hkdf_.salt(&a[0], a.size());
    this->master_secret_ = hkdf_.extract(psk, SHA256::output_size);
}

template<bool SV>
void TLS13<SV>::protect_data() {
    // Called after SERVER_FINISHED
    set_aes(this->master_secret_, CLIENT_APPLICATION_TRAFFIC_LABEL, SERVER_APPLICATION_TRAFFIC_LABEL);
}

template<bool SV>
std::array<std::vector<uint8_t>, 2>
TLS13<SV>::set_aes(std::vector<uint8_t> salt, std::string_view client_label, std::string_view server_label) {
    // Reset sequence numbers each time key material is set.
    this->enc_seq_num_ = 0;
    this->dec_seq_num_ = 0;

    hkdf_.salt(&salt[0], salt.size());
    std::array<std::vector<unsigned char>, 2> secret, finished_key;
    secret[0] = hkdf_.derive_secret(client_label, this->accumulated_handshakes_);
    secret[1] = hkdf_.derive_secret(server_label, this->accumulated_handshakes_);

    for (int i = 0; i < 2; ++i) {
        // 0 is client, 1 is server
        hkdf_.salt(&secret[i][0], secret[i].size());
        auto key = hkdf_.expand_label("key", "", 16);
        auto iv = hkdf_.expand_label("iv", "", 12);
        this->aes_[i].set_key(&key[0]);
        this->aes_[i].set_iv(&iv[0], 0, iv.size());
        finished_key[i] = hkdf_.expand_label("finished", "", SHA256::output_size);
    }

    return finished_key;
}

// Explicit template instantiation
template class TLS13<SV_SERVER>;
template class TLS13<SV_CLIENT>;
