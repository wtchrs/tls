#include "tls/cert.h"

std::string get_certificate_core(std::istream &is) {
    std::string s, r;
    while (s != "-----BEGIN")
        if (!(is >> s))
            return r;
    std::getline(is, s);
    for (is >> s; s != "-----END"; is >> s)
        r += s;
    return r;
}
