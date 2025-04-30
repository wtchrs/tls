#include <string>
#include "tcp/http.h"

int main() {
    Server sv{2002};
    sv.start([](std::string s) { return "Learn cryptography by implementing TLS"; });
}
