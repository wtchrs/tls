#include <iostream>
#include "tcp/tls.h"

int main(void) {
    TlsClient t{"localhost", 4433};
    t.encodeAndSend("GET /");
    std::cout << *t.recvAndDecode() << std::endl;
}
