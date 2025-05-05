#include <iostream>
#include "tcp/http.h"

int main(void) {
    Client cl{"127.0.0.1", 2002};
    cl.send("GET /");
    std::cout << *cl.recv() << std::endl;
}
