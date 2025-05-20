#ifndef TCP_ADDRESS_UTIL_H
#define TCP_ADDRESS_UTIL_H


#include <netdb.h>
#include <string>

bool resolve_addr(const std::string &host, const std::string &port, sockaddr_storage &out);


#endif
