#ifndef TCP_TCP_H
#define TCP_TCP_H


#include <cstdint>
#include <netinet/in.h>
#include <optional>
#include <string>

#define BUF_SIZE 4096

class Tcp {
protected:
    int server_fd;
    int client_fd;
    struct sockaddr_in server_addr, client_addr;
    char buffer[BUF_SIZE];

public:
    Tcp(uint16_t port = 2001);
    virtual ~Tcp();
    void send(const std::string &s, int fd = 0);
    std::optional<std::string> recv(int fd = 0);
};

class Vrecv : public Tcp {
public:
    Vrecv(uint16_t port);
    std::optional<std::string> recv(int fd = 0);

protected:
    virtual size_t get_full_length(const std::string &s);
};


#endif
