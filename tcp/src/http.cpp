#include "tcp/http.h"
#include <arpa/inet.h>
#include <asm-generic/socket.h>
#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <netdb.h>
#include <netinet/in.h>
#include <regex>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>

// class Http

Http::Http(uint16_t port)
    : Vrecv{port} {}

size_t Http::get_full_length(const std::string &s) {
    std::smatch m;
    if (std::regex_search(s, m, std::regex{R"(Content-Length:\s*(\d+))"})) {
        if (auto header_length = s.find("\r\n\r\n"); header_length != std::string::npos) {
            return stoi(m[1].str()) + header_length + 4;
        }
        return -1;
    }
    return s.size();
}

// class Client

Client::Client(std::string ip, uint16_t port)
    : Http{port} {
    server_addr.sin_addr.s_addr = inet_addr(get_addr(ip).c_str());
    if (connect(client_fd, reinterpret_cast<sockaddr *>(&server_addr), sizeof(server_addr))) {
        std::cerr << "fail to connect: " << std::strerror(errno) << std::endl;
    } else {
        std::cout << "connecting to " << ip << ':' << port << std::endl;
    }
}

std::string Client::get_addr(std::string host) {
    auto *a = gethostbyname(host.data());
    return inet_ntoa(*reinterpret_cast<in_addr *>(a->h_addr));
}

// class Server

static void kill_zombie(int) {
    int status;
    pid_t pid;
    while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
        if (WIFEXITED(status)) {
            std::cout << "PROCESS " << pid << " exited with status " << WEXITSTATUS(status) << std::endl;
        } else if (WIFSIGNALED(status)) {
            std::cout << "PROCESS " << pid << " was terminated by signal " << WTERMSIG(status) << std::endl;
        } else {
            std::cout << "PROCESS " << pid << " terminated abnormally" << std::endl;
        }
    }
}

Server::Server(uint16_t port, uint32_t timeout, uint32_t queue_limit, std::string end_string)
    : Http{port}
    , end_string{end_string}
    , timeout{timeout} {
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(server_fd, reinterpret_cast<sockaddr *>(&server_addr), sizeof(server_addr)) == -1) {
        std::cerr << "bind failed: " << std::strerror(errno) << std::endl;
    } else {
        std::cout << "bind successfully" << std::endl;
    }
    if (listen(server_fd, queue_limit) == -1) {
        std::cerr << "listen failed: " << std::strerror(errno) << std::endl;
    } else {
        std::cout << "listening on port " << port << std::endl;
    }

    // Register signal handler
    struct sigaction sa;
    sa.sa_handler = kill_zombie;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART; // Automatically restarts accept() if it is interrupted by a signal.
    sigaction(SIGCHLD, &sa, 0); // When a child process finishes, the parent process receives SIGCHLD.
}

void Server::start(std::function<std::string(std::string)> f) {
    socklen_t cl_size = sizeof(client_addr);
    while (true) {
        client_fd = accept(server_fd, reinterpret_cast<sockaddr *>(&client_addr), &cl_size);
        if (client_fd == -1) {
            std::cerr << "accept failed: " << std::strerror(errno) << std::endl;
            continue;
        }
        struct timeval tv;
        tv.tv_sec = timeout;
        tv.tv_usec = 0;
        // Set socket timeout
        if (setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) == -1) {
            std::cerr << "set timeout failed: " << std::strerror(errno) << std::endl;
            close(client_fd);
            continue;
        }
        pid_t pid = fork();
        if (pid == -1) {
            std::cerr << "fork failed: " << std::strerror(errno) << std::endl;
        } else if (!pid) {
            for (std::optional<std::string> s; (s = recv()); send(f(*s))) {}
            // send(end_string);
            shutdown(client_fd, SHUT_WR);
            close(client_fd);
            exit(0);
        }
        std::cout << "New connection handle by PID " << pid << std::endl;
    }
}

// class TlsLayer

TlsLayer::TlsLayer(uint16_t port)
    : Vrecv{port} {}

size_t TlsLayer::get_full_length(const std::string &s) {
    if (s.size() < 5) {
        return -1;
    }
    return static_cast<uint8_t>(s[3]) * 0x100 + static_cast<uint8_t>(s[4]) + 5;
}
