#include "tcp/acceptor.h"
#include <spdlog/spdlog.h>
#include <sys/wait.h>
#include "tcp/address_util.h"

static void kill_zombie(int) {
    int status;
    pid_t pid;
    while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
        if (WIFEXITED(status)) {
            spdlog::info("PID {} exited with status {}", pid, WEXITSTATUS(status));
        } else if (WIFSIGNALED(status)) {
            spdlog::info("PID {} terminated by signal {}", pid, WTERMSIG(status));
        } else {
            spdlog::warn("PID {} terminated abnormally", pid);
        }
    }
}

void ServerAcceptor::start(
    const std::string &host, const std::string &port, uint32_t timeout, uint32_t queue_limit, Process process
) {
    if (!resolve_addr(host, port, server_addr_)) {
        spdlog::error("Failed to resolve address", host, port);
        return;
    }
    spdlog::info("ss_family: {}", server_addr_.ss_family);
    listening_sock_fd_ = socket(server_addr_.ss_family, SOCK_STREAM, IPPROTO_TCP);
    if (listening_sock_fd_ == -1) {
        spdlog::error("Failed to create socket: {}", std::strerror(errno));
        return;
    }
    if (bind(listening_sock_fd_, reinterpret_cast<sockaddr *>(&server_addr_), sizeof(server_addr_)) == -1) {
        spdlog::error("Failed to bind {}:{}: {}", host, port, std::strerror(errno));
        return;
    }
    if (listen(listening_sock_fd_, queue_limit) == -1) {
        spdlog::error("Failed to listen {}:{}: {}", host, port, std::strerror(errno));
        return;
    }

    // Register signal handler to clean up child process
    struct sigaction sa{};
    sa.sa_handler = kill_zombie;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    sigaction(SIGCHLD, &sa, 0);

    while (true) {
        sockaddr_storage client_addr{};
        socklen_t len = sizeof(client_addr);
        int client_sock_fd = accept(listening_sock_fd_, reinterpret_cast<sockaddr *>(&client_addr), &len);
        if (client_sock_fd == -1) {
            spdlog::error("Failed to accept: {}", host, port, std::strerror(errno));
            continue;
        }

        timeval tv{};
        tv.tv_sec = timeout;
        tv.tv_usec = 0;
        if (setsockopt(client_sock_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) == -1) {
            spdlog::error("Failed to set timeout: {}", std::strerror(errno));
            close(client_sock_fd);
            continue;
        }

        pid_t pid = fork();
        if (pid == -1) {
            spdlog::error("Failed to fork: {}", std::strerror(errno));
            close(client_sock_fd);
            continue;
        }
        if (pid != 0) {
            // TODO: Log client information
            // spdlog::info("Connection from {}", );
            continue;
        }

        auto layer = layer_factory_(client_sock_fd);
        for (std::optional<std::string> s; (s = layer->recv());) {
            layer->send(process(*s));
        }
        shutdown(client_sock_fd, SHUT_WR);
        close(client_sock_fd);
        exit(0);
    }
}
