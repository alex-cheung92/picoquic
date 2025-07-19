//
// Created by Alex on 2025/7/18.
//
#include "common.h"
#include <fcntl.h>

int setup_fd(int fd) {
    int ret = set_fd_noblock(fd);
    if (ret < 0) {
        log_i("set set_fd_noblock error fd:%d",fd);
    }
    ret = set_fd_reuse(fd);
    if (ret < 0) {
        log_i("set set_fd_reuse error fd:%d",fd);
    }

    return 0;
}

int set_fd_reuse(int fd) {
    int reuse = 1;
    if (setsockopt(fd ,SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse)) < 0) {
        log_i("setsockopt SO_REUSEPORT failed");
        return -1;
    }
    return 0;
}

int set_fd_noblock(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) {
        log_i("get flags error");
        return -1;
    }
    flags |= O_NONBLOCK;
    if (fcntl(fd, F_SETFL, flags) == -1) {
        log_i("set fd no block error");
        return -1;
    }
    return 0;
}