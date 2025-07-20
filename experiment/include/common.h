//
// Created by Alex on 2025/7/18.
//

#ifndef COMMON_H
#define COMMON_H

#include <stdio.h>
#include <stdarg.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <picoquic_utils.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <sys/time.h>

#define ALPN "test"

typedef enum phase {
    wait_create_stream0,
    send_data1,
    probe_path,
    send_after_path,
    wait_create_stream1,
    close_stream0,
    close_stream1,
    close_conn
}phase_t;

typedef struct application_ctx {
    struct event *app_event;
    phase_t phase;
    uint8_t *send_buffer;
    int send_idx;
    uint8_t *recv_buffer;
    int recv_idx;
    int send_buffer_size;
    int recv_buffer_size;

    uint64_t sequence;
}application_ctx_t;

static inline void appctx_data_recv(application_ctx_t* appctx, uint8_t *data, int length) {
    if (length == 0) {
        return;
    }
    memcpy(appctx->recv_buffer + appctx->recv_idx, data, length);
    appctx->recv_idx += length;
}

static inline int appctx_recv_available_size(application_ctx_t* appctx) {
    int recv_can_use = appctx->recv_buffer_size - appctx->recv_idx;
    return recv_can_use;
}

static inline int appctx_used_len(application_ctx_t* appctx) {
    return appctx->recv_idx;
}


//return copied number of bytes
static inline int  appctx_recv_copy_out(application_ctx_t* appctx, uint8_t*dst, int dst_lenght) {
    if (dst_lenght<=0) {
        return 0;
    }
    int bytes_copy = dst_lenght;
    int avai = appctx_used_len(appctx);
    if (avai<bytes_copy) {
        bytes_copy = avai;
    }
    if (bytes_copy>0) {
        memcpy(dst, appctx->recv_buffer, bytes_copy);
    }
    if (appctx->recv_idx == bytes_copy) {
        appctx->recv_idx = 0;
    }else {
        appctx->recv_idx -= bytes_copy;
    }
    return bytes_copy;
}


typedef struct socket_handler {
    int fd;
    uint16_t local_port;
    struct event *ev_sock;
    int ifx_idx;
    int path_id;
}socket_handler_t;

static char* event_mapping[] = {
    [picoquic_callback_stream_data] = "picoquic_callback_stream_data",
    [picoquic_callback_stream_fin] = "picoquic_callback_stream_fin",
    [picoquic_callback_stream_reset] = "picoquic_callback_stream_reset",
    [picoquic_callback_stop_sending] = "picoquic_callback_stop_sending",
    [picoquic_callback_stateless_reset] = "picoquic_callback_stateless_reset",
    [picoquic_callback_close] = "picoquic_callback_close",
    [picoquic_callback_application_close] = "picoquic_callback_application_close",
    [picoquic_callback_stream_gap] = "picoquic_callback_stream_gap",
    [picoquic_callback_prepare_to_send] = "picoquic_callback_prepare_to_send",
    [picoquic_callback_almost_ready] = "picoquic_callback_almost_ready",
    [picoquic_callback_ready] = "picoquic_callback_ready",
    [picoquic_callback_version_negotiation] = "picoquic_callback_version_negotiation",
    [picoquic_callback_request_alpn_list] = "picoquic_callback_request_alpn_list",
    [picoquic_callback_set_alpn] = "picoquic_callback_set_alpn",
    [picoquic_callback_pacing_changed] = "picoquic_callback_pacing_changed",
    [picoquic_callback_prepare_datagram] = "picoquic_callback_prepare_datagram",
    [picoquic_callback_datagram_acked] = "picoquic_callback_datagram_acked",
    [picoquic_callback_datagram_lost] = "picoquic_callback_datagram_lost",
    [picoquic_callback_datagram_spurious] = "picoquic_callback_datagram_spurious",
    [picoquic_callback_path_available] = "picoquic_callback_path_available",
    [picoquic_callback_path_suspended] = "picoquic_callback_path_suspended",
    [picoquic_callback_path_deleted] = "picoquic_callback_path_deleted",
    [picoquic_callback_path_quality_changed] = "picoquic_callback_path_quality_changed",
    [picoquic_callback_app_wakeup] = "picoquic_callback_app_wakeup",
    [picoquic_callback_next_path_allowed] = "picoquic_callback_next_path_allowed",

};




static inline void log_facade(char * level,char *file, char * func ,int line, char * fmt, ...)
#if defined(__GNUC__)
__attribute__ (( format (printf, 5, 6) ))
#endif
;

static inline void log(char * fmt, va_list ap) {
    vprintf(fmt, ap);
}


static inline void uint8_to_ascii(uint8_t * buf, int length, char *char_buff, int char_length){
    for (int i = 0; i < length; i++) {
        int tmp = snprintf(char_buff, char_length ,"%02x", buf[i]);
        char_buff += tmp;
    }
}


static inline void log_facade(char * level,char *file, char * func ,int line, char * fmt, ...) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    struct tm *local = localtime(&tv.tv_sec);
    char time_str[64] = {0};
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", local);
    char final_str[70] = {0};
    snprintf(final_str, sizeof(final_str), "%s.%03ld", time_str, tv.tv_usec / 1000);

    char fmt_buf[512] = {0};
    char * tmp = fmt_buf;
    int used = 0;
    int remain = sizeof(fmt_buf);
    used += snprintf(fmt_buf + used, remain, "%s %s %s:%d %s %s \n", final_str, level, file, line ,func ,fmt);
    remain -= used;
    va_list ap;
    va_start(ap, fmt);
    log(fmt_buf, ap);
    va_end(ap);
}

#define log_i(fmt, args...) log_facade("INFO",__FILE__,__FUNCTION__,__LINE__,fmt,##args)


static inline char const* sockaddr_text(const struct sockaddr* addr, char* text, size_t text_size)
{
    char addr_buffer[128];
    char const* addr_text;
    char const* ret_text = "?:?";

    if (addr != NULL) {
        switch (addr->sa_family) {
        case AF_INET:
            addr_text = inet_ntop(AF_INET,
                (const void*)(&((struct sockaddr_in*)addr)->sin_addr),
                addr_buffer, sizeof(addr_buffer));
            if (picoquic_sprintf(text, text_size, NULL, "%s:%d", addr_text, ntohs(((struct sockaddr_in*)addr)->sin_port)) == 0) {
                ret_text = text;
            }
            break;
        case AF_INET6:
            addr_text = inet_ntop(AF_INET6,
                (const void*)(&((struct sockaddr_in6*)addr)->sin6_addr),
                addr_buffer, sizeof(addr_buffer));
            if (picoquic_sprintf(text, text_size, NULL, "[%s]:%d", addr_text, ntohs(((struct sockaddr_in6*)addr)->sin6_port)) == 0) {
                ret_text = text;
            }
        default:
            break;
        }
    }

    return ret_text;
}

int set_fd_noblock(int fd);
int setup_fd(int fd);
int set_fd_reuse(int fd);

#endif //COMMON_H
