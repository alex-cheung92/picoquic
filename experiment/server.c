//
// Created by Alex on 2025/7/17.
//

#include "server.h"
#include "common.h"
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>

#include "picoquic_bbr.h"
#include "picosocks.h"
#include "autoqlog.h"
#include <net/if.h>

int setup_event(server_handler_t *handler) {
    handler->ev_pico = event_new(handler->event_base, -1, EV_TIMEOUT | EV_PERSIST, server_timer_event, handler);
    if (handler->ev_pico == NULL) {
        log_i("create ev_pico error");
        goto error;
    }
    struct timeval tv = {.tv_sec = 1, .tv_usec = 0};
    event_add(handler->ev_pico, &tv);
    socket_handler_t * sock = &handler->sockets[0];
    sock->ev_sock = event_new(handler->event_base, handler->sockets[0].fd, EV_READ | EV_PERSIST , server_socket_event, handler);
    if (sock->ev_sock == NULL) {
        goto error;
    }
    if (event_add(sock->ev_sock, NULL)!=0) {
        goto error;
    }
    return 0;
error:
    log_i("setup event error please check");
    return -1;

}

server_handler_t* alloc_handler(struct event_base *event_base) {
    server_handler_t * handler = malloc(sizeof(server_handler_t));
    memset(handler, 0, sizeof(server_handler_t));
    handler->event_base = event_base;
    handler->send_buffer_size = 2000;
    handler->send_buffer = malloc(handler->send_buffer_size);
    memset(handler->send_buffer, 0, handler->send_buffer_size);
    return handler;
}

int create_server_fd(int port, server_handler_t *handler) {
    int ret = 0;
    struct sockaddr_storage ss = {0};
    struct sockaddr_in* v4 = &ss;
    v4->sin_port = htons(port);
    v4->sin_family = AF_INET;
    v4->sin_addr.s_addr = htonl(INADDR_ANY);
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK , IPPROTO_UDP);
    if (fd<0) {
        log_i("create fd error");
        return -1;
    }
    handler->sockets[0].fd = fd;
    handler->sockets[0].local_port = port;
    handler->sockets[0].ifx_idx = if_nametoindex("lo");
    handler->sockets[0].path_id = 0;
    ret = setup_fd(fd);
    if (ret<0) {
        goto error;
    }
    if (bind(fd, v4, sizeof(struct sockaddr_in))<0){
        goto error;
    }
    return 0;
error:
    log_i("create fd error, please check");
    if (fd>0) {
        close(fd);
    }
    return 0;
}


int send_server_socket(picoquic_cnx_t* last_cnx,int fd, struct sockaddr* addr_dest, struct sockaddr* addr_from, int if_index, int mtu, char *buff, int length) {
    int sock_ret = 0;
    int sock_err;
    size_t packet_index = 0;
    size_t packet_size = mtu;

    while (packet_index < length) {
        if (packet_index + packet_size > length) {
            packet_size = length - packet_index;
        }
        sock_ret = picoquic_sendmsg(fd,addr_dest, addr_from, if_index, (buff + packet_index), (int)packet_size, 0, &sock_err);
        if (sock_ret > 0) {
            char from[64];
            sockaddr_text(addr_from, from, sizeof(from));
            char to[64];
            sockaddr_text(addr_dest, to, sizeof(to));
            log_i("[%s -> %s] ifidx:%d Len:%d",from, to, if_index, packet_size);
            packet_index += packet_size;
        } else if (picoquic_socket_error_implies_unreachable(sock_err)) {
            picoquic_notify_destination_unreachable(last_cnx, picoquic_current_time(), addr_dest, addr_from, if_index, sock_err);
            return -1;
        }else {
            log_i( "Retry with packet size=%zu fails at index %zu, ret=%d, err=%d.", packet_size, packet_index, sock_ret, sock_err);
            break;
        }
    }
    return 0;
}

void server_timer_event(int fd, short what, void * arg) {
    server_handler_t *handler = arg;
    int ret = 0;
    uint64_t current_time = picoquic_current_time();
    picoquic_cnx_t* last_cnx = NULL;
    int if_index = -1;
    size_t send_length = 0;
    struct sockaddr_storage local_addr;
    size_t mtu = 0;  //mtu
    struct sockaddr_storage peer_addr;
    picoquic_connection_id_t log_cid;
    size_t bytes_sent = 0;
    while (ret == 0) {
        send_length = 0;
        ret = picoquic_prepare_next_packet_ex(handler->quic, current_time,
                                                handler->send_buffer, handler->send_buffer_size, &send_length,
                                                &peer_addr, &local_addr, &if_index, &log_cid, &last_cnx,
                                                &mtu);
        if (ret == 0 && send_length > 0) {
            bytes_sent += send_length;
            ret = send_server_socket(last_cnx, handler->sockets[0].fd, &peer_addr, &local_addr, if_index, mtu, handler->send_buffer, send_length);
        }else {
            break;
        }
    }
    current_time = picoquic_current_time();
    struct timeval tv;
    uint64_t delta_t = picoquic_get_next_wake_delay(handler->quic, current_time, 100000);
    if(delta_t <= 0) {
        tv.tv_sec = (long)(0);
        tv.tv_usec = (long)(100000);
        evtimer_add(handler->ev_pico, &tv);
    } else {
        tv.tv_sec = (long)(delta_t / 1000000);
        tv.tv_usec = (long)(delta_t % 1000000);
        evtimer_add(handler->ev_pico, &tv);
    }
}

void server_socket_event(int fd, short what, void *arg) {
    server_handler_t *handler = arg;
    uint8_t buffer[1536];
    struct sockaddr_storage addr_from = {0};
    struct sockaddr_storage addr_to = {0};
    picoquic_cnx_t* last_cnx = NULL;
    struct timeval tv;
    int64_t delta_t = 0;
    uint64_t current_time = 0;
    if (what & EV_WRITE) {
        log_i("should not happen");
    }
    if (what & EV_READ) {
        int if_index_to;
        int bytes_recv;
        unsigned char received_ecn;
        socket_handler_t* socket = &handler->sockets[0];
        while( (bytes_recv = picoquic_recvmsg(socket->fd, &addr_from,
            &addr_to, &if_index_to, &received_ecn, buffer, sizeof(buffer))) > 0 ) {
            current_time = picoquic_current_time();
            /*addr_to 获取到的port默认为0，更新port信息*/
            if(addr_to.ss_family == AF_INET6) {
                log_i("ipv6 not happen");
            } else if (addr_to.ss_family == AF_INET) {
                ((struct sockaddr_in*)&addr_to)->sin_port = ((struct sockaddr_in*)&(socket))->sin_port;
            }else {
                addr_to.ss_family = AF_INET;
                ((struct sockaddr_in*)&addr_to)->sin_port = htons(socket->local_port);
                inet_aton("127.0.0.1", &((struct sockaddr_in*)&addr_to)->sin_addr);
            }
            if (if_index_to == 0) {
                if_index_to = socket->ifx_idx;
            }
            char from[64];
            sockaddr_text(&addr_from, from, sizeof(from));
            char to[64];
            sockaddr_text(&addr_to, to, sizeof(to));
            log_i("[%s <- %s] ifidx:%d Len:%d", to, from, if_index_to, bytes_recv);
            (void)picoquic_incoming_packet_ex(handler->quic, buffer,
                (size_t)bytes_recv, (struct sockaddr*) & addr_from,
                        (struct sockaddr*) & addr_to, if_index_to, received_ecn,
                        &last_cnx, current_time);
        }
        if (bytes_recv <= 0) {
            evtimer_del(handler->ev_pico);
            current_time = picoquic_current_time();
            delta_t = picoquic_get_next_wake_delay(handler->quic, current_time, 100000);
            if(delta_t <= 0 ) {
                tv.tv_sec = (long)(0);
                tv.tv_usec = (long)(100000);
                evtimer_add(handler->ev_pico, &tv);
            } else {
                tv.tv_sec = (long)(delta_t / 1000000);
                tv.tv_usec = (long)(delta_t % 1000000);
                evtimer_add(handler->ev_pico, &tv);
            }
        }
    }
}



int server_callback(picoquic_cnx_t* cnx,
    uint64_t stream_id, uint8_t* bytes, size_t length,
    picoquic_call_back_event_t fin_or_event, void* callback_ctx, void* v_stream_ctx) {
    server_handler_t *handler = callback_ctx;
    log_i("%s ", event_mapping[fin_or_event]);
    return 0;
}

void set_transport_params(server_handler_t *handler) {
    picoquic_tp_t server_default_tp = {0};
    picoquic_tp_t*tp = &server_default_tp;
    tp->initial_max_stream_data_bidi_local = 0x200000;
    tp->initial_max_stream_data_bidi_remote = 65635;
    tp->initial_max_stream_data_uni = 65535;
    tp->initial_max_data = 0x100000;
    tp->initial_max_stream_id_bidir = 5120;
    tp->initial_max_stream_id_unidir = 5120;
    tp->max_packet_size = 1440;
    tp->max_datagram_frame_size = 0;
    tp->ack_delay_exponent = 3;
    tp->active_connection_id_limit = 8;
    tp->max_ack_delay = 10000ull;
    tp->enable_loss_bit = 2;
    tp->min_ack_delay = 1000ull;
    tp->enable_time_stamp = 3;
    tp->enable_bdp_frame = 0;
    tp->is_multipath_enabled = 1;
    tp->initial_max_path_id = 1;
    picoquic_set_default_tp(handler->quic, tp);
}

void set_rest_opts(server_handler_t *handler) {
    picoquic_set_default_congestion_algorithm(handler->quic, picoquic_bbr_algorithm);
    picoquic_set_default_idle_timeout(handler->quic, 1000*60*60);
    picoquic_set_qlog(handler->quic, "./qlog");
    picoquic_set_log_level(handler->quic, 1);
    picoquic_enable_path_callbacks_default(handler->quic, 1);
}

int init_quic(server_handler_t *handler) {
    handler->quic = picoquic_create(1,CERT_FILE, KEY_FILE, NULL,
        ALPN, server_callback,handler, NULL, NULL, NULL,
        picoquic_current_time(),NULL,NULL,NULL, 0);
    if (handler->quic == NULL) {
        goto error;
    }
    set_transport_params(handler);
    set_rest_opts(handler);
    return 0;
error:
    log_i("init_quic please check ");
    return -1;
}


void server_init_and_dispatch(struct event_base *event_base) {
    server_handler_t* handler = alloc_handler(event_base);
    init_quic(handler);
    create_server_fd(28256, handler);
    setup_event(handler);
    log_i("server started using %s ", event_base_get_method(event_base));
    int ret = event_base_dispatch(handler->event_base);
    log_i("dispatch return %d ",ret );
error:
    return;

}
