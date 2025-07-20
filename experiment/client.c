//
// Created by Alex on 2025/7/17.
//
#include "client.h"
#include "picoquic_bbr.h"
#include "picosocks.h"
#include "autoqlog.h"
#include <net/if.h>
#include <fcntl.h>
#include "common.h"
#include "rpc.h"

socket_handler_t* client_find_socket_by_fd(client_handler_t *handler, int fd) {
    for (int i = 0;i < CLIENT_PATH_NUM;i++) {
        if (fd == handler->sockets[i].fd) {
            return handler->sockets + i;
        }
    }
    return NULL;
}

socket_handler_t* client_find_socket_by_localaddr(client_handler_t *handler,  struct sockaddr_storage* local_addr) {
    struct sockaddr_in* v4 = (struct sockaddr_in*)local_addr;
    int port = ntohs(v4->sin_port);
    for (int i = 0;i < CLIENT_PATH_NUM;i++) {
        if (port == handler->sockets[i].local_port) {
            return handler->sockets + i;
        }
    }
    return NULL;
}

socket_handler_t* client_get_default_socket(client_handler_t *handler) {
    return &handler->sockets[0];
}

int client_setup_event(client_handler_t *handler) {
    handler->ev_pico = event_new(handler->event_base, -1, EV_TIMEOUT | EV_PERSIST, client_timer_event, handler);
    if (handler->ev_pico == NULL) {
        log_i("create ev_pico error");
        goto error;
    }
    struct timeval tv = {.tv_sec = 1, .tv_usec = 0};
    event_add(handler->ev_pico, &tv);
    for (int i =0;i<CLIENT_PATH_NUM;i++) {
        socket_handler_t * sock = &handler->sockets[i];
        sock->ev_sock = event_new(handler->event_base, sock->fd, EV_READ | EV_PERSIST , client_socket_event, handler);
        if (sock->ev_sock == NULL) {
            log_i("create ev_sock error idx: %d", i );
            goto error;
        }
        if (event_add(sock->ev_sock, NULL)!=0) {
            log_i("create ev_sock error idx: %d", i);
            goto error;
        }
    }
    return 0;
error:
    log_i("setup event error please check");
    return -1;

}

client_handler_t* client_alloc_handler(struct event_base *event_base) {
    client_handler_t * handler = malloc(sizeof(client_handler_t));
    memset(handler, 0, sizeof(client_handler_t));
    handler->event_base = event_base;
    handler->send_buffer_size = 2000;
    handler->send_buffer = malloc(handler->send_buffer_size);
    handler->quic_state = INIT;
    memset(handler->send_buffer, 0, handler->send_buffer_size);
    return handler;
}

int create_bind_fd(int port, client_handler_t *handler, int idx) {
    int ret;
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
    handler->sockets[idx].fd = fd;
    handler->sockets[idx].local_port = port;
    handler->sockets[idx].ifx_idx = if_nametoindex("lo");
    ret = setup_fd(fd);
    if (ret<0) {
        goto error;
    }
    if (bind(fd, v4, sizeof(struct sockaddr_in))<0){
        goto error;
    }
    log_i("create bind fd %d with port %d success",fd, port);
    return 0;
error:
    log_i("create fd %d error", idx);
    close(fd);
    return -1;
}

int create_client_fd(int port1,int port2, client_handler_t *handler) {
    int ret = 0;
    if (create_bind_fd(port1, handler, 0)<0) {
        goto error;
    }
    if (create_bind_fd(port2, handler, 1)<0) {
        goto error;
    }
    return 0;
error:
    log_i("create fd error, please check");
    return 0;
}


int client_send_socket(picoquic_cnx_t* last_cnx,int fd, struct sockaddr* addr_dest, struct sockaddr* addr_from, int if_index, int mtu, char *buff, int length) {
    int sock_ret = 0;
    int sock_err;
    size_t packet_index = 0;
    size_t packet_size = mtu;

    while (packet_index < length) {
        if (packet_index + packet_size > length) {
            packet_size = length - packet_index;
        }
        sock_ret = picoquic_sendmsg(fd, addr_dest, addr_from, if_index, (buff + packet_index), (int)packet_size, 0, &sock_err);
        if (sock_ret > 0) {
#ifdef SOCKET_LOG
            char from[64];
            sockaddr_text(addr_from, from, sizeof(from));
            char to[64];
            sockaddr_text(addr_dest, to, sizeof(to));
            log_i("[%s -> %s] fd:%d ifidx:%d Len:%d",from, to, fd, if_index, packet_size);
#endif
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

void client_timer_event(int fd, short what, void * arg) {
    client_handler_t *handler = arg;
    int ret = 0;
    uint64_t current_time = picoquic_current_time();
    picoquic_cnx_t* last_cnx = NULL;
    int if_index = -1;
    size_t send_length = 0;
    struct sockaddr_storage local_addr = {0};
    size_t mtu = 0;  //mtu
    struct sockaddr_storage peer_addr = {0};
    picoquic_connection_id_t log_cid;
    size_t bytes_sent = 0;
    while (ret == 0) {
        send_length = 0;
        ret = picoquic_prepare_next_packet_ex(handler->quic, current_time,
                                                handler->send_buffer, handler->send_buffer_size, &send_length,
                                                &peer_addr, &local_addr, &if_index, &log_cid, &last_cnx,
                                                &mtu);

        // if (send_length>0) {
            // char tmp[64];
            // log_i("client picoquic_prepare_next_packet_ex local_addr:%s", sockaddr_text(&local_addr, tmp,sizeof(tmp)));
        // }
        socket_handler_t* socket_handler = client_find_socket_by_localaddr(handler, &local_addr);
        if (socket_handler == NULL) {
            socket_handler = client_get_default_socket(handler);
        }
        if (local_addr.ss_family == AF_UNSPEC) {
            struct sockaddr_in* v4 = (struct sockaddr_in*)&local_addr;
            v4->sin_port = htons(socket_handler->local_port);
            v4->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            v4->sin_family = AF_INET;
        }
        if (if_index == 0) {
            if_index = socket_handler->ifx_idx;
        }

        if (ret == 0 && send_length > 0) {
            bytes_sent += send_length;
            ret = client_send_socket(last_cnx, socket_handler->fd, &peer_addr, &local_addr, if_index, mtu, handler->send_buffer, send_length);
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

void client_socket_event(int fd, short what, void *arg) {
    client_handler_t *handler = arg;
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
        socket_handler_t* socket = client_find_socket_by_fd(handler,fd);
        if (socket == NULL) {
            return;
        }
        while( (bytes_recv = picoquic_recvmsg(socket->fd, &addr_from,
            &addr_to, &if_index_to, &received_ecn, buffer, sizeof(buffer))) > 0 ) {
            current_time = picoquic_current_time();
            if(addr_to.ss_family == AF_INET6) {
                log_i("ipv6 not happen");
            } else if (addr_to.ss_family == AF_INET) {
                // char tmp[64];
                // sockaddr_text(&addr_to, tmp, sizeof(tmp));
                // log_i("recv afinet before set :%s", tmp);
                // ((struct sockaddr_in*)&addr_to)->sin_port = ((struct sockaddr_in*)&(socket))->sin_port;
            }else {
                // char tmp[64];
                // sockaddr_text(&addr_to, tmp, sizeof(tmp));
                // log_i("recv unset before :%s", tmp);
                addr_to.ss_family = AF_INET;
                ((struct sockaddr_in*)&addr_to)->sin_port = htons(socket->local_port);
                inet_aton("127.0.0.1", &((struct sockaddr_in*)&addr_to)->sin_addr);
                // sockaddr_text(&addr_to, tmp, sizeof(tmp));
                // log_i("recv unset after :%s", tmp);
            }
            if (if_index_to == 0) {
                if_index_to = socket->ifx_idx;
            }
#ifdef SOCKET_LOG
            char from[64];
            sockaddr_text(&addr_from, from, sizeof(from));
            char to[64];
            sockaddr_text(&addr_to, to, sizeof(to));
            log_i("[%s <- %s] ifidx:%d Len:%d", to, from, if_index_to, bytes_recv);
#endif
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




void set_client_transport_params(client_handler_t *handler) {
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
    tp->max_idle_timeout = 2;
    picoquic_set_default_tp(handler->quic, tp);
}

void client_set_rest_opts(client_handler_t *handler) {
    picoquic_set_default_congestion_algorithm(handler->quic, picoquic_bbr_algorithm);
    picoquic_set_default_idle_timeout(handler->quic, 1000*60*1000);
    picoquic_set_qlog(handler->quic, "./qlog");
    picoquic_set_log_level(handler->quic, 1);
    picoquic_enable_path_callbacks_default(handler->quic, 1);
    picoquic_enable_sslkeylog(handler->quic, 1);
    picoquic_set_key_log_file(handler->quic,"./pcap/client_sslkeylog.txt");
}

void client_set_cnx_ops(client_handler_t *handler) {
    picoquic_cnx_t* cnx = handler->cnx_handler->cnx;
    picoquic_enable_path_callbacks(cnx,1);
}

int client_init_quic(client_handler_t *handler) {
    handler->quic = picoquic_create(1,NULL, NULL, NULL,
        ALPN, client_callback,handler, NULL, NULL, NULL,
        picoquic_current_time(),NULL,NULL,NULL, 0);
    if (handler->quic == NULL) {
        goto error;
    }
    set_client_transport_params(handler);
    client_set_rest_opts(handler);
    return 0;
error:
    log_i("init_quic please check ");
    return -1;
}
void client_setup_cnx_config(client_handler_t* handler) {
    // picoquic_enable_keep_alive(handler->cnx_handler->cnx,1000000);
    picoquic_enable_keep_alive(handler->cnx_handler->cnx,0);
    client_set_cnx_ops(handler);
}

client_cnx_handler_t * do_connect(client_handler_t* handler, struct sockaddr_storage *to) {
    client_cnx_handler_t * cnx_handler = malloc(sizeof(client_cnx_handler_t));
    memset(cnx_handler,0,sizeof(client_cnx_handler_t));
    cnx_handler-> rpc_sent = 0;
    cnx_handler -> client_handler = handler;
    cnx_handler->cnx = picoquic_create_cnx(handler->quic,picoquic_null_connection_id,picoquic_null_connection_id, to, picoquic_current_time(),0, NULL, ALPN, 1);
    handler->cnx_handler = cnx_handler;
    picoquic_connection_id_t icid = picoquic_get_initial_cnxid(cnx_handler->cnx);
    memcpy(&cnx_handler->cid, &icid, sizeof(picoquic_connection_id_t));
    uint8_to_ascii(icid.id,icid.id_len,cnx_handler->cid_str,sizeof(cnx_handler->cid_str));
    handler->cnx_handler->start_time = picoquic_current_time();
    return cnx_handler;

}

int client_create_connection(client_handler_t* handler) {
    int ret = 0;
    struct sockaddr_storage to  = {0};
    ((struct sockaddr_in*)&to)->sin_family = AF_INET;
    ((struct sockaddr_in*)&to)->sin_port = htons(28256);
    ret = inet_aton("127.0.0.1", &((struct sockaddr_in*)&to)->sin_addr);
    if (ret!=1) {
        goto error;
    }
    do_connect(handler, &to);
    client_setup_cnx_config(handler);
    log_i("start connect to server using cid:%s", handler->cnx_handler->cid_str);
    ret = picoquic_start_client_cnx(handler->cnx_handler->cnx);
    if (ret<0) {
        log_i("picoquic_start_client_cnx error ret %d", ret);
        goto error;
    }
    return 0;
error:
    return -1;
}

void print_ack_info(client_handler_t *handler , application_ctx_t* appctx) {
    uint8_t tmp[RPC_MSG_LENGTH];
    if (appctx_used_len(appctx)>= RPC_MSG_LENGTH) {
        appctx_recv_copy_out(appctx, tmp, RPC_MSG_LENGTH);
        rpc_msg_t* msg = tmp;
        uint64_t* data = msg->data;
        log_i("client receive acked:%ld", *data);
        handler->cnx_handler->rpc_sent = 0;
    }

}

int client_callback(picoquic_cnx_t* cnx, uint64_t stream_id, uint8_t* bytes, size_t length, picoquic_call_back_event_t fin_or_event, void* callback_ctx, void* v_stream_ctx) {
    int no_print_event = 0;
    no_print_event = fin_or_event == picoquic_callback_prepare_to_send || fin_or_event == picoquic_callback_stream_data||
        fin_or_event == picoquic_callback_stream_fin ;
    if (!no_print_event) {
        log_i("%s ", event_mapping[fin_or_event]);
    }
    client_handler_t *handler = callback_ctx;
    application_ctx_t* appctx = handler->application_ctx;
    if (fin_or_event == picoquic_callback_path_available) {
        struct sockaddr_storage local = {0};
        struct sockaddr_storage remote = {0};
        picoquic_get_path_addr(cnx, stream_id,1, &local);
        picoquic_get_path_addr(cnx, stream_id,2, &remote);
        char local_str[64];
        char remote_str[64];
        sockaddr_text(&local,local_str,sizeof(local_str));
        sockaddr_text(&remote_str,remote_str,sizeof(remote_str));
        log_i("event:%s path is available id :%lu, local:%s, remote:%s", event_mapping[fin_or_event], stream_id, local_str, remote_str);
        return 0;
    }

    if (fin_or_event == picoquic_callback_ready) {
        handler->quic_state = CONNECTED;
        return 0;
    }else if (fin_or_event == picoquic_callback_close) {
        handler->quic_state = DISCONNECTED;
        uint64_t local_reason = 0;
        uint64_t remote_reason = 0;
        uint64_t local_application_reason = 0;
        uint64_t remote_application_reason = 0;
        picoquic_get_close_reasons(cnx, &local_reason, &remote_reason, &local_application_reason, &remote_application_reason);
        log_i("application close local reason:%lu, remote reason:%lu, local application reason:%lu, remote application reaseon:%lu", local_reason, remote_reason, local_application_reason, remote_application_reason);
        return 0;
    }

    if (fin_or_event == picoquic_callback_stream_fin || fin_or_event == picoquic_callback_stream_data) {
            if (appctx_recv_available_size(appctx)>=length) {
                appctx_data_recv(appctx, bytes, length);
                print_ack_info(handler, appctx);
            }else {
                log_i("appctx recv size is less than length");
            }
    }

    if (fin_or_event == picoquic_callback_prepare_to_send) {
        if (!handler->cnx_handler->rpc_sent) {
            int len = RPC_MSG_LENGTH;
            uint8_t*  write_buff =  picoquic_provide_stream_data_buffer(bytes, len,0, 1);
            if (write_buff == NULL) {
                log_i("picoquic_provide_stream_data_buffer return null");
                return 0;
            }
            rpc_msg_t *msg = malloc(len);
            memset(msg,0,sizeof(rpc_msg_t));
            msg->type=0;
            msg->version=0;
            msg->length =  RPC_PAYLOAD_LENGTH;
            memcpy(msg->data, &appctx->sequence,sizeof(appctx->sequence));
            memcpy(write_buff, msg, len);
            log_i("client sequence sent: %lu", appctx->sequence);
            handler->cnx_handler->rpc_sent = 1;
            appctx->sequence ++;
            free(msg);
        }else {
            // log_i("redundant callback mark stream %lu inactive ", stream_id);
            (void*)picoquic_provide_stream_data_buffer(bytes,0,0,0);
        }
    }

    return 0;
}
void client_application_event(int fd ,short what, void* arg) {
    client_handler_t* handler = arg;
    application_ctx_t* app_ctx = handler->application_ctx;
    if (handler->quic_state == INIT) {
        //connection not ready  wait 1 second
        struct timeval tv = {.tv_sec=1, .tv_usec = 0};
        event_add(app_ctx->app_event, &tv);
        return;
    }
    if (handler->quic_state == DISCONNECTED) {
        //connection disconnection cancel the event loop
        log_i("disconnected");
        event_del(app_ctx->app_event);
        event_free(app_ctx->app_event);
        app_ctx->app_event = NULL;
        return;
    }
    if (handler->quic_state == CONNECTED) {
        if (app_ctx->phase>wait_create_stream0 && app_ctx->phase<=wait_create_stream1) {
            if (!handler->cnx_handler->rpc_sent) {
                picoquic_mark_active_stream(handler->cnx_handler->cnx, 0, 1, handler);
            }
        }
    }

    //do things by phase ...
    switch (app_ctx->phase) {
        case wait_create_stream0: {
            uint64_t stream0 = picoquic_get_next_local_stream_id(handler->cnx_handler->cnx, 0);
            picoquic_mark_active_stream(handler->cnx_handler->cnx, stream0, 1, handler);
            app_ctx->phase = send_data1;
        }
        break;
        case send_data1: {
            app_ctx->phase = probe_path;
        }
        break;
        case probe_path: {
            struct sockaddr_storage remote = {0};
            struct sockaddr_in *   remotev4 = &remote;
            remotev4->sin_family = AF_INET;
            remotev4->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            remotev4->sin_port = htons(28256);
            struct sockaddr_storage local = {0};
            struct sockaddr_in * localv4 = &local;
            localv4->sin_family = AF_INET;
            localv4->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            localv4->sin_port = htons(50001);
            int allow = 0;
            int probe_ret = picoquic_subscribe_new_path_allowed(handler->cnx_handler->cnx, &allow);
            if (probe_ret!=0) {
                log_i("picoquic_subscribe_new_path_allowed failed ret %d", probe_ret);
                return;
            }else {
                if (allow) {
                    probe_ret = picoquic_probe_new_path(handler->cnx_handler->cnx,remotev4, localv4, picoquic_current_time());
                    if (probe_ret!=0) {
                        log_i("picoquic_probe_new_path failed ret %d", probe_ret);
                    }else {
                        app_ctx->phase = send_after_path;
                    }
                }
            }
        }
        case send_after_path: {
            uint64_t current = picoquic_current_time();
            //20s
            if (current - handler->cnx_handler->start_time >  1000 * 20 * 1000) {
                picoquic_close(handler->cnx_handler->cnx, 0x111);
            }
        }
        default:
        log_i("client_application_event unhandled phase %d", app_ctx->phase);
    }
    struct timeval tv = {.tv_sec=1, .tv_usec = 0};
    event_add(app_ctx->app_event, &tv);

}
void client_setup_application_event(client_handler_t* handler) {
    if (handler->application_ctx == NULL) {
        application_ctx_t* app = malloc(sizeof(application_ctx_t));
        memset(app, 0 , sizeof(application_ctx_t));
        app->send_buffer_size = 16;
        app->send_buffer = malloc(app->send_buffer_size);
        memset(app->send_buffer, 0, app->send_buffer_size);
        app->recv_buffer_size = 16;
        app->recv_buffer = malloc(app->recv_buffer_size);
        memset(app->recv_buffer, 0, app->recv_buffer_size);
        app->sequence = 0;
        app->send_idx = 0;
        app->recv_idx = 0;
        app->phase = wait_create_stream0;
        app->app_event = event_new(handler->event_base, -1, EV_TIMEOUT | EV_PERSIST, client_application_event, handler);
        event_active(app->app_event,0, 1);
        handler->application_ctx= app;
    }else {
        log_i("not expected");
    }
}

void client_init_and_dispatch(struct event_base *event_base) {
    client_handler_t* handler = client_alloc_handler(event_base);
    client_init_quic(handler);
    create_client_fd(50000,50001, handler);
    client_setup_event(handler);
    client_create_connection(handler);
    client_setup_application_event(handler);
    int ret = event_base_dispatch(handler->event_base);
    log_i("dispatch return %d \n",ret );
    return;
error:
    return;

}

