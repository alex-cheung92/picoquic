//
// Created by root on 7/18/25.
//

#ifndef CLIENT_H
#define CLIENT_H
#include "picoquic.h"
#include "event.h"
#include "common.h"

#define CLIENT_PATH_NUM (2)
typedef struct client_handler client_handler_t;
typedef struct client_cnx_handler {
    picoquic_cnx_t* cnx;
    picoquic_connection_id_t cid;
    char cid_str[20];
    client_handler_t *client_handler;
    int rpc_sent;
}client_cnx_handler_t;

typedef enum quic_state{
    INIT,
    CONNECTED,
    DISCONNECTED,
}quic_state_t;

typedef struct client_handler {
    picoquic_quic_t * quic;
    quic_state_t quic_state;
    client_cnx_handler_t* cnx_handler;
    //for quic prepare used
    uint8_t *send_buffer;
    int send_buffer_size;
    //0 for default
    struct socket_handler sockets[CLIENT_PATH_NUM];
    struct event_base *event_base;
    struct event *ev_pico;
    void *application_ctx; // application_ctx_t*



}client_handler_t;

void client_timer_event(int fd, short what, void* arg);
void client_socket_event(int fd, short what, void* arg);
void client_init_and_dispatch(struct event_base *event_base);
void client_application_event(int fd ,short what, void* arg);
int client_callback(picoquic_cnx_t* cnx, uint64_t stream_id, uint8_t* bytes, size_t length, picoquic_call_back_event_t fin_or_event, void* callback_ctx, void* v_stream_ctx);
#endif //CLIENT_H
