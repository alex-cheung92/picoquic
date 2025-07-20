//
// Created by Alex on 2025/7/17.
//
#ifndef SERVER_H
#define SERVER_H
#include "picoquic.h"
#include "event.h"
#include "common.h"

//This points to project's certs dir files, I am in docker mount to a different dir
#define CERT_FILE "/home/dev/picoquic/certs/cert.pem"
#define KEY_FILE "/home/dev/picoquic/certs/key.pem"

typedef struct server_handler {
    picoquic_quic_t * quic;
    struct socket_handler sockets[1];
    struct event_base *event_base;
    struct event *ev_pico;
    //for quic prepare used
    uint8_t *send_buffer;
    int send_buffer_size;

    application_ctx_t* appctx;
    int need_response ;
}server_handler_t;

void server_timer_event(int fd, short what, void * arg);
void server_socket_event(int fd, short what, void *arg);
void server_init_and_dispatch(struct event_base *event_base) ;
#endif //SERVER_H
