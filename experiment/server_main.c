//
// Created by Alex on 2025/7/17.
//
#include "event.h"
#include "common.h"
#include "server.h"

int main(){
    struct event_base * event = event_base_new();
    server_init_and_dispatch(event);
    return 0;
}

