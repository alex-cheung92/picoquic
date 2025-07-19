//
// Created by Alex on 2025/7/17.
//
#include "event.h"
#include "client.h"

int main(){
    struct event_base * event = event_base_new();
    client_init_and_dispatch(event);
    return 0;
}

