//
// Created by root on 7/20/25.
//
#include <stdlib.h>

#include "common.h"
#include "rpc.h"

int test_basic() ;
int test_write_full();
application_ctx_t * alloc();
rpc_msg_t* make_msg(uint8_t type, uint8_t version, uint64_t seq);
void get_properties(application_ctx_t * papctx, int* free, int* used);

int main() {
    printf("msg length = %lu \n", RPC_MSG_LENGTH);
    printf("current ts:%lu\n", picoquic_current_time());
    test_basic();
    test_write_full();

}


int test_write_full() {
    printf("===================================================\n");
    int freesize = 0, used = 0;
    application_ctx_t * ctx = alloc(13);
    get_properties(ctx, &freesize, &used);
    printf("freesize = %d\n", freesize);
    printf("used = %d\n", used);
    rpc_msg_t* msg  = make_msg(4,5,6);

    appctx_data_recv(ctx,msg, RPC_MSG_LENGTH);
    get_properties(ctx, &freesize, &used);
    printf("freesize = %d\n", freesize);
    printf("used = %d\n", used);






    free(msg);
    free(ctx);
    return 0;
}

void get_properties(application_ctx_t * appctx, int *free, int *used) {
    *free = appctx_recv_available_size(appctx);
    *used = appctx_used_len(appctx);
}



int test_basic() {
    printf("===================================================\n");
    application_ctx_t * ctx = alloc(64);
    rpc_msg_t* msg = make_msg(2,3, 44);

    int freesize = 0, used = 0;
    freesize = appctx_recv_available_size(ctx);
    used = appctx_used_len(ctx);
    printf("freesize = %d\n", freesize);
    printf("used = %d\n", used);

    appctx_data_recv(ctx, msg, RPC_MSG_LENGTH);
    used = appctx_used_len(ctx);
    freesize = appctx_recv_available_size(ctx);
    printf("freesize = %d\n", freesize);
    printf("used = %d\n", used);


    uint8_t read[64] = {0};
    appctx_recv_copy_out(ctx, read, RPC_MSG_LENGTH);
    used = appctx_used_len(ctx);
    freesize = appctx_recv_available_size(ctx);
    printf("freesize = %d\n", freesize);
    printf("used = %d\n", used);

    rpc_msg_t * received_msg = read;
    uint64_t received_seq = 0;
    received_seq = *received_msg->data;

    printf("type %d, version %d  received_seq = %llu\n",received_msg->type, received_msg->version, received_seq);

    free(msg);
    free(ctx);
    return 0;
}


application_ctx_t * alloc(int size) {
    application_ctx_t * ctx = malloc(sizeof(application_ctx_t));
    memset(ctx,0,sizeof(application_ctx_t));
    ctx->recv_idx = 0;
    ctx->recv_buffer_size = size;
    ctx->recv_buffer = malloc(ctx->recv_buffer_size);
    return ctx;
}

rpc_msg_t* make_msg(uint8_t type, uint8_t version, uint64_t seq) {
    rpc_msg_t* msg = malloc(RPC_MSG_LENGTH);
    memset(msg,0,sizeof(rpc_msg_t));
    msg->type = type;
    msg->version = version;
    msg->length = RPC_PAYLOAD_LENGTH;
    memcpy(msg->data, &seq,sizeof(uint64_t));
    return msg;
}
