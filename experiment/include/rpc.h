//
// Created by root on 7/18/25.
//

#ifndef RPC_H
#define RPC_H
#include <stdint.h>

#pragma pack(1)
typedef struct rpc_msg{
    uint8_t version;
    uint8_t type;
    uint16_t length;  // the length of data, not including type and length field
    uint8_t data[0];
} rpc_msg_t;

#pragma pack()
#endif //RPC_H
