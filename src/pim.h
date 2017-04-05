/*
 * pim.h
 *
 *  Created on: 2015年9月5日
 *      Author: jesse
 */

#ifndef PIM_H_
#define PIM_H_

#include <stdint.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

/***
 包类型
 ***/
#define PIM_PACKET_CONNECT  1
#define PIM_PACKET_CONNECT_ACK 2
#define PIM_PACKET_PING  3
#define PIM_PACKET_PONG  4
#define PIM_PACKET_DISCONNECT  5
#define PIM_PACKET_MSG 7
#define PIM_PACKET_MSG_ACK 8
#define PIM_PACKET_MSG_RECEIPT  9

/***
 连接错误码
 ***/

/*已连接上*/
#define PIM_ERR_CONNECT_ALREADY_CONNECTED 1
/*客户端错误(如内存不足)*/
#define PIM_ERR_CONNECT_CLIENT 2
/*网络错误*/
#define PIM_ERR_CONNECT_NETWORK 3
/*校验失败*/
#define PIM_ERR_CONNECT_VERIFY_FAILED 11
/*服务器错误*/
#define PIM_ERR_CONNECT_SERVER 12

/***
 断开原因
 ***/
/*网络问题*/
#define PIM_ERR_DISCONNECT_NORMAL 0
/*别处登录*/
#define PIM_ERR_DISCONNECT_DUPLICATE_LOGIN 1
/*主动断开*/
#define PIM_ERR_DISCONNECT_FORCE 2

typedef struct pim_packet {
    uint8_t type;
    uint32_t body_length;
    char* body;
} pim_packet;

typedef struct pim_message {
    char* from;
    char* to;
    uint64_t time;
    char* sequence_id;
    char* msg_id;
    char* content;
    char* extra;
    uint32_t content_length;
} pim_message;

typedef struct pim_msg_send_ack {
    char* sequence_id;
    char* msg_id;
} pim_msg_send_ack;

typedef struct pim_login_result {
    int err;
    int cThreshold;/*compress threshold*/
} pim_login_result;

typedef void (pim_packet_callback)(pim_packet* packet);
typedef void (pim_disconnected_callback)(int reason);
typedef void (pim_parse_login_result)(char* data, uint32_t data_length,
pim_login_result* result);
typedef void (pim_log)(char* msg);

typedef struct pim_init_options {
    pim_log* log;
    pim_packet_callback* on_packet;
    pim_disconnected_callback* on_disconnected;
    pim_parse_login_result* parse_login_result;
    int content_as_string;
} pim_init_options;

typedef struct pim_connect_options {
    char* server_host;
    uint32_t server_port;
    int connect_timeout;
    int write_timeout;
    char* login_data;
    int ssl;
} pim_connect_options;

typedef struct pim_readthread_data {
    char invalidated;
    SSL* ssl;
    int fd;
    void* client;
} pim_readthread_data;

typedef struct pim_client {
    pim_log* log;
    pim_packet_callback* on_packet;
    pim_disconnected_callback* on_disconnected;
    pim_parse_login_result* parse_login_result;
    pthread_mutex_t* mutex;
    int content_as_string;
    int compress_threshold;
    int fd;
    int disconnect_reason;
    pthread_t readthread;
    pim_readthread_data* readthread_data;
    SSL_CTX* ssl_context;
    SSL* ssl;
} pim_client;

pim_client* pim_init(pim_init_options* options);

int pim_connect(pim_client* client, pim_connect_options* options);

int pim_disconnect(pim_client* client);

int pim_is_connected(pim_client* client);

int pim_send_msg(pim_client* client, pim_message* msg);

int pim_send_msg_receipt(pim_client* client, char* msg_id);

int pim_send_ping(pim_client* client);

int pim_send_pong(pim_client* client);

pim_message* pim_parse_msg(pim_client* client, pim_packet* packet);

pim_msg_send_ack* pim_parse_msg_send_ack(pim_client* client, pim_packet* packet);

void pim_free_msg(pim_message* msg);

void pim_free_msg_send_ack(pim_msg_send_ack* ack);

void pim_free_client(pim_client* client);

#endif /* PIM_H_ */
