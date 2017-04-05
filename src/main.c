
#import "pim.h"
#import "cJSON.h"
#include <pthread.h>
#include <time.h>
#include <sys/time.h>
#include <stdarg.h>



static pim_client* client = NULL;



void on_disconnected(int reason) {
    printf("已断开连接，错误码: %d\n", reason);
    do_connect();
    //pim_free_client(client);
}

void on_packet(pim_packet* p) {
    char type = p->type;
    if(type == PIM_PACKET_PING) {
        printf("收到Ping,回一个Pong\n");
        pim_send_pong(client);
    } else if(type == PIM_PACKET_PONG) {
        printf("收到Pong,处理客户端自检网络的情况(发送ping给服务器)\n");
    } else if (type == PIM_PACKET_MSG) {
        pim_message* msg = pim_parse_msg(client, p);
        if (!msg) {
            printf("收到消息，但解析消息出错\n");
        } else {
            printf("收到消息: from:%s, to:%s, id:%s, time:%llu, extra:%s, content length:%d, content:%s.\n",
                   msg->from, msg->to, msg->msg_id, msg->time, msg->extra, msg->content_length, msg->content);

            if (msg->msg_id) {
                 //发送消息接收回执
                pim_send_msg_receipt(client, msg->msg_id);
            }

            // 回一个消息
            /*cJSON* request = cJSON_CreateObject();
            cJSON_AddItemToObject(request, "type", cJSON_CreateString("std.text"));
            cJSON_AddItemToObject(request, "content", cJSON_CreateString("这是发送的内容end"));
            char* recontent =cJSON_Print(request);
            int recontent_len = strlen(recontent);
            cJSON_Delete(request);
            char sequence_id[255];
            bzero(sequence_id, 255);
            //设置sequence_id，才能收到消息发送回执, 这里简单拼接sequence_id，建议用 "时间戳+'-'+序号" 的格式
            sprintf(sequence_id, "%d-%d", (int)time(NULL), 1);
            pim_message remsg = {0};
            remsg.to = msg->from;
            remsg.content = recontent;
            remsg.content_length = recontent_len;
            remsg.sequence_id = sequence_id;
            pim_send_msg(client, &remsg);*/

            //注意：pim_free_msg一定要调
            pim_free_msg(msg);
        }
    } else if(type == PIM_PACKET_MSG_ACK) {
        pim_msg_send_ack* ack = pim_parse_msg_send_ack(client, p);
        if (!ack) {
            printf("解析消息发送回执出错\n");
        } else {
            printf("处理消息发送回执, sequence_id: %s; msg_id: %s \n", ack->sequence_id, ack->msg_id);
            //注意：pim_free_msg_send_ack一定要调
            pim_free_msg_send_ack(ack);
        }
    } else {
        printf("收到Packet，Packet类型 %d \n", (int)type);
    }
}

void parse_login_result(char* data, uint32_t data_length, pim_login_result* result) {
    cJSON* json = data ? cJSON_Parse(data) : NULL;
    if (!json) {
        result->err = PIM_ERR_CONNECT_NETWORK;
        return;
    }
    cJSON* err = cJSON_GetObjectItem(json, "err");
    cJSON* cThreshold = cJSON_GetObjectItem(json, "cThreshold");
    result->err = err ? err->valueint:  PIM_ERR_CONNECT_NETWORK;
    result->cThreshold = cThreshold ? cThreshold->valueint : -1;
    cJSON_Delete(json);
}

void do_log(char* msg) {
    printf("%s\n", msg);
}

void do_connect() {
    pim_connect_options connect_options = {0};
    connect_options.server_host = "127.0.0.1";
    connect_options.server_port = 10001;
    connect_options.ssl = 1;
    connect_options.connect_timeout = 20;
    connect_options.write_timeout = 10;

    cJSON* login_data = cJSON_CreateObject();
    cJSON_AddItemToObject(login_data, "u",  cJSON_CreateString("user.xx"));
    cJSON_AddItemToObject(login_data, "p", cJSON_CreateString("xx"));

    cJSON* login_options = cJSON_CreateObject();
    cJSON_AddItemToObject(login_data, "o", login_options);

    cJSON_AddItemToObject(login_options, "t", cJSON_CreateNumber(1));
#ifndef  PIM_COMPRESS_DISABLED
    cJSON_AddItemToObject(login_options, "c", cJSON_CreateNumber(1));
#endif
    char* login_data_as_string =cJSON_Print(login_data);
    cJSON_Delete(login_data);
    connect_options.login_data = login_data_as_string;

    time_t t1;
    time (&t1);
    printf("t1: %s", asctime(gmtime(&t1)));
    int error_code = pim_connect(client, &connect_options);
    time_t t2;
    time (&t2);
    printf("t2: %s", asctime(gmtime(&t2)));
    //错误码，详见pim.h
    if (error_code) {
        printf("===========not connected, error code: %d===========\n",
               error_code);
    } else {
        printf("===========connected===========\n");
        sleep(399999999);
        pim_disconnect(client);
    }

}

void test_1() {
    //1.先调用pim_init,初始化
    //注意
    pim_init_options init_options = {0};
    //log函数
    init_options.log = do_log;
    //解析登录结果函数
    init_options.parse_login_result = parse_login_result;
    //断开回调
    init_options.on_disconnected = on_disconnected;
    //包回调
    init_options.on_packet = on_packet;
    //是否把内容当string用
    init_options.content_as_string = 1;
    while (1) {
        client = pim_init(&init_options);
        if (client) {
            break;
        }
        sleep(1);
    }

    //connect
    do_connect();
}

int main(int argc, const char* argv[]) {
	test_1();
	return 0;
}
