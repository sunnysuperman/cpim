/*
 * pim.c
 *
 *  Created on: 2015年9月5日
 *      Author: jesse
 */


#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <memory.h>
#include <unistd.h>
#include <time.h>
#include <stdlib.h>
#include <netdb.h>
#include <sys/errno.h>
#include <sys/fcntl.h>
#include <sys/time.h>
#include <stdarg.h>

#ifndef PIM_COMPRESS_DISABLED
#include <zlib.h>
#endif

#ifndef PIM_COMPRESS_BUF_SIZE
#define PIM_COMPRESS_BUF_SIZE 4096
#endif

#define GZIP_ERROR_MEMORY -1
#define GZIP_ERROR_DATA -2

#include "pim.h"

/****** utils ******/
static uint32_t _bytes2int(char* bytes) {
    uint32_t num = 0;
    int i = 0;
    for (; i < 4; i++) {
        num <<= 8;
        num |= (bytes[i] & 0x000000ff);
    }
    return num;
}

static uint64_t _bytes2long(char* bytes) {
    uint64_t num = 0;
    int i = 0;
    for (; i < 8; i++) {
        num <<= 8;
        num |= (bytes[i] & 0xff);
    }
    return num;
}

static void _long2bytes(uint64_t num, char* bytes) {
    int i = 8 - 1;
    for (; i >= 0; i--) {
        *(bytes + i) = (num & 0x00000000000000ff);
        num >>= 8;
    }
}

#ifndef PIM_COMPRESS_DISABLED

static int _zlib_compress(char* data, int ndata, char* zdata, int *nzdata) {
    z_stream c_stream = { 0 };
    int err = 0;
    if (data && ndata > 0) {
        c_stream.zalloc = NULL;
        c_stream.zfree = NULL;
        c_stream.opaque = NULL;
        /*只有设置为MAX_WBITS + 16才能在在压缩文本中带header和trailer*/
        if (deflateInit2(&c_stream, Z_DEFAULT_COMPRESSION, Z_DEFLATED,
                         MAX_WBITS + 16, 8, Z_DEFAULT_STRATEGY) != Z_OK)
            return -1;
        c_stream.next_in = (Byte*) data;
        c_stream.avail_in = ndata;
        c_stream.next_out = (Byte*) zdata;
        c_stream.avail_out = *nzdata;
        while (c_stream.avail_in != 0 && c_stream.total_out < *nzdata) {
            if (deflate(&c_stream, Z_NO_FLUSH) != Z_OK)
                return -1;
        }
        if (c_stream.avail_in != 0)
            return c_stream.avail_in;
        for (;;) {
            if ((err = deflate(&c_stream, Z_FINISH)) == Z_STREAM_END)
                break;
            if (err != Z_OK)
                return -1;
        }
        if (deflateEnd(&c_stream) != Z_OK)
            return -1;
        *nzdata = c_stream.total_out;
        return 0;
    }
    return -1;
}

static int _zlib_decompress(char* zdata, int nzdata, char** data_p, int* ndata,
                            int capacity_grow) {
    int capacity = nzdata;
    char* data = malloc(capacity);
    if (!data) {
        return GZIP_ERROR_MEMORY;
    }
    z_stream d_stream = { 0 };
    d_stream.zalloc = NULL;
    d_stream.zfree = NULL;
    d_stream.opaque = NULL;
    d_stream.next_in = (Byte*) zdata;
    d_stream.avail_in = 0;
    d_stream.next_out = (Byte*) data;
    
    /*只有设置为MAX_WBITS + 16才能在解压带header和trailer的文本*/
    if (inflateInit2(&d_stream, MAX_WBITS + 16) != Z_OK) {
        if (data) {
            free(data);
        }
        return GZIP_ERROR_MEMORY;
    }
    int err = 0;
    while (d_stream.total_in < nzdata) {
        d_stream.avail_in = d_stream.avail_out = 1; /* force small buffers */
        err = inflate(&d_stream, Z_NO_FLUSH);
        if (err == Z_STREAM_END) {
            break;
        }
        if (err != Z_OK) {
            if (data) {
                free(data);
            }
            return GZIP_ERROR_DATA;
        }
        if (d_stream.total_out == capacity) {
            int capacity_new = capacity + capacity_grow;
            char* data_new = realloc(data, capacity_new);
            if (!data_new) {
                if (data) {
                    free(data);
                }
                return GZIP_ERROR_MEMORY;
            }
            data = data_new;
            capacity = capacity_new;
            d_stream.next_out = (Byte*) (data + d_stream.total_out);
        }
    }
    if (inflateEnd(&d_stream) != Z_OK) {
        if (data) {
            free(data);
        }
        return GZIP_ERROR_MEMORY;
    }
    *data_p = data;
    *ndata = d_stream.total_out;
    return 0;
}

#endif

static void _log(pim_client* client, char *format, ...) {
    int buf_size = 150;
    char buf[buf_size];
    bzero(buf, buf_size);
    char *p = buf;
    va_list arg;
    
    struct tm *t;
    time_t tt;
    struct timeval tv;
    gettimeofday(&tv, NULL);
    time(&tt);
    t = localtime(&tt);
    sprintf(buf, "%02d:%02d:%02d.%03d [PIM-LIB]", t->tm_hour, t->tm_min,
            t->tm_sec, tv.tv_usec / 1000);
    p += strlen(buf);
    va_start(arg, format);
    vsnprintf(p, buf_size - strlen(buf), format, arg);
    va_end(arg);
    (client->log)(buf);
}

static int _socket_write(pim_client* client, char* buf, int len) {
    int sent = -1;
    if (client->ssl) {
        sent = SSL_write(client->ssl, buf, len);
    } else if (client->fd > 0) {
        sent = send(client->fd, buf, len, 0);
    } else {
        _log(client, "failed to send data ,because socket is closed");
        return 0;
    }
    if (sent != len) {
        _log(client, "failed to send data");
        return 0;
    }
    return 1;
}

static int _socket_read(pim_client* client, int fd, SSL* ssl, char* buf,
                        int target_size) {
    ssize_t len = 0;
    int nread = 0;
    char* pbuf = buf;
    int trial = 0;
    while (nread < target_size) {
        trial++;
        if (ssl) {
            len = SSL_read(ssl, pbuf, target_size - nread);
        } else {
            len = recv(fd, pbuf, target_size - nread, MSG_WAITALL);
        }
        if (len == 0) {
            _log(client, "read end");
            break;
        }
        if (len < 0) {
            if (ssl) {
                _log(client, "ssl_read error: %d", len);
                break;
            } else {
                if (errno == EINTR) {
                    _log(client, "read - system interrupt");
                    continue;
                } else {
                    _log(client, "read error: %d", errno);
                    break;
                }
            }
        }
        nread += len;
        pbuf += len;
    }
    if (nread != target_size) {
        return 0;
    }
    return 1;
}

static int _socket_set_timeout(pim_client* client, int type, int seconds) {
    struct timeval timeout = { seconds, 0 };
    int ret = setsockopt(client->fd, SOL_SOCKET, type, &timeout,
                         sizeof(struct timeval));
    if (ret < 0) {
        _log(client, "failed to set_socket_timeout %d, %d", type, seconds);
    }
    return ret;
}

static int _socket_close(pim_client* client, int free_ssl) {
    if (client->fd <= 0) {
        return -1;
    }
    if (client->ssl) {
        SSL_shutdown(client->ssl);
        if (free_ssl) {
            SSL_free(client->ssl);
        }
        client->ssl = NULL;
    }
    /*if(shutdown(client->fd, SHUT_RDWR) < 0) {
     _log(client, "shutdown failed");
     }*/
    if (close(client->fd) < 0) {
        _log(client, "close failed");
    }
    client->fd = 0;
    int closed = client->disconnect_reason;
    if (client->readthread_data) {
        client->readthread_data->invalidated = 1;
    }
    return closed;
}

static int _socket_force_close(pim_client* client) {
    return _socket_close(client, 1);
}

static char _packet_get_type(char metadata) {
    /* 0000 1111*/
    return (metadata & 0b00001111);
}

static pim_packet* _packet_make(pim_client* client, char type, char* body) {
    pim_packet* p = (pim_packet*) malloc(sizeof(pim_packet));
    if (!p) {
        _log(client, "make_packet - malloc failed");
        return NULL;
    }
    p->type = type;
    p->body = body;
    return p;
}

static void _packet_free(pim_packet* p) {
    if (!p) {
        return;
    }
    if (p->body) {
        free(p->body);
        p->body = NULL;
    }
    free(p);
}

static void _packet_handle(pim_client* client, pim_packet* p) {
    char type = p->type;
    if (type == PIM_PACKET_DISCONNECT) {
        if (p->body_length == 4) {
            pthread_mutex_lock(client->mutex);
            client->disconnect_reason = _bytes2int(p->body);
            pthread_mutex_unlock(client->mutex);
        }
    } else {
        client->on_packet(p);
    }
}

static pim_packet* _packet_read(pim_client* client, int fd, SSL* ssl) {
    char buf[3];
    char metadata;
    char hasdata;
    uint32_t body_len;
    char* body;
    pim_packet* p;
    
    if (!_socket_read(client, fd, ssl, buf, 1)) {
        return NULL;
    }
    metadata = buf[0];
    hasdata = (metadata >> 7) & 0x1;
    if (!hasdata) {
        return _packet_make(client, _packet_get_type(metadata), NULL);
    }
    if (!_socket_read(client, fd, ssl, buf, 3)) {
        return NULL;
    }
    body_len = ((uint8_t) (buf[2] & 0xFF)) + ((uint8_t) (buf[1] & 0xFF)) * 256
    + ((uint8_t) (buf[0] & 0xFF)) * 65536;
    if (body_len == 0) {
        return _packet_make(client, _packet_get_type(metadata), NULL);
    }
    body = malloc(body_len);
    if (!body) {
        _log(client, "read_packet - malloc body failed");
        return NULL;
    }
    if (!_socket_read(client, fd, ssl, body, body_len)) {
        free(body);
        return NULL;
    }
#ifndef PIM_COMPRESS_DISABLED
    char compress = (metadata >> 6) & 0x1;
    if (compress) {
        char* decompress_body = NULL;
        int nbody = 0;
        int ok = _zlib_decompress(body, body_len, &decompress_body, &nbody,
                                  PIM_COMPRESS_BUF_SIZE);
        free(body);
        if (ok < 0) {
            if (ok == GZIP_ERROR_DATA) {
                _log(client, "decompress error due to error data");
            } else {
                _log(client, "decompress error");
            }
            return NULL;
        }
        body = decompress_body;
        body_len = nbody;
    }
#endif
    p = _packet_make(client, _packet_get_type(metadata), body);
    if (!p) {
        free(body);
        return NULL;
    }
    p->body_length = body_len;
    return p;
}

static int _packet_write(pim_client* client, pim_packet* packet, int lock) {
    char header[4];
    int header_len = 1;
    int body_len = packet->body_length;
    char* body = packet->body;
    
    header[0] = 0;
    if (body_len) {
        header[0] += (0x1 << 7);
    }
#ifndef PIM_COMPRESS_DISABLED
    int threshold = client->compress_threshold;
    if (threshold > 0 && body_len > threshold) {
        int nzdata = body_len - 1;
        char zdata[nzdata];
        int ok = _zlib_compress(packet->body, body_len, zdata, &nzdata);
        if (ok == 0) {
            body_len = nzdata;
            memcpy(body, zdata, body_len);
            header[0] += (0x1 << 6);
        }
    }
#endif
    header[0] += packet->type;
    if (body_len) {
        header[1] = body_len / 65536;
        header[2] = (body_len - (header[1] & 0xFF) * 65536) / 256;
        header[3] = body_len % 256;
        header_len = 4;
    }
    
    if (lock) {
        pthread_mutex_lock(client->mutex);
        if (!_socket_write(client, header, header_len)) {
            pthread_mutex_unlock(client->mutex);
            return 0;
        }
        if (body_len && !_socket_write(client, body, body_len)) {
            pthread_mutex_unlock(client->mutex);
            return 0;
        }
        pthread_mutex_unlock(client->mutex);
    } else {
        if (!_socket_write(client, header, header_len)) {
            return 0;
        }
        if (body_len && !_socket_write(client, body, body_len)) {
            return 0;
        }
    }
    return 1;
}

static int _deserialize_msg(pim_client* client, pim_packet* packet,
                            pim_message* msg) {
    const int len = packet->body_length;
    const char* body = packet->body;
    if (len == 0 || !body) {
        _log(client, "deserialize_msg - packet body length == 0");
        return 0;
    }
    char metadata = *body;
    int offset = 1;
    /* 00EIMSFT */
    int i = 0;
    for (; i <= 5; i++) {
        char has = ((metadata >> i) & 0x1);
        if (has == 0) {
            continue;
        }
        int data_size = 0;
        if (i == 5) {
            if (offset + 1 >= len) {
            	return 0;
            }
            data_size = (body[offset + 1] & 0xFF) + (body[offset] & 0xFF) * 256;
            offset += 2;
        } else if (i == 4) {
            data_size = 8;
        } else {
            if (offset >= len) {
                return 0;
            }
            data_size = body[offset] & 0xFF;
            offset++;
        }
        if (data_size == 0) {
            continue;
        }
        if (offset + data_size > len) {
            return 0;
        }
        char* data = (char*) malloc(data_size + 1);
        if (!data) {
            _log(client, "deserialize_msg - malloc data failed");
            return 0;
        }
        bzero(data, data_size + 1);
        memcpy(data, body + offset, data_size);
        offset += data_size;
        if (i == 0) {
            msg->to = data;
        } else if (i == 1) {
            msg->from = data;
        } else if (i == 2) {
            msg->sequence_id = data;
        } else if (i == 3) {
            msg->msg_id = data;
        } else if (i == 4) {
            msg->time = _bytes2long(data);
            free(data);
        } else if (i == 5) {
            msg->extra = data;
        }
    }
    if (offset < len) {
        int content_length = len - offset;
        char* content = (char*) malloc(
                                       content_length + client->content_as_string);
        if (!content) {
            _log(client, "deserialize_msg - malloc content failed");
            return 0;
        }
        if (client->content_as_string) {
            bzero(content, content_length + 1);
        }
        memcpy(content, body + offset, content_length);
        msg->content = content;
        msg->content_length = content_length;
    }
    return 1;
}

static void _free_readthread_data(pim_readthread_data* data) {
    if (data->ssl) {
        SSL_free(data->ssl);
        data->ssl = NULL;
    }
    free(data);
}

static void* _read_routine(void* arg) {
    pim_readthread_data* data = (pim_readthread_data*) (arg);
    pim_client* client = (pim_client*) data->client;
    pim_packet* p = NULL;
    while (1) {
        p = _packet_read(client, data->fd, data->ssl);
        if (!p) {
            break;
        }
        _packet_handle(client, p);
        _packet_free(p);
    }
    int closed = -1;
    pthread_mutex_lock(client->mutex);
    if (!data->invalidated) {
        closed = _socket_close(client, 0);
    }
    pthread_mutex_unlock(client->mutex);
    _free_readthread_data(data);
    if (closed >= 0 && client->on_disconnected) {
        client->on_disconnected(closed);
    }
#ifdef PIM_DEBUG
    _log(client, "read thread exit");
#endif
    return NULL;
}

static int _deserialize_msg_send_ack(pim_client* client, pim_packet* packet,
                                     pim_msg_send_ack* ack) {
    int offset = 0;
    char* body = packet->body;
    
    uint sequence_id_len = body[offset];
    offset++;
    char* sequence_id = (char*) malloc(sequence_id_len + 1);
    if (!sequence_id) {
        _log(client, "deserialize_msg_send_ack - malloc sequence_id failed");
        return 0;
    }
    bzero(sequence_id, sequence_id_len + 1);
    memcpy(sequence_id, body + offset, sequence_id_len);
    offset += sequence_id_len;
    ack->sequence_id = sequence_id;
    
    uint msg_id_len = body[offset];
    offset++;
    char* msg_id = (char*) malloc(msg_id_len + 1);
    if (!msg_id) {
        _log(client, "deserialize_msg_send_ack - malloc msg_id failed");
        return 0;
    }
    bzero(msg_id, msg_id_len + 1);
    memcpy(msg_id, body + offset, msg_id_len);
    ack->msg_id = msg_id;
    
    return 1;
}

static int _connect_with_timeout(pim_client* client, struct sockaddr* sa,
                                 int connect_timeout) {
    int flags = 0, ret = 0;
    int sock = client->fd;
    fd_set rset, wset;
    /*clear out descriptor sets for select add socket to the descriptor sets*/
    FD_ZERO(&rset);
    FD_SET(sock, &rset);
    wset = rset;
    
    /*set socket nonblocking flag*/
    if ((flags = fcntl(sock, F_GETFL, 0)) < 0) {
        return -1;
    }
    if (fcntl(sock, F_SETFL, flags | O_NONBLOCK) < 0) {
        return -1;
    }
    
    /*initiate non-blocking connect*/
    if ((ret = connect(sock, sa, sizeof(struct sockaddr))) < 0) {
        if (errno != EINPROGRESS) {
            return -1;
        }
    }
    
    if (ret == 0) {
        /*then connect succeeded right away*/
        goto done;
    }
    
    /*we are waiting for connect to complete now*/
    struct timeval ts;
    ts.tv_sec = connect_timeout;
    ts.tv_usec = 0;
    if ((ret = select(sock + 1, &rset, &wset, NULL,
                      (connect_timeout) ? &ts : NULL)) < 0) {
        return -1;
    }
    if (ret == 0) {
        _log(client, "connect timeout");
        return -1;
    }
    
    /*we had a positivite return, so a descriptor is ready*/
    /*在调用select()函数后，用FD_ISSET来检测fd在fdset集合中的状态是否变化, 当检测到fd状态发生变化时返回真（非0），否则，返回假（0）*/
    if (FD_ISSET(sock, &rset) || FD_ISSET(sock, &wset)) {
        socklen_t len = sizeof(ret);
        if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &ret, &len) < 0) {
            return -1;
        }
        if (ret) {
            return -1;
        }
    } else {
        return -1;
    }
done: {
    /*put socket back in blocking mode*/
    if (fcntl(sock, F_SETFL, flags) < 0) {
        _log(client, "failed set fd to block mode again");
        return -1;
    }
    if (connect_timeout > 0) {
        if (_socket_set_timeout(client, SO_RCVTIMEO, connect_timeout) < 0) {
            return -1;
        }
        if (_socket_set_timeout(client, SO_SNDTIMEO, connect_timeout) < 0) {
            return -1;
        }
    }
}
    return 0;
}

static int _connect_ssl(pim_client* client) {
    SSL* ssl = SSL_new(client->ssl_context);
    if (!ssl) {
        _log(client, "SSL_new failed");
        return -1;
    }
    SSL_set_fd(ssl, client->fd);
    int err = SSL_connect(ssl);
    if (err <= 0) {
        _log(client, "SSL_connect failed with code: %d", err);
        SSL_free(ssl);
        return -1;
    }
#ifdef PIM_DEBUG
    X509* server_cert = SSL_get_peer_certificate (ssl);
    if (server_cert) {
        char* str;
        str = X509_NAME_oneline (X509_get_subject_name (server_cert),0,0);
        if (str) {
            _log(client, "certificate subject: %s", str);
            OPENSSL_free (str);
        }
        str = X509_NAME_oneline (X509_get_issuer_name (server_cert),0,0);
        if (str) {
            _log(client, "certificate issuer: %s", str);
            OPENSSL_free (str);
        }
        X509_free (server_cert);
    }
#endif
    client->ssl = ssl;
    /* TODO We could do all sorts of certificate verification stuff here  */
    return 0;
}

static int _connect(pim_client* client, pim_connect_options* options) {
#ifdef PIM_DEBUG
    _log(client, "ready to connect %s:%d,timeout:%d,ssl:%d", options->server_host, options->server_port, options->connect_timeout, options->ssl);
#endif
    if (client->fd > 0) {
        return PIM_ERR_CONNECT_ALREADY_CONNECTED;
    }
    //reset
    client->disconnect_reason = PIM_ERR_DISCONNECT_NORMAL;
    client->readthread = 0;
    
    /** 1.init address **/
    struct sockaddr_in remote_addr;
    memset(&remote_addr, 0, sizeof(remote_addr));
    remote_addr.sin_family = AF_INET;
    
    struct hostent* host_addr = gethostbyname(
                                              (const char*) options->server_host);
    if (!host_addr) {
        _log(client, "connect - gethostbyname failed");
        return PIM_ERR_CONNECT_NETWORK;
    }
    struct in_addr** addr_list = (struct in_addr **) host_addr->h_addr_list;
    remote_addr.sin_addr.s_addr = inet_addr(inet_ntoa(**addr_list));
    remote_addr.sin_port = htons(options->server_port);
    
    /** 2.init fd **/
    if ((client->fd = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
        _log(client, "connect - failed to create socket");
        return PIM_ERR_CONNECT_CLIENT;
    }
    /** 3.connect **/
    if (_connect_with_timeout(client, (struct sockaddr*) &remote_addr,
                              options->connect_timeout) < 0) {
        _log(client, "connect - failed to connect to server");
        _socket_force_close(client);
        return PIM_ERR_CONNECT_NETWORK;
    }
    /** 4.ssl_connect **/
    client->ssl = NULL;
    if (options->ssl) {
        if (_connect_ssl(client) < 0) {
            _log(client, "connect - failed to build ssl connection");
            _socket_force_close(client);
            return PIM_ERR_CONNECT_CLIENT;
        }
    }
    /** 5.login **/
#ifdef PIM_DEBUG
    _log(client, "send connect packet");
#endif
    pim_packet loginpack;
    loginpack.type = PIM_PACKET_CONNECT;
    loginpack.body = options->login_data;
    loginpack.body_length = (uint32_t) strlen(options->login_data);
    if (!_packet_write(client, &loginpack, 0)) {
        _log(client, "connect - failed to send connect packet");
        _socket_force_close(client);
        return PIM_ERR_CONNECT_NETWORK;
    }
    
    pim_packet* p = NULL;
    while (1) {
#ifdef PIM_DEBUG
        _log(client, "wait for connect ack...");
#endif
        p = _packet_read(client, client->fd, client->ssl);
        if (!p) {
            _log(client, "connect - failed to receive connect ack");
            _socket_force_close(client);
            return PIM_ERR_CONNECT_NETWORK;
        }
        if (p->type != PIM_PACKET_CONNECT_ACK) {
#ifdef PIM_DEBUG
            _log(client, "receive packet %d", p->type);
#endif
            _packet_free(p);
            continue;
        }
        break;
    }
#ifdef PIM_DEBUG
    _log(client, "received connect ack");
#endif
    pim_login_result result = { 0 };
    client->parse_login_result(p->body, p->body_length, &result);
    _packet_free(p);
    if (result.err != 0) {
        _log(client, "connect - server response error code: %d", result.err);
        _socket_force_close(client);
        return result.err;
    }
    client->compress_threshold = result.cThreshold;
    if (_socket_set_timeout(client, SO_RCVTIMEO, 0) < 0) {
        _log(client, "connect - failed to reset read timeout");
        _socket_force_close(client);
        return PIM_ERR_CONNECT_CLIENT;
    }
    if (_socket_set_timeout(client, SO_SNDTIMEO, options->write_timeout) < 0) {
        _log(client, "connect - failed to reset write timeout");
        _socket_force_close(client);
        return PIM_ERR_CONNECT_CLIENT;
    }
    
    /** 6.create read thread **/
    pim_readthread_data* readdata = (pim_readthread_data*) malloc(
                                                                  sizeof(pim_readthread_data));
    if (!readdata) {
        _log(client, "connect - failed to malloc read_thread_invalidated");
        _socket_force_close(client);
        return PIM_ERR_CONNECT_CLIENT;
    }
    readdata->invalidated = 0;
    readdata->fd = client->fd;
    readdata->ssl = client->ssl;
    readdata->client = client;
    client->readthread_data = readdata;
    if (pthread_create(&client->readthread, NULL, _read_routine, readdata)
        < 0) {
        _log(client, "connect - failed to create read thread");
        _socket_force_close(client);
        readdata->ssl = NULL;
        _free_readthread_data(readdata);
        return PIM_ERR_CONNECT_CLIENT;
    }
    return 0;
}

int pim_connect(pim_client* client, pim_connect_options* options) {
    if (!options->login_data || !options->server_host
        || !options->server_port) {
        return PIM_ERR_CONNECT_CLIENT;
    }
    pthread_mutex_lock(client->mutex);
    int ret = _connect(client, options);
    pthread_mutex_unlock(client->mutex);
    return ret;
}

int pim_is_connected(pim_client* client) {
    return (client->fd > 0) ? 1 : 0;
}

int pim_disconnect(pim_client* client) {
#ifdef PIM_DEBUG
    _log(client, "ready to disconnect");
#endif
    int closed = 0;
    pthread_mutex_lock(client->mutex);
    closed = _socket_close(client, 0);
    pthread_mutex_unlock(client->mutex);
#ifdef PIM_DEBUG
    _log(client, "disconnected");
#endif
    if (closed >= 0 && client->on_disconnected) {
        /*主动断开码*/
        client->on_disconnected(PIM_ERR_DISCONNECT_FORCE);
    }
    return closed >= 0 ? 1 : 0;
}

int pim_send_msg(pim_client* client, pim_message* msg) {
    char metadata = 0;
    /* 00EIMSFT */
    char flag = 0x1;
    int len = 1;
    
    if (msg->to) {
        metadata += (flag);
        len += (1 + strlen(msg->to));
    }
    
    if (msg->from) {
        metadata += (flag << 1);
        len += (1 + strlen(msg->from));
    }
    
    if (msg->sequence_id) {
        metadata += (flag << 2);
        len += (1 + strlen(msg->sequence_id));
    }
    
    if (msg->msg_id) {
        metadata += (flag << 3);
        len += (1 + strlen(msg->msg_id));
    }
    
    if (msg->time > 0) {
        metadata += (flag << 4);
        len += 8;
    }
    
    if (msg->content) {
        if (msg->content_length <= 0) {
            _log(client, "pim_send_msg - please specify content_length");
            return 0;
        }
        len += msg->content_length;
    }
    
    char body[len];
    int offset = 0;
    char sublen = 0;
    body[offset] = metadata;
    offset++;
    
    if (msg->to) {
        sublen = strlen(msg->to);
        body[offset] = sublen;
        offset++;
        memcpy(body + offset, msg->to, sublen);
        offset += sublen;
    }
    if (msg->from) {
        sublen = strlen(msg->from);
        body[offset] = sublen;
        offset++;
        memcpy(body + offset, msg->from, sublen);
        offset += sublen;
    }
    if (msg->sequence_id) {
        sublen = strlen(msg->sequence_id);
        body[offset] = sublen;
        offset++;
        memcpy(body + offset, msg->sequence_id, sublen);
        offset += sublen;
    }
    if (msg->msg_id) {
        sublen = strlen(msg->msg_id);
        body[offset] = sublen;
        offset++;
        memcpy(body + offset, msg->msg_id, sublen);
        offset += sublen;
    }
    if (msg->time > 0) {
        char time[8];
        _long2bytes(msg->time, time);
        memcpy(body + offset, time, 8);
        offset += 8;
    }
    if (msg->content) {
        memcpy(body + offset, msg->content, msg->content_length);
    }
    
    pim_packet p;
    p.type = PIM_PACKET_MSG;
    p.body = body;
    p.body_length = len;
    return _packet_write(client, &p, 1);
}

void _free_pim_client(pim_client* client) {
    if (client->mutex) {
        pthread_mutex_destroy(client->mutex);
        free(client->mutex);
        client->mutex = NULL;
    }
    if (client->ssl_context) {
        SSL_CTX_free(client->ssl_context);
        client->ssl_context = NULL;
    }
    free(client);
}

pim_client* pim_init(pim_init_options* options) {
    if (!options || !options->log || !options->on_packet
        || !options->parse_login_result) {
        return NULL;
    }
    pim_client* client = (pim_client*) malloc(sizeof(pim_client));
    if (!client) {
        return NULL;
    }
    bzero(client, sizeof(pim_client));
    client->log = options->log;
    client->on_packet = options->on_packet;
    client->parse_login_result = options->parse_login_result;
    client->on_disconnected = options->on_disconnected;
    client->content_as_string = (options->content_as_string) ? 1 : 0;
    
    pthread_mutex_t* mutex = (pthread_mutex_t*) malloc(sizeof(pthread_mutex_t));
    if (!mutex) {
        _log(client, "pim_init - failed to new mutex");
        _free_pim_client(client);
        return NULL;
    }
    client->mutex = mutex;
    if (pthread_mutex_init(client->mutex, NULL) < 0) {
        _log(client, "pim_init - failed to init mutex");
        _free_pim_client(client);
        return NULL;
    }
    OpenSSL_add_ssl_algorithms();
    const SSL_METHOD* meth = TLSv1_2_client_method();
    SSL_load_error_strings();
    client->ssl_context = SSL_CTX_new(meth);
    if (!client->ssl_context) {
        _log(client, "pim_init - SSL_CTX_new failed");
        _free_pim_client(client);
        return NULL;
    }
    return client;
}

int pim_send_ping(pim_client* client) {
    pim_packet ping;
    ping.type = PIM_PACKET_PING;
    ping.body_length = 0;
    return _packet_write(client, &ping, 1);
}

int pim_send_pong(pim_client* client) {
    pim_packet pong;
    pong.type = PIM_PACKET_PONG;
    pong.body_length = 0;
    return _packet_write(client, &pong, 1);
}

void pim_free_msg(pim_message* msg) {
    if (!msg) {
        return;
    }
    if (msg->to) {
        free(msg->to);
    }
    if (msg->from) {
        free(msg->from);
    }
    if (msg->sequence_id) {
        free(msg->sequence_id);
    }
    if (msg->msg_id) {
        free(msg->msg_id);
    }
    if (msg->content) {
        free(msg->content);
    }
    if (msg->extra) {
        free(msg->extra);
    }
    free(msg);
}

pim_message* pim_parse_msg(pim_client* client, pim_packet* packet) {
    pim_message* msg = (pim_message*) malloc(sizeof(pim_message));
    if (!msg) {
        _log(client, "pim_parse_msg - failed to malloc pim_message");
        return NULL;
    }
    bzero(msg, sizeof(pim_message));
    if (!_deserialize_msg(client, packet, msg)) {
        _log(client, "pim_parse_msg - failed to deserialize_msg");
        pim_free_msg(msg);
        return NULL;
    }
    return msg;
}

pim_msg_send_ack* pim_parse_msg_send_ack(pim_client* client, pim_packet* packet) {
    pim_msg_send_ack* ack = (pim_msg_send_ack*) malloc(
                                                       sizeof(pim_msg_send_ack));
    if (!ack) {
        _log(client, "pim_parse_msg - failed to malloc pim_msg_send_ack");
        return NULL;
    }
    bzero(ack, sizeof(pim_msg_send_ack));
    if (!_deserialize_msg_send_ack(client, packet, ack)) {
        _log(client, "pim_parse_msg - failed to deserialize_msg_send_ack");
        pim_free_msg_send_ack(ack);
        return NULL;
    }
    return ack;
}

void pim_free_msg_send_ack(pim_msg_send_ack* ack) {
    if (!ack) {
        return;
    }
    if (ack->sequence_id) {
        free(ack->sequence_id);
    }
    if (ack->msg_id) {
        free(ack->msg_id);
    }
    free(ack);
}

int pim_send_msg_receipt(pim_client* client, char* msg_id) {
    pim_packet ack;
    ack.type = PIM_PACKET_MSG_RECEIPT;
    ack.body = msg_id;
    ack.body_length = (uint32_t) strlen(msg_id);
    return _packet_write(client, &ack, 1);
}

void pim_free_client(pim_client* client) {
    pim_disconnect(client);
    if (client->readthread) {
        pthread_join(client->readthread, NULL);
    }
    _free_pim_client(client);
}
