/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2024 The Fluent Bit Authors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

/*
 * Taken from the in_tcp plugin and modified to add unix domain socket
 * support by Corey Minyard <minyard@mvista.com>.
 */

/*
 * Modified unix domain socket syntex and other function as per Fluent-bit version 3.0
 * Modified by Hitendra Prajapati <hprajapati@mvista.com>.
 */

#ifndef FLB_IN_NET_CONN_H
#define FLB_IN_NET_CONN_H

#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_connection.h>

#define FLB_IN_NET_CHUNK "32768"

enum {
    NET_NEW        = 1,  /* it's a new connection                */
    NET_CONNECTED  = 2,  /* MQTT connection per protocol spec OK */
};

struct net_conn_stream {
    char *tag;
    size_t tag_len;
};

/* Respresents a connection */
struct net_conn {
    int status;                       /* Connection status                 */

    /* Buffer */
    char *buf_data;                   /* Buffer data                       */
    int  buf_len;                     /* Data length                       */
    int  buf_size;                    /* Buffer size                       */
    size_t rest;                      /* Unpacking offset                  */

    struct flb_input_instance *ins;   /* Parent plugin instance            */
    struct flb_in_net_config *ctx;    /* Plugin configuration context      */
    struct flb_pack_state pack_state; /* Internal JSON parser              */
    struct flb_connection *connection;

    struct mk_list _head;
};

struct net_conn *net_conn_add(struct flb_connection *connection, struct flb_in_net_config *ctx);
int net_conn_del(struct net_conn *conn);

#endif
