/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2022 The Fluent Bit Authors
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

#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_network.h>
#include <msgpack.h>

#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>

#include "net.h"
#include "net_conn.h"
#include "net_config.h"

/*
 * For a server event, the collection event means a new client have arrived, we
 * accept the connection and create a new net instance which will wait for
 * JSON map messages.
 */
static int in_net_collect(struct flb_input_instance *in,
                          struct flb_config *config, void *in_context)
{
    int fd;
    struct flb_in_net_config *ctx = in_context;
    struct net_conn *conn;

    /* Accept the new connection */
    fd = flb_net_accept(ctx->server_fd);
    if (fd == -1) {
        flb_plg_error(ctx->ins, "could not accept new connection");
        return -1;
    }

    flb_plg_trace(ctx->ins, "new NET connection arrived FD=%i", fd);
    conn = net_conn_add(fd, ctx);
    if (!conn) {
        return -1;
    }
    return 0;
}

static int net_unix_create(struct flb_in_net_config *ctx)
{
    flb_sockfd_t fd = -1;
    unsigned long len;
    size_t address_length;
    struct sockaddr_un address;

    fd = flb_net_socket_create(AF_UNIX, FLB_TRUE);
    if (fd == -1) {
        return -1;
    }

    ctx->server_fd = fd;

    /* Prepare the unix socket path */
    unlink(ctx->unix_path);
    len = strlen(ctx->unix_path);

    address.sun_family = AF_UNIX;
    sprintf(address.sun_path, "%s", ctx->unix_path);
    address_length = sizeof(address.sun_family) + len + 1;
    if (bind(fd, (struct sockaddr *) &address, address_length) != 0) {
        flb_errno();
        close(fd);
        return -1;
    }

    if (ctx->unix_perm_str) {
        if (chmod(address.sun_path, ctx->unix_perm)) {
            flb_errno();
            flb_plg_error(ctx->ins, "cannot set permission on '%s' to %04o",
                      address.sun_path, ctx->unix_perm);
            close(fd);
            return -1;
        }
    }

    if (listen(fd, 5) != 0) {
        flb_errno();
        flb_plg_error(ctx->ins, "cannot set listen on '%s'", address.sun_path);
        close(fd);
        return -1;
    }
    return 0;
}

/* Initialize plugin */
static int in_net_init(struct flb_input_instance *in,
                      struct flb_config *config, void *data)
{
    int ret;
    struct flb_in_net_config *ctx;
    (void) data;

    /* Allocate space for the configuration */
    ctx = net_config_init(in);
    if (!ctx) {
        return -1;
    }
    ctx->ins = in;
    mk_list_init(&ctx->connections);

    /* Set the context */
    flb_input_set_context(in, ctx);

    /* Create NET server */
    if (ctx->unix_path) {
        if (net_unix_create(ctx) < 0) {
            net_config_destroy(ctx);
            return -1;
        }
    } else {
        ctx->server_fd = flb_net_server(ctx->tcp_port, ctx->listen);
        if (ctx->server_fd > 0) {
            flb_plg_info(ctx->ins, "listening on %s:%s",
                         ctx->listen, ctx->tcp_port);
        }
        else {
            flb_plg_error(ctx->ins, "could not bind address %s:%s. Aborting",
                          ctx->listen, ctx->tcp_port);
            net_config_destroy(ctx);
            return -1;
        }
    }
    flb_net_socket_nonblocking(ctx->server_fd);

    ctx->evl = config->evl;

    /* Collect upon data available on the standard input */
    ret = flb_input_set_collector_socket(in,
                                         in_net_collect,
                                         ctx->server_fd,
                                         config);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "Could not set collector for IN_NET input plugin");
        net_config_destroy(ctx);
        return -1;
    }

    return 0;
}

static int in_net_exit(void *data, struct flb_config *config)
{
    struct mk_list *tmp;
    struct mk_list *head;
    (void) *config;
    struct flb_in_net_config *ctx = data;
    struct net_conn *conn;

    mk_list_foreach_safe(head, tmp, &ctx->connections) {
        conn = mk_list_entry(head, struct net_conn, _head);
        net_conn_del(conn);
    }

    net_config_destroy(ctx);
    return 0;
}

static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_STR, "format", (char *)NULL,
     0, FLB_TRUE, offsetof(struct flb_in_net_config, format_name),
     "Set the format: json or none"
    },
    {
     FLB_CONFIG_MAP_STR, "unix_path", NULL,
     0, FLB_TRUE, offsetof(struct flb_in_net_config, unix_path),
     "The path to unix socket to receive a Forward message."
    },
    {
     FLB_CONFIG_MAP_STR, "unix_perm", (char *)NULL,
     0, FLB_TRUE, offsetof(struct flb_in_net_config, unix_perm_str),
     "Set the permissions for the UNIX socket"
    },
    {
     FLB_CONFIG_MAP_STR, "separator", (char *)NULL,
     0, FLB_TRUE, offsetof(struct flb_in_net_config, raw_separator),
     "Set separator"
    },
    {
      FLB_CONFIG_MAP_STR, "chunk_size", (char *)NULL,
      0, FLB_TRUE, offsetof(struct flb_in_net_config, chunk_size_str),
      "Set the chunk size"
    },
    {
      FLB_CONFIG_MAP_STR, "buffer_size", (char *)NULL,
      0, FLB_TRUE, offsetof(struct flb_in_net_config, buffer_size_str),
      "Set the buffer size"
    },
    /* EOF */
    {0}
};

/* Plugin reference */
struct flb_input_plugin in_net_plugin = {
    .name         = "net",
    .description  = "NET",
    .cb_init      = in_net_init,
    .cb_pre_run   = NULL,
    .cb_collect   = in_net_collect,
    .cb_flush_buf = NULL,
    .cb_exit      = in_net_exit,
    .config_map   = config_map,
    .flags        = FLB_INPUT_NET,
};
