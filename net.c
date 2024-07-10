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

#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_kv.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_engine.h>
#include <fluent-bit/flb_downstream.h>
#include <fluent-bit/flb_utils.h>
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
    struct flb_connection    *connection;
    struct net_conn          *conn;
    struct flb_in_net_config *ctx;

    ctx = in_context;

    connection = flb_downstream_conn_get(ctx->downstream);

    if (connection == NULL) {
        flb_plg_error(ctx->ins, "could not accept new connection");

        return -1;
	}

    flb_plg_info(ctx->ins, "new NET connection arrived FD=%i", connection->fd);

    conn = net_conn_add(connection, ctx);

    if (conn == NULL) {
        flb_plg_error(ctx->ins, "could not accept new connection");

        flb_downstream_conn_release(connection);

        return -1;
    }

	return 0;
}

static int remove_existing_socket_file(char *socket_path)
{
    struct stat file_data;
    int         result;

    result = stat(socket_path, &file_data);

    if (result == -1) {
        if (errno == ENOENT) {
            return 0;
        }

        flb_errno();

        return -1;
    }

    if (S_ISSOCK(file_data.st_mode) == 0) {
        return -2;
    }

    result = unlink(socket_path);

    if (result != 0) {
        return -3;
    }

    return 0;
}

static int net_unix_create(struct flb_in_net_config *ctx)
{
    int ret;

    ret = remove_existing_socket_file(ctx->unix_path);

    if (ret != 0) {
        if (ret == -2) {
            flb_plg_error(ctx->ins,
                          "%s exists and it is not a unix socket. Aborting",
                          ctx->unix_path);
        }
        else {
            flb_plg_error(ctx->ins,
                          "could not remove existing unix socket %s. Aborting",
                          ctx->unix_path);
        }

        return -1;
    }

    ctx->downstream = flb_downstream_create(FLB_TRANSPORT_UNIX_STREAM,
                                            ctx->ins->flags,
                                            ctx->unix_path,
                                            0,
                                            ctx->ins->tls,
                                            ctx->ins->config,
                                            &ctx->ins->net_setup);

    if (ctx->downstream == NULL) {
        return -1;
    }

    if (ctx->unix_perm_str) {
        if (chmod(ctx->unix_path, ctx->unix_perm)) {
            flb_errno();

            flb_plg_error(ctx->ins, "cannot set permission on '%s' to %04o",
                          ctx->unix_path, ctx->unix_perm);

            return -1;
        }
    }

    return 0;
}

/* Initialize plugin */
static int in_net_init(struct flb_input_instance *ins,
                      struct flb_config *config, void *data)
{
    unsigned short int       port;
    int                      ret;
    struct flb_in_net_config *ctx;

    (void) data;

    /* Allocate space for the configuration */
    ctx = net_config_init(ins);
    if (!ctx) {
        return -1;
    }

    ctx->collector_id = -1;
    ctx->ins = ins;
    mk_list_init(&ctx->connections);

    /* Set the context */
    flb_input_set_context(ins, ctx);

    /* Create NET server */
    if (ctx->unix_path) {
        ret = net_unix_create(ctx);
        if (ret != 0) {
            flb_plg_error(ctx->ins, "could not listen on unix://%s",
                          ctx->unix_path);
            net_config_destroy(ctx);
            return -1;
        }
        flb_plg_info(ctx->ins, "listening on unix://%s", ctx->unix_path);
    }
    else {
        port = (unsigned short int) strtoul(ctx->tcp_port, NULL, 10);

        ctx->downstream = flb_downstream_create(FLB_TRANSPORT_TCP,
                                                ctx->ins->flags,
                                                ctx->listen,
                                                port,
                                                ctx->ins->tls,
                                                config,
                                                &ctx->ins->net_setup);

        if (ctx->downstream == NULL) {
            flb_plg_error(ctx->ins,
                          "could not initialize downstream on unix://%s. Aborting",
                          ctx->listen);

            net_config_destroy(ctx);

            return -1;
        }

        if (ctx->downstream != NULL) {
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

    flb_input_downstream_set(ctx->downstream, ctx->ins);

    flb_net_socket_nonblocking(ctx->downstream->server_fd);

    /* Collect upon data available on the standard input */
    ret = flb_input_set_collector_socket(ins,
                                         in_net_collect,
                                         ctx->downstream->server_fd,
                                         config);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "Could not set collector for IN_NET input plugin");
        net_config_destroy(ctx);
        return -1;
    }

    ctx->collector_id = ret;

    return 0;
}

static int in_net_exit(void *data, struct flb_config *config)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_in_net_config *ctx;
    struct net_conn *conn;

	(void) *config;

    ctx = data;

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
    {
      FLB_CONFIG_MAP_STR, "source_address_key", (char *) NULL,
      0, FLB_TRUE, offsetof(struct flb_in_net_config, source_address_key),
      "Key where the source address will be injected"
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
    .flags        = FLB_INPUT_NET_SERVER | FLB_IO_OPT_TLS
};
