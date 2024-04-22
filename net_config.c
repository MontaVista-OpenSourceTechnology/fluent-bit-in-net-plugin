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

/*
 * Taken from the in_tcp plugin and modified to add unix domain socket
 * support by Corey Minyard <minyard@mvista.com>.
 */

#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_unescape.h>

#include "net.h"
#include "net_conn.h"
#include "net_config.h"

#include <stdlib.h>

struct flb_in_net_config *net_config_init(struct flb_input_instance *ins)
{
    int ret;
    int len;
    char port[16];
    char *out;
    const char *p;
    struct flb_in_net_config *ctx;

    /* Allocate plugin context */
    ctx = flb_calloc(1, sizeof(struct flb_in_net_config));
    if (!ctx) {
        flb_errno();
        return NULL;
    }
    ctx->ins = ins;
    ctx->format = FLB_NET_FMT_JSON;
    ctx->server_fd = -1;

    /* Load the config map */
    ret = flb_input_config_map_set(ins, (void *)ctx);
    if (ret == -1) {
        flb_plg_error(ins, "unable to load configuration");
        flb_free(ctx);
        return NULL;
    }

    /* Data format (expected payload) */
    if (ctx->format_name) {
        if (strcasecmp(ctx->format_name, "json") == 0) {
            ctx->format = FLB_NET_FMT_JSON;
        }
        else if (strcasecmp(ctx->format_name, "none") == 0) {
            ctx->format = FLB_NET_FMT_NONE;
        }
        else {
            flb_plg_error(ctx->ins, "unrecognized format value '%s'", ctx->format_name);
            flb_free(ctx);
            return NULL;
        }
    }

    /* String separator used to split records when using 'format none' */
    if (ctx->raw_separator) {
        len = strlen(ctx->raw_separator);
        out = flb_malloc(len + 1);
        if (!out) {
            flb_errno();
            flb_free(ctx);
            return NULL;
        }
        ret = flb_unescape_string(ctx->raw_separator, len, &out);
        if (ret <= 0) {
            flb_plg_error(ctx->ins, "invalid separator");
            flb_free(out);
            flb_free(ctx);
            return NULL;
        }

        ctx->separator = flb_sds_create_len(out, ret);
        if (!ctx->separator) {
            flb_free(out);
            flb_free(ctx);
            return NULL;
        }
        flb_free(out);
    }
    if (!ctx->separator) {
        ctx->separator = flb_sds_create_len("\n", 1);
    }

    p = flb_input_get_property("unix_path", ins);
    if (p == NULL) {
        /* Listen interface (if not set, defaults to 0.0.0.0:5170) */
        flb_input_net_default_listener("0.0.0.0", 5170, ins);
        ctx->listen = ins->host.listen;
        snprintf(port, sizeof(port) - 1, "%d", ins->host.port);
        ctx->tcp_port = flb_strdup(port);
    } else {
        /* Unix socket mode */
        if (ctx->unix_perm_str) {
            ctx->unix_perm = strtol(ctx->unix_perm_str, NULL, 8) & 07777;
        }
    }

    /* Chunk size */
    if (ctx->chunk_size_str) {
        /* Convert KB unit to Bytes */
        ctx->chunk_size  = (atoi(ctx->chunk_size_str) * 1024);
    } else {
        ctx->chunk_size  = atoi(FLB_IN_NET_CHUNK);
    }

    /* Buffer size */
    if (!ctx->buffer_size_str) {
        ctx->buffer_size = ctx->chunk_size;
    }
    else {
        /* Convert KB unit to Bytes */
        ctx->buffer_size  = (atoi(ctx->buffer_size_str) * 1024);
    }

    return ctx;
}

int net_config_destroy(struct flb_in_net_config *ctx)
{
    flb_sds_destroy(ctx->separator);
    if (ctx->server_fd > 0) {
        flb_socket_close(ctx->server_fd);
    }
    if (ctx->unix_path) {
        unlink(ctx->unix_path);
    } else {
        flb_free(ctx->tcp_port);
    }
    flb_free(ctx);

    return 0;
}
