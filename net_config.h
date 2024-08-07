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

#ifndef FLB_IN_NET_CONFIG_H
#define FLB_IN_NET_CONFIG_H

#include "net.h"

struct flb_in_net_config *net_config_init(struct flb_input_instance *i_ins);
int net_config_destroy(struct flb_in_net_config *config);

#endif
