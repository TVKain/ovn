/* Copyright (c) 2015 Nicira, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef LFLOW_H
#define LFLOW_H 1

/* Logical_Flow table translation to OpenFlow
 * ==========================================
 *
 * The Logical_Flow table obtained from the OVN_Southbound database works in
 * terms of logical entities, that is, logical flows among logical datapaths
 * and logical ports.  This code translates these logical flows into OpenFlow
 * flows that, again, work in terms of logical entities implemented through
 * OpenFlow extensions (e.g. registers represent the logical input and output
 * ports).
 *
 * Physical-to-logical and logical-to-physical translation are implemented in
 * physical.[ch] as separate OpenFlow tables that run before and after,
 * respectively, the logical pipeline OpenFlow tables.
 */

#include <stdint.h>

struct hmap;
struct simap;
struct uuid;

struct ovsdb_idl;

/* OpenFlow table numbers.
 *
 */
#define OFTABLE_PHY_TO_LOG 0
#define OFTABLE_ACL_PIPELINE 1
#define OFTABLE_LOG_TO_PHY 2

#define EGRESS_REG 1
#define INGRESS_REG 2

#define START_CT_ZONE 50000

void lflow_init(void);
void lflow_run(const struct ovsdb_idl *fw_idl, struct hmap *flow_table);
void lflow_destroy(void);

#endif
