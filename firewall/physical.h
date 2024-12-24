#ifndef PHYSICAL_H
#define PHYSICAL_H 1

/*
 * The controlled OVS bridge for this setup should look like this
 *
 *        Ingress Port
 *              |
 *              |
 * -------------|-------------
 * |                         |
 * |           br-f          |
 * |                         |
 * |------------|-------------
 *              |
 *              |
 *        Egress Port
 * */

/*
 * This module looks into the interface and port record
 * to see if the 2 ingress/egress ports are present
 *
 * A port is "recognized" as an egress port if it has an entry in the external_ids column
 * as "firewall-port": "egress"
 *
 * A port is "recognized" as an ingress port if it has an entry in the external_ids column
 * as "firewall-port": "ingress"
 *
 * If multiple ports are found or no ports are found we'll stop execution of this module
 *
 * If a port is found and it contains 2 interfaces, we'll stop execution of this module
 *
 * If everything goes right the flow hmap will be populated correct flow entries
 *
 * On each iteration it will return the OpenFlow port number associated with the ingress or  * egress port, essentially a map from "string" to "unsigned int"
 */

#include <stdbool.h>

#include "vswitch-idl.h"

#define INGRESS_PORT "ingress"
#define EGRESS_PORT "egress"

struct hmap;
struct ovsdb_idl;
struct ovsrec_bridge;

void physical_init(void);

void physical_register_ovs_idl(struct ovsdb_idl *);
void physical_run(const struct ovsrec_bridge *br_f, struct hmap *flows);

void physical_destroy(void);

#endif