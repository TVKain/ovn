#ifndef OFCTRL_H
#define OFCTRL_H 1

/*
 * Ofctrl modules define the state machine to process flows
 * ovn-controller uses the IC-Engine but we don't (for now)
 */

#include <stdint.h>

#include "openvswitch/meta-flow.h"
#include "ovsdb-idl.h"
#include "lib/uuidset.h"

struct hmap;
struct match;
struct ofpbuf;

struct ovsrec_bridge;
struct ovsrec_open_vswitch_table;

/* For now the desired flow table will be a hash map with flow match conditions as hash key*/
// struct fw_desired_flow_table
// {
//     struct hmap match_flow_table;
// };
//

/* Compare to fw-controller we don't care about group or meter table (for now)*/
void ofctrl_init(void);

bool ofctrl_run(const struct ovsrec_bridge *br_f, const struct ovsrec_open_vswitch_table *);

void ofctrl_wait(void);
void ofctrl_destroy(void);

void ofctrl_put(struct hmap *);

void ofctrl_add_flow(struct hmap *,
                     uint8_t table_id,
                     uint16_t priority,
                     const struct match *,
                     const struct ofpbuf *ofacts);

void ofctrl_destroy_hmap(struct hmap *);

bool ofctrl_is_connected(void);

#endif