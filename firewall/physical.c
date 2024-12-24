#include "physical.h"

#include <config.h>
#include <stdbool.h>
#include <string.h>

#include "vswitch-idl.h"

#include "lflow.h"
#include "ofctrl.h"

#include "openvswitch/match.h"
#include "openvswitch/ofp-actions.h"
#include "openvswitch/vlog.h"

#include "ovs/lib/flow.h" /* u16_to_ofp */
#include "ovs/lib/simap.h"
#include "ovs/lib/byte-order.h" /* htonll */

#include "openvswitch/hmap.h"

#include "firewall/lib/logical-fields.h"

VLOG_DEFINE_THIS_MODULE(physical);

static struct simap port_map = SIMAP_INITIALIZER(&port_map);

static void
put_resubmit(uint8_t table_id, struct ofpbuf *ofpacts);
static void
put_load(uint64_t value, enum mf_field_id dst, int ofs, int n_bits,
         struct ofpbuf *ofpacts);

static uint64_t get_port_register_value(char *type)
{
    if (strcmp(type, INGRESS_PORT) == 0)
    {
        return INGRESS_REG;
    }
    else if (strcmp(type, EGRESS_PORT) == 0)
    {
        return EGRESS_REG;
    }

    return -1;
}

void physical_init(void)
{
}

void physical_register_ovs_idl(struct ovsdb_idl *ovs_idl)
{
    ovsdb_idl_add_table(ovs_idl, &ovsrec_table_bridge);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_bridge_col_ports);

    ovsdb_idl_add_table(ovs_idl, &ovsrec_table_port);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_port_col_name);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_port_col_interfaces);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_port_col_external_ids);

    ovsdb_idl_add_table(ovs_idl, &ovsrec_table_interface);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_interface_col_name);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_interface_col_ofport);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_interface_col_external_ids);
}

void physical_run(const struct ovsrec_bridge *br_f, struct hmap *flows)
{
    simap_clear(&port_map);

    for (int i = 0; i < br_f->n_ports; ++i)
    {
        const struct ovsrec_port *port_rec = br_f->ports[i];

        if (!strcmp(port_rec->name, br_f->name))
        {
            continue;
        }

        const char *of_firewall_port = smap_get(&port_rec->external_ids, "firewall_port");

        if (!of_firewall_port)
        {
            continue;
        }

        if (strcmp(of_firewall_port, EGRESS_PORT) != 0 && strcmp(of_firewall_port, INGRESS_PORT) != 0)
        {
            VLOG_WARN("Invalid key for of_firewall_port '%s'", of_firewall_port);
            continue;
        }

        unsigned int ofp_port = simap_get(&port_map, of_firewall_port);

        if (ofp_port != 0)
        {
            VLOG_WARN("Multiple %s ports found", of_firewall_port);
            return;
        }

        if (port_rec->n_interfaces > 1)
        {
            VLOG_WARN("Port %s contains multiple interfaces", port_rec->name);
            return;
        }

        const struct ovsrec_interface *iface_rec = port_rec->interfaces[0];

        int64_t ofport = *iface_rec->ofport;

        if (ofport == -1)
        {
            VLOG_WARN("Interface %s contains invalid OF number", iface_rec->name);
            continue;
        }

        // Add the port into the map
        simap_put(&port_map, of_firewall_port, ofport);
    }

    unsigned int ofport;

    ofport = simap_get(&port_map, EGRESS_PORT);

    if (ofport == 0)
    {
        VLOG_WARN("Missing egress port");
        return;
    }

    ofport = simap_get(&port_map, INGRESS_PORT);

    if (ofport == 0)
    {
        VLOG_WARN("Missing ingress port");
        return;
    }

    struct match match;
    struct ofpbuf ofpacts;
    ofpbuf_init(&ofpacts, 1);

    /* Table 0, Priority 100.
     * ==============================
     *
     * Priority 100 flow for traffic going into the bridge
     * either from the ingress port or the egress port
     *
     * For traffic going into the bridge from the egress port,
     * set EGRESS_PORT (1) to MFF_PORT register
     *
     * For traffic going into the bridge from the ingress port
     * set INGRESS_PORT (2) to MFF_PORT register
     * */

    struct simap_node *simap_node;

    SIMAP_FOR_EACH(simap_node, &port_map)
    {
        ofpbuf_clear(&ofpacts);
        match_init_catchall(&match);

        ofp_port_t ofport = u16_to_ofp(simap_node->data);

        match_set_in_port(&match, ofport);

        uint64_t reg_value = get_port_register_value(simap_node->name);

        put_load(reg_value, MFF_OF_FW_PORT, 0, 4, &ofpacts);

        put_resubmit(OFTABLE_ACL_PIPELINE, &ofpacts);
        ofctrl_add_flow(flows, OFTABLE_PHY_TO_LOG, 100, &match, &ofpacts);
    }

    /* Table 2, Priority 100.
     * ==============================
     *
     * Priority 100 flow for traffic going out of the bridge
     * either to the ingress port or the egress port
     *
     * For traffic with MFF_PORT register set to 1 output it to the EGRESS PORT
     *
     * For traffic with MFF_PORT register set to 2 output it to the INGRESS PORT
     * */
    match_init_catchall(&match);
    ofpbuf_clear(&ofpacts);

    unsigned int ingress_ofport = simap_get(&port_map, INGRESS_PORT);

    match_set_reg(&match, MFF_OF_FW_PORT - MFF_REG0, EGRESS_REG);
    ofpact_put_OUTPUT(&ofpacts)->port = ingress_ofport;
    ofctrl_add_flow(flows, OFTABLE_LOG_TO_PHY, 100, &match, &ofpacts);

    ofpbuf_clear(&ofpacts);
    match_init_catchall(&match);

    unsigned int egress_ofport = simap_get(&port_map, EGRESS_PORT);

    match_set_reg(&match, MFF_OF_FW_PORT - MFF_REG0, INGRESS_REG);
    ofpact_put_OUTPUT(&ofpacts)->port = egress_ofport;
    ofctrl_add_flow(flows, OFTABLE_LOG_TO_PHY, 100, &match, &ofpacts);

    ofpbuf_uninit(&ofpacts);
}

void physical_destroy(void)
{
    simap_destroy(&port_map);
}

static void
put_resubmit(uint8_t table_id, struct ofpbuf *ofpacts)
{
    struct ofpact_resubmit *resubmit = ofpact_put_RESUBMIT(ofpacts);
    resubmit->in_port = OFPP_IN_PORT;
    resubmit->table_id = table_id;
}

static void
put_load(uint64_t value, enum mf_field_id dst, int ofs, int n_bits,
         struct ofpbuf *ofpacts)
{
    struct ofpact_set_field *sf = ofpact_put_set_field(ofpacts,
                                                       mf_from_id(dst), NULL,
                                                       NULL);
    ovs_be64 n_value = htonll(value);
    bitwise_copy(&n_value, 8, 0, &sf->value, sf->field->n_bytes, ofs, n_bits);
    bitwise_one(ofpact_set_field_mask(sf), sf->field->n_bytes, ofs, n_bits);
}
