#include "lflow.h"

#include <config.h>
#include <stdint.h>
#include <stdbool.h>
#include <arpa/inet.h>

#include "ofctrl.h"

#include "firewall/lib/logical-fields.h" /* MFF_OF_FIREWALL */

#include "lib/firewall-idl.h"
#include "ovsdb-idl.h"
#include "openvswitch/ofp-actions.h"
#include "openvswitch/match.h"
#include "openvswitch/hmap.h"
#include "openvswitch/meta-flow.h" /* MFF REG0*/

#include "openvswitch/types.h" /* ovsbe32 */

#include "ovs/lib/packets.h" /* Eth type, IP parse */

#include "openvswitch/vlog.h"

#include "odp-netlink.h" /* ct related */

#define ACL_ARP_PRIORITY 65535
#define ACL_PRIVATE_PRIORITY 65534
#define ACL_BASE_PRIORITY 40000

VLOG_DEFINE_THIS_MODULE(lflow);

static void
put_resubmit(uint8_t table_id, struct ofpbuf *ofpacts);

static void
put_ct(uint8_t table_id, uint16_t zone_id, struct ofpbuf *ofpacts);

static void
put_commit(uint8_t table_id, uint16_t zone_id, struct ofpbuf *ofpacts);

static void
put_drop(struct ofpbuf *ofpacts);

static uint32_t cidr_to_mask(int prefix_length);

static bool translate_acl_rule(const struct firewall_rule *rule, struct match *match, struct ofpbuf *ofpacts);

static void
put_drop(struct ofpbuf *ofpacts)
{
    (void)ofpacts;
}

static uint32_t cidr_to_mask(int prefix_length)
{
    return (0xFFFFFFFFU << (32 - prefix_length)) & 0xFFFFFFFFU;
}

static void
put_commit(uint8_t table_id, uint16_t zone_id, struct ofpbuf *ofpacts)
{
    const size_t ct_offset = ofpacts->size;

    struct ofpact_conntrack *ct = ofpact_put_CT(ofpacts);
    ct->recirc_table = table_id;
    ct->zone_imm = zone_id;
    ct->flags = NX_CT_F_COMMIT;
    ct->alg = 0;

    ct = ofpbuf_at_assert(ofpacts, ct_offset, sizeof *ct);
    ofpacts->header = ct;
    ofpact_finish_CT(ofpacts, &ct);
}

static void
put_ct(uint8_t table_id, uint16_t zone_id, struct ofpbuf *ofpacts)
{
    const size_t ct_offset = ofpacts->size;

    struct ofpact_conntrack *ct = ofpact_put_CT(ofpacts);
    ct->recirc_table = table_id;
    ct->zone_imm = zone_id;
    ct->alg = 0;

    ct = ofpbuf_at_assert(ofpacts, ct_offset, sizeof *ct);
    ofpacts->header = ct;
    ofpact_finish_CT(ofpacts, &ct);
}

static void put_resubmit(uint8_t table_id, struct ofpbuf *ofpacts)
{
    struct ofpact_resubmit *resubmit = ofpact_put_RESUBMIT(ofpacts);
    resubmit->in_port = OFPP_IN_PORT;
    resubmit->table_id = table_id;
}

/* Translate the database rule -> OpenFlow rules -> Insert in the desired flow table */
void lflow_run(const struct ovsdb_idl *fw_idl, struct hmap *flow_table)
{

    struct match arp_match;
    struct ofpbuf arp_ofpacts;
    match_init_catchall(&arp_match);
    ofpbuf_init(&arp_ofpacts, 1);

    /* Table 1, Priority 65535 flow to allow ARP packets */
    match_init_catchall(&arp_match);
    ofpbuf_clear(&arp_ofpacts);
    match_set_dl_type(&arp_match, htons(ETH_TYPE_ARP));
    put_resubmit(OFTABLE_LOG_TO_PHY, &arp_ofpacts);
    ofctrl_add_flow(flow_table, OFTABLE_ACL_PIPELINE, ACL_ARP_PRIORITY, &arp_match, &arp_ofpacts);

    ofpbuf_uninit(&arp_ofpacts);

    const struct firewall_vlan *vlan;

    FIREWALL_VLAN_FOR_EACH(vlan, fw_idl)
    {
        /* Table 1, Priority 100.
         * =========================================================================
         *
         * Priority 100 flow for vlans with disabled acls
         * Match with dl_vlan
         *
         * Just resubmit the packets to the next table without matching for metadata
         * */
        if (!vlan->enable_acl)
        {
            struct match match;
            struct ofpbuf ofpacts;

            match_init_catchall(&match);
            ofpbuf_init(&ofpacts, 1);

            match_set_dl_vlan(&match, htons(vlan->vlan_id), 0);
            put_resubmit(OFTABLE_LOG_TO_PHY, &ofpacts);

            ofctrl_add_flow(flow_table, OFTABLE_ACL_PIPELINE, 100, &match, &ofpacts);
            ofpbuf_uninit(&ofpacts);
        }
        /* Table 1, Priority 40000.
         * =========================================================================
         *
         * Priority 40000 flow for vlans with enabled acls
         * Match with dl_vlan
         *
         * One rule to match with untracked packets to send it through the conntrack
         * module with the appropriate zone
         * One rule to match with tracked +est+trk packets to resubmit to the next
         * */
        else
        {
            /* Priority 32768 rule to match with -est packets */
            struct match match;
            struct ofpbuf ofpacts;

            match_init_catchall(&match);
            ofpbuf_init(&ofpacts, 1);

            match_set_dl_vlan(&match, htons(vlan->vlan_id), 0);
            put_ct(OFTABLE_ACL_PIPELINE, START_CT_ZONE + vlan->vlan_id, &ofpacts);

            uint32_t ct_state = OVS_CS_F_TRACKED;

            match_set_dl_type(&match, htons(ETH_TYPE_IP));
            match_set_ct_state_masked(&match, 0, ct_state);

            ofctrl_add_flow(flow_table, OFTABLE_ACL_PIPELINE, ACL_BASE_PRIORITY, &match, &ofpacts);

            /* Priority 32768 rule to match with +est+trk packets */
            match_init_catchall(&match);
            ofpbuf_clear(&ofpacts);
            match_set_dl_vlan(&match, htons(vlan->vlan_id), 0);

            ct_state = OVS_CS_F_TRACKED | OVS_CS_F_ESTABLISHED;

            match_set_dl_type(&match, htons(ETH_TYPE_IP));

            match_set_ct_state_masked(&match, ct_state, ct_state);

            put_resubmit(OFTABLE_LOG_TO_PHY, &ofpacts);

            ofctrl_add_flow(flow_table, OFTABLE_ACL_PIPELINE, ACL_BASE_PRIORITY, &match, &ofpacts);

            /* 3 Priority 65534 flows to match with private IP packets for each vlan */
            const char *cidr_blocks[] = {
                "10.0.0.0/8",
                "172.16.0.0/16",
                "192.168.0.0/24"};

            for (int i = 0; i < 3; ++i)
            {
                match_init_catchall(&match);
                ofpbuf_clear(&ofpacts);

                match_set_dl_vlan(&match, htons(vlan->vlan_id), 0);
                match_set_reg(&match, MFF_OF_FW_PORT - MFF_REG0, EGRESS_REG);
                match_set_dl_type(&match, htons(ETH_TYPE_IP));

                ovs_be32 ip4;
                unsigned int plen;
                char *error = ip_parse_cidr(cidr_blocks[i], &ip4, &plen);

                if (error)
                {
                }

                match_set_nw_dst_masked(&match, ip4, htonl(cidr_to_mask(plen)));

                put_resubmit(OFTABLE_LOG_TO_PHY, &ofpacts);

                ofctrl_add_flow(flow_table, OFTABLE_ACL_PIPELINE, ACL_PRIVATE_PRIORITY, &match, &ofpacts);
            }

            for (int i = 0; i < 3; ++i)
            {
                match_init_catchall(&match);
                ofpbuf_clear(&ofpacts);

                match_set_dl_vlan(&match, htons(vlan->vlan_id), 0);
                match_set_reg(&match, MFF_OF_FW_PORT - MFF_REG0, INGRESS_REG);
                match_set_dl_type(&match, htons(ETH_TYPE_IP));

                ovs_be32 ip4;
                unsigned int plen;
                char *error = ip_parse_cidr(cidr_blocks[i], &ip4, &plen);

                if (error)
                {
                }

                match_set_nw_src_masked(&match, ip4, htonl(cidr_to_mask(plen)));

                put_resubmit(OFTABLE_LOG_TO_PHY, &ofpacts);

                ofctrl_add_flow(flow_table, OFTABLE_ACL_PIPELINE, ACL_PRIVATE_PRIORITY, &match, &ofpacts);
            }

            ofpbuf_uninit(&ofpacts);
        }
    }

    struct match match;
    struct ofpbuf ofpacts;

    ofpbuf_init(&ofpacts, 1);
    const struct firewall_rule *rule;
    FIREWALL_RULE_FOR_EACH(rule, fw_idl)
    {
        match_init_catchall(&match);
        ofpbuf_clear(&ofpacts);

        if (!rule->vlan->enable_acl)
        {
            continue;
        }

        if (!rule->enabled)
        {
            continue;
        }

        if (!rule->enabled[0])
        {
            continue;
        }

        bool result = translate_acl_rule(rule, &match, &ofpacts);

        if (!result)
        {
            VLOG_WARN("Translate rule %u failed", rule->header_.uuid.parts[0]);
            continue;
        }

        ofctrl_add_flow(flow_table, OFTABLE_ACL_PIPELINE, rule->priority, &match, &ofpacts);
    }

    ofpbuf_uninit(&ofpacts);
}

static bool translate_acl_rule(const struct firewall_rule *rule, struct match *match, struct ofpbuf *ofpacts)
{
    /* Parse direction
     * We'll set the MFF_OF_FW_PORT register to the corresponding value based on the direction
     */
    uint32_t reg_value;

    if (strcmp(rule->direction, "ingress") == 0)
    {
        reg_value = INGRESS_REG;
    }
    else
    {
        reg_value = EGRESS_REG;
    }

    match_set_reg(match, MFF_OF_FW_PORT - MFF_REG0, reg_value);
    /* Add vlan matching */
    match_set_dl_vlan(match, htons(rule->vlan->vlan_id), 0);

    /* Add matching on IPv4 ether type */
    match_set_dl_type(match, htons(ETH_TYPE_IP));

    /* Parse protocol */
    if (strlen(rule->protocol))
    {
        uint8_t nw_proto;

        bool is_any = false;

        if (strcmp(rule->protocol, "tcp") == 0)
        {
            nw_proto = IPPROTO_TCP;
        }
        else if (strcmp(rule->protocol, "udp") == 0)
        {
            nw_proto = IPPROTO_UDP;
        }
        else if (strcmp(rule->protocol, "icmp") == 0)
        {
            nw_proto = IPPROTO_ICMP;
        }
        else if (strcmp(rule->protocol, "any") == 0)
        {
            is_any = true;
        }
        else
        {
            VLOG_WARN("Invalid rule protocol %s", rule->protocol);
            return false;
        }

        if (!is_any)
        {
            match_set_nw_proto(match, nw_proto);
        }
    }

    /* Parse source IP address */
    if (strlen(rule->src_ip))
    {
        ovs_be32 ip4;
        unsigned int plen;
        char *error = ip_parse_cidr(rule->src_ip, &ip4, &plen);

        if (error)
        {
            VLOG_WARN("Invalid source IPv4 address '%s'", rule->src_ip);
            return false;
        }

        match_set_nw_src_masked(match, ip4, htons(cidr_to_mask(plen)));
    }

    /* Parse dest IP address */
    if (strlen(rule->dst_ip))
    {
        ovs_be32 ip4;
        unsigned int plen;
        char *error = ip_parse_cidr(rule->dst_ip, &ip4, &plen);

        if (error)
        {
            VLOG_WARN("Invalid destination IPv4 address '%s'", rule->dst_ip);
            return false;
        }

        match_set_nw_dst_masked(match, ip4, htons(cidr_to_mask(plen)));
    }

    /* Parse dest port */
    if (rule->dst_port)
    {

        if (strcmp(rule->protocol, "udp") != 0 && strcmp(rule->protocol, "tcp") != 0)
        {
            VLOG_WARN("Invalid protocol %s: destination port is specified", rule->protocol);
            return false;
        }

        uint16_t dst_port = rule->dst_port[0];

        match_set_tp_dst(match, htons(dst_port));
    }

    /* Parse source port */
    if (rule->src_port)
    {
        if (strcmp(rule->protocol, "udp") != 0 && strcmp(rule->protocol, "tcp") != 0)
        {
            VLOG_WARN("Invalid protocol %s: source port is specified", rule->protocol);
            return false;
        }
        uint16_t src_port = rule->src_port[0];

        match_set_tp_src(match, htons(src_port));
    }

    /* set match for +new+trk */
    uint32_t ct_state = OVS_CS_F_TRACKED | OVS_CS_F_NEW;

    match_set_ct_state_masked(match, ct_state, ct_state);

    if (strcmp(rule->action, "allow") == 0)
    {
        /* Set action to commit */
        put_commit(OFTABLE_LOG_TO_PHY, START_CT_ZONE + rule->vlan->vlan_id, ofpacts);
    }
    else if (strcmp(rule->action, "deny"))
    {
        put_drop(ofpacts);
    }

    return true;
}

void lflow_init(void)
{
}

void lflow_destroy(void)
{
}
