#include "ofctrl.h"

#include <config.h>

#include "openflow/openflow.h"       /* ofp_header, */
#include "openvswitch/ofp-msgs.h"    /* ofp_type */
#include "openvswitch/ofp-actions.h" /* ofpact */
#include "openvswitch/ofpbuf.h"      /* ofpbuf */
#include "openvswitch/match.h"       /* match */
#include "openvswitch/ofp-util.h"    /* flow mod*/
#include "openvswitch/ofp-flow.h"
#include "openvswitch/ofp-print.h" /* ofp_to_string */

#include "ovs/lib/socket-util.h" /* DSCP_DEFAULT */
#include "ovs/lib/dirs.h"        /* ovs_rundir */
#include "ovs/lib/util.h"        /* xasprintf */

#include "openvswitch/hmap.h"
#include "openvswitch/rconn.h"          /* swconn */
#include "openvswitch/dynamic-string.h" /* ds */

#include "vswitch-idl.h"

#include "openvswitch/poll-loop.h" /* poll_wait() */
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(ofctrl);

/* An OpenFlow flow. */
struct fw_flow
{
    /* Key. */
    struct hmap_node hmap_node;
    uint8_t table_id;
    uint16_t priority;
    struct minimatch match;

    /* Hash. */
    uint32_t hash;

    /* Data. */
    struct ofpact *ofpacts;
    size_t ofpacts_len;
    uint64_t cookie;
    // uint32_t ctrl_meter_id; /* Meter to be used for controller actions. */
};

/* Flow related functions */
static uint32_t fw_flow_hash(const struct fw_flow *);

static struct fw_flow *fw_flow_lookup(struct hmap *flow_table,
                                      const struct fw_flow *target);

static void fw_flow_log(const struct fw_flow *, const char *action);

static void fw_flow_destroy(struct fw_flow *);

static char *fw_flow_to_string(const struct fw_flow *);

/* Flow table related functions */

static void fw_flow_table_clear(struct hmap *flow_table);

static void fw_flow_table_destroy(struct hmap *flow_table);

/* Queue flow */

static void queue_flow_mod(struct ofputil_flow_mod *fm);

/* OVS bridge related */

static struct rconn *swconn;
static unsigned int seqno;

/* Connection state machine */
/* Compare to ovn we dont need to request tunnel id */
#define STATES           \
    STATE(S_NEW)         \
    STATE(S_CLEAR_FLOWS) \
    STATE(S_UPDATE_FLOWS)
enum ofctrl_state
{
#define STATE(NAME) NAME,
    STATES
#undef STATE
};

/* Current state */
static enum ofctrl_state state;

/* Transaction IDs for messages in flight to the switch */
static ovs_be32 xid, xid2;

/* Counter for in-flight OpenFlow messages on 'swconn'.  We only send a new
 * round of flow table modifications to the switch when the counter falls to
 * zero, to avoid unbounded buffering. */
static struct rconn_packet_counter *tx_counter;

/* Flow table of struct fw _flows, that holds the flow table currently installed on the switch */
static struct hmap installed_flows;

/* Indicates if we just went through the S_CLEAR_FLOWS state, which means we
 * need to perform a one time deletion for all the existing flows, groups and
 * meters. This can happen during initialization or OpenFlow reconnection
 * (e.g. after OVS restart). */
static bool ofctrl_initial_clear;

/* installed flow table related functions */

/* Handler for packets received from switch */
static void ofctrl_recv(const struct ofp_header *oh, enum ofptype type);

void ofctrl_init(void)
{
    swconn = rconn_create(0, 0, DSCP_DEFAULT, 1 << OFP15_VERSION);
    tx_counter = rconn_packet_counter_create();
    hmap_init(&installed_flows);
}
/* S_NEW, for a new connection.
 *
 * Move to S_CLEAR_FLOWS state */
static void
run_S_NEW(void)
{
    state = S_CLEAR_FLOWS;
}

static void
recv_S_NEW(const struct ofp_header *oh OVS_UNUSED,
           enum ofptype type OVS_UNUSED)
{
    OVS_NOT_REACHED();
}

/* S_CLEAR_FLOWS
 *
 * Clear all flows then transitions to S_UPDATE_FLOWS.
 */
static void
run_S_CLEAR_FLOWS(void)
{
    /* Set the flag so that the ofctrl_run() can clear the existing flows,
     * groups and meters. We clear them in ofctrl_run() right before the new
     * ones are installed to avoid data plane downtime. */
    ofctrl_initial_clear = true;

    VLOG_DBG("clearing all flows");

    /* Clear installed_flows, to match the state of the switch. */
    fw_flow_table_clear(&installed_flows);

    state = S_UPDATE_FLOWS;
    /* Give a chance for the main loop to call ofctrl_put() in case there were
     * pending flows waiting ofctrl state change to S_UPDATE_FLOWS. */
    poll_immediate_wake();
}

static void
recv_S_CLEAR_FLOWS(const struct ofp_header *oh, enum ofptype type)
{
    ofctrl_recv(oh, type);
}

static void
run_S_UPDATE_FLOWS(void)
{
    /* Nothing to do here :> */
}

static void
recv_S_UPDATE_FLOWS(const struct ofp_header *oh, enum ofptype type)
{
    ofctrl_recv(oh, type);
}
/* Runs the OpenFlow state machine against 'br_f', which is local to the
 * hypervisor on which we are running.
 *
 * Returns 'true' if an OpenFlow reconnect happened; 'false' otherwise.
 */
bool ofctrl_run(const struct ovsrec_bridge *br_f, const struct ovsrec_open_vswitch_table *ovs_table)
{
    bool reconnected = false;

    char *target = xasprintf("unix:%s/%s.mgmt", ovs_rundir(), br_f->name);

    if (strcmp(target, rconn_get_target(swconn)))
    {
        VLOG_INFO("%s: connecting to switch", target);
        rconn_connect(swconn, target, target);
    }
    free(target);

    rconn_run(swconn);

    if (!rconn_is_connected(swconn))
    {
        return reconnected;
    }

    if (seqno != rconn_get_connection_seqno(swconn))
    {
        seqno = rconn_get_connection_seqno(swconn);
        reconnected = true;
        state = S_NEW;
    }

    bool progress = true;
    for (int i = 0; progress && i < 50; i++)
    {
        /* Allow the state machine to run. */
        enum ofctrl_state old_state = state;
        switch (state)
        {
#define STATE(NAME)   \
    case NAME:        \
        run_##NAME(); \
        break;
            STATES
#undef STATE
        default:
            OVS_NOT_REACHED();
        }

        /* Try to process a received packet. */
        struct ofpbuf *msg = rconn_recv(swconn);
        if (msg)
        {
            const struct ofp_header *oh = msg->data;
            enum ofptype type;
            enum ofperr error;

            error = ofptype_decode(&type, oh);
            if (!error)
            {
                switch (state)
                {
#define STATE(NAME)            \
    case NAME:                 \
        recv_##NAME(oh, type); \
        break;
                    STATES
#undef STATE
                default:
                    OVS_NOT_REACHED();
                }
            }
            else
            {
                char *s = ofp_to_string(oh, ntohs(oh->length), NULL, NULL, 1);
                VLOG_WARN("could not decode OpenFlow message (%s): %s",
                          ofperr_to_string(error), s);
                free(s);
            }

            ofpbuf_delete(msg);
        }

        /* If we did some work, plan to go around again. */
        progress = old_state != state || msg;
    }

    if (progress)
    {
        poll_immediate_wake();
    }

    return reconnected;
}

void ofctrl_wait(void)
{
    rconn_run_wait(swconn);
    rconn_recv_wait(swconn);
}

void ofctrl_destroy(void)
{
    rconn_destroy(swconn);
    fw_flow_table_destroy(&installed_flows);
    rconn_packet_counter_destroy(tx_counter);
}

/* Openflow message queue */

static ovs_be32 queue_msg(struct ofpbuf *msg)
{
    const struct ofp_header *oh = msg->data;
    ovs_be32 xid_ = oh->xid;
    rconn_send(swconn, msg, tx_counter);
    return xid_;
}

static void
log_openflow_rl(struct vlog_rate_limit *rl, enum vlog_level level,
                const struct ofp_header *oh, const char *title)
{
    if (!vlog_should_drop(&this_module, level, rl))
    {
        char *s = ofp_to_string(oh, ntohs(oh->length), NULL, NULL, 2);
        vlog(&this_module, level, "%s: %s", title, s);
        free(s);
    }
}

static void
ofctrl_recv(const struct ofp_header *oh, enum ofptype type)
{
    if (type == OFPTYPE_ECHO_REQUEST)
    {
        queue_msg(ofputil_encode_echo_reply(oh));
        VLOG_INFO("Got echo request");
    }
    else if (type == OFPTYPE_ERROR)
    {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(30, 300);
        log_openflow_rl(&rl, VLL_INFO, oh, "OpenFlow error");
        rconn_reconnect(swconn);
    }
    else
    {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(30, 300);
        log_openflow_rl(&rl, VLL_DBG, oh, "OpenFlow packet ignored");
    }
}

/*
 * Only put the flow in the hash map in memory
 * Flow does not get sent down to the switch until ofctrl_put is called
 */
void ofctrl_add_flow(struct hmap *desired_flows,
                     uint8_t table_id,
                     uint16_t priority,
                     const struct match *match,
                     const struct ofpbuf *ofacts)
{
    /* Allocate flow */
    struct fw_flow *f = xmalloc(sizeof *f);
    f->table_id = table_id;
    f->priority = priority;
    minimatch_init(&f->match, match);
    f->ofpacts = xmemdup(ofacts->data, ofacts->size);
    f->ofpacts_len = ofacts->size;
    f->hmap_node.hash = fw_flow_hash(f);

    if (fw_flow_lookup(desired_flows, f))
    {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 5);
        if (!VLOG_DROP_INFO(&rl))
        {
            char *s = fw_flow_to_string(f);
            VLOG_INFO("dropping duplicate flow: %s", s);
            free(s);
        }

        fw_flow_destroy(f);
        return;
    }

    hmap_insert(desired_flows, &f->hmap_node, f->hmap_node.hash);
}

/* fw_flow */

static uint32_t
fw_flow_hash(const struct fw_flow *f)
{
    return hash_2words((f->table_id << 16) | f->priority, minimatch_hash(&f->match, 0));
}

static struct fw_flow *fw_flow_lookup(struct hmap *flow_table,
                                      const struct fw_flow *target)
{
    struct fw_flow *f;

    HMAP_FOR_EACH_WITH_HASH(f, hmap_node, target->hmap_node.hash, flow_table)
    {
        if (f->table_id == target->table_id && f->priority == target->priority && minimatch_equal(&f->match, &target->match))
        {
            return f;
        }
    }
    return NULL;
}

static void fw_flow_destroy(struct fw_flow *fw_flow)
{
    if (fw_flow)
    {
        minimatch_destroy(&fw_flow->match);
        free(fw_flow->ofpacts);
        free(fw_flow);
    }
}

static void fw_flow_log(const struct fw_flow *f, const char *action)
{
    if (VLOG_IS_DBG_ENABLED())
    {
        char *s = fw_flow_to_string(f);
        VLOG_DBG("%s flow: %s", action, s);
        free(s);
    }
}

static char *fw_flow_to_string(const struct fw_flow *f)
{
    struct ds s = DS_EMPTY_INITIALIZER;
    ds_put_format(&s, "table_id=%" PRIu8 ", ", f->table_id);
    ds_put_format(&s, "priority=%" PRIu16 ", ", f->priority);
    minimatch_format(&f->match, NULL, NULL, &s, OFP_DEFAULT_PRIORITY);
    ds_put_cstr(&s, ", actions=");
    struct ofpact_format_params fp = {.s = &s};
    ofpacts_format(f->ofpacts, f->ofpacts_len, &fp);
    return ds_steal_cstr(&s);
}
/* Flow table related functions */

static void fw_flow_table_clear(struct hmap *flow_table)
{
    struct fw_flow *f, *next;
    HMAP_FOR_EACH_SAFE(f, next, hmap_node, flow_table)
    {
        hmap_remove(flow_table, &f->hmap_node);
        fw_flow_destroy(f);
    }
}

static void fw_flow_table_destroy(struct hmap *flow_table)
{
    fw_flow_table_clear(flow_table);
    hmap_destroy(flow_table);
}

/* Flow table update */

static void
queue_flow_mod(struct ofputil_flow_mod *fm)
{
    fm->buffer_id = UINT32_MAX;
    fm->out_port = OFPP_ANY;
    fm->out_group = OFPG_ANY;
    queue_msg(ofputil_encode_flow_mod(fm, OFPUTIL_P_OF15_OXM));
}

void ofctrl_put(struct hmap *flow_table)
{
    if (state != S_UPDATE_FLOWS || rconn_packet_counter_n_packets(tx_counter))
    {
        fw_flow_table_clear(flow_table);
        return;
    }

    if (ofctrl_initial_clear)
    {
        struct ofputil_flow_mod fm = {
            .table_id = OFPTT_ALL,
            .command = OFPFC_DELETE,
        };

        minimatch_init_catchall(&fm.match);

        queue_flow_mod(&fm);

        minimatch_destroy(&fm.match);

        ofctrl_initial_clear = false;
    }

    // ofctrl_dump_flow_table(flow_table);

    struct fw_flow *i, *next;
    HMAP_FOR_EACH_SAFE(i, next, hmap_node, &installed_flows)
    {
        struct fw_flow *d = fw_flow_lookup(flow_table, i);
        if (!d)
        {
            /* Installed flow is no longer desirable.  Delete it from the
             * switch and from installed_flows. */
            struct ofputil_flow_mod fm = {
                .match = i->match,
                .priority = i->priority,
                .table_id = i->table_id,
                .command = OFPFC_DELETE_STRICT,
            };
            queue_flow_mod(&fm);
            fw_flow_log(i, "removing");

            hmap_remove(&installed_flows, &i->hmap_node);
            fw_flow_destroy(i);
        }
        else
        {
            if (!ofpacts_equal(i->ofpacts, i->ofpacts_len,
                               d->ofpacts, d->ofpacts_len))
            {
                /* Update actions in installed flow. */
                struct ofputil_flow_mod fm = {
                    .match = i->match,
                    .priority = i->priority,
                    .table_id = i->table_id,
                    .ofpacts = d->ofpacts,
                    .ofpacts_len = d->ofpacts_len,
                    .command = OFPFC_MODIFY_STRICT,
                };
                queue_flow_mod(&fm);
                fw_flow_log(i, "updating");

                /* Replace 'i''s actions by 'd''s. */
                free(i->ofpacts);
                i->ofpacts = d->ofpacts;
                i->ofpacts_len = d->ofpacts_len;
                d->ofpacts = NULL;
                d->ofpacts_len = 0;
            }

            hmap_remove(flow_table, &d->hmap_node);
            fw_flow_destroy(d);
        }
    }

    /* The previous loop removed from 'flow_table' all of the flows that are
     * already installed.  Thus, any flows remaining in 'flow_table' need to
     * be added to the flow table. */
    struct fw_flow *d;
    HMAP_FOR_EACH_SAFE(d, next, hmap_node, flow_table)
    {
        /* Send flow_mod to add flow. */
        struct ofputil_flow_mod fm = {
            .match = d->match,
            .priority = d->priority,
            .table_id = d->table_id,
            .ofpacts = d->ofpacts,
            .ofpacts_len = d->ofpacts_len,
            .command = OFPFC_ADD,
        };
        queue_flow_mod(&fm);
        fw_flow_log(d, "adding");

        /* Move 'd' from 'flow_table' to installed_flows. */
        hmap_remove(flow_table, &d->hmap_node);
        hmap_insert(&installed_flows, &d->hmap_node, d->hmap_node.hash);
    }
}

/* Desired Flow table related functions */
// void fw_desired_flow_table_init(struct hmap *flow_table)
// {
//     hmap_init(&flow_table->match_flow_table);
// }
//
// void fw_desired_flow_table_clear(struct hmap *flow_table)
// {
//     struct fw_flow *f, *next;
//     HMAP_FOR_EACH_SAFE(f, next, hmap_node, flow_table)
//     {
//         hmap_remove(flow_table, &f->hmap_node);
//         fw_flow_destroy(f);
//     }
//
//     hmap_clear(&flow_table->match_flow_table);
// }
//
// void fw_desired_flow_table_destroy(struct hmap *flow_table)
// {
//     fw_desired_flow_table_clear(flow_table);
//     hmap_destroy(&flow_table->match_flow_table);
// }
//
void ofctrl_dump_flow_table(struct hmap *flow_table)
{
    struct fw_flow *flow;
    struct fw_flow *next;

    VLOG_INFO("The current flow table");

    HMAP_FOR_EACH(flow, hmap_node, flow_table)
    {
        char *flow_string = fw_flow_to_string(flow);

        VLOG_INFO(flow_string);

        free(flow_string);
    }

    VLOG_INFO("End of the flow table");
}

void ofctrl_destroy_hmap(struct hmap *flow_table)
{
    fw_flow_table_destroy(flow_table);
}