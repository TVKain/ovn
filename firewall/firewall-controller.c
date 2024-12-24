#include "firewall-controller.h"

#include <config.h>
#include <stdint.h>
#include <stdbool.h>
#include <getopt.h>

#include "chassis.h"
#include "ofctrl.h"
#include "physical.h"
#include "lflow.h"

#include "command-line.h"
#include "stream.h"
#include "dirs.h"
#include "daemon.h"
#include "fatal-signal.h"
#include "unixctl.h"

#include "lib/ovn-util.h"
#include "lib/ovn-dirs.h"

#include "vswitch-idl.h"
#include "ovsdb-idl.h"
#include "lib/firewall-idl.h"

#include "openvswitch/poll-loop.h" // poll_block
#include "openvswitch/vlog.h"      // VLOG...

#include "openvswitch/hmap.h"

VLOG_DEFINE_THIS_MODULE(main);

#define DEFAULT_BRIDGE_NAME "br-f"
#define DEFAULT_DATAPATH "system"

/* Bridge related functions */
static const struct ovsrec_bridge *
get_br_f(const struct ovsrec_bridge_table *bridge_table,
         const struct ovsrec_open_vswitch_table *ovs_table);

static void
process_br_f(struct ovsdb_idl_txn *ovs_idl_txn,
             const struct ovsrec_bridge_table *bridge_table,
             const struct ovsrec_open_vswitch_table *ovs_table,
             const struct ovsrec_bridge **br_f_,
             const struct ovsrec_datapath **br_f_dp);

static const char *
br_f_name(const struct ovsrec_open_vswitch_table *ovs_table);

static const struct ovsrec_bridge *
create_br_f(struct ovsdb_idl_txn *ovs_idl_txn,
            const struct ovsrec_open_vswitch_table *ovs_table);

/* Datpath related functions */

static const struct ovsrec_datapath *
get_br_datapath(const struct ovsrec_open_vswitch *cfg,
                const char *datapath_type);

static const struct ovsrec_datapath *
create_br_datapath(struct ovsdb_idl_txn *ovs_idl_txn,
                   const struct ovsrec_open_vswitch *cfg,
                   const char *datapath_type);

static void
ctrl_register_ovs_idl(struct ovsdb_idl *ovs_idl);

/* Database related functions */
static void update_fw_db(struct ovsdb_idl *ovs_idl, struct ovsdb_idl *fw_idl)
{
    const struct ovsrec_open_vswitch *cfg = ovsrec_open_vswitch_first(ovs_idl);
    if (!cfg)
    {
        return;
    }
    /* Set remote based on user configuration. */
    const struct ovsrec_open_vswitch_table *ovs_table =
        ovsrec_open_vswitch_table_get(ovs_idl);
    const char *chassis_id = get_ovs_chassis_id(ovs_table);
    const char *remote =
        get_chassis_external_id_value(
            &cfg->external_ids, chassis_id, "fw-remote", NULL);
    ovsdb_idl_set_remote(fw_idl, remote, true);

    /* Set probe interval, based on user configuration and the remote. */
    int interval =
        get_chassis_external_id_value_int(
            &cfg->external_ids, chassis_id, "fw-remote-probe-interval", -1);

    VLOG_INFO("interval: %d", interval);

    set_idl_probe_interval(fw_idl, remote, 0);
}

/* CLIs related functions */

static char *
parse_options(int argc, char *argv[]);

static void
usage(void);

/* System related functions */

static char *get_file_system_id(void);
static void
remove_newline(char *s);

static void
remove_newline(char *s)
{
    char *last = &s[strlen(s) - 1];
    switch (*last)
    {
    case '\n':
    case '\r':
        *last = '\0';
    default:
        return;
    }
}

static char *get_file_system_id(void)
{
    char *ret = NULL;
    char *filename = xasprintf("%s/system-id-override", ovn_sysconfdir());
    errno = 0;
    FILE *f = fopen(filename, "r");
    if (f)
    {
        char system_id[64];
        if (fgets(system_id, sizeof system_id, f))
        {
            remove_newline(system_id);
            ret = xstrdup(system_id);
        }
        fclose(f);
    }
    free(filename);
    return ret;
}
int main(int argc, char *argv[])
{
    struct unixctl_server *unixctl;
    struct ovn_exit_args exit_args = {0};
    int retval;
    file_system_id = get_file_system_id();
    ovs_cmdl_proctitle_init(argc, argv);
    ovn_set_program_name(argv[0]);
    service_start(&argc, &argv);

    char *ovs_remote = parse_options(argc, argv);

    fatal_ignore_sigpipe();

    daemonize_start(true, false);

    char *abs_unixctl_path = get_abs_unix_ctl_path(NULL);
    retval = unixctl_server_create(abs_unixctl_path, &unixctl);
    free(abs_unixctl_path);
    if (retval)
    {
        exit(EXIT_FAILURE);
    }
    unixctl_command_register("exit", "", 0, 1, ovn_exit_command_callback,
                             &exit_args);

    daemonize_complete();

    VLOG_INFO("Daemonize complute");

    /* Connect to local OVS OVSDB instance */
    struct ovsdb_idl_loop ovs_idl_loop = OVSDB_IDL_LOOP_INITIALIZER(
        ovsdb_idl_create(ovs_remote, &ovsrec_idl_class, false, true));

    ctrl_register_ovs_idl(ovs_idl_loop.idl);
    physical_register_ovs_idl(ovs_idl_loop.idl);
    ovsdb_idl_get_initial_snapshot(ovs_idl_loop.idl);

    /* Configure connection to firewall database */

    /* We'll monitor everything by default for now */
    struct ovsdb_idl_loop fw_idl_loop = OVSDB_IDL_LOOP_INITIALIZER(
        ovsdb_idl_create_unconnected(&firewall_idl_class, true));

    ovsdb_idl_set_leader_only(fw_idl_loop.idl, false);

    ovsdb_idl_track_add_all(fw_idl_loop.idl);

    /* Init modules e.g ofctrl, chassis,...*/
    ofctrl_init();
    physical_init();
    lflow_init();

    /* Main loop */

    bool exiting = false;
    unsigned int ovs_cond_seqno = UINT_MAX;
    unsigned int fw_cond_seqno = UINT_MAX;

    unsigned int i = 0;
    while (!exiting)
    {
        VLOG_INFO("Iteration %u", i);
        ++i;

        /* Run the ovsdb idl loop to get the transaction for the local ovsdb */
        struct ovsdb_idl_txn *ovs_idl_txn = ovsdb_idl_loop_run(&ovs_idl_loop);
        unsigned int new_ovs_cond_seqno = ovsdb_idl_get_condition_seqno(ovs_idl_loop.idl);

        if (new_ovs_cond_seqno != ovs_cond_seqno)
        {
            if (!new_ovs_cond_seqno)
            {
                VLOG_INFO("OVS IDL reconnected");
            }
            ovs_cond_seqno = new_ovs_cond_seqno;
        }

        update_fw_db(ovs_idl_loop.idl, fw_idl_loop.idl);

        struct ovsdb_idl_txn *fw_idl_txn = ovsdb_idl_loop_run(&fw_idl_loop);
        unsigned int new_fw_cond_seqno = ovsdb_idl_get_condition_seqno(fw_idl_loop.idl);

        if (new_fw_cond_seqno != fw_cond_seqno)
        {
            if (!new_fw_cond_seqno)
            {
                VLOG_INFO("FIREWALL DB IDL reconnected");
            }
            fw_cond_seqno = new_fw_cond_seqno;
        }

        /* Test */
        // ovsdb-client -v transact '["Open_vSwitch", {"op" : "select", "table" : "Interface", "where": [["admin_state", "!=", "down"], ["mtu", "==", 1500]], "columns": ["_uuid"]}]'

        /* Bridge processing */
        const struct ovsrec_bridge_table *bridge_table =
            ovsrec_bridge_table_get(ovs_idl_loop.idl);
        const struct ovsrec_open_vswitch_table *ovs_table =
            ovsrec_open_vswitch_table_get(ovs_idl_loop.idl);
        const struct ovsrec_bridge *br_f = NULL;
        const struct ovsrec_datapath *br_f_dp = NULL;
        process_br_f(ovs_idl_txn, bridge_table, ovs_table, &br_f,
                     ovsrec_server_has_datapath_table(ovs_idl_loop.idl)
                         ? &br_f_dp
                         : NULL);
        /* Handle flow updates with ofctrl, lflow, physical */

        /* Wait for events before moving on to the next iteration */
        if (br_f)
        {
            struct hmap flow_table = HMAP_INITIALIZER(&flow_table);

            const struct firewall_vlan_table *vlan_table =
                firewall_vlan_table_get(fw_idl_loop.idl);

            ofctrl_run(br_f, ovs_table);
            physical_run(br_f, &flow_table);
            lflow_run(fw_idl_loop.idl, &flow_table);

            ofctrl_put(&flow_table);

            ofctrl_destroy_hmap(&flow_table);
        }

        if (!ovsdb_idl_loop_commit_and_wait(&fw_idl_loop))
        {
            VLOG_INFO("FW DB commit failed");
        }

        /* Commit and wait local db */

        int ovs_txn_status = ovsdb_idl_loop_commit_and_wait(&ovs_idl_loop);

        if (!ovs_txn_status)
        {
            /* Failed transaction */
            VLOG_INFO("Transaction failed");
        }
        else if (ovs_txn_status == 1)
        {
            /* Success transaction */
            VLOG_INFO("Transaction success");
        }
        else if (ovs_txn_status == -1)
        {
            /* Commit still in progress */
        }
        else
        {
            OVS_NOT_REACHED();
        }

        if (br_f)
        {
            ofctrl_wait();
        }

        ovsdb_idl_track_clear(ovs_idl_loop.idl);
        ovsdb_idl_track_clear(fw_idl_loop.idl);
    loop_done:
        poll_block();
    }

    ofctrl_destroy();
    physical_destroy();
    lflow_destroy();

    free(ovs_remote);
    free(file_system_id);

    ovsdb_idl_loop_destroy(&ovs_idl_loop);
    ovsdb_idl_loop_destroy(&fw_idl_loop);

    return 0;
}

/* Bridge related functions implementation */
static const char *br_f_name(const struct ovsrec_open_vswitch_table *ovs_table)
{
    const struct ovsrec_open_vswitch *cfg =
        ovsrec_open_vswitch_table_first(ovs_table);
    const char *chassis_id = get_ovs_chassis_id(ovs_table);
    return get_chassis_external_id_value(&cfg->external_ids, chassis_id,
                                         "firewall-bridge", DEFAULT_BRIDGE_NAME);
}

static const struct ovsrec_bridge *
create_br_f(struct ovsdb_idl_txn *ovs_idl_txn,
            const struct ovsrec_open_vswitch_table *ovs_table)
{
    const struct ovsrec_open_vswitch *cfg;
    cfg = ovsrec_open_vswitch_table_first(ovs_table);
    if (!cfg)
    {
        return NULL;
    }
    const char *bridge_name = br_f_name(ovs_table);

    ovsdb_idl_txn_add_comment(ovs_idl_txn,
                              "ovn-controller: creating integration bridge '%s'", bridge_name);

    struct ovsrec_interface *iface;
    iface = ovsrec_interface_insert(ovs_idl_txn);
    ovsrec_interface_set_name(iface, bridge_name);
    ovsrec_interface_set_type(iface, "internal");

    struct ovsrec_port *port;
    port = ovsrec_port_insert(ovs_idl_txn);
    ovsrec_port_set_name(port, bridge_name);
    ovsrec_port_set_interfaces(port, &iface, 1);

    struct ovsrec_bridge *bridge;
    bridge = ovsrec_bridge_insert(ovs_idl_txn);
    ovsrec_bridge_set_name(bridge, bridge_name);
    ovsrec_bridge_set_fail_mode(bridge, "secure");
    ovsrec_bridge_set_ports(bridge, &port, 1);

    struct smap oc = SMAP_INITIALIZER(&oc);
    smap_add(&oc, "disable-in-band", "true");

    /* When a first non-local port is added to the integration bridge, it
     * results in the recalculation of datapath-id by ovs-vswitchd forcing all
     * active connections to the controllers to reconnect.
     *
     * We can avoid the disconnection by setting the 'other_config:hwaddr' for
     * the integration bridge. ovs-vswitchd uses this hwaddr to calculate the
     * datapath-id and it doesn't recalculate the datapath-id later when the
     * first non-local port is added.
     *
     * So generate a random mac and set the 'hwaddr' option in the
     * other_config.
     * */
    struct eth_addr br_hwaddr;
    eth_addr_random(&br_hwaddr);
    char ea_s[ETH_ADDR_STRLEN + 1];
    snprintf(ea_s, sizeof ea_s, ETH_ADDR_FMT,
             ETH_ADDR_ARGS(br_hwaddr));
    smap_add(&oc, "hwaddr", ea_s);

    ovsrec_bridge_set_other_config(bridge, &oc);
    smap_destroy(&oc);

    struct ovsrec_bridge **bridges;
    size_t bytes = sizeof *bridges * cfg->n_bridges;
    bridges = xmalloc(bytes + sizeof *bridges);
    if (cfg->n_bridges)
    {
        memcpy(bridges, cfg->bridges, bytes);
    }
    bridges[cfg->n_bridges] = bridge;
    ovsrec_open_vswitch_verify_bridges(cfg);
    ovsrec_open_vswitch_set_bridges(cfg, bridges, cfg->n_bridges + 1);
    free(bridges);

    return bridge;
}

static void process_br_f(struct ovsdb_idl_txn *ovs_idl_txn,
                         const struct ovsrec_bridge_table *bridge_table,
                         const struct ovsrec_open_vswitch_table *ovs_table,
                         const struct ovsrec_bridge **br_f_,
                         const struct ovsrec_datapath **br_f_dp)
{
    const struct ovsrec_bridge *br_f = get_br_f(bridge_table, ovs_table);

    ovs_assert(br_f_);
    if (ovs_idl_txn)
    {
        if (!br_f)
        {
            br_f = create_br_f(ovs_idl_txn, ovs_table);
        }

        if (br_f)
        {
            const struct ovsrec_open_vswitch *cfg =
                ovsrec_open_vswitch_table_first(ovs_table);
            ovs_assert(cfg);

            /* Propagate "ovn-bridge-datapath-type" from OVS table, if any.
             * Otherwise use the datapath-type set in br-int, if any.
             * Finally, assume "system" datapath if none configured.
             */
            const char *chassis_id = get_ovs_chassis_id(ovs_table);
            const char *datapath_type =
                get_chassis_external_id_value(
                    &cfg->external_ids, chassis_id,
                    "ovn-bridge-datapath-type", NULL);

            if (!datapath_type)
            {
                if (br_f->datapath_type[0])
                {
                    datapath_type = br_f->datapath_type;
                }
                else
                {
                    datapath_type = DEFAULT_DATAPATH;
                }
            }
            if (strcmp(br_f->datapath_type, datapath_type))
            {
                ovsrec_bridge_set_datapath_type(br_f, datapath_type);
            }
            if (!br_f->fail_mode || strcmp(br_f->fail_mode, "secure"))
            {
                ovsrec_bridge_set_fail_mode(br_f, "secure");
                VLOG_WARN("Integration bridge fail-mode changed to 'secure'.");
            }
            if (br_f_dp)
            {
                *br_f_dp = get_br_datapath(cfg, datapath_type);
                if (!(*br_f_dp))
                {
                    *br_f_dp = create_br_datapath(ovs_idl_txn, cfg,
                                                  datapath_type);
                }
            }
        }
    }
    *br_f_ = br_f;
}

static const struct ovsrec_bridge *
get_br_f(const struct ovsrec_bridge_table *bridge_table,
         const struct ovsrec_open_vswitch_table *ovs_table)
{
    const struct ovsrec_open_vswitch *cfg;
    cfg = ovsrec_open_vswitch_table_first(ovs_table);
    if (!cfg)
    {
        return NULL;
    }

    return get_bridge(bridge_table, br_f_name(ovs_table));
}

static void
ctrl_register_ovs_idl(struct ovsdb_idl *ovs_idl)
{
    /* We do not monitor all tables by default, so modules must register
     * their interest explicitly.
     * XXX: when the same column is monitored in different modes by different
     * modules, there is a chance that "track" flag added by
     * ovsdb_idl_track_add_column by one module being overwritten by a
     * following ovsdb_idl_add_column by another module. Before this is fixed
     * in OVSDB IDL, we need to be careful about the order so that the "track"
     * calls are after the "non-track" calls. */
    ovsdb_idl_add_table(ovs_idl, &ovsrec_table_open_vswitch);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_open_vswitch_col_other_config);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_open_vswitch_col_bridges);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_open_vswitch_col_datapaths);
    ovsdb_idl_add_table(ovs_idl, &ovsrec_table_interface);
    ovsdb_idl_add_table(ovs_idl, &ovsrec_table_port);
    ovsdb_idl_add_table(ovs_idl, &ovsrec_table_bridge);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_bridge_col_ports);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_bridge_col_name);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_bridge_col_fail_mode);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_bridge_col_other_config);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_bridge_col_external_ids);
    ovsdb_idl_add_table(ovs_idl, &ovsrec_table_ssl);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_ssl_col_bootstrap_ca_cert);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_ssl_col_ca_cert);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_ssl_col_certificate);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_ssl_col_private_key);
    ovsdb_idl_add_table(ovs_idl, &ovsrec_table_datapath);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_datapath_col_capabilities);
    ovsdb_idl_add_table(ovs_idl, &ovsrec_table_flow_sample_collector_set);
    ovsdb_idl_add_table(ovs_idl, &ovsrec_table_qos);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_qos_col_other_config);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_qos_col_external_ids);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_qos_col_queues);
    ovsdb_idl_add_table(ovs_idl, &ovsrec_table_queue);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_queue_col_other_config);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_queue_col_external_ids);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_interface_col_link_state);

    chassis_register_ovs_idl(ovs_idl);
    //    encaps_register_ovs_idl(ovs_idl);
    //    binding_register_ovs_idl(ovs_idl);
    //    bfd_register_ovs_idl(ovs_idl);
    //    physical_register_ovs_idl(ovs_idl);
    //    vif_plug_register_ovs_idl(ovs_idl);
    ovsdb_idl_track_add_column(ovs_idl, &ovsrec_open_vswitch_col_external_ids);
    ovsdb_idl_track_add_column(ovs_idl, &ovsrec_interface_col_name);
    ovsdb_idl_track_add_column(ovs_idl, &ovsrec_interface_col_bfd);
    ovsdb_idl_track_add_column(ovs_idl, &ovsrec_interface_col_bfd_status);
    ovsdb_idl_track_add_column(ovs_idl, &ovsrec_interface_col_mtu);
    ovsdb_idl_track_add_column(ovs_idl, &ovsrec_interface_col_type);
    ovsdb_idl_track_add_column(ovs_idl, &ovsrec_interface_col_options);
    ovsdb_idl_track_add_column(ovs_idl, &ovsrec_interface_col_ofport);
    ovsdb_idl_track_add_column(ovs_idl, &ovsrec_interface_col_external_ids);
    ovsdb_idl_track_add_column(ovs_idl, &ovsrec_port_col_name);
    ovsdb_idl_track_add_column(ovs_idl, &ovsrec_port_col_interfaces);
    ovsdb_idl_track_add_column(ovs_idl, &ovsrec_port_col_external_ids);
    ovsdb_idl_track_add_column(ovs_idl,
                               &ovsrec_flow_sample_collector_set_col_bridge);
    ovsdb_idl_track_add_column(ovs_idl,
                               &ovsrec_flow_sample_collector_set_col_id);
    // mirror_register_ovs_idl(ovs_idl);
    /* XXX: There is a potential bug in CT zone I-P node,
     * the fact that we have to call recompute for the change of
     * OVS.bridge.external_ids be reflected. Currently, we don't
     * track that column which should be addressed in the future. */
}

/* datapath related functions implementation */
static const struct ovsrec_datapath *
get_br_datapath(const struct ovsrec_open_vswitch *cfg,
                const char *datapath_type)
{
    for (size_t i = 0; i < cfg->n_datapaths; i++)
    {
        if (!strcmp(cfg->key_datapaths[i], datapath_type))
        {
            return cfg->value_datapaths[i];
        }
    }
    return NULL;
}

static const struct ovsrec_datapath *
create_br_datapath(struct ovsdb_idl_txn *ovs_idl_txn,
                   const struct ovsrec_open_vswitch *cfg,
                   const char *datapath_type)
{
    ovsdb_idl_txn_add_comment(ovs_idl_txn,
                              "firewall: creating bridge datapath '%s'",
                              datapath_type);

    struct ovsrec_datapath *dp = ovsrec_datapath_insert(ovs_idl_txn);
    ovsrec_open_vswitch_verify_datapaths(cfg);
    ovsrec_open_vswitch_update_datapaths_setkey(cfg, datapath_type, dp);
    return dp;
}

static char *
parse_options(int argc, char *argv[])
{
    enum
    {
        VLOG_OPTION_ENUMS,
        OVN_DAEMON_OPTION_ENUMS,
    };

    static struct option long_options[] = {
        {"help", no_argument, NULL, 'h'},
        {"version", no_argument, NULL, 'V'},
        VLOG_LONG_OPTIONS,
        OVN_DAEMON_LONG_OPTIONS,
        {NULL, 0, NULL, 0}};
    char *short_options = ovs_cmdl_long_options_to_short_options(long_options);

    for (;;)
    {
        int c;

        c = getopt_long(argc, argv, short_options, long_options, NULL);
        if (c == -1)
        {
            break;
        }

        switch (c)
        {
        case 'h':
            usage();
        case 'V':
            ovs_print_version(OFP15_VERSION, OFP15_VERSION);
            exit(EXIT_SUCCESS);

            OVN_DAEMON_OPTION_HANDLERS
            VLOG_OPTION_HANDLERS
        case '?':
            exit(EXIT_FAILURE);
        default:
            abort();
        }
    }
    free(short_options);

    argc -= optind;
    argv += optind;

    char *ovs_remote;
    if (argc == 0)
    {
        ovs_remote = xasprintf("unix:%s/db.sock", ovs_rundir());
    }
    else if (argc == 1)
    {
        ovs_remote = xstrdup(argv[0]);
    }
    else
    {
        VLOG_FATAL("exactly zero or one non-option argument required; "
                   "use --help for usage");
    }
    return ovs_remote;
}

static void
usage(void)
{
    printf("%s: Firewall controller\n"
           "usage %s [OPTIONS] [OVS-DATABASE]\n"
           "where OVS-DATABASE is a socket on which the OVS OVSDB server is listening.\n",
           program_name, program_name);
    stream_usage("OVS-DATABASE", true, false, true);
    daemon_usage();
    vlog_usage();
    printf("\nOther options:\n"
           "  -h, --help              display this help message\n"
           "  -V, --version           display version information\n");
    exit(EXIT_SUCCESS);
}
