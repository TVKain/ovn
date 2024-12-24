#include "chassis.h"

#include <config.h>

#include "smap.h"

#include "vswitch-idl.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(chassis);

char *cli_system_id = NULL;
char *file_system_id = NULL;

void chassis_register_ovs_idl(struct ovsdb_idl *ovs_idl)
{
    ovsdb_idl_add_table(ovs_idl, &ovsrec_table_open_vswitch);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_open_vswitch_col_external_ids);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_open_vswitch_col_iface_types);
    ovsdb_idl_add_table(ovs_idl, &ovsrec_table_bridge);
    ovsdb_idl_add_column(ovs_idl, &ovsrec_bridge_col_datapath_type);
}

const char *
get_ovs_chassis_id(const struct ovsrec_open_vswitch_table *ovs_table)
{
    if (cli_system_id)
    {
        return cli_system_id;
    }

    if (file_system_id)
    {
        return file_system_id;
    }

    const struct ovsrec_open_vswitch *cfg = ovsrec_open_vswitch_table_first(ovs_table);
    const char *chassis_id = cfg ? smap_get(&cfg->external_ids, "system-id")
                                 : NULL;

    if (!chassis_id)
    {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
        VLOG_WARN_RL(&rl, "'system-id' in Open_vSwitch database is missing.");
    }

    return chassis_id;
}