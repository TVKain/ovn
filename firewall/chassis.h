#ifndef CHASSIS_H
#define CHASSIS_H 1

/* For now this module is only used to get the system-id from Open vSwitch local database*/

#include "vswitch-idl.h"
#include "ovsdb-idl.h"

extern char *cli_system_id;
extern char *file_system_id;

void chassis_register_ovs_idl(struct ovsdb_idl *);
const char *get_ovs_chassis_id(const struct ovsrec_open_vswitch_table *);

#endif