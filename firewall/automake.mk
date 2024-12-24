bin_PROGRAMS += firewall/firewall-controller

firewall_firewall_controller_SOURCES = \
	firewall/firewall-controller.c \
	firewall/firewall-controller.h \
	firewall/chassis.h \
	firewall/chassis.c \
	firewall/ofctrl.h \
	firewall/ofctrl.c \
	firewall/physical.h \
	firewall/physical.c \
	firewall/lflow.h \
	firewall/lflow.c \
	firewall/lib/logical-fields.h

firewall_firewall_controller_LDADD = lib/libovn.la $(OVS_LIBDIR)/libopenvswitch.la