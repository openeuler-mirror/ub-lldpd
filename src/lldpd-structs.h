/* -*- mode: c; c-file-style: "openbsd" -*- */
/*
 * Copyright (c) 2008 Vincent Bernat <bernat@luffy.cx>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef _LLDPD_STRUCTS_H
#define _LLDPD_STRUCTS_H

#if HAVE_CONFIG_H
#  include <config.h>
#endif

#include <sys/types.h>
#include <sys/socket.h>

/* This is not very convenient, but we need net/if.h for IFNAMSIZ and others but
 * we may also need linux/if.h in some modules. And they conflict each others.
 */
#ifdef HOST_OS_LINUX
# include <linux/if.h>
#else
# include <net/if.h>
#endif

#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <sys/queue.h>

#include "compat/compat.h"
#include "marshal.h"
#include "lldp-const.h"

enum {
	LLDPD_AF_UNSPEC = 0,
	LLDPD_AF_IPV4,
	LLDPD_AF_IPV6,
	LLDPD_AF_LAST
};

#define LLDPD_MGMT_MAXADDRSIZE	16 /* sizeof(struct in6_addr) */
union lldpd_address {
	struct in_addr		inet;
	struct in6_addr		inet6;
	u_int8_t		octets[LLDPD_MGMT_MAXADDRSIZE]; /* network byte order! */
};
struct lldpd_mgmt {
	TAILQ_ENTRY(lldpd_mgmt) m_entries;
	int			m_family;
	union lldpd_address	m_addr;
	size_t 			m_addrsize;
	u_int32_t		m_iface;
};
MARSHAL_BEGIN(lldpd_mgmt)
MARSHAL_TQE(lldpd_mgmt, m_entries)
MARSHAL_END(lldpd_mgmt);

struct lldpd_chassis {
	TAILQ_ENTRY(lldpd_chassis) c_entries;
	u_int16_t		 c_refcount; /* Reference count by ports */
	u_int16_t		 c_index;    /* Monotonic index */
	u_int8_t		 c_protocol; /* Protocol used to get this chassis */
	u_int8_t	 	 c_id_subtype;
	char			*c_id;
	int			 c_id_len;
	char			*c_name;
	char			*c_descr;

	u_int16_t		 c_cap_available;
	u_int16_t		 c_cap_enabled;

	TAILQ_HEAD(, lldpd_mgmt) c_mgmt;
};
/* WARNING: any change to this structure should also be reflected into
   `lldpd_copy_chassis()` which is not using marshaling. */
MARSHAL_BEGIN(lldpd_chassis)
MARSHAL_IGNORE(lldpd_chassis, c_entries.tqe_next)
MARSHAL_IGNORE(lldpd_chassis, c_entries.tqe_prev)
MARSHAL_FSTR(lldpd_chassis, c_id, c_id_len)
MARSHAL_STR(lldpd_chassis, c_name)
MARSHAL_STR(lldpd_chassis, c_descr)
MARSHAL_SUBTQ(lldpd_chassis, lldpd_mgmt, c_mgmt)
MARSHAL_END(lldpd_chassis);

struct lldpd_port {
	TAILQ_ENTRY(lldpd_port)	 p_entries;
	struct lldpd_chassis	*p_chassis;    /* Attached chassis */
	time_t			 p_lastchange; /* Time of last change of values */
	time_t			 p_lastupdate; /* Time of last update received */
	time_t			 p_lastremove;	/* Time of last removal of a remote port. Used for local ports only
						 * Used for deciding lldpStatsRemTablesLastChangeTime */
	struct lldpd_frame	*p_lastframe;  /* Frame received during last update */
	u_int8_t		 p_protocol;   /* Protocol used to get this port */
	u_int8_t		 p_hidden_in:1; /* Considered as hidden for reception */
	u_int8_t		 p_hidden_out:1; /* Considered as hidden for emission */
	u_int8_t		 p_disable_rx:1; /* Should RX be disabled for this port? */
	u_int8_t		 p_disable_tx:1; /* Should TX be disabled for this port? */
	/* Important: all fields that should be ignored to check if a port has
	 * been changed should be before this mark. */
#define LLDPD_PORT_START_MARKER (offsetof(struct lldpd_port, _p_hardware_flags))
	int			 _p_hardware_flags; /* This is a copy of hardware flags. Do not use it! */
	u_int8_t		 p_id_subtype;
	char			*p_id;
	int			 p_id_len;
	char			*p_descr;
	int			 p_descr_force; /* Description has been forced by user */
	u_int16_t		 p_mfs;
	u_int16_t		 p_ttl; /* TTL for remote port */

};
MARSHAL_BEGIN(lldpd_port)
MARSHAL_TQE(lldpd_port, p_entries)
MARSHAL_POINTER(lldpd_port, lldpd_chassis, p_chassis)
MARSHAL_IGNORE(lldpd_port, p_lastframe)
MARSHAL_FSTR(lldpd_port, p_id, p_id_len)
MARSHAL_STR(lldpd_port, p_descr)
MARSHAL_END(lldpd_port);

/* Used to modify some port related settings */
#define LLDPD_RXTX_UNCHANGED 0
#define LLDPD_RXTX_TXONLY 1
#define LLDPD_RXTX_RXONLY 2
#define LLDPD_RXTX_DISABLED 3
#define LLDPD_RXTX_BOTH 4
#define LLDPD_RXTX_FROM_PORT(p) (((p)->p_disable_rx && (p)->p_disable_tx)?LLDPD_RXTX_DISABLED: \
	    ((p)->p_disable_rx && !(p)->p_disable_tx)?LLDPD_RXTX_TXONLY:	\
	    (!(p)->p_disable_rx && (p)->p_disable_tx)?LLDPD_RXTX_RXONLY:	\
	    LLDPD_RXTX_BOTH)
#define LLDPD_RXTX_RXENABLED(v) ((v) == LLDPD_RXTX_RXONLY || (v) == LLDPD_RXTX_BOTH)
#define LLDPD_RXTX_TXENABLED(v) ((v) == LLDPD_RXTX_TXONLY || (v) == LLDPD_RXTX_BOTH)
struct lldpd_port_set {
	char *ifname;
	char *local_id;
	char *local_descr;
	int rxtx;
};
MARSHAL_BEGIN(lldpd_port_set)
MARSHAL_STR(lldpd_port_set, ifname)
MARSHAL_STR(lldpd_port_set, local_id)
MARSHAL_STR(lldpd_port_set, local_descr)
MARSHAL_END(lldpd_port_set);

/* Smart mode / Hide mode */
#define SMART_INCOMING_FILTER		(1<<0) /* Incoming filtering enabled */
#define SMART_INCOMING_ONE_PROTO	(1<<1) /* On reception, keep only one proto */
#define SMART_INCOMING_ONE_NEIGH	(1<<2) /* On reception, keep only one neighbor */
#define SMART_OUTGOING_FILTER		(1<<3) /* Outgoing filtering enabled */
#define SMART_OUTGOING_ONE_PROTO	(1<<4) /* On emission, keep only one proto */
#define SMART_OUTGOING_ONE_NEIGH	(1<<5) /* On emission, consider only one neighbor */
#define SMART_INCOMING (SMART_INCOMING_FILTER |    \
			 SMART_INCOMING_ONE_PROTO | \
			 SMART_INCOMING_ONE_NEIGH)
#define SMART_OUTGOING (SMART_OUTGOING_FILTER |		\
			SMART_OUTGOING_ONE_PROTO |	\
			SMART_OUTGOING_ONE_NEIGH)

struct lldpd_config {
	int c_paused;	        /* lldpd is paused */
	int c_tx_interval;	/* Transmit interval (in ms) */
	int c_ttl;		/* TTL */
	int c_smart;		/* Bitmask for smart configuration (see SMART_*) */
	int c_receiveonly;	/* Receive only mode */
	int c_max_neighbors;	/* Maximum number of neighbors (per protocol) */

	char *c_mgmt_pattern;	/* Pattern to match a management address */
	char *c_cid_pattern;	/* Pattern to match interfaces to use for chassis ID */
	char *c_cid_string;     /* User defined string for chassis ID */
	char *c_iface_pattern;	/* Pattern to match interfaces to use */
	char *c_perm_ifaces;	/* Pattern to match interfaces to keep */

	char *c_platform;	/* Override platform description (for CDP) */
	char *c_description;	/* Override chassis description */
	char *c_hostname;	/* Override system name */
	int c_advertise_version; /* Should the precise version be advertised? */
	int c_set_ifdescr;	 /* Set interface description */
	int c_promisc;		 /* Interfaces should be in promiscuous mode */
	int c_cap_advertise;	 /* Chassis capabilities advertisement */
	int c_mgmt_advertise;	 /* Management addresses advertisement */

	int c_tx_hold;		/* Transmit hold */
	int c_lldp_portid_type; /* The PortID type */
};
MARSHAL_BEGIN(lldpd_config)
MARSHAL_STR(lldpd_config, c_mgmt_pattern)
MARSHAL_STR(lldpd_config, c_cid_pattern)
MARSHAL_STR(lldpd_config, c_cid_string)
MARSHAL_STR(lldpd_config, c_iface_pattern)
MARSHAL_STR(lldpd_config, c_perm_ifaces)
MARSHAL_STR(lldpd_config, c_hostname)
MARSHAL_STR(lldpd_config, c_platform)
MARSHAL_STR(lldpd_config, c_description)
MARSHAL_END(lldpd_config);

struct lldpd_frame {
	int size;
	unsigned char frame[1];
};

struct lldpd_hardware;
struct lldpd;
struct lldpd_ops {
	int(*send)(struct lldpd *,
		   struct lldpd_hardware*,
		   char *, size_t); /* Function to send a frame */
	int(*recv)(struct lldpd *,
		   struct lldpd_hardware*,
		   int, char *, size_t); /* Function to receive a frame */
	int(*cleanup)(struct lldpd *, struct lldpd_hardware *); /* Cleanup function. */
};

/* An interface is uniquely identified by h_ifindex, h_ifname and h_ops. This
 * means if an interface becomes enslaved, it will be considered as a new
 * interface. The same applies for renaming and we include the index in case of
 * renaming to an existing interface. */
struct lldpd_hardware {
	TAILQ_ENTRY(lldpd_hardware)	 h_entries;

	struct lldpd		*h_cfg;	    /* Pointer to main configuration */
	void			*h_recv;    /* FD for reception */
	int			 h_sendfd;  /* FD for sending, only used by h_ops */
	struct lldpd_ops	*h_ops;	    /* Hardware-dependent functions */
	void			*h_data;    /* Hardware-dependent data */
	void			*h_timer;   /* Timer for this port */

	int			 h_mtu;
	int			 h_flags; /* Packets will be sent only
					     if IFF_RUNNING. Will be
					     removed if this is left
					     to 0. */
	int			 h_ifindex; /* Interface index, used by SNMP */
	char			 h_ifname[IFNAMSIZ]; /* Should be unique */
	u_int8_t		 h_lladdr[ETHER_ADDR_LEN];

	u_int64_t		 h_tx_cnt;
	u_int64_t		 h_rx_cnt;
	u_int64_t		 h_rx_discarded_cnt;
	u_int64_t		 h_rx_unrecognized_cnt;
	u_int64_t		 h_ageout_cnt;
	u_int64_t		 h_insert_cnt;
	u_int64_t		 h_delete_cnt;
	u_int64_t		 h_drop_cnt;

	/* Previous values of different stuff. */
	/* Backup of the previous local port. Used to check if there was a
	 * change to send an immediate update. All those are not marshalled to
	 * the client. */
	void			*h_lport_previous;
	ssize_t			 h_lport_previous_len;
	/* Backup of the previous chassis ID. Used to check if there was a
	 * change and send an LLDP shutdown. */
	u_int8_t	 	 h_lchassis_previous_id_subtype;
	char			*h_lchassis_previous_id;
	int			 h_lchassis_previous_id_len;
	/* Backup of the previous port ID. Used to check if there was a change
	 * and send an LLDP shutdown. */
	u_int8_t		 h_lport_previous_id_subtype;
	char			*h_lport_previous_id;
	int			 h_lport_previous_id_len;

	struct lldpd_port	 h_lport;  /* Port attached to this hardware port */
	TAILQ_HEAD(, lldpd_port) h_rports; /* Remote ports */
};
MARSHAL_BEGIN(lldpd_hardware)
MARSHAL_IGNORE(lldpd_hardware, h_entries.tqe_next)
MARSHAL_IGNORE(lldpd_hardware, h_entries.tqe_prev)
MARSHAL_IGNORE(lldpd_hardware, h_ops)
MARSHAL_IGNORE(lldpd_hardware, h_data)
MARSHAL_IGNORE(lldpd_hardware, h_cfg)
MARSHAL_IGNORE(lldpd_hardware, h_lport_previous)
MARSHAL_IGNORE(lldpd_hardware, h_lport_previous_len)
MARSHAL_IGNORE(lldpd_hardware, h_lchassis_previous_id_subtype)
MARSHAL_IGNORE(lldpd_hardware, h_lchassis_previous_id)
MARSHAL_IGNORE(lldpd_hardware, h_lchassis_previous_id_len)
MARSHAL_IGNORE(lldpd_hardware, h_lport_previous_id_subtype)
MARSHAL_IGNORE(lldpd_hardware, h_lport_previous_id)
MARSHAL_IGNORE(lldpd_hardware, h_lport_previous_id_len)
MARSHAL_SUBSTRUCT(lldpd_hardware, lldpd_port, h_lport)
MARSHAL_SUBTQ(lldpd_hardware, lldpd_port, h_rports)
MARSHAL_END(lldpd_hardware);

struct lldpd_interface {
	TAILQ_ENTRY(lldpd_interface) next;
	char			*name;
};
MARSHAL_BEGIN(lldpd_interface)
MARSHAL_TQE(lldpd_interface, next)
MARSHAL_STR(lldpd_interface, name)
MARSHAL_END(lldpd_interface);
TAILQ_HEAD(lldpd_interface_list, lldpd_interface);
MARSHAL_TQ(lldpd_interface_list, lldpd_interface);

struct lldpd_neighbor_change {
	char *ifname;
#define NEIGHBOR_CHANGE_DELETED -1
#define NEIGHBOR_CHANGE_ADDED    1
#define NEIGHBOR_CHANGE_UPDATED  0
	int state;
	struct lldpd_port *neighbor;
};
MARSHAL_BEGIN(lldpd_neighbor_change)
MARSHAL_STR(lldpd_neighbor_change, ifname)
MARSHAL_POINTER(lldpd_neighbor_change, lldpd_port, neighbor)
MARSHAL_END(lldpd_neighbor_change);

/* Cleanup functions */
void	 lldpd_chassis_mgmt_cleanup(struct lldpd_chassis *);
void	 lldpd_chassis_cleanup(struct lldpd_chassis *, int);
void	 lldpd_remote_cleanup(struct lldpd_hardware *,
    void(*expire)(struct lldpd_hardware *, struct lldpd_port *),
    int);
void	 lldpd_port_cleanup(struct lldpd_port *, int);
void	 lldpd_config_cleanup(struct lldpd_config *);

#endif
