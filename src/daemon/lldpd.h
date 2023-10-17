/* -*- mode: c; c-file-style: "openbsd" -*- */
/*
 * Copyright (c) 2023-2023 Hisilicon Limited.
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

#ifndef _LLDPD_H
#define _LLDPD_H

#if HAVE_CONFIG_H
#  include <config.h>
#endif

#ifdef HAVE_VALGRIND_VALGRIND_H
# include <valgrind/valgrind.h>
#else
# define RUNNING_ON_VALGRIND 0
#endif

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <sys/queue.h>
#include <sys/types.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <net/if_arp.h>
#include <sys/un.h>

#include "lldp-tlv.h"

#include "../compat/compat.h"
#include "../marshal.h"
#include "../log.h"
#include "../ctl.h"
#include "../lldpd-structs.h"

/* We don't want to import event2/event.h. We only need those as
   opaque structs. */
struct event;
struct event_base;

#define PROCFS_SYS_NET	"/proc/sys/net/"
#define SYSFS_CLASS_NET "/sys/class/net/"
#define SYSFS_CLASS_DMI "/sys/class/dmi/id/"
#define LLDPD_TX_INTERVAL	30
#define LLDPD_TX_HOLD          4
#define LLDPD_TTL              LLDPD_TX_INTERVAL * LLDPD_TX_HOLD
#define LLDPD_TX_MSGDELAY	1
#define LLDPD_MAX_NEIGHBORS	32
#define LLDPD_FAST_TX_INTERVAL	1
#define LLDPD_FAST_INIT	4

#define USING_AGENTX_SUBAGENT_MODULE 1

#define PROTO_SEND_SIG struct lldpd *, struct lldpd_hardware *
#define PROTO_DECODE_SIG struct lldpd *, char *, int, struct lldpd_hardware *, struct lldpd_chassis **, struct lldpd_port **
#define PROTO_GUESS_SIG char *, int

#define ALIGNED_CAST(TYPE, ATTR) ((TYPE) (void *) (ATTR))

#define LLDP_PROTO 0x109
#define GUID_LEN 16
#define UB_CFG_TYPE 5
#define ARPHRD_UB 38
#define DFX_PLACE_NUM 3
#define DFX_BYTE_NUM 2
#define TLV_INFO_BITS 9
#define IEEE802_1Q_TAG_LEN 4

enum link_header_addr {
	HW_ADDR0 = 0,
	HW_ADDR1,
	HW_ADDR2,
	HW_ADDR3,
	HW_ADDR4,
	HW_ADDR5,
	HW_ADDR6,
	HW_ADDR7,
	HW_ADDR8,
	HW_ADDR9,
	HW_ADDR10,
	HW_ADDR11,
	HW_ADDR12,
	HW_ADDR13,
	HW_ADDR14,
	HW_ADDR15
};

struct ub_link_header {
	u_int8_t ub_cfg;
	u_int16_t ub_protocol;
	u_int8_t ub_dguid[GUID_LEN];
	u_int8_t ub_sguid[GUID_LEN];
} __attribute__((packed));

struct protocol {
	int		 mode;		/* > 0 mode identifier (unique per protocol) */
	int		 enabled;	/* Is this protocol enabled? */
	char		*name;		/* Name of protocol */
	char		 arg;		/* Argument to enable this protocol */
	int(*send)(PROTO_SEND_SIG);	/* How to send a frame */
	int(*decode)(PROTO_DECODE_SIG); /* How to decode a frame */
	int(*guess)(PROTO_GUESS_SIG);   /* Can be NULL, use MAC address in this case */
	u_int8_t	 mac[3][ETHER_ADDR_LEN];  /* Destination MAC addresses used by this protocol */
};

#define SMART_HIDDEN(port) (port->p_hidden_in)

struct lldpd;

/* lldpd.c */
struct lldpd_hardware	*lldpd_get_hardware(struct lldpd *,
    char *, int);
struct interfaces_device *lldpd_get_device(struct lldpd *, const char *);
struct lldpd_hardware	*lldpd_alloc_hardware(struct lldpd *, char *, int);
void	 lldpd_hardware_cleanup(struct lldpd*, struct lldpd_hardware *);
struct lldpd_mgmt *lldpd_alloc_mgmt(int family, void *addr, size_t addrsize, u_int32_t iface);
void	 lldpd_recv(struct lldpd *, struct lldpd_hardware *, int);
void	 lldpd_send(struct lldpd_hardware *);
void	 lldpd_loop(struct lldpd *);
int	 lldpd_main(int, char **, char **);
void	 lldpd_update_localports(struct lldpd *);
void	 lldpd_update_localchassis(struct lldpd *);
void	 lldpd_cleanup(struct lldpd *);
void lldpd_dump_packet(const char *token, const char *packet, int length, struct lldpd_hardware *hardware);

/* frame.c */
u_int16_t frame_checksum(const u_int8_t *, int, int);

/* event.c */
void	 levent_loop(struct lldpd *);
void	 levent_shutdown(struct lldpd *);
void	 levent_hardware_init(struct lldpd_hardware *);
void	 levent_hardware_add_fd(struct lldpd_hardware *, int);
void	 levent_hardware_release(struct lldpd_hardware *);
void	 levent_ctl_notify(char *, int, struct lldpd_port *);
void	 levent_send_now(struct lldpd *);
void	 levent_update_now(struct lldpd *);
int	 levent_iface_subscribe(struct lldpd *, int);
void	 levent_schedule_pdu(struct lldpd_hardware *);
void	 levent_schedule_cleanup(struct lldpd *);
int	 levent_make_socket_nonblocking(int);
int	 levent_make_socket_blocking(int);
#ifdef HOST_OS_LINUX
void	 levent_recv_error(int, const char*);
#endif

/* lldp.c */
int	 lldp_send_shutdown(PROTO_SEND_SIG);
int	 lldp_send(PROTO_SEND_SIG);
int	 lldp_decode(PROTO_DECODE_SIG);

/* client.c */
int
client_handle_client(struct lldpd *cfg,
    ssize_t(*send)(void *, int, void *, size_t),
    void *,
    enum hmsg_type type, void *buffer, size_t n,
    int*);

/* priv.c */
#ifdef ENABLE_PRIVSEP
void	 priv_init(const char*, int, uid_t, gid_t);
#else
void	 priv_init(void);
#endif
void	 priv_wait(void);
void	 priv_ctl_cleanup(const char *ctlname);
char   	*priv_gethostname(void);
#ifdef HOST_OS_LINUX
int    	 priv_open(char*);
void	 asroot_open(void);
#endif
int    	 priv_iface_init(int, char *);
int	 asroot_iface_init_os(int, char *, int *);
int	 priv_iface_description(const char *, const char *);
int	 asroot_iface_description_os(const char *, const char *);
int	 priv_iface_promisc(const char*);
int	 asroot_iface_promisc_os(const char *);

enum priv_cmd {
	PRIV_PING,
	PRIV_DELETE_CTL_SOCKET,
	PRIV_GET_HOSTNAME,
	PRIV_OPEN,
	PRIV_IFACE_INIT,
	PRIV_IFACE_DESCRIPTION,
	PRIV_IFACE_PROMISC,
};

/* priv-seccomp.c */
#if defined USE_SECCOMP && defined ENABLE_PRIVSEP
int priv_seccomp_init(int, int);
#endif

/* privsep_io.c */
enum priv_context {
	PRIV_PRIVILEGED,
	PRIV_UNPRIVILEGED
};
int	 may_read(enum priv_context, void *, size_t);
void	 must_read(enum priv_context, void *, size_t);
void	 must_write(enum priv_context, const void *, size_t);
void	 priv_privileged_fd(int);
void	 priv_unprivileged_fd(int);
int	 priv_fd(enum priv_context);
int	 receive_fd(enum priv_context);
void	 send_fd(enum priv_context, int);

/*BPF filter that carries the UBL2 packet header*/
/*Bit[0:7] of the packet is CFG, and the value is 0x5.*/
/*Bits [8:23] in the packet are protocol, and the value is 0x109.*/

#define UB_LLDPD_FILTER_F                                                             \
      { 0x30, 0, 0, 0x00000000 }, { 0x15, 0, 3, 0x00000005 },                         \
      { 0x28, 0, 0, 0x00000001 }, { 0x15, 0, 1, 0x00000109 },                         \
      { 0x6, 0, 0, 0xffffffff }, { 0x6, 0, 0, 0x00000000 }

/* This function is responsible to refresh information about interfaces. It is
 * OS specific but should be present for each OS. It can use the functions in
 * `interfaces.c` as helper by providing a list of OS-independent interface
 * devices. */
void     interfaces_update(struct lldpd *);

/* interfaces.c */
/* An interface cannot be both physical and (bridge or bond or vlan) */
#define IFACE_PHYSICAL_T    (1 << 0) /* Physical interface */
#define IFACE_BRIDGE_T      (1 << 1) /* Bridge interface */
#define IFACE_BOND_T        (1 << 2) /* Bond interface */
#define IFACE_VLAN_T        (1 << 3) /* VLAN interface */
#define IFACE_WIRELESS_T    (1 << 4) /* Wireless interface */
#define IFACE_BRIDGE_VLAN_T (1 << 5) /* Bridge-aware VLAN interface */

struct interfaces_device {
	TAILQ_ENTRY(interfaces_device) next;
	int   ignore;		/* Ignore this interface */
	int   index;		/* Index */
	char *name;		/* Name */
	char *alias;		/* Alias */
	char *address;		/* MAC address */
	char *driver;		/* Driver */
	int   flags;		/* Flags (IFF_*) */
	int   mtu;		/* MTU */
	int   type;		/* Type (see IFACE_*_T) */
	int dev_type;		/* Device type from driver */
	struct interfaces_device *lower; /* Lower interface (for a VLAN for example) */
	struct interfaces_device *upper; /* Upper interface (for a bridge or a bond) */

	/* The following are OS specific. Should be static (no free function) */
#ifdef HOST_OS_LINUX
	int lower_idx;		/* Index to lower interface */
	int upper_idx;		/* Index to upper interface */
#endif
};
struct interfaces_address {
	TAILQ_ENTRY(interfaces_address) next;
	int index;			 /* Index */
	int flags;			 /* Flags */
	struct sockaddr_storage address; /* Address */

	/* The following are OS specific. */
	/* Nothing yet. */
};
TAILQ_HEAD(interfaces_device_list,  interfaces_device);
TAILQ_HEAD(interfaces_address_list, interfaces_address);
void interfaces_free_device(struct interfaces_device *);
void interfaces_free_address(struct interfaces_address *);
void interfaces_free_devices(struct interfaces_device_list *);
void interfaces_free_addresses(struct interfaces_address_list *);
struct interfaces_device* interfaces_indextointerface(
	struct interfaces_device_list *,
	int);
struct interfaces_device* interfaces_nametointerface(
	struct interfaces_device_list *,
	const char *);

void interfaces_helper_promisc(struct lldpd *,
    struct lldpd_hardware *);
void interfaces_helper_allowlist(struct lldpd *,
    struct interfaces_device_list *);
void interfaces_helper_chassis(struct lldpd *,
    struct interfaces_device_list *);
void interfaces_helper_add_hardware(struct lldpd *,
    struct lldpd_hardware *);
void interfaces_helper_physical(struct lldpd *,
    struct interfaces_device_list *,
    struct lldpd_ops *,
    int(*init)(struct lldpd *, struct lldpd_hardware *));
void interfaces_helper_port_name_desc(struct lldpd *,
    struct lldpd_hardware *,
    struct interfaces_device *);
void interfaces_helper_mgmt(struct lldpd *,
    struct interfaces_address_list *,
    struct interfaces_device_list *);
int interfaces_send_helper(struct lldpd *,
    struct lldpd_hardware *, char *, size_t);
int interfaces_routing_enabled(struct lldpd *);
void interfaces_cleanup(struct lldpd *);

#ifdef HOST_OS_LINUX
/* netlink.c */
struct interfaces_device_list  *netlink_get_interfaces(struct lldpd *);
struct interfaces_address_list *netlink_get_addresses(struct lldpd *);
void netlink_cleanup(struct lldpd *);
struct lldpd_netlink {
	int nl_socket;
	int nl_socket_recv_size;
	/* Cache */
	struct interfaces_device_list *devices;
	struct interfaces_address_list *addresses;
};
#endif

/* pattern.c */
int pattern_match(char *, char *, int);

struct lldpd {
	int			 g_sock;
	struct event_base	*g_base;

	struct lldpd_config	 g_config;

	struct protocol		*g_protocols;
	int			 g_lastrid;
	struct event		*g_main_loop;
	struct event		*g_cleanup_timer;

	/* Unix socket handling */
	const char		*g_ctlname;
	int			 g_ctl;
	struct event		*g_iface_event; /* Triggered when there is an interface change */
	struct event		*g_iface_timer_event; /* Triggered one second after last interface change */
	void(*g_iface_cb)(struct lldpd *);	      /* Called when there is an interface change */

	char			*g_lsb_release;

#ifdef HOST_OS_LINUX
	struct lldpd_netlink	*g_netlink;
#endif

	struct lldpd_port	*g_default_local_port;
#define LOCAL_CHASSIS(cfg) ((struct lldpd_chassis *)(TAILQ_FIRST(&cfg->g_chassis)))
	TAILQ_HEAD(, lldpd_chassis) g_chassis;
	TAILQ_HEAD(, lldpd_hardware) g_hardware;
};

#endif /* _LLDPD_H */
