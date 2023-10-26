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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <time.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <string.h>

#include "../log.h"
#include "client.h"

static void
display_cap(struct writer * w, lldpctl_atom_t *chassis, u_int8_t bit, char *symbol)
{
	if (lldpctl_atom_get_int(chassis, lldpctl_k_chassis_cap_available) & bit) {
		tag_start(w, "capability", "Capability");
		tag_attr (w, "type", "", symbol );
		tag_attr (w, "enabled", "",
		    (lldpctl_atom_get_int(chassis, lldpctl_k_chassis_cap_enabled) & bit)?
		    "on":"off");
		tag_end  (w);
	}
}

static void
display_chassis(struct writer* w, lldpctl_atom_t* chassis, int details)
{
	lldpctl_atom_t *mgmts, *mgmt;

	tag_start(w, "chassis", "Chassis");
	tag_start(w, "id", "ChassisID");
	tag_attr (w, "type", "",
	    lldpctl_atom_get_str(chassis,
		lldpctl_k_chassis_id_subtype));
	tag_data(w, lldpctl_atom_get_str(chassis,
		lldpctl_k_chassis_id));
	tag_end(w);
	tag_datatag(w, "name", "SysName",
	    lldpctl_atom_get_str(chassis, lldpctl_k_chassis_name));
	if (details == DISPLAY_BRIEF) {
		tag_end(w);
		return;
	}
	tag_datatag(w, "descr", "SysDescr",
	    lldpctl_atom_get_str(chassis, lldpctl_k_chassis_descr));

	/* Management addresses */
	mgmts = lldpctl_atom_get(chassis, lldpctl_k_chassis_mgmt);
	lldpctl_atom_foreach(mgmts, mgmt) {
		tag_datatag(w, "mgmt-ip", "MgmtIP",
		    lldpctl_atom_get_str(mgmt, lldpctl_k_mgmt_ip));
		if (lldpctl_atom_get_int(mgmt, lldpctl_k_mgmt_iface_index))
			tag_datatag(w, "mgmt-iface", "MgmtIface",
			    lldpctl_atom_get_str(mgmt, lldpctl_k_mgmt_iface_index));
	}
	lldpctl_atom_dec_ref(mgmts);

	/* Capabilities */
	display_cap(w, chassis, LLDP_CAP_OTHER, "Other");
	display_cap(w, chassis, LLDP_CAP_REPEATER, "Repeater");
	display_cap(w, chassis, LLDP_CAP_BRIDGE, "Bridge");
	display_cap(w, chassis, LLDP_CAP_ROUTER, "Router");
	display_cap(w, chassis, LLDP_CAP_WLAN, "Wlan");
	display_cap(w, chassis, LLDP_CAP_TELEPHONE, "Tel");
	display_cap(w, chassis, LLDP_CAP_DOCSIS, "Docsis");
	display_cap(w, chassis, LLDP_CAP_STATION, "Station");

	tag_end(w);
}

static void
display_port(struct writer *w, lldpctl_atom_t *port, int details)
{
	tag_start(w, "port", "Port");
	tag_start(w, "id", "PortID");
	tag_attr (w, "type", "",
	    lldpctl_atom_get_str(port, lldpctl_k_port_id_subtype));
	tag_data(w, lldpctl_atom_get_str(port, lldpctl_k_port_id));
	tag_end(w);

	tag_datatag(w, "descr", "PortDescr",
	    lldpctl_atom_get_str(port, lldpctl_k_port_descr));

	if (details &&
	    lldpctl_atom_get_int(port, lldpctl_k_port_ttl) > 0)
		tag_datatag(w, "ttl", "TTL",
		    lldpctl_atom_get_str(port, lldpctl_k_port_ttl));

	tag_end(w);
}

static void
display_local_ttl(struct writer *w, lldpctl_conn_t *conn, int details)
{
	char *ttl;
	long int tx_hold;
	long int tx_interval;

	lldpctl_atom_t *configuration;
	configuration = lldpctl_get_configuration(conn);
	if (!configuration) {
		log_warnx("ub-lldpctl", "not able to get configuration. %s",
		    lldpctl_last_strerror(conn));
		return;
	}

	tx_hold = lldpctl_atom_get_int(configuration, lldpctl_k_config_tx_hold);
	tx_interval = lldpctl_atom_get_int(configuration, lldpctl_k_config_tx_interval_ms);

	tx_interval = (tx_interval * tx_hold + 999) / 1000;

	if (asprintf(&ttl, "%lu", tx_interval) == -1) {
		log_warnx("ub-lldpctl", "not enough memory to build TTL.");
		goto end;
	}

	tag_start(w, "ttl", "TTL");
	tag_attr(w, "ttl", "", ttl);
	tag_end(w);
	free(ttl);
end:
	lldpctl_atom_dec_ref(configuration);
}

static void
display_ppvids(struct writer *w, lldpctl_atom_t *port)
{
	lldpctl_atom_t *ppvids, *ppvid;
	ppvids = lldpctl_atom_get(port, lldpctl_k_port_ppvids);
	lldpctl_atom_foreach(ppvids, ppvid) {
		int status = lldpctl_atom_get_int(ppvid,
		    lldpctl_k_ppvid_status);
		tag_start(w, "ppvid", "PPVID");
		if (lldpctl_atom_get_int(ppvid,
			lldpctl_k_ppvid_id) > 0)
			tag_attr(w, "value", "",
			    lldpctl_atom_get_str(ppvid,
				lldpctl_k_ppvid_id));
		tag_attr(w, "supported", "supported",
			 (status & LLDP_PPVID_CAP_SUPPORTED)?"yes":"no");
		tag_attr(w, "enabled", "enabled",
			 (status & LLDP_PPVID_CAP_ENABLED)?"yes":"no");
		tag_end(w);
	}
	lldpctl_atom_dec_ref(ppvids);
}

static void
display_pids(struct writer *w, lldpctl_atom_t *port)
{
	lldpctl_atom_t *pids, *pid;
	pids = lldpctl_atom_get(port, lldpctl_k_port_pis);
	lldpctl_atom_foreach(pids, pid) {
		const char *pi = lldpctl_atom_get_str(pid, lldpctl_k_pi_id);
		if (pi && strlen(pi) > 0)
			tag_datatag(w, "pi", "PI", pi);
	}
	lldpctl_atom_dec_ref(pids);
}

static const char*
display_age(time_t lastchange)
{
	static char sage[30];
	int age = (int)(time(NULL) - lastchange);
	if (snprintf(sage, sizeof(sage),
		"%d day%s, %02d:%02d:%02d",
		age / (60*60*24),
		(age / (60*60*24) > 1)?"s":"",
		(age / (60*60)) % 24,
		(age / 60) % 60,
		age % 60) >= sizeof(sage))
		return "too much";
	else
		return sage;
}

void
display_local_chassis(lldpctl_conn_t *conn, struct writer *w,
    struct cmd_env *env, int details)
{
	tag_start(w, "local-chassis", "Local chassis");

	lldpctl_atom_t *chassis = lldpctl_get_local_chassis(conn);
	display_chassis(w, chassis, details);
	lldpctl_atom_dec_ref(chassis);

	tag_end(w);
}

void
display_interface(lldpctl_conn_t *conn, struct writer *w, int hidden,
    lldpctl_atom_t *iface, lldpctl_atom_t *port, int details, int protocol)
{
	int local = 0;

	if (!hidden &&
	    lldpctl_atom_get_int(port, lldpctl_k_port_hidden))
		return;

	/* user might have specified protocol to filter on display */
	if ((protocol != LLDPD_MODE_MAX) &&
	    (protocol != lldpctl_atom_get_int(port, lldpctl_k_port_protocol)))
	    return;

	/* Infer local / remote port from the port index (remote == 0) */
	local = lldpctl_atom_get_int(port, lldpctl_k_port_index)>0?1:0;

	lldpctl_atom_t *chassis = lldpctl_atom_get(port, lldpctl_k_port_chassis);

	tag_start(w, "interface", "Interface");
	tag_attr(w, "name", "",
	    lldpctl_atom_get_str(iface, lldpctl_k_interface_name));
	if (!local) {
		tag_attr(w, "via" , "via",
		    lldpctl_atom_get_str(port, lldpctl_k_port_protocol));
		if (details > DISPLAY_BRIEF) {
			tag_attr(w, "rid" , "RID",
			    lldpctl_atom_get_str(chassis, lldpctl_k_chassis_index));
			tag_attr(w, "age" , "Time",
			    display_age(lldpctl_atom_get_int(port, lldpctl_k_port_age)));
		}
	} else {
		tag_datatag(w, "status", "Administrative status",
		    lldpctl_atom_get_str(port, lldpctl_k_port_status));
	}

	display_chassis(w, chassis, details);
	display_port(w, port, details);
	if (details && local && conn)
		display_local_ttl(w, conn, details);
	if (details == DISPLAY_DETAILS) {
		display_ppvids(w, port);
		display_pids(w, port);
	}

	lldpctl_atom_dec_ref(chassis);

	tag_end(w);
}

/**
 * Display information about interfaces.
 *
 * @param conn       Connection to ub-lldpd.
 * @param w          Writer.
 * @param env        Environment from which we may find the list of ports.
 * @param hidden     Whatever to show hidden ports.
 * @param details    Level of details we need (DISPLAY_*).
 */
void
display_interfaces(lldpctl_conn_t *conn, struct writer *w,
    struct cmd_env *env,
    int hidden, int details)
{
	lldpctl_atom_t *iface;
	int protocol = LLDPD_MODE_MAX;
	const char *proto_str;

	/* user might have specified protocol to filter display results */
	proto_str = cmdenv_get(env, "protocol");

	if (proto_str) {
		log_debug("display", "filter protocol: %s ", proto_str);

		protocol = 0;
		for (lldpctl_map_t *protocol_map =
			 lldpctl_key_get_map(lldpctl_k_port_protocol);
		     protocol_map->string;
		     protocol_map++) {
			if (!strcasecmp(proto_str, protocol_map->string)) {
				protocol = protocol_map->value;
				break;
			}
		}
	}

	tag_start(w, "lldp", "LLDP neighbors");
	while ((iface = cmd_iterate_on_interfaces(conn, env))) {
		lldpctl_atom_t *port;
		lldpctl_atom_t *neighbors;
		lldpctl_atom_t *neighbor;
		port      = lldpctl_get_port(iface);
		neighbors = lldpctl_atom_get(port, lldpctl_k_port_neighbors);
		lldpctl_atom_foreach(neighbors, neighbor) {
			display_interface(conn, w, hidden, iface, neighbor, details, protocol);
		}
		lldpctl_atom_dec_ref(neighbors);
		lldpctl_atom_dec_ref(port);
	}
	tag_end(w);
}


/**
 * Display information about local interfaces.
 *
 * @param conn       Connection to ub-lldpd.
 * @param w          Writer.
 * @param hidden     Whatever to show hidden ports.
 * @param env        Environment from which we may find the list of ports.
 * @param details    Level of details we need (DISPLAY_*).
 */
void
display_local_interfaces(lldpctl_conn_t *conn, struct writer *w,
    struct cmd_env *env,
    int hidden, int details)
{
	lldpctl_atom_t *iface;
	int protocol = LLDPD_MODE_MAX;

	tag_start(w, "lldp", "LLDP interfaces");
	while ((iface = cmd_iterate_on_interfaces(conn, env))) {
		lldpctl_atom_t *port;
		port = lldpctl_get_port(iface);
		display_interface(conn, w, hidden, iface, port, details, protocol);
		lldpctl_atom_dec_ref(port);
	}
	tag_end(w);
 }

void
display_stat(struct writer *w, const char *tag, const char *descr,
	long unsigned int cnt)
{
	char buf[20] = {};

	tag_start(w, tag, descr);
	snprintf(buf, sizeof(buf), "%lu", cnt);
	tag_attr(w, tag, "", buf);
	tag_end(w);
}

void
display_interface_stats(lldpctl_conn_t *conn, struct writer *w,
		lldpctl_atom_t *port)
{
	tag_start(w, "interface", "Interface");
	tag_attr(w, "name", "",
	    lldpctl_atom_get_str(port, lldpctl_k_port_name));

	display_stat(w, "tx", "Transmitted",
			lldpctl_atom_get_int(port, lldpctl_k_tx_cnt));
	display_stat(w, "rx", "Received",
			lldpctl_atom_get_int(port, lldpctl_k_rx_cnt));

	display_stat(w, "rx_discarded_cnt", "Discarded",
			lldpctl_atom_get_int(port,
			lldpctl_k_rx_discarded_cnt));

	display_stat(w, "rx_unrecognized_cnt", "Unrecognized",
			lldpctl_atom_get_int(port,
			lldpctl_k_rx_unrecognized_cnt));

	display_stat(w, "ageout_cnt", "Ageout",
			lldpctl_atom_get_int(port,
			lldpctl_k_ageout_cnt));

	display_stat(w, "insert_cnt", "Inserted",
			lldpctl_atom_get_int(port,
			lldpctl_k_insert_cnt));

	display_stat(w, "delete_cnt", "Deleted",
			lldpctl_atom_get_int(port,
			lldpctl_k_delete_cnt));

	tag_end(w);
}

/**
 * Display interface stats
 *
 * @param conn       Connection to ub-lldpd.
 * @param w          Writer.
 * @param env        Environment from which we may find the list of ports.
 */
void
display_interfaces_stats(lldpctl_conn_t *conn, struct writer *w,
    struct cmd_env *env)
{
	lldpctl_atom_t *iface;
	int summary = 0;
	u_int64_t h_tx_cnt = 0;
	u_int64_t h_rx_cnt = 0;
	u_int64_t h_rx_discarded_cnt = 0;
	u_int64_t h_rx_unrecognized_cnt = 0;
	u_int64_t h_ageout_cnt = 0;
	u_int64_t h_insert_cnt = 0;
	u_int64_t h_delete_cnt = 0;

	if (cmdenv_get(env, "summary"))
		summary = 1;

	tag_start(w, "lldp", (summary ? "LLDP Global statistics" :
		"LLDP statistics"));
	while ((iface = cmd_iterate_on_interfaces(conn, env))) {
		lldpctl_atom_t *port;
		port      = lldpctl_get_port(iface);
		if (!summary)
			display_interface_stats(conn, w, port);
		else {
			h_tx_cnt += lldpctl_atom_get_int(port,
					lldpctl_k_tx_cnt);
			h_rx_cnt += lldpctl_atom_get_int(port,
					lldpctl_k_rx_cnt);
			h_rx_discarded_cnt += lldpctl_atom_get_int(port,
					lldpctl_k_rx_discarded_cnt);
			h_rx_unrecognized_cnt += lldpctl_atom_get_int(port,
					lldpctl_k_rx_unrecognized_cnt);
			h_ageout_cnt += lldpctl_atom_get_int(port,
						lldpctl_k_ageout_cnt);
			h_insert_cnt += lldpctl_atom_get_int(port,
						lldpctl_k_insert_cnt);
			h_delete_cnt += lldpctl_atom_get_int(port,
						lldpctl_k_delete_cnt);
		}
		lldpctl_atom_dec_ref(port);
	}

	if (summary) {
		tag_start(w, "summary", "Summary of stats");
		display_stat(w, "tx", "Transmitted", h_tx_cnt);
		display_stat(w, "rx", "Received", h_rx_cnt);
		display_stat(w, "rx_discarded_cnt", "Discarded",
			h_rx_discarded_cnt);

		display_stat(w, "rx_unrecognized_cnt", "Unrecognized",
			h_rx_unrecognized_cnt);

		display_stat(w, "ageout_cnt", "Ageout", h_ageout_cnt);

		display_stat(w, "insert_cnt", "Inserted", h_insert_cnt);

		display_stat(w, "delete_cnt", "Deleted", h_delete_cnt);
		tag_end(w);
	}
	tag_end(w);
}

static const char *
N(const char *str) {
	if (str == NULL || strlen(str) == 0) return "(none)";
	return str;
}

void
display_configuration(lldpctl_conn_t *conn, struct writer *w)
{
	lldpctl_atom_t *configuration;

	configuration = lldpctl_get_configuration(conn);
	if (!configuration) {
		log_warnx("ub-lldpctl", "not able to get configuration. %s",
		    lldpctl_last_strerror(conn));
		return;
	}

	tag_start(w, "configuration", "Global configuration");
	tag_start(w, "config", "Configuration");

	tag_datatag(w, "tx-delay", "Transmit delay",
	    lldpctl_atom_get_str(configuration, lldpctl_k_config_tx_interval));
	tag_datatag(w, "tx-delay-ms", "Transmit delay in milliseconds",
	    lldpctl_atom_get_str(configuration, lldpctl_k_config_tx_interval_ms));
	tag_datatag(w, "tx-hold", "Transmit hold",
	    lldpctl_atom_get_str(configuration, lldpctl_k_config_tx_hold));
	tag_datatag(w, "max-neighbors", "Maximum number of neighbors",
	    lldpctl_atom_get_str(configuration, lldpctl_k_config_max_neighbors));
	tag_datatag(w, "rx-only", "Receive mode",
	    lldpctl_atom_get_int(configuration, lldpctl_k_config_receiveonly)?
	    "yes":"no");
	tag_datatag(w, "mgmt-pattern", "Pattern for management addresses",
	    N(lldpctl_atom_get_str(configuration, lldpctl_k_config_mgmt_pattern)));
	tag_datatag(w, "iface-pattern", "Interface pattern",
	    N(lldpctl_atom_get_str(configuration, lldpctl_k_config_iface_pattern)));
	tag_datatag(w, "perm-iface-pattern", "Permanent interface pattern",
	    N(lldpctl_atom_get_str(configuration, lldpctl_k_config_perm_iface_pattern)));
	tag_datatag(w, "cid-pattern", "Interface pattern for chassis ID",
	    N(lldpctl_atom_get_str(configuration, lldpctl_k_config_cid_pattern)));
	tag_datatag(w, "cid-string", "Override chassis ID with",
	    N(lldpctl_atom_get_str(configuration, lldpctl_k_config_cid_string)));
	tag_datatag(w, "description", "Override description with",
	    N(lldpctl_atom_get_str(configuration, lldpctl_k_config_description)));
	tag_datatag(w, "platform", "Override platform with",
	    N(lldpctl_atom_get_str(configuration, lldpctl_k_config_platform)));
	tag_datatag(w, "hostname", "Override system name with",
	    N(lldpctl_atom_get_str(configuration, lldpctl_k_config_hostname)));
	tag_datatag(w, "advertise-version", "Advertise version",
	    lldpctl_atom_get_int(configuration, lldpctl_k_config_advertise_version)?
	    "yes":"no");
	tag_datatag(w, "ifdescr-update", "Update interface descriptions",
	    lldpctl_atom_get_int(configuration, lldpctl_k_config_ifdescr_update)?
	    "yes":"no");
	tag_datatag(w, "iface-promisc", "Promiscuous mode on managed interfaces",
	    lldpctl_atom_get_int(configuration, lldpctl_k_config_iface_promisc)?
	    "yes":"no");
	tag_datatag(w, "lldp-portid-type",
		"Port ID TLV subtype for LLDP frames",
		lldpctl_atom_get_str(configuration,
			lldpctl_k_config_lldp_portid_type));

	tag_end(w);
	tag_end(w);

	lldpctl_atom_dec_ref(configuration);
}
