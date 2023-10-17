/* -*- mode: c; c-file-style: "openbsd" -*- */
/*
 * Copyright (c) 2015 Vincent Bernat <vincent@bernat.im>
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
#include <stdarg.h>
#include <string.h>
#include <arpa/inet.h>

#include "../lldpctl.h"
#include "../../log.h"
#include "../atom.h"
#include "../helpers.h"

static struct atom_map lldpd_protocol_map = {
	.key = lldpctl_k_port_protocol,
	.map = {
		{ LLDPD_MODE_LLDP,	"LLDP" },
		{ 0, NULL },
	}
};

ATOM_MAP_REGISTER(lldpd_protocol_map, 3);

static lldpctl_map_t port_id_subtype_map[] = {
	{ LLDP_PORTID_SUBTYPE_IFNAME,   "ifname"},
	{ LLDP_PORTID_SUBTYPE_IFALIAS,  "ifalias" },
	{ LLDP_PORTID_SUBTYPE_LOCAL,    "local" },
	{ LLDP_PORTID_SUBTYPE_LLADDR,   "mac" },
	{ LLDP_PORTID_SUBTYPE_ADDR,     "ip" },
	{ LLDP_PORTID_SUBTYPE_PORT,     "unhandled" },
	{ LLDP_PORTID_SUBTYPE_AGENTCID, "unhandled" },
	{ 0, NULL},
};

static struct atom_map port_status_map = {
	.key = lldpctl_k_port_status,
	.map = {
		{ LLDPD_RXTX_TXONLY,   "TX only" },
		{ LLDPD_RXTX_RXONLY,   "RX only" },
		{ LLDPD_RXTX_DISABLED, "disabled" },
		{ LLDPD_RXTX_BOTH,     "RX and TX" },
		{ 0, NULL },
	}
};

ATOM_MAP_REGISTER(port_status_map, 3);

static lldpctl_atom_iter_t*
_lldpctl_atom_iter_ports_list(lldpctl_atom_t *atom)
{
	struct _lldpctl_atom_any_list_t *plist =
	    (struct _lldpctl_atom_any_list_t *)atom;
	return (lldpctl_atom_iter_t*)TAILQ_FIRST(&plist->parent->hardware->h_rports);
}

static lldpctl_atom_iter_t*
_lldpctl_atom_next_ports_list(lldpctl_atom_t *atom, lldpctl_atom_iter_t *iter)
{
	struct lldpd_port *port = (struct lldpd_port *)iter;
	return (lldpctl_atom_iter_t*)TAILQ_NEXT(port, p_entries);
}

static lldpctl_atom_t*
_lldpctl_atom_value_ports_list(lldpctl_atom_t *atom, lldpctl_atom_iter_t *iter)
{
	struct lldpd_port *port = (struct lldpd_port *)iter;
	return _lldpctl_new_atom(atom->conn, atom_port, 0, NULL, port,
	    ((struct _lldpctl_atom_any_list_t *)atom)->parent);
}

static int
_lldpctl_atom_new_port(lldpctl_atom_t *atom, va_list ap)
{
	struct _lldpctl_atom_port_t *port =
	    (struct _lldpctl_atom_port_t *)atom;
	port->local = va_arg(ap, int);
	port->hardware = va_arg(ap, struct lldpd_hardware*);
	port->port = va_arg(ap, struct lldpd_port*);
	port->parent = va_arg(ap, struct _lldpctl_atom_port_t*);
	if (port->parent)
		lldpctl_atom_inc_ref((lldpctl_atom_t*)port->parent);

	if (port->port) {
		/* Internal atom. We are the parent, but our reference count is
		 * not incremented. */
		port->chassis = _lldpctl_new_atom(atom->conn, atom_chassis,
			    port->port->p_chassis, port, 1);
	}
	return 1;
}

TAILQ_HEAD(chassis_list, lldpd_chassis);

static void
add_chassis(struct chassis_list *chassis_list,
	struct lldpd_chassis *chassis)
{
	struct lldpd_chassis *one_chassis;
	TAILQ_FOREACH(one_chassis, chassis_list, c_entries) {
		if (one_chassis == chassis) return;
	}
	TAILQ_INSERT_TAIL(chassis_list,
	    chassis, c_entries);
}

static void
_lldpctl_atom_free_port(lldpctl_atom_t *atom)
{
	struct _lldpctl_atom_port_t *port =
	    (struct _lldpctl_atom_port_t *)atom;
	struct lldpd_hardware *hardware = port->hardware;
	struct lldpd_chassis  *one_chassis, *one_chassis_next;
	struct lldpd_port     *one_port;

	/* Free internal chassis atom. Should be freed immediately since we
	 * should have the only reference. */
	lldpctl_atom_dec_ref((lldpctl_atom_t*)port->chassis);

	/* We need to free the whole struct lldpd_hardware: local port, local
	 * chassis and remote ports... The same chassis may be present several
	 * times. We build a list of chassis (we don't use reference count). */
	struct chassis_list chassis_list;
	TAILQ_INIT(&chassis_list);

	if (port->parent) lldpctl_atom_dec_ref((lldpctl_atom_t*)port->parent);
	else if (!hardware && port->port) {
		/* No parent, no hardware, we assume a single neighbor: one
		 * port, one chassis. */
		if (port->port->p_chassis) {
			lldpd_chassis_cleanup(port->port->p_chassis, 1);
			port->port->p_chassis = NULL;
		}
		lldpd_port_cleanup(port->port, 1);
		free(port->port);
	}
	if (!hardware) return;

	add_chassis(&chassis_list, port->port->p_chassis);
	TAILQ_FOREACH(one_port, &hardware->h_rports, p_entries)
		add_chassis(&chassis_list, one_port->p_chassis);

	/* Free hardware port */
	lldpd_remote_cleanup(hardware, NULL, 1);
	lldpd_port_cleanup(port->port, 1);
	free(port->hardware);

	/* Free list of chassis */
	for (one_chassis = TAILQ_FIRST(&chassis_list);
	     one_chassis != NULL;
	     one_chassis = one_chassis_next) {
		one_chassis_next = TAILQ_NEXT(one_chassis, c_entries);
		lldpd_chassis_cleanup(one_chassis, 1);
	}
}

static lldpctl_atom_t*
_lldpctl_atom_get_atom_port(lldpctl_atom_t *atom, lldpctl_key_t key)
{
	struct _lldpctl_atom_port_t *p =
	    (struct _lldpctl_atom_port_t *)atom;
	struct lldpd_port     *port     = p->port;
	struct lldpd_hardware *hardware = p->hardware;

	/* Local port only */
	if (hardware != NULL) {
		switch (key) {
		case lldpctl_k_port_neighbors:
			return _lldpctl_new_atom(atom->conn, atom_ports_list, p);
		default: break;
		}
	}

	/* Local and remote port */
	switch (key) {
	case lldpctl_k_port_chassis:
		if (port->p_chassis) {
			return _lldpctl_new_atom(atom->conn, atom_chassis,
			    port->p_chassis, p, 0);
		}
		SET_ERROR(atom->conn, LLDPCTL_ERR_NOT_EXIST);
		return NULL;
	default:
		/* Compatibility: query the associated chassis too */
		if (port->p_chassis)
			return lldpctl_atom_get(p->chassis, key);
		SET_ERROR(atom->conn, LLDPCTL_ERR_NOT_EXIST);
		return NULL;
	}
}

static lldpctl_atom_t*
_lldpctl_atom_set_atom_port(lldpctl_atom_t *atom, lldpctl_key_t key, lldpctl_atom_t *value)
{
	struct _lldpctl_atom_port_t *p =
	    (struct _lldpctl_atom_port_t *)atom;
	struct lldpd_hardware *hardware = p->hardware;
	struct lldpd_port_set set = {};
	int rc;
	char *canary = NULL;

	/* Local and default port only */
	if (!p->local) {
		SET_ERROR(atom->conn, LLDPCTL_ERR_NOT_EXIST);
		return NULL;
	}

	switch (key) {
	case lldpctl_k_port_id:
		set.local_id = p->port->p_id;
		break;
	case lldpctl_k_port_descr:
		set.local_descr = p->port->p_descr;
		break;
	case lldpctl_k_port_status:
		set.rxtx = LLDPD_RXTX_FROM_PORT(p->port);
		break;
	default:
		SET_ERROR(atom->conn, LLDPCTL_ERR_NOT_EXIST);
		return NULL;
	}

	set.ifname = hardware ? hardware->h_ifname : "";

	if (asprintf(&canary, "%d%p%s", key, value, set.ifname) == -1) {
		SET_ERROR(atom->conn, LLDPCTL_ERR_NOMEM);
		return NULL;
	}
	rc = _lldpctl_do_something(atom->conn,
	    CONN_STATE_SET_PORT_SEND, CONN_STATE_SET_PORT_RECV,
	    canary,
	    SET_PORT, &set, &MARSHAL_INFO(lldpd_port_set),
	    NULL, NULL);
	free(canary);
	if (rc == 0) return atom;
	return NULL;
}

static const char*
_lldpctl_atom_get_str_port(lldpctl_atom_t *atom, lldpctl_key_t key)
{
	struct _lldpctl_atom_port_t *p =
	    (struct _lldpctl_atom_port_t *)atom;
	struct lldpd_port     *port     = p->port;
	struct lldpd_hardware *hardware = p->hardware;
	char *ipaddress = NULL; size_t len;

	/* Local port only */
	switch (key) {
	case lldpctl_k_port_name:
		if (hardware != NULL) return hardware->h_ifname;
		break;
	case lldpctl_k_port_status:
		if (p->local) return map_lookup(port_status_map.map,
		    LLDPD_RXTX_FROM_PORT(port));
		break;
	default: break;
	}

	if (!port)
		return NULL;

	/* Local and remote port */
	switch (key) {
	case lldpctl_k_port_protocol:
		return map_lookup(lldpd_protocol_map.map, port->p_protocol);
	case lldpctl_k_port_id_subtype:
		return map_lookup(port_id_subtype_map, port->p_id_subtype);
	case lldpctl_k_port_id:
		switch (port->p_id_subtype) {
		case LLDP_PORTID_SUBTYPE_IFNAME:
		case LLDP_PORTID_SUBTYPE_IFALIAS:
		case LLDP_PORTID_SUBTYPE_LOCAL:
			return port->p_id;
		case LLDP_PORTID_SUBTYPE_LLADDR:
			return _lldpctl_dump_in_atom(atom,
			    (uint8_t*)port->p_id, port->p_id_len,
			    ':', 0);
		case LLDP_PORTID_SUBTYPE_ADDR:
			switch (port->p_id[0]) {
			case LLDP_MGMT_ADDR_IP4: len = INET_ADDRSTRLEN + 1; break;
			case LLDP_MGMT_ADDR_IP6: len = INET6_ADDRSTRLEN + 1; break;
			default: len = 0;
			}
			if (len > 0) {
				ipaddress = _lldpctl_alloc_in_atom(atom, len);
				if (!ipaddress) return NULL;
				if (inet_ntop((port->p_id[0] == LLDP_MGMT_ADDR_IP4)?
					AF_INET:AF_INET6,
					&port->p_id[1], ipaddress, len) == NULL)
					break;
				return ipaddress;
			}
			break;
		}
		SET_ERROR(atom->conn, LLDPCTL_ERR_NOT_EXIST);
		return NULL;
	case lldpctl_k_port_descr:
		return port->p_descr;

	default:
		/* Compatibility: query the associated chassis too */
		return lldpctl_atom_get_str(p->chassis, key);
	}
}

static lldpctl_atom_t*
_lldpctl_atom_set_int_port(lldpctl_atom_t *atom, lldpctl_key_t key,
    long int value)
{
	struct _lldpctl_atom_port_t *p =
	    (struct _lldpctl_atom_port_t *)atom;
	struct lldpd_port     *port     = p->port;

	if (p->local) {
		switch (key) {
		case lldpctl_k_port_status:
			port->p_disable_rx = !LLDPD_RXTX_RXENABLED(value);
			port->p_disable_tx = !LLDPD_RXTX_TXENABLED(value);
			break;
		default:
			SET_ERROR(atom->conn, LLDPCTL_ERR_NOT_EXIST);
			return NULL;
		}
	} else {
		SET_ERROR(atom->conn, LLDPCTL_ERR_NOT_EXIST);
		return NULL;
	}

	return _lldpctl_atom_set_atom_port(atom, key, NULL);
}

static lldpctl_atom_t*
_lldpctl_atom_set_str_port(lldpctl_atom_t *atom, lldpctl_key_t key,
    const char *value)
{
	struct _lldpctl_atom_port_t *p =
	    (struct _lldpctl_atom_port_t *)atom;
	struct lldpd_port     *port     = p->port;

	if (!value || !strlen(value))
		return NULL;

	if (p->local) {
		switch (key) {
		case lldpctl_k_port_status:
			return _lldpctl_atom_set_int_port(atom, key,
			    map_reverse_lookup(port_status_map.map, value));
		default: break;
		}
	}

	switch (key) {
	case lldpctl_k_port_id:
		free(port->p_id);
		port->p_id = strdup(value);
		port->p_id_len = strlen(value);
		break;
	case lldpctl_k_port_descr:
		free(port->p_descr);
		port->p_descr = strdup(value);
		break;
	default:
		SET_ERROR(atom->conn, LLDPCTL_ERR_NOT_EXIST);
		return NULL;
	}

	return _lldpctl_atom_set_atom_port(atom, key, NULL);
}

static long int
_lldpctl_atom_get_int_port(lldpctl_atom_t *atom, lldpctl_key_t key)
{
	struct _lldpctl_atom_port_t *p =
	    (struct _lldpctl_atom_port_t *)atom;
	struct lldpd_port     *port     = p->port;
	struct lldpd_hardware *hardware = p->hardware;

	/* Local port only */
	if (hardware != NULL) {
		switch (key) {
		case lldpctl_k_port_index:
			return hardware->h_ifindex;
		case lldpctl_k_tx_cnt:
			return hardware->h_tx_cnt;
		case lldpctl_k_rx_cnt:
			return hardware->h_rx_cnt;
		case lldpctl_k_rx_discarded_cnt:
			return hardware->h_rx_discarded_cnt;
		case lldpctl_k_rx_unrecognized_cnt:
			return hardware->h_rx_unrecognized_cnt;
		case lldpctl_k_ageout_cnt:
			return hardware->h_ageout_cnt;
		case lldpctl_k_insert_cnt:
			return hardware->h_insert_cnt;
		case lldpctl_k_delete_cnt:
			return hardware->h_delete_cnt;
		default: break;
		}
	}
	if (p->local) {
		switch (key) {
		case lldpctl_k_port_status:
			return LLDPD_RXTX_FROM_PORT(port);
		default: break;
		}
	}
	if (!port)
		return SET_ERROR(atom->conn, LLDPCTL_ERR_NOT_EXIST);

	/* Local and remote port */
	switch (key) {
	case lldpctl_k_port_protocol:
		return port->p_protocol;
	case lldpctl_k_port_age:
		return port->p_lastchange;
	case lldpctl_k_port_ttl:
		return port->p_ttl;
	case lldpctl_k_port_id_subtype:
		return port->p_id_subtype;
	case lldpctl_k_port_hidden:
		return port->p_hidden_in;
	default:
		/* Compatibility: query the associated chassis too */
		return lldpctl_atom_get_int(p->chassis, key);
	}
	return SET_ERROR(atom->conn, LLDPCTL_ERR_NOT_EXIST);
}

static const uint8_t*
_lldpctl_atom_get_buf_port(lldpctl_atom_t *atom, lldpctl_key_t key, size_t *n)
{
	struct _lldpctl_atom_port_t *p =
	    (struct _lldpctl_atom_port_t *)atom;
	struct lldpd_port     *port     = p->port;

	switch (key) {
	case lldpctl_k_port_id:
		*n = port->p_id_len;
		return (uint8_t*)port->p_id;
	default:
		/* Compatibility: query the associated chassis too */
		return lldpctl_atom_get_buffer(p->chassis, key, n);
	}
}

static struct atom_builder ports_list =
	{ atom_ports_list, sizeof(struct _lldpctl_atom_any_list_t),
	  .init = _lldpctl_atom_new_any_list,
	  .free = _lldpctl_atom_free_any_list,
	  .iter = _lldpctl_atom_iter_ports_list,
	  .next = _lldpctl_atom_next_ports_list,
	  .value = _lldpctl_atom_value_ports_list };

static struct atom_builder port =
	{ atom_port, sizeof(struct _lldpctl_atom_port_t),
	  .init = _lldpctl_atom_new_port,
	  .free = _lldpctl_atom_free_port,
	  .get  = _lldpctl_atom_get_atom_port,
	  .set  = _lldpctl_atom_set_atom_port,
	  .get_str = _lldpctl_atom_get_str_port,
	  .set_str = _lldpctl_atom_set_str_port,
	  .get_int = _lldpctl_atom_get_int_port,
	  .set_int = _lldpctl_atom_set_int_port,
	  .get_buffer = _lldpctl_atom_get_buf_port };

ATOM_BUILDER_REGISTER(ports_list, 4);
ATOM_BUILDER_REGISTER(port,       5);

