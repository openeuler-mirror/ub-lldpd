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

#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include "log.h"
#include "lldpd-structs.h"

void
lldpd_chassis_mgmt_cleanup(struct lldpd_chassis *chassis)
{
	struct lldpd_mgmt *mgmt, *mgmt_next;

	log_debug("alloc", "cleanup management addresses for chassis %s",
	    chassis->c_name ? chassis->c_name : "(unknown)");

	for (mgmt = TAILQ_FIRST(&chassis->c_mgmt);
	     mgmt != NULL;
	     mgmt = mgmt_next) {
		mgmt_next = TAILQ_NEXT(mgmt, m_entries);
		free(mgmt);
	}
	TAILQ_INIT(&chassis->c_mgmt);
}

void
lldpd_chassis_cleanup(struct lldpd_chassis *chassis, int all)
{
	lldpd_chassis_mgmt_cleanup(chassis);
	log_debug("alloc", "cleanup chassis %s",
	    chassis->c_name ? chassis->c_name : "(unknown)");
	free(chassis->c_id);
	free(chassis->c_name);
	free(chassis->c_descr);
	if (all)
		free(chassis);
}

/* Cleanup a remote port. The before last argument, `expire` is a function that
 * should be called when a remote port is removed. If the last argument is 1,
 * all remote ports are removed.
 */
void
lldpd_remote_cleanup(struct lldpd_hardware *hardware,
    void(*expire)(struct lldpd_hardware *, struct lldpd_port *),
    int all)
{
	struct lldpd_port *port, *port_next;
	int del;
	time_t now = time(NULL);

	log_debug("alloc", "cleanup remote port on %s",
	    hardware->h_ifname);
	for (port = TAILQ_FIRST(&hardware->h_rports);
	     port != NULL;
	     port = port_next) {
		port_next = TAILQ_NEXT(port, p_entries);
		del = all;
		if (!all && expire &&
		    (now >= port->p_lastupdate + port->p_ttl)) {
			if (port->p_ttl > 0) hardware->h_ageout_cnt++;
			del = 1;
		}
		if (del) {
			if (expire) expire(hardware, port);
			/* This TAILQ_REMOVE is dangerous. It should not be
			 * called while in liblldpctl because we don't have a
			 * real list. It is only needed to be called when we
			 * don't delete the entire list. */
			if (!all) TAILQ_REMOVE(&hardware->h_rports, port, p_entries);

			hardware->h_delete_cnt++;
			/* Register last removal to be able to report lldpStatsRemTablesLastChangeTime */
			hardware->h_lport.p_lastremove = time(NULL);
			lldpd_port_cleanup(port, 1);
			free(port);
		}
	}
	if (all) TAILQ_INIT(&hardware->h_rports);
}

/* If `all' is true, clear all information, including information that
   are not refreshed periodically. Port should be freed manually. */
void
lldpd_port_cleanup(struct lldpd_port *port, int all)
{
	/* will set these to NULL so we don't free wrong memory */
	if (all) {
		free(port->p_id);
		port->p_id = NULL;
		free(port->p_descr);
		port->p_descr = NULL;
		free(port->p_lastframe);
		if (port->p_chassis) { /* chassis may not have been attributed, yet */
			port->p_chassis->c_refcount--;
			port->p_chassis = NULL;
		}
	}
}

void
lldpd_config_cleanup(struct lldpd_config *config)
{
	log_debug("alloc", "general configuration cleanup");
	free(config->c_mgmt_pattern);
	free(config->c_cid_pattern);
	free(config->c_cid_string);
	free(config->c_iface_pattern);
	free(config->c_perm_ifaces);
	free(config->c_hostname);
	free(config->c_platform);
	free(config->c_description);
}
