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

#ifndef _LLDP_H
#define _LLDP_H

/* Chassis ID subtype */
#define LLDP_CHASSISID_SUBTYPE_CHASSIS	1
#define LLDP_CHASSISID_SUBTYPE_IFALIAS	2
#define LLDP_CHASSISID_SUBTYPE_PORT	3
#define LLDP_CHASSISID_SUBTYPE_LLADDR	4
#define LLDP_CHASSISID_SUBTYPE_ADDR	5
#define LLDP_CHASSISID_SUBTYPE_IFNAME	6
#define LLDP_CHASSISID_SUBTYPE_LOCAL	7

/* Port ID subtype */
#define LLDP_PORTID_SUBTYPE_UNKNOWN	0
#define LLDP_PORTID_SUBTYPE_IFALIAS	1
#define LLDP_PORTID_SUBTYPE_PORT	2
#define LLDP_PORTID_SUBTYPE_LLADDR	3
#define LLDP_PORTID_SUBTYPE_ADDR	4
#define LLDP_PORTID_SUBTYPE_IFNAME	5
#define LLDP_PORTID_SUBTYPE_AGENTCID	6
#define LLDP_PORTID_SUBTYPE_LOCAL	7
#define LLDP_PORTID_SUBTYPE_MAX		LLDP_PORTID_SUBTYPE_LOCAL

/* Capabilities */
#define LLDP_CAP_OTHER		0x01
#define LLDP_CAP_REPEATER	0x02
#define LLDP_CAP_BRIDGE		0x04
#define LLDP_CAP_WLAN		0x08
#define LLDP_CAP_ROUTER		0x10
#define LLDP_CAP_TELEPHONE	0x20
#define LLDP_CAP_DOCSIS		0x40
#define LLDP_CAP_STATION	0x80

#define LLDP_PPVID_CAP_SUPPORTED	(1 << 1)
#define LLDP_PPVID_CAP_ENABLED		(1 << 2)

/* see http://www.iana.org/assignments/address-family-numbers */
#define LLDP_MGMT_ADDR_NONE	0
#define LLDP_MGMT_ADDR_IP4	1
#define LLDP_MGMT_ADDR_IP6	2

#define LLDP_MGMT_IFACE_UNKNOWN 1
#define LLDP_MGMT_IFACE_IFINDEX 2
#define LLDP_MGMT_IFACE_SYSPORT	3

#define LLDPD_MODE_LLDP		1
#define LLDPD_MODE_MAX		LLDPD_MODE_LLDP

#endif /* _LLDP_H */
