/* -*- mode: c; c-file-style: "openbsd" -*- */
/*
 * Copyright (c) 2012 Vincent Bernat <bernat@luffy.cx>
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

#ifndef _LLDP_TLV_H
#define _LLDP_TLV_H

#define LLDP_ADDR_NEAREST_BRIDGE		{0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e}
#define LLDP_ADDR_NEAREST_NONTPMR_BRIDGE	{0x01, 0x80, 0xc2, 0x00, 0x00, 0x03}
#define LLDP_ADDR_NEAREST_CUSTOMER_BRIDGE	{0x01, 0x80, 0xc2, 0x00, 0x00, 0x00}

#define LLDP_TLV_END		0
#define LLDP_TLV_CHASSIS_ID	1
#define LLDP_TLV_PORT_ID	2
#define LLDP_TLV_TTL		3
#define LLDP_TLV_PORT_DESCR	4
#define LLDP_TLV_SYSTEM_NAME	5
#define LLDP_TLV_SYSTEM_DESCR	6
#define LLDP_TLV_SYSTEM_CAP	7
#define LLDP_TLV_MGMT_ADDR	8
#define LLDP_TLV_TYPE_NUM	9
#define LLDP_TLV_NAME_SIZE	32
#endif
