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

#include "../lldpd.h"
#include "../frame.h"

#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>

u_int8_t ub_dguid[GUID_LEN] = {0xFF, 0xFF, 0xFF, 0xFF,
			       0xFF, 0xFF, 0xFF, 0xFF,
			       0xFF, 0xFF, 0xFF, 0xFF,
			       0xFF, 0xFF, 0x01, 0x09};

static int
lldpd_af_to_lldp_proto(int af)
{
	switch (af) {
	case LLDPD_AF_IPV4:
		return LLDP_MGMT_ADDR_IP4;
	case LLDPD_AF_IPV6:
		return LLDP_MGMT_ADDR_IP6;
	default:
		return LLDP_MGMT_ADDR_NONE;
	}
}

static int
lldpd_af_from_lldp_proto(int proto)
{
	switch (proto) {
	case LLDP_MGMT_ADDR_IP4:
		return LLDPD_AF_IPV4;
	case LLDP_MGMT_ADDR_IP6:
		return LLDPD_AF_IPV6;
	default:
		return LLDPD_AF_UNSPEC;
	}
}

static int _lldp_send(struct lldpd *global,
    struct lldpd_hardware *hardware,
    u_int8_t c_id_subtype,
    char *c_id,
    int c_id_len,
    u_int8_t p_id_subtype,
    char *p_id,
    int p_id_len,
    int shutdown)
{
	struct lldpd_port *port;
	struct lldpd_chassis *chassis;
	struct interfaces_device *iff;
	struct lldpd_frame *frame;
	int length;
	u_int8_t *packet, *pos, *tlv;
	struct lldpd_mgmt *mgmt;
	int proto;

	u_int8_t mcastaddr_regular[] = LLDP_ADDR_NEAREST_BRIDGE;
	u_int8_t *mcastaddr;
	port = &hardware->h_lport;
	chassis = port->p_chassis;
	length = hardware->h_mtu;
	if ((packet = (u_int8_t*)calloc(1, length)) == NULL)
		return ENOMEM;
	pos = packet;

	iff = lldpd_get_device(global, hardware->h_ifname);
	if (iff == NULL) return ENODEV;

	struct ub_link_header ub_header;

	memset(&ub_header, 0x0, sizeof(struct ub_link_header));
	memcpy(ub_header.ub_dguid, ub_dguid, GUID_LEN);

	ub_header.ub_cfg = UB_CFG_TYPE;
	ub_header.ub_protocol = htons(LLDP_PROTO);
	memcpy(ub_header.ub_sguid, iff->address, GUID_LEN);
	if (!(POKE_BYTES(&ub_header, sizeof(struct ub_link_header))))
		goto toobig;

	/* Ethernet header */
	mcastaddr = mcastaddr_regular;

	if (!(
	      /* LLDP multicast address */
	      POKE_BYTES(mcastaddr, ETHER_ADDR_LEN) &&
	      /* Source GUID */
	      POKE_BYTES(&hardware->h_lladdr, ETHER_ADDR_LEN)))
		goto toobig;

	if (!(
	      /* LLDP frame */
	      POKE_UINT16(ETHERTYPE_LLDP)))
		goto toobig;

	/* Chassis ID */
	if (!(
	      POKE_START_LLDP_TLV(LLDP_TLV_CHASSIS_ID) &&
	      POKE_UINT8(c_id_subtype) &&
	      POKE_BYTES(c_id, c_id_len) &&
	      POKE_END_LLDP_TLV))
		goto toobig;

	/* Port ID */
	if (!(
	      POKE_START_LLDP_TLV(LLDP_TLV_PORT_ID) &&
	      POKE_UINT8(p_id_subtype) &&
	      POKE_BYTES(p_id, p_id_len) &&
	      POKE_END_LLDP_TLV))
		goto toobig;

	/* Time to live */
	if (!(
	      POKE_START_LLDP_TLV(LLDP_TLV_TTL) &&
	      POKE_UINT16(shutdown?0:(global?global->g_config.c_ttl:180)) &&
	      POKE_END_LLDP_TLV))
		goto toobig;

	if (shutdown)
		goto end;

	/* System name */
	if (chassis->c_name && *chassis->c_name != '\0') {
		if (!(
			    POKE_START_LLDP_TLV(LLDP_TLV_SYSTEM_NAME) &&
			    POKE_BYTES(chassis->c_name, strlen(chassis->c_name)) &&
			    POKE_END_LLDP_TLV))
			goto toobig;
	}

	/* System description (skip it if empty) */
	if (chassis->c_descr && *chassis->c_descr != '\0') {
		if (!(
			    POKE_START_LLDP_TLV(LLDP_TLV_SYSTEM_DESCR) &&
			    POKE_BYTES(chassis->c_descr, strlen(chassis->c_descr)) &&
			    POKE_END_LLDP_TLV))
			goto toobig;
	}

	/* System capabilities */
	if (global->g_config.c_cap_advertise && chassis->c_cap_available) {
		if (!(
			    POKE_START_LLDP_TLV(LLDP_TLV_SYSTEM_CAP) &&
			    POKE_UINT16(chassis->c_cap_available) &&
			    POKE_UINT16(chassis->c_cap_enabled) &&
			    POKE_END_LLDP_TLV))
			goto toobig;
	}

	/* Management addresses */
	TAILQ_FOREACH(mgmt, &chassis->c_mgmt, m_entries) {
		proto = lldpd_af_to_lldp_proto(mgmt->m_family);
		if (proto == LLDP_MGMT_ADDR_NONE) continue;
		if (!(
			  POKE_START_LLDP_TLV(LLDP_TLV_MGMT_ADDR) &&
			  /* Size of the address, including its type */
			  POKE_UINT8(mgmt->m_addrsize + 1) &&
			  POKE_UINT8(proto) &&
			  POKE_BYTES(&mgmt->m_addr, mgmt->m_addrsize)))
			goto toobig;

		/* Interface port type, OID */
		if (mgmt->m_iface == 0) {
			if (!(
				  /* We don't know the management interface */
				  POKE_UINT8(LLDP_MGMT_IFACE_UNKNOWN) &&
				  POKE_UINT32(0)))
				goto toobig;
		} else {
			if (!(
				  /* We have the index of the management interface */
				  POKE_UINT8(LLDP_MGMT_IFACE_IFINDEX) &&
				  POKE_UINT32(mgmt->m_iface)))
				goto toobig;
		}
		if (!(
			  /* We don't provide an OID for management */
			  POKE_UINT8(0) &&
			  POKE_END_LLDP_TLV))
			goto toobig;
	}

	/* Port description */
	if (port->p_descr && *port->p_descr != '\0') {
		if (!(
			    POKE_START_LLDP_TLV(LLDP_TLV_PORT_DESCR) &&
			    POKE_BYTES(port->p_descr, strlen(port->p_descr)) &&
			    POKE_END_LLDP_TLV))
			goto toobig;
	}

end:
	/* END */
	if (!(
	      POKE_START_LLDP_TLV(LLDP_TLV_END) &&
	      POKE_END_LLDP_TLV))
		goto toobig;

	if (interfaces_send_helper(global, hardware,
		(char *)packet, pos - packet) == -1) {
		log_warn("lldp", "unable to send packet on real device for %s",
		    hardware->h_ifname);
		free(packet);
		return ENETDOWN;
	}

	hardware->h_tx_cnt++;

	/* We assume that LLDP frame is the reference */
	if (!shutdown && (frame = (struct lldpd_frame*)malloc(
			sizeof(int) + pos - packet)) != NULL) {
		frame->size = pos - packet;
		memcpy(&frame->frame, packet, frame->size);
		if ((hardware->h_lport.p_lastframe == NULL) ||
		    (hardware->h_lport.p_lastframe->size != frame->size) ||
		    (memcmp(hardware->h_lport.p_lastframe->frame, frame->frame,
			frame->size) != 0)) {
			free(hardware->h_lport.p_lastframe);
			hardware->h_lport.p_lastframe = frame;
			hardware->h_lport.p_lastchange = time(NULL);
		} else free(frame);
	}

	free(packet);
	return 0;

toobig:
	log_info("lldp", "Cannot send LLDP packet for %s, Too big message", p_id);
	free(packet);
	return E2BIG;
}

/* Send a shutdown LLDPDU. */
int
lldp_send_shutdown(struct lldpd *global,
    struct lldpd_hardware *hardware)
{
	if (hardware->h_lchassis_previous_id == NULL ||
	    hardware->h_lport_previous_id == NULL)
		return 0;
	return _lldp_send(global, hardware,
	    hardware->h_lchassis_previous_id_subtype,
	    hardware->h_lchassis_previous_id,
	    hardware->h_lchassis_previous_id_len,
	    hardware->h_lport_previous_id_subtype,
	    hardware->h_lport_previous_id,
	    hardware->h_lport_previous_id_len,
	    1);
}

int
lldp_send(struct lldpd *global,
	  struct lldpd_hardware *hardware)
{
	struct lldpd_port *port = &hardware->h_lport;
	struct lldpd_chassis *chassis = port->p_chassis;
	int ret;

	/* Check if we have a change. */
	if (hardware->h_lchassis_previous_id != NULL &&
	    hardware->h_lport_previous_id != NULL &&
	    (hardware->h_lchassis_previous_id_subtype != chassis->c_id_subtype ||
		hardware->h_lchassis_previous_id_len != chassis->c_id_len ||
		hardware->h_lport_previous_id_subtype != port->p_id_subtype ||
		hardware->h_lport_previous_id_len != port->p_id_len ||
		memcmp(hardware->h_lchassis_previous_id,
		    chassis->c_id, chassis->c_id_len) ||
		memcmp(hardware->h_lport_previous_id,
		    port->p_id, port->p_id_len))) {
		log_info("lldp", "MSAP has changed for port %s, sending a shutdown LLDPDU",
		    hardware->h_ifname);
		if ((ret = lldp_send_shutdown(global, hardware)) != 0)
			return ret;
	}

	log_debug("lldp", "send LLDP PDU to %s",
	    hardware->h_ifname);

	if ((ret = _lldp_send(global, hardware,
		    chassis->c_id_subtype,
		    chassis->c_id,
		    chassis->c_id_len,
		    port->p_id_subtype,
		    port->p_id,
		    port->p_id_len,
		    0)) != 0)
		return ret;

	/* Record current chassis and port ID */
	free(hardware->h_lchassis_previous_id);
	hardware->h_lchassis_previous_id_subtype = chassis->c_id_subtype;
	hardware->h_lchassis_previous_id_len = chassis->c_id_len;
	if ((hardware->h_lchassis_previous_id = malloc(chassis->c_id_len)) != NULL)
		memcpy(hardware->h_lchassis_previous_id, chassis->c_id,
		    chassis->c_id_len);
	free(hardware->h_lport_previous_id);
	hardware->h_lport_previous_id_subtype = port->p_id_subtype;
	hardware->h_lport_previous_id_len = port->p_id_len;
	if ((hardware->h_lport_previous_id = malloc(port->p_id_len)) != NULL)
		memcpy(hardware->h_lport_previous_id, port->p_id,
		    port->p_id_len);

	return 0;
}

#define CHECK_TLV_SIZE(x, name)				   \
	do { if (tlv_size < (x)) {			   \
			log_warnx("lldp", name " TLV too short received on %s",	\
	       hardware->h_ifname);			   \
	   goto malformed;				   \
	} } while (0)
#define CHECK_TLV_MAX_SIZE(x, name)			   \
	do { if (tlv_size > (x)) {			   \
			log_warnx("lldp", name " TLV too large received on %s",	\
	       hardware->h_ifname);			   \
	   goto malformed;				   \
	} } while (0)

int
lldp_decode(struct lldpd *cfg, char *frame, int s,
    struct lldpd_hardware *hardware,
    struct lldpd_chassis **newchassis, struct lldpd_port **newport)
{
	struct lldpd_chassis *chassis;
	struct lldpd_port *port;
	char lldpaddr[ETHER_ADDR_LEN];
	unsigned char orgid[3];
	int length, gotend = 0, ttl_received = 0;
	int tlv_size, tlv_type, tlv_subtype, tlv_count = 0;
	u_int8_t *pos, *tlv;
	char *b;
	struct lldpd_mgmt *mgmt;
	int af;
	u_int8_t addr_str_length, addr_str_buffer[32];
	u_int8_t addr_family, addr_length, *addr_ptr, iface_subtype;
	u_int32_t iface_number, iface;

	log_debug("lldp", "receive LLDP PDU on %s",
	    hardware->h_ifname);

	if ((chassis = calloc(1, sizeof(struct lldpd_chassis))) == NULL) {
		log_warn("lldp", "failed to allocate remote chassis");
		return -1;
	}
	TAILQ_INIT(&chassis->c_mgmt);
	if ((port = calloc(1, sizeof(struct lldpd_port))) == NULL) {
		log_warn("lldp", "failed to allocate remote port");
		free(chassis);
		return -1;
	}

	length = s;
	pos = (u_int8_t*)frame;

	if (length < 2*ETHER_ADDR_LEN + sizeof(u_int16_t)) {
		log_warnx("lldp", "too short frame received on %s", hardware->h_ifname);
		goto malformed;
	}
	PEEK_BYTES(lldpaddr, ETHER_ADDR_LEN);
	if (memcmp(lldpaddr, (const char [])LLDP_ADDR_NEAREST_BRIDGE, ETHER_ADDR_LEN) &&
	    memcmp(lldpaddr, (const char [])LLDP_ADDR_NEAREST_NONTPMR_BRIDGE, ETHER_ADDR_LEN) &&
	    memcmp(lldpaddr, (const char [])LLDP_ADDR_NEAREST_CUSTOMER_BRIDGE, ETHER_ADDR_LEN)) {
		log_info("lldp", "frame not targeted at LLDP multicast address received on %s",
		    hardware->h_ifname);
		goto malformed;
	}
	PEEK_DISCARD(ETHER_ADDR_LEN);	/* Skip source address */
	if (PEEK_UINT16 != ETHERTYPE_LLDP) {
		log_info("lldp", "non LLDP frame received on %s",
		    hardware->h_ifname);
		goto malformed;
	}

	while (length && (!gotend)) {
		if (length < 2) {
			log_warnx("lldp", "tlv header too short received on %s",
			    hardware->h_ifname);
			goto malformed;
		}
		tlv_size = PEEK_UINT16;
		tlv_type = tlv_size >> 9;
		tlv_size = tlv_size & 0x1ff;
		(void)PEEK_SAVE(tlv);
		if (length < tlv_size) {
			log_warnx("lldp", "frame too short for tlv received on %s",
			    hardware->h_ifname);
			goto malformed;
		}
		/* Check order for mandatory TLVs */
		tlv_count++;
		switch (tlv_type) {
		case LLDP_TLV_CHASSIS_ID:
			if (tlv_count != 1) {
				log_warnx("lldp", "first TLV should be a chassis ID on %s, not %d",
				    hardware->h_ifname, tlv_type);
				goto malformed;
			}
			break;
		case LLDP_TLV_PORT_ID:
			if (tlv_count != 2) {
				log_warnx("lldp", "second TLV should be a port ID on %s, not %d",
				    hardware->h_ifname, tlv_type);
				goto malformed;
			}
			break;
		case LLDP_TLV_TTL:
			if (tlv_count != 3) {
				log_warnx("lldp", "third TLV should be a TTL on %s, not %d",
				    hardware->h_ifname, tlv_type);
				goto malformed;
			}
			break;
		}

		switch (tlv_type) {
		case LLDP_TLV_END:
			if (tlv_size != 0) {
				log_warnx("lldp", "lldp end received with size not null on %s",
				    hardware->h_ifname);
				goto malformed;
			}
			if (length)
				log_debug("lldp", "extra data after lldp end on %s",
				    hardware->h_ifname);
			gotend = 1;
			break;
		case LLDP_TLV_CHASSIS_ID:
		case LLDP_TLV_PORT_ID:
			CHECK_TLV_SIZE(2, "Port/Chassis Id");
			CHECK_TLV_MAX_SIZE(256, "Port/Chassis Id");
			tlv_subtype = PEEK_UINT8;
			if ((tlv_subtype == 0) || (tlv_subtype > 7)) {
				log_warnx("lldp", "unknown subtype for tlv id received on %s",
				    hardware->h_ifname);
				goto malformed;
			}
			if ((b = (char *)calloc(1, tlv_size - 1)) == NULL) {
				log_warn("lldp", "unable to allocate memory for id tlv "
				    "received on %s",
				    hardware->h_ifname);
				goto malformed;
			}
			PEEK_BYTES(b, tlv_size - 1);
			if (tlv_type == LLDP_TLV_PORT_ID) {
				if (port->p_id != NULL) {
					log_warnx("lldp", "Port ID TLV received twice on %s",
					    hardware->h_ifname);
					free(b);
					goto malformed;
				}
				port->p_id_subtype = tlv_subtype;
				port->p_id = b;
				port->p_id_len = tlv_size - 1;
			} else {
				if (chassis->c_id != NULL) {
					log_warnx("lldp", "Chassis ID TLV received twice on %s",
					    hardware->h_ifname);
					free(b);
					goto malformed;
				}
				chassis->c_id_subtype = tlv_subtype;
				chassis->c_id = b;
				chassis->c_id_len = tlv_size - 1;
			}
			break;
		case LLDP_TLV_TTL:
			if (ttl_received) {
				log_warnx("lldp", "TTL TLV received twice on %s",
				    hardware->h_ifname);
				goto malformed;
			}
			CHECK_TLV_SIZE(2, "TTL");
			port->p_ttl = PEEK_UINT16;
			ttl_received = 1;
			break;
		case LLDP_TLV_PORT_DESCR:
		case LLDP_TLV_SYSTEM_NAME:
		case LLDP_TLV_SYSTEM_DESCR:
			if (tlv_size < 1) {
				log_debug("lldp", "empty tlv received on %s",
				    hardware->h_ifname);
				break;
			}
			if ((b = (char *)calloc(1, tlv_size + 1)) == NULL) {
				log_warn("lldp", "unable to allocate memory for string tlv "
				    "received on %s",
				    hardware->h_ifname);
				goto malformed;
			}
			PEEK_BYTES(b, tlv_size);
			switch (tlv_type) {
			case LLDP_TLV_PORT_DESCR:
				free(port->p_descr);
				port->p_descr = b;
				break;
			case LLDP_TLV_SYSTEM_NAME:
				free(chassis->c_name);
				chassis->c_name = b;
				break;
			case LLDP_TLV_SYSTEM_DESCR:
				free(chassis->c_descr);
				chassis->c_descr = b;
				break;
			default:
				/* unreachable */
				free(b);
				break;
			}
			break;
		case LLDP_TLV_SYSTEM_CAP:
			CHECK_TLV_SIZE(4, "System capabilities");
			chassis->c_cap_available = PEEK_UINT16;
			chassis->c_cap_enabled = PEEK_UINT16;
			break;
		case LLDP_TLV_MGMT_ADDR:
			CHECK_TLV_SIZE(1, "Management address");
			addr_str_length = PEEK_UINT8;
			if (addr_str_length > sizeof(addr_str_buffer)) {
				log_warnx("lldp", "too large management address on %s",
				    hardware->h_ifname);
				goto malformed;
			}
			CHECK_TLV_SIZE(1 + addr_str_length, "Management address");
			PEEK_BYTES(addr_str_buffer, addr_str_length);
			addr_length = addr_str_length - 1;
			addr_family = addr_str_buffer[0];
			addr_ptr = &addr_str_buffer[1];
			CHECK_TLV_SIZE(1 + addr_str_length + 5, "Management address");
			iface_subtype = PEEK_UINT8;
			iface_number = PEEK_UINT32;

			af = lldpd_af_from_lldp_proto(addr_family);
			if (af == LLDPD_AF_UNSPEC)
				break;
			if (iface_subtype == LLDP_MGMT_IFACE_IFINDEX)
				iface = iface_number;
			else
				iface = 0;
			mgmt = lldpd_alloc_mgmt(af, addr_ptr, addr_length, iface);
			if (mgmt == NULL) {
				if (errno == ENOMEM)
					log_warn("lldp", "unable to allocate memory "
					    "for management address");
				else
					log_warn("lldp", "too large management address "
					    "received on %s", hardware->h_ifname);
				goto malformed;
			}
			TAILQ_INSERT_TAIL(&chassis->c_mgmt, mgmt, m_entries);
			break;
		default:
			log_warnx("lldp", "unknown tlv (%d) received on %s",
			    tlv_type, hardware->h_ifname);
			hardware->h_rx_unrecognized_cnt++;
			break;
		}
		if (pos > tlv + tlv_size) {
			log_warnx("lldp", "BUG: already past TLV!");
			goto malformed;
		}
		PEEK_DISCARD(tlv + tlv_size - pos);
	}

	/* Some random check */
	if ((chassis->c_id == NULL) ||
	    (port->p_id == NULL) ||
	    (!ttl_received) ||
	    (gotend == 0)) {
		log_warnx("lldp", "some mandatory tlv are missing for frame received on %s",
		    hardware->h_ifname);
		goto malformed;
	}
	*newchassis = chassis;
	*newport = port;
	return 1;
malformed:
	lldpd_chassis_cleanup(chassis, 1);
	lldpd_port_cleanup(port, 1);
	free(port);
	return -1;
}
