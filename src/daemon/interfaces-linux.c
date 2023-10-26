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

#include "lldpd.h"

#include <stdio.h>
#include <unistd.h>
#include <inttypes.h>
#include <errno.h>
#include <sys/ioctl.h>
#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdocumentation"
#endif
#include <netinet/in.h>
#include <linux/sockios.h>
#include <linux/if_packet.h>
#include <linux/ethtool.h>
#if defined(__clang__)
#pragma clang diagnostic pop
#endif

#define SYSFS_PATH_MAX 256
#define MAX_PORTS 1024
#define MAX_BRIDGES 1024

static int
iflinux_init(struct lldpd *cfg, struct lldpd_hardware *hardware)
{
	int fd;

	log_debug("interfaces", "initialize ub device %s",
	    hardware->h_ifname);
	if ((fd = priv_iface_init(hardware->h_ifindex, hardware->h_ifname)) == -1)
		return -1;
	hardware->h_sendfd = fd; /* Send */

	levent_hardware_add_fd(hardware, fd); /* Receive */
	log_debug("interfaces", "interface %s initialized (fd=%d)", hardware->h_ifname,
	    fd);
	return 0;
}

/* Generic ub send/receive */
static int
iflinux_send(struct lldpd *cfg, struct lldpd_hardware *hardware,
    char *buffer, size_t size)
{
	log_debug("interfaces", "send PDU to ub device %s (fd=%d)",
	    hardware->h_ifname, hardware->h_sendfd);
	lldpd_dump_packet("send", buffer, size, hardware);
	return write(hardware->h_sendfd,
	    buffer, size);
}

static int
iflinux_generic_recv(struct lldpd_hardware *hardware,
    int fd, char *buffer, size_t size,
    struct sockaddr_ll *from)
{
	int n, retry = 0;
	socklen_t fromlen;

retry:
	fromlen = sizeof(*from);
	memset(from, 0, fromlen);
	if ((n = recvfrom(fd, buffer, size, 0,
		    (struct sockaddr *)from,
		    &fromlen)) == -1) {
		if (errno == EAGAIN && retry == 0) {
			/* There may be an error queued in the socket. Clear it and retry. */
			levent_recv_error(fd, hardware->h_ifname);
			retry++;
			goto retry;
		}
		if (errno == ENETDOWN) {
			log_debug("interfaces", "error while receiving frame on %s (network down)",
			    hardware->h_ifname);
		} else {
			log_warn("interfaces", "error while receiving frame on %s (retry: %d)",
			    hardware->h_ifname, retry);
			hardware->h_rx_discarded_cnt++;
		}
		return -1;
	}
	if (from->sll_pkttype == PACKET_OUTGOING)
		return -1;
	return n;
}

static int
iflinux_recv(struct lldpd *cfg, struct lldpd_hardware *hardware,
    int fd, char *buffer, size_t size)
{
	int n;
	struct sockaddr_ll from;

	log_debug("interfaces", "receive PDU from ub device %s",
	    hardware->h_ifname);
	if ((n = iflinux_generic_recv(hardware, fd, buffer, size, &from)) == -1)
		return -1;
	return n;
}

static int
iflinux_close(struct lldpd *cfg, struct lldpd_hardware *hardware)
{
	log_debug("interfaces", "close ub device %s",
	    hardware->h_ifname);
	return 0;
}

static struct lldpd_ops ops = {
	.send = iflinux_send,
	.recv = iflinux_recv,
	.cleanup = iflinux_close,
};

/* Query each interface to get the appropriate driver */
static void
iflinux_add_driver(struct lldpd *cfg,
    struct interfaces_device_list *interfaces)
{
	struct interfaces_device *iface;
	TAILQ_FOREACH(iface, interfaces, next) {
		struct ethtool_drvinfo ethc = {
			.cmd = ETHTOOL_GDRVINFO
		};
		struct ifreq ifr = {
			.ifr_data = (caddr_t)&ethc
		};
		if (iface->driver) continue;

		strlcpy(ifr.ifr_name, iface->name, IFNAMSIZ);
		if (ioctl(cfg->g_sock, SIOCETHTOOL, &ifr) == 0) {
			iface->driver = strdup(ethc.driver);
			log_debug("interfaces", "driver for %s is `%s`",
			    iface->name, iface->driver);
		}
	}
}

static void iflinux_add_physical(struct lldpd *cfg, struct interfaces_device_list *interfaces)
{
    struct interfaces_device *iface;

    TAILQ_FOREACH(iface, interfaces, next)
    {
        iface->type &= ~IFACE_PHYSICAL_T;

        if (iface->dev_type == ARPHRD_UB) {
            iface->type |= IFACE_PHYSICAL_T;
            log_debug("interfaces", "Device list add UB physical device for %s", iface->name);
        }
        continue;
    }
}

void
interfaces_update(struct lldpd *cfg)
{
	struct lldpd_hardware *hardware;
	struct interfaces_device_list *interfaces;
	struct interfaces_address_list *addresses;
	interfaces = netlink_get_interfaces(cfg);
	addresses = netlink_get_addresses(cfg);
	if (interfaces == NULL || addresses == NULL) {
		log_warnx("interfaces", "cannot update the list of local interfaces");
		return;
	}

	/* Add missing bits to list of interfaces */
	iflinux_add_driver(cfg, interfaces);
	iflinux_add_physical(cfg, interfaces);

	interfaces_helper_allowlist(cfg, interfaces);
	interfaces_helper_physical(cfg, interfaces,
	    &ops,
	    iflinux_init);
	interfaces_helper_mgmt(cfg, addresses, interfaces);
	interfaces_helper_chassis(cfg, interfaces);

	/* GUID/PHY */
	TAILQ_FOREACH(hardware, &cfg->g_hardware, h_entries) {
		if (!hardware->h_flags) continue;
		interfaces_helper_promisc(cfg, hardware);
	}
}

void
interfaces_cleanup(struct lldpd *cfg)
{
	netlink_cleanup(cfg);
}
