/* -*- mode: c; c-file-style: "openbsd" -*- */
/*
 * Copyright (c) 2015 Vincent Bernat <bernat@luffy.cx>
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
#include <inttypes.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include "pcap-hdr.h"
#include "../src/daemon/ub-lldpd.h"

#define BUFSIZE 2000

static void
usage(void)
{
	fprintf(stderr, "Usage:   %s PCAP\n", "decode");
	fprintf(stderr, "Version: %s\n", PACKAGE_STRING);

	fprintf(stderr, "\n");

	fprintf(stderr, "Decode content of PCAP files and display a summary\n");
	fprintf(stderr, "on standard output. Only the first packet is decoded.\n");
	exit(1);
}

char*
tohex(char *str, size_t len)
{
	static char *hex = NULL;
	free(hex); hex = NULL;
	if ((hex = malloc(len * 3 + 1)) == NULL) return NULL;
	for (size_t i = 0; i < len; i++)
		snprintf(hex + 3*i, 4, "%02X ", (unsigned char)str[i]);
	return hex;
}

/* We need an assert macro which doesn't abort */
#define assert(x) while (!(x)) { \
		fprintf(stderr, "%s:%d: %s: Assertion  `%s' failed.\n", \
		    __FILE__, __LINE__, __func__, #x); \
		exit(5); \
	}

int
main(int argc, char **argv)
{
	if (argc != 2 ||
	    !strcmp(argv[1], "-h") ||
	    !strcmp(argv[1], "--help"))
		usage();

	int fd = open(argv[1], O_RDONLY);
	assert(fd != -1);

	char buf[BUFSIZE];
	ssize_t len = read(fd, buf, BUFSIZE);
	assert(len != -1);

	struct pcap_hdr hdr;
	assert(len >= sizeof(hdr));
	memcpy(&hdr, buf, sizeof(hdr));
	assert(hdr.magic_number == 0xa1b2c3d4); /* Assume the same byte order as us */
	assert(hdr.version_major == 2);
	assert(hdr.version_minor == 4);
	assert(hdr.thiszone == 0);
	/* Don't care about other flags */

	struct pcaprec_hdr rechdr;
	assert(len >= sizeof(hdr) + sizeof(rechdr));
	memcpy(&rechdr, buf + sizeof(hdr), sizeof(rechdr));
	assert(len >= sizeof(hdr) + sizeof(rechdr) + rechdr.incl_len);

	/* For decoding, we only need a very basic hardware */
	struct lldpd_hardware hardware;
	memset(&hardware, 0, sizeof(struct lldpd_hardware));
	hardware.h_mtu = 1500;
	strlcpy(hardware.h_ifname, "test", sizeof(hardware.h_ifname));

	char *frame = buf + sizeof(hdr) + sizeof(rechdr);
	struct lldpd_chassis *nchassis = NULL;
	struct lldpd_port *nport = NULL;
	int decoded = 0;
	if (lldp_decode(NULL, frame, rechdr.incl_len, &hardware, &nchassis, &nport) == -1) {
		fprintf(stderr, "Not decoded as a LLDP frame\n");
	} else {
		fprintf(stderr, "Decoded as a LLDP frame\n");
		decoded = 1;
	}

	if (!decoded) exit(1);

	printf("Chassis:\n");
	printf(" Index: %" PRIu16 "\n", nchassis->c_index);
	printf(" Protocol: %" PRIu8 "\n", nchassis->c_protocol);
	printf(" ID subtype: %" PRIu8 "\n", nchassis->c_id_subtype);
	printf(" ID: %s\n", tohex(nchassis->c_id, nchassis->c_id_len));
	printf(" Name: %s\n", nchassis->c_name?nchassis->c_name:"(null)");
	printf(" Description: %s\n", nchassis->c_descr?nchassis->c_descr:"(null)");
	printf(" Cap available: %" PRIu16 "\n", nchassis->c_cap_available);
	printf(" Cap enabled: %" PRIu16 "\n", nchassis->c_cap_enabled);
	struct lldpd_mgmt *mgmt;
	TAILQ_FOREACH(mgmt, &nchassis->c_mgmt, m_entries) {
		char ipaddress[INET6_ADDRSTRLEN + 1];
		int af; size_t alen;
		switch (mgmt->m_family) {
		case LLDPD_AF_IPV4:
			alen = INET_ADDRSTRLEN + 1;
			af  = AF_INET;
			break;
		case LLDPD_AF_IPV6:
			alen = INET6_ADDRSTRLEN + 1;
			af = AF_INET6;
			break;
		default:
			len = 0;
		}
		if (len == 0) continue;
		if (inet_ntop(af, &mgmt->m_addr, ipaddress, alen) == NULL)
			break;
		printf(" mgmt: %s\n", ipaddress);
	}

	printf("Port:\n");
	printf(" ID subtype: %" PRIu8 "\n", nport->p_id_subtype);
	printf(" ID: %s\n", tohex(nport->p_id, nport->p_id_len));
	printf(" Description: %s\n", nport->p_descr?nport->p_descr:"(null)");
	printf(" MFS: %" PRIu16 "\n", nport->p_mfs);
	printf(" TTL: %" PRIu16 "\n", nport->p_ttl);
	exit(0);
}
