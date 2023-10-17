AM_CFLAGS = -I $(top_srcdir)/include $(LLDP_CFLAGS)
AM_CPPFLAGS = $(LLDP_CPPFLAGS)
AM_LDFLAGS = $(LLDP_LDFLAGS) $(LLDP_BIN_LDFLAGS)

check_PROGRAMS = decode

decode_SOURCES = decode.c \
	$(top_srcdir)/src/daemon/ub-lldpd.h \
	pcap-hdr.h

LDADD = $(top_builddir)/src/daemon/libublldpd.la @check_LIBS@ @libevent_LDFLAGS@
if ENABLE_SYSTEMTAP
LDADD += $(top_builddir)/src/daemon/probes.o
endif

if HAVE_CHECK

TESTS = check_marshal check_pattern check_bitmap check_fixedpoint \
	check_lldp
AM_CFLAGS += @check_CFLAGS@ -Wno-format-extra-args
LDADD += @check_LIBS@

check_marshal_SOURCES = check_marshal.c \
	$(top_srcdir)/src/marshal.h \
	check-compat.h

check_pattern_SOURCES = check_pattern.c \
	$(top_srcdir)/src/daemon/ub-lldpd.h

check_bitmap_SOURCES = check_bitmap.c \
	$(top_srcdir)/src/daemon/ub-lldpd.h

check_lldp_SOURCES = check_lldp.c \
	$(top_srcdir)/src/daemon/ub-lldpd.h \
	common.h common.c check-compat.h pcap-hdr.h

check_fixedpoint_SOURCES = check_fixedpoint.c
check_fixedpoint_LDADD = $(top_builddir)/src/lib/libfixedpoint.la $(LDADD)

check_PROGRAMS += $(TESTS)

endif

MOSTLYCLEANFILES = *.pcap
