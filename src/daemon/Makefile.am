AM_CFLAGS = -I $(top_srcdir)/include $(LLDP_CFLAGS)
AM_CPPFLAGS = $(LLDP_CPPFLAGS)
AM_LDFLAGS = $(LLDP_LDFLAGS)
BUILT_SOURCES =
CLEANFILES =

sbin_PROGRAMS = ub-lldpd
man_MANS = ub-lldpd.8

noinst_LTLIBRARIES = libublldpd.la

## Convenience library for ub-lldpd and tests
nodist_libublldpd_la_SOURCES =
libublldpd_la_SOURCES  = \
	frame.h frame.c \
	lldp-tlv.h \
	client.c \
	priv.c \
	privsep.c privsep_io.c privsep_fd.c \
	interfaces.c \
	event.c lldpd.c \
	pattern.c \
	probes.d trace.h \
	protocols/lldp.c
libublldpd_la_CFLAGS   = $(AM_CFLAGS) @libevent_CFLAGS@ @libcap_CFLAGS@
libublldpd_la_CPPFLAGS = $(AM_CPPFLAGS) -DSYSCONFDIR='"$(sysconfdir)"' -DLLDPCLI_PATH='"$(sbindir)/ub-lldpcli"'
libublldpd_la_LIBADD   = \
	$(top_builddir)/src/libcommon-daemon-client.la \
	$(top_builddir)/src/libcommon-daemon-lib.la @libevent_LIBS@ @libcap_LIBS@

## ub-lldpd
ub_lldpd_SOURCES = main.c
ub_lldpd_LDFLAGS = $(AM_LDFLAGS) $(LLDP_BIN_LDFLAGS)
ub_lldpd_LDADD   = libublldpd.la @libevent_LDFLAGS@

libublldpd_la_SOURCES += \
	forward-linux.c \
	interfaces-linux.c \
	netlink.c \
	priv-linux.c

# seccomp support
if USE_SECCOMP
BUILT_SOURCES += syscall-names.h
CLEANFILES    += syscall-names.h syscall-names.h.tmp
syscall-names.h:
	$(AM_V_GEN)
	$(AM_V_at)echo "#include <sys/syscall.h>" | $(CPP) -dM - > $@.tmp ;\
	echo "static const char *syscall_names[] = {" > $@ ;\
	grep '^#define __NR_' $@.tmp | \
		LC_ALL=C sed -r -n -e 's/^\#define[ \t]+__NR_([a-z0-9_]+)[ \t]+([0-9]+)(.*)/ [\2] = "\1",/p' >> $@ ;\
	echo "};" >> $@ ;\
	rm $@.tmp
nodist_libublldpd_la_SOURCES += syscall-names.h
libublldpd_la_SOURCES += priv-seccomp.c
libublldpd_la_CFLAGS  += @libseccomp_CFLAGS@
libublldpd_la_LIBADD  += @libseccomp_LIBS@
endif

## Systemtap/DTrace
EXTRA_DIST = dtrace2systemtap.awk
if ENABLE_SYSTEMTAP
BUILT_SOURCES += probes.h
CLEANFILES    += probes.h ub-lldpd.stp
probes.h: probes.d
	$(AM_V_GEN)
	$(AM_V_at)$(DTRACE) -C -h -s $< -o $@
probes.o: probes.d
	$(AM_V_GEN)
	$(AM_V_at)$(DTRACE) -C -G -s $< -o $@
ub_lldpd_LDADD += probes.o

ub-lldpd.stp: probes.d $(srcdir)/dtrace2systemtap.awk $(top_builddir)/config.status
	$(AM_V_GEN)$(AWK) -f $(srcdir)/dtrace2systemtap.awk -v sbindir=$(sbindir) $< > $@ || ( rm -f $@ ; exit 1 )
tapsetdir = $(datadir)/systemtap/tapset
tapset_DATA = ub-lldpd.stp
endif

## libevent
if LIBEVENT_EMBEDDED
event.c: $(top_builddir)/libevent/libevent.la
$(top_builddir)/libevent/libevent.la: $(top_srcdir)/libevent/*.c $(top_srcdir)/libevent/*.h
	(cd $(top_builddir)/libevent && $(MAKE))
endif

## systemd service file
if HAVE_SYSTEMDSYSTEMUNITDIR
systemdsystemunit_DATA = ub-lldpd.service
endif

if HAVE_SYSUSERSDIR
sysusers_DATA = ub-lldpd.sysusers.conf
endif

if HAVE_APPARMORDIR
apparmor_DATA = usr.sbin.ub-lldpd
endif

TEMPLATES   = ub-lldpd.8    ub-lldpd.service    ub-lldpd.sysusers.conf    usr.sbin.ub-lldpd
EXTRA_DIST += ub-lldpd.8.in ub-lldpd.service.in ub-lldpd.sysusers.conf.in usr.sbin.ub-lldpd.in
CLEANFILES += $(TEMPLATES)
ub-lldpd.8: ub-lldpd.8.in
ub-lldpd.service: ub-lldpd.service.in
ub-lldpd.sysusers.conf: ub-lldpd.sysusers.conf.in
usr.sbin.ub-lldpd: usr.sbin.ub-lldpd.in
include $(top_srcdir)/edit.am
