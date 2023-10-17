AM_CFLAGS = -I $(top_srcdir)/include $(LLDP_CFLAGS)
AM_CPPFLAGS = $(LLDP_CPPFLAGS)
AM_LDFLAGS = $(LLDP_LDFLAGS)

lib_LTLIBRARIES = libublldpctl.la
include_HEADERS = lldpctl.h

ATOM_FILES = \
	atoms/config.c \
	atoms/interface.c atoms/mgmt.c atoms/port.c \
	atoms/chassis.c
libublldpctl_la_SOURCES = \
	lldpctl.h atom.h helpers.h \
	errors.c connection.c atom.c helpers.c \
	$(ATOM_FILES)
nodist_libublldpctl_la_SOURCES = atom-glue.c
libublldpctl_la_LIBADD  = $(top_builddir)/src/libcommon-daemon-lib.la

atom-glue.c: $(ATOM_FILES) Makefile
	$(AM_V_GEN)(for f in $(ATOM_FILES:%=$(srcdir)/%); do \
		$(CPP) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) \
		$(CPPFLAGS) $(AM_CFLAGS) $(CFLAGS) $$f; done | \
		$(SED) -n 's+^void init_atom_builder_\([^(]*\)().*, \([0-9]*\)).*+\2 \1+p' | \
		sort | \
		$(AWK) '{ atoms[$$2] = 1 } \
			 END { for (atom in atoms) { print "void init_atom_builder_"atom"(void);" } \
			       print "void init_atom_builder() {"; \
                               print " static int init = 0; if (init) return; init++;"; \
			       for (atom in atoms) { print " init_atom_builder_"atom"();" } \
			       print "}"; }' && \
		for f in $(ATOM_FILES:%=$(srcdir)/%); do \
		$(CPP) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) \
		$(CPPFLAGS) $(AM_CFLAGS) $(CFLAGS) $$f; done | \
		$(SED) -n 's+^void init_atom_map_\([^(]*\)().*, \([0-9]*\)).*+\2 \1+p' | \
		sort -n | \
		$(AWK) '{ atoms[$$2] = 1 } \
			 END { for (atom in atoms) { print "void init_atom_map_"atom"(void);" } \
			       print "void init_atom_map() {"; \
                               print " static int init = 0; if (init) return; init++;"; \
			       for (atom in atoms) { print " init_atom_map_"atom"();" } \
			       print "}"; }' ) \
		> $@.tmp
	$(AM_V_at)$(GREP) -q init_atom_builder_ $@.tmp
	$(AM_V_at)$(GREP) -q init_atom_map_ $@.tmp
	$(AM_V_at)mv $@.tmp $@
CLEANFILES = atom-glue.c

# -version-info format is `current`:`revision`:`age`. For more details, see:
#   https://www.sourceware.org/autobook/autobook/autobook_61.html#Library-Versioning
#
# -version-number could be computed from -version-info, mostly major
# is `current` - `age`, minor is `age` and revision is `revision' and
# major.minor should be used when updaing ub-lldpctl.map.
libublldpctl_la_LDFLAGS = $(AM_LDFLAGS) -version-info 13:0:9

if HAVE_LD_VERSION_SCRIPT
libublldpctl_la_DEPENDENCIES = ub-lldpctl.map
libublldpctl_la_LDFLAGS += -Wl,--version-script=$(srcdir)/ub-lldpctl.map
else
libublldpctl_la_LDFLAGS += -export-symbols-regex '^ub-lldpctl_'
endif

pkgconfig_DATA = ub-lldpctl.pc

TEMPLATES  = ub-lldpctl.pc
EXTRA_DIST = ub-lldpctl.pc.in ub-lldpctl.map
CLEANFILES += $(TEMPLATES)
ub-lldpctl.pc: ub-lldpctl.pc.in
include $(top_srcdir)/edit.am
