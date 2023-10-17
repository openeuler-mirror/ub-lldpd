AM_CFLAGS = -I $(top_srcdir)/include $(LLDP_CFLAGS)
AM_CPPFLAGS = $(LLDP_CPPFLAGS)
AM_LDFLAGS = $(LLDP_LDFLAGS)

sbin_PROGRAMS = ub-lldpcli
man_MANS = ub-lldpcli.8
dist_man_MANS = ub-lldpctl.8

install-exec-local: ub-lldpcli
	cd $(DESTDIR)$(sbindir) && rm -f ub-lldpctl
	cd $(DESTDIR)$(sbindir) && $(LN_S) ub-lldpcli ub-lldpctl
uninstall-local:
	cd $(DESTDIR)$(sbindir) && rm -f ub-lldpctl

ub_lldpcli_SOURCES  = client.h lldpcli.c display.c \
	conf.c \
	conf-lldp.c conf-system.c \
	commands.c show.c \
	misc.c tokenizer.c \
	utf8.c \
	writer.h text_writer.c kv_writer.c json_writer.c
ub_lldpcli_LDADD    = \
	$(top_builddir)/src/libcommon-daemon-client.la \
	$(top_builddir)/src/lib/libublldpctl.la \
	@READLINE_LIBS@
ub_lldpcli_CFLAGS   = $(AM_CFLAGS)
ub_lldpcli_LDFLAGS  = $(AM_LDFLAGS) $(LLDP_BIN_LDFLAGS)

if USE_XML
ub_lldpcli_SOURCES += xml_writer.c
ub_lldpcli_CFLAGS  += @libxml2_CFLAGS@
ub_lldpcli_LDADD   += @libxml2_LIBS@
endif

# Completions
bashcompletiondir = $(datadir)/bash-completion/completions
dist_bashcompletion_DATA = completion/ub-lldpcli
zshcompletiondir = $(datadir)/zsh/site-functions
dist_zshcompletion_DATA = completion/_ub_lldpcli

# Default configuration
lldpdconfdir = $(sysconfdir)/ub-lldpd.d
dist_lldpdconf_DATA = README.conf

TEMPLATES  = ub-lldpcli.8
EXTRA_DIST = ub-lldpcli.8.in
CLEANFILES = $(TEMPLATES)
ub-lldpcli.8: ub-lldpcli.8.in
include $(top_srcdir)/edit.am
