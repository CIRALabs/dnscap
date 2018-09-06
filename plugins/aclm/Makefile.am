MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

AM_CFLAGS = -I$(srcdir) \
    -I$(top_srcdir)/src \
    -I$(top_srcdir)/isc \
    $(SECCOMPFLAGS)

pkglib_LTLIBRARIES = aclm.la
aclm_la_SOURCES = aclm.c
dist_aclm_la_SOURCES = aclm.h
aclm_la_LDFLAGS = -module -avoid-version
