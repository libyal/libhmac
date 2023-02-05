if HAVE_PYTHON
AM_CFLAGS = \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/common \
	@LIBCERROR_CPPFLAGS@ \
	@LIBHMAC_DLL_IMPORT@

pyexec_LTLIBRARIES = pyhmac.la

pyhmac_la_SOURCES = \
	pyhmac.c pyhmac.h \
	pyhmac_error.c pyhmac_error.h \
	pyhmac_libhmac.h \
	pyhmac_libcerror.h \
	pyhmac_python.h \
	pyhmac_unused.h

pyhmac_la_LIBADD = \
	@LIBCERROR_LIBADD@ \
	../libhmac/libhmac.la

pyhmac_la_CPPFLAGS = $(PYTHON_CPPFLAGS)
pyhmac_la_LDFLAGS  = -module -avoid-version $(PYTHON_LDFLAGS)

endif

MAINTAINERCLEANFILES = \
	Makefile.in

distclean: clean
	/bin/rm -f Makefile

