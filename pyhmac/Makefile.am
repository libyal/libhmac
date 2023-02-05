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
	pyhmac_md5.c pyhmac_md5.h \
	pyhmac_md5_context.c pyhmac_md5_context.h \
	pyhmac_python.h \
	pyhmac_sha1.c pyhmac_sha1.h \
	pyhmac_sha1_context.c pyhmac_sha1_context.h \
	pyhmac_sha224.c pyhmac_sha224.h \
	pyhmac_sha224_context.c pyhmac_sha224_context.h \
	pyhmac_sha256.c pyhmac_sha256.h \
	pyhmac_sha256_context.c pyhmac_sha256_context.h \
	pyhmac_sha512.c pyhmac_sha512.h \
	pyhmac_sha512_context.c pyhmac_sha512_context.h \
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

