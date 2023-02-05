# Note that we cannot use: AUTOMAKE_OPTIONS = subdir-objects
# subdir-objects will compile the source files to a single version of Python.
# Since subdir-objects is being deprecated we copy the source files instead.
am__installdirs = "$(DESTDIR)$(pyexecdir2)"
pyexecdir = $(pyexecdir2)

if HAVE_PYTHON2
AM_CFLAGS = \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/common \
	@LIBCERROR_CPPFLAGS@ \
	@LIBHMAC_DLL_IMPORT@

am_pyhmac_la_rpath = -rpath $(pyexecdir2)

BUILT_SOURCES = \
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

pyexec_LTLIBRARIES = pyhmac.la

nodist_pyhmac_la_SOURCES = $(BUILT_SOURCES)

pyhmac_la_LIBADD = \
	@LIBCERROR_LIBADD@ \
	../libhmac/libhmac.la

pyhmac_la_CPPFLAGS = $(PYTHON2_CPPFLAGS)
pyhmac_la_LDFLAGS  = -module -avoid-version $(PYTHON2_LDFLAGS)

$(BUILT_SOURCES):
	/bin/cp -f $(top_srcdir)/pyhmac/$@ $@

endif

MAINTAINERCLEANFILES = \
	Makefile.in

clean-local:
	/bin/rm -f pyhmac*.[ch]

distclean: clean
	/bin/rm -f Makefile

