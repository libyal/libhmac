AM_CPPFLAGS = \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/common \
	@LIBCERROR_CPPFLAGS@ \
	@LIBCRYPTO_CPPFLAGS@ \
	@PTHREAD_CPPFLAGS@ \
	@LIBHMAC_DLL_EXPORT@

lib_LTLIBRARIES = libhmac.la

libhmac_la_SOURCES = \
	libhmac.c \
	libhmac_byte_stream.h \
	libhmac_definitions.h \
	libhmac_extern.h \
	libhmac_error.c libhmac_error.h \
	libhmac_libcerror.h \
	libhmac_md5.c libhmac_md5.h \
	libhmac_md5_context.c libhmac_md5_context.h \
	libhmac_sha1.c libhmac_sha1.h \
	libhmac_sha1_context.c libhmac_sha1_context.h \
	libhmac_sha224.c libhmac_sha224.h \
	libhmac_sha224_context.c libhmac_sha224_context.h \
	libhmac_sha256.c libhmac_sha256.h \
	libhmac_sha256_context.c libhmac_sha256_context.h \
	libhmac_sha512.c libhmac_sha512.h \
	libhmac_sha512_context.c libhmac_sha512_context.h \
	libhmac_support.c libhmac_support.h \
	libhmac_types.h \
	libhmac_unused.h

libhmac_la_LIBADD = \
	@LIBCERROR_LIBADD@ \
	@LIBCRYPTO_LIBADD@ \
	@LIBDL_LIBADD@ \
	@PTHREAD_LIBADD@

libhmac_la_LDFLAGS = -no-undefined -version-info 1:0:0

EXTRA_DIST = \
	libhmac_definitions.h.in \
	libhmac.rc \
	libhmac.rc.in

MAINTAINERCLEANFILES = \
	Makefile.in

distclean: clean
	/bin/rm -f libhmac_definitions.h
	/bin/rm -f libhmac.rc
	/bin/rm -f Makefile

splint:
	@echo "Running splint on libhmac ..."
	-splint -preproc -redef $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(libhmac_la_SOURCES)

