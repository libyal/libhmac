AM_CPPFLAGS = \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/common \
	@LIBCERROR_CPPFLAGS@ \
	@LIBCLOCALE_CPPFLAGS@ \
	@LIBCNOTIFY_CPPFLAGS@ \
	@LIBCSPLIT_CPPFLAGS@ \
	@LIBUNA_CPPFLAGS@ \
	@LIBCFILE_CPPFLAGS@ \
	@LIBCPATH_CPPFLAGS@ \
	@PTHREAD_CPPFLAGS@ \
	@LIBHMAC_DLL_IMPORT@

AM_LDFLAGS = @STATIC_LDFLAGS@

bin_PROGRAMS = \
	hmacsum

hmacsum_SOURCES = \
	byte_size_string.c byte_size_string.h \
	digest_hash.c digest_hash.h \
	hmacsum.c \
	hmactools_getopt.c hmactools_getopt.h \
	hmactools_i18n.h \
	hmactools_libcerror.h \
	hmactools_libcfile.h \
	hmactools_libclocale.h \
	hmactools_libcnotify.h \
	hmactools_libcpath.h \
	hmactools_libcsplit.h \
	hmactools_libhmac.h \
	hmactools_libuna.h \
	hmactools_output.c hmactools_output.h \
	hmactools_signal.c hmactools_signal.h \
	hmactools_system_split_string.h \
	hmactools_unused.h \
	sum_handle.c sum_handle.h

hmacsum_LDADD = \
	@LIBCPATH_LIBADD@ \
	@LIBCFILE_LIBADD@ \
	@LIBUNA_LIBADD@ \
	@LIBCSPLIT_LIBADD@ \
	../libhmac/libhmac.la \
	@LIBCNOTIFY_LIBADD@ \
	@LIBCLOCALE_LIBADD@ \
	@LIBCERROR_LIBADD@ \
	@LIBINTL@ \
	@PTHREAD_LIBADD@

MAINTAINERCLEANFILES = \
	Makefile.in

distclean: clean
	/bin/rm -f Makefile

splint:
	@echo "Running splint on hmacsum ..."
	-splint -preproc -redef $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(hmacsum_SOURCES)

