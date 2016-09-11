AM_CPPFLAGS = \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/common \
	@LIBCSTRING_CPPFLAGS@ \
	@LIBCERROR_CPPFLAGS@ \
	@LIBHMAC_DLL_IMPORT@

TESTS = \
	test_api_functions.sh \
	test_api_types.sh \
	test_md5sum.sh \
	test_sha1sum.sh \
	test_sha2sum.sh

TESTS_INPUT = \
	input/empty \
	input/test1 \
	input/test2 \
	input/test3 \
	input/test4 \
	input/test5 \
	input/test6 \
	input/test7 \
	input/test8

check_SCRIPTS = \
	test_api_functions.sh \
	test_api_types.sh \
	test_md5sum.sh \
	test_runner.sh \
	test_sha1sum.sh \
	test_sha2sum.sh

check_PROGRAMS = \
	hmac_test_error \
	hmac_test_get_version \
	hmac_test_md5_context \
	hmac_test_sha1_context \
	hmac_test_sha224_context \
	hmac_test_sha256_context \
	hmac_test_sha512_context

hmac_test_error_SOURCES = \
	hmac_test_error.c \
	hmac_test_libcstring.h \
	hmac_test_libhmac.h \
	hmac_test_macros.h \
	hmac_test_unused.h

hmac_test_error_LDADD = \
	../libhmac/libhmac.la \
	@LIBCSTRING_LIBADD@

hmac_test_get_version_SOURCES = \
	hmac_test_get_version.c \
	hmac_test_libcstring.h \
	hmac_test_libhmac.h \
	hmac_test_macros.h \
	hmac_test_unused.h

hmac_test_get_version_LDADD = \
	../libhmac/libhmac.la \
	@LIBCSTRING_LIBADD@

hmac_test_md5_context_SOURCES = \
	hmac_test_libhmac.h \
	hmac_test_libcerror.h \
	hmac_test_libcstring.h \
	hmac_test_macros.h \
	hmac_test_memory.c hmac_test_memory.h \
	hmac_test_md5_context.c \
	hmac_test_unused.h

hmac_test_md5_context_LDADD = \
	../libhmac/libhmac.la \
	@LIBCERROR_LIBADD@ \
	@LIBCSTRING_LIBADD@

hmac_test_sha1_context_SOURCES = \
	hmac_test_libhmac.h \
	hmac_test_libcerror.h \
	hmac_test_libcstring.h \
	hmac_test_macros.h \
	hmac_test_memory.c hmac_test_memory.h \
	hmac_test_sha1_context.c \
	hmac_test_unused.h

hmac_test_sha1_context_LDADD = \
	../libhmac/libhmac.la \
	@LIBCERROR_LIBADD@ \
	@LIBCSTRING_LIBADD@

hmac_test_sha224_context_SOURCES = \
	hmac_test_libhmac.h \
	hmac_test_libcerror.h \
	hmac_test_libcstring.h \
	hmac_test_macros.h \
	hmac_test_memory.c hmac_test_memory.h \
	hmac_test_sha224_context.c \
	hmac_test_unused.h

hmac_test_sha224_context_LDADD = \
	../libhmac/libhmac.la \
	@LIBCERROR_LIBADD@ \
	@LIBCSTRING_LIBADD@

hmac_test_sha256_context_SOURCES = \
	hmac_test_libhmac.h \
	hmac_test_libcerror.h \
	hmac_test_libcstring.h \
	hmac_test_macros.h \
	hmac_test_memory.c hmac_test_memory.h \
	hmac_test_sha256_context.c \
	hmac_test_unused.h

hmac_test_sha256_context_LDADD = \
	../libhmac/libhmac.la \
	@LIBCERROR_LIBADD@ \
	@LIBCSTRING_LIBADD@

hmac_test_sha512_context_SOURCES = \
	hmac_test_libhmac.h \
	hmac_test_libcerror.h \
	hmac_test_libcstring.h \
	hmac_test_macros.h \
	hmac_test_memory.c hmac_test_memory.h \
	hmac_test_sha512_context.c \
	hmac_test_unused.h

hmac_test_sha512_context_LDADD = \
	../libhmac/libhmac.la \
	@LIBCERROR_LIBADD@ \
	@LIBCSTRING_LIBADD@

EXTRA_DIST = \
	$(check_SCRIPTS) \
	$(TESTS_INPUT)

MAINTAINERCLEANFILES = \
	Makefile.in

distclean: clean
	/bin/rm -f Makefile

