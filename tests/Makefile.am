AM_CPPFLAGS = \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/common \
	@LIBCERROR_CPPFLAGS@ \
	@LIBCRYPTO_CPPFLAGS@ \
	@PTHREAD_CPPFLAGS@ \
	@LIBHMAC_DLL_IMPORT@

if HAVE_PYTHON_TESTS
TESTS_PYHMAC = \
	test_python_module.sh
endif

TESTS = \
	test_library.sh \
	test_md5sum.sh \
	test_sha1sum.sh \
	test_sha2sum.sh \
	$(TESTS_PYHMAC)

TESTS_INPUT = \
	input/public/empty \
	input/public/test1 \
	input/public/test2 \
	input/public/test3 \
	input/public/test4 \
	input/public/test5 \
	input/public/test6 \
	input/public/test7 \
	input/public/test8

check_SCRIPTS = \
	pyhmac_test_support.py \
	test_library.sh \
	test_manpage.sh \
	test_md5sum.sh \
	test_python_module.sh \
	test_runner.sh \
	test_sha1sum.sh \
	test_sha2sum.sh

check_PROGRAMS = \
	hmac_test_error \
	hmac_test_md5 \
	hmac_test_md5_context \
	hmac_test_sha1 \
	hmac_test_sha1_context \
	hmac_test_sha224 \
	hmac_test_sha224_context \
	hmac_test_sha256 \
	hmac_test_sha256_context \
	hmac_test_sha512 \
	hmac_test_sha512_context \
	hmac_test_support

hmac_test_error_SOURCES = \
	hmac_test_error.c \
	hmac_test_libhmac.h \
	hmac_test_macros.h \
	hmac_test_unused.h

hmac_test_error_LDADD = \
	../libhmac/libhmac.la

hmac_test_md5_SOURCES = \
	hmac_test_libhmac.h \
	hmac_test_libcerror.h \
	hmac_test_macros.h \
	hmac_test_memory.c hmac_test_memory.h \
	hmac_test_md5.c \
	hmac_test_unused.h

hmac_test_md5_LDADD = \
	../libhmac/libhmac.la \
	@LIBCERROR_LIBADD@

hmac_test_md5_context_SOURCES = \
	hmac_test_libhmac.h \
	hmac_test_libcerror.h \
	hmac_test_macros.h \
	hmac_test_memory.c hmac_test_memory.h \
	hmac_test_md5_context.c \
	hmac_test_unused.h

hmac_test_md5_context_LDADD = \
	../libhmac/libhmac.la \
	@LIBCERROR_LIBADD@

hmac_test_sha1_SOURCES = \
	hmac_test_libhmac.h \
	hmac_test_libcerror.h \
	hmac_test_macros.h \
	hmac_test_memory.c hmac_test_memory.h \
	hmac_test_sha1.c \
	hmac_test_unused.h

hmac_test_sha1_LDADD = \
	../libhmac/libhmac.la \
	@LIBCERROR_LIBADD@

hmac_test_sha1_context_SOURCES = \
	hmac_test_libhmac.h \
	hmac_test_libcerror.h \
	hmac_test_macros.h \
	hmac_test_memory.c hmac_test_memory.h \
	hmac_test_sha1_context.c \
	hmac_test_unused.h

hmac_test_sha1_context_LDADD = \
	../libhmac/libhmac.la \
	@LIBCERROR_LIBADD@

hmac_test_sha224_SOURCES = \
	hmac_test_libhmac.h \
	hmac_test_libcerror.h \
	hmac_test_macros.h \
	hmac_test_memory.c hmac_test_memory.h \
	hmac_test_sha224.c \
	hmac_test_unused.h

hmac_test_sha224_LDADD = \
	../libhmac/libhmac.la \
	@LIBCERROR_LIBADD@

hmac_test_sha224_context_SOURCES = \
	hmac_test_libhmac.h \
	hmac_test_libcerror.h \
	hmac_test_macros.h \
	hmac_test_memory.c hmac_test_memory.h \
	hmac_test_sha224_context.c \
	hmac_test_unused.h

hmac_test_sha224_context_LDADD = \
	../libhmac/libhmac.la \
	@LIBCERROR_LIBADD@

hmac_test_sha256_SOURCES = \
	hmac_test_libhmac.h \
	hmac_test_libcerror.h \
	hmac_test_macros.h \
	hmac_test_memory.c hmac_test_memory.h \
	hmac_test_sha256.c \
	hmac_test_unused.h

hmac_test_sha256_LDADD = \
	../libhmac/libhmac.la \
	@LIBCERROR_LIBADD@

hmac_test_sha256_context_SOURCES = \
	hmac_test_libhmac.h \
	hmac_test_libcerror.h \
	hmac_test_macros.h \
	hmac_test_memory.c hmac_test_memory.h \
	hmac_test_sha256_context.c \
	hmac_test_unused.h

hmac_test_sha256_context_LDADD = \
	../libhmac/libhmac.la \
	@LIBCERROR_LIBADD@

hmac_test_sha512_SOURCES = \
	hmac_test_libhmac.h \
	hmac_test_libcerror.h \
	hmac_test_macros.h \
	hmac_test_memory.c hmac_test_memory.h \
	hmac_test_sha512.c \
	hmac_test_unused.h

hmac_test_sha512_LDADD = \
	../libhmac/libhmac.la \
	@LIBCERROR_LIBADD@

hmac_test_sha512_context_SOURCES = \
	hmac_test_libhmac.h \
	hmac_test_libcerror.h \
	hmac_test_macros.h \
	hmac_test_memory.c hmac_test_memory.h \
	hmac_test_sha512_context.c \
	hmac_test_unused.h

hmac_test_sha512_context_LDADD = \
	../libhmac/libhmac.la \
	@LIBCERROR_LIBADD@

hmac_test_support_SOURCES = \
	hmac_test_support.c \
	hmac_test_libhmac.h \
	hmac_test_macros.h \
	hmac_test_unused.h

hmac_test_support_LDADD = \
	../libhmac/libhmac.la

EXTRA_DIST = \
	$(check_SCRIPTS) \
	$(TESTS_INPUT)

MAINTAINERCLEANFILES = \
	Makefile.in

distclean: clean
	/bin/rm -f Makefile

