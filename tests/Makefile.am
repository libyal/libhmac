AM_CPPFLAGS = \
	-I../include -I$(top_srcdir)/include \
	-I../common -I$(top_srcdir)/common \
	@LIBCERROR_CPPFLAGS@ \
	@LIBCRYPTO_CPPFLAGS@ \
	@PTHREAD_CPPFLAGS@ \
	@LIBHMAC_DLL_IMPORT@

check_PYTHONdir = $(abs_top_builddir)

BUILT_SOURCES = package.m4

TESTS = \
	$(check_SCRIPTS)

check_AUTOTESTS = \
	test_library \
	test_manpages

if HAVE_PYTHON_TESTS
check_AUTOTESTS += test_python_module
endif

input_FILES = \
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
	test_md5sum.sh \
	test_sha1sum.sh \
	test_sha2sum.sh

check_PYTHON_SCRIPTS = \
	pyhmac_test_support.py

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

AUTOM4TE = autom4te
AUTOTEST = $(AUTOM4TE) --language=autotest

SUFFIXES = .at

.at:
	$(AM_V_GEN)rm -f $@ $@.tmp; \
	$(AUTOTEST) -I '$(srcdir)' -o $@.tmp $< && \
	mv $@.tmp $@

atconfig: $(top_builddir)/config.status
	cd $(top_builddir) && $(SHELL) ./config.status tests/$@

check-build: $(check_PROGRAMS)

check-local: $(check_AUTOTESTS)
	@fail=0; \
	for test_suite in $(check_AUTOTESTS); do \
		$(AM_TESTS_ENVIRONMENT) $(SHELL) "./$$test_suite" $(TESTSUITEFLAGS) || fail=1; \
		echo ""; \
	done; \
	exit $$fail

clean-local:
	for test_suite in $(check_AUTOTESTS); do \
		test ! -f "$$test_suite" || $(SHELL) "./$$test_suite" --clean; \
	done

package.m4: $(top_srcdir)/configure.ac
	$(AM_V_GEN):; \
	{ \
	  echo 'm4_define([AT_PACKAGE_NAME], [$(PACKAGE_NAME)])' ; \
	  echo 'm4_define([AT_PACKAGE_TARNAME], [$(PACKAGE_TARNAME)])' ; \
	  echo 'm4_define([AT_PACKAGE_VERSION], [$(PACKAGE_VERSION)])' ; \
	  echo 'm4_define([AT_PACKAGE_STRING], [$(PACKAGE_STRING)])' ; \
	  echo 'm4_define([AT_PACKAGE_BUGREPORT], [$(PACKAGE_BUGREPORT)])' ; \
	} > $@

test_library: package.m4 test_library.at test_macros.at

test_manpages: package.m4 test_manpages.at

test_python_module: package.m4 test_python_module.at

EXTRA_DIST = \
	$(check_AUTOTESTS:=.at) \
	$(check_SCRIPTS) \
	$(check_PYTHON_SCRIPTS) \
	$(input_FILES) \
	package.m4 \
	test_macros.at \
	test_runner.sh

CLEANFILES = \
	$(check_AUTOTESTS) \
	*.exe \
	*.tmp

DISTCLEANFILES = \
	*.log \
	atconfig \
	Makefile \
	Makefile.in

