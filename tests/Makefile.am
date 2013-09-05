TESTS = \
	test_md5sum.sh \
	test_sha1sum.sh \
	test_sha256sum.sh \
	test_sha512sum.sh

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
	test_md5sum.sh \
	test_runner.sh \
	test_sha1sum.sh \
	test_sha256sum.sh \
	test_sha512sum.sh

EXTRA_DIST = \
	$(check_SCRIPTS) \
	$(TESTS_INPUT)

MAINTAINERCLEANFILES = \
	Makefile.in

distclean: clean
	/bin/rm -f Makefile

