if HAVE_LIB_FUZZING_ENGINE
AM_CPPFLAGS = \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/common

bin_PROGRAMS = \
	md5_context_fuzzer \
	sha1_context_fuzzer \
	sha224_context_fuzzer \
	sha256_context_fuzzer \
	sha512_context_fuzzer

md5_context_fuzzer_SOURCES = \
	md5_context_fuzzer.cc \
	ossfuzz_libhmac.h

md5_context_fuzzer_LDADD = \
	@LIB_FUZZING_ENGINE@ \
	../libhmac/libhmac.la

sha1_context_fuzzer_SOURCES = \
	sha1_context_fuzzer.cc \
	ossfuzz_libhmac.h

sha1_context_fuzzer_LDADD = \
	@LIB_FUZZING_ENGINE@ \
	../libhmac/libhmac.la

sha224_context_fuzzer_SOURCES = \
	sha224_context_fuzzer.cc \
	ossfuzz_libhmac.h

sha224_context_fuzzer_LDADD = \
	@LIB_FUZZING_ENGINE@ \
	../libhmac/libhmac.la

sha256_context_fuzzer_SOURCES = \
	sha256_context_fuzzer.cc \
	ossfuzz_libhmac.h

sha256_context_fuzzer_LDADD = \
	@LIB_FUZZING_ENGINE@ \
	../libhmac/libhmac.la

sha512_context_fuzzer_SOURCES = \
	sha512_context_fuzzer.cc \
	ossfuzz_libhmac.h

sha512_context_fuzzer_LDADD = \
	@LIB_FUZZING_ENGINE@ \
	../libhmac/libhmac.la
endif

MAINTAINERCLEANFILES = \
	Makefile.in

distclean: clean
	/bin/rm -f Makefile

splint:
	@echo "Running splint on md5_context_fuzzer ..."
	-splint -preproc -redef $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(md5_context_fuzzer_SOURCES)
	@echo "Running splint on sha1_context_fuzzer ..."
	-splint -preproc -redef $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(sha1_context_fuzzer_SOURCES)
	@echo "Running splint on sha224_context_fuzzer ..."
	-splint -preproc -redef $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(sha224_context_fuzzer_SOURCES)
	@echo "Running splint on sha256_context_fuzzer ..."
	-splint -preproc -redef $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(sha256_context_fuzzer_SOURCES)
	@echo "Running splint on sha512_context_fuzzer ..."
	-splint -preproc -redef $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(sha512_context_fuzzer_SOURCES)

