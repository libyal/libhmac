include_HEADERS = \
	libhmac.h

pkginclude_HEADERS = \
	libhmac/definitions.h \
	libhmac/error.h \
	libhmac/extern.h \
	libhmac/features.h \
	libhmac/types.h

EXTRA_DIST = \
	libhmac.h.in \
	libhmac/definitions.h.in \
	libhmac/features.h.in \
	libhmac/types.h.in

MAINTAINERCLEANFILES = \
	Makefile.in

distclean: clean
	-rm -f libhmac.h
	-rm -f libhmac/definitions.h
	-rm -f libhmac/features.h
	-rm -f libhmac/types.h
	-rm -f Makefile

